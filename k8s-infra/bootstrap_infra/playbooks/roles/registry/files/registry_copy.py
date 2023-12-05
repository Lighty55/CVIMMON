#!/usr/bin/python

# The arguments
import sys
import os
import argparse
import tempfile
import time
from multiprocessing.pool import ThreadPool

FETCH_BLOCK_SIZE = 10 * 1048576

# The work

import requests
from urllib import quote
from urlparse import urljoin
import json
import hashlib

# WARNING WARNING WARNING
# Known urllib3 weakness on some platforms - we should fix, this just turns off the chattiness
import urllib3 as xxx
xxx.disable_warnings()


class AtomicFile(object):
    """A context handler producing a file that writes atomically or not at all"""
    def __init__(self, path, name):
        self.f = None
	self.path = path
        self.temp_name = None
        self.target_name=name

    def __enter__(self):
        self.f = tempfile.NamedTemporaryFile(dir=self.path, delete=False)
        self.temp_name = self.f.name
        return self.f

    def __exit__(self, type, value, traceback):
        close_e = None
        if self.f is not None:
            try:
                # Flush all data to disk now (with USB disks this is slow)
                os.fsync(self.f.fileno())
                self.f.close()
            except Exception, e:
                self.fname = None
                close_e = e
        if type is None and close_e is None:
            os.rename(self.temp_name, os.path.join(self.path, self.target_name))
        else:
            os.unlink(self.temp_name)
        if type is None and close_e is not None:
            raise(close_e)

        # Re-raise the exception if required
        return False

class Duration(object):
    def __enter__(self):
        self.start=time.time()
        return self
    def __exit__(self, type, value, traceback):
        self.end=time.time()
    @property
    def duration(self):
        return (self.end - self.start)*1000 # in ms

# Get the manifest (describing the involved layers) from a remote registry
def get_manf(pfx, image, label, creds):
    try:
        if creds:
            r = requests.get("%s/v2/%s/manifests/%s" % (pfx, quote(image), quote(label)), headers={"Authorization": "Basic %s" % (creds)})
        else:
            r = requests.get("%s/v2/%s/manifests/%s" % (pfx, quote(image), quote(label)))
        if r.status_code == 200:
            return (r.text, r.json(), [])
        else:
            return (None, None, ['Failed to get manifest for %s: %s' % (image, ("%d:%s" % (r.status_code, r.text)).rstrip())])
    except Exception, e:
        return (None, None, ['Failed to get manifest for %s: %s' % (image, str(e).rstrip())])


# Get the blob associated with a digest.  Blob returned will suit a requests.post(data=).
def get_layer(pfx, manf_name, digest, creds=None):
    if creds:
        r = requests.get("%s/v2/%s/blobs/%s" % (pfx, quote(manf_name), quote(digest)), stream=True, headers={"Authorization": "Basic %s" % (creds)})
    else:
        r = requests.get("%s/v2/%s/blobs/%s" % (pfx, quote(manf_name), quote(digest)), stream=True)
    if r.status_code == 200:
        return r
    else:
        raise Exception(r)


def get_manf_layers(manf):
    layers=[ layer['blobSum'] for layer in manf['fsLayers']]
    return layers

# See if the blob with the given digest is present
def test_layer(pfx, manf_name, digest):
    url="%s/v2/%s/blobs/uploads/%s" % (pfx, quote(manf_name), quote(digest))
    r = requests.head(url)
    if r.status_code == 404:
	return False
    elif r.status_code == 200:
	return True
    else:
	raise Exception(r)

# This saves dupl downloading or checking for as long as this is running
transferred_layers={}

class PrintState(object):
    def __init__(self):
        self.current_line=0
        self.next_line=0

    def line(self):
        x = self.next_line
        self.next_line += 1
        return x

    def find_line(self, line, col):
        if line < self.current_line:
            p = "\033[A" * (self.current_line - line)
        else:
            p = "\n" * (line - self.current_line)
        p = p + "\r" + ("\033[C" * col)
        self.current_line = line
        return p


class Printer(object):
    state = PrintState()

    def __init__(self):
        self.line = self.state.line()
        self.col = 0
        self.stack=[]

    def push(self):
        self.stack.append(self.col)

    def pop(self):
        self.col = self.stack.pop()

    def overprint(self, s):
        s = str(s)
        # Don't use tabs

        # Clear to end of line as positioned, then print
        p = self.state.find_line(self.line, self.col) + "\033[K" + s
        sys.stdout.write(p)
        sys.stdout.flush()

    def partprint(self, s):
	s = str(s)
        self.overprint(s)
        self.col += len(s)

    # Originally last on line, now no different
    def endprint(self, s):
        self.partprint(s)


def do_manifest(source, output_dir, f, verify=True,
                verify_download=False, creds=None):
    (manf_name, tag) = f.split(':')
    errors=[]

    p = Printer()
    with Duration() as d:
        p.partprint('image {0:>40}:{1: <15} - '.format(manf_name[:40], tag[-15:]))
        (manf_text, manf, manf_errors) = get_manf(source, manf_name, tag, creds)
        if len(manf_errors):
            p.endprint("can't get manifest")
            return (0, 0, 0, 0, manf_errors) # Can't go further

    p.overprint('manifest fetched in %d ms' % d.duration)

    layers = get_manf_layers(manf)

    count = 1
    total_layers=0
    total_xfr=0
    total_dl_ver=0
    total_ver=0
    for digest in layers:
        p.push()
        p.partprint("%d/%d layers: [%s|%s]: " % (count,len(layers), '=' * count, ' ' * (len(layers) - count)))
        (fetched, transferred_bytes, dl_verified_bytes, verified_bytes, layer_errors)  = \
            do_layer(source, manf_name, output_dir, digest, p, verify,verify_download, creds)
        if(fetched):
            total_layers += 1
        total_xfr += transferred_bytes
        total_dl_ver += dl_verified_bytes
        total_ver += verified_bytes
        errors.extend(layer_errors)
        p.pop()
        count += 1

    # Manifest is tiny, we always just write the thing
    # TODO and we never verify it
    name="manifest-%s:%s" % (manf_name, tag)
    manf_name_sanitised =name.replace('/', '_') # it's still inside the manifest
    with AtomicFile(output_dir, manf_name_sanitised) as f:
        f.write(manf_text)
    if(len(errors) > 0):
        p.endprint('failed to fetch all layers.')
    else:
        p.endprint('completed.')

    return (total_layers, total_xfr, total_dl_ver, total_ver, errors)

def do_layer(source, manf_name, output_dir, digest, p, verify, verify_download, creds):
    fetched = False
    transferred_bytes=0
    dl_verified_bytes=0
    verified_bytes=0
    errors = []

    def nicename():
        return digest[7:15]
    done = digest in transferred_layers
    transferred_layers[digest] = True
    if done:
        # Our file store stores layers just once, indexed by digest, and we have fetched/checked
        # or are currently doing so for this layer, so we skip
        p.overprint('layer %s already transferred' % nicename())
    else:
        layer_file = os.path.join(output_dir, digest)
        local_validates = False

        # Local file present and good?
        if verify:
            try:
                h = hashlib.sha256()
                HASHBLOCK_SIZE=FETCH_BLOCK_SIZE
                flen = 0
                flen_mb = -1
                with Duration() as d:
                    with open(layer_file, "rb") as f:
                        flen = os.fstat(f.fileno()).st_size
                        flen_mb = flen / 1048576
                        count = 0
                        while True:
                            p.overprint('verifying checksum of local file (%d MB)...' % (count / 1048576))
                            data = f.read(HASHBLOCK_SIZE)
                            if data == '':
                                break
                            count += len(data)
                            h.update(data)

                if "sha256:" + h.hexdigest() == digest:
                    local_validates = True
                    p.overprint('verified the %d MB copy on disk in %d ms (%f MB/s)'  % (flen_mb, d.duration, flen * 1000 / d.duration / 1048576))
                    verified_bytes += flen
                else:
                    p.overprint('local copy is flawed, refetching... ')
            except(IOError):
                # File might not exist or any other problem: just treat it as 'this content needs updating'
                pass
        else:
            try:
                with open(layer_file, "rb") as f:
                    # This file is readable - that's good enough for us with verification off
                    p.overprint('local copy, not checksummed.')
                    local_validates = True
            except(IOError):
                pass

        if not local_validates:
            fetch_done = False
            xfr_bytes = 0
            with Duration() as d:
                for attempt in range(10): # a few retries
                    try:
                        req = get_layer(source, manf_name, digest, creds)

                        # Pretty prints a fetch counter
                        def contentdebug(content):
                            count=0
                            for f in content:
                                count = count + len(f)
                                p.overprint("layer %s, attempt %d: fetched %s" % (nicename(), attempt, "{:>6}M".format(count / 1048576)))
                                yield f

                        chash = hashlib.sha256()
                        def contenthash(content):
                            for f in content:
                                chash.update(f)
                                yield f

                        HTTP_BLOCK_SIZE=FETCH_BLOCK_SIZE
                        with AtomicFile(output_dir, digest) as fd:
                            it = contentdebug(req.iter_content(chunk_size=HTTP_BLOCK_SIZE))

                            if verify_download:
                                # This will update the hash object with the data as it's downloaded
                                it = contenthash(it)

                            for data in it:
                                xfr_bytes = xfr_bytes + len(data)
                                fd.write(data)

                        if "sha256:" + chash.hexdigest() != digest:
                            raise Exception("Downloaded layer does not match hash. Retrying..")

                            if verify_download:
                                if "sha256:" + chash.hexdigest() == digest:
                                    dl_verified_bytes += xfr_bytes
                                else:
                                    # Not a good download; retry as if the connection failed
                                    raise Exception("Downloaded data does not match hash (%s != %s)" % \
                                                    (chash.hexdigest(), digest))
                        fetch_done = True
                        break
                    except Exception, e:
                        p.overprint('failed on attempt %d (%s)' % (attempt, e))
                    finally:
                        transferred_bytes += xfr_bytes
            if fetch_done:
                p.overprint('fetched in %d ms (%f MB/s)' % (d.duration, xfr_bytes * 1000 / d.duration))
                fetched = True
            else:
                errors.append("layer fetch failed. Retry to fetch again")
                p.overprint('layer fetch failed - rerun command to complete copy')

    return (fetched, transferred_bytes, dl_verified_bytes, verified_bytes, errors)


def download_images(source, output_dir, tagged_images, verify=True,
                    verify_download=False, threads=1, creds=None):
    total_layers=0
    total_xfr=0
    total_dl_ver=0
    total_ver=0
    errors = []

    try:
        sys.stdout.write("\033[?25l")

        pool = ThreadPool(threads)

        def wrapped(val):
            try:
                return do_manifest(source, output_dir, val, verify=verify,
                                   verify_download=verify_download, creds=creds)
            except Exception, e:
                print e
                return (e, val)

        retarr = pool.map(wrapped, tagged_images)
        pool.close()
        pool.join()

        for rv in retarr:
            if len(rv) == 2: # exception trapped in wrapped()
                errors.append("Image %s failed: %s" % (rv[1], str(rv[0])))
            else:
                (layers, xfr, dl_ver, ver, image_errors) = rv
                errors.extend(image_errors)
                total_layers += layers
                total_xfr += xfr
                total_dl_ver += dl_ver
                total_ver += ver
    finally:
        # Make cursor visible before exiting
        sys.stdout.write("\033[?12l\033[?25h")

    # Clear the printy thing before exiting
    p = Printer()
    # will be the last line because it's the last entered
    p.partprint("%d manifests and %d layers fetched; %d MB transferred, %d MB validated on download, %d MB locally validated" \
                % (len(tagged_images),
                   total_layers,
                   total_xfr / 1048576,
                   total_dl_ver / 1048576,
                   total_ver / 1048576))
    # clears the last line
    print ''
    if len(errors):
        print "Errors occurred:-"
        for x in errors:
            print " - ", x
    return (total_layers, total_xfr, total_ver, errors)


if __name__ == "__main__":
    # This lets you try this module out with some simple arguments.

    # From StackOverflow:
    def writeable_dir(prospective_dir):
      if not os.path.isdir(prospective_dir):
        raise argparse.ArgumentError("writeable_dir:{0} is not a directory".format(prospective_dir))
      if os.access(prospective_dir, os.W_OK):
        return prospective_dir
      else:
        raise argparse.ArgumentError("writeable_dir:{0} is not writeable".format(prospective_dir))


    parser = argparse.ArgumentParser(description="Copy docker images in to or out of a registry en masse.",
            epilog="""Choose one of the source and one of the destination types to move a listed set of
    images from one place to another.  This tool has a multi-image archive format that can be used to
    take an offline copy of a container (layer by layer) that can be re-imported to another registry.""")
    parser.add_argument('-s', '--source', help='Source registry URL')
    parser.add_argument('-o', '--output', help='Output directory', type=writeable_dir)
    parser.add_argument('--no-verify', help='Skip local file checks', action='store_true')
    parser.add_argument('images', metavar='IMAGE', nargs='*', help='IMAGE:TAG image description')
    args=parser.parse_args()

    if args is None:
        sys.exit(1)


    if args.source is None:
        raise argparse.ArgumentError('Require a source')

    if args.output is None:
        raise argparse.ArgumentError('Require a destination')

    source = args.source
    output_dir=args.output

    verify = args.no_verify is not True

    images = args.images

    (total_layers, total_xfr, total_ver, success) = download_images(source, output_dir, images, verify=verify, threads=10)

    sys.exit(0 if success else 1)

