#!/usr/bin/python

# Usage-example: python push_images.py  -d http://<local_reg>:<port> <docker.yaml>
import base64
import sys
import argparse
import yaml

parser = argparse.ArgumentParser(description="Push docker images to the registry",
	epilog="""This script pushes the docker images from staging dir
                  to local registry specified in docker.yaml""")
parser.add_argument('-d', '--dest', help='Destination registry URL')
parser.add_argument('dockeryaml', metavar='DOCKER.YAML', help='Installer docker.yaml')
parser.add_argument('-i', '--images_dir', help='Directory where layers/manifests are stored' )
parser.add_argument('-s', '--src', help='Source registry URL' )
parser.add_argument('-u', '--username', help='Registry username', type=str)
parser.add_argument('-p', '--password', help='Registry password', type=str)


args=parser.parse_args()

if args is None:
    sys.exit(1)

if args.dest is None:
    if args.src is None:
        raise ArgumentException('Require a destination dir or source registry')

creds = None
src = None

if args.src:
    src = args.src
    if args.username is None or args.password is None:
        print ('Error: Registry username/password required')
        sys.exit(1)
    else:
        username = args.username
        password = args.password
        creds = base64.b64encode('%s:%s' % (username, password))

dest = args.dest
dockeryaml = args.dockeryaml
DEFAULT_REGISTRY_IMAGE_PATH = args.images_dir

# The work

import requests
from urllib import quote
from urlparse import urljoin
import json

# WARNING WARNING WARNING
# Known urllib3 weakness on some platforms - we should fix, this just turns off the chattiness
import urllib3 as xxx
xxx.disable_warnings()

def make_imagename(x):
    return str(x['name']) + ":" + str(x['image_tag'])

def read_in_chunks(blobfile, chunk_size=50*1024*1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 50k."""
    count = 0
    sys.stdout.write('          ')
    file_object = open(blobfile)
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        count = count + len(data)
        sys.stdout.write("{:8.2f}M".format(count/float(1024*1024)))
        sys.stdout.flush()
        yield data

# Get the manifest (describing the involved layers) from a remote registry
def get_manf(pfx, image, label, creds=None):
    print 'fetching manifest %s:%s' % (image, label)
    if creds:
        r = requests.get("%s/v2/%s/manifests/%s" % (pfx, quote(image), quote(label)),headers={"Authorization": "Basic %s" % (creds)})
    else:
        r = requests.get("%s/v2/%s/manifests/%s" % (pfx, quote(image), quote(label)))
    if r.status_code == 200:
        return (r.text, r.json())
    else:
        raise Exception(r)


# Get the blob associated with a digest.  Blob returned will suit a requests.post(data=).
def get_layer(pfx, manf_name, digest,creds=None):
    #print 'fetching layer %s from manf %s' % ( digest, manf_name)
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

def get_manf_from_fs(manfdir, manfname):
    manfname = manfname.replace("/", "_")
    manffile = manfdir + "/" + "manifest-" + manfname
    print "Manifest file: " + manffile
    with open(manffile) as data_file:
        data = json.load(data_file) # nosec


    layers = []
    for fdata in data['fsLayers']:
        layers.append(fdata['blobSum'])

    with open(manffile) as data_file:
        data = data_file.read()
    return (data, layers)


# See if the blob with the given digest is present
def test_layer(pfx, manf_name, digest):
    url="%s/v2/%s/blobs/%s" % (pfx, quote(manf_name), quote(digest))
    r = requests.head(url)
    if r.status_code == 404:
        return False
    elif r.status_code == 200:
        return True
    else:
        raise Exception(r)

def push_layer(pfx, image, digest, payload):
    url="%s/v2/%s/blobs/uploads/" % (pfx, quote(image))
    r = requests.post(url, data='') # No data: gives PATCH redirect

    if r.status_code == 202:
        location = urljoin(url, r.headers['Location'])
        r = requests.patch(location, data=payload)
        if r.status_code != 202:
            raise Exception(r)
        confirm_url="%s&digest=%s" % (urljoin(url, r.headers['Location']), quote(digest))
        r = requests.put(confirm_url, data='')
        if r.status_code != 201: # created
            raise Exception(r)
    else:
        raise Exception(r)

# The manifest here must be signed, and it can only be signed if it's textual (since apparently
# order and whitespace matters).  We cheat by preserving the original manifest, and we make no
# attempt to change manf name and tag, so everything is spot on.
def push_manf(pfx, image, label, manf_text):
    print 'pushing manifest %s' % image
    url="%s/v2/%s/manifests/%s" % (pfx, quote(image), quote(label))
    r=requests.put(url, data=manf_text)
    if r.status_code != 201:
        raise Exception(r)

all_manfs = []
all_layers = []
transferred_layers={}

dockerdata = None
try:
    with open(dockeryaml) as f:
        dockerdata = yaml.safe_load(f)
except IOError, e:
    raise

containers = dockerdata['docker']
images = [make_imagename(x) for x in containers.values() if 'name' in x]

for f in images:
    (manf_name, tag) = f.split(':')
    imgname = f
    if src is None:
        (manf_text, layers) = get_manf_from_fs(DEFAULT_REGISTRY_IMAGE_PATH, imgname)
    else:
        (manf_text, manf) = get_manf(src, manf_name, tag, creds)
        layers = get_manf_layers(manf)
    for digest in layers:
        if(test_layer(dest, manf_name, digest)):
            print "Layer %s already exists, no upload required" % (digest)
        else:
            sys.stdout.write('transfer %s... ' % digest)
            sys.stdout.flush()
            if src is None:
                blobfile = DEFAULT_REGISTRY_IMAGE_PATH + "/" + digest
                push_layer(dest, manf_name, digest, read_in_chunks(blobfile))
                transferred_layers[digest] = manf_name
                print ' ... layer complete'
            else:
		if digest in transferred_layers:
		    # Fetch from the closer dest registry, not the remote one
		    sys.stdout.write('(local fetch used) ')
		    sys.stdout.flush()
                    x = get_layer(dest, transferred_layers[digest], digest, creds)
                else:
                    x = get_layer(src, manf_name, digest, creds)

                def contentdebug(content):
                    count=0
                    sys.stdout.write('       ')
                    for f in content:
                        count = count + len(f)
                        sys.stdout.write("{:>12}M".format(count / 1048576))
                        sys.stdout.flush()
                        yield f

                push_layer(dest, manf_name, digest, contentdebug(x.iter_content(chunk_size=10485760)))
                transferred_layers[digest] = manf_name
                print ' ... layer complete'

    push_manf(dest, manf_name, tag, manf_text)
