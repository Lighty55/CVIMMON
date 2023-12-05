#!/usr/bin/python
import base64
import os
import sys
import registry_copy
import yaml
import argparse

# From StackOverflow:
def writeable_dir(prospective_dir):
    if not os.path.isdir(prospective_dir):
        raise argparse.ArgumentError("writeable_dir:{0} is not a directory".format(prospective_dir))
    if os.access(prospective_dir, os.W_OK):
        return prospective_dir
    else:
        raise argparse.ArgumentError("writeable_dir:{0} is not writeable".format(prospective_dir))

def pull_containers(registry, output_dir, dockerdata, creds=None, verify=False):
    """ Fetches containers from the registry into the filesystem.

    This will patch up the files it finds to ensure that the data in
    the filesystem has all the containers required without necessarily
    downloading all the data (if it's been fetched and it's valid it's
    used).

    This is paranoid - we're writing to a USB drive, it's slow, and
    corruption is frustrating - so it checks the checksums of both
    what it downloads (against the sha256 in the layer name) and what
    it finds that has previously been fetched.
    """

    containers = dockerdata['docker']
    tagged_images = [make_imagename(x) for x in containers.values() if 'name' in x]

    # We check both existing data on disk ('verify') and any data we
    # download ('verify_download') to ensure that it matches the
    # checksum.
    (total_layers, total_xfr, total_ver, rerrors) = \
                   registry_copy.download_images(registry, output_dir,
                                                 tagged_images, threads=10,
                                                 creds=creds,
                                                 verify=verify,
                                                 verify_download=verify)
    return True if len(rerrors) == 0 else False

def make_imagename(x):
    return str(x['name']) + ':' + str(x['image_tag'])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Copy Cisco VIM's images out of a registry en masse.",
                                     epilog="""The file format used works with the lightweight registry server.""")
    parser.add_argument('-r', '--registry', help='default registry', type=str)
    parser.add_argument('-u', '--username', help='Registry username', type=str)
    parser.add_argument('-p', '--password', help='Registry password', type=str)
    parser.add_argument('-o', '--output', help='Output directory', type=writeable_dir)
    parser.add_argument('--no-verify', help='Skip local and downloaded file checks', action='store_true')
    parser.add_argument('--threads', type=int, help='Run N images concurrently (default 10)', default=10, metavar='N')
    parser.add_argument('dockeryaml', help='docker.yaml file from installer', metavar='DOCKER.YAML')
    args=parser.parse_args()

    if args is None:
        sys.exit(1)

    if args.output is None:
        raise argparse.ArgumentError('Require a destination')

    output_dir=args.output
    verify = args.no_verify is not True
    threads = int(args.threads)
    dockeryaml = args.dockeryaml
    dockerdata = None

    try:
        with open(dockeryaml) as f:
            dockerdata = yaml.safe_load(f)
    except IOError, e:
        # Should probably do things with this
        raise

    default_registry = args.registry or dockerdata['docker']['common']['registry']
    containers = dockerdata['docker']
    registry = args.registry if args.registry else default_registry

    if args.username is None or args.password is None:
        print ('Error: Registry username/password required')
        sys.exit(1)
    else:
        username = args.username
        password = args.password

    creds = base64.b64encode('%s:%s' % (username, password))
    tagged_images = [make_imagename(x) for x in containers.values() if 'name' in x]

    (total_layers, total_xfr, total_ver, rerrors) = registry_copy.download_images(registry, output_dir, tagged_images, verify=False, threads=10, creds=creds)
    sys.exit(0 if len(rerrors) == 0 else 1)
