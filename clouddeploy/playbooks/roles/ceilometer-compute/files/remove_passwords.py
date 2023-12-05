#!/usr/bin/env python

import argparse
import hvac

PASSWORDS = ["CEILOMETER_DB_PASSWORD", "CEILOMETER_KEYSTONE_PASSWORD"]


def main(build_node_ip, token):
    """ Main function to delete ceilometer passwords """
    hvac_client = hvac.Client(url='http://' + build_node_ip + ":8200",
                              token=token)
    for pwd in PASSWORDS:
        hvac_client.kv.v2.delete_metadata_and_all_versions(path="cvim-secrets/" + pwd)
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Script to delete old passwords")
    parser.add_argument("-t", dest="token", default=None)
    parser.add_argument("-m", dest="build_node_ip", default=None)
    args = parser.parse_args()
    main(build_node_ip=args.build_node_ip, token=args.token)
