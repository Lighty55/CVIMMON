#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2015, Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
ANSIBLE: Dynamic Inventory Generator for the Cisco VIM Installer.
"""

import sys
import os
import argparse
import json
sys.path.insert(0, os.path.dirname(
                os.path.dirname(
                os.path.dirname(
                os.path.dirname(
                os.path.abspath(__file__))))))
import clouddeploy.config_manager as config_manager

DEFAULT_CFG_DIR = "openstack-configs"
DEFAULT_SETUP_FILE = "setup_data.yaml"
DEFAULTS_FILE = "defaults.yaml"
SECRETS_FILE = "secrets.yaml"
COBBLER_FILE = ".cobbler_data.yaml"


def print_ansible_usage():
    '''
    Print Usage/Help in case of failure.
    '''
    homedir = get_homedir()
    msg = "=" * 50 + "\n"
    msg += "  Cisco VIM Ansible Dynamic inventory generator" + "\n"
    msg += "=" * 50 + "\n"
    msg += "Validations Failed: " + "\n"
    msg += " 1. Ensure config data folder exists [%s/%s]" % (homedir,
                                                             DEFAULT_CFG_DIR)
    msg += "\n"
    msg += " 2. Ensure Setup Data file exist [%s/%s/%s]" % \
        (homedir, DEFAULT_CFG_DIR,
         DEFAULT_SETUP_FILE)
    msg += "\n"

    print msg


def get_homedir():
    '''
    Get the current username
    '''
    homedir = os.path.expanduser("~")
    return homedir


def check_user_config_location():
    '''
    Make sure user configs are present
    '''
    homedir = get_homedir()
    cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)

    if not os.path.exists(cfg_dir):
        print_ansible_usage()
        sys.exit(0)

    return cfg_dir


def list_groups():
    """
    Handle --list argument.
    """
    # Default config should be in ${HOME}/mercury_install
    cfg_dir = check_user_config_location()

    setup_file = os.path.join(cfg_dir, DEFAULT_SETUP_FILE)
    defaults_file = os.path.join(cfg_dir, DEFAULTS_FILE)
    secrets_file = os.path.join(cfg_dir, SECRETS_FILE)
    cobbler_file = os.path.join(cfg_dir, COBBLER_FILE)

    required_files = [setup_file, defaults_file, secrets_file, cobbler_file]
    for req_file in required_files:
        if not os.path.exists(req_file):
            print "File %s doesn't exist. Cannot create inventory. Exiting.." \
                  % req_file
            sys.exit(1)

    cfgmgr = config_manager.ConfigManager(userinput=setup_file)
    manifest = cfgmgr.generate_openstack_manifest()
    print json.dumps(manifest, indent=4, sort_keys=True)


def write_stderr(string):
    """
    Error handler for --host argument.
    """
    sys.stderr.write('%s\n' % string)


def parse_args():
    """
    Parse agruments.
    """
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--list', action='store_true')
    group.add_argument('--host', action='store_true')
    return parser.parse_args()


def main():
    """
    MAIN.
    """
    args = parse_args()
    if args.list:
        list_groups()
    elif args.host:
        write_stderr('This option is not supported.')
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
