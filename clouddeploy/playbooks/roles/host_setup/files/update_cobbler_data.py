#!/bin/env python

import json
import os
import shutil
import sys
import yaml

homedir = str(os.path.expanduser("~"))
installer_root = os.readlink("%s/openstack-configs" % homedir) + "/.."
sys.path.append(installer_root)
import utils.config_parser as config_parser

setup_data_yaml = homedir + "/openstack-configs/setup_data.yaml"
cobbler_data_yaml = homedir + "/openstack-configs/.cobbler_data.yaml"
cobbler_data_yaml_bak = homedir + "/openstack-configs/.cobbler_data.yaml.bak"
cfghelper = config_parser.YamlHelper(user_input_file=setup_data_yaml)
mercury_hosts = str(sys.argv[1]).split(',')

# Read current .cobbler_data.yaml
with open(cobbler_data_yaml, "r") as f:
    cb_data = yaml.safe_load(f)

# Regenerate nfv_dict for every NFV host, and update the dictionary
for host in mercury_hosts:
    nfv_cfg = cfghelper.get_nfv_configs(host)
    with open("/root/cpu_mem_info-%s.json" % host) as f:
        cpu_mem = json.load(f)

    if not cb_data[host]['nfv_dict']:
        cb_data[host]['nfv_dict'] = {}

    is_nfv_host = 'grub_opts' in cb_data[host]['nfv_dict']
    cb_data[host]['nfv_dict'].update(
        cfghelper.get_nfv_dict(nfv_cfg,
                               cpu_mem,
                               is_nfv_host=is_nfv_host,
                               server_role=[cb_data[host]['role']])
    )

# Backup .cobbler_data.yaml and update with latest information
if os.path.exists(cobbler_data_yaml):
    shutil.move(cobbler_data_yaml, cobbler_data_yaml_bak)
cfghelper.dump_dict_to_yaml(cb_data, cobbler_data_yaml)
