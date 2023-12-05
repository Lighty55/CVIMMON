#!/usr/bin/env python
import os
import sys
import yaml
import json
import subprocess

# Check if the file is a valid config to alertmanager
def is_config_valid(config_file):
    devnull = open(os.devnull, 'w')
    cmd_check = "/opt/cisco/amtool check-config %s" % (config_file)
    cmd_amtool = cmd_check.split(" ")
    output = subprocess.call(cmd_amtool, shell=False, stdout=devnull, stderr=devnull)
    if output != 0:
        return False
    return True

# Check if snmp is set in the route config
def check_snmp_in_routes(routes):
    for elem in routes:
        if elem['receiver'] == 'snmp':
            return True
        if 'routes' in elem:
            if check_snmp_in_routes(elem['routes']):
                return True
    return False

# Check if snmp is set in the config file
def check_snmp_config(config_custom_file):
    if config_custom_file['route']['receiver'] == 'snmp':
        return True
    if 'routes' in config_custom_file['route']:
        return check_snmp_in_routes(config_custom_file['route']['routes'])
    return False

# Add snmp under route and receivers config
def add_snmp_config(config_custom_file):
    snmp_config = {'group_interval': '5m',
                'group_by': ['...'],
                'repeat_interval': '8737h', 'group_wait': '30s',
                'receiver': 'snmp'}
    snmp_config['routes']= [config_custom_file['route']]
    config_custom_file['route'] = snmp_config
    config_custom_file['receivers'].append({
                'webhook_configs': [{'url': 'http://localhost:1161/alarms',
                'send_resolved': True}], 'name': 'snmp'})
    return config_custom_file

def main():
    """
    Merge 2 alertmanager config files into one.
    This script takes 2 arguments: The first argument is the default_config.
    The second argument is the file to merge into the content of the first file (custom_config).
    The third argument is the directory the merged content is written to.
    """
    # Get the info from the default config
    with open(sys.argv[1], 'r') as f:
        config_default = f.read()
        config_default_file = yaml.safe_load(config_default)
    config_file = config_default_file.copy()

    # Get the info from the custom config
    if is_config_valid(sys.argv[2]):
        with open(sys.argv[2], 'r') as f:
            config_custom = f.read()
            config_custom_file = yaml.safe_load(config_custom)

        # If custom config has SNMP and the default doesn't, it means that SNMP was not
        # enabled in setup_data
        if check_snmp_config(config_custom_file) and not check_snmp_config(config_file):
            print 'Alertmanager merge_configs.py: Wrong custom config - SNMP not enabled in setup data.'

        # Check if the custom config has no SNMP and add in case the default has it
        if not check_snmp_config(config_custom_file) and check_snmp_config(config_file):
            config_custom_file = add_snmp_config(config_custom_file)
        config_file.update(config_custom_file)
    else:
        print 'The Custom config file is not in the correct format.'

    # write the result inside the alertmanager config
    with open(sys.argv[3], 'w') as f:
        f.write(yaml.dump(config_file, default_flow_style=False))

    # Check if the merged file is valid, if not copy the default
    if not is_config_valid(sys.argv[3]):
        with open(sys.argv[3], 'w') as f:
            f.write(config_default)

if __name__ == "__main__":
    main()
