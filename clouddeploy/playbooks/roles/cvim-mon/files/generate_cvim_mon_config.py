#!/usr/bin/python
"""
This script creates a copy of .cobbler_data, setup_data  and telegraf_plugins_intervals
file without any critical information for CVIM-MON deployment.
"""
from optparse import OptionParser
import yaml

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-w", "--workspace", dest="workspace",
                      help="Path to workspace")
    parser.add_option("-d", "--destination", dest="destination",
                      help="Path to destination folder")
    (options, args) = parser.parse_args()
    with open(options.workspace + "/openstack-configs/.cobbler_data.yaml", 'r') as f:
        cobbler_data = f.read()
        cobbler_file = yaml.safe_load(cobbler_data)
    with open(options.workspace + "/openstack-configs/setup_data.yaml", 'r') as f:
        setup_data = f.read()
        setup_file = yaml.safe_load(setup_data)
    with open(options.workspace + "/openstack-configs/telegraf_plugins_intervals.yaml", 'r') as f:
        intervals_data = f.read()
        intervals_file = yaml.safe_load(intervals_data)

    new_cobbler_file = {}
    for node in cobbler_file:
        new_cobbler_file[node] = {
            'nfv_dict': cobbler_file[node]['nfv_dict']
        }
    # If some of the data from setup_data, telegraf_plugins_intervals
    # needs to be cropped out, do it here.
    new_setup_file = setup_file
    new_intervals_file = intervals_file
    with open(options.destination + "/.cobbler_data.yaml", 'w') as f:
        f.write(yaml.dump(new_cobbler_file, default_flow_style=False))
    with open(options.destination + "/setup_data.yaml", 'w') as f:
        f.write(yaml.dump(new_setup_file, default_flow_style=False))
    with open(options.destination + "/telegraf_plugins_intervals.yaml", 'w') as f:
        f.write(yaml.dump(new_intervals_file, default_flow_style=False))