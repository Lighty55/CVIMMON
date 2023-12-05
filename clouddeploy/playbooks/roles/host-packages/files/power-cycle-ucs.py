#!/usr/bin/env python

import argparse
from baremetal.baremetal_install import BaremetalInstaller
from baremetal.common.common_install import CommonInstall
import sys

parser = argparse.ArgumentParser(description="Reboot UCS server")
parser.add_argument("--reboot_list", action="store", required=True)
args = parser.parse_args()

baremetal_installer = BaremetalInstaller()
common_install = CommonInstall()

common_install.hardware_type = baremetal_installer.hardware_type
server_list = baremetal_installer.cfghelper.get_server_list()
reboot_list = args.reboot_list.split(",")

if set(reboot_list) <= set(server_list):
    print("Rebooting server: %s" % reboot_list)
    ret = common_install.reboot_servers(server_list=reboot_list)
    status = ret.get("status", None)
    if status is not None and status == "PASS":
        print("Successfully rebooted server: %s" % reboot_list)
        sys.exit(0)
    else:
        print("Failed to reboot server: %s" % reboot_list)
        sys.exit(1)
else:
    print("Reboot server not found in setup_data.yaml: %s" % reboot_list)
    sys.exit(1)
