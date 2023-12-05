#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import yaml


#script to do basic ceph checks
def check_cephmon_status(raw_output, controller_list):
    '''Check Cephmon status'''

    cntl_svrs_list = controller_list.split(" ")

    # if server names are fqdns
    cntl_svr_list = []
    for cntl in cntl_svrs_list:
        if "." in cntl:
            cntl_svr_list.append(cntl.split(".")[0])
        else:
            cntl_svr_list.append(cntl)

    num_active_controllers = 0
    for cntl_server in cntl_svr_list:
        if cntl_server in raw_output:
            num_active_controllers = num_active_controllers + 1

    if num_active_controllers == 0:
        print "FAIL"
    else:
        print "PASS"


def check_cephosd_status(raw_output, osd_list, osdinfo=None):
    '''Check Cephmon status'''

    osd_svrs_list = osd_list.split(" ")
    num_active_osd = 0

    max_num_storage = 25
    tot_num_servers = int(len(osd_svrs_list))
    # if server names are fqdns
    osd_svr_list = []
    for osd in osd_svrs_list:
        if "." in osd:
            osd_svr_list.append(osd.split(".")[0])
        else:
            osd_svr_list.append(osd)

    curr_active_osd_info = raw_output.split(" ")
    if osdinfo is None:
        for osd_server in osd_svr_list:
            if osd_server in curr_active_osd_info:
                num_active_osd = num_active_osd + 1

        if num_active_osd != tot_num_servers:
            print "FAIL: Num of Active osd found: " + str(num_active_osd) + \
                " Expected: " + str(tot_num_servers)
            return
        else:
            print "PASS"

    else:

        osds_to_replace = osdinfo.split(" ")

        osd_to_replace = []
        for osd in osds_to_replace:
            if "." in osd:
                osd_to_replace.append(osd.split(".")[0])
            else:
                osd_to_replace.append(osd)

        if (len(curr_active_osd_info) < 2) or \
                (len(curr_active_osd_info) > max_num_storage):
            print "FAIL: Num of Active osd found: " + \
                str(len(curr_active_osd_info)) + \
                "; Num active OSD has to be between 2 and 25 for " + \
                "add osd to work. Current Active OSD info: " + str(raw_output)
            return

        '''
        if len(osd_to_replace) != 1:
            print "FAIL: Addition of one OSD supported at any given time; " + \
                " Num OSD requested to be added: " + str(len(osd_to_replace)) + \
                "OSD add requested of: " + str(osdinfo)
            return
        '''

        for osd_server in osd_to_replace:
            if osd_server in curr_active_osd_info:
                print "FAIL: OSD " + str(osd_server) + \
                    " planned to be added already in active osd list " + \
                    str(raw_output)
                return

        for osd_server in osd_svr_list:
            if osd_server in curr_active_osd_info:
                num_active_osd = num_active_osd + 1

        if num_active_osd >= max_num_storage:
            print "FAIL: Max Num of Active osd found: " + str(num_active_osd) + \
                " ; Add OSD not supported, when active OSD >= 25"
            return

        elif (num_active_osd < 2) or (num_active_osd >= max_num_storage):
            print "FAIL: Num of Active osd found: " + str(num_active_osd) + \
                " ; Num active OSD has to be between 2 and 25 \
                for management of OSD to work"
            return

        else:
            print "PASS"
            return

if __name__ == "__main__":

    if re.search(r'check_cephmon_status', sys.argv[1]):
        check_cephmon_status(sys.argv[2], str(sys.argv[3]))

    if re.search(r'check_cephosd_status', sys.argv[1]):
        backup_file = "/root/openstack-configs/.backup_setup_data.yaml"

        if not os.path.isfile(backup_file):
            print "FAIL: Backup setupdata is missing..."

        with open(backup_file, "r") as data:
            backup = yaml.safe_load(data)
            if 'ROLES' not in backup:
                print "FAIL: ROLES is missing in backup setupdata"

            roles = backup['ROLES']
            if 'block_storage' not in roles and 'cephosd' not in roles:
                print "FAIL: block_storage is missing in backup setupdata"

            osd_list = backup['ROLES'].get('block_storage', None)
            if osd_list is None:
                osd_list = backup['ROLES'].get('cephosd', None)

            if osd_list is None:
                print "FAIL: block_storage/cephosd is missing in backup setupdata"

            osd_info_str = ' '.join(osd_list)

        try:
            check_cephosd_status(sys.argv[2], osd_info_str, str(sys.argv[4]))
        except IndexError:
            check_cephosd_status(sys.argv[2], osd_info_str)
