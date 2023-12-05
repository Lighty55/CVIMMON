#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess   # nosec
import os
import sys
import re
import json


def create_disk_check_data(role, tools_dir):

    disk_chk_cmd = ['./disk-maintenance.py', '--check_disks', role, '--json_display']
    sproc = subprocess.Popen(disk_chk_cmd,
                             cwd=tools_dir,
                             stdout=subprocess.PIPE)
    outline = []
    while True:
        nextline = sproc.stdout.readline()
        if nextline == '' and sproc.poll() is not None:
            break

        outline.append(nextline)

        if 'ERROR' in nextline or 'fail' in nextline or 'Abort' in nextline:
            if "Disk maintenance tool is meant only for C series pods" in nextline:
                print("SKIP: Disk maintenance tool is meant only for C series pods")
            elif "SW RAID Detected: Disk maintenance tool is meant for HW RAID" in nextline:
                print("SKIP: SW RAID Detected: Disk maintenance tool is meant for HW RAID")
            else:
                print("SKIP: {0}".format(nextline))
            sys.exit(0)


def get_disk_check_data():
    json_file = '/tmp/disk-maintenance/.disk-maintenance.check-disks.json'
    if not os.path.isfile(json_file):
        print("SKIP: Disk maintenance JSON data not generated")
        sys.exit(0)

    with open(json_file) as json_data:
        json_data = json.load(json_data)

    return json_data


def run_test(test, role, dm_json):
    test_ids = {'vd-health': 'VD health', 'raid-health': 'RAID health'}
    test_id = test_ids[test]
    overall_status = dm_json['Overall_Status']
    if overall_status != 'PASS':
        print("SKIP: disk-check indicates overall status problem")
        return

    raid_results = dm_json["Result"]['raid_results_list']
    role_results = [role_result for role_result in raid_results if role in role_result['role']]
    optimal_results = [test_result for test_result in role_results if 'Opt' in test_result[test_id]]
    if len(optimal_results) != len(role_results):
        print("FAIL: {0} indicates suboptimal status".format(test_id))
    else:
        print("PASS: {0} indicates Optimal status".format(test_id))

if __name__ == "__main__":

    method = sys.argv[1]
    role = sys.argv[2]
    test = sys.argv[3]
    install_dir = sys.argv[4]
    if not re.search(r'^create$|^reuse$', method):
        print("FAIL: Invalid method {0} : expected either create|reuse".format(method))
        sys.exit(1)

    if not re.search(r'^management$|^control$|^compute$|^storage$', role):
        print("FAIL: Invalid role {0} : expected one of management|control|compute".format(role))
        sys.exit(1)

    if not re.search(r'^vd-health$|^raid-health$', test):
        print("FAIL: Invalid test {0} : expected either vd-health|raid-health".format(test))
        sys.exit(1)

    if not os.path.isdir(install_dir):
        print("FAIL: Invalid install dir {0}".format(install_dir))
        sys.exit(1)

    tools_dir = install_dir + "/tools"
    if not os.path.isfile(tools_dir + "/disk-maintenance.py"):
        print("SKIP: Disk check {0} for {1} not run: no disk-maintenance.py in this release".format(test, role))
        sys.exit(0)

    if method == 'create':
        create_disk_check_data(role, tools_dir)

    try:
        dm_json = get_disk_check_data()
        run_test(test, role, dm_json)
    except:
        print("SKIP: disk-check.py failed, please run cloud-sanity script for further details")

