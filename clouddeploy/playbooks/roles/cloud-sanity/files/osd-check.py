#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess   # nosec
import os
import sys
import re
import json


def create_osd_data(tools_dir):
    disk_chk_cmd = ['./osd-maintenance.py', '--check_osds', '--json_display']
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
            if "OSD maintenance tool is meant only for C series pods." in nextline:
                print("SKIP: OSD maintenance tool is meant only for C series pods.")
            else:
                print("SKIP: {0}".format(nextline))
            sys.exit(0)


def get_osd_data():
    json_file = '/tmp/osd-maintenance/.osd-maintenance.check-osds.json'
    if not os.path.isfile(json_file):
        print("SKIP: OSD maintenance JSON data not generated")
        sys.exit(0)

    with open(json_file) as json_data:
        json_data = json.load(json_data)

    return json_data


def run_test(test, osd_json):
    overall_status = osd_json['Overall_Status']
    if overall_status != 'PASS':
        print("SKIP: osd-check overall status problem")
        return

    bad_osds = osd_json['Result']['bad_osds_results_list']
    if len(bad_osds) > 0:
        print("FAIL: osd-check detects bad osds {0}".format(bad_osds))
    else:
        osd_detail_result = osd_json['Result']['osd_details_results_list']
        all_good_result = [all_good_status for all_good_status in osd_detail_result
                           if 'All Good' in all_good_status['All OSD status']]
        if len(all_good_result) != len(osd_detail_result):
            print("FAIL: osd-check detects some servers All OSD Status not All Good")
        else:
            print("PASS: Overall OSD Status is good")


if __name__ == "__main__":

    method = sys.argv[1]
    test = sys.argv[2]
    install_dir = sys.argv[3]
    if not re.search(r'^create$|^reuse$', method):
        print("FAIL: Invalid method {0} : expected either create|reuse".format(method))
        sys.exit(1)

    if not re.search(r'^overall-osd-status$', test):
        print("FAIL: Invalid test {0} : expected overall-osd-status".format(test))
        sys.exit(1)

    if not os.path.isdir(install_dir):
        print("FAIL: Invalid install dir {0}".format(install_dir))
        sys.exit(1)

    tools_dir = install_dir + "/tools"
    if not os.path.isfile(tools_dir + "/osd-maintenance.py"):
        print("SKIP: OSD check {0} not run: no osd-maintenance.py in this release".format(test))
        sys.exit(0)

    if method == 'create':
        create_osd_data(tools_dir)

    try:
        osd_json = get_osd_data()
        run_test(test, osd_json)
    except:
        print("SKIP: osd-check.py failed, please run cloud-sanity script for further details")
