#!/usr/bin/env python

'''
Usage: verify_ko_options.py kvm,kvm_intel /etc/modprobe.d/kvm.conf
'''

import os
import sys

run_config = {}
target_config = {}
retVal = True

for ko in sys.argv[1].split(','):
    run_config[ko] = {}
    for dirName, _, fileList in os.walk('/sys/module/%s/parameters' % ko):
        for fname in fileList:
            run_config[ko][fname] = open(dirName + "/" + fname).read().strip()

ko_conf = open(sys.argv[2]).readlines()
for line in ko_conf:
    ko = line.split()[1]
    k, v = line.split()[2].split('=')[:2]
    target_config.setdefault(ko, {})
    target_config[ko][k] = v

for ko in target_config:
    for k, v in target_config[ko].items():
        if run_config.get(ko, {}).get(k, '') != v:
            retVal = False

print(retVal)
