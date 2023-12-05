#!/bin/env python

import json
import subprocess


def run_cmd(cmd, stdin=None, stdout=subprocess.PIPE):
    p = subprocess.Popen(cmd, stdin=stdin, stdout=stdout)
    return p

cpuinfo = run_cmd(["/usr/bin/lscpu"]).stdout
cpuinfo = dict(map(str.strip, ln.split(':', 1)) for ln in cpuinfo.readlines())
mem_p1 = run_cmd(["/usr/sbin/dmidecode", "-t", "17"]).stdout
mem_p2 = run_cmd(["/usr/bin/grep", "Size"], stdin=mem_p1).stdout
meminfo = run_cmd(["/usr/bin/grep", "-v", "No Module Installed"], stdin=mem_p2).stdout
meminfo = [line.split(':')[1].strip() for line in meminfo.readlines()]
total_mem = 0

for dimm in meminfo:
    val, unit = dimm.split()
    unit = 1024 ** (['MB', 'GB', 'TB'].index(unit.upper()))
    total_mem += (int(val) * unit)

cpu_mem = {
    'hyperthreading': int(cpuinfo['Thread(s) per core']) > 1,
    'total_memory': total_mem,
    'nr_sockets': int(cpuinfo['Socket(s)']),
    'cores_per_socket': int(cpuinfo['Core(s) per socket']),
    'total_threads': int(cpuinfo['CPU(s)'])
}

with open("/root/cpu_mem_info.json", "w") as f:
    json.dump(cpu_mem, f)
