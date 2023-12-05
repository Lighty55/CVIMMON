#!/usr/bin/env python
import re, subprocess, sys
import argparse

parser = argparse.ArgumentParser(description='Manipulate masks of CPUs for this host')
parser.add_argument('--anti', action='store_const',
                    const=True, default=False)
parser.add_argument('--mask', action='store_const',
                    const=True, default=False)

parser.add_argument('cpulist', nargs='*')

args = parser.parse_args()

def break_comma_hyphen_list(string):
    grps = (x.split('-') for x in string.split(','))
    return set([i for r in grps for i in range(int(r[0]), int(r[-1]) + 1)])

cpus = set()
for f in args.cpulist:
    cpus |= break_comma_hyphen_list(f)

# Lists all the cores and threads
total_threads = int(subprocess.check_output(['/usr/bin/nproc', '--all']).strip())

if args.anti:
    cpus = set(xrange(total_threads)) - cpus

if args.mask:
    # precision in hex digits that prints a 1 or 0 bit for every CPU in the system
    precision = (3 + total_threads) / 4
    mask = ("%0" + str(precision) + "x") % sum([2**i for i in cpus])
    print re.sub('([\dabcdef])(?=([\dabcdef]{8})+(?![\dabcdef]))', r'\1,', mask)
else:
    # sorted to ensure the set is the same string always
    # no eliding, it's just a full list with no hyphens
    print ','.join(str(f) for f in sorted(cpus))
