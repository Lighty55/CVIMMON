#!/usr/bin/python
# -*- coding: utf-8 -*-

from distutils.dir_util import mkpath
from distutils.errors import DistutilsFileError
import json
from optparse import OptionParser, Option
import os
import select
import subprocess
import sys
import time


def display_js_log_line(line):
    ''' Example of a line following json format:
         {"thread_name": "MainThread",
         "extra": {},
         "process": 48,
         "relative_created": 3522740.1371002197,
         "module": "middleware",
         "message": "Matched GET /122e73e4e72a4f83a9842c702281e7d4/os-services",
         "hostname": "c43-control-2",
         "filename": "middleware.py",
         "levelno": 10,
         "lineno": 100,
         "asctime": "2017-11-03 00:11:57,639",
         "msg": "Matched %s",
         "args": ["GET /122e73e4e72a4f83a9842c702281e7d4/os-services"],
         "process_name": "MainProcess",
         "name": "routes.middleware",
         "thread": 106286288,
         "created": 1509667917.639013,
         "traceback": null,
         "msecs": 639.0130519866943,
         "funcname": "__call__",
         "pathname": "/usr/lib/python2.7/site-packages/routes/middleware.py",
         "levelname": "DEBUG"}
    '''
    if not line:
        return
    out = ""
    try:
        line_dic = json.loads(line)
        keyorder = ['asctime', 'hostname', 'filename', 'name', 'module', 'levelname', 'levelno', 'process_name', 'funcname', 'message', 'msg', 'args', 'traceback']
        for k in keyorder:
            out += str(line_dic[k]) + "  "
    except:
        print("Could not decode the json line(%s)" % line)
    try:
        print out
    except Exception as exc:
        raise sys.exit(exc)

def tail_n_lines_log_file(fp, num_lines):
    total_lines_wanted = int(num_lines)

    BLOCK_SIZE = 1024
    fp.seek(0, 2)
    block_end_byte = fp.tell()
    lines_to_go = total_lines_wanted
    block_number = -1
    blocks = [] # blocks of size BLOCK_SIZE, in reverse order starting
                # from the end of the file
    while lines_to_go > 0 and block_end_byte > 0:
        if (block_end_byte - BLOCK_SIZE > 0):
            # read the last block we haven't yet read
            fp.seek(block_number*BLOCK_SIZE, 2)
            blocks.append(fp.read(BLOCK_SIZE))
        else:
            # file too small, start from beginning
            fp.seek(0,0)
            # only read what was not read
            blocks.append(fp.read(block_end_byte))
        lines_found = blocks[-1].count('\n')
        lines_to_go -= lines_found
        block_end_byte -= BLOCK_SIZE
        block_number -= 1
    all_read_text = ''.join(reversed(blocks))
    #print('\n\n'.join(all_read_text.splitlines()[-total_lines_wanted:]))
    lines = all_read_text.splitlines()[-total_lines_wanted:]
    for l in lines:
        display_js_log_line(l)

def display_log_file(fp):
    try:
        while True:
            line = fp.readline()
            if not line:
                return;
            display_js_log_line(line)
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("Interrupted by the user")
        raise

def display_tail_log_file(filename):
    f = subprocess.Popen(['/usr/bin/tail','-F', '-n', '5', filename],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)

    while True:
        try:
            if p.poll(1):
                new_line = f.stdout.readline()
                if new_line:
                    display_js_log_line(new_line)
            time.sleep(0.1)
        except KeyboardInterrupt:
            print("Interrupted by the user")
            break

def create_log_file(log_file, dest_dir):
    if dest_dir[-1] == "/":
        dest_dir = dest_dir[:-1]
    l = os.path.splitext(os.path.basename(log_file.name))[0]
    dest_filename = l + ".log"
    if not os.path.exists(dest_dir):
        try:
           mkpath(dest_dir)
        except DistutilsFileError as e:
            raise sys.exit("Failed to create path(%s)" % dest_dir)
    try:
       path = os.path.join(dest_dir, dest_filename)
       print("Converting log file: %s into: %s" % (log_file.name, path))
       f = open(path, 'w')
       return f
    except Exception as e:
       msg = "Error[%s] Failed to create file: %s" % (e, path)
       raise sys.exit(msg)


def parse_args():
    parser = OptionParser(
        description="Python client for convert the json logs into a log format")
    parser.add_option("-f", "--file", dest="filename", metavar="FILE",
        help="path of the log file in json format (mandatory)")
    parser.add_option("-n", "--num-lines", action="store", dest="num_lines",
        help="display the last lines of a log file")
    parser.add_option("-t", "--tail", action="store_true", dest="tail",
        default=False, help="Indicates to tail-follow the json file")
    parser.add_option("-c", "--copy", dest="dest_path",
        help="directory path where to put an copy of the converted file")
    (opts, args) = parser.parse_args()
    print("Options: %s\n" % opts)
    if not args and opts and opts.filename:
        return opts
    # Error cases:
    if args:
        print("ERROR: Invalid Option\n")
    if not opts:
        print("Error: Please follow the format")
    if not opts.filename:
        print("Error: Please specify the filename")
    parser.print_help()
    sys.exit(1)


def main():
    opts = parse_args()
    log_file = opts.filename
    if not os.path.exists(log_file):
        print("Filename: %s doesn't exists" % log_file)
        sys.exit(1)
    if opts.num_lines:
        num_lines = int(opts.num_lines)

    fp = None
    sout = None
    orig_stdout = sys.stdout
    try:
       # Get source file
       fp = open(log_file, 'r')
       if opts.dest_path:
           sout = create_log_file(fp, opts.dest_path)
           if sout:
               sys.stdout = sout
       if not opts.num_lines and not opts.tail:
           display_log_file(fp)
       if opts.num_lines:
           tail_n_lines_log_file(fp, num_lines)
       if opts.tail:
          display_tail_log_file(log_file)
    finally:
       if fp:
           fp.close()
       if sys.stdout != orig_stdout:
           sys.stdout = orig_stdout
           if sout:
               sout.close()


if __name__ == '__main__':
    main()
