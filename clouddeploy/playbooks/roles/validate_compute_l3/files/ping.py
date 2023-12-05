from multiprocessing import Pool
import re
import sys
import subprocess

def ping_host(host):
    '''Function to ping host with count of 10'''

    ping_cmd = "/usr/bin/ping" if re.search(
        '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
        host) else "/usr/sbin/ping6"

    cmd = subprocess.Popen([ping_cmd, '-c', '10', host],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    out = cmd.communicate()[0]

    if not out or not re.search(r'received,.* 0% packet loss', out):
        return host

if __name__ == "__main__":
    host_list = sys.argv[1:]
    if host_list:
        p = Pool(len(host_list))
        failed_hosts = p.map(ping_host, host_list)
        for host in failed_hosts:
            if host:
                print host
