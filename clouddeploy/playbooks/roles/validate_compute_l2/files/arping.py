from multiprocessing import Pool
import re
import sys
import subprocess

global interface_name
global interface_address

def arping_host(host):
    """
    arping list of hosts
    :param host:
    :return:
    """
    global interface_name
    arping_cmd = "/usr/sbin/arping"
    cmd = subprocess.Popen([arping_cmd, '-c', '2', '-I', interface_name, '-w', '6',  host],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    out = cmd.communicate()[0]
    if not out or re.search(r'Received 0 response(s)', out):
        return host

if __name__ == "__main__":
    interface_address  = sys.argv[1]
    interface_name  = sys.argv[2]
    host_list = sys.argv[3:]
    arping_hosts = [ip for ip in host_list if not ip == interface_address]
    if arping_hosts:
        p = Pool(len(arping_hosts))
        failed_hosts = p.map(arping_host, arping_hosts)
        for host in failed_hosts:
            if host:
                print host