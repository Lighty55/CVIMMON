from threading import Thread
import threading
import subprocess
import sys
import Queue
import re

print_lock = threading.Lock()


def ping_host(ipaddr_queue):
    while True:
        try:
            target_ip = str(ipaddr_queue.get())
            ping_cmd = ['/usr/bin/ping', '-c5', '-M', 'do', '-s', mtu_size, '-I', src_intf, target_ip]
            ping_proc = subprocess.Popen(ping_cmd,
                                         shell=False,
                                         stdout=subprocess.PIPE)
            ping_out = ping_proc.communicate()[0]
            if not ping_out or not re.search(r'received,.* 0% packet loss', ping_out):
                reply_queue.put(target_ip)
        except Exception as e:
            with print_lock:
                print e.message
        finally:
            ipaddr_queue.task_done()

if __name__ == "__main__":
    mtu_size = sys.argv[1]
    src_intf = sys.argv[2]
    host_list = sys.argv[3:]

    if host_list and len(host_list) > 0:
        max_threads = 200
        if len(host_list) < max_threads:
            max_threads = len(host_list)
        ipaddr_queue = Queue.Queue()
        reply_queue = Queue.Queue()

        for ip in host_list:
            ipaddr_queue.put(ip)

        for i in range(max_threads):
            t = Thread(target=ping_host, args=(ipaddr_queue,))
            t.setDaemon(True)
            t.start()

        # Wait until all pings complete
        ipaddr_queue.join()

        # Process the reply queue
        while True:
            try:
                failed_hosts = reply_queue.get_nowait()
                print failed_hosts
            except Queue.Empty:
                break