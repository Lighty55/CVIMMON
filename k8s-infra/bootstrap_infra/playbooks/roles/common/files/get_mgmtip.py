import netifaces
import sys

address_family = netifaces.AF_INET6 if (len(sys.argv) == 2 and
    sys.argv[1] == "ipv6") else netifaces.AF_INET

mgmt_ip = None
try:
    iface_name = "br_mgmt"
    mgmt_ip = netifaces.ifaddresses(iface_name)[address_family][0]['addr']
    if '%' in mgmt_ip:
        mgmt_ip = None
except (KeyError, ValueError):
    mgmt_ip = None

if mgmt_ip:
    print mgmt_ip
