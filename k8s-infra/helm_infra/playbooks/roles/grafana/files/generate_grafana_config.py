#!/usr/bin/python
"""
This script generates grafana minimum config to deploy dashboards
"""

import filecmp
import yaml
import pytoml as toml
import os
import shutil
import socket
import sys
from optparse import OptionParser
from urlparse import urlparse

def is_valid_ipv6_address(address):
    '''Checks if IP v6 address is valid'''
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False

    return True

def copy_ldap_certs(new_file, grafana_ldap_path):
    """
    Check diff between file in opt path and the new path in setupfile.
    if there is no diff then continue else copy the new cert
    """

    grafana_ldap_path_file = os.listdir(grafana_ldap_path)
    if not grafana_ldap_path_file:
        shutil.copy(new_file, grafana_ldap_path)
    else:
        old_file = os.path.join(grafana_ldap_path, grafana_ldap_path_file[0])
        if not filecmp.cmp(new_file, old_file, shallow=False):
            shutil.copy(new_file, grafana_ldap_path)
            os.remove(old_file)
    return

def generate_ldap_config(ldap_servers_config, check_ldap = None, monitor=False):
    """
    Generate Ldap config toml file
    :return: ldap configuration
    """

    hosts = list()
    scheme = list()
    port = list()
    host_name = ""
    for elem in ldap_servers_config["ldap_uri"].split(","):
        url_elem = urlparse(elem)
        hosts.append(url_elem.hostname)
        port.append(url_elem.port)
        scheme.append(url_elem.scheme)

    host_name = hosts[0]

    # Check if hostname is a valid ipv6 address or not
    if is_valid_ipv6_address(host_name):
        host_name = '[{}]'.format(host_name)
    # Check if the ldap hosts have the same port. It fails in case all
    # ldap_uri elements don't have the same port
    ldap_schema = scheme[0]
    port_num = ""

    # Set default port to 389 if not defined in the setupdata
    if port[0] == None:
        port_num = 389
        if ldap_schema == "ldaps":
            port_num = 636

    else:
        port_num = port[0]

    # Create ldap config
    # group_mappings and servers.attributes are copied directly from the setup_data.yaml
    # ssl_skip_verify and start_tls are False for all cases
    use_ssl_check = ldap_servers_config.get("use_ssl", False)
    start_tls_check = ldap_servers_config.get("start_tls", False)
    root_ca_cert_path = ldap_servers_config.get("root_ca_cert", None)
    client_cert_path = ldap_servers_config.get("client_cert", None)
    client_key_path = ldap_servers_config.get("client_key", None)
    group_search_filter_check = ldap_servers_config.get("group_search_filter",
                                                        None)
    group_search_filter_user_attribute_check = ldap_servers_config.get(
        "group_search_filter_user_attribute", None)
    group_search_base_dns_check = ldap_servers_config.get(
        "group_search_base_dns", None)

    if check_ldap:
        group_mappings = check_ldap["ldap"]["group_mappings"]
    if monitor:
        group_mappings = setup_file["CVIMMONHA_CLUSTER_MONITOR"]["ldap"]["group_mappings"]
    ldap_config = {"servers": [{"attributes": ldap_servers_config["attributes"],
                                "host": "{}".format(host_name),
                                "port": port_num,
                                "search_base_dns": ldap_servers_config[
                                    "search_base_dns"],
                                "search_filter": ldap_servers_config[
                                    "search_filter"],
                                "start_tls": start_tls_check,
                                "use_ssl": use_ssl_check,
                                "group_mappings": group_mappings
                                }]}
    # bind_password can be absent in case that the bind_dn matches all possible users
    if "bind_password" in ldap_servers_config:
        ldap_config["servers"][0]["bind_password"] = ldap_servers_config[
            "bind_password"]

    if "bind_dn" in ldap_servers_config:
        ldap_config["servers"][0]["bind_dn"] = ldap_servers_config["bind_dn"]

    if use_ssl_check or root_ca_cert_path or client_cert_path or client_key_path:
        ldap_config["servers"][0]["ssl_skip_verify"] = False
        if not os.path.exists(grafana_ldap_path):
            os.makedirs(grafana_ldap_path)

    if root_ca_cert_path:
        rootca_cert_name = os.path.split(ldap_servers_config["root_ca_cert"])[
            -1]
        ldap_config["servers"][0]["root_ca_cert"] = os.path.join(
            ldap_cert_path_pod, rootca_cert_name)
        copy_ldap_certs(root_ca_cert_path, grafana_ldap_path)

    if client_cert_path:
        client_cert_name = os.path.split(ldap_servers_config["client_cert"])[-1]
        ldap_config["servers"][0]["client_cert"] = os.path.join(
            ldap_cert_path_pod, client_cert_name)
        copy_ldap_certs(client_cert_path, grafana_ldap_path)

    if client_key_path:
        client_key_path_name = \
        os.path.split(ldap_servers_config["client_key_path"])[-1]
        ldap_config["servers"][0]["client_key"] = os.path.join(
            ldap_cert_path_pod, client_key_path_name)
        copy_ldap_certs(client_key_path, grafana_ldap_path)

    if group_search_filter_check:
        ldap_config["servers"][0]["group_search_filter"] = ldap_servers_config[
            "group_search_filter"]
    if group_search_filter_user_attribute_check:
        ldap_config["servers"][0]["group_search_filter_user_attribute"] = \
        ldap_servers_config["group_search_filter_user_attribute"]
    if group_search_base_dns_check:
        ldap_config["servers"][0]["group_search_base_dns"] = \
        ldap_servers_config["group_search_base_dns"]

    return ldap_config

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-w", "--workspace", dest="workspace",
                      help="Path to workspace")
    parser.add_option("-d", "--destination", dest="destination",
                      help="Path to destination folder")
    parser.add_option("-n", "--namespace", dest="namespace",
                      help="Namespace of which ldap config needs to "
                           "be generated")
    parser.add_option("-m", "--monitor", action="store_true",
                      help="Monitor Namespace to configure ldap.")
    (options, args) = parser.parse_args()
    (options, args) = parser.parse_args()

    if options.namespace and options.monitor:
        print "--namespace and --monitor are mutually exclusive."
        sys.exit(1)

    with open(options.workspace + "/openstack-configs/setup_data.yaml", "r") as f:
        setup_data = f.read()
        setup_file = yaml.safe_load(setup_data)

    stack_name = ""
    if options.namespace:
        stack_name = options.namespace

    ldap_cert_path_pod = "/var/lib/grafana/"
    grafana_opt_path = "/opt/cisco/cvimmon-metros/{}/grafana/".format(stack_name)
    if options.monitor:
        grafana_opt_path = "/opt/cisco/cvimmon-k8s/k8s-cluster-monitor/grafana/"
    grafana_ldap_path = os.path.join(grafana_opt_path, "ldap_cert")
    ldap_cleanup_flag = 1

    # Generate Ldap Toml file if enabled for stack.
    ldap_config = dict()
    if options.namespace:
        for check_ldap in setup_file["cvim-mon-stacks"]:
            if "ldap" in check_ldap.keys() and check_ldap["name"] == stack_name:
                ldap_servers_config = check_ldap["ldap"]["domain_mappings"][0]
                ldap_config = generate_ldap_config(ldap_servers_config, check_ldap, False)
                ldap_cleanup_flag = 0

    elif options.monitor:
        if "CVIMMONHA_CLUSTER_MONITOR" in setup_file.keys():
            for ldap_mon in setup_file["CVIMMONHA_CLUSTER_MONITOR"]:
                if "ldap" in ldap_mon:
                    ldap_servers_config = \
                    setup_file["CVIMMONHA_CLUSTER_MONITOR"]["ldap"][
                        "domain_mappings"][0]
                    ldap_config = generate_ldap_config(ldap_servers_config, "", options.monitor)
                    ldap_cleanup_flag = 0

    if ldap_cleanup_flag:
        ldap_toml_file = os.path.join(grafana_opt_path, "ldap_config.toml")
        if os.path.exists(grafana_ldap_path):
            shutil.rmtree(grafana_ldap_path)
        if os.path.exists(ldap_toml_file):
                os.remove(ldap_toml_file)

    if ldap_config:
        with open(options.destination + "/ldap_config.toml", "w") as outfile:
                    toml.dump(ldap_config, outfile)


    if options.namespace:
        grafana_config = dict()
        # For central cvim-mon this key needs to be true so all the
        # dashboards can change to central format.
        grafana_config['CENTRAL_CVIM_MON'] = True

        # For central deployment, these values are set to None in the central case,
        # this is because they are related to the pod level deployment.
        grafana_config["PODTYPE"] = None
        grafana_config["IS_INTEL_NIC"] = None
        grafana_config["IS_VPP_ENABLED"] = None
        grafana_config["IS_OVS_ENABLED"] = None
        grafana_config["BLOCK_STORAGE"] = None
        grafana_config["IS_TELEGRAF_HAPROXY_ENABLED"] = None
        grafana_config["IS_TELEGRAF_RABBITMQ_ENABLED"] = None
        grafana_config["IS_TELEGRAF_CEPH_ENABLED"] = None

        # The config is save in the same path for both central and local
        with open('/var/lib/cvim_mon/grafana_config.yaml', 'w') as f:
            yaml.dump(grafana_config, f, default_flow_style=False)
