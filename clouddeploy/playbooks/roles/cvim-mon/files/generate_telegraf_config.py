#!/usr/bin/env python

#  Copyright 2017, 2018 Cisco Systems, Inc.  All rights reserved.
import argparse
from argparse import RawTextHelpFormatter
import os
import socket
import pytoml
import yaml
import logging
import json
import base64
import ipaddress
import subprocess

_product_name = 'cvim_mon'


def setup(mute_stdout=False):
    # logging.basicConfig()
    if mute_stdout:
        handler = logging.NullHandler()
    else:
        formatter_str = '%(asctime)s %(levelname)s %(message)s'
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(formatter_str))

    # Add handler to logger
    logger = logging.getLogger(_product_name)
    logger.addHandler(handler)
    set_level()
    # disable unnecessary information capture
    logging.logThreads = 0
    logging.logProcesses = 0
    # to make sure each log record does not have a source file name attached
    # pylint: disable=protected-access
    logging._srcfile = None
    # pylint: enable=protected-access


def add_file_logger(logfile):
    if logfile:
        file_formatter_str = '%(asctime)s %(levelname)s %(message)s'
        file_handler = logging.FileHandler(logfile, mode='w')
        file_handler.setFormatter(logging.Formatter(file_formatter_str))
        logger = logging.getLogger(_product_name)
        logger.addHandler(file_handler)


def set_level(debug=False):
    log_level = logging.DEBUG if debug else logging.INFO
    logger = logging.getLogger(_product_name)
    logger.setLevel(log_level)


def getLogger():
    logger = logging.getLogger(_product_name)
    return logger


LOG = getLogger()


class CVIMMon(object):

    def __init__(self, config_file):
        self.cvim_mon_config = None
        self.config = None
        self.cobbler_data = None
        self.setup_data = None
        self.hosts = None
        self.podtype = None
        self.is_vpp_enabled = None
        self.block_storage = True

        self.telegraf_confs = {}
        self.intervals = None

        self.testbed_name = None

        self.__read_confs(config_file=config_file)
        self.__read_telegraf_confs()
        self.__read_telegraf_intervals()
        self.__read_testbed_name()
        self.__read_podtype()
        self.__read_api_ip()
        self.__read_ui_access()

        # Init default telegraf plugins intervals, in case an entry is missing
        # in the telegraf_plugins_intervals.yaml file
        self.default_telegraf_plugins_intervals = {
            'CEPH': "1m",
            'DISKMON': "12h",
            'DOCKER': "1m",
            'HAPROXY': "4m",
            'LIBVIRT': "1m",
            'OPENSTACK': "4m",
            "RABBITMQ": 0
        }

        # Init CPU group array, it will be used on creating source groups
        self.cpu_groups = {
            'control': set(),
            'block_storage': set(),
            'compute': set(),
            'aio': set(),
            'hc': set(),
            'cephosd': set(),
            "cephcontrol": set(),
            'edge': set(),
            'nano': set()
        }
        # Init node group array, it will be used on creating group level metrics
        self.node_groups = self.setup_data['ROLES']
        # if any group is null, make it an empty list
        for gr in self.node_groups:
            if self.node_groups[gr] is None:
                self.node_groups[gr] = []

        # if cephosd, cephcontrol, control, compute or block_storage are not defined,
        # make them empty list
        for gr in ['control', 'compute', 'block_storage', 'cephcontrol', 'cephosd']:
            if gr not in self.node_groups:
                self.node_groups[gr] = []

        if 'block_storage' not in self.node_groups:
            self.block_storage = False

        extern_servers = self.setup_data.get('CVIM_MON').get('external_servers', None)
        if extern_servers:
            self.node_groups['external'] = extern_servers

        self.__update_node_groups()

    def __read_confs(self, config_file):

        # Read config data and mercury configuration files
        self.config = read_file(path=config_file, is_yaml=True)

        missing_file = False
        try:
            self.cvim_mon_config = read_file(path=self.config['cvim_mon_config_file'], is_yaml=True)
        except IOError:
            missing_file = self.config['cvim_mon_config_file']
        try:
            self.hosts = read_file(path="/etc/hosts", is_yaml=False)
        except IOError:
            missing_file = "/etc/hosts"
        try:
            self.cobbler_data = read_file(path=self.config['cobbler_file'], is_yaml=True)
        except IOError:
            missing_file = self.config['cobbler_file']
        try:
            self.setup_data = read_file(path=self.config['setup_file'], is_yaml=True)
        except IOError:
            missing_file = self.config['setup_file']
        try:
            self.telegraf_plugins_intervals = read_file(path=self.config['intervals_file'],
                                                        is_yaml=True)
        except IOError:
            missing_file = self.config['intervals_file']

        if missing_file:
            LOG.error("The configuration file at %s cannot be opened. If you see this error at "
                      "bootstraping you can safely ignore it as container will be restarted after "
                      "this file is created at step 7.", missing_file)
            exit(-1)

    def __read_telegraf_conf(self, base_path, plugin_config_name):
        # Apply new naming convention and set the telegraf config from file
        telegraf_config_name = plugin_config_name.replace('-', '_')
        full_path = "{}/{}.conf".format(base_path.rstrip("/"), plugin_config_name.lstrip("/"))
        self.telegraf_confs[telegraf_config_name] = read_file(path=full_path)

    def __read_telegraf_confs(self):
        # Read telegraf configuration templates
        base = self.config['plugin_configs_base']
        for plugin_config in ('ceph', 'cvim_proxy', 'net-stats', 'default', 'diskmon',
                              'docker', 'etcd', 'exec-mgmt', 'http_response',
                              'http_response_cvim_mon', 'libvirt', 'net', 'openstack',
                              'prometheus', 'rabbitmq', 'x509_cert', 'ipmi', 'hugepages',
                              'external_version'):
            self.__read_telegraf_conf(base, plugin_config)

    def __read_telegraf_intervals(self):
        self.intervals = {
            'high': self.cvim_mon_config.get('HIGH_FREQUENCY_INTERVAL', "15s"),
            'med': self.cvim_mon_config.get('MEDIUM_FREQUENCY_INTERVAL', "30s"),
            'low': self.cvim_mon_config.get('LOW_FREQUENCY_INTERVAL', "1m")
        }

    def __read_testbed_name(self):
        self.testbed_name = self.cvim_mon_config.get('PODNAME', '')

    def __read_podtype(self):
        # PODTYPE is an optional key in CVIM setup_data.yaml
        # If not defined, defaults to 'fullon'
        self.podtype = self.setup_data.get('PODTYPE', 'fullon')

    def __read_ui_access(self):
        self.ui_access = self.cvim_mon_config.get('CVIM_MON_UI_ACCESS', '')

    def __read_api_ip(self):
        ext_api_fqdn = self.setup_data.get("MGMTNODE_EXTAPI_FQDN", "")
        if ext_api_fqdn:
            self.api_ips = [ext_api_fqdn]
            return

        api_ipv4 = self.cvim_mon_config.get('API_IPv4', '')
        api_ipv6 = self.cvim_mon_config.get('API_IPv6', '')
        if api_ipv6:
            api_ipv6 = "[" + api_ipv6 + "]"
        self.api_ips = [api_ipv4, api_ipv6]

    def __update_node_groups(self):
        #Nanopod case: Only one server to act as control and compute node
        if len(self.node_groups['control']) == 1:
            self.node_groups['nano'] = list(set(self.node_groups['control']).intersection(
            self.node_groups['compute']))

            nano_set = set(self.node_groups['nano'])
            # Remove edge nodes from other groups
            if self.node_groups['nano']:
                self.node_groups['compute'] = list(
                    set(self.node_groups['compute']).difference(nano_set))
                self.node_groups['control'] = list(
                    set(self.node_groups['control']).difference(nano_set))
                self.node_groups['block_storage'] = list(
                    set(self.node_groups['block_storage']).difference(nano_set))
            return
        # Micropod case: (A node having all roles) and HC case: (nodes with compute/storage)
        self.node_groups['hc'] = []
        self.node_groups['edge'] = []
        self.node_groups['aio'] = set(self.node_groups['control']).intersection(
            self.node_groups['block_storage'])
        self.node_groups['aio'] = list(
            self.node_groups['aio'].intersection(self.node_groups['compute']))
        # Remove aio nodes from other groups
        if self.node_groups['aio']:
            all_set = set(self.node_groups['aio'])
            self.node_groups['compute'] = list(set(self.node_groups['compute']).difference(all_set))
            self.node_groups['control'] = list(set(self.node_groups['control']).difference(all_set))
            self.node_groups['block_storage'] = list(
                set(self.node_groups['block_storage']).difference(all_set))
        else:
            # EDGE case: (nodes with control/compute)
            self.node_groups['edge'] = list(set(self.node_groups['compute']).intersection(
                self.node_groups['control']))
            edge_set = set(self.node_groups['edge'])
            # Remove edge nodes from other groups
            if self.node_groups['edge']:
                self.node_groups['compute'] = list(
                    set(self.node_groups['compute']).difference(edge_set))
                self.node_groups['control'] = list(
                    set(self.node_groups['control']).difference(edge_set))
                self.node_groups['block_storage'] = list(
                    set(self.node_groups['block_storage']).difference(edge_set))

            self.node_groups['hc'] = list(set(self.node_groups['compute']).intersection(
                self.node_groups['block_storage']))
            hc_set = set(self.node_groups['hc'])
            # Remove hc nodes from other groups
            if self.node_groups['hc']:
                self.node_groups['compute'] = list(
                    set(self.node_groups['compute']).difference(hc_set))
                self.node_groups['control'] = list(
                    set(self.node_groups['control']).difference(hc_set))
                self.node_groups['block_storage'] = list(
                    set(self.node_groups['block_storage']).difference(hc_set))
        # Central Ceph case (cephosd and cephcontrol roles)
        self.node_groups['ceph-control-osd'] = set(self.node_groups['cephcontrol']).intersection(
            self.node_groups['cephosd'])
        if self.node_groups['ceph-control-osd']:
            ceph_set = set(self.node_groups['ceph-control-osd'])
            self.node_groups['cephosd'] = list(
                set(self.node_groups['cephosd']).difference(ceph_set))
            self.node_groups['cephcontrol'] = list(
                set(self.node_groups['cephcontrol']).difference(ceph_set))

    def __create_agent_config(self, hostname):
        return pytoml.dumps({
            "agent": {
                "interval": self.intervals['high'],
                "round_interval": True,
                "metric_batch_size": 1000,
                "metric_buffer_limit": 10000,
                "collection_jitter": "0s",
                "flush_interval": self.intervals['high'],
                "flush_jitter": "0s",
                "precision": "",
                "debug": False,
                "quiet": False,
                "logfile": "",
                "hostname": hostname,
                "omit_hostname": False
            }
        })

    def __create_node_type_config(self, node_type):
        return pytoml.dumps({
            "processors": [{
                "override": [{
                    # Do NOT produce node_type tag for "up" metric,
                    # and cvim-related metrics (version, resp_size)
                    "namedrop": ["up", "cvim"],
                    "tags": {
                        "node_type": node_type
                    }
                }]
            }]
        }).replace("[[processors]]\n", "").replace("\n\n", "\n")

    def __telegraf_plugin_enabled(self, plugin_name):
        try:
            return self.telegraf_plugins_intervals[plugin_name] != 0
        except KeyError:
            # Unless the plugin is explicitly disabled, it should be enabled
            # with the default interval, even if the entry is missing
            # in telegraf_plugins_intervals.yaml file.
            self.telegraf_plugins_intervals[plugin_name] = \
                self.default_telegraf_plugins_intervals[plugin_name]
            return self.default_telegraf_plugins_intervals[plugin_name] != 0

    def __create_ceph_config(self):
        if self.__telegraf_plugin_enabled('CEPH'):
            return self.telegraf_confs['ceph'].replace(
                "%%INTERVAL%%", self.telegraf_plugins_intervals['CEPH'])
        return ""

    def __create_openstack_config(self, node_type):
        if self.__telegraf_plugin_enabled('OPENSTACK'):
            with open('/root/openstack-configs/openrc', 'r') as f:
                openrc_content = f.readlines()
            openrc = {}
            lines = [i.rstrip()[7:] for i in openrc_content]
            for l in lines:
                words = l.split('=')
                if len(words) > 1:
                    openrc[words[0]] = words[1]
            openstack_config = self.telegraf_confs['openstack'].replace(
                "%%INTERVAL%%", self.telegraf_plugins_intervals['OPENSTACK'])
            openstack_config = openstack_config.replace("%%DOMAIN%%",
                openrc.get('OS_PROJECT_DOMAIN_NAME', ''))
            openstack_config = openstack_config.replace("%%PROJECT%%",
                openrc.get('OS_PROJECT_NAME', ''))
            openstack_config = openstack_config.replace("%%USERNAME%%",
                openrc.get('OS_USERNAME', ''))
            openstack_config = openstack_config.replace("%%PASSWORD%%",
                openrc.get('OS_PASSWORD', ''))
            if node_type is "mgmt":
                # If the plugin is running on mgmt node, it should use external
                # endpoint, and the proper CA certificate
                openstack_config = openstack_config.replace("%%CA_CERT%%",
                    openrc.get('OS_CACERT', ''))
                openstack_config = openstack_config.replace("%%IDENTITY_ENDPOINT%%",
                    openrc.get('OS_AUTH_URL', ''))
            else:
                # If the plugin is running on aio/controller node, it should use internal
                # endpoint. Providing CA certificate is not required in such case
                try:
                    openstack_config = openstack_config.replace("%%IDENTITY_ENDPOINT%%",
                        'http://' + self.setup_data['internal_lb_vip_address'] + ':5000/v3')
                except KeyError:
                    return ""
            return openstack_config
        return ""

    def __create_cpu_tag_config(self, node=None, node_type=None):
        if "mgmt" in node_type:
            return pytoml.dumps({
                "processors": [{
                    "override": [{
                        "namepass": ["cpu"],
                        "tags": {
                            "tag": "mgmt"
                        }
                    }]
                }]
            }).replace("[[processors]]\n", "").replace("\n\n", "\n")

        try:
            ceph_osd_cpuset_cpus = parse_cpu_numbers(
                node['nfv_dict']['ansible_inventory_dict']['ceph_osd_cpuset_cpus'].split(","))

        except KeyError:
            ceph_osd_cpuset_cpus = []

        try:
            hostcpus = parse_cpu_numbers(
                node['nfv_dict']['ansible_inventory_dict']['hostcpus'].split(","))
        except KeyError:
            hostcpus = []

        try:
            vswitchcpus = parse_cpu_numbers(
                node['nfv_dict']['ansible_inventory_dict']['vswitchcpus'].split(","))
        except KeyError:
            vswitchcpus = []

        tags = {}
        if ceph_osd_cpuset_cpus:
            ceph = []
            for cpu in ceph_osd_cpuset_cpus:
                ceph.append("cpu" + str(cpu))
            tags["ceph"] = ceph

        if hostcpus:
            host = []
            for cpu in hostcpus:
                host.append("cpu" + str(cpu))
            tags["host"] = host

        if vswitchcpus:
            self.is_vpp_enabled = vswitchcpus
            vpp = []
            for cpu in vswitchcpus:
                vpp.append("cpu" + str(cpu))
            tags["vpp"] = vpp

        # Default tag
        if self.podtype != "ceph":
            config = pytoml.dumps({
                "processors": [{
                    "override": [{
                        "namepass": ["cpu"],
                        "tags": {
                            "tag": "vm"
                        }
                    }]
                }]
            }).replace("[[processors]]\n", "").replace("\n\n", "\n")
        else:
            config = pytoml.dumps({
                "processors": [{
                    "override": [{
                        "namepass": ["cpu"],
                        "tags": {
                            "tag": "ceph"
                        }
                    }]
                }]
            }).replace("[[processors]]\n", "").replace("\n\n", "\n")

        for tag, cpus in tags.items():
            config += pytoml.dumps({
                "processors": [{
                    "override": [{
                        "namepass": ["cpu"],
                        "tagpass": {
                            "cpu": cpus,
                        },
                        "tags": {
                            "tag": tag
                        }
                    }]
                }]
            }).replace("[[processors]]\n", "").replace("\n\n", "\n")
        return config

    def __create_default_config(self):
        return self.telegraf_confs['default']

    def __create_docker_config(self):
        if self.__telegraf_plugin_enabled('DOCKER'):
            return self.telegraf_confs['docker'].replace(
                "%%INTERVAL%%", self.telegraf_plugins_intervals['DOCKER'])
        return ""

    def __create_net_config(self, node_type):
        # Check IC type (Intel NIC or Cisco VIC)
        try:
            intel_nic = self.setup_data['INTEL_NIC_SUPPORT']
        except KeyError:
            intel_nic = False
        if "mgmt" in node_type:
            network_list = '"br_mgmt"'
        elif "compute" in \
                node_type or "hc" in node_type:
            if intel_nic:
                network_list = ','.join(
                    get_interface_list(int_dict=self.config['intel_nic_interfaces'][
                        'compute']))
            else:
                network_list = ','.join(
                    get_interface_list(int_dict=self.config['cisco_vic_interfaces'][
                        'compute']))
        elif "control" in node_type or "aio" in node_type or "edge" in node_type or "nano" in node_type:
            if intel_nic:
                network_list = ','.join(
                    get_interface_list(int_dict=self.config['intel_nic_interfaces'][
                        'control']))
            else:
                network_list = ','.join(
                    get_interface_list(int_dict=self.config['cisco_vic_interfaces'][
                        'control']))
        elif 'block_storage' in node_type:
            if intel_nic:
                network_list = ','.join(
                    get_interface_list(int_dict=self.config['intel_nic_interfaces'][
                        'storage']))
            else:
                network_list = ','.join(
                    get_interface_list(int_dict=self.config['cisco_vic_interfaces'][
                        'storage']))
        elif 'cephcontrol' in node_type:
            if intel_nic:
                network_list = ','.join(
                    get_interface_list(int_dict=self.config['intel_nic_interfaces'][
                        'ceph']))
            else:
                network_list = ','.join(
                    get_interface_list(int_dict=self.config['cisco_vic_interfaces'][
                        'ceph']))
        elif 'cephosd' in node_type:
            if intel_nic:
                network_list = ','.join(
                    get_interface_list(int_dict=self.config['intel_nic_interfaces'][
                        'ceph']))
            else:
                network_list = ','.join(
                    get_interface_list(int_dict=self.config['cisco_vic_interfaces'][
                        'ceph']))
        else:
            LOG.error('Unexpected node name %s', node_type)
            return ""
        return self.telegraf_confs['net'].replace("%%NETWORK_LIST%%", "[{}]".format(
            network_list))

    def __create_haproxy_config(self, expected="3"):
        if self.__telegraf_plugin_enabled('HAPROXY'):
            protocol = "http"
            try:
                config = {
                    "inputs": [{
                        "haproxy": [{
                            "servers": ["{}://haproxy:{}@{}:1936".format(
                                protocol, self.cvim_mon_config.get('HAPROXY_PASSWORD', ''),
                                self.setup_data['internal_lb_vip_address'])],
                            "interval": self.telegraf_plugins_intervals["HAPROXY"],
                            "tags": {
                                "expected": expected
                            }
                        }]
                    }]
                }
            except KeyError:
                return ""
            return pytoml.dumps(config).replace("[[inputs]]\n", "").replace("\n\n", "\n")
        return ""

    def __create_prometheus_config(self):
        return self.telegraf_confs['prometheus'].replace("%%EXPIRATION_INTERVAL%%", "5m")

    def __create_rabbitmq_config(self, server_ip):
        if self.__telegraf_plugin_enabled('RABBITMQ'):
            rabbitmq_conf = self.telegraf_confs['rabbitmq'].replace("%%URL%%",
                                                                    "http://{}:15672".format(
                                                                        server_ip))
            rabbitmq_conf = rabbitmq_conf.replace(
                "%%PASSWORD%%", self.cvim_mon_config.get('RABBITMQ_PASSWORD', ''))
            return rabbitmq_conf.replace("%%INTERVAL%%",
                                         self.telegraf_plugins_intervals["RABBITMQ"])
        return ""

    def __create_net_stats_config(self, node_type):
        if not self.is_vpp() and not self.is_ovs():
            return ""

        net_stats_node_type = None
        if any(("aio" in node_type, "edge" in node_type, "compute" in node_type and "control" in node_type)):
            net_stats_node_type = "aio"
        elif "compute" in node_type or "hc" in node_type:
            net_stats_node_type = "compute"
        elif "control" in node_type:
            net_stats_node_type = "control"

        if net_stats_node_type:
            return self.telegraf_confs.get("net_stats", "").replace("%%NODE_TYPE%%", net_stats_node_type)
        return ""

    def __create_libvirt_config(self, node_type):
        if self.__telegraf_plugin_enabled('LIBVIRT'):
            if any(t in node_type for t in ("compute", "aio", "hc", "edge", "external", "nano")):
                return self.telegraf_confs['libvirt'].replace(
                    "%%INTERVAL%%", self.telegraf_plugins_intervals['LIBVIRT'])
        return ""

    def __create_x509_cert_config(self, node_type):
        if (any(t in node_type for t in ("control", "aio", "edge", "external", "nano")) and
                ("external_lb_vip_tls" in self.setup_data and
                 self.setup_data["external_lb_vip_tls"])):
            x509_conf = self.telegraf_confs["x509_cert"].replace("%%CERT_PATH%%",
                                                                 "/docker/haproxy/haproxy.pem")
            x509_conf = x509_conf.replace("%%TLS_SKIP%%", "false")
            return x509_conf
        elif node_type == "mgmt":
            x509_conf = self.telegraf_confs["x509_cert"].replace("%%CERT_PATH%%",
                                                                 "/var/www/mercury/mercury.crt")
            x509_conf = x509_conf.replace("%%TLS_SKIP%%", "true")
            return x509_conf
        return ""

    def __create_http_response_config(self):
        config = ""
        RESTAPI_PASSWORD = get_Rest_API_pass()
        RESTAPI_token = generate_token(RESTAPI_PASSWORD)
        KIBANA_token  = generate_token(KIBANA_PASSWORD)
        CVIM_token    = generate_token(CVIM_MON_SERVER_PASSWORD)
        if self.setup_data.get("MGMTNODE_EXTAPI_REACH", '') is not False:
            for ip in self.api_ips:
                if ip:
                    ip_ver = "_IPv4"
                    if ":" in ip:
                        ip_ver = "_IPv6"
                    config += self.telegraf_confs["http_response"].replace(
                        "%%API_IP%%", ip).replace("%%IP_VER%%", ip_ver).replace(
                            "%%RESTAPI_TOKEN%%", RESTAPI_token).replace("%%KIBANA_TOKEN%%", KIBANA_token)
                    if self.ui_access:
                        config += self.telegraf_confs["http_response_cvim_mon"].replace(
                            "%%API_IP%%", ip).replace("%%IP_VER%%", ip_ver).replace(
                                "%%CVIM_SERVER_TOKEN%%", CVIM_token)
        return config

    def __create_cvim_proxy_config(self, node_name):
        targets = set()
        targets.add(socket.gethostname())
        for node_group in self.node_groups:
            if node_group != 'external':
                for node in self.node_groups[node_group]:
                    targets.add(node)
            else:
                extern_nodes = self.get_external_proxy_targets()
                for node in extern_nodes:
                    targets.add(node)
        target_list = '", "'.join(targets)
        if self.podtype != "ceph":
            cvim_proxy_conf = self.telegraf_confs['cvim_proxy'].replace("%%PROXY_LISTEN_IP%%",
                self.__get_node_ip_address(node_name))
        else:
            cvim_proxy_conf = self.telegraf_confs['cvim_proxy'].replace("%%PROXY_LISTEN_IP%%",
                "[::]")
            cvim_proxy_conf = cvim_proxy_conf.replace("%%TLS_CERT%%",
                                                      "/etc/ssl/certs/cvim_proxy.crt")
            cvim_proxy_conf = cvim_proxy_conf.replace("%%TLS_KEY%%",
                                                      "/etc/ssl/certs/cvim_proxy.key")
        cvim_proxy_conf = cvim_proxy_conf.replace("%%PASSWORD%%",
            self.cvim_mon_config.get('CVIM_MON_PROXY_PASSWORD', ''))
        cvim_proxy_conf = cvim_proxy_conf.replace("%%TARGET_LIST%%", target_list)
        return cvim_proxy_conf

    def get_external_proxy_targets(self):
        extern_server_list = []
        extern_servers = self.setup_data.get('CVIM_MON').get('external_servers', None)
        if extern_servers:
            for server in extern_servers:
                if ':' in server:
                    server = '[' + server + ']'
                extern_server_list.append(server)
        return extern_server_list

    def __create_etcd_config(self):
        if self.is_vpp():
            return self.telegraf_confs["etcd"]
        return ""

    def __create_diskmon_config(self):
        if self.__telegraf_plugin_enabled('DISKMON'):
            return self.telegraf_confs['diskmon'].replace(
                "%%INTERVAL%%", self.telegraf_plugins_intervals['DISKMON'])
        return ""

    def __get_node_ip_address(self, node_name, mode="v4"):
        found_node_ip4 = None
        for line in self.hosts.split("\n"):
            if node_name in line:
                node_ip = line.split(" ")[0]
                # Now check for the valid mode here
                if mode == "v6":
                   try:
                       ipaddress.IPv6Address(unicode(node_ip))
                       return "[{}]".format(node_ip)
                   except:
                       # Not a valid ipv6 address
                       # This is a V4 ip so track it as best ip
                       try:
                           ipaddress.IPv4Address(unicode(node_ip))
                           found_node_ip4 = node_ip
                       except:
                           pass
                else:
                    try:
                        ipaddress.IPv4Address(unicode(node_ip))
                        return node_ip
                    except:
                       # Not a valid IPV4Address
                       pass
        # If it comes here it only found an IPV4 so return it
        if found_node_ip4:
            return found_node_ip4
        return "localhost"

    def __get_external_telegraf_version(self):
        return self.telegraf_confs['external_version']

    def __create_ipmi_config(self):
        return self.telegraf_confs['ipmi']

    def __create_hugepages_config(self):
        return self.telegraf_confs['hugepages']

    def create_telegraf_confs(self):
        # Generate telegraf configuration files for nodes
        for node_group in self.node_groups:
            for node_name in self.node_groups[node_group]:

                LOG.debug("Generating telegraf configuration file for node %s", node_name)
                telegraf_config = self.__create_prometheus_config()
                telegraf_config += self.__create_default_config()
                telegraf_config += self.__create_diskmon_config()
                telegraf_config += self.__create_ipmi_config()
                if node_group != 'external':
                    telegraf_config += self.__create_docker_config()
                    telegraf_config += self.__create_cpu_tag_config(node=self.cobbler_data[node_name],
                                                                    node_type=node_group)
                telegraf_config += self.__create_agent_config(hostname=node_name)
                telegraf_config += self.__create_node_type_config(node_type=node_group)
                telegraf_config += self.__create_net_config(node_type=node_group)
                telegraf_config += self.__create_x509_cert_config(node_type=node_group)
                if self.podtype != "ceph":
                    telegraf_config += self.__create_net_stats_config(node_type=node_group)
                    telegraf_config += self.__create_libvirt_config(node_type=node_group)
                # Enable hugepages on all nodes except storage and mgmt (for both OVS and VPP)
                if node_group != 'block_storage':
                    telegraf_config += self.__create_hugepages_config()

                #All nodes that run the control function (controller, aio, edge,nano)
                if node_group in ["control", "aio", "edge", "nano"]:
                    #Check for other storage backends
                    if ('STORE_BACKEND' in self.setup_data and
                            self.setup_data['STORE_BACKEND'] == "ceph" and
                            self.podtype != "edge" and not self.has_remote_storage()) or \
                            self.podtype == "ceph":
                        telegraf_config += self.__create_ceph_config()
                    if self.podtype != "ceph":
                        telegraf_config += self.__create_rabbitmq_config(
                            server_ip=self.__get_node_ip_address(node_name=node_name,mode="v6"))
                    telegraf_config += self.__create_etcd_config()
                    if self.is_central_cvim_mon():
                        telegraf_config += self.__create_cvim_proxy_config(node_name=node_name)
                        if self.podtype != "ceph":
                            telegraf_config += self.__create_openstack_config(node_type=node_group)
                            if "nano" in node_group:
                                telegraf_config += self.__create_haproxy_config(expected="1")
                            else:
                                telegraf_config += self.__create_haproxy_config(expected="3")

                if node_group == 'external':
                    telegraf_config += self.__create_cpu_tag_config(node_type="mgmt")
                    telegraf_config += self.__get_external_telegraf_version()
                    node_name = node_group

                telegraf_config_path = self.config['config_folder'] + node_name + ".conf"
                # Save telegraf config.
                with open(telegraf_config_path, 'w') as node_config:
                    node_config.write(telegraf_config)
                os.chmod(telegraf_config_path, 0o600)

                if node_group == 'external':
                    break

        # Do mgmt node separately so that ansible can understand job is finished
        LOG.debug("Generating telegraf configuration file for node %s", "mgmt node")
        mgmt_name = socket.gethostname()
        telegraf_config = self.__create_prometheus_config()
        telegraf_config += self.__create_default_config()
        if not self.is_virtual_mgmt():
            telegraf_config += self.__create_diskmon_config()
            telegraf_config += self.__create_ipmi_config()
        telegraf_config += self.__create_docker_config()
        telegraf_config += self.__create_agent_config(hostname=mgmt_name)
        telegraf_config += self.__create_node_type_config(node_type="mgmt")
        telegraf_config += self.__create_cpu_tag_config(node_type="mgmt")
        telegraf_config += self.__create_net_config(node_type="mgmt")
        telegraf_config += self.__create_x509_cert_config(node_type="mgmt")
        telegraf_config += self.__create_http_response_config()
        telegraf_config += self.telegraf_confs['exec_mgmt']
        if self.podtype != "ceph" and not self.is_central_cvim_mon():
            telegraf_config += self.__create_openstack_config(node_type="mgmt")
            if self.node_groups.get("nano"):
                telegraf_config += self.__create_haproxy_config(expected="1")
            else:
                telegraf_config += self.__create_haproxy_config(expected="3")
        telegraf_config_path = self.config['config_folder'] + "mgmt" + ".conf"
        with open(telegraf_config_path, 'w') as node_config:
            node_config.write(telegraf_config)
        os.chmod(telegraf_config_path, 0o600)

        LOG.info("Telegraf configurations of all nodes of %s pod are saved.", self.testbed_name)

    def is_intel_nic(self):
        try:
            return self.setup_data['INTEL_NIC_SUPPORT']
        except KeyError:
            return False

    def is_central_cvim_mon(self):
        try:
            return self.setup_data['CVIM_MON']['central']
        except KeyError:
            return False

    def has_remote_storage(self):
        if 'CINDER_CLIENT_KEY' in self.setup_data or \
             'GLANCE_CLIENT_KEY' in self.setup_data:
            return True
        return False

    def _check_mechanism_drivers(self, name):
        return name.lower() in self.setup_data.get('MECHANISM_DRIVERS', '').lower()

    def is_vpp(self):
        return self._check_mechanism_drivers('vpp')

    def is_ovs(self):
        return self._check_mechanism_drivers('openvswitch')

    def is_virtual_mgmt(self):
        try:
            output = subprocess.check_output('/usr/bin/lscpu')
            for line in output.splitlines():
                if "Hypervisorvendor:KVM" in line.replace(" ", ""):
                    return True
            return False
        except subprocess.CalledProcessError:
            return False

    def get_interfaces(self):
        return self.config['intel_nic_interfaces'] if self.is_intel_nic() else self.config[
            'cisco_vic_interfaces']


def get_interface_list(int_dict):
    all_ints = []
    for net in int_dict:
        all_ints.extend(['"{}"'.format(interface) for interface in int_dict[net]])
    return all_ints


def get_intersection(str1, str2):
    intersection = ""
    for i in range(0, len(str1) if len(str1) <= len(str2) else len(str2)):
        if str1[i] == str2[i]:
            intersection += str1[i]
        else:
            break
    return intersection


def parse_cpu_numbers(cpu_list):
    cpu_numbers = [int(cpu) for cpu in cpu_list if cpu.isdigit()]
    for cpu in cpu_list:
        if '-' in cpu:
            try:
                cpu = cpu.split('-')
                cpu_numbers.extend(range(int(cpu[0]), int(cpu[1]) + 1))
            except (KeyError, ValueError):
                LOG.error('Invalid cpu range: %s', cpu)
    return cpu_numbers


def read_file(path, is_yaml=False):
    LOG.debug("Reading file at %s", path)
    with open(path, 'r') as f:
        if is_yaml:
            data = yaml.safe_load(f)
        else:
            data = f.read()
    if not data:
        LOG.error("Cannot access to file at %s", path)
        exit(1)
    return data

def get_Rest_API_pass():
    LOG.debug("Fetching REST API config ")
    REST_API_config_file = "/opt/cisco/ui_config.json"
    if os.path.exists("/opt/cisco/ui_config.json"):
        LOG.debug("  API_config file found: %s", REST_API_config_file)
        json_data=open(REST_API_config_file)
        data = json.load(json_data)
        REST_key = data["RestAPI-Password"]
        json_data.close()
    else:
        LOG.debug("  API_config file not found in: %s", REST_API_config_file)
        REST_key = ""
    return REST_key

def generate_token(password):
    string_token = "admin:" + password
    return stringToBase64(string_token)

def stringToBase64(s):
    return base64.b64encode(s.encode('utf-8'))

def main():
    setup()
    # Read CL args
    parser = argparse.ArgumentParser(description=help, formatter_class=RawTextHelpFormatter)
    parser.add_argument("-c", "--config", action="store", dest="config_file",
                        help="configuration file",
                        default="config.yaml")
    parser.add_argument("-p","--password",nargs=2,metavar=("CVIM_MON_SERVER_PASSWORD", "KIBANA_PASSWORD"),
                        help="These passwords are fetch from either vault or secrets.yaml",default=["pass", "pass"])

    options = parser.parse_args()
    global KIBANA_PASSWORD
    global CVIM_MON_SERVER_PASSWORD
    CVIM_MON_SERVER_PASSWORD = options.password[0]
    KIBANA_PASSWORD = options.password[1]
    cvim_mon = CVIMMon(config_file=options.config_file)
    cvim_mon.create_telegraf_confs()

    LOG.info("All telegraf configuration files have been created")


if __name__ == '__main__':
    main()
