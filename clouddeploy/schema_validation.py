#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Schema Validations:
==============

Schema Validations Module:
---------------------------------------
This module uses voluptous to do the schema validation and then
returns the error string or nothing based on pass or fail

Schema Validation Steps:
------------------
 1. take the input file info and validate against the schema defined

"""
import copy
import os
import re
import subprocess
import socket
import fcntl
import struct
import sys
import ipaddr
import ipaddress
import netaddr
import netifaces
import pytz
import numbers
from voluptuous import Schema, Length, Invalid, MultipleInvalid
from voluptuous import All, Any, Required, Optional, In, Range, Boolean
from voluptuous import IsTrue, IsFalse
import OpenSSL.crypto as crypto
import utils.logger as logger
import utils.config_parser as config_parser
import bootstrap.config_manager as config_manager
import clouddeploy.config_manager as cd_cfg_mgr
import utils.common as common_utils


DEFAULT_CFG_DIR = "openstack-configs"
DEFAULT_SETUP_FILE = "setup_data.yaml"

ROOT_DRIVE_MIN = 0
ROOT_DRIVE_MAX = 26
CVIM_HACERT_PATH = "/root/cvimha_certs"
ROOT_DRIVE_TYPES = ["HDD", "SSD", "M.2_SATA", "NVMe"]
ROOT_DRIVE_RAID_LEVELS = ["raid0", "raid1", "raid10", "raid5", "raid6"]
ROOT_DRIVE_RAID_SPARE_MIN = 0
ROOT_DRIVE_RAID_SPARE_MAX = 4
SUPPORTED_VENDORS = ["CSCO", "HPE", "QCT", "KONTRON", "SMCI"]
ADMIN_FEC_MODE = ["Auto", "Off", "cl74", "cl91"]
LINK_TRAINING = ["OFF", "ON"]
ADMIN_SPEED = ["40Gbps", "4x10Gbps", "Auto"]
BOND_MODES = ["802.3ad", "active-backup"]
IPMI_SUPPORTED_VENDORS = ["CSCO", "QCT"]
IPMI_SUPPORTED_ADAPTERS = ["VIC", "NIC"]

v6_pattern = re.compile('.*(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]' \
    '{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]' \
    '[0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]'
    '|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]' \
    '{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
    '(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})' \
    '?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
    '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
    '(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:' \
    '[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:' \
    '[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.)' \
    '{3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
    '(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}' \
    '(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|' \
    '2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|' \
    '25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]' \
    '{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|' \
    '1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|' \
    '2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})' \
    '?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|' \
    '2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}' \
    '|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})' \
    '?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)' \
    '(?:%25(?:[A-Za-z0-9\\-._~]|%[0-9A-Fa-f]{2})+)?.*')


class SchemaValidator(object):
    '''
    Schema Validator class.
    '''

    def __init__(self, setupfileloc, curr_action, ccp_check=0, vm_list=[]):
        '''
        Initialize schema validator
        '''
        # ###############################################
        # Set up logging
        # ###############################################
        self.loginst = logger.Logger(name=__name__)
        self.log = self.loginst.get_logger()
        self.schema_validation_results = []
        self.testbed_type = None
        self.curr_role = None
        self.ymlhelper = None
        self.curr_action = curr_action
        self.configure_tor = 0
        self.manage_lacp = 0
        self.tor_error_found = 0
        self.server_port_channel_list = []
        self.server_eth_port_list = []

        self.global_mgmt_ip_list = []
        self.global_admin_ip_list = []
        self.global_mgmt_ipv6_list = []
        self.global_admin_ipv6_list = []
        self.global_tenant_ip_list = []
        self.global_snmpv3_user_list = []
        self.global_vxlan_tenant_ip_list = []
        self.global_vxlan_ecn_ip_list = []
        self.global_storage_ip_list = []
        self.global_cluster_ip_list = []

        self.global_sr_mpls_tenant_ip_list = []
        self.global_sr_mpls_prefix_sid_list = []
        self.global_sr_mpls_block_info = {}

        self.global_vxlan_tenant_vtep_ip_list = []
        self.global_vxlan_ecn_vtep_ip_list = []

        self.global_snmpv3_engine_id = []
        self.global_bgp_asn_num = []
        self.global_physnet_name = []
        self.global_nfvimon_master_admin_ip = []

        self.global_vlan_info = {}
        self.global_multi_backend_ceph = 0
        self.global_multi_backend_ssd_ceph = 0
        self.global_multi_backend_hdd_ceph = 0

        self.l2_out_defined = 0
        self.l3_out_defined = 0
        self.l2_out_list = []
        self.l3_out_list = []

        self.api_l2out_network_tor = 0
        self.mgmt_l2out_network_tor = 0
        self.prov_l2out_network_tor = 0
        self.ext_l2out_network_tor = 0
        self.api_l2out_network = 0
        self.mgmt_l2out_network = 0
        self.prov_l2out_network = 0
        self.ext_l2out_network = 0

        self.apic_provider_vlan_list = []
        self.apic_tenant_vlan_list = []
        self.apic_gateway_cidr_list = []
        self.ccp_check = ccp_check

        self.central_flavor_name_list = []
        self.central_keypair_name_list = []
        self.central_image_name_list = []
        self.central_network_name_list = []
        self.central_network_subnet_combo_list = []
        self.curr_network_name = ""
        self.central_network_vlanid_list = []
        self.central_network_subnet_name_list = []
        self.central_network_subnet_gw_list = []
        self.central_network_subnet_cidr_list = []
        self.central_network_subnet_range_list = []
        self.central_network_subnet_cidr = {}
        self.central_network_subnet_ip_version = {}
        self.central_network_subnet_gw = {}
        self.central_server_network_name_list = []
        self.central_server_name_list = []
        self.central_nic_name_list = []
        self.curr_server_name = None
        self.curr_server_nic_name = None
        self.central_server_nic_ip_addr_list = []
        self.curr_nic_network_name = ""
        self.curr_ccp_network_type = ""
        self.curr_node_type = None
        self.vm_list = vm_list

        self.l3_fabric_vni_list = []

        homedir = self.get_homedir()
        self.cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)
        if setupfileloc is None:
            self.setup_file = os.path.join(self.cfg_dir, DEFAULT_SETUP_FILE)
        else:
            self.setup_file = setupfileloc

        self.ymlhelper = config_parser.YamlHelper(
            user_input_file=self.setup_file)

        podtype = self.ymlhelper.get_pod_type()
        # New check because these validations are irrelevant for CVIMMONHA deployment
        if podtype != 'CVIMMONHA' and podtype != 'MGMT_CENTRAL':
            self.cfgmgr = config_manager.ConfigManager(userinput=self.setup_file)

            if os.path.isfile(self.cfg_dir):
                self.cd_cfgmgr = cd_cfg_mgr.ConfigManager(userinput=self.setup_file)
            else:
                self.cd_cfgmgr = cd_cfg_mgr.ConfigManager(userinput=self.setup_file,
                                                          via_softlink=0)

        self.log.debug("Schema Validator Initialized")

    def get_homedir(self):
        '''
        Get the current username
        '''
        homedir = os.path.expanduser("~")
        return homedir

    def do_ips_belong_in_network(self, ip_info_list):
        '''Validate if the ip info is valid and return
        if they belong to the same network'''

        network_info = {}
        for each_ip in ip_info_list:
            (addrString, cidrString) = each_ip.split('/')

            # Split address into octets and turn CIDR into int
            addr = addrString.split('.')
            cidr = int(cidrString)

            # Initialize the netmask and calculate based on CIDR mask
            mask = [0, 0, 0, 0]
            for i in range(cidr):
                try:
                    mask[i / 8] = mask[i / 8] + (1 << (7 - i % 8))
                except IndexError:
                    return 0

            # Initialize net and binary and netmask with addr to get network
            net = []
            for i in range(4):
                net.append(int(addr[i]) & mask[i])

            expected_network = ".".join(map(str, net))
            network_info[each_ip] = expected_network

        if network_info[ip_info_list[0]] != network_info[ip_info_list[1]]:
            return 0

        return 1

    def ironic_schema_validation(self, yaml_input):
        '''Validates the schema for input file'''

        cimc_common = Schema({
            Required('ipmi_username'): All(str, Length(min=1), \
                                           msg='IPMI admin username missing'),
            Required('ipmi_password'): All(str, Length(min=1), \
                                           msg='IPMI admin password missing'),
        })

        standalone_schema = Schema({
            Optional('IPMI-COMMON'): cimc_common,
            Required('SERVERS'): self.validate_ironic_server_syntax,
        }, extra=True)


        err_list = []
        # testbed specific valdation
        try:
            standalone_schema(yaml_input)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))
        except Exception as e:
            try:
                for x in e.errors:
                    err_list.append(str(x))
            except AttributeError:
                err_list.append(str(e))

        return err_list

    def validate_ironic_server_syntax(self, input_str):
        '''validates the standalone server schema'''

        unique_hostname = []
        unique_cimc_list = []
        dup_cimc_list = []
        duplicate_hostname = []
        portgroup_names = {}
        portgroup_macs = {}
        portgroup_ports = {}

        hardware_info_schema = Schema({
            Optional('vendor'): In(frozenset(IPMI_SUPPORTED_VENDORS)),
            Optional('adapter_type'): In(frozenset(IPMI_SUPPORTED_ADAPTERS)),
            Optional('ipmi_encryption_key'): All(str, Length(min=1))

        })
        cimc_ip_schema = Schema({
            Required('ipmi_address'): self.is_ipv4_or_v6_syntax_valid,
            Optional('ipmi_username'): All(str, Length(min=1)),
            Optional('hardware_info'): hardware_info_schema,
            Optional('ipmi_password'): All(str, Length(min=1),
                                           msg='IPMI admin password missing'),
        })

        # only for definition no config
        standalone_schema = Schema({
            Required('IPMI_INFO'): cimc_ip_schema,
            Optional('portgroups'): Schema([self.validate_ironic_server_portgroup]),
        }, extra=True)

        err_list = []

        for server in input_str:
            curr_msg = 'Missing Critical info for ' + server

            if server not in unique_hostname:
                unique_hostname.append(server)
            else:
                duplicate_hostname.append(server)

            try:
                standalone_schema(input_str[server])
                curr_cimc_ip = input_str[server].get('IPMI_INFO').get('ipmi_address')
                if curr_cimc_ip not in unique_cimc_list:
                    unique_cimc_list.append(curr_cimc_ip)
                else:
                    dup_cimc_list.append(curr_cimc_ip)

                for pg in input_str[server].get('portgroups', []):
                    pg_name, pg_mac = pg['name'], pg['address'],
                    if pg_name in portgroup_names:
                        err_str = ('Portgroup name %s is '
                                   'already used by server '
                                   '"%s"' % (pg_name,
                                             portgroup_names[pg_name]))
                        err_list.append(err_str)
                    else:
                        portgroup_names[pg_name] = server

                    if pg_mac in portgroup_macs:
                        err_str = ('Portgroup MAC address "{0}" is already '
                                   'used by server\'s "{1[0]}" port group '
                                   '"{1[1]}"'.format(pg_mac,
                                                     portgroup_macs[pg_mac]))
                        err_list.append(err_str)
                    else:
                        portgroup_macs[pg_mac] = (server, pg_name)

                    for switch, port in pg['ports'].items():
                        # 'E*' prefix could be Ethernet => remove it
                        s2p = (switch, re.sub(r'[a-z]+', '', port,
                                              flags=re.IGNORECASE))
                        if s2p in portgroup_ports:
                            err_str = ('Port "{0}" of a switch "{1}" is already '
                                       'used by server\'s "{2[0]}" port '
                                       'group "{2[1]}"'.format(port, switch,
                                                               portgroup_ports[s2p]))
                            err_list.append(err_str)
                        else:
                            portgroup_ports[s2p] = (server, pg_name)

            except MultipleInvalid as e:
                for x in e.errors:
                    err_str = "%s %s" % (curr_msg, x)
                    err_list.append(err_str)
            except Exception as e:
                try:
                    for x in e.errors:
                        err_list.append(str(x))
                except AttributeError:
                    err_list.append(str(e))

        # Validation bellow checks ALL servers must have (not) portgroups.
        # with_portgroups = [k for k, v in input_str.items()
        #                    if v.get('portgroups')]
        # if with_portgroups:
        #     # All servers should (or not) have port groups
        #     server_names = set(input_str.keys())
        #     without_portgroups = server_names - set(with_portgroups)
        #     if without_portgroups:
        #         err_str = ('Following servers do not have portgroups: '
        #                    '\"{0}\"'.format(', '.join(without_portgroups)))
        #         err_list.append(err_str)

        # return if we detect an error at server schema level
        # subsequent checks are server details
        if err_list:
            raise Invalid(', '.join(err_list))

        if duplicate_hostname:
            err_str = "Duplicate Server hostname " + \
                      str(duplicate_hostname)
            err_list.append(err_str)

        if dup_cimc_list:
            err_str = "Duplicate IPMI IPs found " + \
                      str(dup_cimc_list)
            err_list.append(err_str)

        if err_list:
            raise Invalid(', '.join(err_list))

        return

    def validate_ironic_server_portgroup(self, input_str):
        """validate_ironic_server_portgroup"""

        def validate_port_name(value):
            """validate_port_name"""
            if not re.match(r'Ethernet\d+/\d+', value):
                raise Invalid('Switchport name should look '
                              'like "Ethernet1/2"')

        def validate_portgroup_name(value):
            """Validate portgroup"""
            v = value.lower()
            if not re.match(r'po\d+', v):
                raise Invalid('Switchport name should look like "Po2, Po12"')

        switch_info = self.get_tor_switch_info('ironic')
        err_msg = ('Allowed only hostnames of switches defined in '
                   'setup-data.yaml:IRONIC.IRONIC_SWITCHDETAILS '
                   'dictionary. Here they are: '
                   '{0}.'.format(', '.join(switch_info)))
        portgroups_schema = Schema({
            Required('name'): validate_portgroup_name,
            Required('address'): self.check_macaddress,
            Required('ports'): Schema({
                Optional(si, msg=err_msg): validate_port_name for si in switch_info
            })
        })
        portgroups_schema(input_str)

    def get_storage_deployment_info(self):
        """look at the input file and get storage deployment info"""

        target_storage_deployment = ""
        if self.ymlhelper.get_pod_type() == 'ceph':
            return "DEDICATED_CEPH"

        store_backend = self.ymlhelper.get_setup_data_property("STORE_BACKEND")
        volume_driver = self.ymlhelper.get_setup_data_property("VOLUME_DRIVER")

        if self.ymlhelper.get_pod_type() == 'nano':
            if store_backend != 'file':
                target_storage_deployment = "UNKNOWN"

            if volume_driver is None:
                return "file"

        if self.ymlhelper.get_pod_type() != 'nano' and volume_driver is None:
            target_storage_deployment = "UNKNOWN"
        elif re.match(r'lvm|ceph|netapp', volume_driver):
            target_storage_deployment = volume_driver

        if re.match(r'UNKNOWN', target_storage_deployment):
            return target_storage_deployment

        svr_list = self.ymlhelper.get_server_list(role="block_storage")
        if self.is_netapp_block_defined() and volume_driver != 'netapp':
            return "OOP_NETAPP_BLOCK"
        elif self.is_netapp_block_defined() and store_backend != 'netapp':
            return "OOP_NETAPP_BLOCK"

        if self.is_zadara_block_defined() and volume_driver != 'zadara':
            return "OOP_ZADARA_BLOCK"
        elif self.is_zadara_block_defined() and store_backend != 'zadara':
            return "OOP_ZADARA_BLOCK"

        if not svr_list and re.match(r'ceph', volume_driver):
            return "CENTRAL_CEPH"
        if not svr_list and re.match(r'netapp', volume_driver):
            return "NETAPP"
        if not svr_list and re.match(r'zadara', volume_driver):
            return "ZADARA"
        elif not svr_list and re.match(r'lvm', volume_driver):
            return "LVM"
        elif svr_list and re.match(r'lvm', volume_driver):
            return "LVM_DEDICATED_CEPH"
        elif svr_list and re.match(r'netapp', volume_driver):
            return "NETAPP_DEDICATED_CEPH"
        elif svr_list and re.match(r'zadara', volume_driver):
            return "ZADARA_DEDICATED_CEPH"
        elif svr_list and re.match(r'ceph', volume_driver):
            return "DEDICATED_CEPH"
        else:
            return "STORAGE_TYPE_UNKNOWN"

    def validate_ip_for_a_given_network(self, addrString, network_with_mask, \
                                        get_broadcast=0):
        '''validates if the IP address is correct given the network and mask'''

        if not self.validate_network(network_with_mask):
            self.log.error("incorrect Network info %s", network_with_mask)
            return 0

        if not self.is_ip_valid(addrString):
            self.log.error("incorrect IP %s entered", addrString)
            return 0

        (networkString, cidrString) = network_with_mask.split('/')

        # Split address into octets and turn CIDR into int
        addr = addrString.split('.')
        cidr = int(cidrString)

        # Initialize the netmask and calculate based on CIDR mask
        mask = [0, 0, 0, 0]
        for i in range(cidr):
            try:
                mask[i / 8] = mask[i / 8] + (1 << (7 - i % 8))
            except IndexError:
                return 0

        # Initialize net and binary and netmask with addr to get network
        net = []
        for i in range(4):
            net.append(int(addr[i]) & mask[i])

        # Duplicate net into broad array, gather host bits, and generate broadcast
        broad = list(net)
        brange = 32 - cidr
        for i in range(brange):
            broad[3 - i / 8] = broad[3 - i / 8] + (1 << (i % 8))

        mybroad = ".".join(map(str, broad))
        if get_broadcast:
            return mybroad

        expected_network = ".".join(map(str, net))

        if str(expected_network) != str(networkString):
            self.log.error("incorrect IP addr %s entered", addrString)
            return 0

        if str(addrString) == str(networkString):
            self.log.error("IP addr %s matched the network info", addrString)
            return 0

        if str(addrString) == str(mybroad):
            self.log.error("IP addr %s matches the broadcast info", addrString)
            return 0

        return 1

    def validate_network(self, network_with_mask):
        ''' validates if the input of the network is correct'''

        if network_with_mask is None:
            self.log.error("Network info is missing")
            return 0
        elif not re.search(r'/', network_with_mask):
            self.log.error("Network info doesn't have the right pattern")
            return 0
        else:
            # Get address string and CIDR string from command line
            (addrString, cidrString) = network_with_mask.split('/')

            try:
                _ = int(cidrString)
            except ValueError:
                self.log.error("incorrect mask %s entered", cidrString)
                return 0

            if int(cidrString) < 1 or int(cidrString) > 30:
                self.log.error("incorrect mask %s entered", cidrString)
                return 0

            try:
                ipaddr.IPv4Address(addrString)
                return 1
            except ValueError:
                self.log.error("incorrect Network Address %s entered", addrString)
                return 0

    def is_vmtp_v4gw_reachable(self, input_str):
        '''Check if gateway is reachable'''

        if self.is_ip_syntax_valid(input_str) is not None:
            err_str = "Invalid ip syntax for " + str(input_str)
            raise Invalid(err_str)

        apicinfo = \
            self.ymlhelper.get_data_from_userinput_file(['APICINFO'])
        if apicinfo is not None:
            return

        ignore_gw_ping = \
            self.ymlhelper.get_data_from_userinput_file(['IGNORE_GW_PING'])

        if ignore_gw_ping is not None and ignore_gw_ping:
            self.is_ip_reachable(input_str, ignore_ping=1)
        else:
            self.is_ip_reachable(input_str)
        return

    def is_vmtp_v6gw_reachable(self, input_str):
        '''Check if gateway is reachable'''

        if self.is_ipv6_syntax_valid(input_str) is not None:
            err_str = "Invalid ipv6 syntax for %s" % (input_str)
            raise Invalid(err_str)

        apicinfo = \
            self.ymlhelper.get_data_from_userinput_file(['APICINFO'])
        if apicinfo is not None:
            return

        ignore_gw_ping = \
            self.ymlhelper.get_data_from_userinput_file(['IGNORE_GW_PING'])
        if ignore_gw_ping is not None and ignore_gw_ping:
            self.is_ipv6_reachable(input_str, ignore_ping=1)
        else:
            self.is_ipv6_reachable(input_str)
        return

    def is_ip_reachable(self, ip_addr, ignore_ping=0):
        '''Checks if IP address is reachable'''

        if self.is_ip_syntax_valid(ip_addr) is not None:
            err_str = "Invalid ip syntax for " + str(ip_addr)
            raise Invalid(err_str)

        err_str = "IP Address Unreachable"
        try:
            ping = subprocess.Popen(['/usr/bin/ping', '-c10', '-W2', ip_addr], \
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out = ping.communicate()[0]

            if not out:
                raise Invalid(err_str)

            for item in out.splitlines():
                if re.search(r'100% packet loss', item):
                    self.log.info("Ping failed to %s" % (ip_addr))
                    self.log.info("Ping failed message %s" % (out))

                    if ignore_ping:
                        return ""
                    raise Invalid(err_str)

        except subprocess.CalledProcessError:
            if ignore_ping:
                return ""
            raise Invalid(err_str)

        return ""

    def is_ipv6_reachable(self, ipv6_addr, ignore_ping=0):
        '''Checks if IPv6 address is reachable'''

        if self.is_ipv6_syntax_valid(ipv6_addr) is not None:
            err_str = "Invalid ipv6 syntax for %s" % (ipv6_addr)
            raise Invalid(err_str)

        err_str = "IPv6 Address Unreachable"
        try:
            ping = subprocess.Popen(['/usr/bin/ping6', '-c10', ipv6_addr], \
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out = ping.communicate()[0]

            if not out:
                raise Invalid(err_str)

            for item in out.splitlines():
                if re.search(r'100% packet loss|Network is unreachable', item):
                    self.log.info("Ping failed to %s" % (ipv6_addr))
                    self.log.info("Ping failed message %s" % (out))
                    if ignore_ping:
                        return ""
                    raise Invalid(err_str)

        except subprocess.CalledProcessError:
            if ignore_ping:
                return ""
            raise Invalid(err_str)

        return ""

    def is_ipv4v6_reachable(self, input_str):
        '''Checks if IP v6 address is reachable'''

        found_v6 = 0
        if common_utils.is_valid_ipv6_address(input_str):
            found_v6 = 1

        if not found_v6:
            self.is_ip_reachable(input_str)
        else:
            self.is_ipv6_reachable(input_str)

        return ""

    def validate_v6_network(self, network_with_mask):
        ''' validates if the input of the v6 network is correct'''

        if network_with_mask is None:
            self.log.error("Network info is missing")
            return 0
        elif not re.search(r'/', network_with_mask):
            self.log.error("Network info doesn't have the right pattern")
            return 0
        else:
            # Get address string and CIDR string from command line
            (addrString, cidrString) = network_with_mask.split('/')

            try:
                _ = int(cidrString)
            except ValueError:
                self.log.error("incorrect v6 mask %s entered", cidrString)
                return 0

            if int(cidrString) < 1 or int(cidrString) > 126:
                self.log.error("incorrect v6 mask %s entered", cidrString)
                return 0

            if common_utils.is_valid_ipv6_address(addrString):
                return 1
            else:
                self.log.error("incorrect v6 Network Address %s entered", addrString)
                return 0

    def validate_ipv6_for_a_given_network(self,
                                          addrString,
                                          network_with_mask, \
                                          get_broadcast=0):
        '''validates if the IPv6 address is correct given the network and mask'''

        if not self.validate_v6_network(network_with_mask):
            self.log.error("incorrect v6 Network info %s", network_with_mask)
            return 0

        if not common_utils.is_valid_ipv6_address(addrString):
            self.log.error("incorrect V6 IP %s entered", addrString)
            return 0

        (networkString, cidrString) = network_with_mask.split('/')

        addr_info = addrString + "/" + cidrString
        ipinfo = netaddr.IPNetwork(addr_info)

        if get_broadcast:
            return ipinfo.broadcast

        if not common_utils.is_ipv6_address_info_equal(ipinfo.network,
                                                       str(networkString)):
            self.log.error("incorrect IPv6 addr %s entered", addrString)
            return 0

        if common_utils.is_ipv6_address_info_equal(addrString, str(networkString)):
            self.log.error("IPv6 addr %s matched the network info", addrString)
            return 0

        if common_utils.is_ipv6_address_info_equal(addrString, ipinfo.broadcast):
            self.log.error("IPv6 addr %s matches the broadcast info", addrString)
            return 0

        return 1

    def is_ipv6_address_equal(self, ip1, ip2):
        '''Checks if the 2 IPv6 address are equal'''

        if not common_utils.is_valid_ipv6_address(ip1):
            err_msg = "%s is not a valid IPV6 address" % (ip1)
            raise Invalid(err_msg)

        if not common_utils.is_valid_ipv6_address(ip2):
            err_msg = "%s is not a valid IPV6 address" % (ip2)
            raise Invalid(err_msg)

        if common_utils.is_ipv6_address_info_equal(ip1, ip2):
            return 1
        else:
            return 0

    def is_ip_valid(self, ip_addr):
        '''checks if ip address is valid'''

        try:
            parts = ip_addr.split('.')
            return len(parts) == 4 and all(0 <= int(part) < 256 for part in parts)
        except ValueError:
            return False  # one of the 'parts' not convertible to integer
        except (AttributeError, TypeError):
            return False  # `ip` isn't even a string

    def is_ipv6_syntax_valid(self, input_str):
        '''Checks if IP v6 address is valid'''

        err_str = "Missing IPv6 entry"
        if input_str is None:
            raise Invalid(err_str)

        err_str = "Input is not an ASCII %s" % (input_str)
        if not self.is_input_in_ascii(input_str):
            raise Invalid(err_str)

        err_str = ""
        try:
            socket.inet_pton(socket.AF_INET6, input_str)
        except socket.error:  # not a valid address
            err_str = "Invalid IPv6 format %s" % (input_str)

        if err_str:
            raise Invalid(err_str)

    def is_ip_syntax_valid(self, input_str):
        '''checks if ip address syntax is valid'''

        err_str = "Missing IP entry"
        if input_str is None:
            raise Invalid(err_str)

        err_str = "Input is not an ASCII %s" % (input_str)
        if not self.is_input_in_ascii(input_str):
            raise Invalid(err_str)

        err_str = ""
        try:
            _ = ipaddr.IPv4Address(input_str)
        except ipaddr.AddressValueError:
            err_str = "Invalid IP format %s" % (input_str)

        if err_str:
            raise Invalid(err_str)

    def is_name_defined(self, input_str):
        #Check if cvim-mon ha setup names have at least 1
        #non-Nonetype ascii char
        if input_str is None:
            raise Invalid("Name must have at least one non-Nonetype char")

        return self.is_input_in_ascii(input_str)

    def is_input_in_ascii(self, rhs_value):
        '''checks if input is in ASCII'''

        try:
            str(rhs_value).decode('ascii')
            return 1
        except UnicodeDecodeError:
            return 0
        except ValueError:
            return 0

    def check_ipv4_or_v6_syntax(self, input_str):
        ''' Checks if input_str is an IPv4 or IPv6 entry '''

        if not input_str:
            raise Invalid("Missing Entry")

        if not self.is_input_in_ascii(input_str):
            raise Invalid("Input is not an ASCII %s" % (input_str))

        try:
            ipaddr.IPv4Address(input_str)
        except ipaddr.AddressValueError:
            if not common_utils.is_valid_ipv6_address(input_str):
                raise Invalid("Invalid IPv4/IPv6 address: %s" % (input_str))
            else:
                pass

        return

    def is_ipv4_or_v6_syntax_valid(self, input_str):
        ''' Checks if input_str is an IPv4 or IPv6 entry '''

        found_v6 = 0
        found_v4 = 0
        if not input_str:
            raise Invalid("Missing Entry")

        if not self.is_input_in_ascii(input_str):
            raise Invalid("Input is not an ASCII %s" % (input_str))

        try:
            ipaddr.IPv4Address(input_str)
            found_v4 = 1
        except ipaddr.AddressValueError:
            if not common_utils.is_valid_ipv6_address(input_str):
                raise Invalid("Invalid IPv4/IPv6 address: %s" % (input_str))
            else:
                found_v6 = 1

        # Check if env var has been set, if not run the check,
        # this is for CVIM-MON-HA Testing
        if 'SKIP_REM_IP_BR_API_IP_CHECK' in os.environ:
            return

        if found_v6:
            # Check if syslog export ip is not same as br_api
            br_api_ipv6 = self.get_ip_info("br_api", type='v6')

            if common_utils.is_ipv6_address_info_equal(br_api_ipv6, input_str):
                err_str = "Remote host IP Address:%s is same as br_api of " \
                    "management node; Please adjust the config" % (input_str)
                raise Invalid(err_str)

            # Check if syslog export ip is not same as br_mgmt
            br_mgmt_ipv6 = self.get_ip_info("br_mgmt", type='v6')

            if common_utils.is_ipv6_address_info_equal(br_mgmt_ipv6, input_str):
                err_str = "Remote host IP Address:%s is same as br_mgmt of " \
                    "management node; Please adjust the config" % (input_str)
                raise Invalid(err_str)

        if found_v4:
            # Check if syslog/es remote host is not same as br_mgmt
            br_mgmt_ip = self.get_ip_info("br_mgmt")

            if str(br_mgmt_ip) == str(input_str):
                err_str = "Remote host IP Address:%s is same as br_mgmt of " \
                    "nagement node; Please adjust the config" % (input_str)

                raise Invalid(err_str)

            # Check if syslog/es remote host is not same as br_api
            br_api_ip = self.get_ip_info("br_api")

            if str(br_api_ip) == str(input_str):
                err_str = "Remote host IP Address:%s is same as br_api of " \
                    "management node; Please adjust the config" % (input_str)

                raise Invalid(err_str)
        return

    def is_es_remote_path(self, input_str):
        '''Check remote path format'''
        err_str = self.is_input_in_plain_str(input_str, 255)
        if err_str:
            raise Invalid(err_str)
        if not input_str.startswith('/'):
            raise Invalid("Path must start with '/'")
        if input_str.endswith('/'):
            raise Invalid("Path should not end with '/'")

    def is_input_an_integer(self, my_info):
        '''Check if the input is an integer'''

        try:
            _ = int(my_info)
            return 1
        except ValueError:
            return 0

    def is_input_range_valid(self, my_info, lower_limit, upper_limit):
        ''' is input range valid '''
        if upper_limit < my_info or lower_limit > my_info:
            return 0
        else:
            return 1

    def is_certificate_file(self, check_cert_path=False,
                            msg="not a valid certificate file"):
        """Verify the file is PEM format certificate."""
        pod_check = self.ymlhelper.get_pod_type()

        def f(v):
            """validator to return"""
            if check_cert_path and pod_check == "CVIMMONHA":
                msg_err = "Invalid cert path for cvim certs; " \
                          "should be {0}".format(CVIM_HACERT_PATH)
                cert_path = os.path.split(v)[0]
                if CVIM_HACERT_PATH not in cert_path:
                    raise Invalid(msg_err)
            if not os.path.isfile(v):
                raise Invalid(msg)
            try:
                pem = open(v, 'rt').read()
                crypto.load_certificate(crypto.FILETYPE_PEM, pem)
                crypto.load_privatekey(crypto.FILETYPE_PEM, pem)
            except:
                raise Invalid(msg)
            return v
        return f

    def is_ca_certificate_file(self, check_cert_path=False,
                               msg="not a valid CA certificate file"):
        """Verify the file is a CA certificate."""

        pod_check = self.ymlhelper.get_pod_type()

        def f(v):
            """validator to return"""
            if check_cert_path and pod_check == "CVIMMONHA":
                msg_err = "Invalid cert path for cvim certs; " \
                          "should be {0}".format(CVIM_HACERT_PATH)
                cert_path = os.path.split(v)[0]
                if CVIM_HACERT_PATH not in cert_path:
                    raise Invalid(msg_err)
            if not os.path.isfile(v):
                raise Invalid(msg)
            try:
                pem = open(v, 'rt').read()
                crypto.load_certificate(crypto.FILETYPE_PEM, pem)
            except:
                raise Invalid(msg)
            return v

        return f

    @staticmethod
    def is_valid_path(path):
        """ check if key and cert file are located at the right path. """

        msg_err = "is_valid_path: " \
                  "should be {0}".format(CVIM_HACERT_PATH)
        msg = "not a valid file."
        cert_path = os.path.split(path)[0]

        if CVIM_HACERT_PATH not in cert_path:
            raise Invalid(msg_err)

        if not os.path.isfile(path):
            raise Invalid(msg)

    def vaidate_dns_server_list(self, key_str):
        '''Validate DNS SERVER in list'''

        invalid_value_format = []
        invalid_input_list = []
        if key_str is None:
            raise Invalid("Missing Entry")

        err_str = "Input has to be of type list with unique " \
                  "entry of type IPv4/IPV6"
        if not isinstance(key_str, list):
            raise Invalid(err_str)

        for item in key_str:
            if not self.is_input_in_ascii(item):
                invalid_value_format.append(item)

        if invalid_value_format:
            raise Invalid("Input not a String")

        self.check_ip_address_syntax(key_str)

        if invalid_input_list:
            raise Invalid("Input not a valid IPV4/IPv6 address")

        dup_net_list = \
            self.get_duplicate_entry_in_list(key_str)

        if dup_net_list:
            err_str = "Duplicate entry found: %s" % (','.join(dup_net_list))
            raise Invalid(err_str)

        if len(key_str) > 1:
            num_entries = len(key_str)
            err_str = "Max of 1 entry allowed, found to be " \
                "%s in %s" % (num_entries, ','.join(key_str))
            raise Invalid(err_str)

        return

    def validate_networking_entry(self, key_str):
        '''Validate Networking Parameters'''

        invalid_value_format = []
        invalid_input_list = []
        if key_str is None:
            raise Invalid("Missing Entry")

        err_str = "Input has to be of type list with unique " \
            "entry of type IPv4/IPv6 of FQDN"
        if not isinstance(key_str, list):
            raise Invalid(err_str)

        found_v6 = 0
        for item in key_str:
            if not self.is_input_in_ascii(item):
                invalid_value_format.append(item)

        if invalid_value_format:
            raise Invalid("Input not a String")

        for item in key_str:
            if common_utils.is_valid_hostname(item):
                continue
            elif self.is_ip_valid(item) or \
                    common_utils.is_valid_ipv6_address(item):
                if v6_pattern.match(item):
                    found_v6 = 1
                else:
                    continue
            else:
                invalid_input_list.append(item)

        if invalid_input_list:
            raise Invalid("Input not a valid IPV4 or IPV6 address")

        if found_v6:
            err_msg = self.is_v6_mgmt_network_defined()
            if err_msg:
                raise Invalid(err_msg)

            self.get_ip_info("br_mgmt", type='v6')

        dup_net_list = \
            self.get_duplicate_entry_in_list(key_str)

        if dup_net_list:
            err_str = "Duplicate entry found: %s" % (','.join(dup_net_list))
            raise Invalid(err_str)

        return

    def is_v6_mgmt_network_defined(self):
        '''check if v6 mgmt network is defined'''

        err_msg = ""
        networking_info = self.ymlhelper.get_data_from_userinput_file(['NETWORKING'])
        if networking_info is not None:
            network_info = networking_info.get('networks')
            if network_info is not None:
                for item in network_info:
                    if item is None:
                        continue
                    elif 'segments' in item.keys():
                        if 'management' in item['segments']:
                            if not self.is_ipv6_info_defined(item):
                                err_msg = 'ipv6_gateway and/or ipv6_subnet' \
                                          ' not defined in mgmt pool'

        return err_msg

    def generate_ip_pool(self, segment, ip_pool_list=[], iptype="v4"):
        ''' generates the ip pool from a list '''

        correct_format = "ip_poolA to ip_poolB"
        err_msg = "Incorrect IP pool: " + str(ip_pool_list) + \
                  " entered for " + str(segment) + " " + correct_format

        ip_pool = []

        for item in ip_pool_list:
            try:
                pool_range_list = item.split("to")
            except ValueError:
                return ip_pool, err_msg

            if not pool_range_list or len(pool_range_list) > 2:
                return ip_pool, err_msg

            elif len(pool_range_list) == 2:
                start_ip = pool_range_list[0].strip()
                end_ip = pool_range_list[1].strip()
                if iptype == 'v6':
                    self.is_ipv6_syntax_valid(start_ip)
                    self.is_ipv6_syntax_valid(end_ip)
                else:
                    self.is_ip_syntax_valid(start_ip)
                    self.is_ip_syntax_valid(end_ip)

                err_msg2 = "Start IP address %s should be less than " \
                           "end ip address %s" % (start_ip, end_ip)
                start = ipaddress.ip_address(unicode(start_ip))
                end = ipaddress.ip_address(unicode(end_ip))

                if start > end:
                    return ip_pool, err_msg2

                if iptype == 'v6':
                    temp_ip_pool = self.ipv6Range(start_ip, end_ip)
                else:
                    temp_ip_pool = self.ipRange(start_ip, end_ip)
                ip_pool.extend(temp_ip_pool)

            elif len(pool_range_list) == 1:
                start_ip = pool_range_list[0].strip()
                if iptype == 'v6':
                    self.is_ipv6_syntax_valid(start_ip)
                else:
                    self.is_ip_syntax_valid(start_ip)
                ip_pool.append(start_ip)

        return ip_pool, ""

    def ipv6Range(self, start_ip, end_ip):
        '''generates ip address given 2 IPs'''

        return list(netaddr.iter_iprange(start_ip, end_ip))

    def ipRange(self, start_ip, end_ip):
        '''generates ip address given 2 IPs'''

        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))

        temp = start
        ip_range = []

        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 256:
                    temp[i] = 0
                    temp[i - 1] += 1
            ip_range.append(".".join(map(str, temp)))

        return ip_range

    def get_ip_pool_size(self, segment, ip_pool_list=[], iptype="v4"):
        ''' get the size of the IP pool '''

        correct_format = "ip_poolA to ip_poolB"
        err_msg = "Incorrect IP pool: " + str(ip_pool_list) + \
                  " entered for " + str(segment) + " " + correct_format

        ip_pool_size = 0
        for item in ip_pool_list:
            try:
                pool_range_list = item.split("to")
            except ValueError:
                return 0, err_msg

            if not pool_range_list or len(pool_range_list) > 2:
                return 0, err_msg

            elif len(pool_range_list) == 2:
                start_ip = pool_range_list[0].strip()
                end_ip = pool_range_list[1].strip()
                if iptype == 'v6':
                    ip_start_valid = self.is_ipv6_syntax_valid(start_ip)
                    ip_end_valid = self.is_ipv6_syntax_valid(end_ip)
                else:
                    ip_start_valid = self.is_ip_syntax_valid(start_ip)
                    ip_end_valid = self.is_ip_syntax_valid(end_ip)

                if ip_start_valid is None and ip_end_valid is None:
                    num_ip = list(netaddr.iter_iprange(start_ip, end_ip))
                    ip_pool_size = ip_pool_size + len(num_ip)
                else:
                    return 0, err_msg

            elif len(pool_range_list) == 1:
                start_ip = pool_range_list[0].strip()
                if iptype == 'v6':
                    ip_start_valid = self.is_ipv6_syntax_valid(start_ip)
                else:
                    ip_start_valid = self.is_ip_syntax_valid(start_ip)
                if ip_start_valid is None:
                    ip_pool_size = ip_pool_size + 1
                else:
                    return 0, err_msg

        return ip_pool_size, ""

    def check_overlapping_ip(self, segment, ip_pool_list=[], iptype="v4"):
        ''' get the size of the IP pool '''

        correct_format = "ip_poolA to ip_poolB"
        err_msg = "Incorrect IP pool: " + str(ip_pool_list) + \
                  " entered for " + str(segment) + " " + correct_format

        ip_pool_enteries = []

        for item in ip_pool_list:
            if re.search(r'provision', segment):
                continue
            try:
                pool_range_list = item.split("to")
            except ValueError:
                return 0, err_msg

            if not pool_range_list or len(pool_range_list) > 2:
                return 0, err_msg

            elif len(pool_range_list) == 2:
                start_ip = pool_range_list[0].strip()
                end_ip = pool_range_list[1].strip()
                if iptype == 'v6':
                    ip_start_valid = self.is_ipv6_syntax_valid(start_ip)
                    ip_end_valid = self.is_ipv6_syntax_valid(end_ip)
                else:
                    ip_start_valid = self.is_ip_syntax_valid(start_ip)
                    ip_end_valid = self.is_ip_syntax_valid(end_ip)
                if ip_start_valid is None and ip_end_valid is None:
                    num_ip = list(netaddr.iter_iprange(start_ip, end_ip))

                    for info in num_ip:
                        ip_pool_enteries.append(str(info))

                else:
                    return 0, err_msg

        repeating_ip_pool_info = []
        if ip_pool_enteries:
            if iptype == 'v6':
                repeating_ip_pool_info = \
                    common_utils.check_dup_ipv6_adds(ip_pool_enteries)
            else:
                repeating_ip_pool_info = \
                    self.check_for_dups_in_list(ip_pool_enteries)

        if repeating_ip_pool_info:
            err_msg = " IP Pools in segment %s has Overlapping IPs: %s;" \
                % (segment, ", ".join(repeating_ip_pool_info))

            return 0, err_msg
        else:
            return 1, ""

    def check_ip_pool_size(self, network_info):
        '''checks if pool size is sufficient'''

        err_list = []
        err_str = ""

        tot_num_servers = 0
        server_list = self.ymlhelper.get_server_list()
        tot_num_servers = len(server_list)

        tot_num_storage = 0
        storage_list = self.ymlhelper.get_server_list(role="block_storage")
        if storage_list is not None:
            tot_num_storage = len(storage_list)

        control_list = self.ymlhelper.get_server_list(role="control")
        compute_list = self.ymlhelper.get_server_list(role="compute")

        pod_type = self.ymlhelper.get_pod_type()

        network_pool_check_list = ['management', 'provision', 'tenant']

        if pod_type == 'fullon':
            num_control_compute = len(control_list) + len(compute_list)
        else:
            num_control_compute = len(compute_list)

        if pod_type == 'ceph':
            network_pool_check_list.append('cluster')
        else:
            network_pool_check_list.append('storage')

        v6network_pool_check_list = ['management', 'provision', 'api']

        if self.check_for_optional_enabled('ironic'):
            network_pool_check_list.append('ironic')

        if re.match('UCSM', self.testbed_type):
            network_pool_check_list.append('cimc')

        for segment_info in network_info['segments']:
            if segment_info in network_pool_check_list:
                if 'pool' not in network_info:
                    return_msg = "Missing entry"

                else:
                    curr_pool_size, return_msg = \
                        self.get_ip_pool_size(segment_info, \
                                              network_info['pool'])

                if not return_msg:

                    curr_pool = []
                    if segment_info == 'ironic':
                        # CHeck no overlap in ironic and ironic inspector pool
                        curr_pool.extend(network_info['pool'])
                        curr_pool.extend(network_info['inspector_pool'])
                    else:
                        curr_pool = copy.deepcopy(network_info['pool'])

                    _, overlap_ip_msg = \
                        self.check_overlapping_ip(segment_info, curr_pool)
                    if overlap_ip_msg:
                        err_list.append(overlap_ip_msg)

                if return_msg:
                    if return_msg not in err_list:
                        err_list.append(return_msg)

                elif re.match(r'management|provision|cimc', segment_info):
                    if tot_num_servers > curr_pool_size:
                        err_info = "Num of servers: " + str(tot_num_servers) + " is \
                                   greater than IP pool size " + \
                                   str(curr_pool_size) + \
                                   " allocated for segment:" + segment_info + "; "
                        err_list.append(err_info)

                elif tot_num_storage and re.match(r'storage', segment_info):
                    if tot_num_servers > curr_pool_size:
                        err_info = "Num of storage servers: " + \
                            str(tot_num_servers) + \
                            " is greater than IP pool size " + \
                            str(curr_pool_size) + \
                            " allocated for segment:" + \
                            segment_info + "; "
                        err_list.append(err_info)
                elif re.match(r'tenant', segment_info):
                    if num_control_compute > curr_pool_size:
                        err_info = "Num of control and compute servers: " + \
                            str(num_control_compute) + \
                            " is greater than IP pool size " + \
                            str(curr_pool_size) + \
                            " allocated for segment:" + \
                            segment_info + "; "
                        err_list.append(err_info)

        for segment_info in network_info['segments']:
            if segment_info in v6network_pool_check_list:
                if 'ipv6_pool' not in network_info:
                    continue
                else:
                    curr_poolv6_size, return_v6msg = \
                        self.get_ip_pool_size(segment_info, \
                                              network_info['ipv6_pool'],
                                              iptype='v6')

                if not return_v6msg:
                    _, overlap_ipv6_msg = \
                        self.check_overlapping_ip(segment_info,
                                                  network_info['ipv6_pool'],
                                                  iptype='v6')
                    if overlap_ipv6_msg:
                        err_list.append(overlap_ipv6_msg)

                if return_v6msg:
                    if return_v6msg not in err_list:
                        err_list.append(return_v6msg)

                elif re.match(r'management|provision', segment_info):
                    if tot_num_servers > curr_poolv6_size:
                        err_info = "Num of servers: " + str(tot_num_servers) + " is \
                                   greater than IPv6 pool size " + \
                                   str(curr_poolv6_size) + \
                                   " allocated for segment:" + segment_info + "; "
                        err_list.append(err_info)

        if err_list:
            err_str = " ;".join(err_list)

        return err_str

    def is_ipv6_info_defined(self, input_str, pool_check=0):
        '''Check if ipv6 info is defined'''

        if input_str.get('ipv6_subnet') is not None:
            return 1
        elif input_str.get('ipv6_gateway') is not None:
            return 1
        elif pool_check and input_str.get('ipv6_pool') is not None:
            return 1

        return 0

    def fetch_rt_len(self, rt_prefix_str, rt_suffix_str, vlan_id):
        '''Fetch the route target length '''

        rt_str = "%s:%s%s" % (rt_prefix_str, rt_suffix_str, vlan_id)
        rt_len = sys.getsizeof(rt_str) / 8
        return rt_len

    def check_pool_in_network(self, segment, subnet, ip_pool_list=[]):
        '''Check if IP pool is in network'''

        correct_format = "ip_poolA to ip_poolB"
        err_msg = "ERROR: Incorrect IP pool: " + str(ip_pool_list) + \
            " entered for " + str(segment) + " " + correct_format

        ip_pool_entry_list = []
        invalid_ip_list = []

        for item in ip_pool_list:
            try:
                pool_range_list = item.split("to")
            except ValueError:
                return 0, err_msg

            if not pool_range_list or len(pool_range_list) > 2:
                return 0, err_msg

            elif len(pool_range_list) == 2:
                ip_pool_entry_list.append(pool_range_list[0].strip())
                ip_pool_entry_list.append(pool_range_list[1].strip())

            elif len(pool_range_list) == 1:
                ip_pool_entry_list.append(pool_range_list[0].strip())

        for item in ip_pool_entry_list:
            if not self.validate_ip_for_a_given_network(item, subnet):
                invalid_ip_list.append(item)

        if invalid_ip_list:
            err_msg = "ERROR: IPs:%s in the %s pool doesnot belong " \
                "in %s network" % (','.join(invalid_ip_list), segment, subnet)
            return 0, err_msg

        return 1, "PASS"

    def cross_check_network_subnet(self, input_str, check_v6=0,
                                   segment_name="Default"):
        """Check network and subnet info"""

        err_list = []
        err_info = ""

        if segment_name == "Default":
            segment_name = ':'.join(input_str.get('segments'))

        v4_network_with_mask = input_str.get('subnet')
        v4_gateway = input_str.get('gateway')

        (v4_networkString, _) = v4_network_with_mask.split('/')

        if v4_networkString == v4_gateway:
            err_str = "ERROR: In %s v4 network address and gateway " \
                "are the same" % (segment_name)
            err_list.append(err_str)

        if not self.validate_ip_for_a_given_network(\
                v4_gateway, v4_network_with_mask):
            err_str = "ERROR: Gateway %s of segment %s doesnot belong in %s" \
                % (v4_gateway, segment_name, v4_network_with_mask)
            err_list.append(err_str)

        if check_v6:
            v6_network_with_mask = input_str.get('ipv6_subnet')
            v6_gateway = input_str.get('ipv6_gateway')
            (v6_networkString, _) = v6_network_with_mask.split('/')
            if common_utils.is_ipv6_address_info_equal(v6_networkString, v6_gateway):
                err_str = "ERROR: In %s network v6 address and gateway " \
                    "are the same" % (segment_name)
                err_list.append(err_str)

            if not self.validate_ipv6_for_a_given_network(\
                    v6_gateway, v6_network_with_mask):
                err_str = "ERROR: Gateway %s of segment %s doesnot belong in %s" \
                    % (v6_gateway, segment_name, v6_network_with_mask)
                err_list.append(err_str)

        if err_list:
            err_info = ', '.join(err_list)

        return err_info

    def check_remote_management_syntax(self, input_str):
        """Check syntax for Remote Management"""

        network_with_no_pool_schema = Schema({
            Required('subnet'): self.validate_cidr_syntax,
            Required('gateway'): self.is_ip_syntax_valid,
        })

        networkv6_with_no_pool_schema = Schema({
            Required('subnet'): self.validate_cidr_syntax,
            Required('gateway'): self.is_ip_syntax_valid,
            Required('ipv6_gateway'): self.is_ipv6_syntax_valid,
            Required('ipv6_subnet'): self.validate_v6_cidr_syntax,
        })

        err_list = []
        try:
            if self.is_pod_dual_stack():
                networkv6_with_no_pool_schema(input_str)
            else:
                network_with_no_pool_schema(input_str)

        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        if err_list:
            err_str = ', '.join(err_list)
            raise Invalid(err_str)

        segment_name = "NETWORKING:remote_management"
        if self.is_pod_dual_stack():
            check_info = self.cross_check_network_subnet(input_str,
                                                         check_v6=1,
                                                         segment_name=segment_name)

        else:
            check_info = self.cross_check_network_subnet(input_str,
                                                         check_v6=0,
                                                         segment_name=segment_name)

        if re.search('ERROR:', check_info):
            raise Invalid(check_info)

        if self.is_pod_dual_stack():
            br_mgmt_ipv6 = self.get_ip_info("br_mgmt", type='v6')

            mgmtv6_network_info = self.ymlhelper.nw_get_specific_vnic_info(
                'management', 'ipv6_subnet')

            mgmtv6_gateway_info = self.ymlhelper.nw_get_specific_vnic_info(
                'management', 'ipv6_gateway')

            if mgmtv6_network_info is None:
                err_str = "v6 Network is not defined for Mgmt network"
                raise Invalid(err_str)

            if mgmtv6_gateway_info is None:
                err_str = "v6 Gateway is not defined for Mgmt network"
                raise Invalid(err_str)

            if mgmtv6_network_info is not None and \
                    self.validate_ipv6_for_a_given_network(\
                        br_mgmt_ipv6, str(mgmtv6_network_info)):
                err_str = "br_mgmt_v6: %s belongs in management network %s " \
                          "in layer3 env" % (br_mgmt_ipv6, mgmtv6_network_info)
                raise Invalid(err_str)

            prov_v6network_info = input_str.get('ipv6_subnet')
            if prov_v6network_info is not None and \
                    not self.validate_ipv6_for_a_given_network(\
                        br_mgmt_ipv6, str(prov_v6network_info)):
                err_str = "br_mgmt_v6: %s doesnot belong in remote_management " \
                          "network %s in layer3 env" \
                          % (br_mgmt_ipv6, prov_v6network_info)
                raise Invalid(err_str)

        br_mgmt_ipv4 = self.get_ip_info("br_mgmt")
        prov_network_info = input_str.get('subnet')

        mgmt_network_info = self.ymlhelper.nw_get_specific_vnic_info(
            'management', 'subnet')

        mgmt_gateway_info = self.ymlhelper.nw_get_specific_vnic_info(
            'management', 'gateway')

        if mgmt_network_info is None:
            err_str = "v4 Network is not defined for Mgmt network"
            raise Invalid(err_str)

        if mgmt_gateway_info is None:
            err_str = "v4 Gateway is not defined for Mgmt network"
            raise Invalid(err_str)

        if mgmt_network_info is not None and \
                self.validate_ip_for_a_given_network( \
                    br_mgmt_ipv4, str(mgmt_network_info)):
            err_str = "br_mgmt_v4: %s belongs in management network " \
                "%s in layer3 env;" % (br_mgmt_ipv4, mgmt_network_info)
            raise Invalid(err_str)

        if prov_network_info is not None and \
                not self.validate_ip_for_a_given_network( \
                br_mgmt_ipv4, str(prov_network_info)):
            err_str = "br_mgmt_v4: %s doesnot belong in remote_management %s " \
                "network in layer3 env" % (br_mgmt_ipv4, prov_network_info)
            raise Invalid(err_str)

    def l3_fabric_vni_check(self, input_str):
        """Check the syntax of VNI and add them in global"""

        err_msg = "Incorrect input of vnis %s for L3 Fabric " \
            "needs to be of type int between 4100 and 2^24-1" \
            % (input_str)

        if not isinstance(input_str, int):
            raise Invalid(err_msg)

        if not(4100 < input_str < 16777215):
            raise Invalid(err_msg)

        self.l3_fabric_vni_list.append(input_str)

    def validate_network_details(self, input_str):
        '''Validate Network Details'''

        if self.ymlhelper.get_pod_type() == 'ceph':
            min_input_segment_list = []
            nw_with_no_pool_segment_list = []
            max_input_segment_list = ['management', 'provision', 'cluster']
            base_segment_list = ['management', 'provision', 'cluster']
            mand_segment_list = ['management', 'provision', 'cluster']

        else:
            min_input_segment_list = ['provider', 'external']
            nw_with_no_pool_segment_list = ['api']

            max_input_segment_list = ['management', 'provision',
                                      'tenant', 'storage']

            base_segment_list = ['management', 'provision', 'api', 'tenant',
                                 'storage', 'provider', 'external']
            mand_segment_list = ['management', 'provision', 'tenant', 'api']

        if re.match('UCSM', self.testbed_type):
            base_segment_list.append('cimc')

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        if mechanism_driver == 'aci':
            base_segment_list.append('aciinfra')
            min_input_segment_list.append('aciinfra')
            mand_segment_list.append('aciinfra')

        found_sr_mpls = 0
        found_vxlan = 0
        if self.cd_cfgmgr.is_network_option_enabled('vxlan-tenant'):
            base_segment_list.append('vxlan-tenant')
            mand_segment_list.append('vxlan-tenant')
            max_input_segment_list.append('vxlan-tenant')
            found_vxlan = 1

        if self.cd_cfgmgr.is_network_option_enabled('vxlan-ecn'):
            base_segment_list.append('vxlan-ecn')
            mand_segment_list.append('vxlan-ecn')
            max_input_segment_list.append('vxlan-ecn')
            found_vxlan = 1

        if self.cd_cfgmgr.is_network_option_enabled('sr-mpls-tenant'):
            base_segment_list.append('sr-mpls-tenant')
            mand_segment_list.append('sr-mpls-tenant')
            max_input_segment_list.append('sr-mpls-tenant')
            found_sr_mpls = 1

        if self.check_for_optional_enabled('ironic'):
            base_segment_list.append('ironic')
            mand_segment_list.append('ironic')
            max_input_segment_list.append('ironic')

        found_mand_segment = {}
        for item in mand_segment_list:
            found_mand_segment[item] = 0

        networks_vlan_info = {}
        missing_segment_list = []
        incorrect_segment_list = []

        missing_info_for_no_pool_segment = []
        missing_info_for_min_segment = []
        missing_info_for_max_segment = []
        incorrect_pool_size = []
        missing_vlan_id_list = []
        incorrect_vlan_id_list = []
        err_str_list = []
        mismatch_mgmt_network = []

        err_str_prov_network = ""
        tenant_vlan_err = ""

        missing_rt_prefix_list = []
        missing_rt_suffix_list = []
        invalid_rt_suffix_list = []
        invalid_rt_suffix_syntax_list = []
        invalid_rt_len_list = []
        ironic_inspector_pool_len = 0
        ironic_inspector_pool_info = []
        invalid_inspector_pool_entry = []

        mandatory_network_schema = Schema({
            Required('segments'): list,
            Required('vlan_id'): All(self.is_input_in_ascii),
        })

        mandatory_network_vlan_schema = Schema({
            Required('segments'): list,
            Required('vlan_id'): self.validate_vlan_id_schema,
        })

        mandatory_network_vlan_l3_fabric_schema = mandatory_network_vlan_schema.extend({
            Required('l3_fabric_vni'): self.l3_fabric_vni_check,
        })

        network_with_no_pool_schema = Schema({
            Required('segments'): list,
            Required('vlan_id'): All(self.is_input_in_ascii),
            Required('subnet'): self.validate_cidr_syntax,
            Required('gateway'): self.is_ip_syntax_valid,
            Optional('l3_fabric_vni'): All(int, Range(min=4100, max=100000))
        })

        network_with_no_pool_l3_fabric_schema = network_with_no_pool_schema.extend({
            Required('l3_fabric_vni'): self.l3_fabric_vni_check,
        })

        networkv6_with_no_pool_schema = network_with_no_pool_schema.extend({
            Required('ipv6_gateway'): self.is_ipv6_syntax_valid,
            Required('ipv6_subnet'): self.validate_v6_cidr_syntax,
        })

        max_network_schema = network_with_no_pool_schema.extend({
            Required('pool'): All(list, Length(min=1)),
            Optional('rt_prefix'): All(int, Range(min=1, max=100000)),
            Optional('rt_suffix'): All(self.is_input_in_ascii),
        })

        max_network_l3_fabric_schema = network_with_no_pool_schema.extend({
            Required('pool'): All(list, Length(min=1)),
            Required('l3_fabric_vni'): self.l3_fabric_vni_check,
            Optional('rt_prefix'): All(int, Range(min=1, max=100000)),
            Optional('rt_suffix'): All(self.is_input_in_ascii),
        })

        ironic_network_schema = network_with_no_pool_schema.extend({
            Required('pool'): All(list, Length(min=1)),
            Required('inspector_pool'): All(list, Length(min=1)),
        })

        max_networkv6_schema = network_with_no_pool_schema.extend({
            Required('pool'): All(list, Length(min=1)),
            Required('ipv6_pool'): All(list, Length(min=1)),
            Required('ipv6_gateway'): self.is_ipv6_syntax_valid,
            Required('ipv6_subnet'): self.validate_v6_cidr_syntax,
            Optional('rt_prefix'): All(int, Range(min=1, max=100000)),
            Optional('rt_suffix'): All(self.is_input_in_ascii),
        })

        if input_str is None:
            raise Invalid("Missing Entry")

        error_found = 0
        found_ironic_segment = 0

        for item in input_str:
            if not self.is_input_in_ascii(item):
                err_str = "Invalid input for: " + str(item)
                err_str_list.append(err_str)
                raise Invalid(item)

            if 'ironic' in item['segments']:
                found_ironic_segment = 1

            # Check rt_prefix and rt_suffix for each segment
            if item is not None and item.get('rt_prefix') is None \
                    and item.get('rt_suffix') is None:
                pass

            elif item is not None and item.get('rt_prefix') is None \
                    and item.get('rt_suffix') is not None:
                error_found = 1
                tmp = item.get('segments')
                if tmp is not None and tmp not in missing_rt_prefix_list:
                    missing_rt_prefix_list.extend(tmp)

            elif item is not None and item.get('rt_prefix') is not None \
                    and item.get('rt_suffix') is None:
                error_found = 1
                tmp = item.get('segments')
                if tmp is not None and tmp not in missing_rt_suffix_list:
                    missing_rt_suffix_list.extend(tmp)

            elif item is not None and item.get('rt_prefix') is not None \
                    and item.get('rt_suffix') is not None:

                tmp = item.get('segments')
                rt_suffix_pat = "^([0-9]+):([0-9]+)$"

                # rt_suffix_pat has to be of type: "int:int"
                if not isinstance(item.get('rt_suffix'), str):
                    if tmp is not None and tmp not in invalid_rt_suffix_syntax_list:
                        invalid_rt_suffix_syntax_list.extend(tmp)
                elif not re.match(rt_suffix_pat, item.get('rt_suffix').strip()):
                    if tmp is not None and tmp not in invalid_rt_suffix_list:
                        invalid_rt_suffix_list.extend(tmp)
                else:

                    # Option of rt_suffix and rt_prefix allowed only for NCS-5500
                    if not self.is_tor_type_ncs5500():
                        err_str = "rt_prefix and rt_suffix option only " \
                            "allowed when TOR is NCS-5500"
                        raise Invalid(err_str)

                    # Check it the combo of rt_prefix, suffix
                    # and vlanid is < 6 octect
                    rt_prefix_str = str(item.get('rt_prefix')).strip()
                    rt_suffix_str = re.sub(r':', '', item.get('rt_suffix').strip())
                    curr_vlan_id = str(item.get('vlan_id'))

                    # Hande the special case of tenant and provider VLAN
                    if ('tenant' in item.get('segments')) \
                            or ('provider' in item.get('segments')):

                        if 'tenant' in item.get('segments'):
                            curr_vlan_info = \
                                self.ymlhelper.get_data_from_userinput_file(\
                                    ["TENANT_VLAN_RANGES"])
                        elif 'provider' in item.get('segments'):
                            curr_vlan_info = \
                                self.ymlhelper.get_data_from_userinput_file(\
                                    ["PROVIDER_VLAN_RANGES"])

                        if curr_vlan_info is not None:
                            curr_vlan_bound_list = \
                                self.fetch_vlan_boundaries(curr_vlan_info)

                            for entry in curr_vlan_bound_list:
                                if self.fetch_rt_len(rt_prefix_str,
                                                     rt_suffix_str,
                                                     entry) > 6:
                                    if tmp is not None and \
                                            tmp not in invalid_rt_len_list:
                                        error_found = 1
                                        invalid_rt_len_list.extend(tmp)

                    else:
                        if self.fetch_rt_len(rt_prefix_str,
                                             rt_suffix_str,
                                             curr_vlan_id) > 6:
                            if tmp is not None and tmp not in invalid_rt_len_list:
                                error_found = 1
                                invalid_rt_len_list.extend(tmp)

            if item is None:
                continue
            elif 'segments' not in item.keys() or item['segments'] is None:
                error_found = 1
                missing_segment_list.append(str(item))
                continue
            elif not([i for i in item['segments'] if i in base_segment_list]):
                error_found = 1
                incorrect_segment_list.append(str(item['segments']))
                continue

            elif ([i for i in item['segments'] if i in min_input_segment_list]):
                try:
                    if 'aciinfra' in item['segments']:
                        mandatory_network_vlan_schema(item)
                    elif 'external' in item['segments']:
                        if self.cd_cfgmgr.is_l3_fabric_enabled():
                            mandatory_network_vlan_l3_fabric_schema(item)
                        else:
                            mandatory_network_vlan_schema(item)
                    else:
                        mandatory_network_schema(item)
                except MultipleInvalid as e:
                    err_str = ""
                    for x in e.errors:
                        err_str = err_str + str(x) + " "
                    if err_str:
                        err_str = err_str + " for " + str(item['segments'])
                    error_found = 1
                    missing_info_for_min_segment.append(err_str)

            elif ([i for i in item['segments'] \
                   if i in nw_with_no_pool_segment_list]):
                try:
                    if self.is_ipv6_info_defined(item):
                        networkv6_with_no_pool_schema(item)
                        check_info = self.cross_check_network_subnet(item,
                                                                     check_v6=1)
                        if re.search('ERROR:', check_info):
                            error_found = 1
                            err_str_list.append(check_info)
                    else:
                        if self.cd_cfgmgr.is_l3_fabric_enabled():
                            network_with_no_pool_l3_fabric_schema(item)
                        else:
                            network_with_no_pool_schema(item)
                        check_info = self.cross_check_network_subnet(item)
                        if re.search('ERROR:', check_info):
                            error_found = 1
                            err_str_list.append(check_info)
                except MultipleInvalid as e:
                    err_str = ""
                    for x in e.errors:
                        err_str = err_str + str(x) + " "
                    if err_str:
                        err_str = err_str + " for " + str(item['segments'])
                    error_found = 1
                    missing_info_for_no_pool_segment.append(err_str)

            elif ([i for i in item['segments'] if i in max_input_segment_list]):
                try:
                    if 'ironic' in item['segments']:
                        ironic_network_schema(item)
                        check_info = self.cross_check_network_subnet(item)
                        if re.search('ERROR:', check_info):
                            error_found = 1
                            err_str_list.append(check_info)
                    elif self.is_ipv6_info_defined(item, pool_check=1):
                        max_networkv6_schema(item)
                        check_info = self.cross_check_network_subnet(item,
                                                                     check_v6=1)
                        if re.search('ERROR:', check_info):
                            error_found = 1
                            err_str_list.append(check_info)
                    else:
                        if self.cd_cfgmgr.is_l3_fabric_enabled() and \
                                'tenant' not in item['segments']:
                            max_network_l3_fabric_schema(item)
                        else:
                            max_network_schema(item)
                        check_info = self.cross_check_network_subnet(item)
                        if re.search('ERROR:', check_info):
                            error_found = 1
                            err_str_list.append(check_info)
                except MultipleInvalid as e:
                    err_str = ""
                    for x in e.errors:
                        err_str = err_str + str(x) + " "
                    if err_str:
                        err_str = err_str + " for " + str(item['segments'])
                    error_found = 1
                    missing_info_for_max_segment.append(err_str)
                    raise Invalid(err_str)

                if 'management' in item['segments']:

                    # Check pool info is in the network
                    chk_pool_in_net_stat, return_msg = \
                        self.check_pool_in_network('management',
                                                   item['subnet'],
                                                   item['pool'])
                    if not chk_pool_in_net_stat:
                        error_found = 1
                        err_str_list.append(return_msg)

                    # Check if mgmt network is not same as br_mgmt network
                    br_mgmt_ip = self.get_ip_info('br_mgmt')

                    curr_ip_pool, return_msg = \
                        self.generate_ip_pool('management', \
                                              item['pool'])
                    if return_msg:
                        error_found = 1
                        err_str_list.append(return_msg)
                    elif br_mgmt_ip in curr_ip_pool:
                        error_found = 1
                        err_str = "br_mgmt IP %s is part of IP Pool in \
                            management/provision section" % (br_mgmt_ip)
                        err_str_list.append(err_str)

                    if self.is_ipv6_info_defined(item, pool_check=1):
                        br_mgmt_ipv6 = self.get_ip_info('br_mgmt', type='v6')
                        curr_ipv6_pool, return_msg = \
                            self.generate_ip_pool('management', \
                                                  item['ipv6_pool'], \
                                                  iptype='v6')
                        if return_msg:
                            error_found = 1
                            err_str_list.append(return_msg)
                        elif br_mgmt_ipv6 in curr_ipv6_pool:
                            error_found = 1
                            err_str = "br_mgmt IPv6 %s is part of IPv6 Pool in \
                                management/provision section" % (br_mgmt_ipv6)
                            err_str_list.append(err_str)

                elif item.get('pool') is not None:
                    segment_name = ''.join(item['segments'])
                    curr_ip_pool, return_msg = \
                        self.generate_ip_pool(segment_name,
                                              item['pool'])
                    if return_msg:
                        error_found = 1
                        err_str_list.append(return_msg)

                    # Check pool info is in the network
                    chk_pool_in_net_stat, return_msg = \
                        self.check_pool_in_network(segment_name,
                                                   item['subnet'],
                                                   item['pool'])
                    if not chk_pool_in_net_stat:
                        error_found = 1
                        err_str_list.append(return_msg)

                    if 'ironic' in item['segments']:
                        ironic_inspector_pool_len = len(item.get('inspector_pool'))
                        ironic_inspector_pool_info = \
                            copy.deepcopy(item.get('inspector_pool'))
                        if ironic_inspector_pool_len == 3:
                            for entry in item.get('inspector_pool'):
                                if not re.search('[0-9.]+.*to.*[0-9.]+', entry):
                                    invalid_inspector_pool_entry.append(entry)

                            # Check pool info is in the network
                            chk_pool_in_net_stat, return_msg = \
                                self.check_pool_in_network('inspector_pool',
                                                           item['subnet'],
                                                           item['inspector_pool'])
                            if not chk_pool_in_net_stat:
                                error_found = 1
                                err_str_list.append(return_msg)

            if ([i for i in item['segments'] if i in base_segment_list]):
                # Check if all segements are defined
                for key_info in found_mand_segment.keys():
                    if key_info in item['segments']:
                        found_mand_segment[key_info] = 1

                # Gather all the legit vlan Info
                if item.get('vlan_id') is not None:
                    if item.get('vlan_id') != 'None':
                        curr_segment = item.get('segments')[0]
                        networks_vlan_info[curr_segment] = item.get('vlan_id')

                pool_size_err = self.check_ip_pool_size(item)
                if pool_size_err:
                    incorrect_pool_size.append(pool_size_err)

            if re.match(r'UCSM', self.testbed_type) and \
                    'provider' in item['segments']:

                if 'vlan_id' not in item.keys() or item['vlan_id'] is None:
                    error_found = 1
                    missing_vlan_id_list.append(str(item))
                else:
                    err_str_prov_network = \
                        self.check_vlan_range(item['vlan_id'], prov=True)
            elif not re.match(r'UCSM', self.testbed_type) and \
                    'provider' in item['segments']:

                if 'vlan_id' in item.keys() and item['vlan_id'] == 'None':
                    pass
                else:
                    error_found = 1
                    incorrect_vlan_id_list.append(str(item))

            if re.match(r'UCSM', self.testbed_type) and \
                    'tenant' in item['segments']:
                curr_info = "NETWORKING:networks:tenant:vlan_id"

                ucsm_plugin_chk = self.check_ucsm_plugin_presence()

                if ucsm_plugin_chk:
                    if item['vlan_id'] != 'None':
                        err_str = "ERROR: %s should be None when UCSM PLUGIN" \
                                  " is enabled; found to be:%s" \
                                  % (curr_info, item['vlan_id'])
                        raise Invalid(err_str)
                else:
                    if item.get('vlan_id') == 'None':
                        err_str = "ERROR: %s should be TENANT_VLAN_RANGES when " \
                            "UCSM PLUGIN is disabled; found to be:%s" \
                                  % (curr_info, item['vlan_id'])
                        raise Invalid(err_str)

                    tenant_vlan_err = self.check_vlan_range(item['vlan_id'],
                                                            prov=False,
                                                            curr_info=curr_info)
                    overlap_vlan_list = self.check_for_vlan_overlap(item['vlan_id'])
                    if overlap_vlan_list:
                        err_str = "Overlapping VLANs found in %s:%s" \
                            % (curr_info, item['vlan_id'])
                        raise Invalid(err_str)

                mechanism_driver = \
                    self.ymlhelper.get_data_from_userinput_file(\
                        ["MECHANISM_DRIVERS"])
                network_type = self.get_network_type()
                if network_type is not None and \
                        network_type.lower() == "vlan" and \
                        mechanism_driver is not None and \
                        re.match(r'openvswitch|vpp', mechanism_driver):
                    curr_info = "NETWORKING:networks:tenant:vlan_id"
                    tenant_vlan_info = \
                        self.ymlhelper.get_data_from_userinput_file(\
                            ['TENANT_VLAN_RANGES'])

                    if not ucsm_plugin_chk and tenant_vlan_info != item['vlan_id']:
                        err_str = "ERROR: %s:%s and %s:%s are not exact match" \
                            % ('TENANT_VLAN_RANGES', \
                               tenant_vlan_info, \
                               curr_info, \
                               item['vlan_id'])
                        raise Invalid(err_str)

        decoupled_mgmt_prov_network = False
        invalid_storage_network = False

        missing_mand_segment_list = []
        for curr_key in found_mand_segment.keys():
            if not found_mand_segment[curr_key]:
                missing_mand_segment_list.append(curr_key)

        # check for duplicate vlans
        duplicate_vlan_list = []
        vals = networks_vlan_info.values()
        for key, value in networks_vlan_info.items():
            if vals.count(value) > 1:
                duplicate_vlan_list.append(key)
            else:
                self.global_vlan_info[key] = \
                    common_utils.expand_vlan_range(value)

        for item in input_str:
            if 'segments' in item.keys() and item['segments'] is not None:
                if 'provision' in item['segments'] \
                        and 'management' not in item['segments']:
                    decoupled_mgmt_prov_network = True
                elif 'provision' not in item['segments'] \
                        and 'management' in item['segments']:
                    decoupled_mgmt_prov_network = True

                if not re.search(r'DEDICATED_CEPH', \
                                 self.get_storage_deployment_info()) \
                        and 'storage' in item['segments']:
                    invalid_storage_network = True

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        if mechanism_driver == 'vts' and self.check_managed_vts_config():
            # tenant segment VLAN number should have the
            # lowest VLAN number for managed VTS
            # get all the network VLANs
            network_vlan_list = self.get_vlan_list_in_networks(exclude_tenant=1)
            tenant_segment_vlan_info = \
                self.ymlhelper.nw_get_specific_vnic_info('tenant', 'vlan_id')

            provider_vlan_info = \
                self.ymlhelper.get_data_from_userinput_file(["PROVIDER_VLAN_RANGES"])
            if provider_vlan_info is not None:
                prov_vlan_bound_list = self.fetch_vlan_boundaries(provider_vlan_info)
                if prov_vlan_bound_list:
                    network_vlan_list.extend(prov_vlan_bound_list)

            tenant_vlan_range_info = \
                self.ymlhelper.get_data_from_userinput_file(["TENANT_VLAN_RANGES"])
            if tenant_vlan_range_info is not None:
                tenant_vlan_bound_list = \
                    self.fetch_vlan_boundaries(tenant_vlan_range_info)
                if tenant_vlan_bound_list:
                    network_vlan_list.extend(tenant_vlan_bound_list)

            incorrect_tenant_vlan_list = []
            for item in network_vlan_list:
                if int(tenant_segment_vlan_info) > int(item) \
                        and item not in incorrect_tenant_vlan_list:
                    incorrect_tenant_vlan_list.append(item)

            if incorrect_tenant_vlan_list:
                error_found = 1
                err_str = "VLAN %s in the tenant segment has " \
                    "to be lower than VLANs %s defined " \
                    "in the POD" % (str(tenant_segment_vlan_info), \
                                    str(incorrect_tenant_vlan_list))
                err_str_list.append(err_str)

        if self.check_for_optional_enabled('ironic') and \
                (invalid_inspector_pool_entry \
                or (ironic_inspector_pool_len != 3)):
            err_str = "3 entries of IP pool info expected " \
                "for ironic_inspector in the format " \
                "ip_add_1 to ip_add_2, " \
                "ip_add_3 to ip_add_4, " \
                "ip_add_5 to ip_add_6, found to be %s" % \
                (', '.join(ironic_inspector_pool_info))
            if ironic_inspector_pool_len != 3:
                error_found = 1
                err_str_list.append(err_str)

            elif invalid_inspector_pool_entry:
                error_found = 1
                err_str_list.append(err_str)

        if missing_rt_suffix_list:
            error_found = 1
            err_str = "Missing rt_suffix info when rt_prefix is defined " \
                "for %s segment(s)" % ','.join(missing_rt_suffix_list)
            err_str_list.append(err_str)

        if missing_rt_prefix_list:
            error_found = 1
            err_str = "Missing rt_prefix info when rt_suffix is defined " \
                "for %s segment(s)" % ','.join(missing_rt_prefix_list)
            err_str_list.append(err_str)

        if invalid_rt_len_list:
            error_found = 1
            err_str = "rt_prefix:rt_suffix_Vlan_id is greater than 6 " \
                "Octets for %s segments(s)" % ','.join(invalid_rt_len_list)
            err_str_list.append(err_str)

        if invalid_rt_suffix_syntax_list:
            error_found = 1
            err_str = "Syntax for rt_suffix doesnot match " \
                "<Region_info>:<pod_region_number> in quotes for " \
                "%s segment(s)" % ','.join(invalid_rt_suffix_syntax_list)
            err_str_list.append(err_str)

        if invalid_rt_suffix_list:
            error_found = 1
            err_str = "Syntax for rt_suffix doesnot match " \
                "<Region_info>:<pod_region_number> for %s segment(s)" \
                % ','.join(invalid_rt_suffix_list)
            err_str_list.append(err_str)

        if self.check_for_optional_enabled('ironic'):

            if not found_ironic_segment:
                err_str = "Network segment ironic not " \
                    "defined when ironic is defined as an " \
                    "optional service"
                error_found = 1
                err_str_list.append(err_str)

        else:
            if found_ironic_segment:
                err_str = "Network segment ironic " \
                    "defined when ironic is not defined as an " \
                    "optional service"
                error_found = 1
                err_str_list.append(err_str)

        if found_sr_mpls and found_vxlan:
            err_str = "sr-mpls and vxlan network segments are " \
                "mututally exclusive"
            err_str_list.append(err_str)

        if duplicate_vlan_list:
            error_found = 1
            err_str = "Duplicate VLANs in networks segment %s " \
                % (str(duplicate_vlan_list))
            err_str_list.append(err_str)

        if missing_mand_segment_list:
            error_found = 1
            err_str = "Missing Mandatory networks segment %s " \
                % (str(missing_mand_segment_list))
            err_str_list.append(err_str)

        if tenant_vlan_err:
            error_found = 1
            err_str_list.append(tenant_vlan_err)

        if mismatch_mgmt_network:
            error_found = 1
            err_str = ' '.join(mismatch_mgmt_network)
            err_str_list.append(err_str)

        if invalid_storage_network:
            error_found = 1
            err_str = "Dedicated storage Network defined in central " \
                      "storage environment"
            err_str_list.append(err_str)

        if decoupled_mgmt_prov_network:
            error_found = 1
            err_str = "Management and Provision Network " \
                "can't be separate for Cisco VIM Supported POD"
            err_str_list.append(err_str)

        if incorrect_pool_size:
            error_found = 1
            err_str = ''.join(incorrect_pool_size)
            err_str_list.append(err_str)

        if err_str_prov_network:
            error_found = 1
            err_str_list.append(err_str_prov_network)

        if missing_vlan_id_list:
            err_str = "Missing vlan_id for segement" + \
                      ''.join(missing_vlan_id_list)
            err_str_list.append(err_str)

        if incorrect_vlan_id_list:
            err_str = "Expected vlan_id value to be None, found to be " + \
                      ''.join(incorrect_vlan_id_list)
            err_str_list.append(err_str)

        if missing_info_for_no_pool_segment:
            err_str = ' '.join(missing_info_for_no_pool_segment)
            err_str_list.append(err_str)

        if missing_info_for_min_segment:
            err_str = ' '.join(missing_info_for_min_segment)
            err_str_list.append(err_str)

        if missing_info_for_max_segment:
            err_str = ' '.join(missing_info_for_max_segment)
            err_str_list.append(err_str)

        if missing_segment_list:
            err_str = "Missing Segment Info for " + \
                      ''.join(missing_segment_list)
            err_str_list.append(err_str)

        if incorrect_segment_list:
            err_str = "Incorrect Segment Info for " + \
                      ''.join(incorrect_segment_list)
            err_str_list.append(err_str)

        if error_found:
            raise Invalid(', '.join(err_str_list))

        return

    def admin_ssh_key(self, key_str):
        '''checks the key'''

        err_str = ""

        if key_str is None:
            return
        for item in key_str:
            if re.match(r'ssh-rsa|ssh-ed25519', item):
                continue
            else:
                err_str = "Invalid SSH Key Syntax, \
                          needs to start with ssh-rsa AAAA or ssh-ed25519 AAAA"

        if err_str:
            raise Invalid(err_str)

    def match_kickstart_entry(self, input_str):
        '''checks the key'''

        if not self.is_input_in_ascii(input_str):
            raise Invalid(input_str)
        if not re.search(r'.ks', input_str):
            raise Invalid(input_str)
        # NOTE: commented out to allow consolidated kickstart file
        #elif not re.search(r'compute|control|storage|vts', input_str):
        #    raise Invalid(input_str)


    def validate_kickstart_info(self, kickstart_info):
        '''Validate the kickstart info entry'''

        vim_20_ks = "ucs-b-and-c-series.ks"
        vim_10_c_cntl_ks = "control-flexflash-c220m4.ks"
        vim_10_c_comp_ks = "compute-flexflash-c220m4.ks"
        vim_10_ceph_ks = "storage-flexflash-c240m4.ks"

        vim_10_b_cntl_ks = "control-flexflash-b200m4.ks"
        vim_10_b_comp_ks = "compute-flexflash-b200m4.ks"

        vim_20_b_us_ks = "ucs-b-and-c-series-unsupported.ks"

        kickstart_standalone_schema = Schema({
            Optional('control'): In(frozenset([vim_20_ks, vim_10_c_cntl_ks]), \
                                    msg='only %s or %s allowed as values' \
                                        % (vim_20_ks, vim_10_c_cntl_ks)),
            Optional('compute'): In(frozenset([vim_20_ks, vim_10_c_comp_ks]), \
                                    msg='only %s or %s allowed as values' \
                                        % (vim_20_ks, vim_10_c_comp_ks)),
            Optional('block_storage'): In(frozenset([vim_20_ks, vim_10_ceph_ks]), \
                                          msg='only %s or %s allowed as values' \
                                              % (vim_20_ks, vim_10_ceph_ks)),
            Optional('vts'): All(str, Length(min=1)),
            Optional('kube'): All(str, Length(min=1)),
        })

        kickstart_ucsm_schema = Schema({
            Optional('control'): In(frozenset([vim_20_ks, vim_10_b_cntl_ks,
                                               vim_20_b_us_ks]), \
                                    msg='only %s or %s allowed as values' \
                                        % (vim_20_ks, vim_10_b_cntl_ks)),
            Optional('compute'): In(frozenset([vim_20_ks, vim_10_b_comp_ks,
                                               vim_20_b_us_ks]), \
                                    msg='only %s or %s allowed as values' \
                                        % (vim_20_ks, vim_10_b_comp_ks)),
            Optional('block_storage'): In(frozenset([vim_20_ks, vim_10_ceph_ks]), \
                                          msg='only %s or %s allowed as values' \
                                              % (vim_20_ks, vim_10_ceph_ks)),
            Optional('vts'): All(str, Length(min=1)),
            Optional('kube'): All(str, Length(min=1)),
        })

        if re.match(r'UCSM', self.testbed_type):
            kickstart_ucsm_schema(kickstart_info)
        else:
            kickstart_standalone_schema(kickstart_info)

    def check_for_ceph_servers_info(self, input_str):
        '''Check if dedicated ceph servers exist'''

        if input_str is None:
            return 1
        elif isinstance(input_str, list):
            return 1

        raise Invalid(input_str)

    def validate_list_unique_entry(self, input_str):
        '''validate_list_unique_entry min length of 1 and unique'''

        err_str = "Input has to be of type list with unique entry"
        if not isinstance(input_str, list):
            raise Invalid(err_str)
        elif not input_str:
            raise Invalid(err_str)

        dup_info_exists = self.check_for_dups_in_list(input_str)

        if dup_info_exists:
            err_str1 = "%s; Duplicate entry found:%s" \
                % (err_str, ','.join(dup_info_exists))
            raise Invalid(err_str1)

        return

    def validate_roles(self, input_roles):
        '''Validate controller, compute or storage'''

        err_str_list = []
        error_found = 0
        invalid_input_type = []
        missing_role_list = []
        invalid_role_list = []
        missing_entry_list = []
        missing_min_ceph_node = []

        role_schema = Schema({
            Required('control'): self.validate_list_unique_entry,
            Required('compute'): self.validate_list_unique_entry,
            Optional('block_storage'): self.check_for_ceph_servers_info,
            Optional('networker'): All(self.is_input_in_ascii),
            Optional('object_storage'): All(self.is_input_in_ascii),
            Optional('vts'): list,
            Optional('kube'): list,
        })

        ceph_role_schema = Schema({
            Required('cephcontrol'): self.validate_list_unique_entry,
            Required('cephosd'): self.check_for_ceph_servers_info,
        })

        num_storage = 3

        try:
            if self.ymlhelper.get_pod_type() == 'ceph':
                ceph_role_schema(input_roles)
            else:
                role_schema(input_roles)
        except MultipleInvalid as e:
            err_str = ""
            for x in e.errors:
                err_str = err_str + str(x) + " "
                error_found = 1
                missing_role_list.append(err_str)

        # get the role info to check it against base role_types
        for role in input_roles:
            if re.search(r'control|compute', role) and input_roles[role] is None:
                error_found = 1
                missing_entry_list.append(role)
            elif re.search(r'block_storage', role) and \
                    input_roles[role] is not None:

                if re.search(r'remove_osd', self.curr_action):
                    num_storage = 2

                if len(input_roles[role]) < num_storage:
                    error_found = 1
                    missing_min_ceph_node.append(role)

        if invalid_input_type:
            err_str = "InvalidInputType for " + \
                      ''.join(invalid_input_type)
            err_str_list.append(err_str)

        if missing_entry_list:
            err_str = "Missing Devices for Role: " + \
                      ' '.join(missing_entry_list)
            err_str_list.append(err_str)
        elif missing_role_list:
            err_str = "Missing/DuplicateRoleFound: " + \
                      ' '.join(missing_role_list)
            err_str_list.append(err_str)

        if invalid_role_list:
            err_str = "InvalidRoleFound " + \
                      ' '.join(invalid_role_list)
            err_str_list.append(err_str)

        if missing_min_ceph_node:
            err_str = "Num of dedicated block_storage nodes allowed:" + \
                      str(num_storage) + ", Found:" + \
                      str(len(input_roles['block_storage']))
            err_str_list.append(err_str)

        if error_found:
            raise Invalid(','.join(err_str_list))

        return

    def is_static_ip_defined(self, network):
        """ examine if ip is defined for any node"""

        role_profiles = self.ymlhelper.rp_get_all_roles()
        if role_profiles is None:
            return 0

        for role in role_profiles:
            svr_list = self.ymlhelper.get_server_list(role=role)
            for server in svr_list:
                if network == "tenant":
                    ip = self.ymlhelper.get_server_static_tenant_ip(server)
                elif network == "storage":
                    ip = self.ymlhelper.get_server_static_storage_ip(server)
                elif network == "cluster":
                    ip = self.ymlhelper.get_server_static_cluster_ip(server)
                else:
                    ip = self.ymlhelper.get_server_static_mgmt_ip(server)

                if ip is not None:
                    return 1

        return 0

    def is_static_ipv6_defined(self, network):
        """ examine if ipv6 is defined for any node"""

        role_profiles = self.ymlhelper.rp_get_all_roles()
        if role_profiles is None:
            return 0

        for role in role_profiles:
            svr_list = self.ymlhelper.get_server_list(role=role)
            for server in svr_list:
                ip = self.ymlhelper.get_server_static_mgmt_ipv6(server)

                if ip is not None:
                    return 1

        return 0

    def is_static_mgmt_ipv6_defined(self):
        """ examine if management ip is defined for any node"""
        return self.is_static_ipv6_defined("management")

    def is_static_mgmt_ip_defined(self):
        """ examine if management ip is defined for any node"""
        return self.is_static_ip_defined("management")

    def is_static_storage_ip_defined(self):
        """ examine if storage ip is defined for any node"""
        return self.is_static_ip_defined("storage")

    def is_static_cluster_ip_defined(self):
        """ examine if cluster ip is defined for any node"""
        return self.is_static_ip_defined("cluster")

    def is_static_tenant_ip_defined(self):
        """ examine if tenant ip is defined for any node"""
        return self.is_static_ip_defined("tenant")

    def validate_internal_lb_vip_entry(self, input_str):
        '''Validates the info regarding internal vip'''

        err_str = ""

        self.is_mgmt_ip_valid(input_str, "internal_lb_vip_entry")

        if self.is_static_mgmt_ip_defined():
            if self.does_dup_mgmt_ip_exist(input_str):
                err_str = "internal_lb_vip_entry " + str(input_str) + \
                          " overlaps with statically defined Management IP"

                raise Invalid(err_str)

        # Check if internal_lb_vip_entry is not same as br_mgmt
        br_mgmt_ip = self.get_ip_info("br_mgmt")

        if str(br_mgmt_ip) == str(input_str):
            err_str = "internal_lb_vip_entry " + str(input_str) + \
                      " is same as br_mgmt of management node; \
                      Please adjust the intenral_lb_vip_entry"

            raise Invalid(err_str)

        # Check if internal_lb_vip_entry is not same as br_api
        br_api_ip = self.get_ip_info("br_api")

        if str(br_api_ip) == str(input_str):
            err_str = "internal_lb_vip_entry " + str(input_str) + \
                      " is same as br_api of management node; \
                      Please adjust the intenral_lb_vip_entry"

            raise Invalid(err_str)

        self.global_admin_ip_list.append(br_api_ip)
        return

    def validate_internal_lb_ipv6_vip_entry(self, input_str):
        '''Validates the info regarding internal vip'''

        err_str = ""
        default_entry = "internal_lb_ipv6_vip_entry"

        if self.is_ipv6_syntax_valid(input_str) is not None:
            err_str = "Invalid " + default_entry + " for " + input_str
            raise Invalid(err_str)

        self.is_mgmt_ipv6_valid(input_str, default_entry)

        if self.is_static_mgmt_ipv6_defined():
            if self.does_dup_mgmt_ip_exist(input_str, iptype='v6'):
                err_str = "%s %s overlaps with statically defined Management IP" \
                    % (default_entry, input_str)
                raise Invalid(err_str)

        # Check if internal_lb_vip_entry is not same as br_mgmt
        br_mgmt_ipv6 = self.get_ip_info("br_mgmt", type='v6')

        if common_utils.is_ipv6_address_info_equal(br_mgmt_ipv6, input_str):
            err_str = "%s %s is same as br_mgmt_v6 of management node; " \
                "Please adjust the %s" \
                % (default_entry, input_str, default_entry)

            raise Invalid(err_str)

        # Check if internal_lb_vip_entry is not same as br_api
        try:
            br_api_ipv6 = self.get_ip_info("br_api", type='v6')

            if common_utils.is_ipv6_address_info_equal(br_api_ipv6, input_str):
                err_str = "%s %s is same as br_api_v6 of management node; " \
                    "Please adjust the %s" \
                    % (default_entry, input_str, default_entry)
                raise Invalid(err_str)

            self.global_admin_ipv6_list.append(br_api_ipv6)
        except Exception:  # nosec
            pass

        return

    def get_ip_info(self, intf_name, type='v4'):
        '''Gets ip info given an intf name'''

        if type == 'v4':
            show_command = ['/usr/sbin/ip', 'addr', 'show', intf_name]
        else:
            show_command = ['/usr/sbin/ip', '-6', 'addr', 'show', intf_name]

        error_found = 0
        output = ""
        try:
            output = subprocess.check_output(show_command)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found:
            err_str = "Couldnt execute " + ' '.join(show_command) + \
                " on management node"
            raise Invalid(err_str)

        for item in output.splitlines():

            if re.search(r'inet', item) and re.search(intf_name, item) and \
                    re.search('inet.* ([0-9./]+).* brd', item) and \
                    type == 'v4':

                ipaddr_search = re.search('inet.* ([0-9./]+).* brd', item)
                ipaddr_info = ipaddr_search.group(1)
                ipaddr_details = ipaddr_info.split("/")

                if len(ipaddr_details) != 2:
                    err_str = "IP addr of bridge " + intf_name + \
                              " doesn't have addr/mask"
                    raise Invalid(err_str)
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    my_ipaddr = socket.inet_ntoa(
                        fcntl.ioctl(s.fileno(),
                                    0x8915,
                                    struct.pack('256s', intf_name[:15]))[20:24])

                    return my_ipaddr

            elif re.search(r'inet6', item) and \
                    re.search('scope.* global', item) and \
                    re.search('inet6.* ([a-zA-Z0-9:/]+).* scope', item.strip()) \
                    and type == 'v6':

                ipaddr_search = re.search('inet6.* ([a-zA-Z0-9:/]+).* scope', item)
                ipaddr_info = ipaddr_search.group(1)
                ipaddr_details = ipaddr_info.split("/")

                if len(ipaddr_details) != 2:
                    err_str = "IPv6 addr of bridge " + intf_name + \
                              " doesn't have addr/mask"
                    raise Invalid(err_str)
                elif not common_utils.is_valid_ipv6_address(ipaddr_details[0]):
                    err_str = "IPv6 addr of bridge " + intf_name + \
                              " doesn't have valid addr"
                    raise Invalid(err_str)
                else:
                    addrs = netifaces.ifaddresses(intf_name)
                    my_ipaddr = addrs[netifaces.AF_INET6][0]['addr']
                    return my_ipaddr

        show_command_str = ' '.join(show_command)
        template = "; Expected format: inet ipaddr/mask brd brd_ip scope global " + \
                   intf_name
        err_str = "Couldnt find ip info in mgmt node in the correct format for " + \
                  intf_name + " in the output of " + show_command_str + template

        raise Invalid(err_str)

    def check_valid_solidfire_svip(self, input_str):
        '''Checks that SOLIDFIRE CLUSTER svip syntax is correct
        and its in the management or storage network'''

        mgmt_network_check = 0
        storage_network_check = 0

        if not re.search(r'DEDICATED_CEPH', self.get_storage_deployment_info()):
            err_str = "Only supported with DEDICATED_CEPH"
            raise Invalid(err_str)

        if self.is_ip_syntax_valid(input_str) is not None:
            err_str = "Invalid SOLIDFIRE:cluster_svip for " + input_str
            raise Invalid(err_str)

        mgmt_network = \
            self.ymlhelper.nw_get_specific_vnic_info( \
                'management', 'subnet')
        if self.validate_ip_for_a_given_network( \
                input_str, mgmt_network):
            mgmt_network_check = 1

        storage_network = \
            self.ymlhelper.nw_get_specific_vnic_info( \
                'storage', 'subnet')
        if self.validate_ip_for_a_given_network( \
                input_str, storage_network):
            storage_network_check = 1

        if storage_network_check or mgmt_network_check:
            pass
        elif storage_network_check or mgmt_network_check:
            err_str = "Cannot be poart of management and storage network"
            raise Invalid(err_str)
        else:
            err_str = "Needs to be in management/storage network"
            raise Invalid(err_str)

        if mgmt_network_check:
            self.is_mgmt_ip_valid(input_str, "SOLIDFIRE:cluster_svip")
            if self.is_static_mgmt_ip_defined():
                if self.does_dup_mgmt_ip_exist(input_str):
                    err_str = "Solidfire cluster svip %s " \
                        "overlaps with statically defined Management IP" \
                        % (input_str)
                    raise Invalid(err_str)

            int_lb_info = self.ymlhelper.get_data_from_userinput_file(
                ['internal_lb_vip_address'])
            if str(int_lb_info) == str(input_str):
                err_str = "Solidfire cluster svip %s " \
                          "is same as internal_lb_vip_entry" \
                          % (input_str)
                raise Invalid(err_str)

            # Check if Collector IP is not same as br_mgmt
            br_mgmt_ip = self.get_ip_info("br_mgmt")

            if str(br_mgmt_ip) == str(input_str):
                err_str = "Solidfire cluster svip %s " \
                          "is same as br_mgmt of management node; " \
                          "Please adjust the Solidfire cluster svip" \
                          % (input_str)
                raise Invalid(err_str)

            # Check if internal_lb_vip_entry is not same as br_api
            br_api_ip = self.get_ip_info("br_api")

            if str(br_api_ip) == str(input_str):
                err_str = "Solidfire cluster svip %s " \
                          "is same as br_api of management node; " \
                          "Please adjust the Solidfire cluster svip" \
                          % (input_str)

                raise Invalid(err_str)
        else:
            self.is_segment_ip_valid(input_str,
                                     default_entry="SOLIDFIRE:cluster_svip",
                                     segment_info="storage")

        return

    def check_valid_solidfire_mvip(self, input_str):
        '''Checks that SOLIDFIRE CLUSTER mvip is correct;
        along with ip address syntax, ensure its in the API network
        '''

        default_entry = "SOLIDFIRE:cluster_mvip"
        self.validate_external_lb_vip_entry(input_str,
                                            default_entry,
                                            skip_network_check=1)

        haproxy_vip = self.ymlhelper.get_data_from_userinput_file( \
            ['external_lb_vip_address'])

        if str(haproxy_vip) == str(input_str):
            err_str = "%s %s is same as external_lb_vip_address; \
                      Please adjust the %s" \
                      % (default_entry, input_str, default_entry)

            raise Invalid(err_str)

        return

    def check_valid_nfvimon_mgmt_ip(self, input_str):
        '''Checks that NFVIMON mgmt ip is correct'''

        self.is_mgmt_ip_valid(input_str, "NFVIMON_Collector_Mgmt_IP")

        if self.is_static_mgmt_ip_defined():
            if self.does_dup_mgmt_ip_exist(input_str):
                err_str = "NFVIMON Collector Mgmt IP " + str(input_str) + \
                          " overlaps with statically defined Management IP"
                raise Invalid(err_str)

        int_lb_info = self.ymlhelper.get_data_from_userinput_file(
            ['internal_lb_vip_address'])
        if str(int_lb_info) == str(input_str):
            err_str = "NFVIMON Collector Mgmt IP " + str(input_str) + \
                      " is same as internal_lb_vip_entry"
            raise Invalid(err_str)

        # Check if Collector IP is not same as br_mgmt
        br_mgmt_ip = self.get_ip_info("br_mgmt")

        if str(br_mgmt_ip) == str(input_str):
            err_str = "NFVIMON Collector Mgmt IP " + str(input_str) + \
                      " is same as br_mgmt of management node; \
                      Please adjust the Collector Mgmt IP"

            raise Invalid(err_str)

        # Check if internal_lb_vip_entry is not same as br_api
        br_api_ip = self.get_ip_info("br_api")

        if str(br_api_ip) == str(input_str):
            err_str = "NFVIMON Collector Mgmt IP " + str(input_str) + \
                      " is same as br_api of management node; \
                      Please adjust the Collector Mgmt IP"

            raise Invalid(err_str)

        return

    def check_valid_nfvimon_admin_ip(self, input_str):
        '''Checks that NFVIMON admin ip is correct'''

        err_str = ""
        default_entry = "Collector Admin IP "

        self.is_ip_syntax_valid(input_str)

        # Check if admin_ip is not same as br_api
        br_api_ip = self.get_ip_info("br_api")
        if str(br_api_ip) == str(input_str):
            err_str = str(input_str) + " is same as br_api of management node; " + \
                "Please adjust the " + default_entry

            raise Invalid(err_str)

        # Check if admin is not same as br_mgmt
        br_mgmt_ip = self.get_ip_info("br_mgmt")

        if str(br_mgmt_ip) == str(input_str):
            err_str = str(input_str) + " is same as br_mgmt of management node; \
                Please adjust the " + default_entry
            raise Invalid(err_str)

        # Check if admin ip is not in br_mgmt network
        addrs = netifaces.ifaddresses("br_mgmt")
        br_mgmt_mask = addrs[netifaces.AF_INET][0]['netmask']
        br_mgmt_cidr = br_mgmt_ip + "/" + br_mgmt_mask
        br_mgmt_network = str(netaddr.IPNetwork(br_mgmt_cidr).cidr)
        if self.validate_ip_for_a_given_network(
                input_str, br_mgmt_network):
            err_str = "%s: %s belongs in %s;" \
                      % (default_entry, input_str, br_mgmt_network)
            raise Invalid(err_str)

        return

    def validate_intel_sriov_entry(self, input_str):
        '''Validate Intel SRIOV entry'''

        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])

        vic_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_INTEL_SRIOV'])

        err_msg = "SRIOV Config only supported when " \
                  "INTEL_NIC_SUPPORT or CISCO_VIC_INTEL_SRIOV is True"

        if intel_nic_check or vic_nic_check:
            pass
        elif intel_nic_check and vic_nic_check:
            raise Invalid(err_msg)
        else:
            raise Invalid(err_msg)

        upper_limit = 32
        if vic_nic_check:
            upper_limit = 63

        err_str = "SRIOV VFS must be an integer between 1 and %s ; " \
                  "Found to be %s" % (upper_limit, input_str)

        if not self.is_input_an_integer(input_str):
            raise Invalid(err_str)

        if input_str < 1 or input_str > upper_limit:
            raise Invalid(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        network_type = self.get_network_type()
        if network_type is not None and \
                network_type.lower() == "vxlan" and \
                mechanism_driver is not None and \
                re.match(r'linuxbridge', mechanism_driver):
            err_str = "SRIOV for Intel NIC only allowed for " \
                      "OVS/VLAN"
            raise Invalid(err_str)
        elif mechanism_driver is not None and \
                mechanism_driver == 'vts':
            err_str = "SRIOV for Intel NIC only allowed for " \
                      "OVS/VLAN"
            raise Invalid(err_str)

        return

    def validate_vista_creek_sriov_entry(self, input_str):
        '''Validate Vista Creek SRIOV VFs entry: INTEL_VC_SRIOV_VFS'''

        self.validate_vc_sriov_fpga_vfs_entry(\
            input_str, 'INTEL_VC_SRIOV_VFS', 'INTEL_FPGA_VFS', 32)

    def validate_vista_creek_vfs_entry(self, input_str):
        '''Validate Vista Creek VFs entry: INTEL_FPGA_VFS'''

        self.validate_vc_sriov_fpga_vfs_entry( \
            input_str, 'INTEL_FPGA_VFS', 'INTEL_VC_SRIOV_VFS', 8)


    def validate_vc_sriov_fpga_vfs_entry(\
            self, input_str, target_name, peer_name, upper_limit):
        '''Validate Vista Creek SRIOV VFs entry: INTEL_VC_SRIOV_VFS'''

        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])

        curr_pod_type = self.ymlhelper.get_pod_type()
        err_msg = "%s only supported when " \
            "INTEL_NIC_SUPPORT is True and %s is defined " \
            "on Quanta servers at a global level for pod_type:%s " \
            % (target_name, peer_name, curr_pod_type)

        if curr_pod_type != 'edge' and curr_pod_type != 'nano':
            raise Invalid(err_msg)

        if not self.cd_cfgmgr.is_platform_qct():
            raise Invalid(err_msg)

        if intel_nic_check:
            pass
        else:
            raise Invalid(err_msg)

        if not self.ymlhelper.get_data_from_userinput_file([peer_name]):
            raise Invalid(err_msg)

        err_str = "Input for %s must be an integer " \
                  "between 1 and %s ; Found to be %s" \
                  % (target_name, upper_limit, input_str)

        if not self.is_input_an_integer(input_str):
            raise Invalid(err_str)

        if input_str < 1 or input_str > upper_limit:
            raise Invalid(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        network_type = self.get_network_type()
        if network_type is not None and \
                network_type.lower() != "vlan" and \
                mechanism_driver is not None and \
                mechanism_driver != 'openvswitch':
            err_str = "%s is allowed only OVS/VLAN" % (target_name)
            raise Invalid(err_str)

        return

    def validate_intel_n3000_firmware(self, input_str):
        # Sample config format:
        # ====================
        # INTEL_N3000_FIRMWARE:
        #   user_image_bitstream_id: '0x2392920A010501'
        #   user_image_file: phase1_turbo4g_2x1x25g_1fvl_raw_20ww02_unsigned.bin
        #   xl710_config_file: nvmupdate_25G_0D58.cfg
        #   xl710_image_file: PSG_XL710_7p00_CFGID2p61_XLAUI_DID_0D58_K32246_800052B0.bin
        intel_n3000_firmware_schema = Schema({
            Optional('user_image_bitstream_id'): All(
                str, Length(min=2, max=18),
                msg="Must be string start with 0x and max 18 characters"),
            Optional('user_image_file'): All(str, msg="User image file name"),
            Optional('xl710_config_file'): All(str,
                                               msg="XL710 config file name"),
            Optional('xl710_image_file'): All(str,
                                              msg="XL710 image file name"),
        }, extra=False)

        try:
            intel_n3000_firmware_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        if (input_str.get("user_image_bitstream_id") and
                not input_str.get("user_image_file")):
            raise Invalid("Missing 'user_image_file' info")
        if (not input_str.get("user_image_bitstream_id") and
                input_str.get("user_image_file")):
            raise Invalid("Missing 'user_image_bitstream_id' info")

        if (input_str.get("xl710_config_file") and
                not input_str.get("xl710_image_file")):
            raise Invalid("Missing 'xl710_config_file' info")
        if (not input_str.get("xl710_config_file") and
                input_str.get("xl710_image_file")):
            raise Invalid("Missing 'xl710_image_file' info")

        if (input_str.get("user_image_bitstream_id") and
                not input_str["user_image_bitstream_id"].startswith("0x")):
            raise Invalid("'user_image_bitstream_id' have to start with '0x'")

        if input_str.get("user_image_file"):
            uif = "%s/%s" % (self.cfg_dir, input_str["user_image_file"])
            if not os.path.isfile(uif):
                raise Invalid("Could not find user_image_file at %s" % uif)
        if input_str.get("xl710_config_file"):
            xcf = "%s/%s" % (self.cfg_dir, input_str["xl710_config_file"])
            if not os.path.isfile(xcf):
                raise Invalid("Could not find xl710_config_file at %s" % xcf)
        if input_str.get("xl710_image_file"):
            xif = "%s/%s" % (self.cfg_dir, input_str["xl710_image_file"])
            if not os.path.isfile(xif):
                raise Invalid("Could not find xl710_image_file at %s" % xif)
        return

    def validate_external_lb_ipv6_vip_entry(self, input_str):
        '''Validates the info regarding external ipv6 vip'''

        err_str = ""
        default_entry = "external_lb_ipv6_vip_entry"

        if self.is_ipv6_syntax_valid(input_str) is not None:
            err_str = "Invalid " + default_entry + " for " + input_str
            raise Invalid(err_str)

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        if podtype != "ceph":
            api_network_info = self.ymlhelper.nw_get_specific_vnic_info(
                'api', 'ipv6_subnet')

            api_gateway_info = self.ymlhelper.nw_get_specific_vnic_info(
                'api', 'ipv6_gateway')

            if api_network_info is None:
                err_str = "IPv6 Network is not defined for API network"
                raise Invalid(err_str)

            if api_gateway_info is None:
                err_str = "ipv6 Gateway is not defined for API network"
                raise Invalid(err_str)

            if common_utils.is_ipv6_address_info_equal(input_str, api_gateway_info):
                err_str = "%s: %s matches the API IPv6 network gw info" \
                    % (default_entry, input_str)
                raise Invalid(err_str)

            if not self.validate_ipv6_for_a_given_network(
                    input_str, api_network_info):
                err_str = "%s: %s doesn't belong in %s;" \
                    % (default_entry, input_str, api_network_info)
                raise Invalid(err_str)

            # Check if external_lb_vip_entry is not same as br_api
            try:
                br_api_ipv6 = self.get_ip_info("br_api", type='v6')

                if common_utils.is_ipv6_address_info_equal(br_api_ipv6, input_str):
                    err_str = "external_lb_ipv6_vip_entry " + str(input_str) + \
                        " is same as br_api_ipv6 of management node; \
                        Please adjust the external_lb_ipv6_vip_entry"

                    raise Invalid(err_str)
            except Exception:  # nosec
                pass

            # Check if external_lb_vip_entry is not same as br_mgmt
            br_mgmt_ipv6 = self.get_ip_info("br_mgmt", type='v6')

            if common_utils.is_ipv6_address_info_equal(br_mgmt_ipv6, input_str):
                err_str = "external_lb_ipv6_vip_entry " + str(input_str) + \
                    " is same as br_mgmt_ipv6 of management node; \
                    Please adjust the external_lb_ipv6_vip_entry"
                raise Invalid(err_str)

        else:

            if not self.is_central_cvimmon():
                err_str = "Entry supported only for central CVIM-MON"
                raise Invalid(err_str)

            mgmt_network_info = self.ymlhelper.nw_get_specific_vnic_info(
                'management', 'ipv6_subnet')

            mgmt_gateway_info = self.ymlhelper.nw_get_specific_vnic_info(
                'management', 'ipv6_gateway')

            if mgmt_network_info is None:
                err_str = "IPv6 Network is not defined for management network"
                raise Invalid(err_str)

            if mgmt_gateway_info is None:
                err_str = "IPv6 Gateway is not defined for management network"
                raise Invalid(err_str)

            if common_utils.is_ipv6_address_info_equal(input_str, mgmt_gateway_info):
                err_str = "%s: %s matches the management IPv6 network gw info" \
                    % (default_entry, input_str)
                raise Invalid(err_str)

            if not self.validate_ipv6_for_a_given_network(
                    input_str, mgmt_network_info):
                err_str = "%s: %s doesn't belong in %s;" \
                    % (default_entry, input_str, mgmt_network_info)
                raise Invalid(err_str)

            # Check if external_lb_vip_entry is not same as br_mgmt
            try:
                br_mgmt_ipv6 = self.get_ip_info("br_mgmt", type='v6')

                if common_utils.is_ipv6_address_info_equal(br_mgmt_ipv6, input_str):
                    err_str = "external_lb_ipv6_vip_entry " + str(input_str) + \
                        " is same as br_mgmt_ipv6 of management node; \
                        Please adjust the external_lb_ipv6_vip_entry"

                    raise Invalid(err_str)
            except Exception:  # nosec
                pass

        return

    def validate_vts_vts_api_entry(self, input_str):
        '''validates the sytax of VTS_VTC_API_IP'''

        default_entry = "VTS_VTC_API_IP"
        self.validate_external_lb_vip_entry(input_str, default_entry)

        haproxy_vip = self.ymlhelper.get_data_from_userinput_file(\
            ['external_lb_vip_address'])

        if str(haproxy_vip) == str(input_str):
            err_str = "%s %s is same as external_lb_vip_address; \
                      Please adjust the %s" \
                      % (default_entry, input_str, default_entry)

            raise Invalid(err_str)

        return

    def validate_xrnc_tenant_ips(self, input_str):
        '''Validates VTS_XRNC_TENANT_IPS; has to be a list of 2 IPv4s
        where the IPs have to belong to the tenant nework but not in the
        tenant IP pool'''

        default_entry = "VTS_XRNC_TENANT_IPS"
        err_str = "Input %s has to be of type list with 1 or 2 IPv4 entry, " \
            "where the the IPs have to belong to the tenant nework " \
            "but not in the tenant IP pool" % (default_entry)

        if not isinstance(input_str, list):
            raise Invalid(err_str)
        elif len(input_str) > 2:
            raise Invalid(err_str)
        elif not input_str:
            raise Invalid(err_str)

        for item in input_str:
            self.is_ip_syntax_valid(item)
            self.is_tenant_ip_valid(item, check_absent_from_pool=1)

    def validate_external_lb_vip_entry(self, input_str,
                                       default_entry="external_lb_vip_entry",
                                       skip_network_check=0):
        '''Validates the info regarding external vip'''

        err_str = ""

        if self.is_ip_syntax_valid(input_str) is not None:
            err_str = "Invalid " + default_entry + " for " + input_str
            raise Invalid(err_str)

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        if podtype != "ceph":

            api_network_info = self.ymlhelper.nw_get_specific_vnic_info(
                'api', 'subnet')

            api_gateway_info = self.ymlhelper.nw_get_specific_vnic_info(
                'api', 'gateway')

            if api_network_info is None:
                err_str = "Network is not defined for API network"
                raise Invalid(err_str)

            if api_gateway_info is None:
                err_str = "Gateway is not defined for API network"
                raise Invalid(err_str)

            if re.match(input_str, api_gateway_info):
                err_str = "%s: %s matches the API network gw info" \
                    % (default_entry, input_str)
                raise Invalid(err_str)

            if skip_network_check:
                pass
            elif not self.validate_ip_for_a_given_network(
                    input_str, api_network_info):
                err_str = "%s: %s doesn't belong in %s;" \
                    % (default_entry, input_str, api_network_info)
                raise Invalid(err_str)

            # Check if external_lb_vip_entry is not same as br_api
            br_api_ip = self.get_ip_info("br_api")

            if str(br_api_ip) == str(input_str):
                err_str = "%s %s is same as br_api of management node; \
                        Please adjust the %s" \
                        % (default_entry, input_str, default_entry)

                raise Invalid(err_str)

            # Check if external_lb_vip_entry is not same as br_mgmt
            br_mgmt_ip = self.get_ip_info("br_mgmt")

            if str(br_mgmt_ip) == str(input_str):
                err_str = "%s %s is same as br_mgmt of management node; \
                        Please adjust the %s" \
                        % (default_entry, input_str, default_entry)
                raise Invalid(err_str)

        else:

            if not self.is_central_cvimmon():
                err_str = "Entry supported only for central CVIM-MON"
                raise Invalid(err_str)

            mgmt_network_info = self.ymlhelper.nw_get_specific_vnic_info(
                'management', 'subnet')

            mgmt_gateway_info = self.ymlhelper.nw_get_specific_vnic_info(
                'management', 'gateway')

            if mgmt_network_info is None:
                err_str = "Network is not defined for management network"
                raise Invalid(err_str)

            if mgmt_gateway_info is None:
                err_str = "Gateway is not defined for management network"
                raise Invalid(err_str)

            if re.match(input_str, mgmt_gateway_info):
                err_str = "%s: %s matches the management network gw info" \
                    % (default_entry, input_str)
                raise Invalid(err_str)

            if skip_network_check:
                pass
            elif not self.validate_ip_for_a_given_network(
                    input_str, mgmt_network_info):
                err_str = "%s: %s doesn't belong in %s;" \
                    % (default_entry, input_str, mgmt_network_info)
                raise Invalid(err_str)

            # Check if external_lb_vip_entry is not same as br_mgmt
            br_mgmt_ip = self.get_ip_info("br_mgmt")

            if str(br_mgmt_ip) == str(input_str):
                err_str = "%s %s is same as br_mgmt of management node; \
                        Please adjust the %s" \
                        % (default_entry, input_str, default_entry)
                raise Invalid(err_str)

        return

    def is_tenant_ip_valid(self, input_str, check_absent_from_pool=0):
        """ Check if tenant IP is valid """
        if self.is_ip_syntax_valid(input_str) is not None:
            err_str = "Invalid tenant ip for " + input_str
            raise Invalid(err_str)

        tenant_network_info = self.ymlhelper.nw_get_specific_vnic_info(
            'tenant', 'subnet')

        tenant_gateway_info = self.ymlhelper.nw_get_specific_vnic_info(
            'tenant', 'gateway')

        if tenant_network_info and not self.validate_ip_for_a_given_network(
                input_str, tenant_network_info):
            err_str = "Tenant ip: %s doesn't belong in %s" \
                      % (input_str, tenant_network_info)
            raise Invalid(err_str)

        if tenant_gateway_info is None:
            err_str = "Gateway is not defined for Tenant network"
            raise Invalid(err_str)

        tenant_pool_info = self.ymlhelper.nw_get_specific_vnic_info(
            'tenant', 'pool')

        if tenant_pool_info:
            is_ip_in_pool = self.check_ip_in_pool(input_str,
                                                  tenant_pool_info,
                                                  "tenant")
            if is_ip_in_pool and not check_absent_from_pool:
                err_msg = " Tenant ip: %s not in the tenant pool: %s" \
                    % (input_str, tenant_pool_info)
                raise Invalid(err_msg)

            elif not is_ip_in_pool and check_absent_from_pool:
                err_msg = "ip %s is in the tenant pool: %s" \
                    % (input_str, tenant_pool_info)
                raise Invalid(err_msg)

        self.global_tenant_ip_list.append(input_str)
        return

    def check_ncsip_validity(self, input_str):
        '''Checks if IP is in mgmt network but not in pool'''

        self.is_mgmt_ip_valid(input_str, "NCS_IP")

        manage_vtc_nodes = self.ymlhelper.get_server_list(role='vts')

        if manage_vtc_nodes:
            return
        else:
            if self.is_vmtp_vts_present():
                self.is_ip_reachable(input_str)

    def is_mgmt_ipv6_valid(self, input_str, default_entry="MgmtIP"):
        '''Check if Management IP is valid'''

        # Get the management network type
        curr_mgmt_network = self.ymlhelper.get_management_network_type()

        err_str = ""
        if self.is_ipv6_syntax_valid(input_str) is not None:
            err_str = "Invalid " + default_entry + " for " + input_str
            raise Invalid(err_str)

        mgmt_network_info = self.ymlhelper.nw_get_specific_vnic_info(
            'management', 'ipv6_subnet')

        mgmt_gateway_info = self.ymlhelper.nw_get_specific_vnic_info(
            'management', 'ipv6_gateway')

        mgmt_pool_info = self.ymlhelper.nw_get_specific_vnic_info(
            'management', 'ipv6_pool')

        if mgmt_network_info is None:
            err_str = "v6 Network is not defined for Mgmt network"
            raise Invalid(err_str)

        if mgmt_gateway_info is None:
            err_str = "v6 Gateway is not defined for Mgmt network"
            raise Invalid(err_str)

        if mgmt_pool_info is None:
            err_str = "v6 pool is not defined for Mgmt network"
            raise Invalid(err_str)

        if str(input_str) == str(mgmt_gateway_info):
            err_str = "%s: %s matches the Mgmt network gateway info" \
                      % (default_entry, input_str)
            raise Invalid(err_str)

        if mgmt_network_info is not None and \
                not self.validate_ipv6_for_a_given_network(\
                    input_str, str(mgmt_network_info)):
            err_str = "%s: %s doesn't belong in %s;" \
                      % (default_entry, input_str, mgmt_network_info)
            raise Invalid(err_str)

        if curr_mgmt_network == 'layer3':
            rmt_mgmt_info = ['NETWORKING', 'remote_management']
            rmt_mgmt_flag = \
                self.ymlhelper.get_deepdata_from_userinput_file(rmt_mgmt_info)
            if rmt_mgmt_flag is None:
                err_msg = "NETWORKING/remote_management section not " \
                    "defined for Layer3 Management Node deployment"
                raise Invalid(err_msg)

        # Check that br_mgmt is in the same network as management network
        br_mgmt_ipv6 = self.get_ip_info("br_mgmt", type='v6')
        if mgmt_network_info is not None and \
                not self.validate_ipv6_for_a_given_network( \
                br_mgmt_ipv6, str(mgmt_network_info)) \
                and curr_mgmt_network == 'layer2':
            err_str = "br_mgmt_v6: %s doesn't belong in %s;" \
                % (br_mgmt_ipv6, mgmt_network_info)
            raise Invalid(err_str)

        mgmt_pool_info = self.ymlhelper.nw_get_specific_vnic_info(
            'management', 'ipv6_pool')

        if mgmt_pool_info is not None:
            is_ip_in_mgmt_pool = self.check_ip_in_pool(input_str,
                                                       mgmt_pool_info,
                                                       "management",
                                                       iptype='v6')

            if re.search(r'MgmtIP', default_entry):
                if is_ip_in_mgmt_pool:
                    err_msg = default_entry + ": " + input_str + \
                        " not in management pool ;"
                    raise Invalid(err_msg)
            else:
                if not is_ip_in_mgmt_pool:
                    err_msg = default_entry + ": " + input_str + \
                        " cannot be in server management pool ;"
                    raise Invalid(err_msg)

        self.global_mgmt_ipv6_list.append(input_str)
        return err_str

    def check_vxlan_sr_mpls_entry(self, input_str):
        '''Checks the validity of vxlan sr-mpls entry for the controllers
        belongs in the sr-mpls-tenant, but outside the pool for bgp_speaker'''

        self.is_segment_ip_valid(input_str,
                                 default_entry="bgp_speaker_address_vxlan_sr_mpls",
                                 segment_info="sr-mpls-tenant")

    def check_l3_bgp_entry(self, input_str):
        '''Checks the validity of l3_bgp_entry '''

        self.is_mgmt_ip_valid(input_str, default_entry="l3_bgp_entry")

    def check_vxlan_ecn_entry(self, input_str):
        '''Checks the validity of vxlan ecn entry for the controllers'''

        self.is_segment_ip_valid(input_str,
                                 default_entry="bgp_speaker_address_vxlan_ecn",
                                 segment_info="vxlan-ecn")

    def check_sr_mpls_tenant_vtep_entry(self, input_str):
        '''Checks the validity of vxlan ecn her entry for the compute nodes'''

        self.is_segment_ip_valid(input_str,
                                 default_entry="vtep_ip_sr_mpls_tenant",
                                 segment_info="sr-mpls-tenant", exist_in_pool=1)

    def check_vxlan_ecn_her_entry(self, input_str):
        '''Checks the validity of vxlan ecn her entry for the compute nodes'''

        self.is_segment_ip_valid(input_str,
                                 default_entry="vtep_ip_vxlan_ecn_her",
                                 segment_info="vxlan-ecn", exist_in_pool=1)

    def check_vxlan_tenant_her_entry(self, input_str):
        '''Checks the validity of vxlan tenant her entry for the compute nodes'''

        self.is_segment_ip_valid(input_str,
                                 default_entry="vtep_ip_vxlan_tenant_her",
                                 segment_info="vxlan-tenant", exist_in_pool=1)

    def is_segment_ip_valid(self, input_str,
                            default_entry="bgp_speaker_address_vxlan_tenant",
                            segment_info="vxlan-tenant", exist_in_pool=0):
        '''Checks if vxlan_bgp_speaker_ip is valid'''

        err_str = ""
        if self.is_ip_syntax_valid(input_str) is not None:
            err_str = "Invalid %s for %s" % (default_entry, input_str)
            raise Invalid(err_str)

        network_info = self.ymlhelper.nw_get_specific_vnic_info(
            segment_info, 'subnet')

        gateway_info = self.ymlhelper.nw_get_specific_vnic_info(
            segment_info, 'gateway')

        if network_info is None:
            err_str = "Network is not defined for %s network" \
                % (segment_info)
            raise Invalid(err_str)

        if gateway_info is None:
            err_str = "Gateway is not defined for %s network" \
                % (segment_info)
            raise Invalid(err_str)

        if str(input_str) == str(gateway_info):
            err_str = "%s: %s matches the %s network gateway info" \
                      % (default_entry, input_str, segment_info)
            raise Invalid(err_str)

        if network_info is not None and \
                not self.validate_ip_for_a_given_network( \
                    input_str, network_info):
            err_str = "%s: %s doesn't belong in %s for segment:%s" \
                      % (default_entry, input_str, network_info, segment_info)
            raise Invalid(err_str)

        pool_info = self.ymlhelper.nw_get_specific_vnic_info(
            segment_info, 'pool')

        if pool_info is not None:
            is_ip_in_pool = self.check_ip_in_pool(input_str,
                                                  pool_info,
                                                  segment_info)

            if re.search(r'MgmtIP', default_entry):
                if is_ip_in_pool:
                    err_msg = default_entry + ": " + input_str + \
                        " not in management pool ;"
                    raise Invalid(err_msg)
            else:
                if exist_in_pool:
                    if is_ip_in_pool:
                        err_msg = "%s: %s not in %s pool;" \
                            % (default_entry, input_str, segment_info)
                        raise Invalid(err_msg)
                else:
                    if not is_ip_in_pool:
                        err_msg = "%s: %s cannot be in server %s pool;" \
                            % (default_entry, input_str, segment_info)
                        raise Invalid(err_msg)

        if segment_info == 'vxlan-tenant':
            if default_entry == 'vtep_ip_vxlan_tenant_her':
                self.global_vxlan_tenant_vtep_ip_list.append(input_str)
            else:
                self.global_vxlan_tenant_ip_list.append(input_str)

        if segment_info == 'vxlan-ecn':
            if default_entry == 'vtep_ip_vxlan_ecn_her':
                self.global_vxlan_ecn_vtep_ip_list.append(input_str)
            else:
                self.global_vxlan_ecn_ip_list.append(input_str)

        if segment_info == 'sr-mpls-tenant':
            self.global_sr_mpls_tenant_ip_list.append(input_str)

        return err_str

    def is_storage_ip_valid(self, input_str):
        '''Check if storage IP is valid'''

        self.is_network_ip_valid(input_str,
                                 default_entry="StorageIP",
                                 network='storage')
        return

    def is_cluster_ip_valid(self, input_str):
        ''' Check if cluster IP is valid '''

        self.is_network_ip_valid(input_str,
                                 default_entry="ClusterIP",
                                 network='cluster')
        return

    def is_network_ip_valid(self, input_str,
                            default_entry="MgmtIP",
                            network='management'):
        '''Check if Management IP is valid'''

        # Get the management network type
        curr_mgmt_network = self.ymlhelper.get_management_network_type()

        err_str = ""
        if self.is_ip_syntax_valid(input_str) is not None:
            err_str = "Invalid " + default_entry + " for " + input_str
            raise Invalid(err_str)

        network_info = self.ymlhelper.nw_get_specific_vnic_info(\
            network, 'subnet')

        gateway_info = self.ymlhelper.nw_get_specific_vnic_info(\
            network, 'gateway')

        if network_info is None:
            err_str = "Network is not defined for %s network" % (network)
            raise Invalid(err_str)

        if gateway_info is None:
            err_str = "Gateway is not defined for %s network" % (network)
            raise Invalid(err_str)

        if str(input_str) == str(gateway_info):
            err_str = "%s: %s matches the %s network gateway info" \
                      % (default_entry, input_str, network)
            raise Invalid(err_str)

        if network_info is not None and \
                not self.validate_ip_for_a_given_network(\
                    input_str, network_info):
            err_str = "%s: %s doesn't belong in %s;" \
                      % (default_entry, input_str, network_info)
            raise Invalid(err_str)

        if curr_mgmt_network == 'layer3':
            rmt_mgmt_info = ['NETWORKING', 'remote_management']
            rmt_mgmt_flag = \
                self.ymlhelper.get_deepdata_from_userinput_file(rmt_mgmt_info)
            if rmt_mgmt_flag is None:
                err_msg = "NETWORKING/remote_management section not " \
                          "defined for Layer3 Management Node deployment"
                raise Invalid(err_msg)

        # Check that br_mgmt is in the same network as management network
        if re.search(r'StorageIP|ClusterIP', default_entry):
            pass
        else:
            br_mgmt_ipv4 = self.get_ip_info("br_mgmt")
            if network_info is not None and \
                    not self.validate_ip_for_a_given_network( \
                    br_mgmt_ipv4, str(network_info)) and \
                    curr_mgmt_network == 'layer2':
                err_str = "br_mgmt_v4: %s doesn't belong in %s;" \
                    % (br_mgmt_ipv4, network_info)
                raise Invalid(err_str)

        pool_info = self.ymlhelper.nw_get_specific_vnic_info(
            network, 'pool')

        if pool_info is not None:
            is_ip_in_pool = self.check_ip_in_pool(input_str,
                                                  pool_info,
                                                  network)

            if re.search(r'MgmtIP', default_entry):
                if is_ip_in_pool:
                    err_msg = default_entry + ": " + input_str + \
                        " not in " + network + " pool ;"
                    raise Invalid(err_msg)
            elif re.search(r'StorageIP|ClusterIP', default_entry):
                if is_ip_in_pool:
                    err_msg = default_entry + ": " + input_str + \
                        " not in " + network + " pool ;"
                    raise Invalid(err_msg)

            else:
                if not is_ip_in_pool:
                    err_msg = default_entry + ": " + input_str + \
                        " cannot be in server " + network + " pool ;"
                    raise Invalid(err_msg)

        if default_entry == 'StorageIP':
            self.global_storage_ip_list.append(input_str)
        elif default_entry == 'ClusterIP':
            self.global_cluster_ip_list.append(input_str)
        else:
            self.global_mgmt_ip_list.append(input_str)

        return err_str

    def is_mgmt_ip_valid(self, input_str, default_entry="MgmtIP"):
        '''Check if Management IP is valid'''

        self.is_network_ip_valid(input_str, default_entry=default_entry)
        return

    def does_dup_mgmt_ip_exist(self, target_ip, iptype='v4'):
        '''checks given an ip if it exists more than once'''

        mgmt_ip_list = []
        repeating_mgmt_ip_info = []

        role_profiles = self.ymlhelper.rp_get_all_roles()

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        if podtype is not None and podtype == 'ceph':
            control_server_list = self.ymlhelper.get_server_list(role='cephcontrol')
            compute_server_list = self.ymlhelper.get_server_list(role='cephosd')

        else:
            control_server_list = self.ymlhelper.get_server_list(role='control')
            compute_server_list = self.ymlhelper.get_server_list(role='compute')

        if role_profiles is None:
            return 0

        for role in role_profiles:
            svr_list = self.ymlhelper.get_server_list(role=role)

            for server in svr_list:
                # Skip the relook of management ip for the cntrol servers
                # present in compute/storage in micropod
                if podtype is not None and re.match(r'micro', podtype):
                    if re.match(r'compute|block_storage', role):
                        if server in control_server_list:
                            continue
                elif podtype is not None and re.match(r'edge|nano', podtype):
                    if re.match(r'compute', role):
                        if server in control_server_list:
                            continue
                elif podtype is not None and podtype == 'ceph':
                    if re.match(r'cephosd', role):
                        if server in control_server_list:
                            continue

                # Skip the relook of management ip for the storage servers
                # present in compute in UMHC
                elif podtype is not None and re.match(r'UMHC|NGENAHC', podtype):
                    if re.match(r'block_storage', role):
                        if server in compute_server_list:
                            continue

                if iptype == 'v4':
                    server_mgmt_ip = self.ymlhelper.get_server_static_mgmt_ip(server)
                else:
                    server_mgmt_ip = \
                        self.ymlhelper.get_server_static_mgmt_ipv6(server)

                if server_mgmt_ip is None:
                    continue
                elif server_mgmt_ip is not None:
                    mgmt_ip_list.append(server_mgmt_ip)

        if len(mgmt_ip_list) > 1:
            repeating_mgmt_ip_info = \
                self.check_for_dups_in_list(mgmt_ip_list)

        if repeating_mgmt_ip_info:
            if target_ip in repeating_mgmt_ip_info:
                return 1

        return 0

    def check_ip_in_pool(self, curr_ip, ip_pool_list,
                         segment="management", iptype='v4'):
        '''check if ip is in pool'''

        correct_format = "ip_poolA to ip_poolB"
        err_msg = "Incorrect IP pool: %s entered for %s; %s " \
            % (ip_pool_list, segment, correct_format)

        ip_pool_enteries = []

        for item in ip_pool_list:
            try:
                pool_range_list = item.split("to")
            except ValueError:
                return err_msg

            if not pool_range_list or len(pool_range_list) > 2:
                return err_msg

            elif len(pool_range_list) == 2:
                start_ip = pool_range_list[0].strip()
                end_ip = pool_range_list[1].strip()
                if iptype == 'v6':
                    ip_start_valid = self.is_ipv6_syntax_valid(start_ip)
                    ip_end_valid = self.is_ipv6_syntax_valid(end_ip)

                else:
                    ip_start_valid = self.is_ip_syntax_valid(start_ip)
                    ip_end_valid = self.is_ip_syntax_valid(end_ip)

                if ip_start_valid is None and ip_end_valid is None:
                    num_ip = list(netaddr.iter_iprange(start_ip, end_ip))

                    for info in num_ip:
                        # handle shortened IPv6 enteries
                        if iptype == 'v6':
                            ex_v6 = netaddr.IPAddress(info)
                            ex_v6_ip = ex_v6.format(dialect=netaddr.ipv6_verbose)
                            ip_pool_enteries.append(str(ex_v6_ip))

                        else:
                            ip_pool_enteries.append(str(info))

                else:
                    return err_msg

            elif len(pool_range_list) == 1:
                pool_ip = pool_range_list[0]
                if iptype == 'v6':
                    ex_v6 = netaddr.IPAddress(str(pool_ip))
                    ex_v6_ip = ex_v6.format(dialect=netaddr.ipv6_verbose)
                    ip_pool_enteries.append(str(ex_v6_ip))
                else:
                    ip_pool_enteries.append(str(pool_ip))

        exp_cur_ip = curr_ip
        # handle shortened IPv6 enteries
        if iptype == 'v6':
            temp_curr_ip = netaddr.IPAddress(curr_ip)
            exp_cur_ip = temp_curr_ip.format(dialect=netaddr.ipv6_verbose)

        if ip_pool_enteries:
            if exp_cur_ip not in ip_pool_enteries:
                err_msg = " IP %s not in %s pool;" % (curr_ip, segment)
                return err_msg

        return ""

    def check_tor_info_fi(self, input_str):
        '''Checks the TOR FI info for UCSMCOMMN'''

        self.check_tor_info_for_server(input_str)
        err_list = []

        dup_eth_port_list = \
            self.get_duplicate_entry_in_list(self.server_eth_port_list)
        dup_pc_list = \
            self.get_duplicate_entry_in_list(self.server_port_channel_list)

        if dup_eth_port_list:
            err_str = "Duplicate eth port info across TOR and FI: " + \
                      ' '.join(dup_eth_port_list)
            err_list.append(err_str)

        if dup_pc_list:
            err_str = "Duplicate Port Channel info across TOR and FI: " + \
                      ' '.join(dup_pc_list)
            err_list.append(err_str)

        if err_list:
            err_msg = ','.join(err_list)
            raise Invalid(err_msg)

        return

    def get_tor_details_from_uscm_common(self):
        '''Update the global list with TOR details from UCSM common'''

        ucsm_common = self.ymlhelper.get_data_from_userinput_file(['UCSMCOMMON'])

        if 'tor_info_fi' in ucsm_common.keys():
            self.check_tor_info_for_server(ucsm_common['tor_info_fi'])

        if 'tor_info_fi_redundant' in ucsm_common.keys():
            self.check_tor_info_for_server(ucsm_common['tor_info_fi_redundant'])

        dup_eth_port_list = \
            self.get_duplicate_entry_in_list(self.server_eth_port_list)
        dup_pc_list = \
            self.get_duplicate_entry_in_list(self.server_port_channel_list)

        err_list = []
        if dup_eth_port_list:
            err_str = "Duplicate eth port info across TOR and FI: " + \
                ' '.join(dup_eth_port_list)
            err_list.append(err_str)

        if dup_pc_list:
            err_str = "Duplicate Port Channel info across TOR and FI: " + \
                ' '.join(dup_pc_list)
            err_list.append(err_str)

        if err_list:
            err_msg = ','.join(err_list)
            raise Invalid(err_msg)

        return

    def check_aci_tor_info_for_server(self, input_str):
        '''Checks if ACI tor info is good'''

        self.check_tor_info_for_server(input_str,
                                       skip_port_channel=1,
                                       skip_type="ACI")

    def check_sriov_tor_info_for_server(self, input_str):
        '''Checks if sriov tor info is good for intel NIC'''

        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])

        vic_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_INTEL_SRIOV'])

        if intel_nic_check or vic_nic_check:
            pass
        else:
            err_msg = "sriov_tor_info only allowed with Intel NIC support"
            raise Invalid(err_msg)

        self.check_tor_info_for_server(input_str,
                                       skip_port_channel=1,
                                       skip_type="SRIOV")

    def check_dp_tor_info_for_server(self, input_str):
        '''Checks if dp tor info is good for intel NIC'''

        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])

        if not intel_nic_check:
            err_msg = "dp_tor_info only allowed with Intel NIC support"
            raise Invalid(err_msg)

        self.check_tor_info_for_server(input_str)

    def get_tor_switch_peer_info(self):
        '''Get the TOR Switch Peer Info'''

        peer_switch = {}
        swt_peer_ip = {}
        swt_ssh_ip = {}

        swt_peer_name = {}
        swt_name = {}
        switch_list = []

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        auto_tor_via_aci = self.cd_cfgmgr.extend_auto_tor_to_aci_fabric()

        try:
            torswitchinfo = \
                self.ymlhelper.get_data_from_userinput_file(['TORSWITCHINFO'])

            switchdetails = torswitchinfo.get('SWITCHDETAILS')
            for item in switchdetails:
                curr_hostname = item.get('hostname')
                if curr_hostname is not None:
                    switch_list.append(curr_hostname)
                    if mechanism_driver == 'aci' or auto_tor_via_aci:
                        swt_peer_name[curr_hostname] = item.get('vpc_peer_keepalive')
                        swt_name[curr_hostname] = item.get('hostname')
                    else:
                        swt_peer_ip[curr_hostname] = item.get('vpc_peer_keepalive')
                        swt_ssh_ip[curr_hostname] = item.get('ssh_ip')

            # Get the peer switch info
            for swt in switch_list:
                for item in switchdetails:
                    if swt == item.get('hostname'):
                        for swt2 in switch_list:
                            if mechanism_driver == 'aci' or auto_tor_via_aci:
                                if swt_peer_name[swt] is not None and \
                                        swt_peer_name[swt] == swt_name[swt2]:
                                    peer_switch[swt] = swt2

                            else:
                                if swt_peer_ip[swt] is not None and \
                                        swt_peer_ip[swt] == swt_ssh_ip[swt2]:
                                    peer_switch[swt] = swt2

        except AttributeError:
            return peer_switch

        return peer_switch

    def check_tor_info_for_server(self, input_str, skip_port_channel=0,
                                  skip_type="SRIOV"):
        '''
            Checks the tor info for each server and match against
            common info for each tor
        '''

        found_po = 0
        tor_count = 0
        eth_port_check = 0
        po_syntax_info = []
        po_input_info = []
        dup_pc_info = []
        dup_port_info = []
        invalid_switch_info = []
        invalid_switch_port_info = []
        invalid_peer_switch_info = []
        curr_switch_info = []
        port_channel_dict = {}
        port_info_dict = {}
        invalid_port_syntax = []
        invalid_splitter_mapping_list = []
        overlapping_rsm_splitter_list = []
        invalid_interface_pattern_list = []

        intel_sriov_phys_ports = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_SRIOV_PHYS_PORTS'])

        vic_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_INTEL_SRIOV'])

        # Gets TOR switch(es) detail
        torswitch_list = self.get_tor_switch_info('tor')

        if not torswitch_list:
            err_msg = "TOR Switch info missing to cross check"
            raise Invalid(err_msg)

        for switch in torswitch_list:
            port_channel_dict[switch] = \
                self.get_tor_switch_info_details(switch, "portchannel")
            port_info_dict[switch] = \
                self.get_tor_switch_info_details(switch, "portlist")

        num_keys = len(input_str.keys())
        # Check for Duplication between tor and input
        num_sriov_ports = 0

        for k, v in input_str.iteritems():

            delimit_found = 0
            if skip_port_channel:
                found_po = 1

            if (k == 'po') and skip_port_channel:
                err_str = "Port channel config not allowed for %s" % (skip_type)
                raise Invalid(err_str)

            elif k == 'po':

                found_po = 1
                if not self.is_input_an_integer(v):
                    po_syntax_info.append(v)
                elif int(v) == 0:
                    po_input_info.append(v)

            elif k not in torswitch_list:
                invalid_switch_info.append(k)

            elif k in torswitch_list:
                tor_count += 1
                ncs5500_check = self.is_tor_type_ncs5500()
                if ncs5500_check:
                    splitter_option = self.get_splitter_option(k, '4x10')
                else:
                    splitter_option = "NotDefined"

                curr_switch_info.append(k)

                if not skip_port_channel:
                    # Check if the server port channel info
                    # matches with that in switch
                    if input_str['po'] in port_channel_dict[k]:
                        dup_pc_info.append(str(input_str['po']))
                    else:
                        # dump the port channel/switch info in a list
                        # to ensure that we dont have duplicates
                        tmp = k + ":" + str(input_str['po'])
                        self.server_port_channel_list.append(tmp)

                # Look for dups in eth port list for each switch
                v_items = v.split(",")

                if skip_type == 'SRIOV' and skip_port_channel and \
                        intel_sriov_phys_ports is not None and \
                        intel_sriov_phys_ports == 4:
                    if num_keys == 1 and len(v_items) == 4:
                        delimit_found = 1
                    elif num_keys == 2 and (len(v_items) == 2 or \
                            len(v_items) == 3 or len(v_items) == 1):
                        delimit_found = 1
                    elif num_keys == 4 and len(v_items) == 1:
                        delimit_found = 1
                    elif num_keys == 3 and \
                            (len(v_items) == 2 or len(v_items) == 1):
                        delimit_found = 1

                    if not delimit_found:
                        tmp = k + ":" + str(v)
                        invalid_switch_port_info.append(tmp)
                    else:
                        num_sriov_ports += len(v_items)

                else:

                    if vic_nic_check and skip_port_channel and \
                            num_keys == 2 and len(v_items) == 2 and \
                            skip_type == 'SRIOV':
                        delimit_found = 1

                    elif skip_port_channel and num_keys == 2 and \
                            len(v_items) == 1:
                        delimit_found = 1

                    elif skip_port_channel and num_keys == 1 and \
                            len(v_items) == 2:
                        delimit_found = 1

                    elif not skip_port_channel and len(v_items) == 2:
                        delimit_found = 1

                    if num_keys == 1 and not delimit_found:
                        tmp = k + ":" + str(v)
                        invalid_switch_port_info.append(tmp)

                    elif num_keys == 2 and not delimit_found:
                        tmp = k + ":" + str(v)
                        invalid_switch_port_info.append(tmp)
                    elif num_keys == 3 and delimit_found:
                        tmp = k + ":" + str(v)
                        invalid_switch_port_info.append(tmp)

                    if skip_port_channel:
                        num_sriov_ports += len(v_items)

                for item in v_items:
                    ncs5500_check = self.is_tor_type_ncs5500()
                    eth_port_err_check = \
                        self.check_eth_port_syntax(item, ncs5500_check, skip_type)
                    if eth_port_err_check:
                        invalid_port_syntax.append(eth_port_err_check)

                    # check for splitter mapping
                    if ncs5500_check and splitter_option != "NotDefined":
                        if re.search(r'[0-9]/[0-9]/[0-9]/[0-9]+/[0-3]', item):
                            splitter_mapping_str = \
                                self.is_splitter_option_mapped(k,
                                                               item,
                                                               splitter_option)
                            if splitter_mapping_str:
                                invalid_splitter_mapping_list.append(\
                                    splitter_mapping_str)
                        elif re.search(r'[0-9]/[0-9]/[0-9]/[0-9]/[4-96]', item):
                            tmp = k + ":" + item
                            invalid_interface_pattern_list.append(tmp)
                        else:

                            # if its not splitter check for overlap with Splitter
                            overlapping_rsm_splitter_str = \
                                self.is_splitter_option_mapped(k,
                                                               item,
                                                               splitter_option,
                                                               1)
                            if overlapping_rsm_splitter_str:
                                overlapping_rsm_splitter_list.append(\
                                    overlapping_rsm_splitter_str)

                    # Chandra to add code here
                    tmp = k + ":" + item
                    if item in port_info_dict[k]:
                        dup_port_info.append(tmp)
                    else:
                        self.server_eth_port_list.append(tmp)

        if len(curr_switch_info) == 2:
            peer_switch_info = self.get_tor_switch_peer_info()

            for item in curr_switch_info:
                curr_peer_switch = peer_switch_info.get(item)

                if curr_peer_switch is not None and \
                        curr_peer_switch not in curr_switch_info:
                    tmp = ':'.join(curr_switch_info)
                    invalid_peer_switch_info.append(tmp)

        if skip_port_channel:
            if skip_type == 'SRIOV' and vic_nic_check:
                expected_sriov_port = 4
            elif skip_type == 'NFVBENCH' or intel_sriov_phys_ports is None:
                expected_sriov_port = 2
            elif skip_type == 'ACI':
                expected_sriov_port = 2
            else:
                expected_sriov_port = intel_sriov_phys_ports

            if num_sriov_ports != expected_sriov_port:
                err_msg = " Num of valid switch ports for %s is %s, " \
                    "expected:%s" \
                    % (input_str, num_sriov_ports, expected_sriov_port)
                raise Invalid(err_msg)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        if invalid_port_syntax:
            self.tor_error_found = 1
            if eth_port_check:
                if mechanism_driver == 'vts':
                    err_msg = "Incorrect Switch syntax %s found at server, " \
                        "expected syntax Ethernet[1-3]/[1-96]" \
                        % (','.join(invalid_port_syntax))
                else:
                    err_msg = "Incorrect Switch syntax %s found at server, " \
                        "expected syntax eth[1-3]/[1-96]" \
                        % (','.join(invalid_port_syntax))
            elif self.is_tor_type_ncs5500():
                err_msg = "Incorrect Switch syntax %s found at server, " \
                    "expected syntax GigEa/b/c/d[/e] or FortyGigEa/b/c/d[/e] " \
                    "or TenGigEa/b/c/d[/e] or HundredGigEa/b/c/d[/e] or " \
                    "Tea/b/c/d[/e] or Hua/b/c/d[/e] or Gia/b/c/d[/e] " \
                    "with value of e between 0-3 for splitter cable " \
                    % (','.join(invalid_port_syntax))
            else:
                if mechanism_driver == 'vts':
                    err_msg = "Incorrect Switch syntax %s found at server, " \
                        "expected syntax Ethernet[1-3]/[1-96]" \
                        % (','.join(invalid_port_syntax))
                else:
                    err_msg = "Incorrect Switch syntax %s found at server, " \
                        "expected syntax eth[1-3]/[1-96]" \
                        % (','.join(invalid_port_syntax))
            raise Invalid(err_msg)

        if invalid_interface_pattern_list:
            err_msg = "Incorrect Interface syntax %s found at server, " \
                "expected syntax GigEa/b/c/d/e or FortyGigEa/b/c/d/e or " \
                "TenGigEa/b/c/d/e or HundredGigEa/b/c/d/e or Tea/b/c/d/e or " \
                "Hua/b/c/d/e or Gia/b/c/d/e; with value of e between 0-3 for " \
                "splitter cable " \
                % (','.join(invalid_interface_pattern_list))
            raise Invalid(err_msg)

        if invalid_splitter_mapping_list:
            err_msg = "Splitter Interface index not mapped to " \
                "target controller interface %s" \
                % (','.join(invalid_splitter_mapping_list))
            raise Invalid(err_msg)

        if overlapping_rsm_splitter_list:
            err_msg = "Matching Interface RSM index with " \
                "Splitter Controller index %s" \
                % (','.join(overlapping_rsm_splitter_list))
            raise Invalid(err_msg)

        if invalid_switch_info:
            self.tor_error_found = 1
            err_msg = "Incorrect Switch info " + ' '.join(invalid_switch_info) + \
                      " found at server "
            raise Invalid(err_msg)

        if not found_po:
            self.tor_error_found = 1
            err_msg = "Port Channel Info missing "
            raise Invalid(err_msg)

        if not tor_count:
            self.tor_error_found = 1
            err_msg = "ToR Info missing "
            raise Invalid(err_msg)

        if po_syntax_info:
            self.tor_error_found = 1
            err_msg = "Port Channel Info is not an integer " + \
                ' '.join(po_syntax_info)
            raise Invalid(err_msg)

        if po_input_info:
            self.tor_error_found = 1
            err_msg = "Port Channel Info is not > 0 " + \
                ' '.join(po_syntax_info)
            raise Invalid(err_msg)

        if dup_pc_info:
            self.tor_error_found = 1
            err_msg = "Conflicting Port Channel/VPC domain id Info "\
                + ' '.join(dup_pc_info) + ". Please note: CVIM expects " \
                "VPC domain id to be not conflicting with port-channel " \
                "definition"
            raise Invalid(err_msg)

        if dup_port_info:
            self.tor_error_found = 1
            err_msg = "Eth Port Info " + ' '.join(dup_port_info) + \
                      " is conflicting with that defined at switch level "
            raise Invalid(err_msg)

        if skip_type == 'SRIOV' and skip_port_channel and \
                intel_sriov_phys_ports is not None and \
                intel_sriov_phys_ports == 4 and \
                invalid_switch_port_info:

            if num_keys == 1:
                self.tor_error_found = 1
                err_msg = "Only 4 eth switch port allowed @ " + \
                          ' '.join(invalid_switch_port_info) + \
                          " for server "
                raise Invalid(err_msg)
            elif num_keys == 2:
                self.tor_error_found = 1
                err_msg = "Only 1, 2, 3 eth switch port allowed @ " + \
                          ' '.join(invalid_switch_port_info) + \
                          " for server "
                raise Invalid(err_msg)
            elif num_keys == 4:
                self.tor_error_found = 1
                err_msg = "Only 1 eth switch port allowed @ " + \
                          ' '.join(invalid_switch_port_info) + \
                          " for server "
                raise Invalid(err_msg)
            elif num_keys == 3:
                self.tor_error_found = 1
                err_msg = "Only 2 or 1 eth switch port allowed @ " + \
                          ' '.join(invalid_switch_port_info) + \
                          " for server "
                raise Invalid(err_msg)

        else:
            if skip_port_channel and num_keys == 1 and \
                    invalid_switch_port_info:
                self.tor_error_found = 1
                err_msg = "Only 2 eth switch port allowed @ " + \
                          ' '.join(invalid_switch_port_info) + \
                          " for server "
                raise Invalid(err_msg)

            elif skip_port_channel and num_keys == 2 and \
                    invalid_switch_port_info:
                self.tor_error_found = 1
                err_msg = "Only 1 eth switch port allowed @ " + \
                          ' '.join(invalid_switch_port_info) + \
                          " for server "
                raise Invalid(err_msg)

            elif num_keys == 2 and invalid_switch_port_info:
                self.tor_error_found = 1
                err_msg = "Switch " + ' '.join(invalid_switch_port_info) + \
                    " has no eth port for bonding "
                raise Invalid(err_msg)

            elif num_keys == 3 and invalid_switch_port_info:
                self.tor_error_found = 1
                err_msg = "Extra eth switch port @ " + \
                          ' '.join(invalid_switch_port_info) + \
                          " for server "
                raise Invalid(err_msg)

        if invalid_peer_switch_info:
            self.tor_error_found = 1
            err_msg = "Invalid Peer Switch Combo: " + \
                      ','.join(invalid_peer_switch_info) + \
                      " found at server "
            raise Invalid(err_msg)

        return

    def check_vic_slot_info(self, input_str):
        '''Checks Vic slot value is 1 to 7, or MLOM'''

        self.is_input_in_plain_str(input_str)

        if isinstance(input_str, int):
            err_str = "Integer Input not allowed"
            raise Invalid(err_str)
        elif isinstance(input_str, float):
            err_str = "Float Input not allowed"
            raise Invalid(err_str)
        elif isinstance(input_str, bool):
            err_str = "Bool Input not allowed"
            raise Invalid(err_str)

        err_str = "Expected Input:1-7 or MLOM; " \
            "Current Input: " + str(input_str)
        pattern = re.compile("^(MLOM|[1-7])$")
        if not pattern.match(input_str):
            raise Invalid(err_str)

        return

    def check_ceph_cluster_syntax(self, input_str):
        '''Check Ceph Cluster can only be of type HDD/SSD'''

        if not isinstance(input_str, str):
            err_str = "Non-string Input not allowed"
            raise Invalid(err_str)

        if input_str == 'SSD' or input_str == 'HDD':
            pass
        else:
            err_str = "OSD drive type can be of type SSD or HDD"
            raise Invalid(err_str)

        return

    def check_trusted_vf_mode(self, input_str):
        '''A new kernel feature allows Virtual Functions to become "trusted" by
        the Physical Function and perform some privileged operations, such as
        enabling VF promiscuous mode and changing VF MAC address within the
        guest. The inability to modify mac addresses in the guest prevents the
        users from being able to easily setup up two VFs in a fail-over bond
        in a guest. This spec aims to suggest a way for users to boot
        instances with trusted VFs.
        https://blueprints.launchpad.net/nova/+spec/sriov-trusted-vfs'''

        if not isinstance(input_str, bool):
            err_str = "Only Boolean value True/False allowed; " \
                "default is False"
            raise Invalid(err_str)

        intel_nic_sriov_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_SRIOV_VFS'])

        intel_sriov_phys_ports = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_SRIOV_PHYS_PORTS'])

        intel_fpga_vc_sriov_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_VC_SRIOV_VFS'])

        is_sriov_enabled = 0
        if (intel_nic_sriov_check or intel_sriov_phys_ports or
                intel_fpga_vc_sriov_check):
            is_sriov_enabled = 1

        if not is_sriov_enabled:
            err_str = "Only Supported when SRIOV is enabled"
            raise Invalid(err_str)

        return

    def check_sriov_access_vlan_syntax(self, input_str):
        '''Check if sriov_access_vlan syntax is good'''

        err_str = "A single VLAN input between 2 and 4094 belonging " \
            "to PROVIDER_VLAN_RANGES with details defined in " \
            "vim_apic_networks is allowed in string format"

        if not isinstance(input_str, str):
            raise Invalid(err_str)

        prov_vlan_info = \
            self.ymlhelper.get_data_from_userinput_file(['PROVIDER_VLAN_RANGES'])
        prov_vlan_list = common_utils.expand_vlan_range(prov_vlan_info)

        if int(input_str) not in prov_vlan_list:
            raise Invalid(err_str)

        vim_apic_networks = \
            self.ymlhelper.get_data_from_userinput_file(['vim_apic_networks'])

        vim_apic_prov_networks = vim_apic_networks.get('PROVIDER', None)

        if vim_apic_prov_networks is None:
            raise Invalid(err_str)

        if not self.is_input_range_valid(int(input_str), 2, 4094):
            raise Invalid(err_str)

        found_match = 0
        for item in vim_apic_prov_networks:
            curr_vlan_ids = item.get('vlan_ids')
            if input_str == curr_vlan_ids:
                found_match = 1
                break
            elif re.search(',|:', curr_vlan_ids):
                curr_vlan_list = common_utils.expand_vlan_range(curr_vlan_ids)
                if int(input_str) in curr_vlan_list:
                    found_match = 1
                    break

        if found_match:
            return
        else:
            raise Invalid(err_str)

    def check_sriov_access_vlan(self, input_str):
        '''Check schema of SRIOV_ACCESS_VLAN'''

        err_list = []
        sriov_access_schema = Schema({
            Required('sriov0'): self.check_sriov_access_vlan_syntax,
            Required('sriov1'): self.check_sriov_access_vlan_syntax,
            Required('sriov2'): self.check_sriov_access_vlan_syntax,
            Required('sriov3'): self.check_sriov_access_vlan_syntax,
        })

        try:
            sriov_access_schema(input_str)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        if err_list:
            err_str = ' '.join(err_list)
            raise Invalid(err_str)

        return

    def check_prefix_sid_syntax(self, input_str):
        '''Check the syntax of prefix sid between 1 and 8000'''

        err_str = "Only input of type integer is allowed, " \
            "in the range of 1-8000 (including 1 and 8000), " \
            "current input is %s" % (input_str)

        if not isinstance(input_str, int):
            raise Invalid(err_str)
        elif input_str >= 1 and input_str <= 8000:
            pass
        else:
            raise Invalid(err_str)

        self.global_sr_mpls_prefix_sid_list.append(input_str)

    def check_seccomp_sandbox_settings(self, input_str):
        """Check the seccomp_sandbox input"""

        err_msg = "Input of type int with values of 0 or 1 is " \
            "allowed; found to be %s" % (input_str)
        if not isinstance(input_str, int):
            raise Invalid(err_msg)

        if input_str != 0 and input_str != 1:
            raise Invalid(err_msg)

        return

    def check_rx_tx_queue_size(self, input_str):
        '''Check the syntax of rx_tx_queue_size'''

        err_msg = "Input of type int with values of 256 or 512 or 1024 is " \
            "allowed; found to be %s" % (input_str)
        if not isinstance(input_str, int):
            raise Invalid(err_msg)

        if input_str != 256 and input_str != 512 and input_str != 1024:
            raise Invalid(err_msg)

        return

    def is_pod_dual_stack(self):
        '''Check if pod is of type dual stack'''

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])
        if podtype is None:
            podtype = 'fullon'

        if podtype != 'ceph':
            ipv6_vip = self.ymlhelper.get_data_from_userinput_file(\
                ['external_lb_vip_ipv6_address'])
            if ipv6_vip is None:
                return 0
            else:
                return 1
        else:
            try:
                _ = self.get_ip_info("br_api", type='v6')
                return 1
            except Exception:  # nosec
                return 0

    def populate_sr_global_block_info(self, server_name, input_str):
        """populate the sr_global_block info for each server"""

        sr_global_block_info = input_str.get('sr_global_block', None)

        if sr_global_block_info is not None:
            prefix_sid_index = sr_global_block_info.get('prefix_sid_index', 0)
            base = sr_global_block_info.get('base', 0)
            curr_sid_base = int(prefix_sid_index) + int(base)
            self.global_sr_mpls_block_info[server_name] = curr_sid_base

    def check_vgpu_type(self, input_str):
        """Check VGPU entry"""

        file_name_list = \
            common_utils.find_file_path(\
                common_utils.INSTALLER_DIR, "defaults.yaml")

        default_file_abs_path = ""
        for item in file_name_list:
            if os.path.basename(item) == 'defaults.yaml':
                default_file_abs_path = item
                break

        if not default_file_abs_path:
            curr_msg = "defaults.yaml file not found at %s to " \
                "get the VGPU types" % (file_name_list)
            raise Invalid(curr_msg)

        defaults_yaml = \
            common_utils.get_contents_of_file(default_file_abs_path)
        if not defaults_yaml:
            err_msg = "ERROR: Contents of %s is empty, can't proceed" \
                      % (default_file_abs_path)
            raise Invalid(err_msg)

        vgpu_types = defaults_yaml.get('NVIDIA_T4_VGPU_TYPES', None)
        if vgpu_types is None:
            err_msg = "ERROR: Contents of %s doesnt have NVIDIA_T4_VGPU_TYPES, " \
                "can't proceed" % (default_file_abs_path)
            raise Invalid(err_msg)

        vgpu_type_list = []
        import six
        for key, _ in six.iteritems(vgpu_types):
            vgpu_type_list.append(key)

        if input_str not in vgpu_type_list:
            err_msg = "input %s is not in the whitelist of %s" \
                % (input_str, ','.join(vgpu_type_list))
            raise Invalid(err_msg)

        return

    def validate_server_syntax(self, input_str):
        '''validates the standalone server schema'''

        err_list = []
        unsupported_hostname_len = []
        unique_hostname = []
        unique_hostname_prefix = []
        duplicate_hostname = []
        unsupported_fq_hostname_len = []
        repeating_mgmt_ip_info = []
        missing_mgmt_ip_info = []
        curr_storage_ip_info = []
        missing_storage_ip_info = []
        repeating_storage_ip_info = []
        curr_cluster_ip_info = []
        missing_cluster_ip_info = []
        repeating_cluster_ip_info = []
        repeating_tenant_ip_info = []
        missing_tenant_ip_info = []
        missing_server_role_mapping = []
        invalid_hostname_syntax = []
        invalid_vm_hugh_page_server = []

        repeating_mgmt_ipv6_info = []
        missing_mgmt_ipv6_info = []
        invalid_mcast_snooping_server = []
        invalid_vgpu_server = []

        server_found = {}

        bgp_speaker_addresses_schema = Schema({
            Required('vxlan-tenant'): self.is_segment_ip_valid,
        })

        bgp_vtep_her_schema = Schema({
            Required('vxlan-tenant'): self.check_vxlan_tenant_her_entry,
        })

        bgp_vtep_sr_mpls_schema = Schema({
            Required('sr-mpls-tenant'): self.check_sr_mpls_tenant_vtep_entry,
        })

        bgp_speaker_addresses_sr_mpls_schema = Schema({
            Required('sr-mpls-tenant'): self.check_vxlan_sr_mpls_entry,
        })

        bgp_l3_peer_tenant_sr_mpls_schema = Schema({
            Required('sr-mpls-tenant'): self.check_l3_bgp_entry,
        })

        bgp_speaker_addresses_ecn_schema = Schema({
            Required('vxlan-tenant'): self.is_segment_ip_valid,
            Required('vxlan-ecn'): self.check_vxlan_ecn_entry,
        })

        bgp_vtep_her_ecn_schema = Schema({
            Required('vxlan-tenant'): self.check_vxlan_tenant_her_entry,
            Required('vxlan-ecn'): self.check_vxlan_ecn_her_entry,
        })

        bgp_l3_peer_tenant_schema = Schema({
            Required('vxlan-tenant'): self.check_l3_bgp_entry,
        })

        bgp_l3_peer_tenant_ecn_schema = Schema({
            Required('vxlan-tenant'): self.check_l3_bgp_entry,
            Required('vxlan-ecn'): self.check_l3_bgp_entry,
        })

        cimc_ip_schema = Schema({
            Required('cimc_ip'): self.check_input_as_ipv4v6,
            Optional('cimc_username'): All(str, Length(min=1)),
            Optional('cimc_password'): self.check_password_syntax,
            Optional('SKU_id'): All(str, Length(min=1)),
        })

        rack_info_schema = Schema({
            Required('rack_id'): All(str, Length(min=1)),
        })

        hardware_info_schema = Schema({
            Optional('VIC_slot'): self.check_vic_slot_info,
            Optional('num_root_drive'): All(int, Range(min=ROOT_DRIVE_MIN,
                                                       max=ROOT_DRIVE_MAX)),
            Optional('root_drive_type'): In(frozenset(ROOT_DRIVE_TYPES)),
            Optional('root_drive_raid_level'): In(frozenset(
                ROOT_DRIVE_RAID_LEVELS)),
            Optional('root_drive_raid_spare'): All(int, Range(
                min=ROOT_DRIVE_RAID_SPARE_MIN, max=ROOT_DRIVE_RAID_SPARE_MAX)),
            Optional('NIC_LEVEL_REDUNDANCY'): self.check_nic_level_redundancy,
            Optional('osd_disk_type'): self.check_ceph_cluster_syntax,
            Optional('vendor'): In(frozenset(SUPPORTED_VENDORS)),
            Optional('VIC_admin_fec_mode'): In(frozenset(ADMIN_FEC_MODE)),
            Optional('VIC_port_channel_enable'): bool,
            Optional('VIC_link_training'): In(frozenset(LINK_TRAINING)),
            Optional('VIC_admin_speed'): In(frozenset(ADMIN_SPEED)),
            Optional('NUM_GPU_CARDS'): All(int, Range(min=0, max=6)),
            Optional('VGPU_TYPE'): self.check_vgpu_type,
            Optional('control_bond_mode'): In(frozenset(BOND_MODES)),
            Optional('data_bond_mode'): In(frozenset(BOND_MODES)),
        })

        hardware_info_vic_nic_schema = Schema({
            Optional('VIC_slot'): self.check_vic_slot_info,
            Optional('num_root_drive'): All(int, Range(min=ROOT_DRIVE_MIN,
                                                       max=ROOT_DRIVE_MAX)),
            Optional('root_drive_type'): In(frozenset(ROOT_DRIVE_TYPES)),
            Optional('root_drive_raid_level'): In(frozenset(
                ROOT_DRIVE_RAID_LEVELS)),
            Optional('root_drive_raid_spare'): All(int, Range(
                min=ROOT_DRIVE_RAID_SPARE_MIN, max=ROOT_DRIVE_RAID_SPARE_MAX)),
            Optional('NIC_LEVEL_REDUNDANCY'): self.check_nic_level_redundancy,
            Optional('INTEL_SRIOV_PHYS_PORTS'): self.check_sriov_phy_ports,
            Optional('SRIOV_CARD_TYPE'): self.check_sriov_card_type,
            Optional('vendor'): In(frozenset(SUPPORTED_VENDORS)),
            Optional('VIC_admin_fec_mode'): In(frozenset(ADMIN_FEC_MODE)),
            Optional('VIC_port_channel_enable'): bool,
            Optional('VIC_link_training'): In(frozenset(LINK_TRAINING)),
            Optional('VIC_admin_speed'): In(frozenset(ADMIN_SPEED)),
            Optional('NUM_GPU_CARDS'): All(int, Range(min=0, max=6)),
            Optional('VGPU_TYPE'): self.check_vgpu_type,
            Optional('control_bond_mode'): In(frozenset(BOND_MODES)),
            Optional('data_bond_mode'): In(frozenset(BOND_MODES)),
        })

        sr_global_block_schema = Schema({
            Required('base'): All(int, Range(min=16000, max=1048575)),
            Required('prefix_sid_index'): All(int, Range(min=0, max=7999)),
        })

        # only for definition no config
        standalone_server_base_schema = Schema({
            Required('cimc_info'): cimc_ip_schema,
            Required('rack_info'): rack_info_schema,
            Optional('VM_HUGEPAGE_PERCENTAGE'): self.check_vm_hughpage_percent,
            Optional('DISABLE_HYPERTHREADING'): self.check_disable_hyperthreading,
            Optional('VM_HUGEPAGE_SIZE'): self.check_vm_hughpage_size,
            Optional('rx_tx_queue_size'): self.check_rx_tx_queue_size,
            Optional('seccomp_sandbox'): self.check_seccomp_sandbox_settings,
            Optional('management_ip'): self.is_mgmt_ip_valid,
            Optional('management_ipv6'): self.is_mgmt_ipv6_valid,
            Optional('tenant_ip'): self.is_tenant_ip_valid,
            Optional('MULTICAST_SNOOPING'): bool,
            Optional('storage_ip'): self.is_storage_ip_valid,
            Optional('NOVA_CPU_ALLOCATION_RATIO'):
                All(numbers.Real, Range(min=0.958, max=16.0)),
            Optional('NOVA_RAM_ALLOCATION_RATIO'):
                All(numbers.Real, Range(min=1.0, max=4.0)),
            Optional('ENABLE_VM_EMULATOR_PIN'): self.check_enable_vm_emulator_pin,
            Optional('VM_EMULATOR_PCORES_PER_SOCKET'): All(int, Range(min=1, max=4)),
        })

        standalone_schema_cisco_vic = standalone_server_base_schema.extend({
            Optional('tor_info'): self.check_tor_info_for_server,
            Optional('hardware_info'): hardware_info_schema,
        })

        standalone_schema_cisco_vic_mvts = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_tor_info_for_server,
            Optional('hardware_info'): hardware_info_schema,
        })

        # ACI no plugin dp cp collapsed or Cisco vic
        standalone_schema_csco_vic_aci = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_aci_tor_info_for_server,
            Optional('hardware_info'): hardware_info_vic_nic_schema,
        })

        standalone_schema_csco_nic_aci = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_aci_tor_info_for_server,
            Required('dp_tor_info'): self.check_aci_tor_info_for_server,
            Optional('hardware_info'): hardware_info_schema,
        })

        standalone_schema_ceph_pod_base = Schema({
            Required('cimc_info'): cimc_ip_schema,
            Required('rack_info'): rack_info_schema,
            Optional('hardware_info'): hardware_info_schema,
            Optional('VM_HUGEPAGE_PERCENTAGE'): self.check_vm_hughpage_percent,
            Optional('DISABLE_HYPERTHREADING'): self.check_disable_hyperthreading,
            Optional('VM_HUGEPAGE_SIZE'): self.check_vm_hughpage_size,
            Optional('management_ip'): self.is_mgmt_ip_valid,
            Optional('management_ipv6'): self.is_mgmt_ipv6_valid,
            Optional('MULTICAST_SNOOPING'): bool,
            Optional('cluster_ip'): self.is_cluster_ip_valid,
            Optional('NOVA_CPU_ALLOCATION_RATIO'):
                All(numbers.Real, Range(min=0.958, max=16.0)),
            Optional('NOVA_RAM_ALLOCATION_RATIO'):
                All(numbers.Real, Range(min=1.0, max=4.0)),
        })

        standalone_schema_ceph_pod_w_tor = standalone_schema_ceph_pod_base.extend({
            Required('tor_info'): self.check_aci_tor_info_for_server,
            Required('dp_tor_info'): self.check_aci_tor_info_for_server,
        })

        standalone_schema_ceph_pod = standalone_schema_ceph_pod_base.extend({
            Optional('tor_info'): self.check_aci_tor_info_for_server,
            Optional('dp_tor_info'): self.check_aci_tor_info_for_server,
        })

        standalone_schema_csco_nic_sriov_aci = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_aci_tor_info_for_server,
            Required('dp_tor_info'): self.check_aci_tor_info_for_server,
            Required('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('hardware_info'): hardware_info_schema,
        })

        # ACI no plugin dp cp collapsed
        standalone_schema_dpcp_aci_noplugin = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_aci_tor_info_for_server,
            Optional('hardware_info'): hardware_info_schema,
        })

        # ACI no plugin dp cp collapsed for compute
        standalone_schema_dpcp_sriov_aci_noplugin = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_aci_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('sriov_access_vlan'): self.check_sriov_access_vlan,
            Optional('hardware_info'): hardware_info_schema,
        })

        standalone_schema_intel_nic = standalone_server_base_schema.extend({
            Optional('tor_info'): self.check_tor_info_for_server,
            Optional('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('hardware_info'): hardware_info_schema,
        })

        standalone_schema_intel_nic_sriov = standalone_server_base_schema.extend({
            Optional('tor_info'): self.check_tor_info_for_server,
            Optional('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('INTEL_FPGA_VFS'): self.validate_vista_creek_vfs_entry,
            Optional('INTEL_VC_SRIOV_VFS'): self.validate_vista_creek_sriov_entry,
            Optional('hardware_info'): hardware_info_schema,
        })

        # Cisco VIC Intel 520 SRIOV
        standalone_schema_intel520_nic_sriov = standalone_server_base_schema.extend({
            Optional('tor_info'): self.check_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('sriov_access_vlan'): self.check_sriov_access_vlan,
            Optional('hardware_info'): hardware_info_vic_nic_schema,
        })

        # Cisco VIC Intel 520 SRIOV with TOR
        # ACI no plugin dp cp collapsed for compute
        standalone_schema_intel520_sriov_aci_noplugin = standalone_server_base_schema.extend({
            Optional('tor_info'): self.check_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('hardware_info'): hardware_info_vic_nic_schema,
        })

        # with Cisco VIC
        standalone_wtor_schema = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_tor_info_for_server,
            Optional('hardware_info'): hardware_info_schema,
        })

        standalone_wtor_intel_schema = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('hardware_info'): hardware_info_schema,
        })

        standalone_wtor_mvxlan_her_intel_schema = standalone_server_base_schema.extend({
            Required('vtep_ips'): bgp_vtep_her_ecn_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('hardware_info'): hardware_info_schema,
        })

        standalone_wtor_her_intel_schema = standalone_server_base_schema.extend({
            Required('vtep_ips'): bgp_vtep_her_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('hardware_info'): hardware_info_schema,
        })

        # needed for Equinix VXLAN extension
        control_wncs_vxlan_intel_schema = standalone_server_base_schema.extend({
            Required('bgp_speaker_addresses'): bgp_speaker_addresses_schema,
            Optional('vtep_ips'): bgp_vtep_her_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('bgp_mgmt_addresses'): bgp_l3_peer_tenant_schema,
            Optional('hardware_info'): hardware_info_schema,
        })

        control_wncs_vxlan_her_intel_schema = standalone_server_base_schema.extend({
            Required('bgp_speaker_addresses'): bgp_speaker_addresses_schema,
            Required('vtep_ips'): bgp_vtep_her_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('bgp_mgmt_addresses'): bgp_l3_peer_tenant_schema,
        })

        control_wncs_mvxlan_intel_schema = standalone_server_base_schema.extend({
            Required('bgp_speaker_addresses'): bgp_speaker_addresses_ecn_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Required('bgp_mgmt_addresses'): bgp_l3_peer_tenant_ecn_schema,
            Optional('vtep_ips'): bgp_vtep_her_ecn_schema,
        })

        compute_mvxlan_intel_schema = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('vtep_ips'): bgp_vtep_her_ecn_schema,
            Optional('hardware_info'): hardware_info_schema,
        })

        compute_mvxlan_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('vtep_ips'): bgp_vtep_her_ecn_schema,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('hardware_info'): hardware_info_schema,
        })

        compute_vxlan_intel_schema = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('vtep_ips'): bgp_vtep_her_schema,
            Optional('hardware_info'): hardware_info_schema,
        })

        compute_vxlan_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('vtep_ips'): bgp_vtep_her_schema,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('hardware_info'): hardware_info_schema,
        })

        control_wncs_mvxlan_her_intel_schema = standalone_server_base_schema.extend({
            Required('bgp_speaker_addresses'): bgp_speaker_addresses_ecn_schema,
            Required('vtep_ips'): bgp_vtep_her_ecn_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Required('bgp_mgmt_addresses'): bgp_l3_peer_tenant_ecn_schema,
            Optional('hardware_info'): hardware_info_schema,
        })

        # needed for Equinix VXLAN extension
        control_wncs_vxlan_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('bgp_speaker_addresses'): bgp_speaker_addresses_ecn_schema,
            Optional('vtep_ips'): bgp_vtep_her_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('bgp_mgmt_addresses'): bgp_l3_peer_tenant_schema,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('hardware_info'): hardware_info_schema,
        })

        control_wncs_vxlan_her_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('bgp_speaker_addresses'): bgp_speaker_addresses_schema,
            Required('vtep_ips'): bgp_vtep_her_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('bgp_mgmt_addresses'): bgp_l3_peer_tenant_schema,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('hardware_info'): hardware_info_schema,
        })

        control_only_mvxlan_her_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('bgp_speaker_addresses'): bgp_speaker_addresses_ecn_schema,
            Required('vtep_ips'): bgp_vtep_her_ecn_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Required('bgp_mgmt_addresses'): bgp_l3_peer_tenant_ecn_schema,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('hardware_info'): hardware_info_schema,
        })

        control_wncs_mvxlan_her_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('bgp_speaker_addresses'): bgp_speaker_addresses_ecn_schema,
            Required('vtep_ips'): bgp_vtep_her_ecn_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Required('bgp_mgmt_addresses'): bgp_l3_peer_tenant_ecn_schema,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('hardware_info'): hardware_info_schema,
        })

        control_only_mvxlan_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('bgp_speaker_addresses'): bgp_speaker_addresses_ecn_schema,
            Optional('vtep_ips'): bgp_vtep_her_ecn_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Required('bgp_mgmt_addresses'): bgp_l3_peer_tenant_ecn_schema,
            Optional('hardware_info'): hardware_info_schema,
        })

        control_wncs_mvxlan_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('bgp_speaker_addresses'): bgp_speaker_addresses_ecn_schema,
            Optional('vtep_ips'): bgp_vtep_her_ecn_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Required('bgp_mgmt_addresses'): bgp_l3_peer_tenant_ecn_schema,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('hardware_info'): hardware_info_schema,
        })

        standalone_wtor_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Required('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('hardware_info'): hardware_info_schema,
        })

        standalone_wncs_intel_mvxlan_her_opt_sriov_schema = standalone_server_base_schema.extend({
            Required('vtep_ips'): bgp_vtep_her_ecn_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('hardware_info'): hardware_info_schema,
        })

        standalone_wncs_intel_her_opt_sriov_schema = standalone_server_base_schema.extend({
            Required('vtep_ips'): bgp_vtep_her_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('hardware_info'): hardware_info_schema,
        })

        standalone_wncs_intel_opt_sriov_schema = standalone_server_base_schema.extend({
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_dp_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('hardware_info'): hardware_info_schema,
        })

        # SR MPLS Schema
        compute_wncs_sr_mpls_tenant_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('vtep_ips'): bgp_vtep_sr_mpls_schema,
            Required('sr_global_block'): sr_global_block_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_aci_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('hardware_info'): hardware_info_schema,
        })

        control_only_sr_mpls_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('vtep_ips'): bgp_vtep_sr_mpls_schema,
            Required('sr_global_block'): sr_global_block_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_aci_tor_info_for_server,
            Optional('hardware_info'): hardware_info_schema,
        })

        control_wncs_sr_mpls_intel_sriov_schema = standalone_server_base_schema.extend({
            Required('vtep_ips'): bgp_vtep_sr_mpls_schema,
            Required('sr_global_block'): sr_global_block_schema,
            Required('tor_info'): self.check_tor_info_for_server,
            Required('dp_tor_info'): self.check_aci_tor_info_for_server,
            Optional('sriov_tor_info'): self.check_sriov_tor_info_for_server,
            Optional('trusted_vf'): self.check_trusted_vf_mode,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Required('bgp_speaker_addresses'): bgp_speaker_addresses_sr_mpls_schema,
            Required('bgp_mgmt_addresses'): bgp_l3_peer_tenant_sr_mpls_schema,
            Optional('hardware_info'): hardware_info_schema,
        })

        rack_id_info = Schema({
            Required('rack_id'): All(str, msg='Missing rack id'),
        })

        ucsm_storage_details = Schema({
            Required('rack-unit_id'): All(int, Range(min=1, max=96)),
            Required('server_type'): All(str, Any('rack')),
        })

        ucsm_non_storage_details = Schema({
            Required('chassis_id'): All(int, Range(min=1, max=24)),
            Required('blade_id'): All(int, Range(min=1, max=8)),
            Required('server_type'): All(str, Any('blade')),
        })

        blade_storage_schema = Schema({
            Required('rack_info'): rack_id_info,
            Required('ucsm_info'): ucsm_storage_details,
            Optional('management_ip'): self.is_mgmt_ip_valid,
            Optional('management_ipv6'): self.is_mgmt_ipv6_valid,
            Optional('tenant_ip'): self.is_tenant_ip_valid,
            Optional('VM_HUGEPAGE_PERCENTAGE'): self.check_vm_hughpage_percent,
            Optional('VM_HUGEPAGE_SIZE'): self.check_vm_hughpage_size,
            Optional('rx_tx_queue_size'): self.check_rx_tx_queue_size,
            Optional('storage_ip'): self.is_storage_ip_valid,
            Optional('NOVA_CPU_ALLOCATION_RATIO'): All(numbers.Real, Range(min=0.958, max=16.0)),
            Optional('NOVA_RAM_ALLOCATION_RATIO'): All(numbers.Real, Range(min=1.0, max=4.0)),
        })

        blade_non_storage_schema = Schema({
            Required('rack_info'): rack_id_info,
            Required('ucsm_info'): ucsm_non_storage_details,
            Optional('management_ip'): self.is_mgmt_ip_valid,
            Optional('management_ipv6'): self.is_mgmt_ipv6_valid,
            Optional('tenant_ip'): self.is_tenant_ip_valid,
            Optional('VM_HUGEPAGE_PERCENTAGE'): self.check_vm_hughpage_percent,
            Optional('VM_HUGEPAGE_SIZE'): self.check_vm_hughpage_size,
            Optional('storage_ip'): self.is_storage_ip_valid,
            Optional('rx_tx_queue_size'): self.check_rx_tx_queue_size,
            Optional('NOVA_CPU_ALLOCATION_RATIO'): All(numbers.Real, Range(min=0.958, max=16.0)),
            Optional('NOVA_RAM_ALLOCATION_RATIO'): All(numbers.Real, Range(min=1.0, max=4.0)),
        })

        auto_tor_via_aci = self.cd_cfgmgr.extend_auto_tor_to_aci_fabric()

        is_cpdp_collapsed = self.cd_cfgmgr.is_cp_dp_collapsed()

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])

        vic_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_INTEL_SRIOV'])

        intel_nic_sriov_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_SRIOV_VFS'])

        intel_sriov_phys_ports = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_SRIOV_PHYS_PORTS'])

        is_sriov_enabled = 0
        if intel_nic_sriov_check or intel_sriov_phys_ports:
            is_sriov_enabled = 1

        num_gpu_global_cards = \
            self.ymlhelper.get_data_from_userinput_file(['NUM_GPU_CARDS'])

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])
        if podtype is None:
            podtype = 'fullon'

        compute_nodes = self.ymlhelper.get_server_list(role="compute")
        if podtype is not None and podtype == 'ceph':
            osd_nodes = self.ymlhelper.get_server_list(role="cephosd")
            control_nodes = self.ymlhelper.get_server_list(role="cephcontrol")
        else:
            osd_nodes = self.ymlhelper.get_server_list(role="block_storage")
            control_nodes = self.ymlhelper.get_server_list(role="control")

        duplicate_hostname_prefix = []
        role_profiles = self.ymlhelper.rp_get_all_roles()
        if role_profiles is None:
            raise Invalid("Couldnt get ROLE info")

        # for every server validate a role exists,
        # if not dont even parse the input
        for server in input_str:
            try:
                self.ymlhelper.get_server_cimc_role(server)
            except Exception as e:
                missing_server_role_mapping.append(server)

        if missing_server_role_mapping:
            err_str = "Missing role info for servers: " + \
                ','.join(missing_server_role_mapping)
            raise Invalid(err_str)

        hostname_len_to_look_for = 32
        fq_hostname_len_to_look_for = 64
        if re.match(r'UCSM', self.testbed_type):
            hostname_len_to_look_for = 16
            fq_hostname_len_to_look_for = 16

        compute_server_list = self.ymlhelper.get_server_list(role='compute')
        if podtype is not None and podtype == 'ceph':
            compute_server_list = self.ymlhelper.get_server_list(role='cephosd')

        for role in role_profiles:

            svr_list = self.ymlhelper.get_server_list(role=role)

            for server in svr_list:
                server_details = input_str.get(server)
                if server_details is not None:
                    server_vm_hp_perc = \
                        input_str[server].get('VM_HUGEPAGE_PERCENTAGE', None)
                    if server_vm_hp_perc is not None and \
                            server not in compute_server_list:
                        invalid_vm_hugh_page_server.append(server)

                if re.search(r'\.', server):
                    server_name = server.split(".")[0]
                    fq_server_name = server
                    tmp_server_name = server_name
                    if tmp_server_name in unique_hostname_prefix:
                        if server not in unique_hostname:
                            unique_hostname.append(fq_server_name)
                        else:
                            # Handle duplicate fqdn server exists or not
                            if podtype is not None and \
                                    re.match(r'UMHC|NGENAHC', podtype):
                                if re.match(r'block_storage', role) and \
                                        server in compute_server_list:
                                    continue
                                elif server not in duplicate_hostname:
                                    duplicate_hostname.append(fq_server_name)
                            elif podtype is not None and \
                                    re.match(r'micro', podtype):
                                if re.match(r'control|block_storage', role):
                                    continue
                                elif server not in duplicate_hostname:
                                    duplicate_hostname.append(fq_server_name)
                            elif podtype is not None and \
                                    re.match(r'edge|nano', podtype):
                                if re.match(r'control', role):
                                    continue
                                elif server not in duplicate_hostname:
                                    duplicate_hostname.append(fq_server_name)
                            elif podtype is not None and \
                                    podtype == 'ceph':
                                if re.match(r'cephcontrol', role):
                                    continue
                                elif server not in duplicate_hostname:
                                    duplicate_hostname.append(fq_server_name)

                            else:
                                duplicate_hostname.append(fq_server_name)

                        # Handle duplicate server exists or not
                        if podtype is not None and \
                                re.match(r'UMHC|NGENAHC', podtype):
                            if re.match(r'block_storage', role) and \
                                    server in compute_server_list:
                                continue
                            elif tmp_server_name not in \
                                    duplicate_hostname_prefix:
                                duplicate_hostname_prefix.append(tmp_server_name)
                        elif podtype is not None and \
                                re.match(r'micro', podtype):
                            if re.match(r'control|block_storage', role):
                                continue
                            elif tmp_server_name not in \
                                    duplicate_hostname_prefix:
                                duplicate_hostname_prefix.append(tmp_server_name)
                        elif podtype is not None and \
                                re.match(r'edge|nano', podtype):
                            if re.match(r'control', role):
                                continue
                            elif tmp_server_name not in \
                                    duplicate_hostname_prefix:
                                duplicate_hostname_prefix.append(tmp_server_name)

                        elif podtype is not None and \
                                podtype == 'ceph':
                            if re.match(r'cephcontrol', role):
                                continue
                            elif tmp_server_name not in \
                                    duplicate_hostname_prefix:
                                duplicate_hostname_prefix.append(tmp_server_name)

                        elif tmp_server_name not in duplicate_hostname_prefix:
                            duplicate_hostname_prefix.append(tmp_server_name)

                    else:
                        if podtype is not None and \
                                re.match(r'micro', podtype) and \
                                re.match(r'control|block_storage', role):
                            continue
                        elif podtype is not None and \
                                re.match(r'edge|nano', podtype) and \
                                re.match(r'control', role):
                            continue
                        elif podtype is not None and \
                                re.match(r'ceph', podtype) and \
                                re.match(r'cephcontrol', role):
                            continue
                        else:
                            unique_hostname_prefix.append(tmp_server_name)

                else:
                    server_name = server
                    fq_server_name = ""

                # Check for server with FQDN hostname > 64
                # Check for server with FQDN hostname < 64,
                # but first part of hostname > 32
                # Check for server with hostname > 32
                if len(fq_server_name) > fq_hostname_len_to_look_for:
                    if server not in unsupported_fq_hostname_len:
                        unsupported_fq_hostname_len.append(server)
                elif len(server_name) > hostname_len_to_look_for:
                    if server not in unsupported_hostname_len:
                        unsupported_hostname_len.append(server)
                elif fq_server_name and \
                        not common_utils.is_valid_hostname(fq_server_name):
                    if server not in invalid_hostname_syntax:
                        invalid_hostname_syntax.append(server)
                elif server_name and \
                        not common_utils.is_valid_hostname(server_name):
                    if server not in invalid_hostname_syntax:
                        invalid_hostname_syntax.append(server)

                if server not in server_found.keys():
                    server_found[server] = 0

                curr_msg = 'Missing/Invalid Critical information for %s' % server

                if re.match(r'UCSM', self.testbed_type):
                    if server in svr_list and \
                            re.search(r'control|compute', role):
                        server_found[server] = 1
                        try:
                            blade_non_storage_schema(input_str[server])
                        except MultipleInvalid as e:
                            for x in e.errors:
                                err_str = curr_msg + " " + str(x)
                                err_list.append(err_str)
                    elif server in svr_list and \
                            re.search(r'storage', role):
                        server_found[server] = 1
                        try:
                            blade_storage_schema(input_str[server])
                        except MultipleInvalid as e:
                            for x in e.errors:
                                err_str = curr_msg + " " + str(x)
                                err_list.append(err_str)
                else:
                    if server in svr_list:
                        server_found[server] = 1

                        if podtype is not None and re.match(r'micro', podtype):
                            if re.match(r'control|block_storage', role):
                                continue
                        elif podtype is not None and re.match(r'edge|nano', podtype):
                            if re.match(r'control', role):
                                continue

                        # Skip the relook of details for the storage servers
                        # present in compute in UMHC
                        elif podtype is not None and \
                                re.match(r'UMHC|NGENAHC', podtype):
                            if re.match(r'block_storage', role):
                                if server in compute_server_list:
                                    continue

                        elif podtype is not None and \
                                podtype == 'ceph':
                            if re.match(r'cephcontrol', role):
                                if server in compute_server_list:
                                    continue

                        try:

                            if role == 'compute':
                                hw_info = input_str[server].get('hardware_info', None)
                                if hw_info is not None:
                                    num_gpu_local_cards = hw_info.get('NUM_GPU_CARDS', None)
                                    vgpu_type_info = hw_info.get('VGPU_TYPE', None)

                                    if vgpu_type_info is not None and \
                                            num_gpu_local_cards is None:
                                        invalid_vgpu_server.append(server)

                            if role == 'compute':
                                pass
                            else:
                                mcast_snooping = \
                                    input_str[server].get('MULTICAST_SNOOPING', None)

                                server_type = self.ymlhelper.get_platform_vendor(server)
                                if server_type in ['QCT', 'HPE', 'KONTRON',
                                                   'SMCI']:

                                    if mcast_snooping is not None \
                                            and server not in compute_nodes:
                                        if server not in invalid_mcast_snooping_server:
                                            invalid_mcast_snooping_server.append(server)
                                elif mcast_snooping is not None:
                                    if server not in invalid_mcast_snooping_server:
                                        invalid_mcast_snooping_server.append(server)

                            global_intel_vc_sriov_vfs = \
                                self.ymlhelper.get_data_from_userinput_file(['INTEL_VC_SRIOV_VFS'])

                            if self.is_tor_config_enabled() or auto_tor_via_aci:
                                if intel_nic_check:

                                    # no dp_info for storage
                                    if re.match(r'block_storage', role) and \
                                            osd_nodes and server in osd_nodes:
                                        if mechanism_driver == 'aci':
                                            standalone_schema_csco_vic_aci(\
                                                input_str[server])
                                        elif is_cpdp_collapsed:
                                            standalone_schema_dpcp_aci_noplugin( \
                                                input_str[server])
                                        else:
                                            standalone_wtor_schema(input_str[server])
                                    else:
                                        if re.match(r'compute|control', role) and \
                                                is_sriov_enabled and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server in control_nodes and \
                                                self.is_head_end_rep_defined( \
                                                    'vxlan-ecn') and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):

                                            if podtype == 'fullon' and role == 'control':
                                                control_only_mvxlan_her_intel_sriov_schema(\
                                                    input_str[server])
                                            else:
                                                control_wncs_mvxlan_her_intel_sriov_schema(\
                                                    input_str[server])
                                        elif re.match(r'compute|control', role) and \
                                                self.is_tor_type_ncs5500() and \
                                                is_sriov_enabled and \
                                                compute_nodes and \
                                                server in control_nodes and \
                                                self.is_network_segment_defined(\
                                                    'sr-mpls-tenant') and \
                                                compute_nodes:

                                            if podtype == 'fullon' and role == 'control':
                                                control_only_sr_mpls_intel_sriov_schema(\
                                                    input_str[server])
                                            else:
                                                control_wncs_sr_mpls_intel_sriov_schema(\
                                                    input_str[server])
                                            self.populate_sr_global_block_info(server, input_str[server])
                                        elif re.match(r'compute|control', role) and \
                                                is_sriov_enabled and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server in control_nodes and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):

                                            if podtype == 'fullon' and role == 'control':
                                                control_only_mvxlan_intel_sriov_schema( \
                                                    input_str[server])
                                            else:
                                                control_wncs_mvxlan_intel_sriov_schema(\
                                                    input_str[server])
                                        elif re.match(r'compute|control', role) and \
                                                not is_sriov_enabled and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                self.is_head_end_rep_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server in control_nodes and \
                                                self.is_network_segment_defined( \
                                                    'vxlan-tenant'):
                                            control_wncs_mvxlan_her_intel_schema( \
                                                input_str[server])
                                        elif re.match(r'compute|control', role) and \
                                                not is_sriov_enabled and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server in control_nodes and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            control_wncs_mvxlan_intel_schema(\
                                                input_str[server])
                                        elif re.match(r'compute|control', role) and \
                                                is_sriov_enabled and \
                                                compute_nodes and \
                                                server in control_nodes and \
                                                self.is_head_end_rep_defined(\
                                                    'vxlan-tenant') and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            control_wncs_vxlan_her_intel_sriov_schema(\
                                                input_str[server])
                                        elif re.match(r'compute|control', role) and \
                                                is_sriov_enabled and \
                                                compute_nodes and \
                                                server in control_nodes and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            control_wncs_vxlan_intel_sriov_schema( \
                                                input_str[server])
                                        elif re.match(r'compute|control', role) and \
                                                not is_sriov_enabled and \
                                                compute_nodes and \
                                                server in control_nodes and \
                                                self.is_head_end_rep_defined(\
                                                    'vxlan-tenant') and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            control_wncs_vxlan_her_intel_schema(\
                                                input_str[server])
                                        elif re.match(r'compute|control', role) and \
                                                not is_sriov_enabled and \
                                                compute_nodes and \
                                                server in control_nodes and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            control_wncs_vxlan_intel_schema(\
                                                input_str[server])
                                        elif re.match(r'compute|control', role) and \
                                                self.is_tor_type_ncs5500() and \
                                                is_sriov_enabled and \
                                                compute_nodes and \
                                                server not in control_nodes and \
                                                self.is_network_segment_defined(\
                                                    'sr-mpls-tenant') and \
                                                compute_nodes:
                                            compute_wncs_sr_mpls_tenant_intel_sriov_schema(\
                                                input_str[server])
                                            self.populate_sr_global_block_info(server, input_str[server])
                                        elif re.match(r'compute', role) and \
                                                is_sriov_enabled and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server not in control_nodes and \
                                                self.is_head_end_rep_defined(\
                                                    'vxlan-ecn') and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            standalone_wncs_intel_mvxlan_her_opt_sriov_schema(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                is_sriov_enabled and \
                                                not self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server not in control_nodes and \
                                                self.is_head_end_rep_defined(\
                                                    'vxlan-tenant') and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            standalone_wncs_intel_her_opt_sriov_schema(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                not is_sriov_enabled and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server not in control_nodes and \
                                                self.is_head_end_rep_defined(\
                                                    'vxlan-ecn') and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            standalone_wtor_mvxlan_her_intel_schema(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                not is_sriov_enabled and \
                                                not self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server not in control_nodes and \
                                                self.is_head_end_rep_defined(\
                                                    'vxlan-tenant') and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            standalone_wtor_her_intel_schema(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                not is_sriov_enabled and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server not in control_nodes and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            compute_mvxlan_intel_schema(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                is_sriov_enabled and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server not in control_nodes and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            compute_mvxlan_intel_sriov_schema(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                not is_sriov_enabled and \
                                                not self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server not in control_nodes and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            compute_vxlan_intel_schema(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                is_sriov_enabled and \
                                                not self.is_network_segment_defined(\
                                                    'vxlan-ecn') and \
                                                compute_nodes and \
                                                server not in control_nodes and \
                                                self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            compute_vxlan_intel_sriov_schema(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                not is_sriov_enabled and \
                                                compute_nodes and \
                                                server in control_nodes and \
                                                not self.is_network_segment_defined(\
                                                    'vxlan-tenant'):
                                            standalone_wtor_intel_schema(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                self.is_tor_type_ncs5500() and \
                                                is_sriov_enabled and \
                                                compute_nodes and \
                                                server in compute_nodes:
                                            standalone_wncs_intel_opt_sriov_schema(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                self.is_tor_type_ncs5500() and \
                                                compute_nodes and \
                                                server in compute_nodes:
                                            standalone_wtor_intel_schema(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                intel_nic_sriov_check and \
                                                compute_nodes and \
                                                server in compute_nodes \
                                                and is_cpdp_collapsed:
                                            standalone_schema_dpcp_sriov_aci_noplugin(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                intel_nic_sriov_check and \
                                                compute_nodes and \
                                                server in compute_nodes and \
                                                (mechanism_driver == 'aci' or auto_tor_via_aci):
                                            standalone_schema_csco_nic_sriov_aci(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                intel_nic_sriov_check and \
                                                compute_nodes and \
                                                server in compute_nodes:
                                            standalone_wtor_intel_sriov_schema(\
                                                input_str[server])
                                        else:
                                            if mechanism_driver == 'aci':
                                                standalone_schema_csco_nic_aci(\
                                                    input_str[server])
                                            elif auto_tor_via_aci and \
                                                    is_cpdp_collapsed:
                                                standalone_schema_dpcp_aci_noplugin(\
                                                    input_str[server])
                                            else:
                                                standalone_wtor_intel_schema(\
                                                    input_str[server])
                                elif vic_nic_check:
                                    # no dp_info for storage
                                    if re.match(r'block_storage', role) and \
                                            osd_nodes and server in osd_nodes:
                                        if auto_tor_via_aci:
                                            standalone_schema_dpcp_aci_noplugin( \
                                                input_str[server])
                                        else:
                                            standalone_schema_cisco_vic(\
                                                input_str[server])
                                    else:
                                        if auto_tor_via_aci and \
                                                re.match(r'compute', role) and \
                                                intel_nic_sriov_check and \
                                                compute_nodes and \
                                                server in compute_nodes \
                                                and is_cpdp_collapsed:
                                            standalone_schema_dpcp_sriov_aci_noplugin(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                compute_nodes and \
                                                server in compute_nodes and \
                                                mechanism_driver == 'aci':
                                            standalone_schema_intel520_sriov_aci_noplugin(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                compute_nodes and \
                                                server in compute_nodes:
                                            standalone_schema_intel520_nic_sriov(\
                                                input_str[server])
                                        else:
                                            if auto_tor_via_aci:
                                                standalone_schema_dpcp_aci_noplugin(\
                                                    input_str[server])
                                            else:
                                                standalone_schema_cisco_vic(\
                                                    input_str[server])
                                else:
                                    if auto_tor_via_aci and podtype == 'ceph':
                                        standalone_schema_ceph_pod_w_tor( \
                                            input_str[server])
                                    elif podtype == 'ceph':
                                        standalone_schema_ceph_pod( \
                                            input_str[server])
                                    elif auto_tor_via_aci:
                                        standalone_schema_csco_vic_aci(input_str[server])
                                    else:
                                        standalone_wtor_schema(input_str[server])
                            else:
                                if intel_nic_check:
                                    # no dp_info for storage
                                    if re.match(r'block_storage', role) and \
                                            osd_nodes and server in osd_nodes:
                                        if mechanism_driver == 'aci':
                                            standalone_schema_csco_vic_aci(\
                                                input_str[server])
                                        elif auto_tor_via_aci and \
                                                is_cpdp_collapsed:
                                            standalone_schema_dpcp_aci_noplugin( \
                                                input_str[server])
                                        else:
                                            standalone_schema_cisco_vic(\
                                                input_str[server])
                                    else:
                                        if re.match(r'compute', role) and \
                                                intel_nic_sriov_check and \
                                                compute_nodes and \
                                                server in compute_nodes and \
                                                mechanism_driver == 'aci':
                                            standalone_schema_csco_nic_sriov_aci(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                intel_nic_sriov_check and \
                                                compute_nodes and \
                                                server in compute_nodes \
                                                and auto_tor_via_aci and \
                                                is_cpdp_collapsed:
                                            standalone_schema_dpcp_sriov_aci_noplugin(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                (intel_nic_sriov_check or \
                                                global_intel_vc_sriov_vfs) and \
                                                (intel_nic_sriov_check or \
                                                global_intel_vc_sriov_vfs) and \
                                                compute_nodes and \
                                                server in compute_nodes:
                                            standalone_schema_intel_nic_sriov(\
                                                input_str[server])
                                        else:
                                            if mechanism_driver == 'aci':
                                                standalone_schema_csco_nic_aci(\
                                                    input_str[server])
                                            elif auto_tor_via_aci and \
                                                    is_cpdp_collapsed:
                                                standalone_schema_dpcp_aci_noplugin(\
                                                    input_str[server])
                                            else:
                                                standalone_schema_intel_nic(\
                                                    input_str[server])
                                elif vic_nic_check:
                                    # no dp_info for storage
                                    if re.match(r'block_storage', role) and \
                                            osd_nodes and server in osd_nodes:
                                        if auto_tor_via_aci:
                                            standalone_schema_dpcp_aci_noplugin( \
                                                input_str[server])
                                        elif mechanism_driver == 'aci' \
                                                and podtype == 'fullon':
                                            standalone_schema_csco_vic_aci(\
                                                input_str[server])
                                        else:
                                            standalone_schema_cisco_vic(\
                                                input_str[server])
                                    else:

                                        if re.match(r'compute', role) and \
                                                compute_nodes and \
                                                server in compute_nodes and \
                                                auto_tor_via_aci:
                                            standalone_schema_intel520_sriov_aci_noplugin(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                compute_nodes and \
                                                server in compute_nodes and \
                                                mechanism_driver == 'aci':
                                            standalone_schema_intel520_sriov_aci_noplugin(\
                                                input_str[server])
                                        elif re.match(r'compute', role) and \
                                                compute_nodes and \
                                                server in compute_nodes:
                                            standalone_schema_intel520_nic_sriov(\
                                                input_str[server])
                                        else:
                                            if auto_tor_via_aci or \
                                                    mechanism_driver == 'aci':
                                                standalone_schema_csco_vic_aci( \
                                                    input_str[server])
                                            else:
                                                standalone_schema_cisco_vic(\
                                                    input_str[server])

                                elif podtype == 'ceph':
                                    standalone_schema_ceph_pod(input_str[server])
                                elif mechanism_driver == 'aci':
                                    standalone_schema_csco_vic_aci(input_str[server])
                                elif mechanism_driver == 'vts' and \
                                        self.check_managed_vts_config():
                                    if role == 'control' or role == 'compute' \
                                            or role == 'block_storage':
                                        standalone_schema_cisco_vic_mvts(\
                                            input_str[server])
                                    else:
                                        standalone_schema_cisco_vic(\
                                            input_str[server])
                                else:
                                    standalone_schema_cisco_vic(input_str[server])

                            vm_em_pcores_per_server = \
                                input_str[server].get('VM_EMULATOR_PCORES_PER_SOCKET', None)
                            if vm_em_pcores_per_server is not None:
                                vm_em_pin_per_server = \
                                    input_str[server].get('ENABLE_VM_EMULATOR_PIN', None)
                                self.check_vm_emulator_pcore_per_server(input_str[server],
                                                                        vm_em_pcores_per_server,
                                                                        vm_em_pin_per_server)

                        except MultipleInvalid as e:
                            for x in e.errors:
                                err_str = curr_msg + " " + str(x)
                                err_list.append(err_str)
                        except Exception as e:
                            err_str = curr_msg + " " + str(e)
                            err_list.append(err_str)

        # return if we detect an error at server schema level
        # subsequent checks are server details
        if err_list:
            raise Invalid(', '.join(err_list))

        found_static_mgmt_ip = 0
        found_static_mgmt_ipv6 = 0
        found_static_storage_ip = 0
        found_static_cluster_ip = 0

        dup_eth_port_list = \
            self.get_duplicate_entry_in_list(self.server_eth_port_list)
        dup_pc_list = \
            self.get_duplicate_entry_in_list(self.server_port_channel_list)

        missing_role_list = []
        for key, value in server_found.iteritems():
            if not value:
                missing_role_list.append(key)

        for server in input_str:

            server_mgmt_ip = self.ymlhelper.get_server_static_mgmt_ip(server)
            server_mgmt_ipv6 = self.ymlhelper.get_server_static_mgmt_ipv6(server)

            # checks if there are any duplicate IP in mgmt pool
            if server_mgmt_ip is not None:
                if self.does_dup_mgmt_ip_exist(server_mgmt_ip) and \
                        server_mgmt_ip not in repeating_mgmt_ip_info:
                    repeating_mgmt_ip_info.append(server_mgmt_ip)

            if server_mgmt_ipv6 is not None:
                if self.does_dup_mgmt_ip_exist(server_mgmt_ipv6, iptype='v6') and \
                        server_mgmt_ipv6 not in repeating_mgmt_ipv6_info:
                    repeating_mgmt_ipv6_info.append(server_mgmt_ipv6)

            # checks if all or no serves have mgmt_ip defined
            if self.is_static_mgmt_ip_defined():
                found_static_mgmt_ip = 1
                if server_mgmt_ip is None:
                    missing_mgmt_ip_info.append(server)

            if self.is_static_mgmt_ipv6_defined():
                found_static_mgmt_ipv6 = 1
                if server_mgmt_ipv6 is None:
                    missing_mgmt_ipv6_info.append(server)

            if podtype is not None and podtype == 'ceph':

                # checks if there are any duplicate IP in cluster pool
                server_cluster_ip = \
                    self.ymlhelper.get_server_static_cluster_ip(server)
                if server_cluster_ip is not None:
                    if server_cluster_ip not in curr_cluster_ip_info:
                        curr_cluster_ip_info.append(server_cluster_ip)
                    else:
                        tmp = str(server) + ":" + str(server_cluster_ip)
                        repeating_cluster_ip_info.append(tmp)

                # checks if all or no serves have cluster_ip defined
                if self.is_static_cluster_ip_defined():
                    found_static_cluster_ip = 1
                    if server_cluster_ip is None:
                        missing_cluster_ip_info.append(server)

            else:

                # checks if there are any duplicate IP in storage pool
                server_storage_ip = \
                    self.ymlhelper.get_server_static_storage_ip(server)
                if server_storage_ip is not None:
                    if server_storage_ip not in curr_storage_ip_info:
                        curr_storage_ip_info.append(server_storage_ip)
                    else:
                        tmp = str(server) + ":" + str(server_storage_ip)
                        repeating_storage_ip_info.append(tmp)

                # checks if all or no serves have storage_ip defined
                if self.is_static_storage_ip_defined():
                    found_static_storage_ip = 1
                    if server_storage_ip is None:
                        missing_storage_ip_info.append(server)

            server_role = self.ymlhelper.get_server_cimc_role(server,
                                                              allroles=True)

            if len(server_role) == 1 and server_role[0] == "block_storage":
                continue

            server_tenant_ip = self.ymlhelper.get_server_static_tenant_ip(
                server)
            if server_tenant_ip is not None:
                if self.does_dup_mgmt_ip_exist(server_tenant_ip) and \
                        server_tenant_ip not in repeating_tenant_ip_info:
                    repeating_tenant_ip_info.append(server_tenant_ip)
            if self.is_static_tenant_ip_defined() and server_tenant_ip is None:
                missing_tenant_ip_info.append(server)

        if num_gpu_global_cards is not None:
            err_str = "NUM_GPU_CARDS Global level is not supported, " \
                "please define it at a per server level"
            err_list.append(err_str)

        if invalid_vgpu_server:
            err_str = "NUM_GPU_CARDS not defined at server level " \
                "for VGPU enablement on %s" % (', '.join(invalid_vgpu_server))
            err_list.append(err_str)

        if invalid_mcast_snooping_server:
            err_str = "MULTICAST_SNOOPING cannot be set for servers %s " \
                "that are not in compute role or for servers in compute role, " \
                " where control and data plane are not collapsed on the Intel " \
                "NIC" \
                % (', '.join(invalid_mcast_snooping_server))
            err_list.append(err_str)

        if invalid_vm_hugh_page_server:
            err_str = "Server(s):%s are not in compute role but have " \
                "VM_HUGEPAGE_PERCENTAGE enabled" \
                % (', '.join(invalid_vm_hugh_page_server))
            err_list.append(err_str)

        if dup_eth_port_list:
            err_str = "Duplicate eth port info across servers: " + \
                ' '.join(dup_eth_port_list)
            err_list.append(err_str)

        if dup_pc_list:
            err_str = "Duplicate Port Channel info across servers: " + \
                ' '.join(dup_pc_list)
            err_list.append(err_str)

        if self.is_pod_dual_stack() and found_static_mgmt_ip and \
                not found_static_mgmt_ipv6:
            err_str = "Static server management IP should be " \
                "configured with static management IPv6 in a " \
                "dual stack environment"
            err_list.append(err_str)

        if found_static_mgmt_ipv6 and not found_static_mgmt_ip:
            err_str = "Static server management IPv6 should be " \
                "configured with static management ip"
            err_list.append(err_str)

        if found_static_storage_ip and not found_static_mgmt_ip:
            err_str = "Static server storage IP should be configured " \
                "with static management ip"
            err_list.append(err_str)

        if found_static_cluster_ip and not found_static_mgmt_ip:
            err_str = "Static server cluster IP should be configured " \
                "with static management ip"
            err_list.append(err_str)

        if missing_storage_ip_info:
            err_str = "Missing Storage IP Info for: " + \
                      str(missing_storage_ip_info)
            err_list.append(err_str)

        if repeating_storage_ip_info:
            err_str = "Duplicate Static Storage IPs: " + \
                      str(repeating_storage_ip_info)
            err_list.append(err_str)

        if missing_cluster_ip_info:
            err_str = "Missing Cluster IP Info for: " + \
                      str(missing_cluster_ip_info)
            err_list.append(err_str)

        if repeating_cluster_ip_info:
            err_str = "Duplicate Static Cluster IPs: " + \
                      str(repeating_cluster_ip_info)
            err_list.append(err_str)

        if missing_mgmt_ip_info:
            err_str = "Missing Mgmt IP Info for: " + \
                      str(missing_mgmt_ip_info)
            err_list.append(err_str)

        if repeating_mgmt_ip_info:
            err_str = "Duplicate Static Mgmt IPs: " + \
                      str(repeating_mgmt_ip_info)
            err_list.append(err_str)

        if missing_mgmt_ipv6_info:
            err_str = "Missing Mgmt IPv6 Info for: " + \
                      str(missing_mgmt_ipv6_info)
            err_list.append(err_str)

        if repeating_mgmt_ipv6_info:
            err_str = "Duplicate Static Mgmt IPv6s: " + \
                      str(repeating_mgmt_ipv6_info)
            err_list.append(err_str)

        if missing_tenant_ip_info:
            err_str = "Missing tenant ip Info for: " + \
                      str(missing_tenant_ip_info)
            err_list.append(err_str)

        if repeating_tenant_ip_info:
            err_str = "Duplicate static tenant ip: " + \
                      str(repeating_tenant_ip_info)
            err_list.append(err_str)

        if missing_role_list:
            err_str = "Missing roles for servers " + \
                      str(missing_role_list)
            err_list.append(err_str)

        if unsupported_fq_hostname_len:
            err_info = "FQDN Servers with hostname length > " + \
                       fq_hostname_len_to_look_for + " found: "
            err_info = err_info + str(unsupported_fq_hostname_len)
            err_list.append(err_info)

        if invalid_hostname_syntax:
            valid_syntax = "; Invalid hostname syntax: Max of 64 chars, " \
                           "where the characters are any combination of " \
                           "\"A-Za-z0-9-.\"; and the TLD is not all-numeric"

            err_info = "Servers with invalid hostname syntax found: "
            err_info = err_info + ','.join(invalid_hostname_syntax) + valid_syntax
            err_list.append(err_info)

        if unsupported_hostname_len:
            err_info = "Servers with hostname length > %s found: " \
                % (hostname_len_to_look_for)
            err_info = err_info + str(unsupported_hostname_len)
            err_list.append(err_info)

        if duplicate_hostname:
            err_info = "Multiple servers with matching hostname found: "
            err_info = "\n" + err_info

            duplicate_fq_hostname = []
            for item in duplicate_hostname:
                for server in input_str:
                    if re.match(item, server):
                        duplicate_fq_hostname.append(server)

            err_info += str(duplicate_fq_hostname)
            err_list.append(err_info)

        if duplicate_hostname_prefix:
            err_info = "Multiple servers with matching hostname prefix found: "
            err_info = "\n" + err_info

            duplicate_fq_hostname_prefix = []
            for item in duplicate_hostname_prefix:
                for server in input_str:
                    tmp_item = item + str(r'\.')
                    if re.match(tmp_item, server):
                        duplicate_fq_hostname_prefix.append(server)

            err_info += str(duplicate_fq_hostname_prefix)
            err_list.append(err_info)

        if err_list:
            raise Invalid(', '.join(err_list))

        return

    def check_for_optional_enabled(self, service_name):
        '''Check if specific optional service is enabled'''

        try:
            opt_list = \
                self.ymlhelper.get_data_from_userinput_file(\
                    ['OPTIONAL_SERVICE_LIST'])

            if opt_list is None:
                return 0
            elif service_name in opt_list:
                return 1
        except AttributeError:
            return 0

        return 0

    def check_domain_info(self, input_str):
        '''Checks the LDAP domain URL syntax and CURL'''

        err_str = "Incorrect LDAP DOMAIN Syntax; " \
                  "Expecting: the format to be: " \
                  "url: '<ldaps|ldap>://<fqdn|ip-address>:[port]’," \
                  "or <ldaps|ldap>://[ipv6-address>]:[port]" \
                  " Found: "

        incorrect_suffix_list = []
        incorrect_entry_format = []
        possible_ldaps = input_str.split(",")
        for item in possible_ldaps:
            tmp_item = item.strip()
            if not re.match(r'ldap://|ldaps://', tmp_item):
                incorrect_suffix_list.append(tmp_item)

        # fail on incorrect suffix
        if incorrect_suffix_list:
            err_str_fin = "%s Missing ldap://|ldaps:// in %s " \
                % (err_str, ','.join(incorrect_suffix_list))
            raise Invalid(err_str_fin)

        v6_url_found = 0
        for item in possible_ldaps:
            match_type = "UNKNOWN"
            tmp_item = item.strip()
            if v6_pattern.match(tmp_item) and \
                    re.search(r'\[', tmp_item) and \
                    re.search(r'\]', tmp_item):
                match_type = 'v6'
                v6_url_found = 1
                ldap_ip_info = re.split(r'[\[ \]]', tmp_item)
                ldap_ip = ldap_ip_info[1]
            else:
                match_type = 'v4'
                ldap_ip_info = tmp_item.split(":")
                ldap_ip = ldap_ip_info[1].strip("//")

            if len(ldap_ip_info) == 3 and ldap_ip_info[2]:
                if not re.search(r':[0-9]+$', tmp_item):
                    err_str_info = "%s Missing port info in %s " \
                        % (err_str, ldap_ip_info)
                    raise Invalid(err_str_info)

            found_match = 0
            if re.match(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', ldap_ip):
                found_match = 1
                self.is_ip_syntax_valid(ldap_ip)

            elif match_type == 'v6':
                found_match = 1
                self.is_ipv6_syntax_valid(ldap_ip)

            elif re.match('[a-zA-Z0-9.]+', ldap_ip):
                found_match = 1
                self.is_input_in_plain_str(ldap_ip)

            if not found_match:
                incorrect_entry_format.append(tmp_item)

        if incorrect_entry_format:
            err_str_fin = "%s Incorrect Syntx for v4/v6/domain %s " \
                % (err_str, ','.join(incorrect_entry_format))
            raise Invalid(err_str_fin)

        if v6_url_found:
            err_msg = self.is_v6_mgmt_network_defined()

            if err_msg:
                raise Invalid(err_msg)

            self.get_ip_info("br_mgmt", type='v6')

        return

    def check_user_filter_info(self, input_str):
        '''Checks the syntax of user_file_info'''

        self.is_input_in_plain_str(input_str)

        err_str = "incorrect format, needs to be enclosed in (..); " \
                  "current_input: %s" % (input_str)

        if re.match(r'\(', input_str) and re.search(r'\)$', input_str):
            pass
        else:
            raise Invalid(err_str)

        return

    def check_ceph_pg_info(self, input_str):
        '''Checks the syntax and validity of the CEPH_PG_INFO input
        '''
        ceph_local_schema = Schema({
            Required('cinder_percentage_data'): All(int, Range(min=10, max=90)),
            Required('glance_percentage_data'): All(int, Range(min=10, max=90)),
            Optional('gnocchi_percentage_data'): All(int, Range(min=5, max=80))
        })
        ceph_boot_schema = Schema({
            Required('cinder_percentage_data'): All(int, Range(min=10, max=80)),
            Required('glance_percentage_data'): All(int, Range(min=10, max=80)),
            Required('nova_percentage_data'): All(int, Range(min=10, max=80)),
            Optional('gnocchi_percentage_data'): All(int, Range(min=5, max=80))
        })
        nova_boot_from = \
            self.ymlhelper.get_data_from_userinput_file(['NOVA_BOOT_FROM'])
        store_backend = \
            self.ymlhelper.get_data_from_userinput_file(['STORE_BACKEND'])
        if store_backend != "ceph":
            err_str = "Store backend ceph needed for CEPH_PG_INFO"
            raise Invalid(err_str)
        ceph_pg = self.ymlhelper.get_data_from_userinput_file(['CEPH_PG_INFO'])
        if nova_boot_from == "ceph":
            try:
                ceph_boot_schema(input_str)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))
            cinder_pc_data = ceph_pg.get('cinder_percentage_data')
            glance_pc_data = ceph_pg.get('glance_percentage_data')
            nova_pc_data = ceph_pg.get('nova_percentage_data')
            total_pc_data = cinder_pc_data + glance_pc_data + nova_pc_data
        else:
            try:
                ceph_local_schema(input_str)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))
            cinder_pc_data = ceph_pg.get('cinder_percentage_data')
            glance_pc_data = ceph_pg.get('glance_percentage_data')
            total_pc_data = cinder_pc_data + glance_pc_data
        if self.check_for_optional_enabled('ceilometer'):
            gnocchi_pc_data = ceph_pg.get('gnocchi_percentage_data')
            if not gnocchi_pc_data:
                err_str = ("Ceilometer is enabled. Need to configure "
                           "'gnocchi_percentage_data' to write metrics")
                raise Invalid(err_str)
            total_pc_data += gnocchi_pc_data
        if total_pc_data != 100:
            err_str = "Total data percentage should add up to 100 percent"
            raise Invalid(err_str)
        return

    def check_vim_ldap_admins(self, input_str):
        '''check the syntax and validity of LDAP admin on management node'''

        ldap_bn_info_schema = Schema({
            Required('domain_name'): self.is_input_in_plain_str,
            Required('ldap_uri'): self.check_domain_info,
            Required('ldap_search_base'): self.is_input_in_plain_str,
            Optional('ldap_schema'): self.is_input_in_plain_str,
            Optional('ldap_user_object_class'): self.is_input_in_plain_str,
            Optional('ldap_user_uid_number'): self.is_input_in_ascii,
            Optional('ldap_user_gid_number'): self.is_input_in_ascii,
            Optional('ldap_group_member'): self.is_input_in_plain_str,
            Optional('ldap_default_bind_dn'): self.is_input_in_plain_str,
            Optional('ldap_default_authtok'): self.is_input_in_plain_str,
            Optional('ldap_default_authtok_type'): self.is_input_in_plain_str,
            Optional('ldap_group_search_base'): self.is_input_in_plain_str,
            Optional('ldap_user_search_base'): self.is_input_in_plain_str,
            Optional('access_provider'): self.is_input_in_plain_str,
            Optional('simple_allow_groups'): self.is_input_in_plain_str,
            Optional('ldap_id_use_start_tls'): bool,
            Optional('ldap_tls_reqcert'):
                In(frozenset(["never", "allow", "try", "demand"])),
            Optional('chpass_provider'):
                In(frozenset(["ldap", "krb5", "ad", "none"])),
        })

        err_list = []
        domain_list = []
        ldap_uri_list = []

        for item in input_str:
            try:
                ldap_bn_info_schema(item)
                domain_list.append(item.get('domain_name'))
                ldap_info = item.get('ldap_uri')
                tmp = ldap_info.split(",")
                ldap_uri_list.extend(tmp)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))

        if err_list:
            err_str = ' '.join(err_list)
            raise Invalid(err_str)

        dup_domain_list = \
            self.get_duplicate_entry_in_list(domain_list)
        if dup_domain_list:
            err_str = "Duplicate Domain list found %s " \
                % (','.join(dup_domain_list))
            err_list.append(err_str)

        dup_ldap_uri_list = \
            self.get_duplicate_entry_in_list(ldap_uri_list)
        if dup_ldap_uri_list:
            err_str = "Duplicate LDAP URI found %s " \
                % (','.join(dup_domain_list))
            err_list.append(err_str)

        non_secure_ldap_list = []
        for item in ldap_uri_list:
            if not re.search(r'ldaps', item):
                non_secure_ldap_list.append(item)

        if non_secure_ldap_list:
            err_str = "Non secure ldap list found %s" \
                % (','.join(non_secure_ldap_list))
            err_list.append(err_str)

        is_tls_enabled = self.ymlhelper.get_data_from_userinput_file(\
            ['external_lb_vip_tls'])

        if is_tls_enabled is None or is_tls_enabled is False:
            err_str = "External TLS has to be enabled"
            err_list.append(err_str)

        if err_list:
            raise Invalid(', '.join(err_list))

        return

    def check_ldap_input(self, input_str):
        '''Checks the syntax and validity of the LDAP input
        Beyond syntax check, check if LDAP is defined only when
        Keystone v3 is defined'''

        ldap_info_schema = Schema({
            Required('domain'): self.is_input_in_plain_str,
            Required('url'): self.check_domain_info,
            Optional('user'): All(str, msg='Missing LDAP User Info'),
            Optional('password'): self.check_password_syntax,
            Required('suffix'): All(str, msg='Missing LDAP Suffix Info'),
            Required('user_tree_dn'): All(str, msg='Missing LDAP User Tree DN Info'),
            Required('user_objectclass'): self.is_input_in_plain_str,
            Required('group_tree_dn'):
                All(str, msg='Missing LDAP Group Tree DN Info'),
            Required('group_objectclass'): self.is_input_in_plain_str,
            Optional('user_filter'): All(str, msg='Missing LDAP User Filter Info'),
            Required('user_id_attribute'): self.is_input_in_plain_str,
            Required('user_name_attribute'): self.is_input_in_plain_str,
            Optional('user_mail_attribute'): self.is_input_in_plain_str,
            Required('group_name_attribute'): self.is_input_in_plain_str,
            Optional('group_filter'): self.is_input_in_ascii,
            Optional('group_member_attribute'): self.is_input_in_plain_str,
            Optional('group_id_attribute'): self.is_input_in_plain_str,
            Optional('group_members_are_ids'): self.is_input_in_plain_str,
            Optional('chase_referrals'): All(Boolean(str), \
                msg="Only Boolean value True/False allowed; default is True"),
        })

        err_list = []
        try:
            ldap_info_schema(input_str)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        if err_list:
            err_str = ' '.join(err_list)
            raise Invalid(err_str)

        ldap_uname = input_str.get('user')
        ldap_pwd = input_str.get('password')

        if ldap_uname is None and ldap_pwd is None:
            pass
        elif ldap_uname is None and ldap_pwd is not None:
            err_str = "LDAP user has to be defined, if password is defined"
            raise Invalid(err_str)
        elif ldap_uname is not None and ldap_pwd is None:
            err_str = "LDAP password has to be defined, if user is defined"
            raise Invalid(err_str)

        return

    def check_nfvbench_tor_info(self, input_str):
        '''Checks the NFVbench tor info;
        Compares the input with switch and the servers'''

        err_list = []

        # compare input with switch first
        self.check_tor_info_for_server(input_str,
                                       skip_port_channel=1,
                                       skip_type="NFVBENCH")

        dup_eth_port_list = \
            self.get_duplicate_entry_in_list(self.server_eth_port_list)

        if dup_eth_port_list:
            err_str = "Duplicate eth port info across Servers and NFVBENCH: " + \
                ' '.join(dup_eth_port_list)
            err_list.append(err_str)

        if err_list:
            raise Invalid(', '.join(err_list))

        return

    def check_vts_vtep_ip_nfvbench_info(self, input_str):
        '''Check if vts_vtep_ip_nfvbench_info is correct'''

        vtep_ip_list = self.check_vtep_ip_syntax(input_str, "NFVbench")
        for item in vtep_ip_list:
            self.is_segment_ip_valid(item,
                                     default_entry="tenant_for_vts",
                                     segment_info="tenant")

        return

    def check_vtep_ip_nfvbench_info(self, input_str):
        '''Check vtep ip nfvbench info'''

        vtep_ip_list = self.check_vtep_ip_syntax(input_str, "NFVbench")

        if vtep_ip_list:
            for item in vtep_ip_list:
                self.is_segment_ip_valid(item)

        return

    def check_vtep_ip_syntax(self, input_str, section):
        '''Check VTEP IP Syntax under a given section'''

        if not isinstance(input_str, str):
            err_str = "Non-String Input not allowed; has to be of the " \
                      "format: vtep_ip1,vtep_ip2 in %s" % (section)
            raise Invalid(err_str)

        vtep_ip_list = input_str.split(",")
        if len(vtep_ip_list) != 2:
            err_str = "Expected input to be of pattern " \
                "vtep_ip1,vtep_ip2 in %s" % (section)
            raise Invalid(err_str)

        dup_vtep_ip_list = \
            self.get_duplicate_entry_in_list(vtep_ip_list)
        if dup_vtep_ip_list:
            err_msg = "Duplicate vtep_ips %s found under NFVbench " \
                      % (','.join(dup_vtep_ip_list))
            raise Invalid(err_msg)

        return vtep_ip_list

    def check_vni_nfvbench_info(self, input_str):
        '''Check VNI info in nfvbench'''

        if not isinstance(input_str, str):
            err_str = "Non-String Input not allowed; has to be of the " \
                      "format: vni_id1:vni_id2"
            raise Invalid(err_str)

        vni_id_list = input_str.split(":")
        if len(vni_id_list) != 2:
            err_str = "Expected input to be of pattern vni_id1:vni_id2"
            raise Invalid(err_str)

        dup_vniid_list = \
            self.get_duplicate_entry_in_list(vni_id_list)
        if dup_vniid_list:
            err_msg = "Duplicate VNI id %s found under NFVbench " \
                      % (','.join(dup_vniid_list))
            raise Invalid(err_msg)

        for item in vni_id_list:
            if int(item) < 1 or int(item) > 16777215:
                err_msg = "Incorrect input of vnis %s found under NFVBench:%s " \
                          "needs to be between 1 and 2^24-1" \
                          % (item, input_str)
                raise Invalid(err_msg)

            if self.cd_cfgmgr.is_l3_fabric_enabled():
                self.l3_fabric_vni_list.append(int(item))

        return

    def check_vpn_labels(self, input_str):
        """heck VPN label fits interval 1-1000000 and
        Label_A > Label_B and Label_A != Label_B"""

        err_str = "Entry of type string, with syntax Label_A:Label_B " \
            "where each label is in the range of 1 to 1000000 and " \
            "Label_A > Label_B and Label_A != Label_B; " \
            "Current input %s" % input_str

        tmp = re.sub(" ", '', input_str)
        input_str = tmp

        if not isinstance(input_str, str):
            raise Invalid(err_str)

        if not re.search(":", input_str):
            raise Invalid(err_str)

        input_list = input_str.split(":")
        if len(input_list) != 2:
            raise Invalid(err_str)

        for item in input_list:
            if not (1 < int(item) < 1000000):
                raise Invalid(err_str)

        if input_list[0] > input_list[1]:
            raise Invalid(err_str)

    def check_transport_labels_prefixes(self, input_str):
        """Check transport_labels_prefixes;
        These subnets should not intersect with setup_data
        NETWORK subnets sections or check_vtep_gateway_networks"""

        err_str = "Have to be of the syntax a.b.c.d/e:f.g.h.i/j, " \
            "where the subnets does not intersect with any in the setup_data; " \
            "Current input is: %s" % input_str

        self.check_gateway_network_consistency(\
            input_str, err_str, 'transport_labels_prefixes')

    def check_vtep_gateway_networks(self, input_str):
        """Check check_vtep_gateway_networks;
        These subnets should not intersect with setup_data
        NETWORK subnets sections"""

        err_str = "Entry syntax of a.b.c.d/e:f.g.h.i/j allowed, " \
            "where the subnets does not intersect with any in " \
            "the setup_data; Current input %s" % input_str

        self.check_gateway_network_consistency(\
            input_str, err_str, 'vtep_gateway_networks')

    def check_gateway_network_consistency(self, input_str, err_str, item_name):
        """General CHeck for gateway_network_consistency"""

        tmp = re.sub(" ", '', input_str)
        input_str = tmp
        if not re.search(",", input_str):
            raise Invalid(err_str)

        input_list = input_str.split(",")
        if len(input_list) != 2:
            raise Invalid(err_str)

        if input_list[0] == input_list[1]:
            raise Invalid(err_str)

        networks = ['NETWORKING', 'networks']
        networks_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(networks)
        pod_nets = [net['subnet'] for net in networks_info if 'subnet' in net]

        vmtp_subnet_list = self.cd_cfgmgr.fetch_vmtp_networks()
        if vmtp_subnet_list:
            pod_nets.extend(vmtp_subnet_list)

        nfvbench_entry = None
        if item_name == 'transport_labels_prefixes':
            nfvbench_entry = ['NFVBENCH', 'vtep_gateway_networks']
        elif item_name == 'vtep_gateway_networks':
            nfvbench_entry = ['NFVBENCH', 'transport_labels_prefixes']

        if nfvbench_entry is not None:
            nfvbench_entry_info = \
                self.ymlhelper.get_deepdata_from_userinput_file(nfvbench_entry)
            if nfvbench_entry_info is not None:
                new_subnets = nfvbench_entry_info.split(",")
                pod_nets.extend(new_subnets)

        # Check if 'Nfvbench vtep_gateway_networks conflicts with NETWORKING subnets
        same_subnet_list = []
        overlapping_subnet_list = []
        for net_val in pod_nets:
            for vtep_val in input_list:
                vtep_hosts = \
                    [host for host in ipaddress.IPv4Network(unicode(vtep_val))]
                if (vtep_hosts[0] or vtep_hosts[-1]) in \
                        ipaddress.IPv4Network(unicode(net_val)):
                    same_subnet_list.append(vtep_val)
                n1 = ipaddress.IPv4Network(unicode(net_val))
                n2 = ipaddress.IPv4Network(unicode(vtep_val))
                if n1.overlaps(n2) or n2.overlaps(n1):
                    tmp = "%s:overlaps:%s" % (n1, n2)
                    overlapping_subnet_list.append(tmp)

        err_list = []
        if overlapping_subnet_list:
            err_msg = "Entry of NFVBENCH:%s %s" \
                % (item_name, ','.join(overlapping_subnet_list))
            err_list.append(err_msg)

        if same_subnet_list:
            err_msg = "Entry of NFVBENCH:%s with value %s conflicts with subnets " \
                "in setup_data" % (item_name, ','.join(same_subnet_list))
            err_list.append(err_msg)

        if err_list:
            err_msg = ', '.join(err_list)
            raise Invalid(err_msg)

    def check_transport_labels(self, input_str):
        """check_transport_labels syntax"""

        err_str = "Entry has to be of type list of length 2, with unique " \
            "assembled transport label (base +  prefix_sid_index) " \
            "for the entire SR-MPLS domain; Current input is:%s" % input_str

        if not isinstance(input_str, list):
            raise Invalid(err_str)

        if len(input_str) != 2:
            raise Invalid(err_str)

        sr_block_schema = Schema({
            Required('base'): All(int, Range(min=16000, max=1048575)),
            Required('prefix_sid_index'): All(int, Range(min=0, max=7999)),
        })

        err_list = []
        transport_labels = []
        server_labels = []
        for item in input_str:
            try:
                sr_block_schema(item)
                curr_label = item.get('base') + item.get('prefix_sid_index')
                transport_labels.append(curr_label)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))

        servers = self.ymlhelper.get_data_from_userinput_file(['SERVERS'])
        computes = set(self.ymlhelper.get_server_list(role="compute"))

        for server in servers:
            if server in computes:
                if servers[server].get('sr_global_block', None) is not None:
                    label = servers[server]['sr_global_block']['base'] + \
                        servers[server]['sr_global_block']['prefix_sid_index']
                    server_labels.append(label)

        dup_label_list = \
            self.get_duplicate_entry_in_list(transport_labels)
        if dup_label_list:
            err_msg = "%s; Identical assembled transport label value" % err_str
            raise Invalid(err_msg)

        conflicting_label = set(server_labels).intersection(transport_labels)
        if conflicting_label:
            err_msg = 'NFVBENCH transport_labels %s (base +  prefix_sid_index)' \
                ' conflicts with that defined in SERVERS' % conflicting_label
            raise Invalid(err_msg)

    def nfvbench_check_list(self, input_str):
        """Validates the Syntax content of NFVBench; Also checks if Intel NIC
        is present in the mangement node.

        Here are some of working items for the validation works that
        needs to be done on management node to support NFVBench in management node.

        (1) Check if mgmt node has the right NIC card for Intel NIC:
        (2) Check if TOR has right configurations:
            In the case we have two TORs run in vPC, and physical connection
            will be from X710 ports to both TORs, one for each.

            In the case we have one TOR, then both ports will go to the same
            TOR.  The configuration needed on TORs should be the same
            regardless of one TOR or two TORs;

            The sample configurations on two ports are just regular VLAN trunk
            port, and it is symmetric if on two TORs. In the case of VLAN
            deployments (ML2/VPP, OVS/VLAN, LB/VLAN), the allowed vlan range
            should be the exact the range of TENANT_VLAN_RANGES in
            setup_data.yaml. In the case of VTS deployments, the allowed vlan
            ranges can be any two random VLANs as we are doing VLAN->VxLAN
            encapsulation in N9K TORs anyway.
        """

        nfvbench_schema_tor = Schema({
            Required('enabled'): All(Boolean(str), msg="Only Boolean value \
                                     True/False allowed; default is False"),
            Required('tor_info'): self.check_nfvbench_tor_info,
            Optional('nic_slot'): self.check_nfvbench_nic_slot,
            Optional('nic_ports'): self.check_nfvbench_nic_port,
        })

        nfvbench_schema_tor_opt = Schema({
            Required('enabled'): All(Boolean(str), msg="Only Boolean value \
                                     True/False allowed; default is False"),
            Optional('tor_info'): self.check_nfvbench_tor_info,
            Optional('nic_slot'): self.check_nfvbench_nic_slot,
            Optional('nic_ports'): self.check_nfvbench_nic_port,
        })

        nfvbench_schema_vts_tor = Schema({
            Required('enabled'): All(Boolean(str), msg="Only Boolean value \
                                     True/False allowed; default is False"),
            Required('tor_info'): self.check_nfvbench_tor_info,
            Required('vteps'): self.check_vts_vtep_ip_nfvbench_info,
            Optional('nic_slot'): self.check_nfvbench_nic_slot,
            Optional('nic_ports'): self.check_nfvbench_nic_port,
        })

        nfvbench_schema_vts_tor_opt = Schema({
            Required('enabled'): All(Boolean(str), msg="Only Boolean value \
                                     True/False allowed; default is False"),
            Optional('tor_info'): self.check_nfvbench_tor_info,
            Required('vteps'): self.check_vts_vtep_ip_nfvbench_info,
            Optional('nic_slot'): self.check_nfvbench_nic_slot,
            Optional('nic_ports'): self.check_nfvbench_nic_port,
        })

        nfvbench_schema_vxlan_tor = Schema({
            Required('enabled'): All(Boolean(str), msg="Only Boolean value \
                                     True/False allowed; default is False"),
            Required('tor_info'): self.check_nfvbench_tor_info,
            Required('vtep_vlans'): self.check_nfvbench_vlan_range,
            Optional('nic_slot'): self.check_nfvbench_nic_slot,
            Optional('nic_ports'): self.check_nfvbench_nic_port,
        })

        nfvbench_schema_vxlan_tor_opt = Schema({
            Required('enabled'): All(Boolean(str), msg="Only Boolean value \
                                     True/False allowed; default is False"),
            Optional('tor_info'): self.check_nfvbench_tor_info,
            Optional('vtep_vlans'): self.check_nfvbench_vlan_range,
            Optional('nic_slot'): self.check_nfvbench_nic_slot,
            Optional('nic_ports'): self.check_nfvbench_nic_port,
        })

        nfvbench_tenant_vxlan_schema_tor = Schema({
            Required('enabled'): All(Boolean(str), msg="Only Boolean value \
                                     True/False allowed; default is False"),
            Required('tor_info'): self.check_nfvbench_tor_info,
            Optional('nic_slot'): self.check_nfvbench_nic_slot,
            Optional('nic_ports'): self.check_nfvbench_nic_port,
            Optional('vteps'): self.check_vtep_ip_nfvbench_info,
            Optional('vnis'): self.check_vni_nfvbench_info,
        })

        nfvbench_sr_mpls_tor_opt_schema = nfvbench_schema_tor_opt.extend({
            Required('vtep_gateway_networks'): self.check_vtep_gateway_networks,
            Required('vpn_labels'): self.check_vpn_labels,
            Required('transport_labels'): self.check_transport_labels,
            Required('transport_labels_prefixes'):
                self.check_transport_labels_prefixes,
        })

        nfvbench_sr_mpls_tor_schema = nfvbench_schema_tor.extend({
            Required('vtep_gateway_networks'): self.check_vtep_gateway_networks,
            Required('vpn_labels'): self.check_vpn_labels,
            Required('transport_labels'): self.check_transport_labels,
            Required('transport_labels_prefixes'):
                self.check_transport_labels_prefixes,
        })

        err_list = []

        # Get the management network type
        curr_mgmt_network = self.ymlhelper.get_management_network_type()
        if curr_mgmt_network == 'layer3' and \
                self.cd_cfgmgr.check_nfvbench_presence():
            err_str = "NFVbench is not supported in layer3 " \
                "deployment environments"
            raise Invalid(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        network_type = self.get_network_type()

        if network_type is None:
            err_str = "Undefined TENANT_NETWORK_TYPE"
            raise Invalid(err_str)
        elif re.match(r'linuxbridge', mechanism_driver) and \
                network_type == 'VXLAN':
            err_str = "NFVbench not supported for LB/VXLAN"
            raise Invalid(err_str)

        try:
            if self.cd_cfgmgr.is_network_option_enabled('sr-mpls-tenant'):
                if self.is_tor_config_enabled():
                    nfvbench_sr_mpls_tor_schema(input_str)
                else:
                    nfvbench_sr_mpls_tor_opt_schema(input_str)

            elif re.match(r'vts', mechanism_driver):
                if self.is_tor_config_enabled():
                    nfvbench_schema_vts_tor(input_str)
                else:
                    nfvbench_schema_vts_tor_opt(input_str)

            elif network_type == 'VXLAN':
                if self.is_tor_config_enabled() or self.is_tor_type_ncs5500():
                    nfvbench_schema_vxlan_tor(input_str)
                else:
                    nfvbench_schema_vxlan_tor_opt(input_str)

            elif self.is_network_segment_defined():
                nfvbench_tenant_vxlan_schema_tor(input_str)

            elif self.is_tor_config_enabled() or self.is_tor_type_ncs5500():
                nfvbench_schema_tor(input_str)
            else:
                nfvbench_schema_tor_opt(input_str)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        if not self.check_no_vts_presence():
            vts = self.ymlhelper.get_data_from_userinput_file(['VTS_PARAMETERS'])
            vtc_username = vts.get('VTC_SSH_USERNAME')
            vtc_password = vts.get('VTC_SSH_PASSWORD')

            if vtc_username is None:
                err_str = "VTC_SSH_USERNAME is required for nfvbench;"
                err_list.append(err_str)
            if vtc_password is None:
                err_str = "VTC_SSH_PASSWORD is required for nfvbench;"
                err_list.append(err_str)

        if err_list:
            err_str = ' '.join(err_list)
            raise Invalid(err_str)

        # check if Intel NIC is there on the management node
        if curr_mgmt_network == 'layer3':
            pass
        else:
            bom_check = common_utils.is_bom_valid_for_nfvbench()
            if re.search(r'ERROR', bom_check):
                raise Invalid(bom_check)

        return

    def check_nfvbench_vlan_range(self, input_str):
        '''Checks VLAN range syntax, expects the syntax to be of
        type vlan1,vlan2 and is of length 2'''

        err_msg = "Correct format: vlan_id1,vlan_id2; with end_vlan " \
                  "not equal to start_vlan by 1; with range from 2 and 4094; " + \
                  "current Input: " + str(input_str)

        if input_str is None:
            raise Invalid(err_msg)

        if not re.match(r'[0-9]+,[0-9]+|[0-9]+:[0-9]+', input_str):
            raise Invalid(err_msg)

        str_token_type = ""
        if re.search(r':', input_str):
            vlan_ranges = str(input_str).split(":")
            str_token_type = ":"
        else:
            vlan_ranges = str(input_str).split(",")

        if vlan_ranges:
            for ind_vlan_entry in vlan_ranges:
                if not self.is_input_an_integer(ind_vlan_entry):
                    raise Invalid(err_msg)
                elif not self.is_input_range_valid(int(ind_vlan_entry), 2, 4094):
                    raise Invalid(err_msg)

        if len(vlan_ranges) != 2:
            raise Invalid(err_msg)

        if vlan_ranges[0] == vlan_ranges[1]:
            raise Invalid(err_msg)

        if re.search(r':', str_token_type):
            if vlan_ranges[0] > vlan_ranges[1]:
                raise Invalid(err_msg)
            elif (int(vlan_ranges[1]) - int(vlan_ranges[0])) != 1:
                raise Invalid(err_msg)

        tmp = []
        for item in vlan_ranges:
            tmp.append(int(item))

        if 'NFVBENCH' not in self.global_vlan_info.keys():
            self.global_vlan_info['NFVBENCH'] = tmp

        return

    def check_nfvbench_nic_slot(self, input_str):
        '''Checks NIC slot syntax, expects one single integer'''

        if not isinstance(input_str, int):
            err_str = "Non-Integer Input not allowed"
            raise Invalid(err_str)

        err_str = "Entry value of 1 to 6 allowed, " \
            "found to be %s" % (input_str)
        if input_str == 0:
            raise Invalid(err_str)
        elif input_str > 6:
            raise Invalid(err_str)

        nfvbench_info = \
            self.ymlhelper.get_data_from_userinput_file(['NFVBENCH'])
        nic_port_info = nfvbench_info.get('nic_ports')
        if nic_port_info is None:
            err_str = "nic_ports need to be defined "
            raise Invalid(err_str)

        return

    def check_nfvbench_nic_port(self, input_str):
        '''Checks NIC ports syntax, expects the syntax to be of
        type 1,2 and the range is 1-4'''

        err_msg = "Correct format: port_info1,port_info2; with unique " \
                  "ports ranging from 1 and 4, input_str:" + str(input_str)

        if input_str is None:
            raise Invalid(err_msg)

        nfvbench_info = \
            self.ymlhelper.get_data_from_userinput_file(['NFVBENCH'])
        nic_slot_info = nfvbench_info.get('nic_slot')
        if nic_slot_info is None:
            err_str = "nic_slot needs to be defined "
            raise Invalid(err_str)

        if not re.match(r'[1-4],[1-4]', input_str):
            raise Invalid(err_msg)

        if not re.search(r',', input_str):
            raise Invalid(err_msg)
        else:
            port_ranges = str(input_str).split(",")

        if port_ranges:
            for ind_entry in port_ranges:
                if not self.is_input_an_integer(ind_entry):
                    raise Invalid(err_msg)
                elif not self.is_input_range_valid(int(ind_entry), 1, 4):
                    raise Invalid(err_msg)

        if len(port_ranges) != 2:
            raise Invalid(err_msg)

        if port_ranges[0] == port_ranges[1]:
            raise Invalid(err_msg)

        return

    def podtype_check_list(self, input_str):
        '''Check for micropod options'''

        # Make sure its a string
        self.is_input_in_plain_str(input_str)
        expected_values = ['micro', 'fullon', 'UMHC',
                           'NGENAHC', 'edge', 'ceph', 'nano']

        if input_str not in expected_values:
            err_str = "Only value of %s allowed" \
                % ','.join(expected_values)
            raise Invalid(err_str)

        if re.match(r'fullon', input_str):
            return

        if re.match(r'UCSM', self.testbed_type):
            err_str = "Micropod/UMHC/NGENAHC is only supported " \
                "with C-series testbed"
            raise Invalid(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        network_type = self.get_network_type()

        if self.ymlhelper.get_pod_type() == 'ceph' and mechanism_driver is not None:
            err_str = "Mechanism driver not allowed for podtype ceph"
            raise Invalid(err_str)
        elif self.ymlhelper.get_pod_type() == 'ceph' and network_type is not None:
            err_str = "TENANT_NETWORK_TYPE not allowed for podtype ceph"
            raise Invalid(err_str)
        elif self.ymlhelper.get_pod_type() == 'ceph':
            return

        err_str_net = "Undefined TENANT_NETWORK_TYPE; "
        if network_type is None:
            raise Invalid(err_str_net)

        if mechanism_driver is None:
            err_str1 = "Undefined MECHANISM_DRIVER; "
            raise Invalid(err_str1)

        if input_str == 'NGENAHC' \
                and (network_type != 'VLAN' or mechanism_driver != 'vpp'):
            err_str = "Only VPP/VLAN supported with NGENAHC"
            raise Invalid(err_str)

        if (input_str == 'edge' or input_str == 'UMHC' or input_str == 'nano'):
            if network_type != 'VLAN' and mechanism_driver != 'openvswitch':
                err_str = "Only openvswitch/VLAN is supported with PODTYPE of %s" \
                    % (input_str)
                raise Invalid(err_str)

        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])
        vic_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_INTEL_SRIOV'])

        if re.match(r'UMHC', input_str) and not (vic_nic_check or intel_nic_check):
            err_str1 = "UMHC option currently supported with Intel NIC only"
            raise Invalid(err_str1)

        if re.match(r'NGENAHC', input_str) and vic_nic_check:
            err_str1 = "NGENAHC option not supported " \
                "with CISCO_VIC_INTEL_SRIOV"
            raise Invalid(err_str1)

        if re.match(r'NGENAHC', input_str) and intel_nic_check:
            err_str1 = "NGENAHC option not " \
                "supported with INTEL_NIC_SUPPORT"
            raise Invalid(err_str1)

        return

    def check_ccp_tenant_image_presence(self, input_str):
        """Check tenant Image syntax and location"""

        self.check_qcow2_path_presence(input_str)

        filename = os.path.basename(input_str)
        if not re.search('ccp-tenant-image.*qcow2', filename):
            msg = "Image of format qcow2 with prefix " \
                "ccp-tenant-image in image name not found; " \
                "current image name is %s" % (filename)
            raise Invalid(msg)

        return

    def check_ccp_installer_image_presence(self, input_str):
        """Check installer Image syntax and location"""

        self.check_qcow2_path_presence(input_str)

        filename = os.path.basename(input_str)
        if not re.search('kcp-vm.*qcow2', filename):
            msg = "Image of format qcow2 with prefix " \
                "kcp-vm in image name not found, " \
                "current image name is %s" % (filename)
            raise Invalid(msg)

        return

    def check_qcow2_path_presence(self, input_str):
        '''Check for valid QCOW2 file path'''

        suffix = ".qcow2"
        msg = "Image of format qcow2 not found in %s" % input_str
        if not os.path.isfile(input_str):
            raise Invalid(msg)
        elif not input_str.endswith(suffix):
            raise Invalid(msg)

        return

    def check_file_presence(self, input_str):
        '''Check for valid QCOW2 file path'''

        msg = "File %s not found" % (input_str)
        if not os.path.isfile(input_str):
            raise Invalid(msg)

        return

    def check_version_syntax(self, input_str):
        '''Check Version is of syntax a.b.c'''

        err_str = "Expected input of type [d].[d].[d]"
        self.is_input_in_plain_str_len32(input_str)

        if not re.search("[0-9]+.[0-9]+.[0-9]+", input_str):
            raise Invalid(err_str)

        return

    def check_flavor_input(self, input_str):
        """Check the flavor details"""

        self.is_input_in_plain_str(input_str)

        int_lb_info = self.ymlhelper.get_data_from_userinput_file(\
            ['internal_lb_vip_ipv6_address'])
        via_v6 = 1
        if int_lb_info is None:
            int_lb_info = self.ymlhelper.get_data_from_userinput_file(\
                ['internal_lb_vip_address'])
            via_v6 = 0
        flavor_check = common_utils.execute_openstack_command(\
            'openstack', 'flavor list', input_str, int_lb_info, via_v6, \
            return_raw_output=0, fetch_exact_match=1)

        if re.search('ERROR', flavor_check):
            raise Invalid(flavor_check)

        per_flavor_cmd = "flavor show %s" % (input_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        huge_page_status = \
            self.ymlhelper.get_data_from_userinput_file(["VM_HUGEPAGE_PERCENTAGE"])

        if mechanism_driver == "vpp" or \
                huge_page_status is not None:
            flavor_pattern = "hw:mem_page_size"
        else:
            flavor_pattern = input_str

        flavor_detail_info = \
            common_utils.execute_openstack_command('openstack',
                                                   per_flavor_cmd,
                                                   flavor_pattern,
                                                   int_lb_info,
                                                   via_v6)

        if re.search('ERROR', flavor_detail_info):
            err_msg = "Huge Page association to flavor " \
                "%s is required" % input_str
            raise Invalid(err_msg)

        return

    def check_network_uuid_input(self, input_str):
        """Check the PUBLIC_NETWORK_UUID details"""

        self.is_input_in_plain_str(input_str)

        pod_cidr = ['CCP_DEPLOYMENT', 'POD_CIDR']
        pod_cidr_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(pod_cidr)

        exp_network_type = 4
        if pod_cidr_info is not None and re.search(r':', pod_cidr_info):
            exp_network_type = 6

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        if mechanism_driver == 'vpp' and exp_network_type == 6:
            err_msg = "ERROR: Mechanism driver of vpp is not supported " \
                "with CCP over IPv6"
            raise Invalid(err_msg)

        int_v6_lb_info = self.ymlhelper.get_data_from_userinput_file(\
            ['internal_lb_vip_ipv6_address'])
        via_v6 = 1
        int_lb_info = int_v6_lb_info
        if int_v6_lb_info is None:
            int_lb_info = self.ymlhelper.get_data_from_userinput_file(\
                ['internal_lb_vip_address'])
            via_v6 = 0

        ext_lb_fqdn_info = self.ymlhelper.get_data_from_userinput_file(\
            ['external_lb_vip_fqdn'])

        if via_v6 and exp_network_type != 6 and ext_lb_fqdn_info is None:
            err_msg = "CCP over v4 network is supported in a " \
                "dual stack environment when external_lb_vip_fqdn is enabled"
            raise Invalid(err_msg)

        flavor_check = common_utils.execute_openstack_command(\
            'openstack', 'network list', input_str, int_lb_info, via_v6, \
            return_raw_output=0, fetch_exact_match=1)

        if re.search('ERROR', flavor_check):
            raise Invalid(flavor_check)

        if self.curr_ccp_network_type == 'tenant':
            exp_network_type = 4

        msg, network_type_check = \
            common_utils.check_os_network_type(\
                input_str, int_lb_info, via_v6, exp_network_type)
        if not network_type_check:
            err_msg = "ERROR: %s Cannot get network type for %s" \
                % (msg, input_str)
            raise Invalid(err_msg)
        elif network_type_check == 1:
            pass
        elif int(exp_network_type) != int(network_type_check):
            if pod_cidr_info is not None:
                err_msg = "ERROR: Network type check for %s Failed for " \
                    "POD_CIDR of %s with UUID %s: Expected: ipv%s, " \
                    "Found: ipv%s" % (self.curr_ccp_network_type, \
                    pod_cidr_info, input_str, exp_network_type, \
                    network_type_check)

            else:
                err_msg = "ERROR: Network type check for %s Failed with " \
                    "UUID %s: Expected: ipv%s, Found: ipv%s" \
                    % (self.curr_ccp_network_type, input_str, \
                       exp_network_type, network_type_check)
            raise Invalid(err_msg)

        return

    def check_pod_cidr_validity(self, input_str):
        """Check POD CIDR validity"""

        v6_check = 0
        if re.search(':', input_str):
            v6_check = 1
            self.validate_v6_cidr_syntax(input_str)
        else:
            self.validate_cidr_syntax(input_str)

        dns_server_info = ['CCP_DEPLOYMENT', 'DNS_SERVER']
        dns_server_list = \
            self.ymlhelper.get_deepdata_from_userinput_file(dns_server_info)

        invalid_dns_list = []
        if dns_server_list:
            for item in dns_server_list:
                if v6_check and not common_utils.is_valid_ipv6_address(item):
                    invalid_dns_list.append(item)

        if invalid_dns_list:
            err_msg = "DNS server entry is of type v4 when the " \
                "POD CIDR is of type v6"
            raise Invalid(err_msg)

        int_lb_info = self.ymlhelper.get_data_from_userinput_file(\
            ['internal_lb_vip_ipv6_address'])

        if v6_check and int_lb_info is None:
            err_msg = "POD CIDR is of type v6, when the pod is V4 based"
            raise Invalid(err_msg)

        esc_info = \
            self.ymlhelper.get_data_from_userinput_file(['ENABLE_ESC_PRIV'])

        if v6_check:
            if esc_info is None or (esc_info is not None and not esc_info):
                err_msg = "ENABLE_ESC_PRIV entry of true is required when " \
                    "POD CIDR is of type v6"
                raise Invalid(err_msg)

        return

    def check_ccp_deployment(self, input_str):
        """Enable CCP deployment"""

        ccp_control_tenant_schema = Schema({
            Required('UI_PASSWORD'): self.check_password_syntax,
            Required('password'): self.check_password_syntax,
            Required('private_key'): self.check_file_presence,
            Required('project_name'): self.is_input_in_plain_str_len32,
            Required('public_key'): self.check_file_presence,
            Required('username'): self.is_input_in_plain_str_len32,
            Required('ccp_subnet_cidr'): self.validate_cidr_syntax,
            Required('installer_subnet_cidr'): self.validate_cidr_syntax,
            Required('installer_subnet_gw'): self.is_ip_syntax_valid,
        })

        ccp_control_provider_schema = Schema({
            Required('UI_PASSWORD'): self.check_password_syntax,
            Required('password'): self.check_password_syntax,
            Required('private_key'): self.check_file_presence,
            Required('project_name'): self.is_input_in_plain_str_len32,
            Required('public_key'): self.check_file_presence,
            Required('username'): self.is_input_in_plain_str_len32,
        })

        ccp_tenant_schema = Schema({
            Required('password'): self.check_password_syntax,
            Required('project_name'): self.is_input_in_plain_str_len32,
            Required('username'): self.is_input_in_plain_str_len32,
            Required('workers'): All(int, Range(min=1)),
            Required('subnet_cidr'): self.validate_cidr_syntax,
        })

        ccp_tenant_with_provider_schema = Schema({
            Required('password'): self.check_password_syntax,
            Required('project_name'): self.is_input_in_plain_str_len32,
            Required('username'): self.is_input_in_plain_str_len32,
            Required('workers'): All(int, Range(min=1)),
        })

        ccp_pre_install_schema_with_tenant = Schema({
            Required('CCP_CONTROL'): ccp_control_tenant_schema,
            Required('CCP_INSTALLER_IMAGE'): self.check_ccp_installer_image_presence,
            Optional('CCP_TENANT'): ccp_tenant_schema,
            Required('CCP_TENANT_IMAGE'): self.check_ccp_tenant_image_presence,
            Required('DNS_SERVER'): self.vaidate_dns_server_list,
            Required('KUBE_VERSION'): self.check_version_syntax,
            Required('NETWORK_TYPE'): In(frozenset(["tenant", "provider"])),
            Optional('POD_CIDR'): self.check_pod_cidr_validity,
            Optional('PUBLIC_NETWORK_UUID'): self.is_input_in_plain_str,
            Optional('CCP_FLAVOR'): self.is_input_in_plain_str,
        })

        ccp_pre_install_schema_with_provider = Schema({
            Required('CCP_CONTROL'): ccp_control_provider_schema,
            Required('CCP_INSTALLER_IMAGE'): self.check_ccp_installer_image_presence,
            Optional('CCP_TENANT'): ccp_tenant_with_provider_schema,
            Required('CCP_TENANT_IMAGE'): self.check_ccp_tenant_image_presence,
            Required('DNS_SERVER'): self.vaidate_dns_server_list,
            Required('KUBE_VERSION'): self.check_version_syntax,
            Required('NETWORK_TYPE'): In(frozenset(["tenant", "provider"])),
            Optional('POD_CIDR'): self.check_pod_cidr_validity,
            Optional('PUBLIC_NETWORK_UUID'): self.is_input_in_plain_str,
            Optional('CCP_FLAVOR'): self.is_input_in_plain_str,
        })

        ccp_install_schema_with_tenant = Schema({
            Required('CCP_CONTROL'): ccp_control_tenant_schema,
            Required('CCP_INSTALLER_IMAGE'): self.check_ccp_installer_image_presence,
            Optional('CCP_TENANT'): ccp_tenant_schema,
            Required('CCP_TENANT_IMAGE'): self.check_ccp_tenant_image_presence,
            Required('DNS_SERVER'): self.vaidate_dns_server_list,
            Required('KUBE_VERSION'): self.check_version_syntax,
            Required('NETWORK_TYPE'): In(frozenset(["tenant", "provider"])),
            Optional('POD_CIDR'): self.check_pod_cidr_validity,
            Required('PUBLIC_NETWORK_UUID'): self.check_network_uuid_input,
            Optional('CCP_FLAVOR'): self.check_flavor_input,
        })

        ccp_install_schema_with_provider = Schema({
            Required('CCP_CONTROL'): ccp_control_provider_schema,
            Required('CCP_INSTALLER_IMAGE'): self.check_ccp_installer_image_presence,
            Optional('CCP_TENANT'): ccp_tenant_with_provider_schema,
            Required('CCP_TENANT_IMAGE'): self.check_ccp_tenant_image_presence,
            Required('DNS_SERVER'): self.vaidate_dns_server_list,
            Required('KUBE_VERSION'): self.check_version_syntax,
            Required('NETWORK_TYPE'): In(frozenset(["tenant", "provider"])),
            Optional('POD_CIDR'): self.check_pod_cidr_validity,
            Required('PUBLIC_NETWORK_UUID'): self.check_network_uuid_input,
            Optional('CCP_FLAVOR'): self.check_flavor_input,
        })

        ccp_install_vpp_schema_with_tenant = Schema({
            Required('CCP_CONTROL'): ccp_control_tenant_schema,
            Required('CCP_INSTALLER_IMAGE'): self.check_ccp_installer_image_presence,
            Optional('CCP_TENANT'): ccp_tenant_schema,
            Required('CCP_TENANT_IMAGE'): self.check_ccp_tenant_image_presence,
            Required('DNS_SERVER'): self.vaidate_dns_server_list,
            Required('KUBE_VERSION'): self.check_version_syntax,
            Required('NETWORK_TYPE'): In(frozenset(["tenant", "provider"])),
            Optional('POD_CIDR'): self.check_pod_cidr_validity,
            Required('PUBLIC_NETWORK_UUID'): self.check_network_uuid_input,
            Required('CCP_FLAVOR'): self.check_flavor_input,
        })

        ccp_install_vpp_schema_with_provider = Schema({
            Required('CCP_CONTROL'): ccp_control_provider_schema,
            Required('CCP_INSTALLER_IMAGE'): self.check_ccp_installer_image_presence,
            Optional('CCP_TENANT'): ccp_tenant_with_provider_schema,
            Required('CCP_TENANT_IMAGE'): self.check_ccp_tenant_image_presence,
            Required('DNS_SERVER'): self.vaidate_dns_server_list,
            Required('KUBE_VERSION'): self.check_version_syntax,
            Required('NETWORK_TYPE'): In(frozenset(["tenant", "provider"])),
            Optional('POD_CIDR'): self.check_pod_cidr_validity,
            Required('PUBLIC_NETWORK_UUID'): self.check_network_uuid_input,
            Required('CCP_FLAVOR'): self.check_flavor_input,
        })

        err_list = []

        ccp_network_type = ['CCP_DEPLOYMENT', 'NETWORK_TYPE']

        ccp_network_type_chk = \
            self.ymlhelper.get_deepdata_from_userinput_file(ccp_network_type)

        err_msg = "NETWORK_TYPE information has to be tenant or provider " \
                  " in CCP_DEPLOYMENT section"
        if ccp_network_type_chk is None:
            raise Invalid(err_msg)
        elif ccp_network_type_chk != 'tenant' and \
                ccp_network_type_chk != 'provider':
            raise Invalid(err_msg)

        is_tls_enabled = self.ymlhelper.get_data_from_userinput_file(\
            ['external_lb_vip_tls'])

        if is_tls_enabled is None or is_tls_enabled is False:
            err_str = "External TLS has to be enabled for CCP"
            err_list.append(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        huge_page_status = \
            self.ymlhelper.get_data_from_userinput_file(["VM_HUGEPAGE_PERCENTAGE"])

        missing_pod_cidr = 0
        int_lb_info = self.ymlhelper.get_data_from_userinput_file(\
            ['internal_lb_vip_ipv6_address'])

        pod_cidr_info = ['CCP_DEPLOYMENT', 'POD_CIDR']
        pod_cidr_check = \
            self.ymlhelper.get_deepdata_from_userinput_file(pod_cidr_info)

        self.curr_ccp_network_type = ccp_network_type_chk

        try:
            if ccp_network_type_chk == 'tenant':
                if self.ccp_check:
                    if mechanism_driver == "vpp" or \
                            huge_page_status is not None:
                        ccp_install_vpp_schema_with_tenant(input_str)
                    else:
                        ccp_install_schema_with_tenant(input_str)
                else:
                    ccp_pre_install_schema_with_tenant(input_str)
            else:
                if self.ccp_check:
                    if mechanism_driver == "vpp" or \
                            huge_page_status is not None:
                        ccp_install_vpp_schema_with_provider(input_str)
                    else:
                        ccp_install_schema_with_provider(input_str)

                    if int_lb_info is not None and pod_cidr_check is None:
                        missing_pod_cidr = 1

                else:
                    ccp_pre_install_schema_with_provider(input_str)

        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        if missing_pod_cidr:
            err_msg = "POD_CIDR info is needed for CCP over IPv6"
            err_list.append(err_msg)

        if not self.check_for_optional_enabled('lbaas'):
            err_msg = "CCP can only be enabled with lbaas as OPTIONAL_SERVICE_LIST"
            err_list.append(err_msg)

        if mechanism_driver != 'openvswitch' and mechanism_driver != 'vpp':
            err_msg = "CCP can only be enabled with mechanism driver OVS or vpp"
            err_list.append(err_msg)

        if err_list:
            err_str = ', '.join(err_list)
            raise Invalid(err_str)

        return

    def is_network_segment_defined(self, \
                                   segment_name='vxlan-tenant'):
        '''check if target segment is defined'''

        found_network_segment = 0
        networking_info = \
            self.ymlhelper.get_data_from_userinput_file(['NETWORKING'])
        if networking_info is not None:
            network_info = networking_info.get('networks')
            if network_info is not None:
                for item in network_info:
                    if item is None:
                        continue
                    elif 'segments' in item.keys():
                        if segment_name in item['segments']:
                            found_network_segment = 1
                            break

        return found_network_segment

    def check_sr_mpls_bgp_peer_ip_list(self, input_str):
        '''Check for bgp_peer_ip_list'''

        if not isinstance(input_str, list):
            err_str = "entry has to be of type list"
            raise Invalid(err_str)
        elif len(input_str) != 1:
            err_str = "Entry needs to be a list of min of 1 IP"
            raise Invalid(err_str)

        self.check_bgp_peer_ip_list(input_str)
        return

    def check_bgp_peer_ip_list(self, input_str):
        '''Check for bgp_peer_ip_list'''

        if not isinstance(input_str, list):
            err_str = "entry has to be of type list"
            raise Invalid(err_str)
        elif not input_str:
            err_str = "Entry needs to be a list of min of 1 IP"
            raise Invalid(err_str)

        for item in input_str:
            self.is_ipv4_or_v6_syntax_valid(item)
            self.global_admin_ip_list.append(item)
            self.global_mgmt_ip_list.append(item)

        return

    def check_bgp_router_id(self, input_str):
        '''Check for bgp_router_id'''

        self.is_ip_valid(input_str)
        self.global_admin_ip_list.append(input_str)
        self.global_mgmt_ip_list.append(input_str)

        return

    def check_bgp_asn_syntax(self, input_str):
        '''Check bgp_asn input'''

        if not isinstance(input_str, int):
            err_str = "Only input of type integer is allowed, " \
                "in the range of 1-4294967295 (including 1 and 4294967295), " \
                "current input is %s" % (input_str)
            raise Invalid(err_str)
        elif input_str >= 1 and input_str <= 4294967295:
            pass
        else:
            err_str = "Allowed bgp_as_num range 1-4294967295; " \
                "Found: %s" % (input_str)
            raise Invalid(err_str)

        self.global_bgp_asn_num.append(input_str)

        return

    def check_physnet_name_syntax(self, input_str):
        '''Check bgp_asn input'''

        if not isinstance(input_str, str):
            err_str = "Only input of type string is allowed, " \
                "for the physnet_name. Current input is: %s" \
                % (input_str)
            raise Invalid(err_str)

        self.global_physnet_name.append(input_str)

        return

    def is_head_end_rep_defined(self, option_value):
        '''check if is_head_end_rep defined'''

        if not self.cd_cfgmgr.is_network_option_enabled(option_value):
            return 0

        ntwrk_opt_info = \
            self.ymlhelper.get_data_from_userinput_file(\
                ['NETWORK_OPTIONS'])
        vxlan_option = ntwrk_opt_info['vxlan'].get(option_value)

        her_info = vxlan_option.get('head_end_replication')

        if her_info is None:
            return 0
        else:
            return 1

    def check_head_end_replication(self, input_str):
        '''Check head_end_replication syntax'''

        vtep_key_list = []
        if not isinstance(input_str, dict):
            err_str = "Entry needs to be of type dict"
            raise Invalid(err_str)

        for vtep, value in input_str.iteritems():
            self.is_ip_syntax_valid(vtep)
            vtep_key_list.append(vtep)
            vni_id_list = self.fetch_vlan_boundaries(value)
            dup_vniid_list = \
                self.get_duplicate_entry_in_list(vni_id_list)
            if dup_vniid_list:
                err_msg = "Duplicate VNI id %s found under VTEP:%s " \
                    % (','.join(dup_vniid_list), vtep)
                raise Invalid(err_msg)

            expanded_vni_id = common_utils.expand_vlan_range(value)
            dup_vniid_s = \
                set([x for x in expanded_vni_id if expanded_vni_id.count(x) > 1])
            if dup_vniid_s:
                dup_vniid_str = \
                    list(dup_vniid_s).__str__().replace('[', '').replace(']', '')

                err_msg = "Overlapping VNI id %s found under VTEP:%s " \
                    % (dup_vniid_str, vtep)
                raise Invalid(err_msg)

            for item in vni_id_list:
                if int(item) < 1 or int(item) > 16777215:
                    err_msg = "Incorrect input of VNI id %s found under VTEP:%s " \
                        "needs to be between 1 and 2^24-1" \
                        % (item, vtep)
                    raise Invalid(err_msg)

        return

    def check_ecmp_private_pool_syntax(self, input_str):
        '''Check ecmp private pool syntax'''

        enable_ecmp_info = ['NETWORK_OPTIONS', 'enable_ecmp']

        enable_ecmp_check = \
            self.ymlhelper.get_deepdata_from_userinput_file(enable_ecmp_info)

        if enable_ecmp_check is None or \
                (enable_ecmp_check is not None and enable_ecmp_check is False):
            err_msg = "ecmp_private_pool information can only be present" \
                " when enable_ecmp is True under NETWORK_OPTIONS"
            raise Invalid(err_msg)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        if mechanism_driver != 'vpp':
            err_msg = "Option allowed with vpp only"
            raise Invalid(err_msg)

        self.validate_cidr_syntax(input_str)

        return

    def network_options_list(self, input_str):
        '''check for network_options_list'''

        vxlan_network_option_schema = Schema({
            Required('physnet_name'): self.check_physnet_name_syntax,
            Required('bgp_as_num'): self.check_bgp_asn_syntax,
            Required('bgp_peers'): self.check_bgp_peer_ip_list,
            Required('bgp_router_id'): self.check_bgp_router_id,
            Optional('head_end_replication'): self.check_head_end_replication,
        })

        sr_mpls_tenant_schema = Schema({
            Required('physnet_name'): self.check_physnet_name_syntax,
            Required('bgp_as_num'): self.check_bgp_asn_syntax,
            Required('bgp_peers'): self.check_sr_mpls_bgp_peer_ip_list,
            Required('bgp_router_id'): self.check_bgp_router_id,
        })

        sr_mpls_schema = Schema({
            Optional('physnet_name'): self.check_physnet_name_syntax,
            Optional('enable_ecmp'): All(Boolean(str), \
                msg="Only true or false allowed; " \
                "default is false"),
            Optional('ecmp_private_pool'): self.check_ecmp_private_pool_syntax,
            Required('sr-mpls'): All(dict),
        })

        if input_str is None:
            err_str = "Need to have at least 1 entry"
            raise Invalid(err_str)

        if not isinstance(input_str, dict):
            err_str = "Entry needs to be of type dict"
            raise Invalid(err_str)

        if not input_str:
            err_str = "Entry needs to have some input"
            raise Invalid(err_str)

        expected_keys = ['vxlan', 'l3vpn', 'sr-mpls']
        expected_vxlan_keys = ['vxlan-tenant', 'vxlan-ecn']
        expected_sr_mpls_keys = ['enable_ecmp', 'ecmp_private_pool', 'physnet_name']
        expected_sr_mpls_sub_keys = ['sr-mpls-tenant']
        found_vxlan_ecn = 0
        found_vxlan_tenant = 0
        found_sr_mpls = 0
        found_vxlan = 0

        invalid_key_list = []
        invalid_vxlan_key_list = []
        invalid_srmpls_sub_key_list = []

        if self.cd_cfgmgr.is_network_option_enabled('sr-mpls-tenant'):
            try:
                sr_mpls_schema(input_str)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        for key, value in input_str.iteritems():
            if self.cd_cfgmgr.is_network_option_enabled('sr-mpls-tenant') and \
                    key in expected_sr_mpls_keys:
                continue
            elif key not in expected_keys:
                invalid_key_list.append(key)
            elif key == 'vxlan' or key == 'sr-mpls':
                for key1, value1 in value.iteritems():
                    if key == 'vxlan' and key1 not in expected_vxlan_keys:
                        invalid_vxlan_key_list.append(key1)
                    elif key == 'sr-mpls' and key1 not in expected_sr_mpls_sub_keys:
                        invalid_srmpls_sub_key_list.append(key1)
                    elif not isinstance(value, dict):
                        err_str = "Entry needs to be of type dict"
                        raise Invalid(err_str)
                    else:
                        try:
                            if re.search(r'vxlan-tenant|vxlan-ecn', key1):
                                found_vxlan = 1
                                vxlan_network_option_schema(value1)
                                if not self.is_network_segment_defined(key1):
                                    err_str = "data[\'NETWORKING\'][\'networks\']\
                                        [\'%s\'] segment not defined" % (key1)
                                    raise Invalid(err_str)
                                if key1 == 'vxlan-tenant':
                                    found_vxlan_tenant = 1
                                elif key1 == 'vxlan-ecn':
                                    found_vxlan_ecn = 1
                                    if not self.is_network_segment_defined(\
                                            'vxlan-tenant'):
                                        err_str = "data[\'NETWORKING\'][\'networks\']\
                                            [\'vxlan-tenant\'] segment not defined along " \
                                            "with vxlan-ecn segment"
                                        raise Invalid(err_str)
                            elif re.search(r'sr-mpls-tenant', key1):
                                found_sr_mpls = 1
                                sr_mpls_tenant_schema(value1)
                                if not self.is_network_segment_defined(key1):
                                    err_str = "data[\'NETWORKING\'][\'networks\']\
                                        [\'%s\'] segment not defined" % (key1)
                                    raise Invalid(err_str)

                        except MultipleInvalid as e:
                            raise Invalid(' '.join(str(x) for x in e.errors))

        if found_vxlan and found_sr_mpls:
            err_str = "NETWORK_OPTIONS of vxlan and sr-mpls are mutually " \
                "exclusive"
            raise Invalid(err_str)

        if found_vxlan_ecn and not found_vxlan_tenant:
            err_str = "NETWORK_OPTIONS of vxlan-ecn is only allowed " \
                "with vxlan-tenant"
            raise Invalid(err_str)

        if invalid_vxlan_key_list:
            err_str = "Invalid key %s found" % (', '.join(invalid_vxlan_key_list))
            raise Invalid(err_str)

        if invalid_srmpls_sub_key_list:
            err_str = "Invalid key %s found"\
                % (', '.join(invalid_srmpls_sub_key_list))
            raise Invalid(err_str)

        if invalid_key_list:
            err_str = "Invalid key %s found" % (', '.join(invalid_key_list))
            raise Invalid(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        if mechanism_driver != 'vpp':
            err_str = "Mechanism driver of %s is not supported with %s" \
                % (mechanism_driver, input_str)
            raise Invalid(err_str)

        return

    def optional_service_check_list(self, input_str):
        '''check for optional services entry'''

        if input_str is None:
            err_str = "Need to have at least 1 entry"
            raise Invalid(err_str)

        is_ceilometer_present = 0
        is_heat_present = 0
        is_ironic_present = 0
        is_magnum_present = 0
        is_lbaas_present = 0
        is_octavia_present = 0

        expected_values = ['taas', 'heat', 'lbaas',
                           'ironic', 'ceilometer',
                           'octavia']

        if not isinstance(input_str, list):
            err_msg = "input has to be of type list"
            raise Invalid(err_msg)

        dup_entry_list = self.get_duplicate_entry_in_list(input_str)
        if dup_entry_list:
            err_msg = "Duplicate enterie(s) of %s in " \
                "setup_data.yaml" % (','.join(dup_entry_list))
            raise Invalid(err_msg)

        incorrect_entry_list = []
        for item in input_str:
            if item not in expected_values:
                incorrect_entry_list.append(item)
            elif re.match(r'heat', item):
                is_heat_present = 1
            elif re.match(r'ironic', item):
                is_ironic_present = 1
            elif re.match(r'magnum', item):
                is_magnum_present = 1
            elif re.match(r'ceilometer', item):
                is_ceilometer_present = 1
            elif re.match(r'lbaas', item):
                is_lbaas_present = 1
            elif re.match(r'octavia', item):
                is_octavia_present = 1

        curr_pod_type = self.ymlhelper.get_pod_type()
        if is_ceilometer_present and curr_pod_type != 'fullon':
            err_str = "Ceilometer is not supported with pod type %s; " \
                "it is supported with fullon pod only" % (curr_pod_type)
            raise Invalid(err_str)

        storage_info = self.get_storage_deployment_info()
        if is_ceilometer_present and \
                not re.search(r'DEDICATED_CEPH', storage_info):
            err_str = "Ceilometer is not supported with storage " \
                "type %s; it is only supported with DEDICATED_CEPH " \
                "for storage type" % (storage_info)
            raise Invalid(err_str)

        if is_magnum_present and not is_heat_present:
            err_str = "Magnum can only be supported with heat is enabled"
            raise Invalid(err_str)

        if is_magnum_present and re.match(r'UCSM', self.testbed_type):
            err_str = "Magnum is only supported with C-series testbed"
            raise Invalid(err_str)
        elif is_ironic_present and re.match(r'UCSM', self.testbed_type):
            err_str = "Ironic is only supported with C-series testbed"
            raise Invalid(err_str)

        if is_lbaas_present and is_octavia_present:
            err_str = "lbaas and octavia support are mutually exclusive"
            raise Invalid(err_str)

        octavia_dep_info = \
            self.ymlhelper.get_data_from_userinput_file(["OCTAVIA_DEPLOYMENT"])
        if is_octavia_present and octavia_dep_info is None:
            err_str = "OCTAVIA_DEPLOYMENT is not defined when octavia is " \
                "present"
            raise Invalid(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        network_type = self.get_network_type()

        err_str = "Magnum is only supported with Linuxbridge/VXLAN"
        if is_magnum_present and network_type is None:
            err_str1 = "Undefined TENANT_NETWORK_TYPE; " + err_str
            raise Invalid(err_str1)
        elif is_magnum_present and re.search(r'vts|openvswitch', mechanism_driver) \
                and not re.match(r'VXLAN', network_type):
            err_str1 = "MECHANISM_DRIVER found to be:" + mechanism_driver + \
                       "; and TENANT_NETWORK_TYPE found to be:" + \
                       network_type + "; " + err_str
            raise Invalid(err_str1)
        elif is_magnum_present and re.search(r'vts|openvswitch', mechanism_driver):
            err_str1 = "MECHANISM_DRIVER found to be " + mechanism_driver + \
                       ": " + err_str
            raise Invalid(err_str1)
        elif is_magnum_present and not re.match(r'VXLAN', network_type):
            err_str1 = "TENANT_NETWORK_TYPE found to be " + network_type + \
                       ": " + err_str
            raise Invalid(err_str1)
        elif is_ironic_present and re.search(r'openvswitch|vpp', mechanism_driver) \
                and not re.match(r'VLAN', network_type):
            err_str1 = "Ironic supported only with %s:%s, current deployment " \
                "found to be %s:%s" \
                % (mechanism_driver, 'VLAN', mechanism_driver, network_type)
            raise Invalid(err_str1)
        elif is_ironic_present and \
                not re.search(r'openvswitch|vpp', mechanism_driver):
            err_str1 = "Ironic supported only with %s, current deployment " \
                "found to be %s" % ('openvswitch or vpp', mechanism_driver)
            raise Invalid(err_str1)
        elif is_ironic_present and \
                self.is_provider_network_defined() == "UNDEFINED":
            err_str1 = "Ironic is supported only when provider " \
                "network is defined in the networking segment"
            raise Invalid(err_str1)
        elif is_lbaas_present and \
                not re.search(r'openvswitch|vpp', mechanism_driver):
            err_str1 = "lbass is only supported with openvswitch or vpp as " \
                "the mechanism driver. Current mechanism driver found " \
                "to be %s" % (mechanism_driver)
            raise Invalid(err_str1)
        elif is_octavia_present and \
                not re.search(r'openvswitch|vpp', mechanism_driver):
            err_str1 = "octavia is only supported with openvswitch or vpp as " \
                "the mechanism driver. Current mechanism driver found " \
                "to be %s" % (mechanism_driver)
            raise Invalid(err_str1)

        if incorrect_entry_list:
            err_str = "Item(s) " + str(incorrect_entry_list) + \
                      " not allowed; only values allowed are " + \
                      str(expected_values)
            raise Invalid(err_str)

    def validate_vpc_peer_port_address(self, input_str):
        '''Validate the VPC peer port address'''

        peer_port_addr_list = input_str.split(",")
        dup_peer_port_list = []
        seen = set()

        peer_port_space_check = input_str.split(" ")
        if len(peer_port_space_check) > 1 and not re.search(r',', input_str):
            err_str = "vpc_peer_port_address needs to be ',' separated; " \
                "Found: %s" % input_str
            raise Invalid(err_str)

        for item in peer_port_addr_list:
            self.validate_external_network_syntax(item, max_mask=31)

            if item in seen and item not in dup_peer_port_list:
                dup_peer_port_list.append(item)
            else:
                seen.add(item)

        if dup_peer_port_list:
            err_str = "Multiple Enteries of port list found: " + \
                      " ".join(dup_peer_port_list)
            raise Invalid(err_str)

        return

    def validate_cidr_syntax(self, input_str, max_mask=30):
        '''Validate the v4 CIDR subnet input'''

        self.validate_external_network_syntax(input_str, max_mask)

        network_info = input_str.split("/")[0]
        mask_info = input_str.split("/")[1]

        network_details = netaddr.IPNetwork(input_str)
        curr_network = network_details.network

        # Ensure that the subnet supplied is correct
        curr_network_calc = ipaddress.ip_address(unicode(curr_network))
        network_info_calc = ipaddress.ip_address(unicode(network_info))
        if curr_network_calc != network_info_calc:
            err_str = "Invalid subnet info provided %s, expected %s/%s" \
                % (input_str, curr_network, mask_info)
            raise Invalid(err_str)

    def validate_external_network_syntax(self, input_str, max_mask=30):
        '''Validate the external network syntax'''

        if input_str is None:
            raise Invalid("subnet parameter is not defined")
        elif not self.is_input_in_ascii(input_str):
            raise Invalid("subnet parameter is not in ASCII;  \
                          Found: " + input_str)
        elif not re.search(r'/', input_str):
            raise Invalid("Expected subnet format of IP/mask not present; "
                          "Found: " + input_str)

        network_info = input_str.split("/")[0]
        mask_info = input_str.split("/")[1]

        if network_info is None:
            raise Invalid("Missing Network Info for subnet; \
                          Expected format IP/mask")

        if mask_info is None:
            raise Invalid("Missing Mask Info for subnet; \
                          Expected format IP/mask")

        if not self.is_input_an_integer(mask_info) or \
                not self.is_input_range_valid(int(mask_info), 1, max_mask):
            err_str = "Invalid NW Mask info for subnet: " + \
                str(mask_info) + \
                " Expected: type integer in range 1-" + str(max_mask)
            raise Invalid(err_str)

        self.is_ip_syntax_valid(network_info)

    def validate_v6_cidr_syntax(self, input_str):
        '''Validate the v6 CIDR subnet input'''

        self.validate_external_v6network_syntax(input_str)

        network_info = input_str.split("/")[0]
        mask_info = input_str.split("/")[1]

        # Ensure that the subnet supplied is correct
        network_details = netaddr.IPNetwork(input_str)
        curr_network = network_details.network
        if not common_utils.is_ipv6_address_info_equal(network_info,
                                                       curr_network):
            err_str = "Invalid subnet info provided %s, expected %s/%s" \
                % (input_str, curr_network, mask_info)
            raise Invalid(err_str)

    def validate_external_v6network_syntax(self, input_str):
        '''Validate the external v6 network syntax'''

        if input_str is None:
            raise Invalid("subnet parameter is not defined")
        elif not self.is_input_in_ascii(input_str):
            raise Invalid("subnet parameter is not in ASCII;  \
                          Found: " + input_str)
        elif not re.search(r'/', input_str):
            raise Invalid("Expected subnet format of IP/mask not present; "
                          "Found: " + input_str)

        network_info = input_str.split("/")[0]
        mask_info = input_str.split("/")[1]

        if network_info is None:
            raise Invalid("Missing Network Info for subnet; \
                          Expected format IP/mask")

        if mask_info is None:
            raise Invalid("Missing Mask Info for subnet; \
                          Expected format IP/mask")

        if not self.is_input_an_integer(mask_info) or \
                not self.is_input_range_valid(int(mask_info), 1, 126):
            err_str = "Invalid v6 NW Mask info for subnet: " + \
                str(mask_info) + \
                " Expected: type integer in range 1-126"
            raise Invalid(err_str)

        self.is_ipv6_syntax_valid(network_info)

    def jumbo_frame_check_list(self, input_str):
        '''Check conditions for jumbo frame option;
        should be only for b-series, vpp, aci, or vts'''

        if input_str is False:
            return

        if self.ymlhelper.get_pod_type() == 'ceph':
            return

        b_series = re.match(r'UCSM', self.testbed_type) is not None
        err_str = ("Jumbo Frame option not supported for %s-series with " %
                   'B' if b_series else 'C')

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        if mechanism_driver is None:
            err_str = "Jumbo Frame option can't be determined as \
            MECHANISM_DRIVERS is not defined"
            raise Invalid(err_str)

        network_type = self.get_network_type()
        if network_type is None:
            err_str = "Jumbo Frame option can't be determined as \
            TENANT_NETWORK_TYPES is not defined"
            raise Invalid(err_str)

        if (re.match(r'VXLAN', network_type) and \
                re.match(r'linuxbridge', mechanism_driver) and b_series):
            return
        elif (re.match(r'VLAN', network_type) and \
              re.match(r'openvswitch', mechanism_driver)):
            return
        elif (re.match(r'VLAN', network_type) and \
              re.match(r'vts', mechanism_driver)):
            return
        elif (re.match(r'VLAN', network_type) and \
              re.match(r'vpp', mechanism_driver)):
            return
        elif (re.match(r'VLAN', network_type) and \
              re.match(r'aci', mechanism_driver)):
            return
        else:
            err_str += mechanism_driver + " and " + network_type
            raise Invalid(err_str)

        return

    def is_jumbo_frame_enabled(self):
        '''Checks to see if jumbo frame is enabled'''

        frame_type = \
            self.ymlhelper.get_data_from_userinput_file(["ENABLE_JUMBO_FRAMES"])
        if frame_type is None:
            return 0
        elif frame_type is False:
            return 0
        elif frame_type is True:
            return 1
        else:
            return 0

    def check_disable_hyperthreading(self, input_str):
        '''Checks if disable_hyperthreading info is correct'''

        if not isinstance(input_str, bool):
            err_str = "Only Boolean value True/False allowed; " \
                "default is False"
            raise Invalid(err_str)

        return

    def check_vm_hughpage_size(self, input_str):
        '''Check vm hugh page info'''

        if not self.ymlhelper.get_data_from_userinput_file(['NFV_HOSTS']):
            err_info = "VM_HUGEPAGE_SIZE info provided, " \
                "but @ data['NFV_HOSTS'] is missing"
            raise Invalid(err_info)

        if (input_str == '2M') or (input_str == '1G'):
            pass
        else:
            err_str = "VM_HUGEPAGE_SIZE of 2M or 1G allowed; Found: %s" % (input_str)
            raise Invalid(err_str)

        return

    def check_vm_hughpage_percent(self, input_str):
        '''Check vm hugh page percent info'''

        if not self.ymlhelper.get_data_from_userinput_file(['NFV_HOSTS']):
            err_info = "VM_HUGEPAGE_PERCENTAGE info provided, " \
                "but @ data['NFV_HOSTS'] is missing"
            raise Invalid(err_info)

        if not isinstance(input_str, int):
            err_str = "Only input of type integer is allowed, " \
                "in the range of 0-100 (including 0 and 100), " \
                "current input is %s" % (input_str)
            raise Invalid(err_str)
        elif (input_str >= 0) and (input_str <= 100):
            pass
        else:
            err_str = "Allowed VM_HUGEPAGE_PERCENTAGE range 0-100; Found: %s" \
                % (input_str)
            raise Invalid(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        if re.match(r'vpp|vts', mechanism_driver) and input_str != 100:
            err_str = "VM_HUGEPAGE_PERCENTAGE has to be 100 for " \
                "mechanism_driver %s" % (mechanism_driver)
            raise Invalid(err_str)

        return

    def check_nfv_host(self, input_str):
        '''Check NFV_HOSTS are valid. Inputs are considered as valid if either
        conditions is satisfied:
        (1) Equal to reserved word "ALL";
        (2) A valid comma separated string which consists zero or several
            compute nodes;
        '''

        if input_str is False:
            return

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        if mechanism_driver == 'linuxbridge' and input_str:
            err_str = "NFV_HOSTS is not allowed for mechanism driver as linuxbridge"
            raise Invalid(err_str)

        if str(input_str) == 'ALL':
            return

        nfv_hosts = set(self.ymlhelper.get_server_list(role="nfv_host"))
        computes = set(self.ymlhelper.get_server_list(role="compute"))
        if not nfv_hosts.issubset(computes):
            err_str = "NFV_HOSTS must be compute nodes. (role=='compute')"
            raise Invalid(err_str)

    def check_vnic_type(self, input_str):
        '''Check if SRIOV is allowed or not'''

        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])

        intel_nic_sriov_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_SRIOV_VFS'])

        vic_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_INTEL_SRIOV'])

        global_intel_vc_sriov_vfs = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_VC_SRIOV_VFS'])

        if intel_nic_sriov_check and not (intel_nic_check or vic_nic_check):
            err_str = "SRIOV for Standalone server is allowed for intel NIC only"
            raise Invalid(err_str)

        ucsm_status = self.check_ucsm_plugin_presence()

        if ucsm_status and input_str and \
                not re.search(r'direct', input_str):
            err_str = "Only value of direct allowed with B-Series"
            raise Invalid(err_str)

        elif not ucsm_status and not \
                (intel_nic_sriov_check or global_intel_vc_sriov_vfs) \
                and input_str and not re.search(r'normal', input_str):
            err_str = "Only value of normal allowed with B-Series and VIC"
            raise Invalid(err_str)

        elif input_str:
            if (input_str == 'direct') or (input_str == 'normal'):
                pass
            else:
                err_str = "Only value of direct or normal allowed with C-Series"
                raise Invalid(err_str)

        if (self.testbed_type != 'UCSM') and (input_str == 'direct'):
            vmtp_info = \
                self.ymlhelper.get_data_from_userinput_file(['VMTP_VALIDATION'])

            prov_net_info = vmtp_info.get('PROV_NET', None)
            if prov_net_info is None:
                err_str = "PROV_NET section missing under VMTP"
                raise Invalid(err_str)
            else:
                physnet_info = prov_net_info.get('PHYSNET_NAME', None)
                if physnet_info is None:
                    err_str = "PHYSNET_NAME missing under " \
                        "PROV_NET section of VMTP for SRIOV"
                    raise Invalid(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        network_type = self.get_network_type()
        if network_type is not None and \
                network_type.lower() == "vxlan" and \
                mechanism_driver is not None and \
                re.match(r'linuxbridge', mechanism_driver):
            err_str = "VNIC type option only allowed for OVS/VLAN"
            raise Invalid(err_str)

        return

    def check_physnet_input(self, input_str):
        '''Checks if physnet input is valid when PROV_FI_PIN is enabled'''

        if re.match(r'UCSM', self.testbed_type):
            prov_fi_pin_status = self.check_prov_fi_pin_status()

            if input_str and not prov_fi_pin_status:
                err_str = "Entry for PHYSNET_NAME not allowed, \
                    when ENABLE_PROV_FI_PIN is not True"
                raise Invalid(err_str)

            if prov_fi_pin_status and not input_str:
                err_str = "Entry for PHYSNET_NAME is blank, \
                    when ENABLE_PROV_FI_PIN is True"
                raise Invalid(err_str)

            if prov_fi_pin_status and input_str:
                if not re.match(r'phys_prov_fia|phys_prov_fib', input_str):
                    err_str = "Only phys_prov_fia or phys_prov_fib is \
                        allowed for PHYSNET_NAME values"
                    raise Invalid(err_str)

        else:
            intel_sriov_phys_port = \
                self.ymlhelper.get_data_from_userinput_file(\
                    ['INTEL_SRIOV_PHYS_PORTS'])

            num_intel_phys_port = 4
            if intel_sriov_phys_port is not None:
                num_intel_phys_port = int(intel_sriov_phys_port)

            max_phy_port_str = num_intel_phys_port - 1
            search_pat = "phys_sriov[0-%s]" % (max_phy_port_str)

            if not re.search(search_pat, input_str):
                err_str = "PHYSNET_NAME entry under PROV_NET section of VMTP " \
                    "for SRIOV has to be of type phys_sriov[0-%s], found to be %s" \
                    % (max_phy_port_str, input_str)
                raise Invalid(err_str)

        return

    def is_provider_network_defined(self):
        '''Check if provider network and VLAN is defined'''

        segments = self.ymlhelper.nw_get_server_vnic_segment()
        prov_net = segments.get('provider')

        if prov_net is None:
            return "UNDEFINED"

        # if prov defined, return the vlan info
        prov_vlan_info = segments['provider'].get('vlan_id')
        return prov_vlan_info

    def check_segmentation_info_vmtp(self, input_str):
        """Check Seg info for VMTP; if ACI it cannot be
        part of provider nettwork"""

        apicinfo = \
            self.ymlhelper.get_data_from_userinput_file(['APICINFO'])

        apic_check = 0
        if apicinfo is not None:
            apic_check = 1

        self.check_segmentation_info(input_str, apic_check=apic_check)

    def check_segmentation_info(self, input_str, apic_check=0):
        '''Check Segmentation Input'''

        if not isinstance(input_str, int):
            err_str = "Input of type non-integer not allowed"
            raise Invalid(err_str)
        elif not self.is_input_range_valid(int(input_str), 2, 4094):
            raise Invalid('Expected integer input between 2 and 4094')

        prov_vlan_info = \
            self.ymlhelper.get_data_from_userinput_file(['PROVIDER_VLAN_RANGES'])

        prov_net_det = self.is_provider_network_defined()
        if prov_net_det == 'UNDEFINED':
            raise Invalid("@ data['NETWORKING']['networks']['provider'] "
                          "not defined to run VMTP provider network tests")
        elif apic_check:
            pass
        elif prov_net_det != 'None':
            if input_str not in common_utils.expand_vlan_range(prov_net_det):
                err_str = "seg_id %s is not part of PROVIDER_VLAN_RANGES: %s" \
                          % (input_str, prov_net_det)
                raise Invalid(err_str)
        elif prov_vlan_info is None:
            err_str = "PROVIDER_VLAN_RANGES not defined"
            raise Invalid(err_str)
        elif prov_vlan_info is not None:
            if input_str not in common_utils.expand_vlan_range(prov_vlan_info) \
                    and not apic_check:
                err_str = "seg_id %s is not part of PROVIDER_VLAN_RANGES: %s" \
                          % (input_str, prov_vlan_info)
                raise Invalid(err_str)

            if input_str in common_utils.expand_vlan_range(prov_vlan_info) \
                    and apic_check:
                err_str = "seg_id %s is part of PROVIDER_VLAN_RANGES: %s" \
                          % (input_str, prov_vlan_info)
                raise Invalid(err_str)

        return

    def vmtp_check_list(self, input_str):
        '''check for VMTP schema'''

        ext_network_check = Schema({
            Required('NET_NAME'): All(str, msg='Missing Ext network name'),
            Required('NET_SUBNET'): self.validate_cidr_syntax,
            Required('NET_IP_START'): self.is_ip_syntax_valid,
            Required('NET_IP_END'): self.is_ip_syntax_valid,
            Required('NET_GATEWAY'): self.is_vmtp_v4gw_reachable,
            Required('DNS_SERVER'): self.is_ip_syntax_valid,
            Optional('VNIC_TYPE'): self.check_vnic_type,
        })

        provider_network_check = Schema({
            Required('NET_NAME'): All(str, msg='Missing Provider network name'),
            Required('NET_SUBNET'): self.validate_cidr_syntax,
            Required('NET_IP_START'): self.is_ip_syntax_valid,
            Required('NET_IP_END'): self.is_ip_syntax_valid,
            Required('NET_GATEWAY'): self.is_vmtp_v4gw_reachable,
            Required('DNS_SERVER'): self.is_ip_syntax_valid,
            Required('SEGMENTATION_ID'): self.check_segmentation_info_vmtp,
            Optional('VNIC_TYPE'): self.check_vnic_type,
            Optional('PHYSNET_NAME'): self.check_physnet_input,
        })

        provider_v6_network_check = Schema({
            Required('NET_NAME'): All(str, msg='Missing Provider network name'),
            Required('NET_SUBNET'): self.validate_v6_cidr_syntax,
            Required('NET_IP_START'): self.is_ipv6_syntax_valid,
            Required('NET_IP_END'): self.is_ipv6_syntax_valid,
            Required('NET_GATEWAY'): self.is_vmtp_v6gw_reachable,
            Required('DNS_SERVER'): self.is_ipv6_syntax_valid,
            Required('SEGMENTATION_ID'): self.check_segmentation_info_vmtp,
            Optional('VNIC_TYPE'): self.check_vnic_type,
            Required('IPV6_MODE'):
                In(frozenset(["slaac", "dhcpv6-stateless", "dhcpv6-stateful"])),
            Optional('PHYSNET_NAME'): self.check_physnet_input,
        })

        vts_net_check = Schema({
            Required('ENABLED'): All(Boolean(str), \
                                     msg="Only true or false allowed; " \
                                         "default is false"),
        })

        network_type_list = []
        prov_net_present = 0
        ext_net_present = 0
        vts_net_present = 0
        prov_net_v6 = 0

        if self.cd_cfgmgr.is_network_option_enabled('sr-mpls-tenant'):
            raise Invalid("VMTP is not supported with sr-mpls")

        if input_str is None:
            raise Invalid("Neither Provider or External Network defined")

        if 'PROV_NET' in input_str.keys():
            prov_net_present = 1
            network_type_list.append('PROV_NET')
            if input_str['PROV_NET'].get('IPV6_MODE', None) is not None:
                prov_net_v6 = 1

        if 'EXT_NET' in input_str.keys():
            ext_net_present = 1
            network_type_list.append('EXT_NET')

        if 'VTS_NET' in input_str.keys():
            vts_net_present = 1
            network_type_list.append('VTS_NET')

        if prov_net_present:
            prov_net_det = self.is_provider_network_defined()
            if prov_net_det == 'UNDEFINED':
                raise Invalid("@ data['NETWORKING']['networks']['provider'] "
                              "not defined to run VMTP provider network tests")

            if re.match(r'UCSM', self.testbed_type) and \
                    not self.check_ucsm_plugin_presence() and \
                    prov_net_det is None:
                raise Invalid("Info @ "
                              "['NETWORKING']['networks']['provider']['vlan_id']"
                              "not defined when UCSM plugin is not enabled")

        if not prov_net_present and not ext_net_present and not vts_net_present:
            raise Invalid("Neither VTS_NET or Provider or External Network defined")

        if not self.check_no_vts_presence() and \
                (ext_net_present or prov_net_present):
            raise Invalid("Only VTS_NET is allowed for VTS")

        if prov_net_present and ext_net_present:
            if prov_net_v6:
                vmtp_schema = Schema({
                    Required('EXT_NET'): ext_network_check,
                    Required('PROV_NET'): provider_v6_network_check,
                })
            else:
                vmtp_schema = Schema({
                    Required('EXT_NET'): ext_network_check,
                    Required('PROV_NET'): provider_network_check,
                })
        elif ext_net_present:
            vmtp_schema = Schema({
                Required('EXT_NET'): ext_network_check,
            })
        elif prov_net_present:
            if prov_net_v6:
                vmtp_schema = Schema({
                    Required('PROV_NET'): provider_v6_network_check,
                })
            else:
                vmtp_schema = Schema({
                    Required('PROV_NET'): provider_network_check,
                })
        elif vts_net_present:
            vmtp_schema = Schema({
                Required('VTS_NET'): vts_net_check,
                Optional('EXT_NET'): ext_network_check,
            })

        err_list = []
        err_str = ""
        try:
            vmtp_schema(input_str)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        # if schema is good check details of IP address
        if not err_list:
            for net_type in network_type_list:
                curr_net_type = ""
                if re.match(r'PROV_NET', net_type):
                    curr_net_type = "PROV_NET"
                elif re.match(r'EXT_NET', net_type):
                    curr_net_type = "EXT_NET"
                elif re.match(r'VTS_NET', net_type):
                    continue

                curr_gateway = input_str[curr_net_type]['NET_GATEWAY'].strip()
                start_ip_address = input_str[curr_net_type]['NET_IP_START'].strip()

                end_ip_address = input_str[curr_net_type]['NET_IP_END'].strip()
                network_info = input_str[curr_net_type]['NET_SUBNET'].strip()

                start = ipaddress.ip_address(unicode(start_ip_address))
                end = ipaddress.ip_address(unicode(end_ip_address))

                if start > end:
                    err_msg = "NET_IP_START info for " + str(curr_net_type) + " " \
                              + str(start_ip_address) + \
                              " is greater than NET_IP_END info:" + \
                              str(end_ip_address) + "; "
                    err_list.append(err_msg)

                if (curr_net_type == 'PROV_NET' and prov_net_v6):
                    if not self.validate_ipv6_for_a_given_network(start_ip_address, \
                                                                  network_info):

                        err_msg = "NET_IP_START info for %s %s doesn't " \
                            "belong in %s; " % (curr_net_type, \
                            start_ip_address, network_info)
                        err_list.append(err_msg)

                    if not self.validate_ipv6_for_a_given_network(end_ip_address,
                                                                  network_info):
                        err_msg = "NET_IP_END info for %s %s doesn't " \
                            "belong in %s; " % (curr_net_type, \
                            end_ip_address, network_info)
                        err_list.append(err_msg)

                    if not self.validate_ipv6_for_a_given_network(curr_gateway, \
                                                                  network_info):
                        err_msg = "NET_GATEWAY info for %s %s doesn't " \
                            "belong in %s; " % (curr_net_type, \
                                                curr_gateway, \
                                                network_info)
                        err_list.append(err_msg)

                    curr_bcast = self.validate_ipv6_for_a_given_network( \
                        end_ip_address, network_info, get_broadcast=1)

                    if curr_bcast:
                        bcast_ip = ipaddr.IPv6Address(curr_bcast)

                        if end == bcast_ip:
                            err_msg = "NET_IP_END " + str(end_ip_address) + \
                                      " for curr_net_type " + str(curr_net_type) + \
                                      " is same as its broadcast IP;"
                            err_list.append(err_msg)

                    num_ip = self.ipv6Range(start_ip_address, end_ip_address)
                    total_num_ip = len(num_ip)
                    if total_num_ip < 4:
                        err_msg = "Minimum number of IPv6 need is 4. " + \
                                  "Please adjust the NET_IP_START and " + \
                                  "NET_IP_END info in section " + str(curr_net_type)
                        err_list.append(err_msg)

                else:
                    if not self.validate_ip_for_a_given_network(start_ip_address,
                                                                network_info):
                        err_msg = "NET_IP_START info for " + curr_net_type + " " + \
                            str(start_ip_address) + " doesn't belong in " + \
                            str(network_info) + "; "
                        err_list.append(err_msg)

                    if not self.validate_ip_for_a_given_network(end_ip_address,
                                                                network_info):
                        err_msg = "NET_IP_END info for " + curr_net_type + " " \
                            + str(end_ip_address) + " doesn't belong in " \
                            + str(network_info) + "; "
                        err_list.append(err_msg)

                    if not self.validate_ip_for_a_given_network(curr_gateway,
                                                                network_info):
                        err_msg = "NET_GATEWAY info for " + curr_net_type + " " + \
                            str(curr_gateway) + " doesn't belong in " + \
                            str(network_info) + "; "
                        err_list.append(err_msg)

                    curr_bcast = self.validate_ip_for_a_given_network( \
                        end_ip_address, network_info, get_broadcast=1)

                    if curr_bcast:
                        bcast_ip = ipaddr.IPv4Address(curr_bcast)

                        if end == bcast_ip:
                            err_msg = "NET_IP_END " + str(end_ip_address) + \
                                " for curr_net_type " + str(curr_net_type) + \
                                " is same as its broadcast IP;"
                            err_list.append(err_msg)

                    num_ip = \
                        list(netaddr.iter_iprange(start_ip_address, end_ip_address))
                    total_num_ip = len(num_ip)
                    if total_num_ip < 4:
                        err_msg = "Minimum number of IP need is 4. " + \
                            "Please adjust the NET_IP_START and " + \
                            "NET_IP_END info in section " + str(curr_net_type)
                        err_list.append(err_msg)

        if err_list:
            err_str = ' '.join(err_list)
            raise Invalid(err_str)

        return

    def is_netapp_block_defined(self):
        '''check if netapp block defined'''

        netapp_info = self.ymlhelper.get_data_from_userinput_file(['NETAPP'])
        if netapp_info is None:
            return 0
        else:
            return 1

    def is_zadara_block_defined(self):
        """check if zadara block defined"""

        zadara_info = self.ymlhelper.get_data_from_userinput_file(['ZADARA'])
        if zadara_info is None:
            return 0
        else:
            return 1

    def get_netapp_transport_type(self):
        '''gets the netapp transport type'''

        netapp_info = self.ymlhelper.get_data_from_userinput_file(['NETAPP'])
        netapp_transport = netapp_info.get('transport_type')

        if netapp_transport is None:
            err_msg = "transport_type for netapp not defined, " \
                "can't validate port entry"
            raise Invalid(err_msg)

        return netapp_transport

    def check_netapp_cert_file(self, input_str):
        '''Checks the netapp cert path'''

        netapp_transport = self.get_netapp_transport_type()

        if netapp_transport != 'https':
            err_msg = "netapp cert path can only be defined " \
                "when netapp transport type is https"
            raise Invalid(err_msg)

        return

    def check_input_as_ipv4v6(self, input_str):
        '''Check v4 and v6 and skip fqdn'''

        self.check_input_as_ip_or_str(input_str, check_v6=1, check_fqdn=0)

    def check_input_as_ipv4v6_or_str(self, input_str):
        '''Check v4 and v6 or hostname'''

        self.check_input_as_ip_or_str(input_str, check_v6=1)

    def check_input_as_ip_or_str(self, input_str, check_v6=0, check_fqdn=1):
        '''Checks if input is of type string or ip address'''

        found_valid_fqdn = 0
        found_v4 = 0
        found_v6 = 0
        if not self.is_input_in_ascii(input_str):
            err_str = "Invalid input %s; not a string" % (input_str)
            raise Invalid(err_str)

        if re.search(r'\[[0-9:a-fA-F]+\]', input_str):
            tmp2 = (input_str.strip("]")).strip("[")
            input_str = tmp2

        try:
            ipaddr.IPv4Address(input_str)
            found_v4 = 1
        except ipaddr.AddressValueError:
            if check_v6 and common_utils.is_valid_ipv6_address(input_str):
                found_v6 = 1
            elif not check_v6 and common_utils.is_valid_ipv6_address(input_str):
                err_str = "Invalid input %s; " \
                    "only a FQDN/IPv4 address allowed" % (input_str)
                raise Invalid(err_str)
            elif check_v6 and not common_utils.is_valid_ipv6_address(input_str):
                err_str = "Invalid input %s; needs to be a valid IPv6 " \
                    "address" % (input_str)
                raise Invalid(err_str)
            else:
                pass

        if found_v4 or found_v6:
            return

        if not check_fqdn:
            return

        if common_utils.is_valid_hostname(input_str):
            found_valid_fqdn = 1

        if not found_valid_fqdn and not check_v6:
            err_str = "Invalid input %s; " \
                "not a FQDN/IPv4 address" % (input_str)
            raise Invalid(err_str)
        elif not found_valid_fqdn and check_v6:
            err_str = "Invalid input %s; " \
                "not a FQDN/IPv4/IPv6 address" % (input_str)
            raise Invalid(err_str)

        return

    def check_zadara_input(self, input_str):
        """Checks the entry for Zadara"""

        zadara_schema = Schema({
            Required('access_key'): All(str, Length(min=1)),
            Required('vpsa_host'): self.check_hostname_syntax,
            Required('vpsa_poolname'): All(str, Length(min=1)),
            Required('glance_nfs_name'): All(str, Length(min=1)),
            Required('glance_nfs_path'): All(str, Length(min=1)),
        })

        try:
            zadara_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        # TBD
        nova_boot_from = \
            self.ymlhelper.get_data_from_userinput_file(['NOVA_BOOT_FROM'])
        if nova_boot_from is not None:
            err_msg = "Entry for NOVA_BOOT_FROM is not allowed"
            raise Invalid(err_msg)

        return

    def check_netapp_input(self, input_str):
        '''Checks the entry for Netapp'''

        netapp_tls_schema = Schema({
            Required('server_hostname'): self.check_input_as_ipv4v6_or_str,
            Required('server_port'): All(443, msg='Value of 443 allowed'),
            Required('transport_type'): In(frozenset(["https"]), \
                msg='only https allowed with netapp over TLS'),
            Required('username'): All(str, Length(min=1)),
            Required('password'): All(str, Length(min=1)),
            Required('vserver'): All(str, Length(min=1)),
            Required('cinder_nfs_server'): self.check_input_as_ip_or_str,
            Required('cinder_nfs_path'): All(str, Length(min=1)),
            Required('glance_nfs_server'): self.check_input_as_ip_or_str,
            Required('glance_nfs_path'): All(str, Length(min=1)),
            Required('nova_nfs_server'): self.check_input_as_ip_or_str,
            Required('nova_nfs_path'): All(str, Length(min=1)),
            Required('netapp_cert_file'): self.check_netapp_cert_file,
        })

        netapp_non_tls_schema = Schema({
            Required('server_hostname'): self.check_input_as_ipv4v6_or_str,
            Required('server_port'): All(80, msg='Value of 80 allowed'),
            Required('transport_type'): In(frozenset(["http"]), \
                msg='only https allowed with netapp over clear'),
            Required('username'): All(str, Length(min=1)),
            Required('password'): All(str, Length(min=1)),
            Required('vserver'): All(str, Length(min=1)),
            Required('cinder_nfs_server'): self.check_input_as_ip_or_str,
            Required('cinder_nfs_path'): All(str, Length(min=1)),
            Required('glance_nfs_server'): self.check_input_as_ip_or_str,
            Required('glance_nfs_path'): All(str, Length(min=1)),
            Required('nova_nfs_server'): self.check_input_as_ip_or_str,
            Required('nova_nfs_path'): All(str, Length(min=1)),
        })

        netapp_transport = self.get_netapp_transport_type()

        if netapp_transport == "https":
            try:
                netapp_tls_schema(input_str)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))
        else:
            try:
                netapp_non_tls_schema(input_str)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        nova_boot_from = \
            self.ymlhelper.get_data_from_userinput_file(['NOVA_BOOT_FROM'])
        if nova_boot_from is not None:
            err_msg = "Entry for NOVA_BOOT_FROM is not allowed"
            raise Invalid(err_msg)

        return

    def check_cc_entry(self, input_str):
        '''Check CVIM MON Entry'''

        found_v4 = 0
        found_v6 = 0
        if not isinstance(input_str, str):
            err_msg = "Input needs to be , separated string " \
                "of all IPv4 or IPv6 addresses"
            raise Invalid(err_msg)

        input_list = input_str.split(",")
        if len(input_list) != 3:
            err_msg = "Input needs to have 3 enteries"
            raise Invalid(err_msg)

        for item in input_list:
            self.check_input_as_ip_or_str(item, check_v6=1, check_fqdn=0)
            if self.is_ip_valid(item):
                found_v4 = 1
            else:
                found_v6 = 1

        if found_v6 and found_v4:
            err_msg = "Combination of v6 and v4 is not supported"
            raise Invalid(err_msg)

        if found_v6:
            err_msg = self.is_v6_mgmt_network_defined()
            if err_msg:
                raise Invalid(err_msg)

        return

    def check_storage_schema(self, yaml_input):
        '''Check for storage schame'''

        storage_info = self.get_storage_deployment_info()

        if re.match(r'UNKNOWN', storage_info):
            return "InCorrect VOLUME_DRIVER"
        elif re.match(r'STORAGE_TYPE_UNKNOWN', storage_info):
            return "Can't Determine Storage type"
        elif re.match(r'LVM_DEDICATED_CEPH', storage_info):
            return "InCorrect Combo: Volume Driver: LVM; " \
                "block_storage: Dedicated"
        elif re.match(r'NETAPP_DEDICATED_CEPH', storage_info):
            return "InCorrect Combo: Volume Driver: netapp; " \
                "block_storage: Dedicated"
        elif storage_info == 'OOP_NETAPP_BLOCK':
            return "NETAPP block defined with incorrect " \
                "VOLUME_DRIVER and/or STORE_BACKEND"
        elif re.match(r'ZADARA_DEDICATED_CEPH', storage_info):
            return "InCorrect Combo: Volume Driver: zadara; " \
                "block_storage: Dedicated"
        elif storage_info == 'OOP_ZADARA_BLOCK':
            return "ZADARA block defined with incorrect " \
                "VOLUME_DRIVER and/or STORE_BACKEND"

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])
        if podtype is not None and re.match(r'UMHC|NGENAHC', podtype) and \
                not re.match(r'DEDICATED_CEPH', storage_info):
            err_str = "PDDTYPE of UMHC option only supported with " \
                "DEDICATED_CEPH storage option, current " \
                "storage found to be %s " % (storage_info)
            return err_str

        if podtype is not None and re.match(r'micro', podtype) and \
                not re.match(r'DEDICATED_CEPH', storage_info):
            err_str = "PDDTYPE of micro option only supported with " \
                "DEDICATED_CEPH storage option,, current storage " \
                "found to be %s " % (storage_info)
            return err_str

        if podtype is not None and re.match(r'edge', podtype) and \
                not re.match(r'CENTRAL_CEPH', storage_info):
            err_str = "PDDTYPE of edge option only supported with " \
                "CENTRAL_CEPH storage option, " \
                "current storage found to be %s " % (storage_info)
            return err_str

        if podtype is not None and re.match(r'nano', podtype) and \
                not re.match(r'LVM|file', storage_info):
            err_str = "PDDTYPE of nano option only supported with " \
                "LVM or file as storage option, " \
                "current storage found to be %s " % (storage_info)
            return err_str

        if re.match(r'DEDICATED_CEPH', storage_info):

            storage_schema = Schema({
                Required('VOLUME_DRIVER'): All(str, Any('ceph')),
                Required('STORE_BACKEND'): All(str, Any('ceph')),
                Optional('CLUSTER_ID'): self.check_absence_input,
                Optional('MON_HOSTS'): self.check_absence_input,
                Optional('MON_MEMBERS'): self.check_absence_input,
                Optional('SECRET_UUID'): self.check_absence_input,
                Optional('GLANCE_CLIENT_KEY'): self.check_absence_input,
                Optional('CINDER_CLIENT_KEY'): self.check_absence_input,
                Optional('CINDER_RBD_POOL'): self.check_absence_input,
                Optional('NOVA_RBD_POOL'): self.check_absence_input,
                Optional('GLANCE_RBD_POOL'): self.check_absence_input,
            }, extra=True)

        elif re.match(r'CENTRAL_CEPH', storage_info):
            storage_schema = Schema({
                Required('CLUSTER_ID'): All(str, msg='Missing CLUSTER_ID info'),
                Required('MON_HOSTS'): self.check_cc_entry,
                Required('MON_MEMBERS'): self.check_cc_entry,
                Required('GLANCE_RBD_POOL'): All(str, Length(min=1)),
                Required('STORE_BACKEND'): All(str, Any('ceph')),
                Required('GLANCE_CLIENT_KEY'): All(str, Length(min=1)),
                Required('VOLUME_DRIVER'): 'ceph',
                Optional('SECRET_UUID'): All(str, msg='Missing SECRET_UUID info'),
                Optional('CINDER_CLIENT_KEY'): All(str, Length(min=1)),
                Optional('CINDER_RBD_POOL'): All(str, Length(min=1)),
                Required('NOVA_RBD_POOL'): All(str, Length(min=1)),
                Optional('CEPH_NAT:'): All(Boolean(str),
                                           msg="Only Boolean value True/False "
                                               "allowed; default is False"),
            }, extra=True)

        elif re.match(r'LVM', storage_info):
            storage_schema = Schema({
                Required('VOLUME_DRIVER'): All(str, Any('lvm')),
                Required('VOLUME_GROUP'): All(str, Any('cinder-volumes')),
            }, extra=True)

        elif re.match(r'file', storage_info):
            storage_schema = Schema({
                Required('STORE_BACKEND'): All(str, Any('file')),
            }, extra=True)

        elif re.match(r'NETAPP', storage_info):
            storage_schema = Schema({
                Required('VOLUME_DRIVER'): All(str, Any('netapp')),
                Required('STORE_BACKEND'): All(str, Any('netapp')),
                Optional('CLUSTER_ID'): self.check_absence_input,
                Optional('MON_HOSTS'): self.check_absence_input,
                Optional('MON_MEMBERS'): self.check_absence_input,
                Optional('SECRET_UUID'): self.check_absence_input,
                Optional('GLANCE_CLIENT_KEY'): self.check_absence_input,
                Optional('CINDER_CLIENT_KEY'): self.check_absence_input,
                Optional('CINDER_RBD_POOL'): self.check_absence_input,
                Optional('NOVA_RBD_POOL'): self.check_absence_input,
                Optional('GLANCE_RBD_POOL'): self.check_absence_input,
            }, extra=True)

        elif re.match(r'ZADARA', storage_info):
            storage_schema = Schema({
                Required('VOLUME_DRIVER'): All(str, Any('zadara')),
                Required('STORE_BACKEND'): All(str, Any('zadara')),
                Optional('CLUSTER_ID'): self.check_absence_input,
                Optional('MON_HOSTS'): self.check_absence_input,
                Optional('MON_MEMBERS'): self.check_absence_input,
                Optional('SECRET_UUID'): self.check_absence_input,
                Optional('GLANCE_CLIENT_KEY'): self.check_absence_input,
                Optional('CINDER_CLIENT_KEY'): self.check_absence_input,
                Optional('CINDER_RBD_POOL'): self.check_absence_input,
                Optional('NOVA_RBD_POOL'): self.check_absence_input,
                Optional('GLANCE_RBD_POOL'): self.check_absence_input,
            }, extra=True)

        err_list = []
        err_str = ""

        try:
            storage_schema(yaml_input)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        if err_list:
            err_str = ' '.join(err_list)

        return err_str

    def get_network_type(self):
        '''Returns the network type'''

        try:
            ret_value = self.ymlhelper.check_section_exists(
                'TENANT_NETWORK_TYPES')
            return ret_value
        except KeyError:
            return None
        except ValueError:
            return None

    def check_ucsm_plugin_presence(self):
        '''Check if UCSM plugin is present in setup_data.yaml file'''

        if re.match(r'UCSM', self.testbed_type):
            ucsm_common = self.ymlhelper.get_data_from_userinput_file(['UCSMCOMMON'])
            if 'ENABLE_UCSM_PLUGIN' in ucsm_common.keys():
                ucsm_plugin_info = ucsm_common['ENABLE_UCSM_PLUGIN']
                if ucsm_plugin_info:
                    return 1

        return 0

    def is_tor_config_enabled(self):
        '''Check if tor configuration enabled'''

        try:
            torswitchinfo = \
                self.ymlhelper.get_data_from_userinput_file(['TORSWITCHINFO'])
            if 'CONFIGURE_TORS' in torswitchinfo.keys():
                cfg_tor_info = torswitchinfo['CONFIGURE_TORS']
                if cfg_tor_info:
                    return 1
        except AttributeError:
            return 0

        return 0

    def get_tor_switch_info(self, switch_type):
        '''Get the list of TOR Switches'''

        torswitch_list = []
        if switch_type == 'ironic':
            switch_key = 'IRONIC'
            switch_details = 'IRONIC_SWITCHDETAILS'
        else:
            switch_key = 'TORSWITCHINFO'
            switch_details = 'SWITCHDETAILS'

        try:
            torswitchinfo = \
                self.ymlhelper.get_data_from_userinput_file([switch_key])
            for key in torswitchinfo.keys():
                if re.search(r'SWITCHDETAILS', key):
                    switchdetails = torswitchinfo.get(switch_details)
                    for item in switchdetails:
                        if item.get('hostname') is not None:
                            torswitch_list.append(item.get('hostname'))
        except AttributeError:
            return torswitch_list

        return torswitch_list

    def get_tor_switch_info_details(self, switchname, infoname):
        '''Get particular info for a TOR Switch'''

        switch_info_list = []

        try:
            torswitchinfo = \
                self.ymlhelper.get_data_from_userinput_file(['TORSWITCHINFO'])
            switchdetails = torswitchinfo.get('SWITCHDETAILS')
            for item in switchdetails:
                switch_hostname = item.get('hostname')
                if re.search(switch_hostname, switchname):
                    if re.search(r'portchannel', infoname):
                        if item.get('vpc_domain') is not None:
                            curr_item = item.get('vpc_domain')
                            if curr_item not in switch_info_list:
                                switch_info_list.append(curr_item)
                        if item.get('br_mgmt_po_info') is not None:
                            curr_item = item.get('br_mgmt_po_info')
                            if curr_item not in switch_info_list:
                                switch_info_list.append(curr_item)

                    elif re.search(r'portlist', infoname):
                        if item.get('br_mgmt_port_info') is not None:
                            curr_item = item.get('br_mgmt_port_info')
                            if curr_item not in switch_info_list:
                                switch_info_list.append(curr_item)

                        if item.get('vpc_peer_port_info') is not None:
                            t_list = item.get('vpc_peer_port_info').split(',')
                            for entry in t_list:
                                if entry not in switch_info_list:
                                    switch_info_list.append(entry)

        except AttributeError:
            return switch_info_list

        return switch_info_list

    def check_prov_fi_pin_status(self):
        '''Check prov fi pin is enabled'''

        if re.match(r'UCSM', self.testbed_type):
            ucsm_common = self.ymlhelper.get_data_from_userinput_file(['UCSMCOMMON'])
            if 'ENABLE_PROV_FI_PIN' in ucsm_common.keys():
                prov_fi_pin_status = ucsm_common['ENABLE_PROV_FI_PIN']
                if prov_fi_pin_status:
                    return 1

        return 0

    def check_nfvimon_presence(self):
        '''Check if NFVIMON is present in setup_data.yaml file'''

        if 'NFVIMON' in self.ymlhelper.parsed_config.keys():
            return 1
        else:
            return 0

    def check_nfvimon_2nd_instance_present(self):
        '''Check if NFVIMON 2nd Instance is present in setup_data.yaml file'''

        master_ha_present = 0
        collector_ha_present = 0
        if 'NFVIMON' in self.ymlhelper.parsed_config.keys():
            nfvimon_info = self.ymlhelper.get_data_from_userinput_file(['NFVIMON'])
            if 'MASTER_2' in nfvimon_info.keys():
                master_ha_present = 1

            if 'COLLECTOR_2' in nfvimon_info.keys():
                collector_ha_present = 1

            if master_ha_present and not collector_ha_present:
                return "ERROR: COLLECTOR_2 section has not been defined " \
                    "for NFVIMON HA in setup_data under NFVIMON"
            elif collector_ha_present and not master_ha_present:
                return "ERROR: MASTER_2 section has not been defined " \
                    "for NFVIMON HA in setup_data under NFVIMON"
            else:
                return "NO HA"
        else:
            return "NO NFVIMON"

    def check_virtual_router_id_presence(self):
        '''Check if VIRTUAL_ROUTER_ID is present in setup_data.yaml file'''
        virtual_router_id_check = self.ymlhelper.\
            get_data_from_userinput_file(['VIRTUAL_ROUTER_ID'])
        return virtual_router_id_check is not None

    def check_cvimmon_presence(self):
        '''Check if CVIM_MON is present in setup_data.yaml file'''
        cvimmon_check = self.ymlhelper.\
            get_data_from_userinput_file(['CVIM_MON'])
        return cvimmon_check is not None

    def is_cvimmon_enabled(self):
        '''Check if CVIM_MON is enabled in setup_data.yaml file'''
        cvimmon_check = self.ymlhelper.\
            get_data_from_userinput_file(['CVIM_MON'])

        if cvimmon_check is None:
            return 0

        key = ["CVIM_MON", "enabled"]
        ret_value = self.ymlhelper.get_data_from_userinput_file(key)
        if ret_value is not None and ret_value is True:
            return 1
        else:
            return 0

    def is_central_cvimmon(self):
        '''Check if central CVIM_MON is enabled in setup_data.yaml file'''
        cvimmon_check = self.ymlhelper.\
            get_data_from_userinput_file(['CVIM_MON'])

        if cvimmon_check is None:
            return 0

        key = ["CVIM_MON", "central"]
        ret_value = self.ymlhelper.get_data_from_userinput_file(key)
        if ret_value is not None and ret_value is True:
            return 1
        else:
            return 0

    def is_cvimmonha_enabled(self):
        '''Check if Pod is CVIMMONHA type is in setup_data.yaml file'''
        podtype = self.ymlhelper.get_pod_type()
        return (podtype == 'CVIMMONHA')

    def is_inventory_discovery_enabled(self):
        """Check if INVENTORY_DISCOVERY is enabled in setup_data.yaml file"""

        return self.ymlhelper.get_data_from_userinput_file(\
            ['INVENTORY_DISCOVERY', 'enabled']) is True

    def validate_inventory_discovery(self, input_str):
        """Validate inventory discovery"""
        inventory_discovery_properties_schema = Schema({
            Required('enabled'): bool,
        })

        err_list = []
        try:
            inventory_discovery_properties_schema(input_str)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        if self.is_inventory_discovery_enabled() and not self.is_cvimmon_enabled():
            err_list.append("CVIM_MON has to be enabled")

        podtype = self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])
        if self.is_inventory_discovery_enabled() and podtype == 'ceph':
            err_list.append("Inventory Discovery is currently not supported "
                            "on central ceph pods.")

        if err_list:
            raise Invalid(" ".join(err_list))

    @staticmethod
    def validate_inventory_discovery_cvimmon_ha(input_str):
        """Validate inventory discovery on CVIMMONHA pod"""
        inventory_discovery_properties_schema = Schema({
            Required('enabled'): bool,
        })

        err_list = []
        try:
            inventory_discovery_properties_schema(input_str)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        if err_list:
            raise Invalid(" ".join(err_list))

    def check_ceph_virtual_router_id(self, input_str):
        '''Check if VIRTUAL_ROUTER_ID is in setup_data.yaml and valid
        for central ceph pod'''

        if not self.is_central_cvimmon():
            err_str = "Entry supported only for central CVIM-MON"
            raise Invalid(err_str)

        virtual_router_id_schema = Schema(All(int, Range(min=1, max=256)))

        try:
            virtual_router_id_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))
        return

    def check_ceph_external_vip_crt_key_present(self):
        '''Check if external_lb_vip certificate and key are present
        for central ceph pod'''

        user_provided_crt = \
            self.ymlhelper.get_data_from_userinput_file(["external_lb_vip_cert"])
        user_provided_key = \
            self.ymlhelper.get_data_from_userinput_file(["external_lb_vip_key"])

        if user_provided_crt is not None:
            haproxy_crt_path = user_provided_crt
        else:
            haproxy_crt_path = "/root/openstack-configs/haproxy.crt"

        if user_provided_key is not None:
            haproxy_key_path = user_provided_key
        else:
            haproxy_key_path = "/root/openstack-configs/haproxy.key"

        if not os.path.exists(haproxy_crt_path):
            err_str = "External_lb_vip certificate missing in: %s" \
                % (haproxy_crt_path)
            raise Invalid(err_str)
        if not os.path.exists(haproxy_key_path):
            err_str = "External_lb_vip key missing in: %s" \
                % (haproxy_key_path)
            raise Invalid(err_str)
        return

    def check_frequency_syntax(self, input_str):
        '''Checks frequency syntax'''

        err_str = "Input must be a duration, specified as seconds, " \
            "minutes or hours, e.g.: 45s, 2m, 12h"
        if not re.match('([0-9]+)(s|m|h)', str(input_str)):
            raise Invalid(err_str)

    def check_cvim_mon_ldap(self, input_str):
        '''Check if CVIM-MON ldap is in setup_data.yaml and valid'''

        if self.is_central_cvimmon():
            err_str = "Entry supported only for local CVIM_MON"
            raise Invalid(err_str)

        cvimmon_ldap_schema = Schema({
            Required('group_mappings'): self.cvimmon_ldap_group_mappings,
            Required('domain_mappings'): self.cvimmon_ldap_domain_mappings,
        })

        try:
            cvimmon_ldap_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

    def check_cvim_mon_ui_access(self, input_str):
        ''' Check if CVIM-MON ui_access is in setup_data.yaml and valid'''

        if self.is_central_cvimmon():
            err_str = "Entry supported only for local CVIM_MON"
            raise Invalid(err_str)

        cvim_mon_ui_access_schema = Schema(All(Boolean(str), \
                msg="Only Boolean value True/False allowed; \
                default is True"))

        try:
            cvim_mon_ui_access_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

    def check_cvim_mon_central(self, input_str):
        '''Check if CVIM_MON central is in setup_data.yaml file and valid'''

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        if self.is_central_cvimmon() and not self.is_cvimmon_enabled():
            err_str = "CVIM_MON has to be enabled to configure " \
                "central CVIM_MON"
            raise Invalid(err_str)

        # if self.is_central_cvimmon() and podtype == 'ceph' \
        #        and not self.check_virtual_router_id_presence():
        #    err_str = "VIRTUAL_ROUTER_ID has to be provided to " \
        #        "configure central CVIM-MON for central ceph pod"
        #    raise Invalid(err_str)

        if self.is_central_cvimmon() and podtype == 'ceph':
            # self.check_ceph_external_vip_crt_key_present()
            err_str = "Central CVIM-MON is currently not supported " \
                "for central ceph pods."
            raise Invalid(err_str)

        cvim_mon_central_schema = Schema(All(Boolean(str), \
                msg="Only Boolean value True/False allowed; \
                default is False"))

        try:
            cvim_mon_central_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))
        return

    def check_cvim_mon_intervals(self, input_str):
        '''Check if CVIM_MON intervals are in setup_data.yaml file and valid'''

        cvim_mon_intervals_schema = Schema({
            Optional('low_frequency'): self.check_frequency_syntax,
            Optional('medium_frequency'): self.check_frequency_syntax,
            Optional('high_frequency'): self.check_frequency_syntax,
        }, extra=False)

        cvim_mon = self.ymlhelper.get_data_from_userinput_file(["CVIM_MON"])
        if cvim_mon:
            if 'polling_intervals' in cvim_mon:
                cvim_mon_intervals_schema(input_str)
                intervals = cvim_mon['polling_intervals']

                try:
                    hf = 'high_frequency'
                    _ = self.convert_cvim_mon_intervals(hf, intervals[hf] \
                        if hf in intervals else '15s')

                except ValueError as e:
                    err_str = "Invalid intervals."
                    raise Invalid(e.message)
                except NameError as e:
                    raise Invalid(e.message)
                except:
                    err_str = "Invalid intervals."
                    raise Invalid(err_str)

            self.log.info("Intervals are not present, default values will be used.")
            return
        return

    def convert_cvim_mon_intervals(self, interval_name, interval):
        '''converts cvim mon intervals based on units'''

        if interval[-1] == 's':
            multiplier = 1
        elif interval[-1] == 'm':
            multiplier = 60
        elif interval[-1] == 'h':
            multiplier = 60 * 60
        else:
            err_msg = "Input can only have units of h,m,s; " \
                "Found to be %s for %s " % (interval, interval_name)
            raise NameError(err_msg)
        value = int(interval[:-1]) * multiplier
        if value < 10:
            err_str = "Exceeded lower bound value of 10s; " \
                "Found to be %s for %s" % (interval, interval_name)
            raise ValueError(err_str)
        if value > 3600:
            err_str = "Exceeded upper bound value of 3600s/60m/1h; " \
                "Found to be %s for %s" % (interval, interval_name)
            raise ValueError(err_str)
        return value

    def check_no_vts_presence(self):
        '''Check if VTS is present in setup_data.yaml file'''

        vts = self.ymlhelper.get_data_from_userinput_file(['VTS_PARAMETERS'])
        if vts is None:
            return 1
        else:
            return 0

    def check_vts_day0_config(self):
        '''Checks if VTS_DAY0 Config is True or false'''

        vts_day0_chk = 0
        if not self.check_no_vts_presence():
            vts = self.ymlhelper.get_data_from_userinput_file(['VTS_PARAMETERS'])
            vts_day0_info = vts.get('VTS_DAY0')
            if vts_day0_info is None or not vts_day0_info:
                vts_day0_chk = 0
            else:
                vts_day0_chk = 1

        return vts_day0_chk


    def check_managed_vts_config(self):
        '''Checks if VTS MANAGED is True or false'''

        vts_mng_chk = 0
        if not self.check_no_vts_presence():
            vts = self.ymlhelper.get_data_from_userinput_file(['VTS_PARAMETERS'])
            vts_mng_info = vts.get('MANAGED')
            if vts_mng_info is None or not vts_mng_info:
                vts_mng_chk = 0
            else:
                vts_mng_chk = 1

        return vts_mng_chk


    def is_vmtp_vts_present(self):
        '''Checks the VMTP, VTS dependencies are all laid out'''

        if self.check_no_vts_presence():
            return 0

        vmtp_info = self.ymlhelper.get_data_from_userinput_file(['VMTP_VALIDATION'])
        if vmtp_info is None:
            return 0

        return 1

    def check_vts_vni_range(self, input_str):
        '''Method to validate the VNI range provided for VTS'''

        ex_input = ""

        if not re.search(r':', input_str):
            ex_input = input_str + ": Expected Format: min_vni_id:max_vni_id"
            raise Invalid(ex_input)

        vni_items = input_str.split(":")
        if len(vni_items) != 2:
            ex_input = input_str + ": Expected Format: min_vni_id:max_vni_id"
            raise Invalid(ex_input)

        elif not vni_items[0].isdigit or not vni_items[1].isdigit:
            ex_input = input_str + " Expected Format: min_vni_id:max_vni_id"
            raise Invalid(ex_input)

        elif int(vni_items[0]) < 1 or int(vni_items[0]) > 16777215:
            ex_input = input_str + " Expected Range: min_vni_id 1 to 2^24-1"
            raise Invalid(ex_input)

        elif int(vni_items[1]) < 1 or int(vni_items[1]) > 16777215:
            ex_input = input_str + " Expected Range: max_vni_id 1 to 2^24-1"
            raise Invalid(ex_input)

        elif int(vni_items[0]) > int(vni_items[1]):
            ex_input = input_str + " Expected min_vni_id < max_vni_id"
            raise Invalid(ex_input)

        return ex_input

    def check_switch_port_number(self, input_str):
        '''Method to validate Switch slot and Port '''

        err_str = "Missing Switch Slot and Port"
        if input_str is None:
            raise Invalid(err_str)

        err_str = ""
        if not re.search(r'/', input_str):
            err_str = "Switch port number doesn't have the right pattern"
            raise Invalid(err_str)
        else:
            # Get slot and port input
            #err_str = "Switch port number doesn't have the right pattern"
            err_str = ""
            (slot, port) = input_str.split('/')

            if int(slot) and int(port):
                if int(slot) < 1 or int(slot) > 253:
                    err_str = "Switch slot out of range"
                    raise Invalid(err_str)

                if int(port) < 1 or int(port) > 512:
                    err_str = "Switch port out of range"
                    raise Invalid(err_str)

            else:
                err_str = "Switch slot and/or port not numberic"
                raise Invalid(err_str)

        return err_str

    def check_vlan_range(self,
                         given_vlan_range,
                         prov=False,
                         curr_info="UNKNOWN"):
        '''Method to validate the range'''

        if not re.match(r'UNKNOWN', curr_info):
            msg_info = curr_info
        elif prov is False:
            msg_info = "TENANT_VLAN_RANGES"
        else:
            msg_info = "Provider Network Segment"

        # For Provider network
        format_type = "\'vlan1:vlan2,vlan3:vlan4\' or \'vlan1,vlan2:vlan3\' " \
                      "or \'vlan1\' or \'vlan1:vlan2\' " \
                      "with the start vlan < end vlan in each segment, and " \
                      "vlans are in between 2 and 4094, and not overlapping " \
                      "with vlans defined in the setup_data"

        if prov is False:
            format_type = "\'vlan1:vlan2,vlan3:vlan4\' or \'vlan1:vlan2\' " \
                          "or \'vlan1,vlan2\' or \'vlan1:vlan2\' " \
                          "with the start vlan < end vlan in each segment, and " \
                          "vlans are in between 2 and 4094, and not overlapping " \
                          "with min of 2 vlans defined in the setup_data"

        err_msg = "%s: Incorrect format given for VLAN range. " \
            "Correct format: %s" % (msg_info, format_type)

        ucsm_plugin_present = self.check_ucsm_plugin_presence()

        if ucsm_plugin_present and prov is True and \
                not re.match(r'PROVIDER_VLAN_RANGES', curr_info):
            if given_vlan_range is None or \
                    re.search(r'None', str(given_vlan_range)):
                return ""
            else:
                return msg_info + ": VLAN should be defined as None, " \
                    "for provider network with UCSM Plugin"

        elif re.match(r'UCSM', self.testbed_type) and not ucsm_plugin_present \
                and prov is False:
            mechanism_driver = \
                self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

            network_type = self.get_network_type()
            if network_type is not None and \
                    network_type.lower() == "vxlan" and \
                    mechanism_driver is not None and \
                    re.match(r'linuxbridge', mechanism_driver):
                err_msg = "VLAN between 2 and 4094, found %s" % (given_vlan_range)
                if not self.is_input_range_valid(int(given_vlan_range), 2, 4094):
                    return err_msg
                else:
                    return

        if given_vlan_range is None:
            return err_msg

        vlan_ranges = str(given_vlan_range).split(",")

        if prov is False:
            vlan_list = common_utils.expand_vlan_range(given_vlan_range)
            if len(vlan_list) < 2:
                err_str = "%s; Found:%s" % (err_msg, given_vlan_range)
                return err_str

        for ranges in vlan_ranges:
            ind_vlan_entry = str(ranges).split(":")
            if len(ind_vlan_entry) == 1:
                vlan_info = ind_vlan_entry[0]
                if not self.is_input_an_integer(vlan_info):
                    return err_msg
                elif not self.is_input_range_valid(int(vlan_info), 2, 4094):
                    return err_msg
                else:
                    pass
            else:
                if not re.search(r'\:', str(ranges)):
                    return err_msg + " VLAN info Found: " + ranges

            if len(ind_vlan_entry) == 2:
                if re.search(r'\:', str(ranges)):
                    ind_ranges = ranges.split(":")

                if int(ind_ranges[0]) >= int(ind_ranges[1]):
                    return str(err_msg) + " curent input:" + \
                        str(given_vlan_range)

                if ind_ranges and len(ind_ranges) == 2:
                    for rang in ind_ranges:
                        if not self.is_input_range_valid(int(rang), 2, 4094):
                            return msg_info + ":Invalid VLAN ID given :  " \
                                + str(rang) + "; expected VLAN value between " \
                                "2 and 4094; input:" + str(given_vlan_range)
                else:
                    if not re.match(r'UNKNOWN', curr_info):
                        msg = curr_info
                    else:
                        msg = "Provider" if prov else "Tenant"
                    return "Incorrect format given for " + msg + " VLAN range." \
                        "Correct format: start1:end1, start2:end2"

        return ""

    def fetch_vlan_boundaries(self, vlan_range):
        '''Fetch the VLAN boundaries; \
        expected formant is: a:b,c:d,...'''

        vlan_bound_list = []
        vlan_info = str(vlan_range).split(",")

        for item in vlan_info:
            ind_info = item.split(":")
            if len(ind_info) == 2:
                vlan_bound_list.append(ind_info[0].strip())
                vlan_bound_list.append(ind_info[1].strip())

                if int(ind_info[1].strip()) < int(ind_info[0].strip()):
                    err_str = "VNI id %s should be less than %s in the " \
                        "input string:%s" % (ind_info[0].strip(),
                                             ind_info[1].strip(),
                                             vlan_range)
                    raise Invalid(err_str)
            else:
                vlan_bound_list.append(ind_info[0].strip())

        return vlan_bound_list

    def check_for_vlan_overlap(self, tenant_vlan_range):
        '''Check for vlan overlap within an entry of a:b,c:d,..'''

        overlapping_vlan_info = []
        if not re.search(r',', str(tenant_vlan_range)):
            return overlapping_vlan_info

        tenant_vlan_info = str(tenant_vlan_range).split(",")

        vlan_dict = {}
        entry_count = 0

        for item in tenant_vlan_info:
            ind_info = str(item).split(":")
            if len(ind_info) == 2:
                vlan_dict[entry_count] = \
                    range(int(ind_info[0]), (int(ind_info[1]) + 1))
            else:
                vlan_dict[entry_count] = [int(ind_info[0])]

            entry_count += 1

        curr_count = 0
        while curr_count < entry_count:
            inside_count = 0
            while inside_count < entry_count:
                if curr_count == inside_count:
                    inside_count += 1
                    continue

                my_list = list(set(vlan_dict[curr_count]) & \
                               set(vlan_dict[inside_count]))

                if my_list:
                    for item in my_list:
                        if item not in overlapping_vlan_info:
                            overlapping_vlan_info.append(item)

                inside_count += 1
            curr_count += 1

        return overlapping_vlan_info

    def validate_vlan_vni_entry(self, input_str, min, max, err_msg):

        vlan_or_vni_ranges = str(input_str).split(",")

        for ranges in vlan_or_vni_ranges:
            ind_entry = str(ranges).split(":")
            if len(ind_entry) == 1:
                curr_info = ind_entry[0]
                if not self.is_input_an_integer(curr_info):
                    return err_msg
                elif not self.is_input_range_valid(int(curr_info), min, max):
                    return err_msg
                else:
                    pass
            else:
                if not re.search(r'\:', str(ranges)):
                    return err_msg + " info Found: " + ranges

            if len(ind_entry) == 2:
                if int(ind_entry[0]) >= int(ind_entry[1]):
                    return str(err_msg) + " current input:" + \
                        str(ranges)

                for rang in ind_entry:
                    if not self.is_input_range_valid(int(rang), min, max):
                        err_str = "%s :Invalid ID given: %s; expected " \
                            "value between %s and %s; input: %s" \
                            % (err_msg, rang, min, max, ranges)
                        return err_str

        return ""

    def check_l3_prov_vni_info(self, l3_prov_vni_range):
        '''Check Prov VNI info'''

        min = 4100
        max = 16777215
        format_type = "\'vni1:vni2,vni3:vni4\' or \'vni1,vni2:vni3\' " \
                      "or \'vni1\' or \'vni1:vni2\' " \
                      "with the start vni < end vni in each segment, and " \
                      "vnis are in between 4100 and 2^24-1, and not " \
                      "overlapping with vnis defined in the setup_data"

        err_msg = "Input %s has to be of type string supplied within \'\'; " \
            "Supported format: %s" % (l3_prov_vni_range, format_type)

        if isinstance(l3_prov_vni_range, int):
            raise Invalid(err_msg)

        # Check for overlapping VNIs
        overlap_vni_list = self.check_for_vlan_overlap(l3_prov_vni_range)
        if overlap_vni_list:
            err_str = "Overlapping VNIs found in %s" % l3_prov_vni_range
            raise Invalid(err_str)

        l3_prov_vni_det = common_utils.expand_vlan_range(l3_prov_vni_range)

        prov_vlan_info = \
            self.ymlhelper.get_data_from_userinput_file(['PROVIDER_VLAN_RANGES'])
        prov_vlan_det = common_utils.expand_vlan_range(prov_vlan_info)

        if len(l3_prov_vni_det) != len(prov_vlan_det):
            err_msg = "Number of PROVIDER_VLAN_RANGES:%s and " \
                "L3_PROV_VNI_RANGES:%s are not the same" \
                % (len(prov_vlan_det), len(l3_prov_vni_det))
            raise Invalid(err_msg)

        entry_validation_status = \
            self.validate_vlan_vni_entry(l3_prov_vni_range, min, max, err_msg)

        if entry_validation_status:
            raise Invalid(entry_validation_status)

        self.l3_fabric_vni_list.extend(l3_prov_vni_det)
        return

    def check_prov_vlan_info(self, prov_vlan_range):
        '''Check Prov Vlan info for provider network'''

        prov_name = "PROVIDER_VLAN_RANGES"
        tenant_name = "TENANT_VLAN_RANGES"
        format_type = "\'vlan1:vlan2,vlan3:vlan4\' or \'vlan1,vlan2:vlan3\' " \
                      "or \'vlan1\' or \'vlan1:vlan2\' " \
                      "with the start vlan < end vlan in each segment, and " \
                      "vlans are in between 2 and 4094, and not overlapping with " \
                      "vlans defined in the setup_data"

        if isinstance(prov_vlan_range, int):
            err_msg = "Input %s has to be of type string supplied within \'\'; " \
                "Supported format: %s" % (prov_vlan_range, format_type)
            raise Invalid(err_msg)

        prov_segment_name = "@ data['NETWORKING']['networks']['provider']['vlan_id']"

        prov_net_det = self.is_provider_network_defined()
        if prov_net_det == 'UNDEFINED':
            err_str = "%s defined when NETWORKING:networks:provider " \
                "section is not defined" % (prov_name)
            raise Invalid(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        if mechanism_driver == 'vts':
            err_str = "With MECHANISM_DRIVER:%s, option not allowed" \
                      % (mechanism_driver)
            raise Invalid(err_str)

        err_str = self.check_vlan_range(prov_vlan_range,
                                        prov=True,
                                        curr_info=prov_name)

        if err_str:
            raise Invalid(err_str)

        # check no overlapping VLANs in the entry
        overlap_vlan_list = self.check_for_vlan_overlap(prov_vlan_range)
        if overlap_vlan_list:
            err_str = "Overlapping VLANS found in %s" % (prov_vlan_range)
            raise Invalid(err_str)

        prov_seg_vlan_overlap_list = []
        prov_vlan_det = common_utils.expand_vlan_range(prov_vlan_range)

        if 'PROVIDER_VLAN_RANGES' not in self.global_vlan_info.keys():
            self.global_vlan_info['PROVIDER_VLAN_RANGES'] = prov_vlan_det

        if re.match(r'UCSM', self.testbed_type) and \
                prov_net_det != 'None' and prov_net_det != 'UNDEFINED':
            prov_segment_vlan_det = common_utils.expand_vlan_range(prov_net_det)
            for item in prov_vlan_det:
                if item not in prov_segment_vlan_det:
                    prov_seg_vlan_overlap_list.append(item)

        if prov_seg_vlan_overlap_list:
            err_str = "%s info is not a subset of %s:%s" \
                      % (prov_vlan_range, prov_segment_name, prov_net_det)
            raise Invalid(err_str)

        # Check no overlapping VLAN with TENANT_VLAN_RANGES
        tenant_vlan_info = \
            self.ymlhelper.get_data_from_userinput_file(["TENANT_VLAN_RANGES"])

        if tenant_vlan_info is not None:
            tenant_vlan_det = common_utils.expand_vlan_range(tenant_vlan_info)
            ten_prov_overlap_list = list(set(tenant_vlan_det) & set(prov_vlan_det))

            if ten_prov_overlap_list:
                err_str = "%s and %s have Overlapping VLANS:%s" \
                    % (prov_name, tenant_name, ten_prov_overlap_list)
                raise Invalid(err_str)

        return

    def check_vlan_info(self, tenant_vlan_range):
        '''Check Vlan info for tenant network'''

        format_type = "\'vlan1:vlan2,vlan3:vlan4\' or \'vlan2:vlan3\' " \
                      "or \'vlan2,vlan3\' " \
                      "with the start vlan < end vlan in each segment, and " \
                      "vlans are in between 2 and 4094, and not overlapping with " \
                      "vlans (min of 2) defined in the setup_data"

        if isinstance(tenant_vlan_range, int):
            err_msg = "Input %s has to be of type string supplied within \'\'; " \
                "Supported format: %s" % (tenant_vlan_range, format_type)
            raise Invalid(err_msg)

        err_str = None
        network_type = self.get_network_type()

        if network_type is None:
            raise Invalid("Can't validate VLAN_RANGES, \
                          as TENANT_NETWORK_TYPES is undefined")

        err_str = self.check_vlan_range(tenant_vlan_range)

        if err_str:
            raise Invalid(err_str)

        tenant_vlan_det = common_utils.expand_vlan_range(tenant_vlan_range)
        if 'TENANT_VLAN_RANGES' not in self.global_vlan_info.keys():
            self.global_vlan_info['TENANT_VLAN_RANGES'] = tenant_vlan_det

        overlap_vlan_list = self.check_for_vlan_overlap(tenant_vlan_range)
        if overlap_vlan_list:
            err_str = "Overlapping VLANs found in %s" % (tenant_vlan_range)
            raise Invalid(err_str)

        return err_str

    def is_ipv4v6_valid(self, input_str):
        '''Checks if input is of type v4 or v6 address'''

        found_v4 = 0
        found_v6 = 0
        if not self.is_input_in_ascii(input_str):
            err_str = "Invalid input %s; not a string" % (input_str)
            self.log.info(err_str)
            return False

        if re.search(r'\[[0-9:a-fA-F]+\]', input_str):
            tmp2 = (input_str.strip("]")).strip("[")
            input_str = tmp2

        try:
            ipaddr.IPv4Address(input_str)
            found_v4 = 1
        except ipaddr.AddressValueError:
            if common_utils.is_valid_ipv6_address(input_str):
                found_v6 = 1

        if found_v4 or found_v6:
            return True

        return False

    def is_dns_valid(self, dns_name):
        '''Checks if DNS is valid '''

        if not self.is_ipv4v6_valid(dns_name) and \
                common_utils.is_valid_hostname(dns_name):
            try:
                _ = socket.getaddrinfo(dns_name, None)
                return 1
            except socket.gaierror, err:
                self.log.info("cannot resolve hostname: %s err:%s",
                              dns_name, err)
                err_str = "Cannot resolve v4v6 DNS hostname: %s" % dns_name
                raise Invalid(err_str)

        if common_utils.is_valid_ipv6_address(dns_name):
            try:
                ipv6_addr_det = \
                    socket.getaddrinfo(dns_name, None, 0, socket.SOCK_STREAM)[0][4]
                _ = ipv6_addr_det[0]
            except socket.gaierror, err:
                self.log.info("cannot resolve hostname: %s err:%s",
                              dns_name, err)
                err_str = "Cannot resolve v6 DNS: %s" % dns_name
                raise Invalid(err_str)

            return common_utils.is_valid_ipv6_address(dns_name)

        else:
            try:
                ip_addr = socket.gethostbyname(dns_name)
            except socket.gaierror, err:
                self.log.info("cannot resolve hostname: %s err:%s",
                              dns_name, err)
                err_str = "Cannot resolve v4 DNS: %s" % dns_name
                raise Invalid(err_str)

            return self.is_ip_valid(ip_addr)

    def validate_email(self, email_str):
        '''validate email syntax'''

        err_str = ""
        if re.match(r"[\w\.\-]*@[\w\.\-]*\.\w+", str(email_str)):
            return err_str
        else:
            err_str = "Incorrect email address for Auth Registry"

        if err_str:
            raise Invalid(err_str)

        return err_str

    def validate_vlan_id_schema(self, vlan_id):
        ''' validates if the input of vlan is correct'''

        if vlan_id is None or re.match(r'None', str(vlan_id)):
            err_info = "vlan_id is missing: %s" % (vlan_id)
            self.log.error(err_info)
            raise Invalid(err_info)

        try:
            _ = int(vlan_id)
        except ValueError:
            err_info = "incorrect vlan_id %s entered" % (vlan_id)
            self.log.error(err_info)
            raise Invalid(err_info)

        if int(vlan_id) > 4094 or int(vlan_id) < 1:
            err_info = "incorrect vlan_id %s entered" % (vlan_id)
            self.log.error(err_info)
            raise Invalid(err_info)

        return

    def get_duplicate_entry_in_list(self, input_list):
        '''Gets Duplicate entry in list'''

        s = set(input_list)
        dup_entry = []
        for x in input_list:
            if x in s:
                s.remove(x)
            else:
                dup_entry.append(x)

        return dup_entry

    def generate_all_vlans(self, vlan_list):
        '''Takes in a vlan list of ['12', '23-45'] and generates a list
        with all vlans'''

        vlans = set()
        for item in vlan_list:
            vlan_ranges = str(item).split(",")
            for ranges in vlan_ranges:
                lo, _, hi = ranges.partition('-')
                low = int(lo)
                if hi:
                    vlans.update(range(low, int(hi) + 1))
                else:
                    vlans.add(low)

        all_vlan_list = [str(v) for v in vlans]

        return all_vlan_list

    def validate_vlan_id(self, vlan_id):
        ''' validates if the input of vlan is correct'''

        if vlan_id is None or re.match(r'None', str(vlan_id)):
            self.log.error("vlan_id is missing")
            return 0

        try:
            _ = int(vlan_id)
        except ValueError:
            self.log.error("incorrect vlan_id %s entered", vlan_id)
            return 0

        if int(vlan_id) > 4094 or int(vlan_id) < 1:
            self.log.error("incorrect vlan_id %s entered", vlan_id)
            return 0
        else:
            return 1

    def validate_sriov_multivlan_trunk(self, input_str):
        '''Validate SRIOV MultiVLAN Tunking'''

        err_str = ""

        #get all the network VLANs
        network_vlan_list = self.get_vlan_list_in_networks(exclude_tenant=1)

        prop_sriov_vlan = []
        overlapping_vlan_list = []
        overlapping_network_list = []
        sriov_network_list = []
        dup_entry_list = []
        err_list = []
        invalid_vlan_type = 0
        invalid_vlan_type_list = []
        invalid_vlan_range = []

        # get the list of VLANs that need to be trunked
        for d in input_str:
            for k, v in d.items():
                if k not in sriov_network_list:
                    sriov_network_list.append(k)
                else:
                    overlapping_network_list.append(k)

                curr_vlan = str(v).split(",")
                for item in curr_vlan:
                    if re.search(r':', item):
                        start_vlan = item.split(":")[0]
                        end_vlan = item.split(":")[1]
                        if self.is_input_an_integer(start_vlan):
                            prop_sriov_vlan.append(start_vlan.strip())
                        else:
                            invalid_vlan_type = 1
                            invalid_vlan_type_list.append(start_vlan)

                        if self.is_input_an_integer(end_vlan):
                            prop_sriov_vlan.append(end_vlan.strip())
                        else:
                            invalid_vlan_type = 1
                            invalid_vlan_type_list.append(end_vlan)

                        if not invalid_vlan_type:
                            a = int(start_vlan)
                            while a < (int(end_vlan) - 1):
                                a = a + 1
                                prop_sriov_vlan.append(str(a))

                    elif self.is_input_an_integer(item):
                        prop_sriov_vlan.append(item.strip())
                    else:
                        invalid_vlan_type_list.append(item.strip())

        for item in prop_sriov_vlan:
            if not self.validate_vlan_id(item):
                invalid_vlan_range.append(item)

        if invalid_vlan_range:
            err_str = "SRIOV_MULTIVLAN_TRUNK input has invalid vlan range:" + \
                      ', '.join(invalid_vlan_range) + " in setup_data.yaml"
            err_list.append(err_str)

        if invalid_vlan_type_list:
            err_str = "SRIOV_MULTIVLAN_TRUNK input has non int vlan:" + \
                      ', '.join(invalid_vlan_type_list) + " in setup_data.yaml"
            err_list.append(err_str)

        if overlapping_network_list:
            err_str = "SRIOV_MULTIVLAN_TRUNK input has duplicate networks:" + \
                      ', '.join(overlapping_network_list) + " in setup_data.yaml"
            err_list.append(err_str)

        for item in prop_sriov_vlan:
            tmp = item.strip()
            if int(tmp) in network_vlan_list:
                overlapping_vlan_list.append(tmp)
            elif str(tmp) in network_vlan_list:
                overlapping_vlan_list.append(tmp)

        # Get dup vlans in SRIOV runk section
        dup_entry_list = self.get_duplicate_entry_in_list(prop_sriov_vlan)
        if dup_entry_list:
            err_str = "SRIOV_MULTIVLAN_TRUNK input has duplicate vlans:" + \
                      ', '.join(dup_entry_list) + " in setup_data.yaml"
            err_list.append(err_str)

        if overlapping_vlan_list:
            err_str = "SRIOV trunk VLANs overlaps with existing network VLANS: " + \
                      ', '.join(overlapping_vlan_list) + " in setup_data.yaml"
            err_list.append(err_str)

        if err_list:
            err_str = "; ".join(err_list)
            raise Invalid(err_str)

        return err_str

    def get_vlan_list_in_networks(self, exclude_tenant=0):
        '''gets the list of vlans defined in networks section of setup_data.yaml'''

        vlan_list = []
        # Get the management network type
        curr_mgmt_network = self.ymlhelper.get_management_network_type()

        if exclude_tenant:
            base_segment_list = ['management', 'provision', 'api', 'storage',
                                 'provider', 'external']
        else:
            base_segment_list = ['management', 'provision', 'api', 'tenant',
                                 'storage', 'provider', 'external']

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        if mechanism_driver == 'aci':
            base_segment_list.append('aciinfra')

        if self.cd_cfgmgr.is_network_option_enabled('vxlan-tenant'):
            base_segment_list.append('vxlan-tenant')

        if self.cd_cfgmgr.is_network_option_enabled('vxlan-ecn'):
            base_segment_list.append('vxlan-ecn')

        if self.cd_cfgmgr.is_network_option_enabled('sr-mpls-tenant'):
            base_segment_list.append('sr-mpls-tenant')

        for segment in base_segment_list:
            curr_vlan = self.ymlhelper.nw_get_specific_vnic_info(segment, "vlan_id")
            if curr_vlan is not None:
                if re.search(r'[0-9:]+', str(curr_vlan)):
                    if self.is_input_an_integer(curr_vlan):
                        vlan_list.append(int(curr_vlan))
                    elif re.search(r':', str(curr_vlan)):
                        start_vlan = curr_vlan.split(":")[0]
                        end_vlan = curr_vlan.split(":")[1]
                        a = int(start_vlan)
                        vlan_list.append(a)
                        while a <= (int(end_vlan) - 1):
                            a = a + 1
                            vlan_list.append(str(a))
        return vlan_list

    @staticmethod
    def validate_netmask_format(input_str):
        '''validates the netmask format'''

        err_str = ""
        try:
            socket.inet_aton(input_str)
            # legal
        except socket.error:
            # Not legal
            err_str = "Incorrect netmask format"

        if err_str:
            raise Invalid(err_str)

        return err_str

    def is_file_exists(self, file_path):
        """Check if file exists"""
        err_str = "File path: {} does not exists".format(file_path)
        if not os.path.exists(file_path):
            raise Invalid(err_str)

    def is_input_in_plain_str_ldap(self, str_value):
        """Check if input exists"""
        err_str = ""
        if len(str_value) < 1:
            err_str = "Min string length of 1 is required"
            raise Invalid(err_str)

    def is_input_in_plain_str_len16(self, rhs_value):
        '''checks if input is in plain str'''
        err_str = ""
        err_str = self.is_input_in_plain_str(rhs_value, 16)
        return err_str

    def is_input_in_plain_str_len32(self, rhs_value):
        '''checks if input is in plain str'''
        err_str = ""
        err_str = self.is_input_in_plain_str(rhs_value, 32)
        return err_str

    def is_input_in_plain_str_len256(self, rhs_value):
        '''checks if input is in plain str'''
        err_str = ""
        err_str = self.is_input_in_plain_str(rhs_value, 256)
        return err_str

    def is_input_in_plain_str(self, rhs_value, max_len=1):
        '''checks if input is in plain str'''

        err_str = ""
        rhs_value = str(rhs_value)
        if not self.is_input_in_ascii(rhs_value):
            err_str = "Invalid input; not a string"
            raise Invalid(err_str)

        if re.search(r'>|<|&|\*|\\|\"|\`', rhs_value):
            err_str = "One or more invalid chars in \"" + str(rhs_value) + "\""
            raise Invalid(err_str)

        if re.search(r'\s', rhs_value):
            err_str = "Space not allowed in \"" + str(rhs_value) + "\""
            raise Invalid(err_str)

        if not rhs_value:
            err_str = "Min string length of 1 is required"
            raise Invalid(err_str)

        if max_len != 1:
            if len(rhs_value) > max_len:
                err_str = "Max string length of " + str(max_len) + \
                    " allowed for " + str(rhs_value)
                raise Invalid(err_str)

        return err_str

    def validate_linux_username(self, username):
        """check if input is a valid linux username
            length: 1 to 32
            first character underscore or lowercase letter
            remaining characters: lowercase, digits, underscore, or dash
            not a known system user name
        """
        if len(username) < 1 or len(username) > 32:
            err_str = "Length must be between 1 and 32"
            raise Invalid(err_str)
        system_list = ["root", "bin", "daemon", "adm", "lp", "sync",
                       "shutdown", "halt", "mail", "operator", "games",
                       "ftp", "nobody", "systemd-network", "dbus", "polkitd",
                       "ntp", "apache", "dockerroot", "postfix", "sshd",
                       "tcpdump"]
        if username in system_list:
            err_str = username + " username is reserved for system use"
            raise Invalid(err_str)
        if not username[0].islower() and username[0] != '_':
            err_str = "First character must be lowercase or underscore"
            raise Invalid(err_str)
        if len(username) == 1:
            return ""
        valid_chars = 'abcdefghijklmnopqrstuvwxyz0123456789_-'
        # check remaining characters
        if len(username) > 1:
            for letter in username[1:]:
                if letter not in valid_chars:
                    err_str = "Only lowercase, digits, underscore, and "\
                              "dash are valid characters"
                    raise Invalid(err_str)
        return ""

    def check_qos_policy(self, input_str):
        ''' Check QOS Policy is on or off'''

        err_str = ""

        if self.check_ucsm_plugin_presence():
            err_str = "Only Boolean value True/False allowed for \
                    ENABLE_QOS_POLICY"
            if input_str is True:
                return err_str
            elif input_str is False:
                return err_str
            elif input_str is None:
                raise Invalid(err_str)
            elif input_str:
                raise Invalid(err_str)

        elif not self.check_ucsm_plugin_presence():
            err_str = "ENABLE_QOS_POLICY can only be set to True/False when \
                      ENABLE_UCSM_PLUGIN is True"
            if input_str is True:
                raise Invalid(err_str)
            elif input_str is False:
                return
            elif input_str is None:
                raise Invalid(err_str)
            elif input_str:
                raise Invalid(err_str)

        return err_str

    def check_qos_policy_settings(self):
        '''Check if QOS policy is set in setup_data.yaml file'''

        if re.match(r'UCSM', self.testbed_type):
            ucsm_common = self.ymlhelper.get_data_from_userinput_file(['UCSMCOMMON'])
            if 'ENABLE_UCSM_PLUGIN' in ucsm_common.keys():
                ucsm_plugin_info = ucsm_common['ENABLE_UCSM_PLUGIN']
                if ucsm_plugin_info:
                    if 'ENABLE_QOS_POLICY' in ucsm_common.keys():
                        ucsm_qos_check = ucsm_common['ENABLE_QOS_POLICY']
                        if ucsm_qos_check:
                            return 1

        return 0


    def check_qos_policy_for_pp(self, input_str):
        ''' Check QOS Policy at port profile is on or off'''

        err_str = ""

        if self.check_ucsm_plugin_presence():
            if self.check_qos_policy_settings():
                err_str = "Only Boolean value True/False allowed \
                          for QOS_FOR_PORT_PROFILE"
                if input_str is True:
                    return err_str
                elif input_str is False:
                    return err_str
                elif input_str is None:
                    raise Invalid(err_str)
                elif input_str:
                    raise Invalid(err_str)

            elif not self.check_qos_policy_settings():
                err_str = "QOS_FOR_PORT_PROFILE can only be set to \
                          True/False when ENABLE_QOS_POLICY is set to True"
                if input_str is True:
                    raise Invalid(err_str)
                elif input_str is False:
                    return err_str
                elif input_str is None:
                    raise Invalid(err_str)
                elif input_str:
                    raise Invalid(err_str)

        elif not self.check_ucsm_plugin_presence():
            err_str = "QOS_FOR_PORT_PROFILE can only be set to \
                      False when ENABLE_UCSM_PLUGIN is True and \
                      ENABLE_QOS_POLICY is set to True; else \
                      set it to False"
            if input_str is True:
                raise Invalid(err_str)
            elif input_str is False:
                return err_str
            elif input_str is None:
                raise Invalid(err_str)
            elif input_str:
                raise Invalid(err_str)

        return err_str

    def check_qos_policy_type(self, input_str):
        '''Checks the QOS Policy type if defined'''
        err_str = "QOS_POLICY_TYPE can only have a value of 'nfvi' \
                  or 'media'"

        if not self.is_input_in_ascii(input_str):
            raise Invalid(err_str)
        elif not re.search(r'nfvi|media', input_str):
            raise Invalid(input_str)

    def check_absence_input(self, input_str):
        '''Checks if input string is absent'''

        if isinstance(input_str, str):
            err_str = "Input not allowed for this entry"
            raise Invalid(err_str)
        elif isinstance(input_str, int):
            err_str = "Input not allowed for this entry"
            raise Invalid(err_str)
        elif isinstance(input_str, float):
            err_str = "Input not allowed for this entry"
            raise Invalid(err_str)
        elif isinstance(input_str, bool):
            err_str = "Input not allowed for this entry"
            raise Invalid(err_str)
        elif input_str is None:
            err_str = "Input not allowed for this entry"
            raise Invalid(err_str)

        return

    def check_eth_port_syntax(self, input_str, ncs5500_chk=0, skip_type="SRIOV"):
        '''Checks the syntax of eth port'''

        err_str = ""
        err_list = []
        search_str = "GigE|TenGigE|FortyGigE|HundredGigE|Te|Hu|Gi"
        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        if ncs5500_chk:
            if not re.search(search_str, input_str, re.IGNORECASE):
                err_str = input_str
                return err_str
            else:
                pass
        elif mechanism_driver == 'vts' and skip_type == 'SRIOV' and \
                not re.search(r'^Ethernet', input_str):
            err_str = input_str
        elif mechanism_driver != 'vts' and \
                not re.search(r'^eth', input_str, re.IGNORECASE):
            err_str = input_str
        elif not re.search(r'[1-3]/[1-96]', input_str):
            err_str = input_str

        if ncs5500_chk:
            intf_list = input_str.split(",")
            for item in intf_list:

                if re.search('^([A-Za-z]+)([0-9]/[0-9]/[0-9]/[0-9]+/[0-3])$', \
                             item):
                    continue
                elif re.search('^([A-Za-z]+)([0-9]/[0-9]/[0-9]/[0-9]+)$', \
                               item):
                    continue
                else:
                    err_list.append(item)

        if err_list:
            err_str = ','.join(err_list)

        return err_str

    def is_splitter_option_mapped(self, target_switch_name,
                                  target_interface,
                                  splitter_source,
                                  splitter_rsm_overlap_check=0):
        '''Verify if target_interface is subset of splitter_source;
        Also, checks if splitter_opt and rsm are overlapping'''

        intf_list = target_interface.split(",")
        splitter_source_list = splitter_source.split(",")

        rsm_prefix_list = []
        rsm_list = []
        mismatch_list = []
        mismatch_splitter_info_str = ""
        b = ""
        splitter_suffix_list = []

        # Separate the splitter prefix and RSM part
        for splitter_item in splitter_source_list:
            try:
                c = re.search('^([A-Za-z]+)([0-9]/[0-9]/[0-9]/[0-9]+)$', \
                              splitter_item.strip())
                splitter_info = c.group(2)
                splitter_suffix_list.append(splitter_info)
            except AttributeError:
                tmp = target_switch_name + ":splitter_opt:" + splitter_item
                mismatch_list.append(tmp)

        if mismatch_list:
            mismatch_splitter_info_str = ','.join(mismatch_list)
            return mismatch_splitter_info_str

        # now look at interface info
        for item in intf_list:
            try:

                if splitter_rsm_overlap_check:
                    b = re.search('^([A-Za-z]+)([0-9]/[0-9]/[0-9]/[0-9]+)$', \
                                  item)
                else:
                    b = re.search('([A-Za-z]+)([0-9]/[0-9]/[0-9]/[0-9]+/[0-3])', \
                        item)

                rsm_prefix_info = b.group(1)
                rsm_info = b.group(2)
                rsm_list.append(rsm_info)
                rsm_prefix_list.append(rsm_prefix_info)

            except AttributeError:
                tmp = target_switch_name + ":interface_name:" + item
                mismatch_list.append(tmp)

        if mismatch_list:
            mismatch_splitter_info_str = ','.join(mismatch_list)
            return mismatch_splitter_info_str

        for (rsm_item, rsm_prefix_item) in zip(rsm_list, rsm_prefix_list):
            found_match = 0
            for split_item in splitter_suffix_list:
                if splitter_rsm_overlap_check:
                    if split_item == rsm_item:
                        found_match = 1
                        break
                elif not splitter_rsm_overlap_check:
                    curr_intf = rsm_prefix_item.strip() + rsm_item.strip()
                    if re.search('^([A-Za-z]+)([0-9]/[0-9]/[0-9]/[0-9]+/[0-9])$', \
                            curr_intf):
                        if split_item in rsm_item:
                            found_match = 1
                            break

            # splitter option needs to be a subset of intf name
            # for non-overlapping check
            if not splitter_rsm_overlap_check and not found_match:
                tmp = "switch_name:intf_name:splitter_opt %s:%s%s:%s" \
                      % (target_switch_name, rsm_prefix_item, rsm_item,
                         splitter_source)
                mismatch_list.append(tmp)

            elif splitter_rsm_overlap_check and found_match:
                # splitter option cant be same as intf name
                # for intf which are not split
                tmp = "switch_name:intf_name:splitter_opt %s:%s%s:%s" \
                      % (target_switch_name, rsm_prefix_item, rsm_item,
                         splitter_source)
                mismatch_list.append(tmp)

        if mismatch_list:
            mismatch_splitter_info_str = ','.join(mismatch_list)

        return mismatch_splitter_info_str

    def get_splitter_option(self,
                            target_switch_name,
                            target_splitter_option):
        '''Check if splitter cable option is enabled'''

        try:
            torswitchinfo = \
                self.ymlhelper.get_data_from_userinput_file(['TORSWITCHINFO'])

            if 'SWITCHDETAILS' in torswitchinfo.keys():
                switchdetails = torswitchinfo['SWITCHDETAILS']
                for item in switchdetails:
                    curr_switchname = item.get('hostname')
                    if target_switch_name == curr_switchname:
                        if target_splitter_option == '4x10':
                            curr_splitter_4_10_option = item.get('splitter_opt_4_10')
                            if curr_splitter_4_10_option is None:
                                return "NotDefined"
                            else:
                                return curr_splitter_4_10_option
                        else:
                            return "NotDefined"
            else:
                return "NotDefined"

        except AttributeError:
            return "NotDefined"

    def check_splitter_cable_option(self, input_str):
        '''Check that the splitter info is valid'''

        intf_list = input_str.split(",")
        invalid_int_range_list = []
        invalid_prefix_list = []
        dup_int_list = []
        seen = set()

        # ensure there is no overlap on the suffix
        suffix_seen = set()
        dup_suffix_list = []

        if not self.is_tor_type_ncs5500():
            err_str = "Option allowed only with NCS-5500 as TOR"
            raise Invalid(err_str)

        self.is_input_in_plain_str_len256(input_str)

        intf_list_space_check = input_str.split(" ")
        if len(intf_list_space_check) > 1 and not re.search(r',', input_str):
            err_str = "Multiple spliter_4_10 info in the same TOR " \
                "needs to be ',' separated; Found: %s" % input_str
            raise Invalid(err_str)

        search_str = "FortyGigE|HundredGigE|Hu"
        splitter_suffix_list = []

        for item in intf_list:
            if not re.search(search_str, item.strip()):
                invalid_prefix_list.append(item)
            elif not re.search(r'^([A-Za-z]+)([0-9]/[0-9]/[0-9]/[0-9]+)$', \
                    item.strip()):
                invalid_int_range_list.append(item)
            else:
                c = re.search('^([A-Za-z]+)([0-9]/[0-9]/[0-9]/[0-9]+)$', \
                    item.strip())
                splitter_info = c.group(2)
                splitter_suffix_list.append(splitter_info)

            if item in seen and item not in dup_int_list:
                dup_int_list.append(item)
            else:
                seen.add(item)

        for item in splitter_suffix_list:
            if item in suffix_seen and item not in dup_suffix_list:
                dup_suffix_list.append(item)
            else:
                suffix_seen.add(item)

        if invalid_prefix_list:
            err_str = "Splitter port info has to be provided in " \
                "format of (FortyGigE|HundredGigE)a/b/c/d; a, b and c " \
                "are integers and can be between 0-9 and d can " \
                "be between 0-48; " \
                "Found: %s" % (" ".join(invalid_int_range_list))
            raise Invalid(err_str)

        if invalid_int_range_list:
            err_str = "Splitter port info has to be provided in " \
                "format of (FortyGigE|HundredGigE)a/b/c/d; a, b and c " \
                "are integers and can be between 0-9 and d can " \
                "be between 0-48; " \
                "Found: %s" % (" ".join(invalid_int_range_list))
            raise Invalid(err_str)

        if dup_int_list:
            err_str = "Repeating enteries of Splitter info" \
                " found: " + " ".join(dup_int_list)
            raise Invalid(err_str)

        if dup_suffix_list:
            err_str = "Repeating enteries of Splitter port info (RSMI)" \
                " found for different Interface speed: " \
                + " ".join(dup_suffix_list)
            raise Invalid(err_str)

        return

    def is_eth_port_info_valid(self, input_str):
        '''Check the syntax of the port info'''

        invalid_int_list = []
        intf_list = input_str.split(",")
        invalid_int_range_list = []
        dup_int_list = []
        seen = set()

        self.is_input_in_plain_str_len256(input_str)

        intf_list_space_check = input_str.split(" ")
        if len(intf_list_space_check) > 1 and not re.search(r',', input_str):

            err_str = "vpc_peer_port_info needs to be ',' separated; " \
                      "Found: %s" % input_str
            raise Invalid(err_str)

        search_str = "GigE|TenGigE|FortyGigE|HundredGigE|Te|Hu|Gi"
        for item in intf_list:
            if self.is_tor_type_ncs5500():
                if not re.search(search_str, item, re.IGNORECASE):
                    invalid_int_list.append(item)
            elif not re.search(r'^eth', item, re.IGNORECASE):
                invalid_int_list.append(item)
            elif not re.search(r'[1-3]/[1-96]', item):
                invalid_int_range_list.append(item)

            if item in seen and item not in dup_int_list:
                dup_int_list.append(item)
            else:
                seen.add(item)

        if invalid_int_list:
            err_str = "Port Info of type ethernet allowed; Found: " + \
                      " ".join(invalid_int_list)
            raise Invalid(err_str)

        if invalid_int_range_list:
            err_str = ""
            if self.is_tor_type_ncs5500():
                err_str = "Port Info of format %s; Found: %s" \
                    % (search_str, " ".join(invalid_int_list))
            else:
                err_str = "Port Info from eth1 to eth1/96 allowed; Found: %s" \
                    % (" ".join(invalid_int_list))
            raise Invalid(err_str)

        if dup_int_list:
            err_str = "Multiple Enteries of port list found: " + \
                      " ".join(dup_int_list)
            raise Invalid(err_str)

        return

    def is_channel_list_valid(self, input_str):
        '''Check the syntax of the channel list'''

        invalid_channel_list = []
        channel_list = input_str.split(" ")

        for item in channel_list:
            if not self.is_input_an_integer(item):
                invalid_channel_list.append(item)

        if invalid_channel_list:
            err_str = "Port Channel Entry of type integer allowed; Found: " \
                      + " ".join(invalid_channel_list)
            raise Invalid(err_str)

        return

    def is_vlan_list_valid(self, input_str):
        '''Check the syntax of the vlan list'''

        invalid_vlan_list = []
        vlan_list = input_str.split(" ")

        for item in vlan_list:
            ind_vlan_list = re.split(r',|-|\^', item)
            for vlan_id in ind_vlan_list:
                if not self.validate_vlan_id(vlan_id):
                    if item not in invalid_vlan_list:
                        invalid_vlan_list.append(item)

        if invalid_vlan_list:
            err_str = "Invalid syntax of VLAN Entry found: " \
                      + " ".join(invalid_vlan_list)
            raise Invalid(err_str)

        return

    def check_if_all_vlans_included(self, switch_name, vpc_peer_vlan_info):
        '''Checks if all vlans from openstack is defined in vcp_peer_vlan_info'''

        excluded_vlan_list = []

        os_vlan_info = self.cfgmgr.resolve_segment_vlans()[0]

        os_vlan_info_val = os_vlan_info.values()

        os_vlan_list = self.generate_all_vlans(os_vlan_info_val)

        vpc_peer_raw_vlan_list = vpc_peer_vlan_info.split(",")
        vpc_peer_vlan_list = self.generate_all_vlans(vpc_peer_raw_vlan_list)

        if set(os_vlan_list) <= set(vpc_peer_vlan_list):
            pass
        else:
            excluded_vlan_list = list(set(os_vlan_list) - set(vpc_peer_vlan_list))
        return excluded_vlan_list

    def validate_list_input(self, input_str):
        '''Validate List input'''

        err_list = []
        if not isinstance(input_str, list):
            err_list.append(input_str)

        if err_list:
            err_str = "Input of type list allowed for CUSTOM_CONFIG: " \
                      + " ".join(err_list)
            raise Invalid(err_str)

        return

    def check_switch_custom_config(self, input_str):
        '''Check Switch Custom Config'''

        switch_custom_schema = Schema({
            Optional('GLOBAL'): self.validate_list_input,
            Optional('PORTCHANNEL'): self.validate_list_input,
            Optional('SWITCHPORT'): self.validate_list_input,
        }, extra=False)

        err_str = ""

        try:
            switch_custom_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        return err_str

    def check_zen_collector_tor_info(self, input_str):
        ''' Check the NFVIMON TOR input for Collector'''

        err_list = []

        if not isinstance(input_str, (list)):
            err_str = "Input type of list supported, " \
                "please refer to the example file for syntax"
            raise Invalid(err_str)

        if len(input_str) > 1:
            err_str = "Max entry of 1 supported; found to be %s" \
                % (len(input_str))
            raise Invalid(err_str)

        # compare input with switch first
        for item in input_str:
            for _, value in item.items():
                self.check_tor_info_for_server(value)

            dup_eth_port_list = \
                self.get_duplicate_entry_in_list(self.server_eth_port_list)

            dup_pc_list = \
                self.get_duplicate_entry_in_list(self.server_port_channel_list)

            if dup_eth_port_list:
                err_str = "Duplicate eth port info across Servers and " \
                    "Zenoss Collector: " + ' '.join(dup_eth_port_list)
                err_list.append(err_str)

            if dup_pc_list:
                err_str = "Duplicate Port Channel info across TOR and " \
                    "Zenoss Collector: " + ' '.join(dup_pc_list)
                err_list.append(err_str)

        if err_list:
            raise Invalid(', '.join(err_list))

        return

    def check_zen_collector_input(self, input_str):
        '''Checks the NFVIMON collector input'''

        mgmt_ip_list = []
        admin_ip_list = []

        collector_vm_schema = Schema({
            Required('hostname'): self.is_input_in_plain_str_len32,
            Required('password'): self.check_password_syntax,
            Required('ccuser_password'): self.check_password_syntax,
            Required('admin_ip'): self.check_valid_nfvimon_admin_ip,
            Required('management_ip'): self.check_valid_nfvimon_mgmt_ip,
        })

        collector_vm_info_count = 0
        collector_vm_hostname_list = []
        err_str_list = []
        for item in input_str:
            collector_vm_schema(item)
            mgmt_ip_list.append(item.get('management_ip'))
            admin_ip_list.append(item.get('admin_ip'))
            if item.get('hostname'):
                collector_vm_hostname_list.append(item.get('hostname'))
                collector_vm_info_count += 1

        nfvimon_info = \
            self.ymlhelper.get_data_from_userinput_file(['NFVIMON'])
        collector_info = nfvimon_info.get('COLLECTOR')
        mgmt_vip_info = collector_info.get('management_vip')

        if mgmt_vip_info is not None:
            mgmt_ip_list.append(mgmt_vip_info)

        repeating_mgmt_ip_info = self.check_for_dups_in_list(mgmt_ip_list)
        repeating_admin_ip_info = self.check_for_dups_in_list(admin_ip_list)
        repeating_vmname_info = self.check_for_dups_in_list(\
            collector_vm_hostname_list)

        if repeating_admin_ip_info:
            err_str = "Duplicate Admin IPs for Collector VM found:" + \
                      ", ".join(repeating_admin_ip_info) + ";"
            err_str_list.append(err_str)
        else:
            self.global_admin_ip_list.extend(admin_ip_list)

        if repeating_mgmt_ip_info:
            err_str = "Duplicate Mgmt IPs for Collector VM found:" + \
                      ", ".join(repeating_mgmt_ip_info) + ";"
            err_str_list.append(err_str)

        if repeating_vmname_info:
            err_str = "Duplicate hostname for Collector VM found:" + \
                      ", ".join(repeating_mgmt_ip_info) + ";"
            err_str_list.append(err_str)

        # Checks if only 2 collector VMs are there
        if collector_vm_info_count == 0:
            err_str = "Both Collector VMs Info are absent"
            err_str_list.append(err_str)
        elif collector_vm_info_count == 1:
            err_str = "1 Collector VM is absent"
            err_str_list.append(err_str)
        elif collector_vm_info_count != 2:
            err_str = "Only 2 collector VMs allowed on each pod"
            err_str_list.append(err_str)

        if err_str_list:
            raise Invalid('; '.join(err_str_list))

        return

    def check_for_dups_in_list(self, input_list, input_type="non_ip"):
        '''Checks if list has duplicate,
        returns the entrys that are repeating'''

        seen = set()
        dup_list_info = []
        for x in input_list:
            if input_type != "non_ip" and not self.is_ip_valid(x):
                tmp = x
                x = ipaddr.IPv6Address(tmp).exploded

            if str(x) in seen and str(x) not in dup_list_info:
                dup_list_info.append(str(x))
            else:
                seen.add(str(x))

        return dup_list_info

    def check_for_dups_in_dict(self, input_dict):
        '''Checks if dict has duplicate,
        returns the entrys that are repeating'''

        plugin_absent = 0
        ucsm_present = 0
        if re.match(r'UCSM', self.testbed_type):
            ucsm_present = 1
        if re.match(r'UCSM', self.testbed_type) and \
                not self.check_ucsm_plugin_presence():
            plugin_absent = 1

        dup_vlan_keys = []

        for k, v in input_dict.iteritems():
            for k_int, v_int in input_dict.iteritems():
                if k == k_int:
                    continue
                elif ucsm_present and \
                        re.search(r'TENANT_VLAN_RANGES|tenant', k) and \
                        re.search(r'TENANT_VLAN_RANGES|tenant', k_int):
                    continue
                elif plugin_absent and \
                        re.search(r'PROVIDER_VLAN_RANGES|provider', k) and \
                        re.search(r'PROVIDER_VLAN_RANGES|provider', k_int):
                    continue

                elif isinstance(v_int, list) and isinstance(v, list):
                    overlap_vlan_list = list(set(v_int) & set(v))
                    if overlap_vlan_list:
                        tmp1 = k + ":" + k_int
                        tmp2 = k_int + ":" + k
                        if tmp1 not in dup_vlan_keys and \
                                tmp2 not in dup_vlan_keys:
                            dup_vlan_keys.append(tmp1)
                elif isinstance(v_int, int) and isinstance(v, int) and v_int == v:
                    tmp1 = k + ":" + k_int
                    tmp2 = k_int + ":" + k
                    if tmp1 not in dup_vlan_keys and \
                            tmp2 not in dup_vlan_keys:
                        dup_vlan_keys.append(tmp1)

        return dup_vlan_keys

    def aci_vpc_peer_keepalive_check(self, input_str):
        '''Checks and make sure that the VPC peer keepalive is not an IP address'''

        self.is_input_in_plain_str_len32(input_str)

        if re.match(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', input_str):
            err_msg = "IP Address not accepted in ACI setup"
            raise Invalid(err_msg)

        return

    def check_spine_rr_node_id(self, input_str):
        '''Checks the validity of spine_rr_node_id'''

        err_str = "Input has to be of type list, " \
                  "where each entry is a number in string format:" \
                  "for eg: ['303', 405']; found %s" % (input_str)
        if not isinstance(input_str, (list)):
            raise Invalid(err_str)

        invalid_rr_list = []
        for item in input_str:
            if not item.isdigit():
                invalid_rr_list.append(item)

        if invalid_rr_list:
            raise Invalid(err_str)

        return

    def check_tenant_vlan_range(self):
        '''checks that the tenant vlan range is within
        limits for NCS-5500'''

        tenant_vlan_info = \
            self.ymlhelper.get_data_from_userinput_file(['TENANT_VLAN_RANGES'])
        if tenant_vlan_info is None:
            err_msg = "TENANT_VLAN_RANGES undefined when TOR is NCS-5500"
            raise Invalid(err_msg)

        expanded_prov_vlan_list = []
        prov_vlan_info = \
            self.ymlhelper.get_data_from_userinput_file(['PROVIDER_VLAN_RANGES'])
        if prov_vlan_info is not None:
            prov_vlan_info_sub = re.sub(r':', '-', prov_vlan_info)
            prov_vlan_list = prov_vlan_info_sub.split(",")
            expanded_prov_vlan_list = self.generate_all_vlans(prov_vlan_list)

        prov_net_det = self.is_provider_network_defined()
        if prov_net_det != 'UNDEFINED' and prov_vlan_info is None:
            err_str = 'Incompatible configuration: Provider network segment ' \
                'defined without PROVIDER_VLAN_RANGES for NCS-5500'
            raise Invalid(err_str)

        max_tenant_vlan = 600

        tenant_vlan_info_sub = re.sub(r':', '-', tenant_vlan_info)
        tenant_vlan_list = tenant_vlan_info_sub.split(",")
        expanded_tenant_vlan_list = self.generate_all_vlans(tenant_vlan_list)
        tot_vlan_list = \
            len(expanded_tenant_vlan_list) + len(expanded_prov_vlan_list)

        if tot_vlan_list > max_tenant_vlan:
            err_msg = "Max of %s VLANs allowed between TENANT_VLAN_RANGES and/or " \
                "PROVIDER_VLAN_RANGES for NCS-5500, found:%s" \
                % (max_tenant_vlan, tot_vlan_list)
            raise Invalid(err_msg)

        return

    def check_mgmt_l2out_network_4tor(self, input_str):
        '''Check mgmt l2out network syntax'''

        self.check_l2_out_4tor(input_str, 'mgmt_l2out_network')
        if input_str:
            self.mgmt_l2out_network_tor = 1
        return

    def check_api_l2out_network_4tor(self, input_str):
        '''Check api l2out network syntax'''

        self.check_l2_out_4tor(input_str, 'api_l2out_network')

        if input_str is True:
            self.api_l2out_network_tor = 1

        return

    def check_prov_l2out_network_4tor(self, input_str):
        '''Check prov l2out network syntax'''

        self.check_l2_out_4tor(input_str, 'prov_l2out_network')
        if input_str is True:
            self.prov_l2out_network_tor = 1

        return

    def check_ext_l2out_network_4tor(self, input_str):
        '''Check external l2out network syntax'''

        self.check_l2_out_4tor(input_str, 'ext_l2out_network')
        if input_str is True:
            self.ext_l2out_network_tor = 1

        return

    def check_l2_out_4tor(self, input_str, segment_name):
        '''Check the L2out  4 tors'''

        if not isinstance(input_str, bool):
            err_str = "Input has to be of type bool"
            raise Invalid(err_str)

        if input_str is True:
            mgmt_l2_out = ['APICINFO', segment_name]

            mgmt_l2_out_chk = \
                self.ymlhelper.get_deepdata_from_userinput_file(mgmt_l2_out)

            if mgmt_l2_out_chk is None:
                err_msg = "%s information is missing in " \
                    "APICINFO section" % (segment_name)
                raise Invalid(err_msg)
        return

    def check_torswitch_aci_input(self, input_str):
        '''Checks the schema of torswitch'''

        switch_list = []
        hostname_list = []
        err_list = []
        peer_switch = {}
        conflicting_vpc_peer_keepalive = []
        vpc_peer_keepalive_list = []
        node_id_list = []

        torswitch_vpc_schema = Schema({
            Required('hostname'): self.is_input_in_plain_str_len32,
            Required('vpc_peer_keepalive'): self.aci_vpc_peer_keepalive_check,
            Required('vpc_domain'): All(int, Range(min=1, max=256)),
            Optional('br_mgmt_port_info'): self.is_eth_port_info_valid,
            Required('node_id'): All(int, Range(min=1, max=65535)),
            Optional('mgmt_l2out_network'): self.check_mgmt_l2out_network_4tor,
            Optional('api_l2out_network'): self.check_api_l2out_network_4tor,
            Optional('prov_l2out_network'): self.check_prov_l2out_network_4tor,
            Optional('ext_l2out_network'): self.check_ext_l2out_network_4tor,
        })

        switch_info_count = 0
        # check syntax
        invalid_input_list = []
        for key in input_str:
            if re.search(r'SWITCHDETAILS', key):
                switchdetails = input_str.get('SWITCHDETAILS')
                for item in switchdetails:
                    try:
                        switch_info_count += 1
                        switch_list.append(item.get('hostname'))
                        torswitch_vpc_schema(item)
                    except MultipleInvalid as e:
                        for x in e.errors:
                            tmp = str(item.get('hostname')) + ":" + str(x)
                            err_list.append(str(tmp))
            else:
                invalid_input_list.append(key)

        missing_key_kist = []
        if invalid_input_list:
            err_str = "Extra Keys %s in TORSWITCHINFO section" \
                % (','.join(invalid_input_list))
            missing_key_kist.append(err_str)

        err_str_list = []
        switchdetails = input_str.get('SWITCHDETAILS')
        if switchdetails is None:
            err_str = "SWITCHDETAILS section not defined"
            missing_key_kist.append(err_str)

        if missing_key_kist:
            err_str = ' '.join(missing_key_kist)
            raise Invalid(err_str)

        if err_list:
            err_str = ' '.join(err_list)
            raise Invalid(err_str)

        # Get the peer info and hostname info and look for conflicts
        for item in switchdetails:
            node_id_list.append(str(item.get('node_id')))
            hostname_list.append(item.get('hostname'))

            if item.get('vpc_peer_keepalive') is not None and \
                    item.get('hostname') == item.get('vpc_peer_keepalive'):
                conflicting_vpc_peer_keepalive.append( \
                    item.get('vpc_peer_keepalive'))
                vpc_peer_keepalive_list.append(item.get('vpc_peer_keepalive'))

        dup_vpc_peer_keepalive_list = \
            self.get_duplicate_entry_in_list(vpc_peer_keepalive_list)
        dup_node_id_list = self.get_duplicate_entry_in_list(node_id_list)
        dup_hostname_list = self.get_duplicate_entry_in_list(hostname_list)

        if dup_hostname_list:
            err_str = "Duplicate Switch hostname listed: " + \
                      ', '.join(dup_hostname_list)
            err_str_list.append(err_str)

        if dup_node_id_list:
            err_str = "Duplicate node_id listed: " + \
                      ', '.join(dup_node_id_list)
            err_str_list.append(err_str)

        if vpc_peer_keepalive_list and \
                dup_vpc_peer_keepalive_list:
            err_str = "Duplicate vpc_peer_keepalive listed: " + \
                      ', '.join(dup_vpc_peer_keepalive_list)
            err_str_list.append(err_str)

        if conflicting_vpc_peer_keepalive:
            err_str = "Conflicting Switch hostname and VPC Peer Info: " + \
                      ', '.join(conflicting_vpc_peer_keepalive)
            err_str_list.append(err_str)

        if err_str_list:
            raise Invalid('; '.join(err_str_list))

        # Get the peer switch info
        for item in switchdetails:
            curr_peer_hn = item.get('vpc_peer_keepalive')
            for item2 in switchdetails:
                if curr_peer_hn and \
                        curr_peer_hn == item2.get('hostname'):
                    peer_switch[item.get('hostname')] = item2.get('hostname')

        mismatch_peer_swt_info = []
        matching_peer_swt_info = []
        mismatch_vpc_info = []
        mismatch_br_mgmt_port_info = []
        non_peer_swt_list = []
        missing_peer_switch_info = []
        incorrect_br_mgmt_port_info = []

        info_found_at_peer = 0
        num_br_mgmt_port_info = 0

        num_api_l2_network = 0
        num_prov_l2_network = 0
        num_ext_l2_network = 0
        num_mgmt_l2_network = 0

        prov_l2out_info_found_at_peer = 0
        ext_l2out_info_found_at_peer = 0
        mgmt_l2out_info_found_at_peer = 0
        api_l2out_info_found_at_peer = 0

        mismatch_prov_l2out_network = []
        mismatch_ext_l2out_network = []
        mismatch_api_l2out_network = []
        mismatch_mgmt_l2out_network = []

        # Check if peer switch info cross-match
        for swt in switch_list:
            if swt in peer_switch.keys():

                curr_peer_swt = peer_switch.get(swt)
                remote_peer_swt = peer_switch.get(curr_peer_swt)

                if remote_peer_swt is None:
                    missing_peer_switch_info.append(curr_peer_swt)

                elif swt != remote_peer_swt:
                    mismatch_peer_swt = swt + ":" + curr_peer_swt
                    mismatch_peer_swt_rev = curr_peer_swt + ":" + swt

                    if mismatch_peer_swt not in mismatch_peer_swt_info and \
                            mismatch_peer_swt_rev not in mismatch_peer_swt_info:
                        mismatch_peer_swt_info.append(mismatch_peer_swt)
                else:
                    matching_peer_swt = swt + ":" + curr_peer_swt
                    matching_peer_swt_rev = curr_peer_swt + ":" + swt

                    if matching_peer_swt not in matching_peer_swt_info and \
                            matching_peer_swt_rev not in matching_peer_swt_info:
                        matching_peer_swt_info.append(matching_peer_swt)
            else:
                non_peer_swt_list.append(swt)

        if non_peer_swt_list:
            err_str = "Standalone Switch in ACI setup not allowed:" + \
                      ', '.join(non_peer_swt_list)
            err_str_list.append(err_str)

        if missing_peer_switch_info:
            err_str = "Missing Peer Switch Info:" + \
                      ', '.join(missing_peer_switch_info)
            err_str_list.append(err_str)

        if err_str_list:
            raise Invalid('; '.join(err_str_list))

        # For all peer switches ensure that all entries match
        for item in matching_peer_swt_info:
            switch_info = item.split(":")
            curr_swt_info = switch_info[0]
            remote_swt_info = switch_info[1]
            curr_swt_details = {}
            rmt_swt_det = {}
            found_curr_swt = 0
            found_rmt_swt = 0
            curr_num_br_mgmt_swt_port = 0
            remote_num_br_mgmt_swt_port = 0

            for entry in switchdetails:

                if curr_swt_info == entry.get('hostname'):
                    try:
                        torswitch_vpc_schema(entry)
                    except MultipleInvalid as e:
                        for x in e.errors:
                            tmp = str(entry.get('hostname')) + ":" + str(x)
                            err_list.append(str(tmp))

                if curr_swt_info == entry.get('hostname'):
                    found_curr_swt = 1

                    if entry.get('br_mgmt_port_info') is not None:
                        curr_info = entry.get('br_mgmt_port_info')
                        if re.search(',', curr_info):
                            tmp = str(curr_swt_info) + ":" + curr_info
                            incorrect_br_mgmt_port_info.append(tmp)

                        curr_num_br_mgmt_swt_port = \
                            len((entry.get('br_mgmt_port_info')).split(" "))
                        num_br_mgmt_port_info += 1
                        info_found_at_peer = 1

                    curr_swt_details['vpc_domain'] = entry.get('vpc_domain')

                    if entry.get('api_l2out_network') is not None \
                            and entry.get('api_l2out_network') is True:
                        num_api_l2_network += 1
                        api_l2out_info_found_at_peer = 1
                        curr_swt_details['api_l2out_network'] = \
                            entry.get('api_l2out_network')

                    if entry.get('mgmt_l2out_network') is not None \
                            and entry.get('mgmt_l2out_network') is True:
                        num_mgmt_l2_network += 1
                        mgmt_l2out_info_found_at_peer = 1
                        curr_swt_details['mgmt_l2out_network'] = \
                            entry.get('mgmt_l2out_network')

                    if entry.get('ext_l2out_network') is not None \
                            and entry.get('ext_l2out_network') is True:
                        num_ext_l2_network += 1
                        ext_l2out_info_found_at_peer = 1
                        curr_swt_details['ext_l2out_network'] = \
                            entry.get('ext_l2out_network')

                    if entry.get('prov_l2out_network') is not None \
                            and entry.get('prov_l2out_network') is True:
                        num_prov_l2_network += 1
                        prov_l2out_info_found_at_peer = 1
                        curr_swt_details['prov_l2out_network'] = \
                            entry.get('prov_l2out_network')

                if remote_swt_info == entry.get('hostname'):
                    found_rmt_swt = 1

                    if entry.get('br_mgmt_port_info') is not None:
                        curr_info = entry.get('br_mgmt_port_info')
                        if re.search(',', curr_info):
                            tmp = str(remote_swt_info) + ":" + curr_info
                            incorrect_br_mgmt_port_info.append(tmp)

                        remote_num_br_mgmt_swt_port = \
                            len((entry.get('br_mgmt_port_info')).split(" "))
                        num_br_mgmt_port_info += 1
                        info_found_at_peer = 1

                    rmt_swt_det['vpc_domain'] = entry.get('vpc_domain')
                    if entry.get('api_l2out_network') is not None \
                            and entry.get('api_l2out_network') is True:
                        num_api_l2_network += 1
                        api_l2out_info_found_at_peer = 1
                        rmt_swt_det['api_l2out_network'] = \
                            entry.get('api_l2out_network')

                    if entry.get('mgmt_l2out_network') is not None \
                            and entry.get('mgmt_l2out_network') is True:
                        num_mgmt_l2_network += 1
                        mgmt_l2out_info_found_at_peer = 1
                        rmt_swt_det['mgmt_l2out_network'] = \
                            entry.get('mgmt_l2out_network')

                    if entry.get('ext_l2out_network') is not None \
                            and entry.get('ext_l2out_network') is True:
                        num_ext_l2_network += 1
                        ext_l2out_info_found_at_peer = 1
                        rmt_swt_det['ext_l2out_network'] = \
                            entry.get('ext_l2out_network')

                    if entry.get('prov_l2out_network') is not None \
                            and entry.get('prov_l2out_network') is True:
                        num_prov_l2_network += 1
                        prov_l2out_info_found_at_peer = 1
                        rmt_swt_det['prov_l2out_network'] = \
                            entry.get('prov_l2out_network')

                if found_curr_swt and found_rmt_swt:

                    if curr_swt_details['vpc_domain'] != \
                            rmt_swt_det['vpc_domain']:
                        mismatch_vpc_info.append(item)

                    # check if the num of br_mgmt_port_info entry are the same
                    if curr_num_br_mgmt_swt_port != remote_num_br_mgmt_swt_port:
                        mismatch_br_mgmt_port_info.append(item)

                    if curr_swt_details.get('prov_l2out_network') != \
                            rmt_swt_det.get('prov_l2out_network'):
                        mismatch_prov_l2out_network.append(item)

                    if curr_swt_details.get('api_l2out_network') != \
                            rmt_swt_det.get('api_l2out_network'):
                        mismatch_api_l2out_network.append(item)

                    if curr_swt_details.get('ext_l2out_network') != \
                            rmt_swt_det.get('ext_l2out_network'):
                        mismatch_ext_l2out_network.append(item)

                    if curr_swt_details.get('mgmt_l2out_network') != \
                            rmt_swt_det.get('mgmt_l2out_network'):
                        mismatch_mgmt_l2out_network.append(item)
                    break

        if err_list:
            raise Invalid('; '.join(err_list))

        err_str_list = []

        if not info_found_at_peer:
            err_str = "br_mgmt related info absent on TOR switch"
            raise Invalid(err_str)
        else:
            match_info = 2

        if num_br_mgmt_port_info != match_info:
            err_str = "%s entrie(s) for br_mgmt_port_info needs to " \
                "be present; found: %s for AUTO TOR Configuration" \
                % (str(match_info), str(num_br_mgmt_port_info))
            err_str_list.append(err_str)

        if prov_l2out_info_found_at_peer and num_prov_l2_network != 2:
            err_str = "2 entrie(s) for prov_l2out_network needs to " \
                "be present; found: %s for AUTO TOR Configuration" \
                % (str(num_prov_l2_network))
            err_str_list.append(err_str)

        if ext_l2out_info_found_at_peer and num_ext_l2_network != 2:
            err_str = "2 entrie(s) for ext_l2out_network needs to " \
                "be present; found: %s for AUTO TOR Configuration" \
                % (str(num_ext_l2_network))
            err_str_list.append(err_str)

        if mgmt_l2out_info_found_at_peer and num_mgmt_l2_network != 2:
            err_str = "2 entrie(s) for mgmt_l2out_network needs to " \
                "be present; found: %s for AUTO TOR Configuration" \
                % (str(num_mgmt_l2_network))
            err_str_list.append(err_str)

        if api_l2out_info_found_at_peer and num_api_l2_network != 2:
            err_str = "2 entrie(s) for api_l2out_network needs to " \
                "be present; found: %s for AUTO TOR Configuration" \
                % (str(num_api_l2_network))
            err_str_list.append(err_str)

        if err_str_list:
            raise Invalid('; '.join(err_str_list))

        if incorrect_br_mgmt_port_info:
            err_str = "More than 1 br_mgmt_port_info found for :" + \
                      ', '.join(incorrect_br_mgmt_port_info)
            err_str_list.append(err_str)

        if mismatch_peer_swt_info:
            err_str = "Mismatch Peer Switch Info:" + \
                      ', '.join(mismatch_peer_swt_info)
            err_str_list.append(err_str)

        if mismatch_vpc_info:
            err_str = "Mismatch vpc domain between VPC peers:" + \
                      ', '.join(mismatch_vpc_info)
            err_str_list.append(err_str)

        if mismatch_br_mgmt_port_info:
            err_str = "Unequal Number of br_mgmt Port List between VPC peers:" + \
                      ', '.join(mismatch_br_mgmt_port_info)
            err_str_list.append(err_str)

        if err_str_list:
            raise Invalid('; '.join(err_str_list))

        return

    def is_tor_type_ncs5500(self):
        '''Check if TOR is NCS 5500'''

        torswitchinfo = \
            self.ymlhelper.get_data_from_userinput_file(['TORSWITCHINFO'])

        if torswitchinfo is None:
            return 0

        tor_type = torswitchinfo.get('TOR_TYPE')

        if tor_type is None:
            return 0

        if tor_type == 'NCS-5500':
            return 1

        return 0

    def get_num_ncs5500_tor(self):
        '''Check if TOR is NCS 5500'''

        torswitchinfo = \
            self.ymlhelper.get_data_from_userinput_file(['TORSWITCHINFO'])

        if torswitchinfo is None:
            return 0

        tor_type = torswitchinfo.get('TOR_TYPE')

        if tor_type is None:
            return 0

        if tor_type == 'NCS-5500':
            switchdetails = torswitchinfo.get('SWITCHDETAILS')
            if switchdetails is None:
                return 0

            return len(switchdetails)

        return 0

    def is_msr_routing_info_defined(self):
        '''Is routing info defined'''

        msr_routing_info = \
            self.ymlhelper.get_data_from_userinput_file(\
                ['MULTI_SEGMENT_ROUTING_INFO'])

        if msr_routing_info is None:
            return 0

        return 1

    def check_isis_netid_syntax(self, input_str):
        '''check_isis_netid_syntax'''

        err_str = "ISIS NET info is missing"
        if input_str is None:
            raise Invalid(err_str)
        hex_pat = re.compile(r'([0-9A-F]+)?', re.I | re.S | re.M)
        netid_pieces = input_str.split(".")
        netid_len = len(netid_pieces)
        if netid_pieces[netid_len - 1] != "00":
            err_msg = "ISIS NET info has to end with .00; " \
                "Found to be %s" % (netid_pieces[netid_len - 1])
            raise Invalid(err_msg)

        for netid_item in netid_pieces:
            m = re.search(hex_pat, netid_item)
            if not m:
                err_msg = "All parts of ISIS NET info has to be in hex format;  " \
                    "Found to be:%s" % (input_str)
                raise Invalid(err_msg)

        return

    def check_ironic_torswitch_input(self, input_str):
        '''Checks the schema of ironic torswitch'''

        switch_info_count = 0
        switch_hostname_list = []
        switch_ssh_ip_list = []
        switch_type_list = []

        err_list = []

        ironic_torswitch_nxos_schema = Schema({
            Required('hostname'): self.is_input_in_plain_str_len32,
            Required('username'): self.is_input_in_plain_str_len32,
            Required('password'): self.check_password_syntax,
            Required('ssh_ip'): self.is_ip_syntax_valid,
            Required('switch_type'): In(frozenset(["NCS", \
                "Nexus", "ACI", "BypassNeutron"]), \
                msg='only NCS-5500, Nexus, ACI or BypassNeutron is allowed'),
            Optional('switch_ports'): str,
        })

        ironic_torswitch_nonswitch_schema = Schema({
            Required('switch_type'): In(frozenset(["NCS", \
                "Nexus", "ACI", "BypassNeutron"]), \
                msg='only NCS-5500, Nexus, ACI or BypassNeutron is allowed'),
        })

        if not isinstance(input_str, list):
            err_str = "entry has to be of type list"
            raise Invalid(err_str)

        found_non_nexus = 0
        for item in input_str:
            try:
                curr_swt_type = item.get('switch_type')
                if curr_swt_type == 'Nexus':
                    ironic_torswitch_nxos_schema(item)
                else:
                    found_non_nexus = 1
                    ironic_torswitch_nonswitch_schema(item)

                switch_info_count += 1
                curr_hostname = item.get('hostname')
                curr_ssh_ip = item.get('ssh_ip')

                switch_hostname_list.append(curr_hostname)
                switch_ssh_ip_list.append(curr_ssh_ip)
                switch_type_list.append(curr_swt_type)

            except MultipleInvalid as e:
                for x in e.errors:
                    tmp = str(item.get('hostname')) + ":" + str(x)
                    err_list.append(str(tmp))

        if len(switch_type_list) > 1:
            if len(set(switch_type_list)) != 1:
                err_str = "Expecting identical Ironic switch types " \
                    "setup_data.yaml. Current found to be different %s" \
                    % (','.join(switch_type_list))
                err_list.append(err_str)

        if len(switch_type_list) > 1 and found_non_nexus:
            err_str = "List of 1 entry allowed for non Nexus option"
            err_list.append(err_str)

        if not found_non_nexus:
            dup_tor_switch_info = \
                self.check_for_dups_in_list(switch_hostname_list)
            if dup_tor_switch_info:
                err_str = "Repeating Ironic Switch Hostname setup_data.yaml: %s" \
                    % (','.join(dup_tor_switch_info))
                err_list.append(err_str)

            dup_tor_ssh_info = \
                self.check_for_dups_in_list(switch_ssh_ip_list)
            if dup_tor_ssh_info:
                err_str = "Repeating Ironic Switch SSH IP setup_data.yaml: %s" \
                          % (','.join(dup_tor_ssh_info))
                err_list.append(err_str)

        if err_list:
            err_str = ','.join(err_list)
            raise Invalid(err_str)

        return

    def check_tor_hostname_syntax(self, input_str):
        '''Tor switch cant have _'''

        self.is_input_in_plain_str_len32(input_str)
        if re.search(r'_', input_str):
            err_str = "hostname cannot have underscore in it"
            raise Invalid(err_str)
        return

    def l3_fabric_loopback_check(self, input_str):
        """Check that entry is Loopback"""

        self.is_input_in_plain_str(input_str)
        pattern = "^loopback[0-9]+$"
        err_msg = "ERROR: expected input is of type loopback[int], " \
            "found to be %s" % input_str

        if not re.search(pattern, input_str, re.IGNORECASE):
            raise Invalid(err_msg)

    def check_torswitch_input(self, input_str):
        '''Checks the schema of torswitch'''

        switch_list = []
        ssh_ip_list = []
        ssh_ip_peer_list = []
        hostname_list = []
        err_list = []
        peer_switch = {}
        dup_ssh_ip_peer_list = []
        conflicting_sship_with_peer_ip = []

        configure_tor_check_schema = Schema({
            Required('CONFIGURE_TORS'): All(Boolean(str), \
                                            msg="Only Boolean value True/False"),
        }, extra=True)

        manage_lacp_check_schema = Schema({
            Required('MANAGE_LACP'): All(Boolean(str), \
                                            msg="Only Boolean value True/False"),
        }, extra=True)

        tor_custom_check_schema = Schema({
            Optional('CUSTOM_CONFIG'): self.check_switch_custom_config,
        }, extra=True)

        tor_type_schema = Schema({
            Optional('TOR_TYPE'): In(frozenset(["NCS-5500", "Nexus"]),
                                     msg='only NCS-5500 or Nexus is allowed, ' \
                                         'defaults to Nexus'),
        })

        torswitch_pc_schema = Schema({
            Required('hostname'): self.check_tor_hostname_syntax,
            Required('username'): self.is_input_in_plain_str_len32,
            Required('password'): self.check_password_syntax,
            Required('ssh_ip'): self.is_ip_syntax_valid,
            Optional('ssn_num'): self.is_input_in_plain_str_len32,
            Optional('tenant_ip'): self.is_ip_syntax_valid,
            Optional('br_mgmt_port_info'): self.is_eth_port_info_valid,
            Optional('br_mgmt_po_info'): All(int, Range(min=1, max=256)),
        })

        torswitch_schema = torswitch_pc_schema.extend({
            Optional('vpc_peer_keepalive'): self.is_ip_syntax_valid,
            Optional('vpc_domain'): All(int, Range(min=1, max=256)),
            Optional('vpc_peer_port_info'): self.is_eth_port_info_valid,
            Optional('vpc_peer_vlan_info'): self.is_vlan_list_valid,
        })

        torswitch_l3_fabric_schema = torswitch_schema.extend({
            Required('l3_fabric_loopback'): self.l3_fabric_loopback_check,
        })

        torswitch_vpc_schema = torswitch_pc_schema.extend({
            Required('vpc_peer_keepalive'): self.is_ip_syntax_valid,
            Required('vpc_domain'): All(int, Range(min=1, max=256)),
            Required('vpc_peer_port_info'): self.is_eth_port_info_valid,
            Optional('vpc_peer_vlan_info'): self.is_vlan_list_valid,
        })

        torswitch_vpc_l3_fabric_schema = torswitch_vpc_schema.extend({
            Required('l3_fabric_loopback'): self.l3_fabric_loopback_check,
        })

        torswitch_fretta_pc_schema = Schema({
            Required('hostname'): self.check_tor_hostname_syntax,
            Required('username'): self.is_input_in_plain_str_len32,
            Required('password'): self.check_password_syntax,
            Required('ssh_ip'): self.is_ip_syntax_valid,
            Optional('ssn_num'): self.is_input_in_plain_str_len32,
            Optional('tenant_ip'): self.is_ip_syntax_valid,
            Required('br_mgmt_port_info'): self.is_eth_port_info_valid,
            Required('br_mgmt_po_info'): All(int, Range(min=1, max=256)),
            Optional('splitter_opt_4_10'): self.check_splitter_cable_option,
        })

        torswitch_fretta_vpc_schema = torswitch_fretta_pc_schema.extend({
            Required('vpc_peer_keepalive'): self.is_ip_syntax_valid,
            Required('vpc_peer_port_info'): self.is_eth_port_info_valid,
            Required('vpc_peer_port_address'): self.validate_vpc_peer_port_address,
            Required('isis_loopback_addr'): self.is_ip_syntax_valid,
            Required('isis_net_entity_title'): self.check_isis_netid_syntax,
            Optional('isis_prefix_sid'): All(int, Range(min=16000, max=1048575)),
        })

        torswitch_fretta_pc_mpls_plugin_schema = torswitch_fretta_pc_schema.extend({
            Required('grpc_username'): self.is_input_in_plain_str_len32,
            Required('grpc_password'): self.check_password_syntax,
            Required('grpc_port'): All(int, Range(min=57344, max=57999)),
            Required('grpc_timeout'): All(int, Range(min=5, max=30)),
            Optional('splitter_opt_4_10'): self.check_splitter_cable_option,
        })

        torswitch_fretta_vpc_mpls_plugin_schema = \
            torswitch_fretta_vpc_schema.extend({
                Required('grpc_username'): self.is_input_in_plain_str_len32,
                Required('grpc_password'): self.check_password_syntax,
                Required('grpc_port'): All(int, Range(min=57344, max=57999)),
                Required('grpc_timeout'): All(int, Range(min=5, max=30)),
                Optional('splitter_opt_4_10'): self.check_splitter_cable_option,
            })

        switch_info_count = 0
        isis_prefix_sid_present = 0
        found_tor_type = "UNDEFINED"
        # check syntax
        for key in input_str:
            if re.search(r'CONFIGURE_TORS', key):

                try:
                    tmp_dir = {}
                    tmp_dir[key] = input_str[key]

                    configure_tor_check_schema(tmp_dir)
                    if input_str[key]:
                        self.configure_tor = 1
                except MultipleInvalid as e:
                    for x in e.errors:
                        tmp = key + ":" + str(x)
                        err_list.append(str(tmp))
                    if err_list:
                        err_str = ' '.join(err_list)
                        raise Invalid(err_str)
            elif re.search(r'MANAGE_LACP', key):
                try:
                    tmp_dir = {}
                    tmp_dir[key] = input_str[key]

                    manage_lacp_check_schema(tmp_dir)
                    if input_str[key]:
                        self.manage_lacp = 1
                except MultipleInvalid as e:
                    for x in e.errors:
                        tmp = key + ":" + str(x)
                        err_list.append(str(tmp))
                    if err_list:
                        err_str = ' '.join(err_list)
                        raise Invalid(err_str)

            elif re.search(r'TOR_TYPE', key):
                try:
                    tmp_dir = {}
                    tmp_dir[key] = input_str[key]
                    tor_type_schema(tmp_dir)
                    found_tor_type = tmp_dir[key]
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))
                    if err_list:
                        err_str = ' '.join(err_list)
                        raise Invalid(err_str)
            elif re.search(r'CUSTOM_CONFIG', key):
                try:
                    tmp_dir[key] = input_str[key]
                    tor_custom_check_schema(tmp_dir)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))
                    if err_list:
                        err_str = ' '.join(err_list)
                        raise Invalid(err_str)
            elif re.search(r'SWITCHDETAILS', key):
                switchdetails = input_str.get('SWITCHDETAILS')
                for item in switchdetails:
                    try:
                        switch_info_count += 1
                        if self.configure_tor or self.is_vmtp_vts_present():
                            if self.is_tor_type_ncs5500():
                                if self.get_num_ncs5500_tor() == 2:
                                    if self.cd_cfgmgr.is_network_option_enabled(\
                                            'l3vpn'):
                                        torswitch_fretta_vpc_mpls_plugin_schema(item)
                                    else:
                                        torswitch_fretta_vpc_schema(item)
                                        if item.get('isis_prefix_sid') is not None:
                                            isis_prefix_sid_present = 1
                                else:
                                    if self.cd_cfgmgr.is_network_option_enabled(\
                                            'l3vpn'):
                                        torswitch_fretta_pc_mpls_plugin_schema(item)
                                    else:
                                        torswitch_fretta_pc_schema(item)
                                        if item.get('isis_prefix_sid') is not None:
                                            isis_prefix_sid_present = 1
                            else:
                                if self.cd_cfgmgr.is_l3_fabric_enabled():
                                    torswitch_l3_fabric_schema(item)
                                else:
                                    torswitch_schema(item)
                            switch_list.append(item.get('hostname'))
                        else:
                            if self.is_tor_type_ncs5500():
                                if self.get_num_ncs5500_tor() == 2:
                                    if self.cd_cfgmgr.is_network_option_enabled(\
                                            'l3vpn'):
                                        torswitch_fretta_vpc_mpls_plugin_schema(item)
                                    else:
                                        torswitch_fretta_vpc_schema(item)
                                        if item.get('isis_prefix_sid') is not None:
                                            isis_prefix_sid_present = 1
                                else:
                                    if self.cd_cfgmgr.is_network_option_enabled(\
                                            'l3vpn'):
                                        torswitch_fretta_pc_mpls_plugin_schema(item)
                                    else:
                                        torswitch_fretta_pc_schema(item)
                                        if item.get('isis_prefix_sid') is not None:
                                            isis_prefix_sid_present = 1
                            else:
                                torswitch_schema(item)
                    except MultipleInvalid as e:
                        for x in e.errors:
                            tmp = str(item.get('hostname')) + ":" + str(x)
                            err_list.append(str(tmp))
            else:
                err_str = "Unknown %s in TORSWITCHINFO section" % (key)
                raise Invalid(err_str)

        if err_list:
            err_str = ' '.join(err_list)
            raise Invalid(err_str)

        err_str_list = []
        if self.cd_cfgmgr.is_l3_fabric_enabled() and not self.configure_tor:
            err_msg = "CONFIGURE_TORS has to be true for l3_fabric support"
            raise Invalid(err_msg)

        if found_tor_type == 'NCS-5500':
            esi_prefix_present = \
                self.ymlhelper.get_data_from_userinput_file(["ESI_PREFIX"])
            # if esi_prefix_present is not None and isis_prefix_sid_present:
            #    err_msg = "ESI_PREFIX and isis_prefix_sid info should not co-exist"
            #    raise Invalid(err_msg)
            if esi_prefix_present is None and not isis_prefix_sid_present:
                err_msg = "isis_prefix_sid not defined"
                raise Invalid(err_msg)

            self.check_tenant_vlan_range()
            if not self.configure_tor and not self.manage_lacp:
                err_msg = "CONFIGURE_TORS or MANAGE_LACP has to be true " \
                    "for NCS-5500 TOR support"
                raise Invalid(err_msg)

            if re.match(r'UCSM', self.testbed_type):
                err_msg = "NCS-5500 as TOR not supported for B-series testbed"
                raise Invalid(err_msg)

            if switch_info_count > 2:
                err_msg = "Max of 2 NCS-5500 TOR supported on a given testbed"
                raise Invalid(err_msg)

            if switch_info_count == 2 and not self.is_msr_routing_info_defined():
                err_msg = "MULTI_SEGMENT_ROUTING_INFO section not defined. " \
                    " It is a must to support 2 NCS-5500 TOR on a given testbed"
                raise Invalid(err_msg)

            if switch_info_count == 1 and self.is_msr_routing_info_defined():
                err_msg = "MULTI_SEGMENT_ROUTING_INFO section defined. " \
                    "It is a must to support 2 NCS-5500 TOR on a given testbed; " \
                    "current testbed has 1 NCS-5500"
                raise Invalid(err_msg)

            mechanism_driver = \
                self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
            if mechanism_driver != 'vpp':
                err_msg = "NCS-5500 as TOR supported only for VPP as " \
                    "mechanism_driver"
                raise Invalid(err_msg)

        else:
            if self.manage_lacp:
                err_msg = "MANAGE_LACP option is allowed when ToR is NCS-5500"
                raise Invalid(err_msg)

        switchdetails = input_str.get('SWITCHDETAILS')
        if switchdetails is None:
            err_str = "SWITCHDETAILS section not defined"
            raise Invalid(err_str)

        if re.match(r'UCSM', self.testbed_type) \
                and switch_info_count > 2:
            err_str = "Max TOR switch allowed for B-series pod is 2; " \
                "found %s" % (switch_info_count)
            raise Invalid(err_str)

        if err_list:
            err_str = ' '.join(err_list)
            raise Invalid(err_str)

        # Get the SSH and hostname info and look for conflicts
        for item in switchdetails:
            ssh_ip_list.append(item.get('ssh_ip'))
            hostname_list.append(item.get('hostname'))

            if item.get('vpc_peer_keepalive') is not None and \
                    item.get('ssh_ip') == item.get('vpc_peer_keepalive'):
                conflicting_sship_with_peer_ip.append( \
                    item.get('vpc_peer_keepalive'))
                ssh_ip_peer_list.append(item.get('vpc_peer_keepalive'))

        dup_ssh_ip_list = self.get_duplicate_entry_in_list(ssh_ip_list)
        dup_hostname_list = self.get_duplicate_entry_in_list(hostname_list)

        if dup_hostname_list:
            err_str = "Duplicate Switch hostname listed: " + \
                      ', '.join(dup_hostname_list)
            err_str_list.append(err_str)

        if ssh_ip_peer_list:
            dup_ssh_ip_peer_list = self.get_duplicate_entry_in_list(ssh_ip_peer_list)

        if dup_ssh_ip_list:
            err_str = "Duplicate Switch SSH IP listed: " + \
                      ', '.join(dup_ssh_ip_list)
            err_str_list.append(err_str)

        if ssh_ip_peer_list and dup_ssh_ip_peer_list:
            err_str = "Duplicate IP listed for vpc_peer_keepalive: " + \
                      ', '.join(dup_ssh_ip_peer_list)
            err_str_list.append(err_str)

        if conflicting_sship_with_peer_ip:
            err_str = "Conflicting Switch SSH IP and VPC Peer IP: " + \
                      ', '.join(conflicting_sship_with_peer_ip)
            err_str_list.append(err_str)

        if self.manage_lacp and self.configure_tor:
            err_str = "Both MANAGE_LACP and CONFIGURE_TOR cannot be " \
                "true at the same time"
            err_str_list.append(err_str)

        if err_str_list:
            raise Invalid('; '.join(err_str_list))

        # Get the peer switch info
        for item in switchdetails:
            curr_peer_ip = item.get('vpc_peer_keepalive')
            for item2 in switchdetails:
                if curr_peer_ip is not None and \
                        curr_peer_ip == item2.get('ssh_ip'):
                    peer_switch[item.get('hostname')] = item2.get('hostname')

        if self.is_vmtp_vts_present():
            pass
        elif not self.configure_tor:
            return

        mismatch_peer_swt_info = []
        matching_peer_swt_info = []
        mismatch_vpc_info = []
        mismatch_vpc_port_info = []
        mismatch_br_mgmt_port_info = []
        incorrect_br_mgmt_port_info = []
        mismatch_vpc_peer_vlan_info = []
        mismatch_br_mgmt_po_info = []
        missing_vpc_peer_vlan_info = []
        excluded_vpc_peer_vlan_info = []
        non_peer_swt_list = []
        mismatch_l3_fabric_loopback_info = []

        info_found_at_non_peer = 0
        info_found_at_peer = 0
        num_br_mgmt_po_info = 0
        num_br_mgmt_port_info = 0

        # Check if peer switch info cross-match
        for swt in switch_list:
            if swt in peer_switch.keys():
                curr_peer_swt = peer_switch[swt]
                remote_peer_swt = peer_switch[curr_peer_swt]

                if swt != remote_peer_swt:
                    mismatch_peer_swt = swt + ":" + curr_peer_swt
                    mismatch_peer_swt_rev = curr_peer_swt + ":" + swt

                    if mismatch_peer_swt not in mismatch_peer_swt_info and \
                            mismatch_peer_swt_rev not in mismatch_peer_swt_info:
                        mismatch_peer_swt_info.append(mismatch_peer_swt)
                else:
                    matching_peer_swt = swt + ":" + curr_peer_swt
                    matching_peer_swt_rev = curr_peer_swt + ":" + swt

                    if matching_peer_swt not in matching_peer_swt_info and \
                            matching_peer_swt_rev not in matching_peer_swt_info:
                        matching_peer_swt_info.append(matching_peer_swt)
            else:
                non_peer_swt_list.append(swt)

        # For all peer switches ensure that all entries match
        for item in non_peer_swt_list:
            for entry in switchdetails:
                curr_num_br_mgmt_np_swt_port = 0
                if item == entry.get('hostname'):
                    try:
                        if found_tor_type == 'NCS-5500':
                            if self.cd_cfgmgr.is_network_option_enabled('l3vpn'):
                                torswitch_fretta_pc_mpls_plugin_schema(item)
                            else:
                                torswitch_fretta_pc_schema(entry)
                        else:
                            torswitch_pc_schema(entry)

                        if entry.get('br_mgmt_port_info') is not None:
                            num_br_mgmt_port_info += 1
                            info_found_at_non_peer = 1
                            curr_num_br_mgmt_np_swt_port = \
                                len((entry.get('br_mgmt_port_info')).split(","))

                        if entry.get('br_mgmt_po_info') is not None:
                            num_br_mgmt_po_info += 1
                            info_found_at_non_peer = 1

                    except MultipleInvalid as e:
                        for x in e.errors:
                            tmp = str(entry.get('hostname')) + ":" + str(x)
                            err_list.append(str(tmp))

                    if curr_num_br_mgmt_np_swt_port:
                        if curr_num_br_mgmt_np_swt_port != 2:
                            err_msg = "Number of br_mgmt_port_info for %s " \
                                "needs to be 2, found to be %s" \
                                % (item, curr_num_br_mgmt_np_swt_port)
                            incorrect_br_mgmt_port_info.append(err_msg)

        if err_list:
            raise Invalid('; '.join(err_list))

        # For all peer switches ensure that all entries match
        for item in matching_peer_swt_info:
            switch_info = item.split(":")
            curr_swt_info = switch_info[0]
            remote_swt_info = switch_info[1]
            curr_swt_details = {}
            rmt_swt_det = {}

            found_curr_swt = 0
            found_rmt_swt = 0
            curr_num_vpc_swt_port = 0
            remote_num_vpc_swt_port = 0
            curr_num_br_mgmt_swt_port = 0
            remote_num_br_mgmt_swt_port = 0

            for entry in switchdetails:
                info_found_at_peer = 0
                if (self.configure_tor or self.is_vmtp_vts_present()) \
                        and curr_swt_info == entry.get('hostname'):
                    try:
                        if found_tor_type == 'NCS-5500':
                            if self.cd_cfgmgr.is_network_option_enabled('l3vpn'):
                                torswitch_fretta_vpc_mpls_plugin_schema(entry)
                            else:
                                torswitch_fretta_vpc_schema(entry)
                        else:
                            if self.cd_cfgmgr.is_l3_fabric_enabled():
                                torswitch_vpc_l3_fabric_schema(entry)
                            else:
                                torswitch_vpc_schema(entry)
                    except MultipleInvalid as e:
                        for x in e.errors:
                            tmp = str(entry.get('hostname')) + ":" + str(x)
                            err_list.append(str(tmp))

                if curr_swt_info == entry.get('hostname'):
                    found_curr_swt = 1

                    if self.configure_tor or self.is_vmtp_vts_present():
                        if entry.get('br_mgmt_port_info') is not None:
                            curr_num_br_mgmt_swt_port = \
                                len((entry.get('br_mgmt_port_info')).split(","))
                            num_br_mgmt_port_info += 1
                            info_found_at_peer = 1

                    curr_swt_details['vpc_peer_vlan_info'] = \
                        entry.get('vpc_peer_vlan_info')

                    curr_swt_details['l3_fabric_loopback'] = \
                        entry.get('l3_fabric_loopback', None)

                    if self.configure_tor or self.is_vmtp_vts_present():
                        curr_swt_details['vpc_domain'] = entry.get('vpc_domain')

                        if entry.get('vpc_peer_port_info') is not None:
                            curr_num_vpc_swt_port = \
                                len((entry.get('vpc_peer_port_info')).split(","))

                        curr_swt_details['br_mgmt_po_info'] = \
                            entry.get('br_mgmt_po_info')
                        curr_swt_details['vpc_peer_vlan_info'] = \
                            str(entry.get('vpc_peer_vlan_info'))

                        if entry.get('br_mgmt_po_info') is not None:
                            num_br_mgmt_po_info += 1
                            info_found_at_peer = 1

                    if self.is_tor_type_ncs5500() and \
                            self.get_num_ncs5500_tor() == 2:
                        curr_swt_details['vpc_peer_port_address'] = \
                            entry.get('vpc_peer_port_address')

                        curr_swt_details['isis_net_entity_title'] = \
                            entry.get('isis_net_entity_title')

                        curr_swt_details['isis_prefix_sid'] = \
                            entry.get('isis_prefix_sid')

                if remote_swt_info == entry.get('hostname'):
                    found_rmt_swt = 1

                    if self.configure_tor or self.is_vmtp_vts_present():
                        if entry.get('br_mgmt_port_info') is not None:
                            remote_num_br_mgmt_swt_port = \
                                len((entry.get('br_mgmt_port_info')).split(","))

                            num_br_mgmt_port_info += 1
                            info_found_at_peer = 1

                    rmt_swt_det['vpc_peer_vlan_info'] = \
                        entry.get('vpc_peer_vlan_info')

                    rmt_swt_det['l3_fabric_loopback'] = \
                        entry.get('l3_fabric_loopback', None)

                    if self.configure_tor or self.is_vmtp_vts_present():
                        rmt_swt_det['vpc_domain'] = entry.get('vpc_domain')

                        if entry.get('vpc_peer_port_info') is not None:
                            remote_num_vpc_swt_port = \
                                len((entry.get('vpc_peer_port_info')).split(","))
                        rmt_swt_det['br_mgmt_po_info'] = \
                            entry.get('br_mgmt_po_info')
                        rmt_swt_det['vpc_peer_vlan_info'] = \
                            str(entry.get('vpc_peer_vlan_info'))

                        if entry.get('br_mgmt_po_info') is not None:
                            num_br_mgmt_po_info += 1
                            info_found_at_peer = 1

                    if self.is_tor_type_ncs5500() and \
                            self.get_num_ncs5500_tor() == 2:
                        rmt_swt_det['vpc_peer_port_address'] = \
                            entry.get('vpc_peer_port_address')

                        rmt_swt_det['isis_net_entity_title'] = \
                            entry.get('isis_net_entity_title')

                        rmt_swt_det['isis_prefix_sid'] = \
                            entry.get('isis_prefix_sid')

                if found_curr_swt and found_rmt_swt:
                    if curr_swt_details.get('vpc_domain') != \
                            rmt_swt_det.get('vpc_domain'):
                        mismatch_vpc_info.append(item)

                    # check if l3_fabric_loopback for current and peer are the same
                    if curr_swt_details.get('l3_fabric_loopback') \
                            != rmt_swt_det.get('l3_fabric_loopback'):

                        a = curr_swt_details.get('l3_fabric_loopback')
                        b = rmt_swt_det.get('l3_fabric_loopback')
                        tmp = "%s:%s^%s:%s" % \
                              (curr_swt_info, a, remote_swt_info, b)
                        if tmp not in mismatch_l3_fabric_loopback_info:
                            mismatch_l3_fabric_loopback_info.append(tmp)

                    # check if the num of vpc_peer_port_info are the same
                    if curr_num_vpc_swt_port != remote_num_vpc_swt_port:
                        mismatch_vpc_port_info.append(item)

                    # check if the num of br_mgmt_port_info entry are the same
                    if curr_num_br_mgmt_swt_port != remote_num_br_mgmt_swt_port:
                        mismatch_br_mgmt_port_info.append(item)

                    if info_found_at_peer and curr_num_br_mgmt_swt_port != 1:
                        err_msg = "Expected number of br_mgmt_port_info i" \
                            "n %s is 1; found to be %s" \
                            % (curr_swt_info, curr_num_br_mgmt_swt_port)
                        incorrect_br_mgmt_port_info.append(err_msg)

                    if info_found_at_peer and remote_num_br_mgmt_swt_port != 1:
                        err_msg = "Expected number of br_mgmt_port_info " \
                            "in %s is 1; found to be %s" \
                            % (remote_swt_info, remote_num_br_mgmt_swt_port)
                        incorrect_br_mgmt_port_info.append(err_msg)

                    # Check for VPC peer vlan info
                    if curr_swt_details.get('vpc_peer_vlan_info') \
                            and not rmt_swt_det.get('vpc_peer_vlan_info'):

                        a = rmt_swt_det.get('vpc_peer_vlan_info')
                        tmp = switch_info[0] + ":" + a
                        missing_vpc_peer_vlan_info.append(tmp)
                    elif not curr_swt_details.get('vpc_peer_vlan_info') \
                            and rmt_swt_det.get('vpc_peer_vlan_info'):

                        b = curr_swt_details.get('vpc_peer_vlan_info')
                        tmp = \
                            switch_info[1] + ":" + b
                        missing_vpc_peer_vlan_info.append(tmp)

                    elif curr_swt_details.get('vpc_peer_vlan_info') != \
                            rmt_swt_det.get('vpc_peer_vlan_info'):
                        mismatch_vpc_peer_vlan_info.append(item)

                    elif not curr_swt_details.get('vpc_peer_vlan_info'):

                        try:
                            tmp_list = self.check_if_all_vlans_included(
                                switch_info[0],
                                curr_swt_details.get('vpc_peer_vlan_info'))

                            if tmp_list:
                                tmp = switch_info[0] + ":" + ','.join(tmp_list)
                                excluded_vpc_peer_vlan_info.append(tmp)
                        except AttributeError:
                            pass

                    if curr_swt_details.get('br_mgmt_po_info') != \
                            rmt_swt_det.get('br_mgmt_po_info'):
                        mismatch_br_mgmt_po_info.append(item)

        if err_list:
            raise Invalid('; '.join(err_list))

        err_str_list = []

        if self.is_tor_type_ncs5500() and \
                self.get_num_ncs5500_tor() == 2:
            if rmt_swt_det.get('vpc_peer_port_address') is None:
                err_msg = "vpc_peer_port_address for %s not defined" \
                    % (remote_swt_info)
                raise Invalid(err_msg)
            else:
                rmt_swt_vpc_peer_port_address = \
                    rmt_swt_det.get('vpc_peer_port_address')
                rmt_swt_vpc_peer_port_add_list = \
                    rmt_swt_vpc_peer_port_address.split(",")

            if curr_swt_details.get('vpc_peer_port_address') is None:
                err_msg = "vpc_peer_port_address for %s not defined" \
                    % (curr_swt_info)
                raise Invalid(err_msg)
            else:
                curr_swt_vpc_peer_port_address = \
                    curr_swt_details.get('vpc_peer_port_address')
                curr_swt_vpc_peer_port_add_list = \
                    curr_swt_vpc_peer_port_address.split(",")

            if len(rmt_swt_vpc_peer_port_add_list) != \
                    len(curr_swt_vpc_peer_port_add_list):
                err_msg = "Number of enteries for vpc_peer_port_address " \
                          "across the 2 NCSs do not match"
                raise Invalid(err_msg)

            if len(curr_swt_vpc_peer_port_add_list) == 2:
                if self.do_ips_belong_in_network(curr_swt_vpc_peer_port_add_list):
                    err_msg = "vpc_peer_port_addresses:%s in %s are " \
                        "in the same network" \
                        % (curr_swt_vpc_peer_port_add_list, curr_swt_info)
                    raise Invalid(err_msg)

            elif len(rmt_swt_vpc_peer_port_add_list) == 2:
                if self.do_ips_belong_in_network(rmt_swt_vpc_peer_port_add_list):
                    err_msg = "vpc_peer_port_addresses:%s in %s are " \
                        "in the same network" \
                        % (rmt_swt_vpc_peer_port_add_list, remote_swt_info)
                    raise Invalid(err_msg)

            if curr_num_vpc_swt_port != len(curr_swt_vpc_peer_port_add_list):
                err_msg = "Mismatch in number of enteries of " \
                    "vpc_peer_port_address:%s and vpc_peer_port_info:%s \
                    in switch:%s" % (curr_num_vpc_swt_port, \
                       len(curr_swt_vpc_peer_port_add_list), curr_swt_info)
                raise Invalid(err_msg)

            if remote_num_vpc_swt_port != len(rmt_swt_vpc_peer_port_add_list):
                err_msg = "Mismatch in number of enteries of " \
                    "vpc_peer_port_address:%s and vpc_peer_port_info:%s \
                    in switch:%s" % (remote_num_vpc_swt_port, \
                       len(rmt_swt_vpc_peer_port_add_list), remote_swt_info)
                raise Invalid(err_msg)

            repeating_peer_add_list = []
            for item in rmt_swt_vpc_peer_port_add_list:
                if item in curr_swt_vpc_peer_port_add_list:
                    repeating_peer_add_list.append(item)

            if repeating_peer_add_list:
                err_msg = "Repeating vpc_peer_port_address " \
                    "across the 2 NCSs: %s" % (repeating_peer_add_list)
                raise Invalid(err_msg)

            for (curr, rmt) in \
                    zip(curr_swt_vpc_peer_port_add_list, \
                    rmt_swt_vpc_peer_port_add_list):
                ip_info_list = []

                ip_info_list.append(curr)
                ip_info_list.append(rmt)
                if not self.do_ips_belong_in_network(ip_info_list):
                    err_msg = "vpc_peer_port_address %s:%s is not in the " \
                        "same network as that of %s:%s" \
                        % (curr_swt_info, curr, remote_swt_info, rmt)

                    raise Invalid(err_msg)

            if curr_swt_details['isis_net_entity_title'] == \
                    rmt_swt_det['isis_net_entity_title']:
                err_msg = "isis_net_entity_title %s:%s is same as that " \
                    "of the peer %s:%s" \
                    % (curr_swt_info,
                       curr_swt_details['isis_net_entity_title'],
                       remote_swt_info,
                       rmt_swt_det['isis_net_entity_title'])

                raise Invalid(err_msg)

            if curr_swt_details['isis_prefix_sid'] is None and \
                    rmt_swt_det['isis_prefix_sid'] is None:
                pass

            elif curr_swt_details['isis_prefix_sid'] is None and \
                    rmt_swt_det['isis_prefix_sid'] is not None:
                err_msg = "isis_prefix_sid %s:%s is not defined but the " \
                    "peer is %s:%s" % (curr_swt_info, \
                                       curr_swt_details['isis_prefix_sid'], \
                                       remote_swt_info, \
                                       rmt_swt_det['isis_prefix_sid'])
                raise Invalid(err_msg)

            elif curr_swt_details['isis_prefix_sid'] is not None and \
                    rmt_swt_det['isis_prefix_sid'] is None:
                err_msg = "isis_prefix_sid %s:%s is defined but the " \
                    "peer isis_prefix_sid is not %s:%s" \
                    % (curr_swt_info, curr_swt_details['isis_prefix_sid'], \
                       remote_swt_info, rmt_swt_det['isis_prefix_sid'])
                raise Invalid(err_msg)

            elif curr_swt_details['isis_prefix_sid'] == \
                    rmt_swt_det['isis_prefix_sid']:
                err_msg = "isis_prefix_sid %s:%s is same as that " \
                    "of the peer %s:%s" % (curr_swt_info, \
                                           curr_swt_details['isis_prefix_sid'], \
                                           remote_swt_info, \
                                           rmt_swt_det['isis_prefix_sid'])

                raise Invalid(err_msg)

        if info_found_at_peer and info_found_at_non_peer:
            err_str = "br_mgmt related info only allowed on peer " \
                      "or non-peering switch"
            raise Invalid(err_str)

        if info_found_at_non_peer:
            match_info = 1
        else:
            match_info = 2

        if self.configure_tor:
            if num_br_mgmt_port_info != match_info:
                err_str = "%s entrie(s) for br_mgmt_port_info needs to " \
                    "be present; found: %s for Auto TOR configuration" \
                    % (str(match_info), str(num_br_mgmt_port_info))
                err_str_list.append(err_str)

            if num_br_mgmt_po_info != match_info:
                err_str = "%s entrie(s) for br_mgmt_po_info needs to " \
                    "be present; found: %s for Auto TOR configuration" \
                    % (str(match_info), str(num_br_mgmt_po_info))
                err_str_list.append(err_str)

        elif self.is_vmtp_vts_present():
            if num_br_mgmt_port_info != match_info:
                err_str = "%s entrie(s) for br_mgmt_port_info needs to " \
                    "be present; found: %s" \
                    % (str(match_info), str(num_br_mgmt_port_info))
                err_str_list.append(err_str)

        if err_str_list:
            raise Invalid('; '.join(err_str_list))

        if excluded_vpc_peer_vlan_info:
            err_str = "vpc_peer_vlan_info excludes the following vlans " + \
                      ','.join(excluded_vpc_peer_vlan_info)
            err_str_list.append(err_str)

        if missing_vpc_peer_vlan_info:
            err_str = "Missing VPC Peer VLAN Info:" + \
                      ', '.join(missing_vpc_peer_vlan_info)
            err_str_list.append(err_str)

        if mismatch_peer_swt_info:
            err_str = "Mismatch Peer Switch Info:" + \
                      ', '.join(mismatch_peer_swt_info)
            err_str_list.append(err_str)

        if mismatch_vpc_info:
            err_str = "Mismatch vpc domain between VPC peers:" + \
                      ', '.join(mismatch_vpc_info)
            err_str_list.append(err_str)

        if mismatch_l3_fabric_loopback_info:
            err_str = "Mismatch l3_fabtic_loopback_info across " \
                "switches: %s" % (', '.join(mismatch_l3_fabric_loopback_info))
            err_str_list.append(err_str)

        if mismatch_vpc_port_info:
            err_str = "Unequal Number of Port List between VPC peers:" + \
                      ', '.join(mismatch_vpc_port_info)
            err_str_list.append(err_str)

        if mismatch_br_mgmt_port_info:
            err_str = "Unequal Number of br_mgmt Port List between VPC peers:" + \
                      ', '.join(mismatch_br_mgmt_port_info)
            err_str_list.append(err_str)

        if incorrect_br_mgmt_port_info:
            err_str = ', '.join(incorrect_br_mgmt_port_info)
            err_str_list.append(err_str)

        if mismatch_vpc_peer_vlan_info:
            err_str = "Mismatch Peer VLAN list between VPC peers:" + \
                      ', '.join(mismatch_vpc_peer_vlan_info)
            err_str_list.append(err_str)

        if mismatch_br_mgmt_po_info:
            err_str = "Mismatch br_mgmt Port Channel between VPC peers:" + \
                      ', '.join(mismatch_br_mgmt_po_info)
            err_str_list.append(err_str)

        if err_str_list:
            raise Invalid('; '.join(err_str_list))

        return

    def check_http_syntax(self, input_str):
        '''Check if http/https proxy if defined'''

        invalid_http_servers = []
        invalid_http_port = []
        skip_port_check = 0

        dns_check_entry = input_str.split(":")[0]

        try:
            port_check_entry = input_str.split(":")[1]
        except IndexError:
            skip_port_check = 1
            missing_port_info = dns_check_entry + ":MissingPort"
            invalid_http_port.append(missing_port_info)

        if not skip_port_check and not self.is_input_an_integer(port_check_entry):
            invalid_http_port.append(port_check_entry)

        if not self.is_dns_valid(dns_check_entry):
            invalid_http_servers.append(dns_check_entry)

        if invalid_http_servers:
            err_str = "DNS check failed for " + str(input_str)
            raise Invalid(err_str)

        if invalid_http_port:
            err_str = "Port Info is incorrect for " + str(input_str)
            raise Invalid(err_str)

    def check_admin_source_syntax(self, input_str):
        '''Check if admin_source_networks are defined correctly'''

        if input_str is None:
            err_str = "Need to have at least 1 entry"
            raise Invalid(err_str)

        if not isinstance(input_str, list):
            err_str = "entry has to be of type list"
            raise Invalid(err_str)

        if not input_str:
            err_str = "entry has to have a min input of 1 target address"
            raise Invalid(err_str)

        for network in input_str:
            err_str = "Network format is incorrect; " \
                "Found %s, expected to be: ipaddr/mask" % (network)

            if not re.search(r'/', network):
                raise Invalid(err_str)

            (addrString, cidrString) = network.split('/')

            if common_utils.is_valid_ipv6_address(addrString):
                try:
                    cidr = int(cidrString)
                except:
                    raise Invalid(err_str)
                if cidr < 0 or cidr > 128:
                    raise Invalid(err_str)
            else:
                if cidrString == '31' or cidrString == '32':
                    self.is_ip_syntax_valid(addrString)

                elif not self.validate_network(network):
                    raise Invalid(err_str)

    def check_password_hash_pat(self, input_str):
        '''Checks the admin password hash syntax'''

        self.is_input_in_plain_str(input_str)
        if not re.match(r'\$6', input_str):
            err_str = "admin hash password on mgmt node" \
                      " doesn't start with $6"
            raise Invalid(err_str)
        return

    def check_public_key_pat(self, input_str):
        '''Checks the admin public key syntax'''

        if not re.match(r'(ssh-rsa|ssh-ed25519) AAAA', input_str):
            err_str = "admin public key does not start with ssh-rsa " \
                "AAAA or ssh-ed25519 AAAA"
            raise Invalid(err_str)
        return

    def check_cobbler_input(self, input_str):
        '''Check cobbler Input'''

        cobbler_schema = Schema({
            Optional('cobbler_username'): All(str, Any('cobbler'),
                                              msg='only cobbler allowed as values'),
            Optional('cobbler_password'): self.check_absence_input,
            # NOTE: COBBLER.admin_username is not being used anywhere in the
            #       code.  Temporary keeping the option for backward
            #       compatibility only and should be depreciate later on.
            Optional('admin_username'): All(str, Any('root'),
                                            msg='only root allowed as values'),
            Required('admin_password_hash'): self.check_password_hash_pat,
            Optional('admin_ssh_keys'): self.admin_ssh_key,
            Optional('kickstart'): self.validate_kickstart_info,
            Optional('pxe_timeout'): All(int, Range(min=30, max=120)),
            Optional('host_profile'): str,
            Optional('hw_raid'): In(frozenset(["enable", "disable"]),
                                    msg='only enable or disable allowed as values'),
            Optional('use_teaming'): All(Boolean(str),
                                         msg="Only Boolean value True/False "
                                             "allowed; default is True"),
            Optional('enable_ipv6_pxe'): All(Boolean(str),
                                             msg="Only Boolean value "
                                                 "True/False allowed; default "
                                                 "is False"),
        }, extra=False)

        err_str = ""

        try:
            cobbler_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        return err_str

    def check_ntp_syntax(self, input_str):
        '''Check the ntp info'''

        self.validate_networking_entry(input_str)

        dup_ntp_list = \
            self.get_duplicate_entry_in_list(input_str)

        if dup_ntp_list:
            err_str = "Duplicate ntp_servers Found: " + \
                      ' '.join(dup_ntp_list)
            raise Invalid(err_str)

        return

    def check_networking_input(self, input_str):
        '''Check Networking Schema'''

        networking_schema = Schema({
            Required('domain_name'): All(str, msg='Missing Domain Name info'),
            Required('ntp_servers'): self.check_ntp_syntax,
            Required('domain_name_servers'): self.validate_networking_entry,
            Optional('http_proxy_server'): self.check_http_syntax,
            Optional('https_proxy_server'): self.check_http_syntax,
            Required('networks'): self.validate_network_details,
            Optional('admin_source_networks'): self.check_admin_source_syntax,
            Optional('remote_management'): self.check_remote_management_syntax,
        })

        networking_schema_l3 = networking_schema.extend({
            Required('remote_management'): self.check_remote_management_syntax,
        })

        mgmt_node_type = common_utils.fetch_mgmt_node_type()
        err_str = ""
        try:
            if mgmt_node_type == "vm":
                networking_schema_l3(input_str)
            else:
                networking_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        return err_str

    def validate_ss_cluster_api_endpoint(self, input_str):
        '''Validates if the input is of the format IPADDR/v1'''

        error_str = "Expected input format is of type FQDN/v1 or IPADDR/v1, " \
                    "found: " + str(input_str)
        self.is_input_in_plain_str(input_str)

        if not re.search(r'/', input_str):
            raise Invalid(error_str)

        input_contents = input_str.split("/")

        if len(input_contents) != 2:
            raise Invalid(error_str)

        if not re.match(r'v1', input_contents[1]):
            raise Invalid(error_str)

        if re.match(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', input_contents[0]):
            self.is_ip_syntax_valid(input_contents[0])
        elif re.match('[a-zA-Z.]+', input_contents[0]):
            self.is_input_in_plain_str(input_contents[0])

        return

    def check_swiftstack_input(self, input_str):
        '''Check swiftstack entry'''

        swiftstack_schema = Schema({
            Required('cluster_api_endpoint'): self.validate_ss_cluster_api_endpoint,
            Required('reseller_prefix'): self.is_input_in_plain_str,
            Required('admin_user'): self.is_input_in_plain_str,
            Required('admin_password'): self.check_password_syntax,
            Required('admin_tenant'): self.is_input_in_plain_str,
            Required('protocol'): In(frozenset(["http", "https"]),
                                     msg='only http and https allowed as values'),
        })

        err_str = ""
        try:
            swiftstack_schema(input_str)
            err_msg = "Swiftstack is not supported with Keystone V3"
            raise Invalid(err_msg)

        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        return err_str

    def check_solidfire_input(self, input_str):
        '''Check solidfire entry'''

        solidfire_schema = Schema({
            Required('cluster_mvip'): self.check_valid_solidfire_mvip,
            Required('cluster_svip'): self.check_valid_solidfire_svip,
            Required('admin_username'): self.is_input_in_plain_str,
            Required('admin_password'): self.check_password_syntax,
        })

        err_str = ""
        try:
            solidfire_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        return err_str

    def check_vim_admins_input(self, input_str):
        '''Check vim_admins entry'''

        key_schema = Schema({
            Required(
                Any('vim_admin_password_hash', 'vim_admin_public_key'),
                msg='Must specify password_hash and/or public_key'): str
        }, extra=True)

        value_schema = Schema({
            Required('vim_admin_username'): self.validate_linux_username,
            Optional('vim_admin_password_hash'): self.check_password_hash_pat,
            Optional('vim_admin_public_key'): self.check_public_key_pat,
        })

        vim_admins_schema = All(key_schema, value_schema)

        if input_str is None:
            raise Invalid("Missing Entry")

        admin_username_list = []
        for item in input_str:
            try:
                vim_admins_schema(item)
                admin_username_list.append(item['vim_admin_username'])
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        dup_vim_admin_list = \
            self.get_duplicate_entry_in_list(admin_username_list)

        if dup_vim_admin_list:
            err_str = "Duplicate vim_admin_username Found: " + \
                      ' '.join(dup_vim_admin_list)
            raise Invalid(err_str)

        return

    def check_permit_root_login(self, input_str):
        '''Check permit_root_login entry'''

        permit_root_login_schema = All(Boolean(str),
                                       msg="Only Boolean value "
                                           "True/False allowed; "
                                           "default is True")

        if input_str is None:
            raise Invalid("Missing Entry")

        permit = permit_root_login_schema(input_str)

        vim_admins = self.ymlhelper.get_data_from_userinput_file(['vim_admins'])

        if not permit and not vim_admins:
            raise Invalid("vim_admins list must be configured for "
                          "permit_root_login to be False ")

        return ""

    def check_syslog_export_settings(self, input_str):
        '''Enable Syslog settings to offload ELK logs to
        a remote syslog server'''

        syslog_schema = Schema({
            Required('remote_host'): self.is_ipv4_or_v6_syntax_valid,
            Required('protocol'): In(frozenset(["udp"]),
                                     msg='only udp allowed as values'),
            Required('facility'): In(frozenset(["local0", "local1", "local2",
                                                "local3", "local4", "local5",
                                                "local6", "local7", "user"]),
                                     msg='only user or local0 through local7 '
                                         'allowed as values'),
            Required('severity'): In(frozenset(["debug"]),
                                     msg='only debug allowed as values'),
            Required('port'): All(int, Range(min=1, max=65535)),
            Required('clients'): In(frozenset(["ELK"]),
                                    msg='only ELK allowed as values'),
        })

        if not isinstance(input_str, list):
            err_str = "entry has to be of type list"
            raise Invalid(err_str)
        elif len(input_str) > 4:
            err_str = "Max of 4 entries supported "
            raise Invalid(err_str)

        ext_syslog_ip_list = []
        try:
            for item in input_str:
                syslog_schema(item)
                ext_syslog_ip_list.append(item['remote_host'])
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        dup_ext_syslog_ip_list = \
            self.get_duplicate_entry_in_list(ext_syslog_ip_list)

        if dup_ext_syslog_ip_list:
            err_str = "Duplicate Remote Host info Found: " + \
                      ' '.join(dup_ext_syslog_ip_list)
            raise Invalid(err_str)

        return

    def check_remote_backup_settings(self, input_str):
        '''Enable remote backup settings to use NFS on a remote server'''

        es_remote_schema = Schema({
            Required('service'): In(frozenset(["NFS"]),
                                    msg='only nfs is allowed as values'),
            Required('remote_host'): self.is_ipv4_or_v6_syntax_valid,
            Required('remote_path'): self.is_es_remote_path,
        })
        err_str = ""
        try:
            es_remote_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))
        return err_str

    def check_octet_syntax(self, input_str):
        '''Check the input to be octet'''

        err_str = "entry %s has to be an octet string, " \
                  "not starting with 0x and of length between " \
                  "5 and 32 characters; Also, input cannot have " \
                  "all characters with FFF... or 000.." % (input_str)

        if not isinstance(input_str, str):
            raise Invalid(err_str)

        if re.search('^0x', input_str):
            raise Invalid(err_str)

        if re.search(r'^[fF]+$', input_str):
            raise Invalid(err_str)

        if re.search(r'^[0]+$', input_str):
            raise Invalid(err_str)

        oct_match = re.search(r'^[0-9a-fA-F]+$', input_str)
        if not oct_match:
            raise Invalid(err_str)

        err_str1 = "; Current input found to be of length %s" \
            % (len(input_str))
        err_str_fin = str(err_str) + str(err_str1)

        if len(input_str) < 5:
            raise Invalid(err_str_fin)

        if len(input_str) > 32:
            raise Invalid(err_str_fin)

        self.global_snmpv3_engine_id.append(input_str)

        return

    def check_snmpv3_user_name(self, input_str):
        '''Checks the SNMPv3 User name per manager
        and check against duplicate entry'''

        if not isinstance(input_str, str):
            err_str = "entry has to be of type string"
            raise Invalid(err_str)

        if len(input_str) >= 1:
            pass
        else:
            err_str = "entry has to be of type string " \
                "with min length of 1"
            raise Invalid(err_str)

        self.global_snmpv3_user_list.append(input_str)
        return

    def check_snmpv3_users_syntax(self, input_str):
        '''Checks SNMPv3 user syntax'''

        snmpv3_users_schema = Schema({
            Required('name'): self.check_snmpv3_user_name,
            Required('auth_key'): self.check_password_syntax,
            Optional('authentication'): In(frozenset(["SHA", "MD5"]), \
                                           msg='only SHA or MD5 allowed as values'),
            Optional('privacy_key'): self.check_password_syntax,
            Optional('encryption'): In(frozenset(['AES128', 'AES192', 'AES256']), \
                                       msg='only AES128, AES192, '
                                           'AES256 allowed as values'),
        })

        if not isinstance(input_str, list):
            err_str = "entry has to be of type list"
            raise Invalid(err_str)
        elif len(input_str) > 3:
            err_str = "Maximum of 3 users per manager are supported"
            raise Invalid(err_str)

        for item in input_str:
            try:
                snmpv3_users_schema(item)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        return

    @staticmethod
    def get_snmp_ip_mgmt_list(item):
        """Get the SNMP IP MGMT List"""
        tmp = ""
        if item.get('port') is None:
            tmp = str(item.get('address')) + ":162"
        else:
            tmp = str(item.get('address')) + ":" + str(item.get('port'))
        return (tmp)

    def is_snmpv2_ip_syntax_valid(self, input_str):
        """Check if SNMPv2 IP syntax is valid"""
        if not input_str:
            raise Invalid("Missing IP address")
        try:
            self.is_ip_syntax_valid(input_str)
        except Exception:
            try:
                self.is_ipv6_syntax_valid(input_str)
            except Exception:
                pass
            else:
                err_str = "IPv6 address not supported with SNMPv2"
                raise Invalid(err_str)
            raise Invalid("Invalid IPv4 address")

    def check_snmp_managers_input(self, input_str):
        '''Check SNMP managers list format'''

        snmpv2_mgrs_schema = Schema({
            Required('address'): self.is_snmpv2_ip_syntax_valid,
            Optional('port'): All(int, Range(min=1, max=65535)),
            Optional('community'): All(str, Length(min=1), \
                                       msg='community name is missing; '
                                           'default value is "public"'),
            Optional('version'): In(frozenset(["v2c"]), \
                                    msg='Only v2c or v3 version allowed '
                                        'as values'),
        })

        found_snmpv3_input = 0
        snmpv3_mgrs_schema = Schema({
            Required('address'): self.is_ipv4_or_v6_syntax_valid,
            Optional('port'): All(int, Range(min=1, max=65535)),
            Required('version'): In(frozenset(["v3"]), \
                                    msg='Only v2c or v3 version allowed '
                                        'as values'),
            Required('engine_id'): self.check_octet_syntax,
            Required('users'): self.check_snmpv3_users_syntax,
        })

        snmp_ip_mgr_list = []
        if not isinstance(input_str, list):
            err_str = "entry has to be of type list"
            raise MultipleInvalid(err_str)
        elif len(input_str) > 3:
            err_str = "Maximum of 3 managers are supported"
            raise Invalid(err_str)
        try:
            for item in input_str:
                curr_version_type = item.get('version')
                if curr_version_type is None or curr_version_type == 'v2c':
                    snmpv2_mgrs_schema(item)
                    e = self.get_snmp_ip_mgmt_list(item)
                    if e:
                        snmp_ip_mgr_list.append(e)
                else:
                    found_snmpv3_input = 1
                    self.global_snmpv3_user_list = []
                    snmpv3_mgrs_schema(item)
                    e = self.get_snmp_ip_mgmt_list(item)
                    if e:
                        snmp_ip_mgr_list.append(e)
                    dup_snmpv3_user_info = \
                        self.get_duplicate_entry_in_list(\
                            self.global_snmpv3_user_list)
                    if dup_snmpv3_user_info:
                        err_str = "Duplicate SNMP user info found: " + \
                                  ' '.join(dup_snmpv3_user_info)
                        raise Invalid(err_str)

        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        dup_snmp_mgr_ip_info = \
            self.get_duplicate_entry_in_list(snmp_ip_mgr_list)

        if dup_snmp_mgr_ip_info:
            err_str = "Duplicate SNMP Manager IP:Port info Found: " + \
                      ' '.join(dup_snmp_mgr_ip_info)
            raise Invalid(err_str)

        if found_snmpv3_input:
            dup_engid = self.get_duplicate_entry_in_list(\
                self.global_snmpv3_engine_id)
            if dup_engid and not self.is_cvimmonha_enabled():
                err_str = "Duplicate SNMPv3 engine_id found: " + ' '.join(dup_engid)
                raise Invalid(err_str)
        return

    def check_snmp_settings(self, input_str):
        '''Enable SNMP settings to sent traps to remote SNMP managers'''

        if self.is_snmp_enabled() and not self.is_cvimmon_enabled():
            err_str = "SNMP options can only be enabled when " \
                "CVIM_MON is enabled"
            raise Invalid(err_str)

        if self.is_snmp_enabled() and self.is_central_cvimmon():
            err_str = "SNMP options cannot be enabled when " \
                "central CVIM_MON is enabled"
            raise Invalid(err_str)

        snmp_schema = Schema({
            Required('enabled'): All(Boolean(str), \
                                     msg="Only true or false allowed; "
                                         "default is false"),
            Required('managers'): self.check_snmp_managers_input,
        })
        try:
            snmp_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))
        return

    def is_snmp_enabled(self):
        '''Check if SNMP is enabled'''

        key = ["SNMP", "enabled"]
        ret_value = self.ymlhelper.get_data_from_userinput_file(key)
        if ret_value is not None and ret_value is True:
            return 1

        return 0

    def check_server_mon_host_info(self, input_str):
        '''Check if Server MON is ALL or a subset of Cisco Nodes
        Inputs are considered as valid if either
        conditions is satisfied:
        (1) Equal to a list with entry ['ALL'];
        (2) A list consists of one to several nodes;
        '''

        server_list = list(set(self.ymlhelper.get_server_list()))
        if not isinstance(input_str, list):
            err_str = "entry has to be of type list"
            raise Invalid(err_str)
        elif (len(input_str) == 1 and
              ('ALL' not in input_str) and (input_str[0] not in server_list)):
            err_str = "ALL or server name is the only value allowed when " \
                "there is 1 entry; Found to have %s" \
                % (','.join(input_str))
            raise Invalid(err_str)
        elif len(input_str) == 1 and 'ALL' in input_str:
            return

        dup_server_mon_info = \
            self.get_duplicate_entry_in_list(input_str)

        if dup_server_mon_info:
            err_str = "Duplicate Info found: " + \
                      ' '.join(dup_server_mon_info)
            raise Invalid(err_str)

        invalid_server_list = []
        for item in input_str:
            if item not in server_list:
                invalid_server_list.append(item)

        if invalid_server_list:
            err_str = "server(s) %s must be part of the " \
                "target pod" % (','.join(invalid_server_list))
            raise Invalid(err_str)

        return

    @staticmethod
    def check_vault_enabled(input_str):
        '''Checks VAULT is enabled'''
        vault_schema = Schema({
            Required('enabled'): All(Boolean(str), \
                                     msg="Only true or false allowed; "
                                         "default is false"),
        })
        try:
            vault_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))
        return

    def check_server_mon_settings(self, input_str):
        '''Checks SERVER_MON input for SNMP traps via CIMC'''

        CIMC_SEVERITIES = ['emergency', 'alert', 'critical', 'error',
                           'warning', 'notice', 'informational', 'debug']
        server_mon_schema = Schema({
            Required('enabled'): All(Boolean(str), \
                                     msg="Only true or false allowed; "
                                         "default is false"),
            Required('host_info'): self.check_server_mon_host_info,
            Optional('rsyslog_severity'): In(frozenset(CIMC_SEVERITIES),
                                             msg='only allowed values: %s' \
                                                 % (CIMC_SEVERITIES)),
        })

        if re.match(r'UCSM', self.testbed_type):
            err_str = "Entry supported only in a C-series testbed"
            raise Invalid(err_str)

        if not self.is_snmp_enabled():
            if not self.is_central_cvimmon():
                err_str = "Entry supported only with SNMP option"
                raise Invalid(err_str)

        try:
            server_mon_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        # Check that rsyslog only there if SYSLOG_EXPORT_SETTINGS is defined
        syslog_check = \
            self.ymlhelper.get_data_from_userinput_file(['SYSLOG_EXPORT_SETTINGS'])
        sev_check = \
            self.ymlhelper.is_sub_key_defined('SERVER_MON', 'rsyslog_severity')

        if sev_check and not syslog_check:
            err_str = "rsyslog_severity only supported when " \
                "SYSLOG_EXPORT_SETTINGS is enabled"
            raise Invalid(err_str)

        return

    def check_vic_nic_entry(self, input_str):
        '''Check CISCO VIN INTEL SRIOV option'''

        if not isinstance(input_str, bool):
            err_str = "Input has to be of type bool"
            raise Invalid(err_str)

        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])

        vic_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_INTEL_SRIOV'])

        intel_nic_sriov_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_SRIOV_VFS'])

        if not vic_nic_check:
            return

        if vic_nic_check and not intel_nic_sriov_check:
            err_str = "Intel 520 option only supported with INTEL_SRIOV_VFS"
            raise Invalid(err_str)

        if intel_nic_check and vic_nic_check:
            err_str = "Intel NIC & CISCO_VIC_NIC options are mutually exclusive"
            raise Invalid(err_str)

        if not self.is_provider_network_defined():
            err_str = "Intel 520 option only supported with provider network info"
            raise Invalid(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        if mechanism_driver is not None and \
                mechanism_driver == 'vts':
            err_str = "SRIOV for Intel NIC only allowed for " \
                      "OVS/VLAN"
            raise Invalid(err_str)

        return

    def check_nic_level_redundancy(self, input_str):
        '''Checks if INTEL_NIC_SUPPORT is enabled for NIC level redundancy'''

        if not self.ymlhelper.get_data_from_userinput_file(
                ['INTEL_NIC_SUPPORT']):
            raise Invalid("Option only allowed for Intel 710 NIC POD")
        if not isinstance(input_str, bool):
            raise Invalid("Only Boolean value True/False")

        return

    def check_sriov_card_type(self, input_str):
        '''Check sriov card type'''

        self.is_input_in_plain_str(input_str)
        if input_str in ['X520', 'XL710', 'XXV710']:
            pass
        else:
            err_str = "Only values of X520, XL710, or XXV710 allowed, " \
                "found to be %s" % (input_str)
            raise Invalid(err_str)

        vic_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_INTEL_SRIOV'])

        if not vic_nic_check:
            err_msg = "CISCO_VIC_INTEL_SRIOV not defined for"
            raise Invalid(err_msg)

        return

    def get_sriov_card_type(self):
        '''gets SRIOV card type'''

        sriov_card_type = \
            self.ymlhelper.get_data_from_userinput_file(['SRIOV_CARD_TYPE'])

        if not sriov_card_type:
            return "UNDEFINED"

        return sriov_card_type

    def check_sriov_phy_ports(self, input_str):
        '''Checks if sriov_phy_ports is 2 or 4 for pure intel XL710
        or X710, 4 or 8 for VIC_NIC'''

        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])

        vic_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_INTEL_SRIOV'])

        vic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_SUPPORT'])

        if intel_nic_check or vic_nic_check:
            pass
        else:
            err_str = "Option only allowed for Intel 710 NIC POD"
            raise Invalid(err_str)

        if not isinstance(input_str, int):
            err_str = "Non-Integer Input not allowed"
            raise Invalid(err_str)

        if vic_nic_check and \
                self.get_sriov_card_type() == "XL710":
            if input_str == 4 or input_str == 8:
                pass
            else:
                err_str = "Only values 4 or 8 supported, found:%s" \
                    % (input_str)
                raise Invalid(err_str)

        elif vic_nic_check and input_str != 4:
            err_str = "Only value of 4 supported, found:%s" \
                % (input_str)
            raise Invalid(err_str)

        elif vic_check and intel_nic_check and input_str != 2:
            err_str = "Only values of 2 supported when CISCO_VIC_SUPPORT " \
                "is enabled, found:%s" % (input_str)
            raise Invalid(err_str)

        elif intel_nic_check:
            if self.ymlhelper.get_pod_type() == 'nano':
                if not (1 <= input_str <= 4):
                    err_str = ("value between 1 and 4 supported for Nano POD, "
                               "found: %s" % input_str)
                    raise Invalid(err_str)
            elif input_str == 2 or input_str == 4:
                pass
            else:
                err_str = "Only values of 2 or 4 supported, found:%s" \
                    % (input_str)
                raise Invalid(err_str)
        return

    def check_apic_host_info(self, input_str):
        '''Checks the apic host info provided'''

        if not isinstance(input_str, list):
            err_str = "input has to be of type list"
            raise Invalid(err_str)

        if len(input_str) >= 1 or len(input_str) < 6:
            pass
        else:
            err_str = "1 to 5 apic_hosts allowed; Found:%s" \
                % (len(input_str))
            raise Invalid(err_str)

        dup_apic_host_info = \
            self.get_duplicate_entry_in_list(input_str)

        if dup_apic_host_info:
            err_str = "Duplicate APIC Host Info found: " + \
                      ' '.join(dup_apic_host_info)
            raise Invalid(err_str)

        for curr_item in input_str:
            self.check_input_as_ip_or_str(curr_item, check_v6=1)

        return

    def check_password_syntax(self, input_str):
        '''Checks Password Syntax'''

        if not input_str:
            raise Invalid("Missing entry")

        self.is_input_in_plain_str(input_str)

        if common_utils.is_pod_upgraded():
            return

        err_str = ""
        pwd_len_msg = ""
        other_pwd_msg_list = []
        msg_list = []
        pwd_criteria = "satisfy at least 3 of the following conditions: " \
                       "at least 1 letter between a to z, " \
                       "at least 1 letter between A to Z, " \
                       "at least 1 number between 0 to 9, " \
                       "at least 1 character from !$@%^-_+=, " \
                       "AND password length is between 8 and 20 characters."

        match_count = 0
        pwd_length_check = 0
        if (len(input_str) >= 8 and len(input_str) <= 20):
            pwd_length_check = 1
        else:
            msg = "Password length needs to be " \
                  "between 8 and 20 characters " \
                  "found to be %s" % (len(input_str))
            pwd_len_msg = msg
            self.log.info(msg)
            msg_list.append(msg)

        if re.search("[a-z]", input_str):
            match_count += 1
        else:
            msg = "Password needs to have at least 1 " \
                  "letter between [a - z]"
            self.log.info(msg)
            msg_list.append(msg)
            other_pwd_msg_list.append(msg)

        if re.search("[0-9]", input_str):
            match_count += 1
        else:
            msg = "Password needs to have at least 1 " \
                  "number between [0 - 9]"
            self.log.info(msg)
            msg_list.append(msg)
            other_pwd_msg_list.append(msg)

        if re.search("[A-Z]", input_str):
            match_count += 1
        else:
            msg = "Password needs to have at least 1 " \
                  "letter between [A - Z]"
            self.log.info(msg)
            msg_list.append(msg)
            other_pwd_msg_list.append(msg)

        if re.search("[!$@$%^-_+=]", input_str):
            match_count += 1
        else:
            char_info = '!$#@%^-_+='
            msg = "Password needs to have at least 1 character from %s" % (char_info)
            self.log.info(msg)
            msg_list.append(msg)
            other_pwd_msg_list.append(msg)

        if match_count < 3 or (not pwd_length_check):
            if match_count < 3 and (not pwd_length_check):
                err_str2 = ' and/or '.join(msg_list)
                err_str = "Password should %s; Current Password: %s" \
                          % (pwd_criteria, err_str2)
                raise Invalid(err_str)

            elif (not pwd_length_check):
                raise Invalid(pwd_len_msg)

            elif match_count < 3:
                err_str2 = ' and/or '.join(other_pwd_msg_list)
                err_str = "Password should %s; Current Password: %s" \
                    % (pwd_criteria, err_str2)
                raise Invalid(err_str)

        if re.search(r'cisco', input_str, re.IGNORECASE):
            err_str = "Password having Cisco in it is not allowed"
            raise Invalid(err_str)

        return err_str

    def check_apic_tep_address_pool(self, input_str):
        '''set the apic_tep_address_pool'''

        self.is_input_in_plain_str_len32(input_str)
        default_value = '10.0.0.0/16'
        if input_str != default_value:
            err_str = "Only Value of %s is allowed" % (default_value)
            raise Invalid(err_str)

        return

    def check_multicast_address_pool(self, input_str):
        '''set the multicast_address_pool'''

        self.is_input_in_plain_str_len32(input_str)
        default_value = '225.0.0.0/15'
        if input_str != default_value:
            err_str = "Only Value of %s is allowed" % (default_value)
            raise Invalid(err_str)

        return


    def check_mgmt_l3out_vrf(self, input_str):
        '''check mgmt_l3out_vrf, goes with mgmt_l3out_network'''

        self.is_input_in_plain_str_len32(input_str)

        try:
            apicinfo = \
                self.ymlhelper.get_data_from_userinput_file(['APICINFO'])

        except AttributeError:
            err_msg = 'APICINFO section not defined'
            raise Invalid(err_msg)

        mgmt_l3out_network_info = apicinfo.get('mgmt_l3out_network')
        if mgmt_l3out_network_info is None:
            err_msg = 'mgmt_l3out_network info not defined in APICINFO section, ' \
                      'a must'
            raise Invalid(err_msg)

        self.l3_out_defined = 1
        self.l3_out_list.append('mgmt_l3out_network')

        return

    def check_mgmt_l3out_network(self, input_str):
        '''check mmgmt_l3out_network, goes with mgmt_l3out_vrf'''

        self.is_input_in_plain_str_len32(input_str)

        try:
            apicinfo = \
                self.ymlhelper.get_data_from_userinput_file(['APICINFO'])

        except AttributeError:
            err_msg = 'APICINFO section not defined'
            raise Invalid(err_msg)

        mgmt_l3out_network_info = apicinfo.get('mgmt_l3out_vrf')
        if mgmt_l3out_network_info is None:
            err_msg = 'mgmt_l3out_vrf into not defined in APICINFO section, ' \
                      'a must'
            raise Invalid(err_msg)
        self.l3_out_defined = 1
        self.l3_out_list.append('mgmt_l3out_vrf')

        return

    def check_prov_l3out_vrf(self, input_str):
        '''check prov_l3out_vrf, goes with prov_l3out_network'''

        self.is_input_in_plain_str_len32(input_str)

        try:
            apicinfo = \
                self.ymlhelper.get_data_from_userinput_file(['APICINFO'])

        except AttributeError:
            err_msg = 'APICINFO section not defined'
            raise Invalid(err_msg)

        prov_l3out_network_info = apicinfo.get('prov_l3out_network')
        if prov_l3out_network_info is None:
            err_msg = 'prov_l3out_network info not defined in APICINFO section, ' \
                      'a must'
            raise Invalid(err_msg)

        self.l3_out_defined = 1
        self.l3_out_list.append('prov_l3out_network')

        return

    def check_prov_l3out_network(self, input_str):
        '''check prov_l3out_network, goes with prov_l3out_vrf'''

        self.is_input_in_plain_str_len32(input_str)

        try:
            apicinfo = \
                self.ymlhelper.get_data_from_userinput_file(['APICINFO'])

        except AttributeError:
            err_msg = 'APICINFO section not defined'
            raise Invalid(err_msg)

        prov_l3out_network_info = apicinfo.get('prov_l3out_vrf')
        if prov_l3out_network_info is None:
            err_msg = 'prov_l3out_vrf into not defined in APICINFO section, ' \
                      'a must'
            raise Invalid(err_msg)
        self.l3_out_defined = 1
        self.l3_out_list.append('prov_l3out_vrf')

        return


    def check_api_l3out_network(self, input_str):
        '''check api_l3 out_network, syntax'''

        self.is_input_in_plain_str_len32(input_str)
        self.l3_out_defined = 1
        self.l3_out_list.append('api_l3out_network')

        return

    def check_mgmt_l2out_network(self, input_str):
        '''check mmgmt_l2out_network, syntax'''

        self.is_input_in_plain_str_len32(input_str)
        self.check_l2out_network(input_str, 'management')
        self.l2_out_defined = 1
        self.l2_out_list.append('mgmt_l2out_network')
        self.mgmt_l2out_network = 1
        return

    def check_api_l2out_network(self, input_str):
        '''check api_l2out_network, syntax'''

        self.is_input_in_plain_str_len32(input_str)
        self.check_l2out_network(input_str, 'api')
        self.l2_out_defined = 1
        self.l2_out_list.append('api_l2out_network')
        self.api_l2out_network = 1

        return

    def check_prov_l2out_network(self, input_str):
        '''check provider_l2out_network, syntax'''

        self.is_input_in_plain_str_len32(input_str)
        self.check_l2out_network(input_str, 'provider')
        self.l2_out_defined = 1
        self.l2_out_list.append('prov_l2out_network')
        self.prov_l2out_network = 1

        return

    def check_ext_l2out_network(self, input_str):
        '''check external_l2out_network, syntax'''

        self.is_input_in_plain_str_len32(input_str)
        self.check_l2out_network(input_str, 'external')
        self.l2_out_defined = 1
        self.l2_out_list.append('ext_l2out_network')
        self.ext_l2out_network = 1

        return

    def check_l2out_network(self, input_str, segment_name):
        '''Check L2 out network'''

        err_list = []
        if segment_name == 'provider':
            if self.is_provider_network_defined() == "UNDEFINED":
                err_str = "provider segment is not defined in " \
                    "[NETWORKING][networks] section"
                err_list.append(err_str)

            prov_l3_out = ['APICINFO', 'prov_l3out_network']
            prov_l3_vrf = ['APICINFO', 'prov_l3out_vrf']

            prov_l3_out_chk = \
                self.ymlhelper.get_deepdata_from_userinput_file(prov_l3_out)

            prov_l3_vrf_chk = \
                self.ymlhelper.get_deepdata_from_userinput_file(prov_l3_vrf)

            if prov_l3_out_chk is not None:
                err_msg = "Conflicting input of prov_l3out_network and " \
                          "prov_l2out_network provided"
                err_list.append(err_msg)

            if prov_l3_vrf_chk is not None:
                err_msg = "Conflicting input of prov_l3out_vrf and " \
                          "prov_l2out_network provided"
                err_list.append(err_msg)

        elif segment_name == 'management':
            mgmt_l3_out = ['APICINFO', 'mgmt_l3out_network']
            mgmt_l3_vrf = ['APICINFO', 'mgmt_l3out_vrf']

            mgmt_l3_out_chk = \
                self.ymlhelper.get_deepdata_from_userinput_file(mgmt_l3_out)

            mgmt_l3_vrf_chk = \
                self.ymlhelper.get_deepdata_from_userinput_file(mgmt_l3_vrf)

            if mgmt_l3_out_chk is not None:
                err_msg = "Conflicting input of mgmt_l3out_network and " \
                    "mgmt_l2out_network provided"
                err_list.append(err_msg)

            if mgmt_l3_vrf_chk is not None:
                err_msg = "Conflicting input of mgmt_l3out_vrf and " \
                    "mgmt_l2out_network provided"
                err_list.append(err_msg)

        elif segment_name == 'api':
            api_l3_out = ['APICINFO', 'api_l3out_network']
            api_l3_out_chk = \
                self.ymlhelper.get_deepdata_from_userinput_file(api_l3_out)

            if api_l3_out_chk is not None:
                err_msg = "Conflicting input of api_l3out_network and " \
                    "api_l2out_network provided"
                err_list.append(err_msg)

        elif segment_name == 'external':
            if not self.is_network_segment_defined('external'):
                err_str = "external segment is not defined in " \
                    "[NETWORKING][networks] section"
                err_list.append(err_str)

        if err_list:
            err_str = ','.join(err_list)
            raise Invalid(err_str)

        input_list = input_str.split(' ')
        self.execute_command_in_aci('query_interface_policy', input_list)

        return

    def check_loopback_syntax(self, input_str):
        '''Check Loopback Syntax'''

        self.is_input_in_plain_str_len32(input_str)
        if not re.match(r'loopback([0-9]+)', input_str, re.IGNORECASE):
            err_str = "syntax has to be of the type loopback<int>"
            raise Invalid(err_str)

    def check_ncs_mpls_plugin(self, input_str):
        '''Check if check_ncs_mpls_plugin is enabled'''

        if not isinstance(input_str, bool):
            err_str = "Input has to be of type bool"
            raise Invalid(err_str)

        if not self.is_tor_type_ncs5500() and input_str:
            err_str = "Input can be True, only TOR as NCS-5500 "
            raise Invalid(err_str)

        return

    def check_sriov_intf_policy_nofab_cfg_def(self, input_str):
        '''Check SRIOV interface policy with no fab cfg'''

        err_str = "Input of list with 1 interface policy " \
            "having a prefix of accportgrp- for SRIOV allowed"
        if not isinstance(input_str, list):
            raise Invalid(err_str)

        if len(input_str) > 1:
            raise Invalid(err_str)

        for item in input_str:
            if not re.match('accportgrp', item):
                raise Invalid(err_str)

        self.check_fab_intf_policy_def(input_str, 'query_fabric_port_policy')
        return

    def check_fab_sriov_intf_policy_def(self, input_str):
        '''Check the existence of Fabric SRIOV Policy in ACI'''

        if not isinstance(input_str, list):
            err_str = "Only input as list is allowed"
            raise Invalid(err_str)

        for item in input_str:
            if re.match('lacplagp', item):
                err_str = 'Policy of type lacplagp not allowed for SRIOV'
                raise Invalid(err_str)

        self.check_fab_intf_policy_def(input_str)
        return

    def check_fab_tor_intf_policy_def(self, input_str):
        '''Check the existence of Fabric Policy in ACI for tor_info'''

        if not isinstance(input_str, list):
            err_str = "Only input as list is allowed"
            raise Invalid(err_str)

        found_lacp_policy = 0
        for item in input_str:
            if re.match('lacplagp', item):
                found_lacp_policy = 1

        if not found_lacp_policy:
            err_str = 'Policy of type lacplagp needs to be defined'
            raise Invalid(err_str)

        self.check_fab_intf_policy_def(input_str)
        return

    def check_fab_intf_policy_def(self, input_str,
                                  api_name='query_fabric_infra_policy'):
        '''Check the existence of Fabric Policy in ACI'''

        if not isinstance(input_str, list):
            err_str = "Only input as list is allowed"
            raise Invalid(err_str)

        self.execute_command_in_aci(api_name, input_str)

        return

    def check_epg_policies(self, input_str):
        '''Check EPG Policy'''

        if not isinstance(input_str, list):
            err_str = "Only input as list is allowed"
            raise Invalid(err_str)

        dup_epg_policy_list = \
            self.check_for_dups_in_list(input_str)
        if dup_epg_policy_list:
            err_str = "Duplicate EPG Policy within a segement %s" \
                % (','.join(dup_epg_policy_list))
            raise Invalid(err_str)

        self.execute_command_in_aci('query_epg_policy', input_str)

        return

    def check_epg_policy(self, input_str):
        '''check_fepg_policy'''

        fab_intf_policy_schema = Schema({
            Optional('management'): self.check_epg_policies,
            Optional('provider'): self.check_epg_policies,
            Optional('tenant'): self.check_epg_policies,
        })

        if not self.cd_cfgmgr.extend_auto_tor_to_aci_fabric():
            err_msg = "EPG_POLICIES section can only be defined " \
                "when TOR configuration via ACI API is enabled"
            raise Invalid(err_msg)


        try:
            fab_intf_policy_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_fabric_interface_policy(self, input_str):
        '''check_fabric_interface_policy'''

        fab_intf_policy_schema = Schema({
            Required('tor_info'): self.check_fab_tor_intf_policy_def,
            Optional('dp_tor_info'): self.check_fab_intf_policy_def,
            Optional('sriov_tor_info'): self.check_fab_sriov_intf_policy_def,
        })

        fab_intf_policy_cpdp_schema = Schema({
            Required('tor_info'): self.check_fab_tor_intf_policy_def,
            Optional('sriov_tor_info'): self.check_fab_sriov_intf_policy_def,
        })

        fab_intf_policy_cpdp_nofab_cfg_schema = Schema({
            Required('sriov_tor_info'): self.check_sriov_intf_policy_nofab_cfg_def,
        })

        fab_intf_ceph_policy_schema = Schema({
            Required('tor_info'): self.check_fab_tor_intf_policy_def,
            Optional('dp_tor_info'): self.check_fab_intf_policy_def,
        })

        fabric_interface_fullon_policy_schema = Schema({
            Required('global'): fab_intf_policy_schema,
            Optional('control'): fab_intf_policy_schema,
            Optional('compute'): fab_intf_policy_schema,
            Optional('storage'): fab_intf_policy_schema,
        })

        fabric_interface_fullon_cpdp_policy_schema = Schema({
            Required('global'): fab_intf_policy_cpdp_schema,
            Optional('control'): fab_intf_policy_cpdp_schema,
            Optional('compute'): fab_intf_policy_cpdp_schema,
            Optional('storage'): fab_intf_policy_cpdp_schema,
        })

        fabric_interface_fullon_cpdp_nofab_cfg_policy_schema = Schema({
            Required('global'): fab_intf_policy_cpdp_nofab_cfg_schema,
        })

        fabric_interface_ceph_policy_schema = Schema({
            Required('global'): fab_intf_ceph_policy_schema,
            Optional('cephcontrol'): fab_intf_ceph_policy_schema,
            Optional('cephosd'): fab_intf_ceph_policy_schema,
        })

        fabric_interface_edge_cpdp_policy_schema = Schema({
            Required('global'): fab_intf_policy_cpdp_schema,
            Optional('control'): fab_intf_policy_cpdp_schema,
            Optional('compute'): fab_intf_policy_cpdp_schema,
        })

        vic_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_INTEL_SRIOV'])

        if vic_nic_check:
            try:
                if not self.cd_cfgmgr.check_configure_aci_fabric():
                    fabric_interface_fullon_cpdp_nofab_cfg_policy_schema(input_str)
                else:
                    fabric_interface_fullon_cpdp_policy_schema(input_str)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        elif self.ymlhelper.get_pod_type() == 'ceph':
            try:
                if not self.cd_cfgmgr.check_configure_aci_fabric():
                    fabric_interface_fullon_cpdp_nofab_cfg_policy_schema(input_str)
                else:
                    fabric_interface_ceph_policy_schema(input_str)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        elif (self.ymlhelper.get_pod_type() == 'fullon' or \
                self.ymlhelper.get_pod_type() == 'micro'):
            try:
                if not self.cd_cfgmgr.check_configure_aci_fabric():
                    fabric_interface_fullon_cpdp_nofab_cfg_policy_schema(input_str)
                else:
                    fabric_interface_fullon_policy_schema(input_str)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        elif self.ymlhelper.get_pod_type() == 'edge':
            try:
                fabric_interface_edge_cpdp_policy_schema(input_str)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_server_common(self, input_str):
        '''Check SERVER_COMMON Syntax'''

        common_hardware_info_options_schema = Schema({
            Optional('num_root_drive'): All(int, Range(min=ROOT_DRIVE_MIN,
                                                       max=ROOT_DRIVE_MAX)),
            Optional('root_drive_type'): In(frozenset(ROOT_DRIVE_TYPES)),
            Optional('root_drive_raid_level'): In(frozenset(
                ROOT_DRIVE_RAID_LEVELS)),
            Optional('root_drive_raid_spare'): All(int, Range(
                min=ROOT_DRIVE_RAID_SPARE_MIN, max=ROOT_DRIVE_RAID_SPARE_MAX)),
            Optional('vendor'): In(frozenset(SUPPORTED_VENDORS)),
            Optional('control_bond_mode'): In(frozenset(BOND_MODES)),
            Optional('data_bond_mode'): In(frozenset(BOND_MODES)),
        })

        server_common_hardware_info_schema = Schema({
            Optional('hardware_info'): common_hardware_info_options_schema,
        })

        server_common_schema = Schema({
            Required('server_username'): All(
                'root', msg='Only value of root supported'),
            Optional('vendor'): In(frozenset(SUPPORTED_VENDORS)),
            Optional('control'): server_common_hardware_info_schema,
            Optional('compute'): server_common_hardware_info_schema,
            Optional('block_storage'): server_common_hardware_info_schema,
            Optional('FABRIC_INTERFACE_POLICIES'):
                self.check_fabric_interface_policy,
            Optional('EPG_POLICIES'): self.check_epg_policy,
            Optional('VIC_admin_fec_mode'): In(frozenset(ADMIN_FEC_MODE)),
            Optional('VIC_port_channel_enable'): bool,
            Optional('VIC_link_training'): In(frozenset(LINK_TRAINING)),
            Optional('VIC_admin_speed'): In(frozenset(ADMIN_SPEED)),
            Optional('control_bond_mode'): In(frozenset(BOND_MODES)),
            Optional('data_bond_mode'): In(frozenset(BOND_MODES)),
        })

        try:
            server_common_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        fab_info = ['SERVER_COMMON', 'FABRIC_INTERFACE_POLICIES']

        fab_intf_policy = \
            self.ymlhelper.get_deepdata_from_userinput_file(fab_info)

        if fab_intf_policy is not None and \
                not self.cd_cfgmgr.extend_auto_tor_to_aci_fabric():
            err_msg = "FABRIC_INTERFACE_POLICIES section defined " \
                "when TOR configuration via ACI API is not enabled"
            raise Invalid(err_msg)

        epg_info = ['SERVER_COMMON', 'EPG_POLICIES']

        epg_info_policy = \
            self.ymlhelper.get_deepdata_from_userinput_file(epg_info)

        if epg_info_policy is not None and \
                not self.cd_cfgmgr.extend_auto_tor_to_aci_fabric():
            err_msg = "EPG_POLICIES section defined " \
                "when TOR configuration via ACI API is not enabled"
            raise Invalid(err_msg)

        return

    def check_mgmtnode_extapi_reach_status(self, input_str):
        '''Check cloud API reachability flag from mgmt node'''

        if not isinstance(input_str, bool):
            err_str = "Only boolean (True/False) input allowed"
            raise Invalid(err_str)

        if not input_str and self.is_vmtp_vts_present():
            err_str = "Entry not supported with VMTP option"
            raise Invalid(err_str)

        if not input_str and self.cd_cfgmgr.check_nfvbench_presence():
            err_str = "Entry not supported with NFVBENCH option"
            raise Invalid(err_str)

        return

    def check_vswitch_worker_profile(self, input_str):
        '''check for vswitch_worker_profile'''

        self.is_input_in_plain_str_len32(input_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        if mechanism_driver != 'vpp':
            err_str = "VSWITCH_WORKER_PROFILE allowed only with " \
                      "mechanism_driver vpp; " \
                      "Current mechanism driver is %s" % (mechanism_driver)
            raise Invalid(err_str)

        if input_str == 'numa_zero':
            pass
        elif input_str == 'even':
            pass
        else:
            err_msg = "Values of \'even\' or \'numa_zero' allowed " \
                "with mechanism driver vpp; Found to be %s" \
                % (input_str)
            raise Invalid(err_msg)

        return

    def check_vpp_enable_avf(self, input_str):
        """Value of true or false, default is false, \
        mechanism driver VPP and Intel NIC"""

        err_list = []
        if not isinstance(input_str, bool):
            err_str = "Only Boolean value True/False allowed; " \
                "default is False; current Input: %s" % input_str
            raise Invalid(err_str)

        if input_str is False:
            return

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        if mechanism_driver != 'vpp':
            err_str = "Option allowed when vpp is enabled"
            err_msg = "%s; Current mechanism driver is %s" \
                % (err_str, mechanism_driver)
            err_list.append(err_msg)

        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])
        if not intel_nic_check:
            err_str = "Option allowed when INTEL_NIC_SUPPORT is enabled"
            err_list.append(err_str)

        if err_list:
            err_msg = ", ".join(err_list)
            raise Invalid(err_msg)

    def check_reserved_pcores(self, input_str):
        '''Check check_reserved_pcores values'''

        if not isinstance(input_str, int):
            err_str = "Only input of type integer is allowed, " \
                      "in the range of 2-6 (including 2 and 6), " \
                      "current input is %s" % (input_str)
            raise Invalid(err_str)
        elif input_str >= 2 and input_str <= 6:
            pass
        else:
            err_str = "Allowed NR_RESERVED_VSWITCH_PCORES range of 2-6; " \
                      "Found: %s" % (input_str)
            raise Invalid(err_str)

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        if mechanism_driver != 'vpp':
            err_str = "NR_RESERVED_VSWITCH_PCORES allowed only with " \
                      "mechanism_driver vpp; " \
                      "Current mechanism driver is %s" % (mechanism_driver)
            raise Invalid(err_str)

        if not self.ymlhelper.get_data_from_userinput_file(['NFV_HOSTS']):
            err_info = "NR_RESERVED_VSWITCH_PCORES info provided, " \
                       "but @ data['NFV_HOSTS'] is missing"
            raise Invalid(err_info)

        return

    def check_reserved_pcores_control(self, input_str):
        """Check check_reserved_pcores Controller values"""

        if not isinstance(input_str, int):
            err_str = "Only input of type integer is allowed, " \
                      "in the range of 2-6 (including 2 and 6, " \
                      "current input is %s" % (input_str)
            raise Invalid(err_str)

        elif input_str >= 2 and input_str <= 6:
            pass

        else:
            err_str = "Allowed NR_RESERVED_HOST_PCORES range of 2-6; " \
                      "Found: %s" % (input_str)
            raise Invalid(err_str)

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        if podtype is not None and re.match(r'micro|edge|nano|ceph', podtype):
            pass
        else:
            err_str = "Configuration not allowed for Fullon or UMHC or NGENAHC pod"
            raise Invalid(err_str)

        return

    def check_ceph_osd_reserved_core(self, input_str):
        '''Checks the CEPH_OSD_RESERVED_PCORES values'''

        if not isinstance(input_str, int):
            err_str = "Only input of type integer is allowed, " \
                      "in the range of 2-12 (including 2 and 12), " \
                      "current input is %s" % (input_str)
            raise Invalid(err_str)
        elif input_str >= 2 and input_str <= 12:
            pass
        else:
            err_str = "Allowed range of 2-12; found to be %s" % (input_str)
            raise Invalid(err_str)

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        if podtype is not None and re.match(r'UMHC|NGENAHC|micro', podtype):
            pass
        else:
            err_str = "Configuration not allowed for Fullon pod"
            raise Invalid(err_str)

        return

    def is_ceph_multi_backend(self):
        '''Check if Ceph is multi backend'''

        ceph_server_list = self.ymlhelper.get_server_list(role="block_storage")

        for server in ceph_server_list:
            ceph_type = self.ymlhelper.get_ceph_cluster_info(server)

            if self.global_multi_backend_hdd_ceph and \
                    self.global_multi_backend_ssd_ceph:
                break

            if ceph_type == 'UNDEFINED' or ceph_type == 'HDD':
                self.global_multi_backend_hdd_ceph = 1
            elif ceph_type == 'SSD':
                self.global_multi_backend_ssd_ceph = 1

        if self.global_multi_backend_hdd_ceph and \
                self.global_multi_backend_ssd_ceph:
            self.global_multi_backend_ceph = 1
            return 1

        return 0

    def check_multi_backend_ceph(self):
        '''Check multi_backend_ceph'''

        ceph_server_list = self.ymlhelper.get_server_list(role="block_storage")
        tmp_ceph_server_list = copy.deepcopy(ceph_server_list)

        hdd_ceph_dict = {}
        ssd_ceph_dict = {}
        num_storage = 3

        missing_ssd_node_list = []
        missing_hdd_node_list = []
        unique_ssd_ceph_type_list = []
        unique_hdd_ceph_type_list = []

        err_list = []
        if re.search(r'remove_osd', self.curr_action):
            num_storage = 2

        for server in ceph_server_list:
            ceph_type = self.ymlhelper.get_ceph_cluster_info(server)

            if ceph_type == 'UNDEFINED' or ceph_type == 'HDD':
                ceph_type = 'HDD'
                if ceph_type not in unique_hdd_ceph_type_list:
                    unique_hdd_ceph_type_list.append(ceph_type)
                hdd_ceph_dict.setdefault(ceph_type, []).append(server)

            elif ceph_type == 'SSD':
                if ceph_type not in unique_ssd_ceph_type_list:
                    unique_ssd_ceph_type_list.append(ceph_type)
                ssd_ceph_dict.setdefault(ceph_type, []).append(server)

        if ssd_ceph_dict:
            for item in unique_ssd_ceph_type_list:
                ceph_list = ssd_ceph_dict[item]
                if len(ceph_list) < num_storage:
                    err_str = "Min number of SSD based storage " \
                              "node(s) is %s; found %s" \
                              % (num_storage, len(ceph_list))
                    err_list.append(err_str)

                for info in ceph_list:
                    if info not in ceph_server_list:
                        missing_ssd_node_list.append(info)
                    else:
                        tmp_ceph_server_list.remove(info)

                if missing_ssd_node_list:
                    err_str = "Missing SSD node(s) %s " \
                        "from block_storage_list" \
                        % (','.join(missing_ssd_node_list))
                    err_list.append(err_str)

        if hdd_ceph_dict:
            for item in unique_hdd_ceph_type_list:
                ceph_list = hdd_ceph_dict[item]

                if len(ceph_list) < num_storage:
                    err_str = "Min number of HHD based storage " \
                              "node(s) is %s; found %s" \
                              % (num_storage, len(ceph_list))
                    err_list.append(err_str)

                for info in ceph_list:
                    if info not in ceph_server_list:
                        missing_hdd_node_list.append(info)
                    else:
                        tmp_ceph_server_list.remove(info)

                if missing_hdd_node_list:
                    err_str = "Missing HDD node(s) %s " \
                              "from block_storage_list" \
                              % (','.join(missing_hdd_node_list))
                    err_list.append(err_str)

        if self.global_multi_backend_hdd_ceph \
                and self.global_multi_backend_ssd_ceph \
                and tmp_ceph_server_list:
            err_str = "Few Block storage node(s) are " \
                "not allocated to HDD/SSD backend:%s" \
                % (','.join(tmp_ceph_server_list))
            err_list.append(err_str)
        elif tmp_ceph_server_list:
            if len(tmp_ceph_server_list) < num_storage:
                err_str = "Min number of non osd_disk_type based " \
                          "storage node(s) is %s; found %s" \
                          % (num_storage, len(tmp_ceph_server_list))
                err_list.append(err_str)

        if self.global_multi_backend_hdd_ceph and \
                self.global_multi_backend_ssd_ceph:
            self.global_multi_backend_ceph = 1

        return err_list

    def check_nfvimon_master_admin_ip(self, input_str):
        '''Checks nfvimon_master_admin_ip validity'''

        self.is_ip_syntax_valid(input_str)
        self.global_nfvimon_master_admin_ip.append(input_str)

    def check_esi_prefix_syntax(self, input_str):
        ''' Check ESI Prefix syntax'''

        err_str = "Input has to be of 8 octets in length and in dotted " \
            "decimal format with only numbers in between the dots"
        if not isinstance(input_str, str):
            raise Invalid(err_str)

        err_str1 = "%s; Found to be %s" % (err_str, input_str)

        pattern = re.compile("^([0-9][0-9])$")
        entry_list = input_str.split(".")
        for item in entry_list:
            if not pattern.match(item):
                raise Invalid(err_str1)

        if len(entry_list) != 7:
            raise Invalid(err_str1)

        num_octect_len = sys.getsizeof(input_str) / 8
        if num_octect_len > 7:
            raise Invalid(err_str1)

        if not self.is_tor_type_ncs5500():
            err_str = "Option allowed when TOR is NCS-5500"
            raise Invalid(err_str)

        return

    def check_nfvimon_admin_entry(self, input_str):
        '''Check NFVIMON ADMIN Entry'''

        if not isinstance(input_str, str):
            err_msg = "input has to be of type string"
            raise Invalid(err_msg)
        elif ' ' in input_str:
            err_msg = "entry has spaces"
            raise Invalid(err_msg)

        return

    def check_enable_vm_emulator_pin(self, input_str):
        '''Check enable_vm_emulator_pin input'''

        if not isinstance(input_str, bool):
            err_str = "Only Boolean value True/False allowed; " \
                "default is False"
            raise Invalid(err_str)

        if not self.ymlhelper.get_data_from_userinput_file(['NFV_HOSTS']):
            err_msg = "Allowed only with NFV_HOSTS"
            raise Invalid(err_msg)

        return True

    def check_vm_emulator_pcore_per_server(\
            self, server_name, input_str, vm_em_pin_per_server):
        """Check enable_vm_emulator_pcore on a per server basis"""

        if not isinstance(input_str, int):
            err_str = "Non-Integer Input not allowed"
            raise Invalid(err_str)

        err_str = "Entry value of 1 to 4 allowed, " \
            "found to be %s" % (input_str)
        if input_str == 0:
            raise Invalid(err_str)
        elif input_str > 4:
            raise Invalid(err_str)

        global_vm_em_pin_status = \
            self.ymlhelper.get_data_from_userinput_file(\
                ['ENABLE_VM_EMULATOR_PIN'])

        if vm_em_pin_per_server is not None and vm_em_pin_per_server is False:
            err_msg = ": VM_EMULATOR_PCORES_PER_SOCKET allowed at per " \
                "server level when ENABLE_VM_EMULATOR_PIN is enabled at a " \
                "per server or global level; currently " \
                "ENABLE_VM_EMULATOR_PIN is set to false at server level"
            raise Invalid(err_msg)

        if (global_vm_em_pin_status is None or \
                global_vm_em_pin_status is False) and \
                (vm_em_pin_per_server is None):
            err_msg = "Allowed only with " \
                "ENABLE_VM_EMULATOR_PIN enabled globally or at " \
                "a per server level"
            raise Invalid(err_msg)

        return True

    def check_vm_emulator_pcore_per_socket(self, input_str):
        '''Check enable_vm_emulator_pin input'''

        if not isinstance(input_str, int):
            err_str = "Non-Integer Input not allowed"
            raise Invalid(err_str)

        err_str = "Entry value of 1 to 4 allowed, " \
            "found to be %s" % (input_str)
        if input_str == 0:
            raise Invalid(err_str)
        elif input_str > 4:
            raise Invalid(err_str)

        vm_em_pin_status = \
            self.ymlhelper.get_data_from_userinput_file(\
                ['ENABLE_VM_EMULATOR_PIN'])

        if vm_em_pin_status is None or vm_em_pin_status is False:
            err_msg = "Allowed only with " \
                "ENABLE_VM_EMULATOR_PIN enabled"
            raise Invalid(err_msg)

        return True

    def check_base_macaddress(self, input_str):
        '''Check Base Mac address Syntax'''

        expt_err_str = "Input of mac address that ends with 00:00; " \
            "Also in the first octet, the 1st entry " \
            "is a hex and the 2nd entry has to be 2, 6, a or e; " \
            "Current input found to be %s; Expected: x[2,6,a,e]:yz:uv:ws:00:00" \
            % (input_str)

        err_str = self.is_input_in_plain_str(input_str, 255)
        if err_str:
            raise Invalid(err_str)

        if not netaddr.valid_mac(input_str.lower()):
            raise Invalid(expt_err_str)

        if not re.match("[a-f:][2,6,a,e][0-9a-f:]+00:00$", input_str.lower()):
            raise Invalid(expt_err_str)

        return

    def check_macaddress(self, input_str):
        """ Check Mac address Syntax """
        expt_err_str = "Incorrect mac address; " \
                       "Current input found to be %s; "\
                       "Expected like: 72:d4:93:f5:47:e1 hex values "\
                       "separated by a colon" \
                       % (input_str)

        err_str = self.is_input_in_plain_str(input_str, 255)
        if err_str:
            raise Invalid(err_str)

        if not netaddr.valid_mac(input_str.lower()):
            raise Invalid(expt_err_str)

    def is_testing_section_defined(self):
        '''Check if testing section is defined'''

        testing_list = []
        item_not_found_list = []
        item_found_list = []
        testing_list.append('TESTING_TESTBED_NAME')
        testing_list.append('TESTING_MGMT_NODE_CIMC_IP')
        testing_list.append('TESTING_MGMT_CIMC_USERNAME')
        testing_list.append('TESTING_MGMT_CIMC_PASSWORD')
        testing_list.append('TESTING_MGMT_NODE_API_IP')
        testing_list.append('TESTING_MGMT_NODE_API_GW')
        testing_list.append('TESTING_MGMT_NODE_TIMEZONE')
        testing_list.append('TESTING_MGMT_NODE_IPV6_ENABLE')
        testing_list.append('TESTING_MGMT_NODE_MODE')
        testing_list.append('TESTING_MGMT_NODE_USE_TEAMING')

        testing_v6_list = []
        testing_v6_list.append('TESTING_MGMT_NODE_API_GW_IPV6')
        testing_v6_list.append('TESTING_MGMT_NODE_API_IPV6')
        testing_v6_list.append('TESTING_MGMT_NODE_MGMT_IPV6')

        for item in testing_list:
            check_item = \
                self.ymlhelper.get_data_from_userinput_file([item])

            if check_item is None:
                item_not_found_list.append(item)
            else:
                item_found_list.append(item)

        item = 'TESTING_MGMT_NODE_IPV6_ENABLE'
        is_ipv6_on = self.ymlhelper.get_data_from_userinput_file([item])
        if is_ipv6_on == 'yes':
            for item in testing_v6_list:
                check_item = \
                    self.ymlhelper.get_data_from_userinput_file([item])

                if check_item is None:
                    item_not_found_list.append(item)
                else:
                    item_found_list.append(item)

        if item_found_list and item_not_found_list:
            err_str = "ERROR: Information missing for %s in " \
                "TESTING section" % (','.join(item_not_found_list))
            return err_str

        return "PASS"

    def check_epg_syntax(self, input_str):
        '''check_epg_syntax'''
        self.check_epg_bd_syntax(input_str, "VL-%s-EPG")

    def check_bd_syntax(self, input_str):
        '''check_bd_syntax'''
        self.check_epg_bd_syntax(input_str, "VL-%s-BD")

    def check_epg_bd_syntax(self, input_str, pattern):
        '''check_epg_bd_syntax'''
        err_str = "Input has to be of type string with the " \
            "following syntax %s" % (pattern)

        if not isinstance(input_str, str):
            raise Invalid(err_str)
        elif not re.match(pattern, input_str):
            raise Invalid(err_str)
        return

    def check_apic_provider_vlan_details(self, input_str):
        '''check_apic_provider_vlan_details'''
        self.check_apic_vlan_details(input_str, 'PROVIDER')

    def check_apic_tenant_vlan_details(self, input_str):
        '''check_apic_tenant_vlan_details'''
        self.check_apic_vlan_details(input_str, 'TENANT')

    def check_prov_vlan_id_syntax(self, input_str):
        '''Check if VLAN are in right syntax'''
        self.check_prov_vlan_info(input_str)
        return

    def check_tenant_vlan_id_syntax(self, input_str):
        '''Check if VLAN are in right syntax'''
        self.check_vlan_info(input_str)
        return

    def check_l3_vlanid_syntax(self, input_str):
        '''Check check_l3_vlanid_syntax'''

        err_msg = "Single VLAN input of type string between " \
            "2 and 4094 allowed for L3 network, found %s" \
            % (input_str)

        try:
            if not isinstance(input_str, str):
                raise Invalid(err_msg)
            elif not isinstance(int(input_str), int):
                raise Invalid(err_msg)
            elif not self.is_input_range_valid(int(input_str), 2, 4094):
                raise Invalid(err_msg)
        except ValueError:
            raise Invalid(err_msg)

        return

    def check_vlan_pools_in_apic(self, input_str):
        '''check_vlan_pools_in_apic'''

        if not isinstance(input_str, list):
            err_str = "Only input as list is allowed"
            raise Invalid(err_str)

        self.execute_command_in_aci('query_vlan_pool', input_str)
        return

    def check_phys_dom_in_apic(self, input_str):
        '''check_phys_dom_in_apic'''

        if not isinstance(input_str, str):
            err_str = "Only input as string is allowed"
            raise Invalid(err_str)

        input_list = input_str.split(' ')
        self.execute_command_in_aci('query_phys_dom', input_list)
        return

    def check_tenant_in_apic(self, input_str):
        '''check_tenant_in_apic'''

        if not isinstance(input_str, str):
            err_str = "Only input as string is allowed"
            raise Invalid(err_str)

        input_list = input_str.split(' ')
        self.execute_command_in_aci('query_apic_tenant', input_list)
        return

    def check_app_profile_in_apic(self, tenant_name, app_profile):
        '''check_app_profile_in_apic'''

        response = self.execute_minput_command_in_aci(\
            'query_apic_app_profile', tenant_name, app_profile)

        if re.search(r'ERROR:', response):
            raise Invalid(response)

        return

    def check_vrf_in_apic(self, tenant_name, vrf_name):
        '''check_vrf_in_apic'''

        response = self.execute_minput_command_in_aci(\
            'query_apic_vrf', tenant_name, vrf_name)

        if re.search(r'ERROR:', response):
            raise Invalid(response)

        return

    def check_l3out_in_apic(self, tenant_name, input_list):
        '''check_l3out_in_apic'''

        err_msg = "Input has to be of type list"
        if not isinstance(input_list, list):
            raise Invalid(err_msg)

        invalid_response_list = []
        api_name = 'query_l3out_network'

        for item in input_list:
            response = self.execute_minput_command_in_aci(\
                api_name, tenant_name, item)

            if re.search(r'ERROR:', response):
                invalid_response_list.append(item)

        if invalid_response_list:
            err_msg = "ERROR: APIC check via %s failed for %s on %s" \
                % (api_name, tenant_name, ','.join(invalid_response_list))
            raise Invalid(err_msg)

        return

    def execute_minput_command_in_aci(self,
                                      api_name,
                                      tenant_name,
                                      tenant_attribute,
                                      attribute_profile=""):
        '''Execute APIC API post login'''

        try:

            if attribute_profile:
                api_response = \
                    self.ymlhelper.execute_apic_command_via_api(\
                        api_name, tenant_name, tenant_attribute, \
                        attribute_profile)

            else:
                api_response = \
                    self.ymlhelper.execute_apic_command_via_api(\
                        api_name, tenant_name, tenant_attribute)

            if not self.ymlhelper.check_api_response(api_response):
                err_msg = "ERROR: Invalid API response for %s via %s; " \
                    "Response details:%s" \
                    % (api_name, tenant_name, api_response)
                self.log.info(err_msg)
                return err_msg

        except Exception:
            err_msg = "ERROR: APIC check via %s failed for %s on %s" \
                % (api_name, tenant_name, tenant_attribute)

            return err_msg

        return "PASS"

    def execute_command_in_aci(self, api_name, input_list):
        '''Execute APIC API post login'''

        invalid_apic_response_list = []
        for item in input_list:
            try:
                api_response = \
                    self.ymlhelper.execute_apic_command_via_api(\
                        api_name, item)

                if not self.ymlhelper.check_api_response(api_response):
                    err_msg = "Invalid API response for %s via %s; " \
                        "Response details:%s" \
                        % (item, api_name, api_response)
                    self.log.info(err_msg)
                    invalid_apic_response_list.append(item)
            except AttributeError:
                err_msg = "ERROR: APIC check via %s on %s failed" \
                          % (api_name, item)
                raise Invalid(err_msg)

        if invalid_apic_response_list:
            err_msg = "ERROR: APIC check via %s on %s failed" \
                      % (api_name, ','.join(invalid_apic_response_list))
            raise Invalid(err_msg)
        return

    def check_ipv4v6_cidr(self, input_str):
        '''Check IPv4 or V6 based CIDR'''

        found_v4 = 0
        found_v6 = 0
        err_msg = "Input needs to be IPv4 or IPv6 based CIDR"

        if not isinstance(input_str, str):
            raise Invalid(err_msg)

        if not re.search(r'/', input_str):
            raise Invalid(err_msg)

        input_list = input_str.split("/")

        curr_ip = input_list[0]
        self.check_input_as_ipv4v6(curr_ip)
        if self.is_ip_valid(curr_ip):
            found_v4 = 1
        else:
            found_v6 = 1

        if (not found_v6) and (not found_v4):
            raise Invalid(err_msg)

        if found_v4:
            self.validate_external_network_syntax(input_str)

        if found_v6:
            self.validate_external_v6network_syntax(input_str)
        return

    def check_subnet_def_in_apic(self, input_str):
        '''check_subnet_def_in_apic'''

        if not isinstance(input_str, list):
            err_str = "Only input as list is allowed"
            raise Invalid(err_str)

        subnet_v6_schema = Schema({
            Required('scope'): In(frozenset(["private", "public", \
                "private,shared"]), \
                msg='only values of private or public or private,shared allowed'),
            Required('gateway_cidr'): self.check_ipv4v6_cidr,
            Optional('ctrl'): In(frozenset(["no-default-gateway", "nd", \
                "nd,no-default-gateway", "no-default-gateway,nd", "unspecified"])),
        })

        subnet_v4_schema = Schema({
            Required('scope'): In(frozenset(["private", "public", \
                "private,shared"]), \
                msg='only values of private or public or private,shared allowed'),
            Required('gateway_cidr'): self.check_ipv4v6_cidr,
            Optional('ctrl'): In(frozenset(["no-default-gateway", "querier", \
                "querier,no-default-gateway", "no-default-gateway,querier", \
                "unspecified"])),
        })

        for item in input_str:
            ip_info = item.get('gateway_cidr', None)
            if ip_info is None:
                err_str = "gateway_cidr input is not defined"
                raise Invalid(err_str)

            ip_info_list = ip_info.split("/")
            curr_ip = ip_info_list[0]
            self.check_input_as_ipv4v6(curr_ip)
            found_v4 = 0

            if self.is_ip_valid(curr_ip):
                found_v4 = 1

            try:
                if found_v4:
                    subnet_v4_schema(item)
                else:
                    subnet_v6_schema(item)
                self.apic_gateway_cidr_list.append(item.get('gateway_cidr'))
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def cvimmonha_monitor_schema(self, input_str):
        '''Validate the CVIM MON MONITOR Namespace features'''

        cvimmonmonitor_ldap_schema = Schema({
            Required('group_mappings'): self.cvimmon_ldap_group_mappings,
            Required('domain_mappings'): self.cvimmon_ldap_domain_mappings,
        })

        monitor_schema = Schema({
            Optional('ldap'): cvimmonmonitor_ldap_schema,
        }, extra=False)

        try:
            monitor_schema(input_str)
        except MultipleInvalid as e:
            raise \
                Invalid(' '.join(str(x) for x in e.errors))

        return

    def cvimmonha_properties_schema(self, input_str):
        '''Validate stack info within cvim-mon-stacks'''
        if input_str is None:
            raise Invalid("Missing Entry, need to provide a list of stacks")

        cvimmon_ldap_schema = Schema({
            Required('group_mappings'): self.cvimmon_ldap_group_mappings,
            Required('domain_mappings'): self.cvimmon_ldap_domain_mappings,
        })

        stack_name = Schema({
            Required('name'): self.is_stack_name_valid,
        }, extra=True)

        stack_schema = stack_name.extend({
            Optional('metrics_retention'): self.is_metrics_retention_valid,
            Optional('SNMP'): self.check_snmp_settings,
            Optional('stack_ca_cert'):
                All(str, self.is_certificate_file(check_cert_path=True)),
            Optional('ldap'): cvimmon_ldap_schema,
            Optional('https_proxy_server'): self.check_http_syntax,
            Required('metrics_volume_size_gb'): self.is_metrics_volume_size_valid,
            Optional('max_node_count'): self.is_max_node_count_valid,
            Optional('scrape_interval'): self.is_scrape_interval_valid,
            Optional('regions'): self.check_region,
        }, extra=False)

        for stack in input_str:
            try:
                stack_name(stack)
            except MultipleInvalid as e:
                raise \
                    Invalid("expected a list of stacks")
            try:
                stack_schema(stack)
            except MultipleInvalid as e:
                stackname = stack.get('name')
                raise Invalid(' '.join(str(x) for x in e.errors) + \
                              " for stack " + stackname)

        return

    def check_region(self, input_str):
        '''Validate the metro keys'''

        if not input_str:
            raise Invalid("Missing Entry")

        region_schema = Schema({
            Required('name'): self.is_name_defined,
            Optional('metros'): self.check_metro,
        })

        for region in input_str:
            try:
                region_schema(region)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_metro(self, input_str):
        '''Validate openstack node keys'''

        if input_str is None:
            raise Invalid("Missing Entry")

        metro_schema = Schema({
            Required('name'): self.is_name_defined,
            Optional('pods'): self.check_pod,
        })

        for metro in input_str:
            try:
                metro_schema(metro)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_pod(self, input_str):
        '''Validate telegraf key'''

        if input_str is None:
            raise Invalid("Missing Entry")

        for pod in input_str:

            pod_name_schema = Schema({
                Required('name'): self.is_name_defined,
            }, extra=True)

            external_pod_schema = pod_name_schema.extend({
                Required('ip'): self.check_telegraf_syntax,
                Optional('target_type'): In(frozenset(["internal", "external"])),
            }, extra=False)

            pod_schema = external_pod_schema.extend({
                Required('cert'):
                    All(str, self.is_ca_certificate_file(check_cert_path=True)),
                Required('cvim_mon_proxy_password'): All(str, Length(min=1)),
                Required('username'): self.is_input_in_plain_str,
                Optional('inventory_api_password'): self.is_input_in_plain_str,
                Optional('inventory_mongo_password'): self.is_input_in_plain_str,
            }, extra=False)

            try:
                pod_name_schema(pod)
            except MultipleInvalid as e:
                raise \
                    Invalid(' '.join(str(x) for x in e.errors))

            curr_target_type = pod.get('target_type', None)
            podname = pod.get('name')

            try:
                if curr_target_type is not None and curr_target_type == 'external':
                    external_pod_schema(pod)
                else:
                    pod_schema(pod)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors) + " for " + podname)

        return

    def check_telegraf_input(self, input_str):
        '''Validate Telegraf settings keys'''
        telegraf_input_schema = Schema({
            Required('Cert'): All(str, self.is_ca_certificate_file()),
            Required('IP'): self.check_telegraf_syntax,
            Required('Secret'): All(str, Length(min=1)),
            Required('Username'): self.is_input_in_plain_str,
        })

        try:
            telegraf_input_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_telegraf_syntax(self, input_str):
        '''Check that the port and ip of telegraf node is valid'''
        if input_str is None:
            raise Invalid("Missing ip address and port info")

        dhcp_mode = self.ymlhelper.get_argus_ip_install_mode()

        ip = input_str.rsplit(':', 1)[0]

        try:
            ip = input_str.rsplit(':', 1)[0]
            port_check_entry = input_str.rsplit(':', 1)[1]

            if port_check_entry != "9283" and port_check_entry != "9273":
                err_str = "Incorrect or missing cvim target port information 9283" \
                    + " or 9273 for external servers"
                raise Invalid(err_str)

            if dhcp_mode == 'v6':
                if not ip.startswith('[') or not ip.endswith(']'):
                    err_str = "Cvim-mon target " \
                        + " %s needs to be ipv6 with " % (ip) \
                        + "'[' before ip address and ']' after ip address"
                    raise Invalid(err_str)
                self.is_ipv6_syntax_valid(ip[1:-1])
            else:
                self.is_ip_syntax_valid(ip)

        except IndexError:
            err_str = "Invalid ip and port syntax for " \
                + "Cvim-mon target %s" % (input_str)
            raise Invalid(err_str)

        return

    def check_loadbalancer_ip(self, input_str):
        '''Check if external/internal loadbalancer ip is valid'''
        dhcp_mode = self.ymlhelper.get_argus_ip_install_mode()
        if dhcp_mode is None:
            return

        if dhcp_mode == 'v6':
            self.is_ipv6_syntax_valid(input_str)
        else:
            self.is_ip_syntax_valid(input_str)

        return

    def check_domain_suffix(self, input_str):
        '''Check if cvim-mon-ha domain suffix is valid'''
        err_str = "Incorrect format for domain name suffix"

        if re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', str(input_str)):
            pass
        else:
            raise Invalid(err_str)

        return

    def check_log_rotation_size(self, input_str):
        '''Check the max size of the cloud log files to start rotating them'''

        if (input_str[-1:] not in list("kMG")):
            raise Invalid("Must specify unit: (k)ilobytes, (M)egabytes "
                          "or (G)igabytes")

        if isinstance(input_str[:-1], int):
            if input_str[:-1] <= 0:
                raise Invalid("Input has to be an integer > 0 plus the "
                              "unit(k,M,G)")
            else:
                raise Invalid("Only integer input type is allowed")
        return ""

    def check_log_rotation_del_older(self, input_str):
        '''
        Check the parameter which indicates the older logs to be deleted
        on the cloud nodes
        '''

        err_str = ""
        if isinstance(input_str, int):
            if input_str <= 0:
                err_str = "Input has to be a non-zero positive number"
                raise Invalid(err_str)
        else:
            err_str = "Only input type of int is allowed"
            raise Invalid(err_str)

    def is_stack_name_valid(self, input_str):
        '''Check if cvim-mon stack names are kubernetes standard compliant'''
        err_str = "Stack name must only contain lower-case alphanumeric " \
            + "characters and special character '-'"

        if re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', str(input_str)):
            pass
        else:
            raise Invalid(err_str)

        return

    def is_cluster_name_valid(self, input_str):
        '''Check if cvim-mon cluster name is domain name compliant'''
        if input_str is None:
            err_str = "Must provide cluster name in domain name format"
            raise Invalid(err_str)

        err_str = "Cluster name must only contain lower-case alphanumeric " \
            + "characters and special character '-'"
        if re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', input_str):
            pass
        else:
            raise Invalid(err_str)

        return

    def is_metrics_retention_valid(self, input_str):
        """Check if the metrics_retention value is valid input for prometheus"""
        err_str = "Incorrect prometheus metrics retention policy. " \
                  + "Must be an integer followed by d, w, or y"

        if re.match(r'^[1-9]([0-9]+)?([dwy])$', str(input_str)):
            pass
        else:
            raise Invalid(err_str)

        return

    def is_max_node_count_valid(self, input_str):
        """Check Max_nodes_size"""
        err_str = "Incorrect Max Nodes size. "\
                  + "Should be between 1k to 10k.Integer followed by 'k' suffix"
        m = re.match(r'^(\d+)([K])$', str(input_str).upper())
        if not m:
            raise Invalid(err_str)
        if m.group(2).upper() == 'K' and 1 <= int(m.group(1)) <= 10:
            pass
        else:
            raise Invalid(err_str)
        return

    def is_metrics_volume_size_valid(self, input_str):
        """Check metrics volume siz"""
        err_str = "Incorrect metrics volume size. " \
                  + "Should be a integer or integer followed by 'Gi' suffix"

        if re.match(r'^[1-9]([0-9]+)?Gi$', str(input_str)):
            pass
        else:
            raise Invalid(err_str)
        return

    def is_scrape_interval_valid(self, input_str):
        """Check if the user has provided a scrape interval that is valid
        If not, default scrape interval to 1 minute"""
        err_str = "Incorrect scrape interval format provided. " \
            + "Must be an integer followed by s, m, or h"

        m = re.match(r'^(\d+)([smh])$', str(input_str))
        if not m:
            raise Invalid(err_str)
        if m.group(2) == 's' and int(m.group(1)) < 15:
            raise Invalid('The value of scrape_interval should be at least 15s')
        return

    def check_iso(self, input_str):
        '''Check if ARGUS_BAREMETAL key is present or not'''

        if input_str is None or len(input_str) != 1:
            err_str = "ISO section of setup data must contain exactly " \
                + " one key-value pair"
            raise Invalid(err_str)

        if not re.match(r'^[a-zA-Z]+(-[a-zA-Z]+)*$', str(input_str.keys()[0])):
            err_str = "ISO Key cannot have special chars," \
                + " numbers or spaces"
            raise Invalid(err_str)

        if input_str.values()[0] is None:
            err_str = "ISO file must be present in provided ISO location"
            raise Invalid(err_str)

        iso_name = input_str.values()[0].split('/')[-1]
        if not re.match(r'^buildnode-(internal|K9)-\d+\.iso$', iso_name):
            err_str = "ISO Value must be in format," \
                + " buildnode-<internal/K9>-<integer>.iso"
            raise Invalid(err_str)

        self.check_file_presence(input_str.values()[0])
        return

    def check_argus_server_names(self, input_str):
        '''Check if all argus server names follow kubernetes naminc conventions'''

        err_str = "Argus server names should consist of lower " \
            + "case alphanumeric characters, -, and ."

        if not re.match(r'^[a-z0-9]+([-.][a-z0-9]+)*$', input_str):
            raise Invalid(err_str)

        return

    def check_cvim_role(self, role_name):
        '''Check if CVIM-MON roles are properly defined'''

        err_str = "Invalid role '%s'." % role_name
        err_str = err_str + "CVIM-MON roles can be either 'master' or 'worker'"

        if role_name not in ['worker', 'master']:
            raise Invalid(err_str)
        return

    def check_site_schema(self, input_str):
        '''Check the site config options'''

        site_config_schema = Schema({
            Required('name'): self.is_name_defined,
            Required('info'): self.is_input_in_ascii,
            Required('clusters'): self.check_argus_clusters,
            Required('common_info'): self.check_argus_common_info,
        }, extra=False)

        try:
            site_config_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_argus_clusters(self, input_str):
        '''Check argus server name, cimc, management ips, api ips'''
        if input_str is None:
            raise Invalid("Missing Entry")

        if len(input_str) != 1:
            raise Invalid("Error: Cannot have more than one Argus site cluster")

        argus_cluster_schema = Schema({
            Required('name'): self.is_name_defined,
            Required('info'): self.is_input_in_ascii,
            Required('servers'): self.check_argus_servers,
        }, extra=False)

        for cluster in input_str:
            try:
                argus_cluster_schema(cluster)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_provider_nd_policy_input(self, input_str):
        '''Check the syntax and semantics of nd_policy; if true,
        check if ndifpol is defined in EPG_POLICIES/provider info'''

        if not isinstance(input_str, bool):
            err_str = "Only Boolean value True/False allowed"
            raise Invalid(err_str)

        if input_str:
            epg_policy_stat = self.check_epg_policy_def(segment_name="provider", \
                                                        epg_policy_prefix="ndifpol")
            if re.search('ERROR:', epg_policy_stat):
                raise Invalid(epg_policy_stat)

        return

    def check_tenant_nd_policy_input(self, input_str):
        '''Check the syntax and semantics of nd_policy; if true,
        check if ndifpol is defined in EPG_POLICIES/tenant info'''

        if not isinstance(input_str, bool):
            err_str = "Only Boolean value True/False allowed"
            raise Invalid(err_str)

        if input_str:
            epg_policy_stat = self.check_epg_policy_def(segment_name="tenant", \
                                                        epg_policy_prefix="ndifpol")
            if re.search('ERROR:', epg_policy_stat):
                raise Invalid(epg_policy_stat)

        return

    def check_epg_policy_def(self, segment_name, epg_policy_prefix):
        '''Check if EPG Policy is defined'''

        epg_policy = ['SERVER_COMMON', 'EPG_POLICIES']
        epg_policy_chk = \
            self.ymlhelper.get_deepdata_from_userinput_file(epg_policy)

        if epg_policy_chk is None:
            return "ERROR: SERVER_COMMON:EPG_POLICIES not defined"
        else:
            segment_specific_info = epg_policy_chk.get(segment_name, None)

            if segment_specific_info is None:
                return "ERROR: SERVER_COMMON:EPG_POLICIES:%s " \
                    "not defined" % (segment_name)
            elif not isinstance(segment_specific_info, list):
                return "ERROR: SERVER_COMMON:EPG_POLICIES:%s " \
                    "not defined" % (segment_name)

            else:
                for item in segment_specific_info:
                    if re.search(epg_policy_prefix, item):
                        return "PASS"

        return "ERROR: SERVER_COMMON:EPG_POLICIES:%s:%s not defined" \
            % (segment_name, epg_policy_prefix)

    def check_apic_vlan_details(self, input_str, vlan_type):
        ''''Check the VLAN details for TENANT or PROVIDER'''

        apic_pre_prov_schema = Schema({
            Required('vlan_ids'): self.check_l3_vlanid_syntax,
            Optional('EPG_NAME'): str,
            Required('tenant'): self.check_tenant_in_apic,
            Required('app_profile'): str,
            Required('vlan_pools'): self.check_vlan_pools_in_apic,
            Required('mode'): In(frozenset(["trunk", "access"]),
                                 msg='only trunk or access allowed as values'),
            Optional('config_type'): In(frozenset(["pre-provisioned"])),
        })

        apic_l3_schema = Schema({
            Required('vlan_ids'): self.check_l3_vlanid_syntax,
            Optional('EPG_NAME'): str,
            Optional('BD_NAME'): str,
            Required('vlan_pools'): self.check_vlan_pools_in_apic,
            Required('phys_dom'): self.check_phys_dom_in_apic,
            Optional('description'): str,
            Required('tenant'): self.check_tenant_in_apic,
            Required('app_profile'): str,
            Required('vrf'): str,
            Required('subnets'): self.check_subnet_def_in_apic,
            Optional('l3-out'): list,
            Required('mode'): In(frozenset(["trunk", "access"]),
                                 msg='only trunk or access allowed as values'),
            Optional('config_type'): In(frozenset(["automated"])),
            Required('l2_unknown_unicast'): In(frozenset(["flood", "proxy"]), \
                msg='only trunk or access allowed as values'),
            Required('limit_ip_learning'): bool,
            Optional('preferred_group_member'):
                In(frozenset(["include", "exclude"]), \
                msg='only include or exclude allowed as values'),
            Required('arp_flood'): bool,
            Required('unicast_routing'): bool,
            Required('nd_policy'): self.check_provider_nd_policy_input,
        })

        apic_l2_prov_schema = Schema({
            Required('vlan_ids'): self.check_prov_vlan_id_syntax,
            Optional('EPG_NAME'): str,
            Optional('BD_NAME'): str,
            Required('vlan_pools'): self.check_vlan_pools_in_apic,
            Required('phys_dom'): self.check_phys_dom_in_apic,
            Optional('description'): str,
            Required('tenant'): self.check_tenant_in_apic,
            Required('app_profile'): str,
            Required('vrf'): str,
            Required('mode'): In(frozenset(["trunk", "access"]),
                                 msg='only trunk or access allowed as values'),
            Optional('config_type'): In(frozenset(["automated"]),
                                        msg='only automated allowed as values'),
            Required('l2_unknown_unicast'): In(frozenset(["flood", "proxy"]), \
                msg='only trunk or access allowed as values'),
            Required('limit_ip_learning'): bool,
            Optional('preferred_group_member'):
                In(frozenset(["include", "exclude"]), \
                msg='only include or exclude allowed as values'),
            Required('arp_flood'): bool,
            Required('unicast_routing'): bool,
            Required('nd_policy'): self.check_provider_nd_policy_input,
        })

        apic_l2_tenant_schema = Schema({
            Required('vlan_ids'): self.check_tenant_vlan_id_syntax,
            Optional('EPG_NAME'): str,
            Optional('BD_NAME'): str,
            Required('vlan_pools'): self.check_vlan_pools_in_apic,
            Required('phys_dom'): self.check_phys_dom_in_apic,
            Optional('description'): str,
            Required('tenant'): self.check_tenant_in_apic,
            Required('app_profile'): str,
            Required('vrf'): str,
            Required('mode'): In(frozenset(["trunk", "access"]),
                                 msg='only trunk or access allowed as values'),
            Optional('config_type'): In(frozenset(["automated"]),
                                        msg='only automated allowed as values'),
            Required('l2_unknown_unicast'): In(frozenset(["flood", "proxy"]), \
                msg='only trunk or access allowed as values'),
            Required('limit_ip_learning'): bool,
            Optional('preferred_group_member'):
                In(frozenset(["include", "exclude"]), \
                msg='only include or exclude allowed as values'),
            Required('arp_flood'): bool,
            Required('unicast_routing'): bool,
            Required('nd_policy'): bool,
        })

        err_str = "Input has to be of the type list, " \
            "please check the documentation for details"
        if not isinstance(input_str, list):
            return err_str

        for item in input_str:
            curr_tenant = item.get('tenant', None)
            curr_app = item.get('app_profile', None)
            curr_vrf = item.get('vrf', None)
            curr_l3out = item.get('l3-out', None)
            curr_cfg_type = item.get('config_type', None)

            if curr_cfg_type is not None and curr_cfg_type == 'pre-provisioned':
                try:
                    apic_pre_prov_schema(item)

                    if vlan_type == 'TENANT':
                        self.apic_tenant_vlan_list.append(item.get('vlan_ids'))
                    else:
                        self.apic_provider_vlan_list.append(item.get('vlan_ids'))

                except MultipleInvalid as e:
                    raise Invalid(' '.join(str(x) for x in e.errors))

            elif item.get('subnets') is None:
                if vlan_type == 'TENANT':
                    try:
                        apic_l2_tenant_schema(item)
                        self.apic_tenant_vlan_list.append(item.get('vlan_ids'))
                    except MultipleInvalid as e:
                        raise Invalid(' '.join(str(x) for x in e.errors))
                else:
                    try:
                        apic_l2_prov_schema(item)
                        self.apic_provider_vlan_list.append(item.get('vlan_ids'))
                    except MultipleInvalid as e:
                        raise Invalid(' '.join(str(x) for x in e.errors))
            else:
                try:
                    apic_l3_schema(item)
                    if vlan_type == 'TENANT':
                        self.apic_tenant_vlan_list.append(item.get('vlan_ids'))
                    else:
                        self.apic_provider_vlan_list.append(item.get('vlan_ids'))

                except MultipleInvalid as e:
                    raise Invalid(' '.join(str(x) for x in e.errors))

            try:
                if curr_app is not None:
                    self.check_app_profile_in_apic(curr_tenant,
                                                   item.get('app_profile'))

                if curr_vrf is not None:
                    self.check_vrf_in_apic(curr_tenant, item.get('vrf'))

                if curr_l3out is not None:
                    self.check_l3out_in_apic(curr_tenant, item.get('l3-out'))

            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_argus_servers(self, input_str):
        """heck argus server name, cimc, management, ips, api ips"""
        if input_str is None:
            raise Invalid("Missing Entry")

        master_servers = [server for server in input_str \
            if server.get('role') is None or server.get('role') == 'master']
        if len(master_servers) < 3:
            err_msg = "Argus cluster must have 3 master servers. " +\
                "Only %s masters defined in setupdata " % (str(len(master_servers)))
            raise Invalid(err_msg)
        elif len(master_servers) > 3:
            err_msg = "Argus cluster must have only 3 master servers. " +\
                "Define the other servers as worker nodes"
            raise Invalid(err_msg)

        argus_server_schema = Schema({
            Required('name'): self.check_argus_server_names,
            Required('oob_ip'): self.check_input_as_ipv4v6,
            Optional('oob_username'): All(str, Length(min=1)),
            Optional('oob_password'): self.check_password_syntax,
            Optional('password_hash'): self.check_password_hash_pat,
            Optional('role'): self.check_cvim_role,
            Required('ip_address'): self.check_argus_ips,
        }, extra=False)

        for server in input_str:
            try:
                argus_server_schema(server)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_vim_apic_networks(self, input_str):
        '''Check syntax and symantics of check_vim_apic_networks'''

        err_list = []
        vim_apic_networks_schema = Schema({
            Required('EPG_NAME'): self.check_epg_syntax,
            Required('BD_NAME'): self.check_bd_syntax,
            Required('PROVIDER'): self.check_apic_provider_vlan_details,
            Required('TENANT'): self.check_apic_tenant_vlan_details,
        })

        try:
            vim_apic_networks_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        # CHeck for dups in apic_prov_vlan_list
        apic_prov_vlan_str = ','.join(self.apic_provider_vlan_list)
        apic_prov_vlan_list = common_utils.expand_vlan_range(apic_prov_vlan_str)

        dup_apic_prov_vlan_list = \
            self.check_for_dups_in_list(apic_prov_vlan_list)
        if dup_apic_prov_vlan_list:
            err_str = "Repeating vlan_ids in PROVIDER section of " \
                "vim_apic_networks in setup_data.yaml: %s" \
                % (','.join(dup_apic_prov_vlan_list))
            err_list.append(err_str)

        # Check if Provider VLAN defined is in PROVIDER_VLAN_RANGES
        prov_vlan_info = \
            self.ymlhelper.get_data_from_userinput_file(['PROVIDER_VLAN_RANGES'])
        prov_vlan_list = common_utils.expand_vlan_range(prov_vlan_info)

        apic_prov_vlan_notin_prov_vlan = \
            (set(prov_vlan_list).difference(apic_prov_vlan_list))

        prov_vlan_notin_apic_prov_vlan = \
            (set(apic_prov_vlan_list).difference(prov_vlan_list))

        if bool(apic_prov_vlan_notin_prov_vlan):
            err_str = "PROVIDER_VLAN_RANGES %s is not defiend in " \
                "PROVIDER VLAN ids of vim_apic_networks not " \
                % (apic_prov_vlan_notin_prov_vlan)

            err_list.append(err_str)

        if bool(prov_vlan_notin_apic_prov_vlan):
            err_str = "PROVIDER VLAN ids %s in vim_apic_networks is not " \
                "defined in PROVIDER_VLAN_RANGES" \
                % (prov_vlan_notin_apic_prov_vlan)
            err_list.append(err_str)

        # CHeck for dups in apic_prov_vlan_list
        apic_tenant_vlan_str = ','.join(self.apic_tenant_vlan_list)
        apic_ten_vlan_list = \
            common_utils.expand_vlan_range(apic_tenant_vlan_str)

        dup_apic_tenant_vlan_list = \
            self.check_for_dups_in_list(apic_ten_vlan_list)
        if dup_apic_tenant_vlan_list:
            err_str = "Repeating vlan_ids in TENANT section of " \
                "vim_apic_networks in setup_data.yaml: %s" \
                % (','.join(dup_apic_tenant_vlan_list))
            err_list.append(err_str)

        if dup_apic_prov_vlan_list:
            err_str = "Repeating vlan_ids in PROVIDER section of " \
                "vim_apic_networks in setup_data.yaml: %s" \
                % (','.join(dup_apic_prov_vlan_list))
            err_list.append(err_str)

        # Check if Tenant VLAN defined is in TENANT_VLAN_RANGES
        tenant_vlan_info = \
            self.ymlhelper.get_data_from_userinput_file(['TENANT_VLAN_RANGES'])
        tenant_vlan_list = common_utils.expand_vlan_range(tenant_vlan_info)

        apic_tenant_vlan_notin_tenant_vlan = \
            (set(tenant_vlan_list).difference(apic_ten_vlan_list))

        tenant_vlan_notin_apic_tenant_vlan = \
            (set(apic_ten_vlan_list).difference(tenant_vlan_list))

        if bool(apic_tenant_vlan_notin_tenant_vlan):
            err_str = "TENANT_VLAN_RANGES %s is not defined in " \
                "TENANT VLAN ids of vim_apic_networks not " \
                % (apic_tenant_vlan_notin_tenant_vlan)
            err_list.append(err_str)

        if bool(tenant_vlan_notin_apic_tenant_vlan):
            err_str = "TENANT VLAN ids %s in vim_apic_networks is not " \
                "defined in TENANT_VLAN_RANGES" \
                % (tenant_vlan_notin_apic_tenant_vlan)
            err_list.append(err_str)

        dup_apic_gw_cidr_list = \
            self.check_for_dups_in_list(self.apic_gateway_cidr_list)
        if dup_apic_gw_cidr_list:
            err_str = "Repeating gateway_cidrs in " \
                "vim_apic_networks in setup_data.yaml: %s" \
                % (','.join(dup_apic_gw_cidr_list))
            err_list.append(err_str)

        if err_list:
            err_str = ', '.join(err_list)
            raise Invalid(err_str)

        return

    def validate_timezone(self, input_str):
        """ Validate time zone """
        self.is_input_in_plain_str(input_str)

        if input_str not in pytz.all_timezones:
            raise Invalid("Invalid time zone input")

    def check_argus_ips(self, input_str):
        '''Check if all the ips for argus provided are valid'''
        if input_str is None:
            raise Invalid("Missing Entry")

        argus_common_ip_schema = Schema({
            Required('management_1_v4'): self.validate_external_network_syntax,
            Required('management_1_gateway_v4'): self.is_ip_syntax_valid,
            Required('api_1_v4'): self.validate_external_network_syntax,
            Required('api_1_gateway_v4'): self.is_ip_syntax_valid,
            Optional('api_1_vlan_id'): All(int, Range(min=2, max=4095)),
        }, extra=False)

        argus_ipv6_schema = argus_common_ip_schema.extend({
            Required('management_1_v6'): self.validate_external_v6network_syntax,
            Required('management_1_gateway_v6'): self.is_ipv6_syntax_valid,
            Required('api_1_v6'): self.validate_external_v6network_syntax,
            Required('api_1_gateway_v6'): self.is_ipv6_syntax_valid,
        }, extra=False)

        dhcp_mode = self.ymlhelper.get_argus_ip_install_mode()

        try:
            if dhcp_mode == 'v6':
                argus_ipv6_schema(input_str)
            else:
                argus_common_ip_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_argus_common_info(self, input_str):
        '''Check schema validity of common_info section of argus setupdata'''
        argus_common_schema = Schema({
            Required('oob_username'): All(str, Length(min=1)),
            Required('oob_password'): self.check_password_syntax,
            Required('password_hash'): self.check_password_hash_pat,
        }, extra=False)

        try:
            argus_common_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_intel_rdt_settings(self, input_str):
        '''check the intel_rdt_settings'''

        intel_rdt_schema = Schema({
            Required('ENABLE_CAT'):
                All(Boolean(str), msg="Only Boolean value True/False \
                                  allowed; default is False"),
            Optional('RESERVED_L3_CACHELINES_PER_SOCKET'):
                All(int, Range(min=1, max=32)),
        })

        try:
            intel_rdt_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        if not self.ymlhelper.get_data_from_userinput_file(['NFV_HOSTS']):
            err_info = "INTEL_RDT is enabled, but @ data['NFV_HOSTS'] \
                is missing"
            raise Invalid(err_info)

        enable_cat = ['INTEL_RDT', 'ENABLE_CAT']
        enable_cat_chk = \
            self.ymlhelper.get_deepdata_from_userinput_file(enable_cat)

        l3_cl_per_soc = ['INTEL_RDT', 'RESERVED_L3_CACHELINES_PER_SOCKET']
        l3_cl_per_soc_chk = \
            self.ymlhelper.get_deepdata_from_userinput_file(l3_cl_per_soc)

        if enable_cat_chk is None or \
                (enable_cat_chk is not None and enable_cat_chk is False):

            if l3_cl_per_soc_chk is not None:
                err_info = "RESERVED_L3_CACHELINES_PER_SOCKET is defined, " \
                    "when ENABLE_CAT is False"
                raise Invalid(err_info)

        return

    def cvimmon_ldap_group_mappings(self, input_str):
        ''' Validate CVIMMON Ldap group mappings '''

        ldap_group_mappings = Schema({
            Required('group_dn'): All(str, msg='Missing CVIMMON LDAP group_dn'),
            Required('org_role'): In(frozenset(['Admin', 'Viewer'])),
        })

        if not isinstance(input_str, list):
            err_str = "Entry of type list is allowed"
            raise Invalid(err_str)

        for elem in input_str:
            try:
                ldap_group_mappings(elem)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def cvimmon_ldap_domain_mappings(self, input_str):
        ''' Validate CVIMMON Ldap Servers '''

        attributes_ldap_servers = Schema({
            Optional('email'): All(str),
            Optional('member_of'): All(str),
            Optional('name'): All(str),
            Optional('surname'): All(str),
            Optional('username'): All(str),
        })

        ldap_domain_schema = Schema({
            Required('domain_name'): self.is_input_in_plain_str_ldap,
            Required('attributes'): attributes_ldap_servers,
            Optional('bind_dn'): self.is_input_in_plain_str_ldap,
            Optional('bind_password'): self.is_input_in_plain_str_ldap,
            Required('ldap_uri'): self.check_domain_info,
            Required('search_base_dns'): All(list, Length(min=1)),
            Required('search_filter'): self.is_input_in_plain_str_ldap,
            Optional('group_attribute'): self.is_input_in_plain_str_ldap,
            Optional('group_attribute_is_dn'): bool,
            Optional('use_ssl'): bool,
            Optional('start_tls'): bool,
            Optional('client_cert'): self.is_valid_path,
            Optional('root_ca_cert'):
                All(str, self.is_ca_certificate_file(check_cert_path=True)),
            Optional('client_key'): self.is_valid_path,
            Optional('group_search_filter'): self.is_input_in_plain_str_ldap,
            Optional('group_search_base_dns'): self.is_input_in_plain_str_ldap,
            Optional('group_search_filter_user_attribute'):
                self.is_input_in_plain_str_ldap,
        })

        if not isinstance(input_str, list):
            err_str = "Entry of type list is allowed"
            raise Invalid(err_str)

        if len(input_str) > 1:
            num_enteries = len(input_str)
            err_info = "Currnetly only one set of CVIMMON LDAP domains supported; " \
                "found to be %s" % (num_enteries)
            raise Invalid(err_info)

        for elem in input_str:
            try:
                ldap_domain_schema(elem)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        return

    def check_apic_installer_tenant(self, input_str):
        '''check_apic_installer_tenant'''

        self.is_input_in_plain_str_len32(input_str)
        input_list = input_str.split(' ')
        self.execute_command_in_aci('query_apic_tenant', input_list)
        return

    def check_apic_installer_vrf(self, input_str):
        '''check_apic_installer_vrf'''

        self.is_input_in_plain_str_len32(input_str)
        apic_tenant_info = self.cd_cfgmgr.fetch_apic_installer_tenant_info()
        if not apic_tenant_info:
            err_str = "apic_installer_tenant info not found in APICINFO section"
            raise Invalid(err_str)

        self.check_vrf_in_apic(apic_tenant_info, input_str)
        return

    def check_apic_installer_vlan_pool(self, input_str):
        '''check_apic_installer_vlan_pool'''

        self.is_input_in_plain_str_len32(input_str)
        input_list = input_str.split(' ')
        self.execute_command_in_aci('query_vlan_pool', input_list)
        return

    def check_apic_installer_physdom(self, input_str):
        '''check_apic_installer_physdom'''

        self.is_input_in_plain_str_len32(input_str)
        input_list = input_str.split(' ')
        self.execute_command_in_aci('query_phys_dom', input_list)
        return

    def check_apic_installer_app_profile(self, input_str):
        '''check_apic_installer_app_profile'''

        self.is_input_in_plain_str_len32(input_str)
        apic_tenant_info = self.cd_cfgmgr.fetch_apic_installer_tenant_info()
        if not apic_tenant_info:
            err_str = "apic_installer_tenant info not found in APICINFO section"
            raise Invalid(err_str)
        self.check_app_profile_in_apic(apic_tenant_info, input_str)
        return

    def check_apic_installer_aep(self, input_str):
        '''check_apic_installer_vlan_pool'''

        self.is_input_in_plain_str_len32(input_str)
        input_list = input_str.split(' ')
        self.execute_command_in_aci('query_apic_aep', input_list)
        return

    def check_cisco_vic_support(self, input_str):
        '''Check Cisco VIC support enabled with Intel NIC'''

        if not isinstance(input_str, bool):
            err_str = "Only Boolean value True/False allowed; " \
                "default is False"
            raise Invalid(err_str)

        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])

        if not intel_nic_check:
            err_str = "Option allowed when INTEL_NIC_SUPPORT is enabled"
            raise Invalid(err_str)

    def check_sriov_slot_order(self, input_str):
        """Checks the SRIOV slot order for QCT
        takes only 2 values ascending or descending,
        defaults to descending"""

        non_qct_list = []
        err_msg = "SRIOV slot order applies to Quanta based Pods with SRIOV, " \
            "takes a value of ascending or descending; " \
            "Current value found to be %s" % input_str

        if isinstance(input_str, str) and \
                input_str != 'ascending' and input_str != "descending":
            raise Invalid(err_msg)

        server_list = []

        control_list = self.ymlhelper.get_server_list(role="control")
        if control_list is not None:
            server_list.extend(control_list)

        compute_list = self.ymlhelper.get_server_list(role="compute")
        if compute_list is not None:
            server_list.extend(compute_list)

        bc_list = self.ymlhelper.get_server_list(role="block_storage")
        if bc_list is not None:
            server_list.extend(bc_list)

        server_list_final = list(set(server_list))
        for server in server_list_final:
            server_type = self.ymlhelper.get_platform_vendor(server)
            if server_type != 'QCT':
                tmp = "%s:%s" % (server, server_type)
                non_qct_list.append(tmp)

        if non_qct_list:
            err_str = "%s; Found the following non QCT server %s" \
                % (err_msg, ', '.join(non_qct_list))
            raise Invalid(err_str)

        intel_nic_sriov_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_SRIOV_VFS'])

        if intel_nic_sriov_check is None:
            err_str = "%s; Pod not enabled with SRIOV" % (err_msg)
            raise Invalid(err_str)

        return

    def check_ip_address_syntax(self, input_str):
        """Checks if the input is a list of IPV4 or IPv6 address"""

        err_str = "Input has to be of type list of " \
            "IPv4 and/or IPv6 addresses; Found to be %s" % input_str
        if not isinstance(input_str, list):
            raise Invalid(err_str)

        for item in input_str:
            self.is_ipv4_or_v6_syntax_valid(item)
        return

    def check_hostname_syntax(self, input_str):
        """check the hostname syntax"""

        err_msg = "Hostname with FQDN has to be max of " \
            "64 ASCII chars with no spaces; current " \
            "entry:%s" % input_str
        if not common_utils.is_valid_hostname(input_str):
            raise Invalid(err_msg)
        return

    def check_ipa_server_syntax(self, input_str):
        """Check IPA server syntax"""

        ipa_domain = ['IPA_INFO', 'ipa_domain_name']
        ipa_domain_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(ipa_domain)

        hostname_addr_schema = Schema({
            Required('hostname'): self.check_hostname_syntax,
            Optional('ipaddresses'): self.check_ip_address_syntax,
        })

        err_str = "Input has to be of type list with IPA " \
            "server name and address; Found to be %s" % input_str
        if not isinstance(input_str, list):
            raise Invalid(err_str)

        err_list = []
        for item in input_str:
            try:
                hostname_addr_schema(item)
                if ipa_domain_info is not None:
                    curr_hostname = item.get('hostname')
                    if not curr_hostname.endswith(ipa_domain_info):
                        err_list.append(curr_hostname)
            except MultipleInvalid as e:
                raise Invalid(' '.join(str(x) for x in e.errors))

        if err_list:
            err_str = "ipa_servers:%s doesnt belong in ipa_domain_name:%s" \
                % ((','.join(err_list)), ipa_domain_info)
            raise Invalid(err_str)

        return

    def check_ipa_input(self, input_str):
        """Check IPA validity"""

        ipa_schema = Schema({
            Required('ipa_servers'): self.check_ipa_server_syntax,
            Required('enroller_user'): All(str, Length(min=1)),
            Required('enroller_password'): All(str, Length(min=1)),
            Required('ipa_domain_name'): All(str, Length(min=1)),
        })

        try:
            ipa_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        tty_logging_status = \
            self.ymlhelper.get_data_from_userinput_file(['ENABLE_TTY_LOGGING'])
        if tty_logging_status is not None and tty_logging_status:
            err_msg = "ENABLE_TTY_LOGGING cannot be enabled with IPA"
            raise Invalid(err_msg)

        vim_ldap_admin_status = \
            self.ymlhelper.get_data_from_userinput_file(['vim_ldap_admins'])
        if vim_ldap_admin_status is not None:
            err_msg = "vim_ldap_admins cannot be enabled with IPA"
            raise Invalid(err_msg)

        return

    def check_amp_boot_network_list(self, input_str):
        """Check amp_boot_network info"""

        err_str = "Input has to be of type list with minimum length of 1; " \
            "Found to be %s" % input_str

        if not isinstance(input_str, list):
            raise Invalid(err_str)

        if not input_str:
            raise Invalid(err_str)

        amp_boot_network_schema = Schema({
            Required('dns_server'): self.is_ip_syntax_valid,
            Required('nw_gateway'): self.is_vmtp_v4gw_reachable,
            Required('nw_ip_end'): self.is_ip_syntax_valid,
            Required('nw_ip_start'): self.is_ip_syntax_valid,
            Required('nw_name'): All(str, Length(min=1)),
            Required('segmentation_id'): self.check_segmentation_info,
            Required('subnet_cidr'): self.validate_cidr_syntax,
        })

        amp_boot_v6_network_schema = Schema({
            Required('dns_server'): self.is_ipv6_syntax_valid,
            Required('nw_gateway'): self.is_ipv6_syntax_valid,
            Required('nw_ip_end'): self.is_ipv6_syntax_valid,
            Required('nw_ip_start'): self.is_ipv6_syntax_valid,
            Required('nw_name'): All(str, Length(min=1)),
            Required('segmentation_id'): self.check_segmentation_info,
            Required('subnet_cidr'): self.validate_v6_cidr_syntax,
            Required('ipv6_mode'):
                In(frozenset(["slaac", "dhcpv6-stateless", "dhcpv6-stateful"])),
        })

        vmtp_prov_net_name = "UNKNOWN"
        vmtp_prov_seg_id = 0
        vmtp_prov_gw = "UNKNOWN"
        vmtp_network_type = "UNKNOWN"

        vmtp_info = self.ymlhelper.get_data_from_userinput_file(['VMTP_VALIDATION'])
        if vmtp_info is not None:
            prov_net = ['VMTP_VALIDATION', 'PROV_NET']
            prov_net_info = \
                self.ymlhelper.get_deepdata_from_userinput_file(prov_net)

            if prov_net_info is not None:
                vmtp_prov_net_name = prov_net_info.get('NET_NAME', None)
                vmtp_prov_seg_id = prov_net_info.get('SEGMENTATION_ID', None)
                vmtp_prov_gw = prov_net_info.get('NET_GATEWAY', None)
                vmtp_network_type = prov_net_info.get('IPV6_MODE', None)
                if vmtp_network_type is None:
                    vmtp_network_type = "v4"
                else:
                    vmtp_network_type = "v6"

        err_list = []
        segmentation_id_list = []
        nw_gateway_list = []
        for item in input_str:

            network_type = "v4"
            try:
                if item.get('ipv6_mode', None) is not None:
                    network_type = "v6"
                    amp_boot_v6_network_schema(item)

                    curr_gateway = item.get('nw_gateway', None)
                    if curr_gateway is not None:
                        curr_gw = ipaddr.IPv6Address(curr_gateway).exploded
                        nw_gateway_list.append(curr_gw)

                else:
                    amp_boot_network_schema(item)
                    curr_gw = item.get('nw_gateway', None)
                    if curr_gw is not None:
                        nw_gateway_list.append(curr_gw)

                tmp = item.get('segmentation_id', None)
                if tmp is not None:

                    seg_tmp = "%s-%s" % (network_type, tmp)
                    segmentation_id_list.append(str(seg_tmp))
                    if tmp == vmtp_prov_seg_id and \
                            vmtp_network_type == network_type:
                        curr_nw_name = item.get('nw_name', None)
                        if curr_nw_name != vmtp_prov_net_name:
                            err_str = "Network Name: %s does not match with " \
                                "that defined in VMTP/PROV_NET (%s) for the " \
                                "same segmentation id %s" \
                                % (curr_nw_name, vmtp_prov_net_name,
                                   vmtp_prov_seg_id)
                            err_list.append(err_str)
                        if curr_gw != vmtp_prov_gw:
                            err_str = "Gateway %s does not match with " \
                                "that defined in VMTP/PROV_NET (%s) " \
                                "for the same segmentation id %s" \
                                % (curr_gw, vmtp_prov_gw, vmtp_prov_seg_id)
                            err_list.append(err_str)
                    elif tmp == vmtp_prov_seg_id and \
                            vmtp_network_type != network_type:
                        curr_nw_name = item.get('nw_name', None)
                        if curr_nw_name == vmtp_prov_net_name:
                            err_str = "Network Name: %s cannot not match with " \
                                "that defined in VMTP/PROV_NET (%s) for the " \
                                "same segmentation id %s, due to incompatible " \
                                "network types" \
                                % (curr_nw_name, vmtp_prov_net_name,
                                   vmtp_prov_seg_id)
                            err_list.append(err_str)

            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))

            # if schema is good check details of IP address
            if not err_list:
                nw_name = item['nw_name'].strip()
                curr_gateway = item['nw_gateway'].strip()
                start_ip_address = item['nw_ip_start'].strip()

                end_ip_address = item['nw_ip_end'].strip()
                network_info = item['subnet_cidr'].strip()

                start = ipaddress.ip_address(unicode(start_ip_address))
                end = ipaddress.ip_address(unicode(end_ip_address))
                if start > end:
                    err_msg = "NET_IP_START info for " + str(network_type) + " " \
                        + str(start_ip_address) + \
                        " is greater than NET_IP_END info:" + \
                        str(end_ip_address) + "; "
                    err_list.append(err_msg)

                if network_type == 'v6':
                    if not self.validate_ipv6_for_a_given_network(start_ip_address, \
                                                                  network_info):
                        err_msg = "nw_ip_start %s in %s doesn't " \
                            "belong in %s; " % (start_ip_address, \
                            nw_name, network_info)
                        err_list.append(err_msg)

                    if not self.validate_ipv6_for_a_given_network(end_ip_address,
                                                                  network_info):
                        err_msg = "nw_ip_end %s in %s doesn't " \
                            "belong in %s; " % (end_ip_address, \
                            nw_name, network_info)
                        err_list.append(err_msg)

                    if not self.validate_ipv6_for_a_given_network(curr_gateway, \
                                                                  network_info):
                        err_msg = "nw_gateway %s info for %s doesn't " \
                            "belong in %s; " % (curr_gateway, \
                                                nw_name, \
                                                network_info)
                        err_list.append(err_msg)

                    curr_bcast = self.validate_ipv6_for_a_given_network( \
                        end_ip_address, network_info, get_broadcast=1)

                    if curr_bcast:
                        bcast_ip = ipaddr.IPv6Address(curr_bcast)

                        if end == bcast_ip:
                            err_msg = "nw_ip_end " + str(end_ip_address) + \
                                      " for " + str(nw_name) + \
                                      " is same as its broadcast IP;"
                            err_list.append(err_msg)

                    num_ip = self.ipv6Range(start_ip_address, end_ip_address)
                    total_num_ip = len(num_ip)
                    if total_num_ip < 4:
                        err_msg = "Minimum number of IPv6 need is 4. " + \
                                  "Please adjust the nw_ip_start and " + \
                                  "nw_ip_end info in section " + str(network_type)
                        err_list.append(err_msg)

                else:
                    if not self.validate_ip_for_a_given_network(start_ip_address,
                                                                network_info):
                        err_msg = "nw_ip_start %s in %s doesn't " \
                            "belong in %s; " % (start_ip_address, \
                            nw_name, network_info)
                        err_list.append(err_msg)

                    if not self.validate_ip_for_a_given_network(end_ip_address,
                                                                network_info):
                        err_msg = "nw_ip_end %s in %s doesn't " \
                            "belong in %s; " % (end_ip_address, \
                            nw_name, network_info)
                        err_list.append(err_msg)

                    if not self.validate_ip_for_a_given_network(curr_gateway,
                                                                network_info):
                        err_msg = "nw_gateway %s info for %s doesn't " \
                            "belong in %s; " % (curr_gateway, nw_name, network_info)
                        err_list.append(err_msg)

                    curr_bcast = self.validate_ip_for_a_given_network( \
                        end_ip_address, network_info, get_broadcast=1)

                    if curr_bcast:
                        bcast_ip = ipaddr.IPv4Address(curr_bcast)

                        if end == bcast_ip:
                            err_msg = "nw_ip_end " + str(end_ip_address) + \
                                      " for " + str(nw_name) + \
                                      " is same as its broadcast IP;"
                            err_list.append(err_msg)

                    num_ip = \
                        list(netaddr.iter_iprange(start_ip_address, end_ip_address))
                    total_num_ip = len(num_ip)
                    if total_num_ip < 4:
                        err_msg = "Minimum number of IPv4 need is 4. " + \
                                  "Please adjust the nw_ip_start and " + \
                                  "nw_ip_end info in section " + str(network_type)
                        err_list.append(err_msg)

        dup_segmentation_id_list = \
            self.get_duplicate_entry_in_list(segmentation_id_list)

        dup_nw_gateway_list = \
            self.get_duplicate_entry_in_list(nw_gateway_list)

        if dup_segmentation_id_list:
            err_str = "Duplicate segmentation_id found %s" \
                % (','.join(dup_segmentation_id_list))
            err_list.append(err_str)

        if dup_nw_gateway_list:
            err_str = "Duplicate nw_gateway found %s" \
                % (','.join(dup_nw_gateway_list))
            err_list.append(err_str)

        if err_list:
            err_str = '; '.join(err_list)
            raise Invalid(err_str)

        return

    def check_amp_secgroup_list(self, input_str):
        """Check amp_secgroup_list"""

        err_str = "Input is of type string, which may have multiple , " \
            "separated enteries; Found to be: %s" % input_str

        if not isinstance(input_str, str):
            raise Invalid(err_str)

        input_list = input_str.split(',')
        for item in input_list:
            if not isinstance(item, str):
                err_str = "Input is of type string; Found to be: %s" % item
                raise Invalid(err_str)

    def check_octavia_options(self, input_str):
        """Check if Octavia options are correct"""

        if not self.check_for_optional_enabled('octavia'):
            err_msg = "octavia as OPTIONAL_SERVICE_LIST is needed"
            raise Invalid(err_msg)

        amp_ssh_key_schema = Schema({
            Required('public_key'): self.is_file_exists,
            Required('name'): All(str, Length(min=1)),
        })

        amphora_image_schema = Schema({
            Required('image_path'): self.is_file_exists,
            Required('image_tag'): All(str, Length(min=1)),
        })

        octavia_deployment_schema = Schema({
            Required('amp_boot_network_list'): self.check_amp_boot_network_list,
            Required('amp_flavor'): All(str, Length(min=1)),
            Required('amp_secgroup_list'): self.check_amp_secgroup_list,
            Required('amp_ssh_key'): amp_ssh_key_schema,
            Required('amphora_image'): amphora_image_schema,
            Required('ca_certificate'):
                All(str, self.is_ca_certificate_file(check_cert_path=True)),
            Required('ca_private_key'): self.is_file_exists,
            Required('ca_private_key_passphrase'): All(str, Length(min=1)),
            Required('client_cert'): self.is_file_exists,
        })

        try:
            octavia_deployment_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

    def check_ssh_access_options(self, input_str):
        """check_ssh_access_options"""

        ssh_access_options_schema = Schema({
            Optional('session_idle_timeout'): All(int, Range(min=300, max=3600)),
            Optional('enforce_single_session'): All(Boolean(str)),
            Optional('session_login_attempt'): All(int, Range(min=3, max=6)),
            Optional('session_lockout_duration'):
                All(int, Range(min=300, max=86400)),
            Optional('session_root_lockout_duration'):
                All(int, Range(min=300, max=1800)),
            Optional('lockout_inactive_users'):
                All(int, Range(min=90, max=99999)),
        })

        try:
            ssh_access_options_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))

        err_list = []

        is_vim_ldap_admins_enabled = \
            self.ymlhelper.get_data_from_userinput_file(['vim_ldap_admins'])

        ipa_enabled = \
            self.ymlhelper.get_data_from_userinput_file(['IPA_INFO'])

        if ipa_enabled is not None:
            err_msg = "Feature of IPA and SSH_ACCESS_OPTIONS cannot co-exist"
            raise Invalid(err_msg)

        sess_lockout_duration = ['SSH_ACCESS_OPTIONS', 'session_lockout_duration']
        is_sess_lockout_dur = \
            self.ymlhelper.get_deepdata_from_userinput_file(sess_lockout_duration)

        sess_root_lockout_duration = ['SSH_ACCESS_OPTIONS',
                                      'session_root_lockout_duration']
        is_sess_root_lockout_dur = \
            self.ymlhelper.get_deepdata_from_userinput_file(\
                sess_root_lockout_duration)

        lockout_inactive_users = ['SSH_ACCESS_OPTIONS', 'lockout_inactive_users']
        is_lockout_inactive_users_defined = \
            self.ymlhelper.get_deepdata_from_userinput_file(lockout_inactive_users)

        enforce_single_session = ['SSH_ACCESS_OPTIONS', 'enforce_single_session']
        is_enforce_single_session_defined = \
            self.ymlhelper.get_deepdata_from_userinput_file(enforce_single_session)

        sess_login_attempt = ['SSH_ACCESS_OPTIONS', 'session_login_attempt']
        is_sess_login_defined = \
            self.ymlhelper.get_deepdata_from_userinput_file(sess_login_attempt)

        if is_sess_lockout_dur is not None and is_sess_login_defined is None:
            err_msg = "session_lockout_duration can only exist when " \
                "session_login_attempt is defined"
            err_list.append(err_msg)

        if is_sess_root_lockout_dur is not None and is_sess_login_defined is None:
            err_msg = "session_root_lockout_duration can only exist when " \
                "session_login_attempt is defined"
            err_list.append(err_msg)

        if is_sess_lockout_dur is None and is_sess_root_lockout_dur is None:
            if is_sess_login_defined is not None:
                err_msg = "session_login_attempt can only exist when " \
                    "session_lockout_duration or session_root_lockout_duration" \
                    " is defined"
                err_list.append(err_msg)

        if is_vim_ldap_admins_enabled is not None:
            if is_sess_lockout_dur is not None:
                sess_lockout_duration_str = '/'.join(sess_lockout_duration)
                err_msg = "Option of %s cannot co-exist with " \
                    "vim_ldap_admins" % sess_lockout_duration_str
                err_list.append(err_msg)

            if is_sess_root_lockout_dur is not None:
                sess_root_lockout_duration_str = '/'.join(sess_root_lockout_duration)
                err_msg = "Option of %s cannot co-exist with " \
                    "vim_ldap_admins" % sess_root_lockout_duration_str
                err_list.append(err_msg)

            if is_lockout_inactive_users_defined is not None:
                lockout_inactive_users_str = '/'.join(lockout_inactive_users)
                err_msg = "Option of %s cannot co-exist " \
                    "with vim_ldap_admins" % (lockout_inactive_users_str)
                err_list.append(err_msg)

            if is_enforce_single_session_defined is not None:
                enforce_single_session_str = '/'.join(enforce_single_session)
                err_msg = "Option of %s cannot co-exist " \
                    "with vim_ldap_admins" % (enforce_single_session_str)
                err_list.append(err_msg)

        if err_list:
            err_str = ', '.join(err_list)
            raise Invalid(err_str)

    def check_password_mgmt_input(self, input_str):
        """Check Password Mgmt Input"""

        password_mgmt_schema = Schema({
            Optional('strength_check'): All(Boolean(str)),
            Optional('maximum_days'): All(int, Range(min=90, max=99999)),
            Optional('warning_age'): All(int, Range(min=1, max=99998)),
            Optional('history_check'): All(int, Range(min=2, max=12)),
        })

        try:
            password_mgmt_schema(input_str)
        except MultipleInvalid as e:
            raise Invalid(' '.join(str(x) for x in e.errors))
        ipa_enabled = \
            self.ymlhelper.get_data_from_userinput_file(['IPA_INFO'])

        if ipa_enabled is not None:
            err_msg = "Feature of IPA and PASSWORD MANAGEMENT cannot co-exist"
            raise Invalid(err_msg)

        max_days_chk = ['PASSWORD_MANAGEMENT', 'maximum_days']
        is_max_days_defined = \
            self.ymlhelper.get_deepdata_from_userinput_file(max_days_chk)

        warn_age_chk = ['PASSWORD_MANAGEMENT', 'warning_age']
        is_warn_age_defined = \
            self.ymlhelper.get_deepdata_from_userinput_file(warn_age_chk)

        if is_max_days_defined is None and is_warn_age_defined is None:
            pass
        elif is_warn_age_defined is None and is_max_days_defined is not None:

            err_max_days = "Entry for warning_age is not defined " \
                "when maximum_days:%s is defined; Input of maximum_days " \
                "has to be of type int, with a value greater than that " \
                "of warning_age" % is_max_days_defined
            raise Invalid(err_max_days)

        elif is_warn_age_defined is not None and is_max_days_defined is None:

            err_warn_age = "Entry for maximum_days is not defined " \
                "when warning_age:%s is defined; Input of warning_age " \
                "has to be of type int, with a value less than that " \
                "of maximum_days" % is_warn_age_defined
            raise Invalid(err_warn_age)

        elif is_warn_age_defined is not None and is_max_days_defined is not None:

            err_str = "Entry of maximum_days:%s has to be greater than that of " \
                      "warning_age:%s" % (is_max_days_defined, is_warn_age_defined)
            if int(is_max_days_defined) <= int(is_warn_age_defined):
                raise Invalid(err_str)

    def check_cloud_settings(self, input_str):
        '''Check schema validity of cloud_settings section of setupdata'''
        cloud_settings_schema = Schema({
            Optional('keystone_lockout_failure_attempts'):
                All(int, Range(min=0, max=10)),
            Optional('keystone_lockout_duration'):
                All(int, Range(min=300, max=86400)),
            Optional('keystone_unique_last_password_count'):
                All(int, Range(min=0, max=10)),
            Optional('keystone_minimum_password_age'): All(int, Range(min=0, max=2)),
            Optional('horizon_session_timeout'): All(int, Range(min=300, max=86400)),
        }, extra=False)

        error_string = ''
        try:
            cloud_settings_schema(input_str)
        except MultipleInvalid as e:
            error_string = ' '.join(str(x) for x in e.errors)

        minimum_password_age = \
            self.ymlhelper.get_deepdata_from_userinput_file(
                ['cloud_settings', 'keystone_minimum_password_age'])
        password_expires_days = \
            self.ymlhelper.get_deepdata_from_userinput_file(
                ['cloud_settings', 'keystone_password_expires_days'])

        if minimum_password_age is not None and password_expires_days is not None\
                and minimum_password_age != 0 and password_expires_days != 0:
            if minimum_password_age >= password_expires_days:
                error_string += "ERROR: keystone_password_expires_days must be \
                                 greater than keystone_minimum_password_age"

        if error_string:
            raise(Invalid(error_string))

        return

    def external_servers_monitored_schema(self, input_str):
        """Check the schema of external servers monitored by CVIM MON"""

        err_str = "Input has to be of type list with External " \
            "servers that are monitored by CVIM MON; Found to be %s" % input_str
        if not isinstance(input_str, list):
            raise Invalid(err_str)

        if not input_str:
            raise Invalid(err_str)

        for item in input_str:
            self.is_ipv4_or_v6_syntax_valid(item)

        return

    def validate_v6_networking_entry(self, input_str):
        """Check the entry is v6 or FQDN"""

        self.validate_networking_entry(input_str)

        err_list = []
        for item in input_str:
            if common_utils.is_valid_hostname(item):
                continue
            elif not self.is_ipv6_syntax_valid(item):
                err_list.append(item)

        if err_list:
            err_str = "Expecting v6 dns info; found to be %s" ','.join(err_list)
            raise Invalid(err_str)
        return

    def validate_v4_networking_entry(self, input_str):
        """Check the entry is v4 or FQDN"""

        self.validate_networking_entry(input_str)

        err_list = []
        for item in input_str:
            if common_utils.is_valid_hostname(item):
                continue
            elif not self.is_ip_syntax_valid(item):
                err_list.append(item)

        if err_list:
            err_str = "Expecting v4/FQDN dns info; found to be %s" ','.join(err_list)
            raise Invalid(err_str)
        return

    def check_central_range_validity(\
            self, name, range_info, network_type, nw_cidr, gateway):
        """Cheeck that the range is not overlapping and in the cidr"""

        dup_range_list = \
            self.get_duplicate_entry_in_list(range_info)

        if dup_range_list:
            err_str = "Duplicate range found: %s" % (','.join(dup_range_list))
            raise Invalid(err_str)

        for item in range_info:
            if network_type == 4:
                if not self.validate_ip_for_a_given_network(item, nw_cidr):
                    err_str = "V4 Range Entry %s in %s doesn't belong in %s" \
                              % (item, name, nw_cidr)
                    raise Invalid(err_str)

                if item == gateway:
                    err_str = "v4 Range Entry %s in %s is the same as its gateway" \
                              % (item, name)
                    raise Invalid(err_str)

            if network_type == 6:
                if not self.validate_ipv6_for_a_given_network(item, nw_cidr):
                    err_str = "V6 Range Entry %s in %s doesn't belong in %s" \
                              % (item, name, nw_cidr)
                    raise Invalid(err_str)

                if ipaddr.IPv6Address(item).exploded == \
                        ipaddr.IPv6Address(gateway).exploded:
                    err_str = "V6 Range Entry %s in %s is the same as its gateway" \
                              % (item, name)
                    raise Invalid(err_str)

        return

    def check_central_mgmt_subnet_validity(self, input_str):
        """ Check central_mgmt_subnet validity"""

        err_str = "Input has to be of type list with minimum of v4 subnet " \
            "in Central Management Node Networks section; Found to be %s" % input_str
        if not isinstance(input_str, list):
            raise Invalid(err_str)

        if not input_str:
            raise Invalid(err_str)

        central_v4_subnet_schema = Schema({
            Required('name'): self.is_input_in_plain_str,
            Required('network_cidr'): self.validate_cidr_syntax,
            Required('gateway'): self.is_ip_syntax_valid,
            Required('range'): All(list, Length(2)),
            Required('ip_version'): In(frozenset([4])),
            Required('dns_nameservers'): self.validate_networking_entry,
        })

        central_v6_subnet_schema = Schema({
            Required('name'): self.is_input_in_plain_str,
            Required('network_cidr'): self.validate_v6_cidr_syntax,
            Required('gateway'): self.is_ipv6_syntax_valid,
            Required('range'): All(list, Length(2)),
            Required('ip_version'): In(frozenset([6])),
            Required('dns_nameservers'): self.validate_networking_entry,
        })

        found_v4 = 0
        error_string = ''
        for item in input_str:
            network_type = item.get('ip_version', None)
            if network_type is None:
                err_str_ip = "ip_version not defined for %s" % input_str
                raise Invalid(err_str_ip)

            try:
                if network_type == 4:
                    found_v4 = 1
                    central_v4_subnet_schema(item)

                elif network_type == 6:
                    central_v6_subnet_schema(item)

                curr_gateway = item.get('gateway')
                curr_nw_cidr = item.get('network_cidr')
                curr_name = item.get('name')
                curr_range = item.get('range')
                curr_dns = item.get('dns_nameservers')

                self.check_central_range_validity(\
                    curr_name, curr_range, network_type, curr_nw_cidr, curr_gateway)

                if network_type == 6:
                    v6_gw = ipaddr.IPv6Address(curr_gateway).exploded
                    curr_gateway = v6_gw

                tmp = "%s:%s" % (self.curr_network_name, curr_name)
                self.central_network_subnet_combo_list.append(tmp)
                self.central_network_subnet_name_list.append(curr_name)
                self.central_network_subnet_cidr_list.append(curr_nw_cidr)

                self.central_network_subnet_cidr[curr_name] = curr_nw_cidr
                self.central_network_subnet_ip_version[curr_name] = network_type

                if network_type == 4:

                    self.central_network_subnet_gw_list.append(curr_gateway)
                    self.central_network_subnet_gw[curr_name] = curr_gateway

                    for each_item in curr_range:
                        self.central_network_subnet_range_list.append(each_item)

                    if not self.validate_ip_for_a_given_network(\
                            curr_gateway, curr_nw_cidr):
                        err_str = "v4 Gateway Entry %s in %s doesn't belong in %s" \
                            % (curr_gateway, curr_name, curr_nw_cidr)
                        raise Invalid(err_str)

                if network_type == 6:
                    curr_v6_gw = ipaddr.IPv6Address(curr_gateway).exploded
                    self.central_network_subnet_gw_list.append(curr_v6_gw)
                    self.central_network_subnet_gw[curr_name] = curr_v6_gw

                    for each_item in curr_range:
                        v6_exp_range = ipaddr.IPv6Address(each_item).exploded
                        self.central_network_subnet_range_list.append(v6_exp_range)

                    if not self.validate_ipv6_for_a_given_network(\
                            curr_gateway, curr_nw_cidr):
                        err_str = "v6 Gateway Entry %s in %s doesn't belong in %s" \
                            % (curr_gateway, curr_name, curr_nw_cidr)
                        raise Invalid(err_str)

                if len(curr_dns) > 3:
                    err_str = "Max of 3 dns servers allowed; found to be %s " \
                        "for entry %s" % (len(curr_dns), ','.join(curr_dns))
                    raise Invalid(err_str)

            except MultipleInvalid as e:
                error_string = ' '.join(str(x) for x in e.errors)

        if not found_v4:
            raise Invalid(err_str)

        if error_string:
            raise(Invalid(error_string))

        return

    def check_central_mgmt_vlan_id_validity(self, input_str):
        """ Check central_mgmt_vlan_id validity"""

        err_str = "Input has to be of type int for Central Management " \
            "Node vlan in the range of 2 to 4094, and must exist " \
            "in the PROVIDER_VLAN_RANGES of the pod; " \
            "Found to be %s" % input_str

        if not isinstance(input_str, int):
            raise Invalid(err_str)
        elif not self.is_input_range_valid(int(input_str), 2, 4094):
            raise Invalid(err_str)

        setup_yaml_path = common_utils.get_setup_data_file_path()

        if setup_yaml_path is None:
            msg = "ERROR: Cannot get the setup_data at " \
                "/root/openstack-configs/setup_data.yaml to find the " \
                "PROVIDER_VLAN_RANGES info"
            raise Invalid(msg)
        elif os.path.getsize(setup_yaml_path) == 0:
            msg = "ERROR: setup_data is of 0 size openstack-configs dir, " \
                "cannot fetch the PROVIDER_VLAN_RANGES info"
            raise Invalid(msg)

        setup_yaml = common_utils.get_contents_of_file(setup_yaml_path)
        if not setup_yaml:
            msg = "ERROR: setup_data has no content in " \
                "openstack-configs dir, cannot proceed"
            raise Invalid(msg)

        prov_vlan_range = setup_yaml.get('PROVIDER_VLAN_RANGES', None)
        if prov_vlan_range is None:
            msg = "ERROR: PROVIDER_VLAN_RANGES not defined in %s, " \
                "cannot proceed" % setup_yaml_path
            raise Invalid(msg)

        prov_vlan_list = common_utils.expand_vlan_range(prov_vlan_range)
        if input_str not in prov_vlan_list:
            err_str2 = "%s; Defined PROVIDER_VLAN_RANGES:%s" \
                % (err_str, prov_vlan_range)
            raise Invalid(err_str2)

        return

    def check_mn_central_networks(self, input_str):
        """Check Networks input"""

        err_str = "Input has to be of type list with minimum of 2 enteries " \
            "for Central Management Node Networks; Found to be %s" % input_str
        if not isinstance(input_str, list):
            raise Invalid(err_str)

        if not input_str or len(input_str) < 2:
            raise Invalid(err_str)

        central_network_schema = Schema({
            Required('segment'): In(frozenset(["management", "api"])),
            Required('vlan_id'): self.check_central_mgmt_vlan_id_validity,
            Required('name'): self.is_input_in_plain_str,
            Required('subnets'): self.check_central_mgmt_subnet_validity,
        })

        error_string = ''
        for item in input_str:

            curr_vlan_id = item.get('vlan_id', None)
            self.curr_network_name = item.get('name', None)

            if self.curr_network_name is None:
                err_str = "name info missing in NETWORKS section"
                raise Invalid(err_str)
            else:
                self.central_network_name_list.append(item.get('name'))

            if curr_vlan_id is None:
                err_str = "vlan_id missing in NETWORKS section for %s" \
                    % self.curr_network_name
                raise Invalid(err_str)
            else:
                self.central_network_vlanid_list.append(item.get('vlan_id'))

            try:
                central_network_schema(item)

            except MultipleInvalid as e:
                error_string = ' '.join(str(x) for x in e.errors)

        if error_string:
            raise(Invalid(error_string))

        err_list = []
        dup_central_network_subnet_name_list = \
            self.check_for_dups_in_list(self.central_network_subnet_name_list)
        if dup_central_network_subnet_name_list:
            err_str = "Repeating NETWORKS:subnets name for %s" \
                % (','.join(dup_central_network_subnet_name_list))
            err_list.append(err_str)

        dup_central_network_subnet_gw_list = \
            self.check_for_dups_in_list(self.central_network_subnet_gw_list)
        if dup_central_network_subnet_gw_list:
            err_str = "Repeating NETWORKS:subnets gateway for %s" \
                % (','.join(dup_central_network_subnet_gw_list))
            err_list.append(err_str)

        dup_central_network_subnet_cidr_list = \
            self.check_for_dups_in_list(self.central_network_subnet_cidr_list)
        if dup_central_network_subnet_cidr_list:
            err_str = "Repeating NETWORKS:subnets cidr for %s" \
                % (','.join(dup_central_network_subnet_cidr_list))
            err_list.append(err_str)

        dup_central_network_subnet_range_list = \
            self.check_for_dups_in_list(self.central_network_subnet_range_list)
        if dup_central_network_subnet_range_list:
            err_str = "Repeating NETWORKS:subnets range for %s" \
                % (','.join(dup_central_network_subnet_range_list))
            err_list.append(err_str)

        if err_list:
            err_str = ','.join(err_list)
            raise Invalid(err_str)

        return

    def check_mn_central_images(self, input_str):
        """Check Images Input"""

        err_str = "Input has to be of type list for Central Management " \
            "Node Images; Found to be %s" % input_str
        if not isinstance(input_str, list):
            raise Invalid(err_str)

        if not input_str:
            raise Invalid(err_str)

        central_keypair_schema = Schema({
            Required('name'): self.is_input_in_plain_str,
            Required('file_location'): self.check_file_presence,
        })

        error_string = ''
        for item in input_str:
            try:
                central_keypair_schema(item)
                self.central_image_name_list.append(item.get('name'))
            except MultipleInvalid as e:
                error_string = ' '.join(str(x) for x in e.errors)

        if error_string:
            raise(Invalid(error_string))

        err_list = []
        dup_central_image_name_list = \
            self.check_for_dups_in_list(self.central_image_name_list)
        if dup_central_image_name_list:
            err_str = "Repeating Image Names for %s" \
                % (','.join(dup_central_image_name_list))
            err_list.append(err_str)

        if err_list:
            err_str = ','.join(err_list)
            raise Invalid(err_str)

        return

    def check_mn_central_flavors(self, input_str):
        """Check Flavor Input"""

        err_str = "Input has to be of type list for Central Management " \
            "Node Flavors; Found to be %s" % input_str
        if not isinstance(input_str, list):
            raise Invalid(err_str)

        if not input_str:
            raise Invalid(err_str)

        central_flavor_schema = Schema({
            Required('name'): self.is_input_in_plain_str,
            Required('ram'): All(int, Range(24000, 200000)),
            Required('vcpus'): All(int, Range(4, 20)),
            Optional('disk'): All(int, Range(512, 4096)),
        })

        error_string = ''
        for item in input_str:
            try:
                central_flavor_schema(item)
                self.central_flavor_name_list.append(item.get('name'))
            except MultipleInvalid as e:
                error_string = ' '.join(str(x) for x in e.errors)

        if error_string:
            raise(Invalid(error_string))

        err_list = []
        dup_central_flavor_name_list = \
            self.check_for_dups_in_list(self.central_flavor_name_list)
        if dup_central_flavor_name_list:
            err_str = "Repeating Flavor Names for %s" \
                % (','.join(dup_central_flavor_name_list))
            err_list.append(err_str)

        if err_list:
            err_str = ','.join(err_list)
            raise Invalid(err_str)

        return

    def check_mn_central_keypairs(self, input_str):
        """Check keypair syntax"""

        err_str = "Input has to be of type list for Central Management " \
            "Node Keypairs; Found to be %s" % input_str
        if not isinstance(input_str, list):
            raise Invalid(err_str)

        if not input_str:
            raise Invalid(err_str)

        central_keypair_schema = Schema({
            Required('name'): self.is_input_in_plain_str,
            Required('public_key_file'): self.check_file_presence,
        })

        error_string = ''
        for item in input_str:
            try:
                central_keypair_schema(item)
                self.central_keypair_name_list.append(item.get('name'))
            except MultipleInvalid as e:
                error_string = ' '.join(str(x) for x in e.errors)

        if error_string:
            raise(Invalid(error_string))

        err_list = []
        dup_central_keypair_name_list = \
            self.check_for_dups_in_list(self.central_keypair_name_list)
        if dup_central_keypair_name_list:
            err_str = "Repeating Keypairs Names for %s" \
                % (','.join(dup_central_keypair_name_list))
            err_list.append(err_str)

        if err_list:
            err_str = ','.join(err_list)
            raise Invalid(err_str)

        return

    def check_keypair_presence(self, input_str):
        """Check KeyPair Info in server"""

        self.is_input_in_plain_str(input_str)
        if input_str not in self.central_keypair_name_list:
            err_str = "%s for target VM %s not defined in %s" \
                % (input_str, self.curr_server_name,
                   ','.join(self.central_keypair_name_list))
            raise Invalid(err_str)
        return

    def check_flavor_presence(self, input_str):
        """Check Flavor Info in server"""

        self.is_input_in_plain_str(input_str)
        if input_str not in self.central_flavor_name_list:
            err_str = "%s for target VM %s not defined in %s" \
                % (input_str, self.curr_server_name,
                   ','.join(self.central_flavor_name_list))
            raise Invalid(err_str)
        return

    def check_image_presence(self, input_str):
        """Check Image Info in server"""

        self.is_input_in_plain_str(input_str)
        if input_str not in self.central_image_name_list:
            err_str = "%s for target VM %s not defined in %s" \
                % (input_str, self.curr_server_name,
                   ','.join(self.central_image_name_list))
            raise Invalid(err_str)
        return

    def check_network_presence(self, input_str):
        """Check if network name is present in Central NETWORKS section"""

        self.is_input_in_plain_str(input_str)
        if input_str not in self.central_network_name_list:
            err_str = "%s for target VM %s not defined in %s" \
                % (input_str, self.curr_server_name,
                   ','.join(self.central_network_name_list))
            raise Invalid(err_str)
        return

    def check_ipaddress_validity(self, ipaddress, subnet_name,
                                 curr_server_nic_name, ip_version):
        """Check if ip address belongs in the subnet defined"""

        exp_ip_version = \
            self.central_network_subnet_ip_version.get(subnet_name, None)
        curr_subnet_cidr = self.central_network_subnet_cidr.get(subnet_name, None)
        curr_subnet_gw = self.central_network_subnet_gw.get(subnet_name, None)
        err_list = []

        if ip_version != exp_ip_version:
            err_str = "IP version of %s in %s found to be %s; expected:%s " \
                % (subnet_name, curr_server_nic_name, ip_version, exp_ip_version)
            err_list.append(err_str)

        if ip_version == 4 and \
                not self.validate_ip_for_a_given_network(\
                    ipaddress, curr_subnet_cidr):
            err_str = "Entry %s in %s doesn't belong to %s" \
                % (ipaddress, subnet_name, curr_subnet_cidr)
            err_list.append(err_str)

        elif ip_version == 6 and \
                not self.validate_ipv6_for_a_given_network(\
                    ipaddress, curr_subnet_cidr):
            err_str = "Entry %s in %s doesn't belong to %s" \
                % (ipaddress, subnet_name, curr_subnet_cidr)
            err_list.append(err_str)

        if ip_version == 4 and ipaddress == curr_subnet_gw:
            err_str = "v4 address: %s of %s in %s the same as its gateway" \
                % (ipaddress, subnet_name, curr_server_nic_name)
            err_list.append(err_str)

        elif ip_version == 6 and \
                ipaddr.IPv6Address(ipaddress).exploded == curr_subnet_gw:
            err_str = "v6 address: %s of %s in %s the same as its gateway" \
                % (ipaddress, subnet_name, curr_server_nic_name)
            err_list.append(err_str)

        if err_list:
            err_str1 = "ERROR: %s" % (','.join(err_list))
            raise Invalid(err_str1)

        return

    def check_fixed_ip_info(self, input_str):
        """Check the fixed IP schema on a per SERVER basis"""

        err_str = "Input has to be of type list for fixed_ip info in " \
            "Central Node VM %s of type %s; Found to be %s"\
            % (self.curr_server_name, self.curr_node_type, input_str)

        if not isinstance(input_str, list):
            raise Invalid(err_str)

        server_nic_fixed_ip_schema = Schema({
            Required('subnet'): self.is_input_in_plain_str,
            Required('ipaddress'): self.is_ipv4_or_v6_syntax_valid,
        })

        err_list = []
        error_string = ''
        num_v4_address_found = 0
        local_ip_list = []
        local_subnet_list = []

        for item in input_str:
            try:
                server_nic_fixed_ip_schema(item)
                curr_subnet = item.get('subnet', None)
                curr_ip_address = item.get('ipaddress', None)
                local_ip_list.append(curr_ip_address)
                local_subnet_list.append(curr_subnet)

                # Fetch the current network/subnet Name
                curr_subnet_network_name = \
                    "%s:%s" % (self.curr_nic_network_name, curr_subnet)

                # Check if the current network/subnet Name is in the global list
                if curr_subnet_network_name not in \
                        self.central_network_subnet_combo_list:
                    err_str = "network/subnet info %s missing in %s" \
                        % (curr_subnet_network_name,
                           self.central_network_subnet_combo_list)
                    err_list.append(err_str)

                if curr_subnet not in self.central_network_subnet_name_list:
                    err_str = "subnet %s under %s missing from %s" \
                        % (curr_subnet, self.curr_server_nic_name,
                           self.central_network_subnet_name_list)
                    err_list.append(err_str)
                else:

                    if self.is_ip_valid(curr_ip_address):
                        num_v4_address_found += 1
                        ip_version = 4
                        self.central_server_nic_ip_addr_list.append(curr_ip_address)
                        self.check_ipaddress_validity(\
                            curr_ip_address, curr_subnet, \
                            self.curr_server_nic_name, ip_version)

                    else:
                        ip_version = 6
                        self.central_server_nic_ip_addr_list.append(curr_ip_address)
                        self.check_ipaddress_validity(\
                            curr_ip_address, curr_subnet, \
                            self.curr_server_nic_name, ip_version)

            except MultipleInvalid as e:
                error_string = ' '.join(str(x) for x in e.errors)

        if error_string:
            raise(Invalid(error_string))

        if num_v4_address_found > 1:
            err_str = "Both IP enteries %s are of type v4, need to have one " \
                "of them as v6" % (','.join(local_ip_list))
            err_list.append(err_str)

        dup_local_subnet_list = \
            self.check_for_dups_in_list(local_subnet_list)
        if dup_local_subnet_list:
            err_str = "Repeating subnet %s for %s" \
                % (','.join(dup_local_subnet_list), self.curr_server_nic_name)
            err_list.append(err_str)

        if err_list:
            err_str1 = "ERROR: %s" % (','.join(err_list))
            raise Invalid(err_str1)

        return

    def check_nic_presence(self, input_str):
        """Check nic Info in server"""

        err_str = "Input has to be of type list for nic info with length " \
            "of 2 in Central Node VMS: %s of type %s; Found to be %s" \
            % (self.curr_server_name, self.curr_node_type, input_str)
        expected_num_input = 2

        if self.curr_node_type == 'um':
            err_str = "Input has to be of type list for nic info with length " \
                "of 1 in Central Node VMS: %s of type %s; Found to be %s" \
                % (self.curr_server_name, self.curr_node_type, input_str)
            expected_num_input = 1

        if not isinstance(input_str, list):
            raise Invalid(err_str)

        if len(input_str) != expected_num_input:
            raise Invalid(err_str)

        server_nic_schema = Schema({
            Required('name'): self.is_input_in_plain_str,
            Required('network_name'): self.check_network_presence,
            Required('fixed_ips'): self.check_fixed_ip_info,
        })

        nic_name_list = []
        nic_network_name_list = []

        error_string = ''
        for item in input_str:
            curr_nic_name = item.get('name', None)
            if curr_nic_name is None:
                err_str = "Entry of name not defined in %s:nics section, " \
                          "cannot proceed" % self.curr_server_name
                raise Invalid(err_str)
            else:
                nic_name_list.append(item.get('name'))
                self.central_nic_name_list.append(item.get('name'))

            tmp = self.curr_server_name + ":nics:" + curr_nic_name
            self.curr_server_nic_name = tmp

            self.curr_nic_network_name = item.get('network_name', None)

            if self.curr_nic_network_name is None:
                if self.curr_nic_network_name is None:
                    err_str = "Entry of network_name not defined in " \
                        "%s:nics section, cannot proceed" % self.curr_server_name
                    raise Invalid(err_str)
            else:
                nic_network_name_list.append(self.curr_nic_network_name)

            try:
                server_nic_schema(item)
            except MultipleInvalid as e:
                error_string = ' '.join(str(x) for x in e.errors)

        if error_string:
            raise(Invalid(error_string))

        err_list = []
        dup_nic_network_name_list = \
            self.check_for_dups_in_list(nic_network_name_list)
        if dup_nic_network_name_list:
            err_str = "Repeating nics:network_name %s for %s" \
                % (','.join(dup_nic_network_name_list), self.curr_server_name)
            err_list.append(err_str)

        dup_nic_name_list = \
            self.check_for_dups_in_list(nic_name_list)
        if dup_nic_network_name_list:
            err_str = "Repeating nics:name %s for %s" \
                % (','.join(dup_nic_name_list), self.curr_server_name)
            err_list.append(err_str)

        dup_central_server_nic_ip_addr_list = \
            self.check_for_dups_in_list(
                self.central_server_nic_ip_addr_list, input_type="ip")
        if dup_central_server_nic_ip_addr_list:
            err_str = "Repeating nics:fixed_ips %s across SERVERS_IN_VMS" \
                % (','.join(dup_central_server_nic_ip_addr_list))
            err_list.append(err_str)

        if err_list:
            err_str = "ERROR: %s" % (','.join(err_list))
            raise Invalid(err_str)

        return

    def check_mn_central_servers_syntax(self, input_str):
        """Check Server syntax"""

        err_str = "Input has to be of type list for Central Management " \
            "Node VMS; Found to be %s" % input_str
        if not isinstance(input_str, list):
            raise Invalid(err_str)

        if not input_str:
            raise Invalid(err_str)
        return

    def get_disk_info_in_flavor(self, flavor_name):
        """Get the disk info for a given flavor"""

        flavor_list = \
            self.ymlhelper.get_data_from_userinput_file(["FLAVORS"])

        for item in flavor_list:
            if flavor_name == item.get('name'):
                if item.get('disk', None) is None:
                    return None
                return item.get('disk')

    def check_mn_central_servers(self, input_str):
        """Check Server syntax"""

        central_server_schema = Schema({
            Required('name'): self.is_input_in_plain_str,
            Required('keypair'): self.check_keypair_presence,
            Required('image'): self.check_image_presence,
            Required('flavor'): self.check_flavor_presence,
            Required('nics'): self.check_nic_presence,
            Required('node_type'): In(frozenset(["management", "sds", "um"]),
                                      msg='only sds or um allowed'),
            Optional('disk_vol_size'): All(int, Range(min=512, max=4096)),
            Optional('domain_name'): self.is_input_in_plain_str,
            Optional('timezone'): self.check_timezone_validity,
            Optional('cvimadmin_password_hash'): self.check_password_hash_pat,
        })

        err_list = []
        err_str = ""

        global_cvimadmin_password_hash = \
            self.ymlhelper.get_data_from_userinput_file(["CVIMADMIN_PASSWORD_HASH"])
        for item in input_str:
            self.curr_server_name = None
            self.curr_node_type = None
            try:
                self.curr_server_name = item.get('name', None)
                if self.curr_server_name is None:
                    err_str = "Entry of name not defined in SERVER_IN_VMS " \
                        "section, cannot proceed"
                    raise Invalid(err_str)

                self.curr_node_type = item.get('node_type', None)
                if self.curr_node_type is None:
                    err_str = "Entry of node_type not defined in " \
                        "SERVERVMS section for %s, " \
                        "cannot proceed" % (self.curr_server_name)
                    raise Invalid(err_str)

                self.central_server_name_list.append(item.get('name'))
                central_server_schema(item)

                # Check if disk info is defined only in
                # flavor or server basis, not both
                curr_flavor_name = item.get('flavor', None)
                curr_disk_vol_size = item.get('disk_vol_size', None)
                curr_disk_info_for_flavor = \
                    self.get_disk_info_in_flavor(curr_flavor_name)

                curr_cvimadmin_pwd_hash = item.get('cvimadmin_password_hash')

                if curr_disk_vol_size is None and \
                        curr_disk_info_for_flavor is None:
                    err_msg = "Disk info should be defined at " \
                        "flavor %s or at server %s level" \
                        % (curr_flavor_name, item.get('name'))
                    err_list.append(err_msg)

                if curr_disk_vol_size is not None and \
                        curr_disk_info_for_flavor is not None:
                    err_msg = "Disk info can only be defined at " \
                        "flavor %s or at server %s level, not at both" \
                        % (curr_flavor_name, item.get('name'))
                    err_list.append(err_msg)

                if curr_cvimadmin_pwd_hash is None and \
                        global_cvimadmin_password_hash is None:
                    err_msg = "CVIMADMIN_PASSWORD_HASH of cvimadmin_pwd_hash " \
                        "has to be defined for %s" % item.get('name')
                    err_list.append(err_msg)

            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))

        if err_list:
            err_str = ':'.join(err_list)

        return err_str

    def check_aggr_host_validity(self, input_str):
        """Checks Aggr Host Validity"""

        self.is_input_in_plain_str(input_str)
        int_lb_info = \
            self.ymlhelper.get_data_from_userinput_file(\
                ['internal_lb_vip_ipv6_address'])
        via_v6 = 1
        if int_lb_info is None:
            int_lb_info = \
                self.ymlhelper.get_data_from_userinput_file(\
                    ['internal_lb_vip_address'])
            via_v6 = 0
        az_host = common_utils.get_info_from_az( \
            input_str, "hosts", int_lb_info, via_v6)
        if re.search(r'ERROR:', az_host):
            raise Invalid(az_host)

        if not az_host:
            err_msg = "Expected to have atleast 1 compute in host " \
                "aggregate %s found 0" % input_str
            raise Invalid(err_msg)

        az_host_list = az_host.split(",")
        if not az_host_list:
            err_msg = "Expected to have atleast 1 compute in host " \
                "aggregate %s found 0" % input_str
            raise Invalid(err_msg)

    def check_timezone_validity(self, input_str):
        """Check timezone Validity"""

        self.is_input_in_plain_str(input_str)
        tz_base_path = "/usr/share/zoneinfo/"
        tz_full_path = "%s%s" % (tz_base_path, input_str)
        tz_url = "https://en.wikipedia.org/wiki/List_of_tz_database_time_zones"
        if not os.path.isfile(tz_full_path):
            err_msg = "timezone info %s doesnot match that " \
                "defined in TZ database %s; please refer to the TZ database " \
                "name at %s to check on possible values" \
                % (input_str, tz_base_path, tz_url)
            raise Invalid(err_msg)

    def check_cm_username(self, input_str):
        """Check that CM username is not admin"""

        self.is_input_in_plain_str(input_str)
        if input_str == 'admin':
            err_str = "CENTRAL_MGMT_USER_INFO/username cannot be admin"
            raise Invalid(err_str)

    def check_ext_api_fqdn_entry(self, input_str):
        """Check the External API (br_api) FQDN entry"""

        self.check_hostname_syntax(input_str)
        crt_file = os.path.join(self.cfg_dir, "mercury.crt")

        if not os.path.isfile(crt_file):
            err_msg = "file %s not found" % crt_file
            raise Invalid(err_msg)

        _, err_msg = common_utils.is_valid_fqdn(input_str)
        if err_msg:
            raise Invalid(err_msg)
        _, err_msg = common_utils.match_fqdn_in_cert(input_str, crt_file)
        if err_msg:
            raise Invalid(err_msg)

    def validate_schema(self, yaml_input, testbed_type):
        ''' validate the schema based on input'''

        err_list = []
        ucsm_common = Schema({
            Required('ucsm_username'): All(str, Length(min=1), \
                                           msg='UCSM admin username missing'),
            Required('ucsm_password'): self.check_password_syntax, \
            Required('ucsm_ip'): self.is_ip_reachable,
            Required('ucsm_resource_prefix'): All(str, Length(min=1, max=6)),
            Optional('MRAID_CARD'): All(Boolean(str), \
                                        msg="Only Boolean value True/False \
                                        allowed; default is False"),
            Optional('ENABLE_UCSM_PLUGIN'): All(Boolean(str), \
                                        msg="Only Boolean value True/False \
                                        allowed; default is False"),
            Optional('ENABLE_QOS_POLICY'): self.check_qos_policy,
            Optional('ENABLE_QOS_FOR_PORT_PROFILE'): self.check_qos_policy_for_pp,
            Optional('ENABLE_PROV_FI_PIN'): All(Boolean(str), \
                                        msg="Only Boolean value True/False \
                                        allowed; default is False"),
            Optional('QOS_POLICY_TYPE'): self.check_qos_policy_type,
            Optional('MAX_VF_COUNT'): All(int, \
                                          Range(min=1, \
                                                max=config_parser.MAX_VF_COUNT)),
            Optional('ENABLE_VF_PERFORMANCE'): All(Boolean(str), \
                                        msg="Only Boolean value True/False \
                                        allowed; default is False"),
            Optional('tor_info_fi'): self.check_tor_info_fi,
            Optional('tor_info_fi_redundant'): self.check_tor_info_fi,
        })

        ucsm_common_tor = Schema({
            Required('ucsm_username'): All(str, Length(min=1), \
                                           msg='UCSM admin username missing'),
            Required('ucsm_password'): self.check_password_syntax,
            Required('ucsm_ip'): self.is_ip_reachable,
            Required('ucsm_resource_prefix'): All(str, Length(min=1, max=6)),
            Optional('MRAID_CARD'): All(Boolean(str), \
                                        msg="Only Boolean value True/False \
                                        allowed; default is False"),
            Optional('ENABLE_UCSM_PLUGIN'): All(Boolean(str), \
                                        msg="Only Boolean value True/False \
                                        allowed; default is False"),
            Optional('ENABLE_QOS_POLICY'): self.check_qos_policy,
            Optional('ENABLE_QOS_FOR_PORT_PROFILE'): self.check_qos_policy_for_pp,
            Optional('ENABLE_PROV_FI_PIN'): All(Boolean(str), \
                                        msg="Only Boolean value True/False \
                                        allowed; default is False"),
            Optional('QOS_POLICY_TYPE'): self.check_qos_policy_type,
            Optional('MAX_VF_COUNT'): All(int, \
                                          Range(min=1, \
                                                max=config_parser.MAX_VF_COUNT)),
            Optional('ENABLE_VF_PERFORMANCE'): All(Boolean(str), \
                                        msg="Only Boolean value True/False \
                                        allowed; default is False"),
            Required('tor_info_fi'): self.check_tor_info_fi,
            Optional('tor_info_fi_redundant'): self.check_tor_info_fi,
        })

        cimc_common = Schema({
            Required('cimc_username'): All(str, Length(min=1), \
                                           msg='CIMC admin username missing'),
            Required('cimc_password'): self.check_password_syntax,
            Optional('SKU_id'): All(str, Length(min=1)),
        })

        ucsm_schema = Schema({
            Required('UCSMCOMMON'): ucsm_common,
            Required('SERVERS'): self.validate_server_syntax,
        }, extra=True)

        ucsm_tor_schema = Schema({
            Required('UCSMCOMMON'): ucsm_common_tor,
            Required('SERVERS'): self.validate_server_syntax,
        }, extra=True)

        standalone_schema = Schema({
            Required('CIMC-COMMON'): cimc_common,
            Required('SERVERS'): self.validate_server_syntax,
        }, extra=True)

        nfvimon_dispatcher = Schema({
            Required('rabbitmq_username'): self.is_input_in_plain_str_len32,
        })

        nfvimon_master = Schema({
            Required('admin_ip'): self.check_nfvimon_master_admin_ip,
        })

        nfvimon_collector = Schema({
            Required('management_vip'): self.check_valid_nfvimon_mgmt_ip,
            Required('Collector_VM_Info'): self.check_zen_collector_input,
            Optional('COLLECTOR_TORCONNECTIONS'): self.check_zen_collector_tor_info,
        })

        nfvimon_schema = Schema({
            Required('MASTER'): nfvimon_master,
            Required('COLLECTOR'): nfvimon_collector,
            Required('DISPATCHER'): nfvimon_dispatcher,
            Optional('MASTER_2'): nfvimon_master,
            Optional('COLLECTOR_2'): nfvimon_collector,
            Optional('NFVIMON_ADMIN'): self.check_nfvimon_admin_entry,
        })

        complete_nfvimon_schema = Schema({
            Required('NFVIMON'): nfvimon_schema,
            Optional('TORSWITCHINFO'): self.check_torswitch_input,
        }, extra=True)

        complete_nfvimon_aci_schema = Schema({
            Required('NFVIMON'): nfvimon_schema,
            Required('TORSWITCHINFO'): self.check_torswitch_aci_input,
        }, extra=True)

        tor_switch_mand_schema = Schema({
            Required('TORSWITCHINFO'): self.check_torswitch_input,
        }, extra=True)

        tor_switch_mand_aci_schema = Schema({
            Required('TORSWITCHINFO'): self.check_torswitch_aci_input,
        }, extra=True)

        tor_switch_schema = Schema({
            Optional('TORSWITCHINFO'): self.check_torswitch_input,
        }, extra=True)

        tor_switch_aci_schema = Schema({
            Required('TORSWITCHINFO'): self.check_torswitch_aci_input,
        }, extra=True)

        ironic_properties_schema = Schema({
            Required('IRONIC_SWITCHDETAILS'):
                self.check_ironic_torswitch_input,
        })

        ironic_schema = Schema({
            Required('IRONIC'): ironic_properties_schema,
        }, extra=True)


        cvimmon_properties_schema = Schema({
            Required('enabled'): All(Boolean(str), msg="Only Boolean value \
                                     True/False allowed; default is False"),
            Optional('polling_intervals'): self.check_cvim_mon_intervals,
            Optional('ui_access'): self.check_cvim_mon_ui_access,
            Optional('central'): self.check_cvim_mon_central,
            Optional('ldap'): self.check_cvim_mon_ldap,
            Optional('external_servers'): self.external_servers_monitored_schema,
        })

        cvimmon_schema = Schema({
            Optional('CVIM_MON'): cvimmon_properties_schema,
        }, extra=True)

        podname_schema = Schema({
            Required('PODNAME'): self.is_input_in_plain_str,
        }, extra=True)

        msr_paramaters = Schema({
            Required('bgp_as_num'): All(int, Range(min=1, max=65535)),
            Required('isis_area_tag'): self.is_input_in_plain_str_len32,
            Required('loopback_name'): self.check_loopback_syntax,
            Optional('api_bundle_id'): All(int, Range(min=1, max=65535)),
            Optional('api_bridge_domain'): self.is_input_in_plain_str_len32,
            Required('ext_bridge_domain'): self.is_input_in_plain_str_len32,
        })

        msr_schema = Schema({
            Required('MULTI_SEGMENT_ROUTING_INFO'): msr_paramaters,
        }, extra=True)

        mercury_common = Schema({
            Required('COBBLER'): self.check_cobbler_input,
            Required('NETWORKING'): self.check_networking_input,
            Required('ROLES'): self.validate_roles,
            Required('SERVER_COMMON'): self.check_server_common,
            Required('ADMIN_USER'): self.is_input_in_plain_str,
            Required('ADMIN_TENANT_NAME'): self.is_input_in_plain_str,
            Optional('ADMIN_USER_PASSWORD'): self.check_absence_input,
            Required('external_lb_vip_address'): self.validate_external_lb_vip_entry,
            Optional('PODNAME'): self.is_input_in_plain_str,
            Optional('ESI_PREFIX'): self.check_esi_prefix_syntax,
            Optional('external_lb_vip_fqdn'): self.check_hostname_syntax,
            Optional('HORIZON_ALLOWED_HOSTS'): self.validate_networking_entry,
            Optional('CISCO_VIC_SUPPORT'): self.check_cisco_vic_support,
            Optional('INTEL_NIC_SUPPORT'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('COMBINE_CPDP'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('NIC_LEVEL_REDUNDANCY'): self.check_nic_level_redundancy,
            Optional('SRIOV_CARD_TYPE'): self.check_sriov_card_type,
            Optional('INTEL_SRIOV_PHYS_PORTS'): self.check_sriov_phy_ports,
            Optional('autobackup'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('CISCO_VIC_INTEL_SRIOV'): self.check_vic_nic_entry,
            Optional('INTEL_SRIOV_VFS'): self.validate_intel_sriov_entry,
            Optional('INTEL_FPGA_VFS'): self.validate_vista_creek_vfs_entry,
            Optional('INTEL_VC_SRIOV_VFS'): self.validate_vista_creek_sriov_entry,
            Optional('INTEL_N3000_FIRMWARE'): self.validate_intel_n3000_firmware,
            Required('VIRTUAL_ROUTER_ID'): All(int, Range(min=1, max=256)),
            Required('internal_lb_vip_address'): self.validate_internal_lb_vip_entry,
            Optional('REGISTRY_NAME'): self.is_dns_valid,
            Required('REGISTRY_USERNAME'): self.is_input_in_plain_str,
            Required('REGISTRY_PASSWORD'): All(str, Length(min=1)),
            Required('REGISTRY_EMAIL'): self.validate_email,
            Required('MECHANISM_DRIVERS'):
                In(frozenset(["linuxbridge", "openvswitch", "vts", "vpp", "aci"]),
                   msg='only Linuxbridge, openvswitch, vts, vpp or aci allowed \
                    as values'),
            Required('TENANT_NETWORK_TYPES'): In(frozenset(["VXLAN", "VLAN"]),
                                                 msg='only VXLAN or VLAN allowed'),
            Optional('PROVIDER_VLAN_RANGES'): self.check_prov_vlan_info,
            Optional('L3_PROVIDER_VNI_RANGES'): self.check_l3_prov_vni_info,
            Optional('ENABLE_JUMBO_FRAMES'): self.jumbo_frame_check_list,
            Optional('NFV_HOSTS'): self.check_nfv_host,
            Optional('CEPH_PG_INFO'): self.check_ceph_pg_info,
            Optional('VM_HUGEPAGE_SIZE'): self.check_vm_hughpage_size,
            Optional('VM_HUGEPAGE_PERCENTAGE'): self.check_vm_hughpage_percent,
            Optional('VSWITCH_WORKER_PROFILE'): self.check_vswitch_worker_profile,
            Optional('NR_RESERVED_VSWITCH_PCORES'): self.check_reserved_pcores,
            Optional('CEPH_OSD_RESERVED_PCORES'): self.check_ceph_osd_reserved_core,
            Optional('NR_RESERVED_HOST_PCORES'): self.check_reserved_pcores_control,
            Optional('VPP_ENABLE_AVF'): self.check_vpp_enable_avf,
            Optional('INSTALL_MODE'):
                In(frozenset(["connected", "disconnected"]),
                   msg='only connected, disconnected allowed \
                   as values'),
            Optional('VMTP_VALIDATION'): self.vmtp_check_list,
            Optional('NOVA_BOOT_FROM'): In(frozenset(["local", "ceph"]),
                                           msg='only ceph/local allowed as values, \
                                               defaults to local'),
            Optional('OPTIONAL_SERVICE_LIST'): self.optional_service_check_list,
            Optional('NETWORK_OPTIONS'): self.network_options_list,
            Optional('DISABLE_HYPERTHREADING'): self.check_disable_hyperthreading,
            Optional('MULTICAST_SNOOPING'): bool,
            Optional('SYSLOG_EXPORT_SETTINGS'): self.check_syslog_export_settings,
            Optional('ES_REMOTE_BACKUP'): self.check_remote_backup_settings,
            Optional('LDAP'): self.check_ldap_input,
            Optional('vim_ldap_admins'): self.check_vim_ldap_admins,
            Optional('PODTYPE'): self.podtype_check_list,
            Optional('ENABLE_ESC_PRIV'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('ENABLE_READONLY_ROLE'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('NFVBENCH'): self.nfvbench_check_list,
            Optional('CINDER_DB_PASSWORD'): self.check_absence_input,
            Optional('CINDER_KEYSTONE_PASSWORD'): self.check_absence_input,
            Optional('CLOUDPULSE_KEYSTONE_PASSWORD'): self.check_absence_input,
            Optional('COBBLER_PASSWORD'): self.check_absence_input,
            Optional('CPULSE_DB_PASSWORD'): self.check_absence_input,
            Optional('DB_ROOT_PASSWORD'): self.check_absence_input,
            Optional('ELK_PASSWORD'): self.check_absence_input,
            Optional('GLANCE_DB_PASSWORD'): self.check_absence_input,
            Optional('GLANCE_KEYSTONE_PASSWORD'): self.check_absence_input,
            Optional('GNOCCHI_DB_PASSWORD'): self.check_absence_input,
            Optional('GNOCCHI_KEYSTONE_PASSWORD'): self.check_absence_input,
            Optional('HAPROXY_PASSWORD'): self.check_absence_input,
            Optional('HEAT_DB_PASSWORD'): self.check_absence_input,
            Optional('HEAT_KEYSTONE_PASSWORD'): self.check_absence_input,
            Optional('HEAT_STACK_DOMAIN_ADMIN_PASSWORD'): self.check_absence_input,
            Optional('KEYSTONE_ADMIN_TOKEN'): self.check_absence_input,
            Optional('KEYSTONE_DB_PASSWORD'): self.check_absence_input,
            Optional('METADATA_PROXY_SHARED_SECRET'): self.check_absence_input,
            Optional('NEUTRON_DB_PASSWORD'): self.check_absence_input,
            Optional('NEUTRON_KEYSTONE_PASSWORD'): self.check_absence_input,
            Optional('NOVA_DB_PASSWORD'): self.check_absence_input,
            Optional('IRONIC_DB_PASSWORD'): self.check_absence_input,
            Optional('NOVA_KEYSTONE_PASSWORD'): self.check_absence_input,
            Optional('IRONIC_KEYSTONE_PASSWORD'): self.check_absence_input,
            Optional('IRONIC_INSPECTOR_DB_PASSWORD'): self.check_absence_input,
            Optional('IRONIC_INSPECTOR_KEYSTONE_PASSWORD'): self.check_absence_input,
            Optional('RABBITMQ_ERLANG_COOKIE'): self.check_absence_input,
            Optional('RABBITMQ_PASSWORD'): self.check_absence_input,
            Optional('WSREP_PASSWORD'): self.check_absence_input,
            Optional('ETCD_ROOT_PASSWORD'): self.check_absence_input,
            Optional('VPP_ETCD_PASSWORD'): self.check_absence_input,
            Optional('HORIZON_SECRET_KEY'): self.check_absence_input,
            Optional('VOLUME_ENCRYPTION_KEY'): self.check_absence_input,
            Optional('HEAT_VERBOSE_LOGGING'): self.check_absence_input,
            Optional('HEAT_DEBUG_LOGGING'): self.check_absence_input,
            Optional('GLANCE_VERBOSE_LOGGING'): self.check_absence_input,
            Optional('GLANCE_DEBUG_LOGGING'): self.check_absence_input,
            Optional('CINDER_VERBOSE_LOGGING'): self.check_absence_input,
            Optional('CINDER_DEBUG_LOGGING'): self.check_absence_input,
            Optional('NOVA_VERBOSE_LOGGING'): self.check_absence_input,
            Optional('NOVA_DEBUG_LOGGING'): self.check_absence_input,
            Optional('NEUTRON_VERBOSE_LOGGING'): self.check_absence_input,
            Optional('NEUTRON_DEBUG_LOGGING'): self.check_absence_input,
            Optional('KEYSTONE_VERBOSE_LOGGING'): self.check_absence_input,
            Optional('KEYSTONE_DEBUG_LOGGING'): self.check_absence_input,
            Optional('CLOUDPULSE_VERBOSE_LOGGING'): self.check_absence_input,
            Optional('CLOUDPULSE_DEBUG_LOGGING'): self.check_absence_input,
            Optional('IRONIC_VERBOSE_LOGGING'): self.check_absence_input,
            Optional('IRONIC_DEBUG_LOGGING'): self.check_absence_input,
            Optional('OPFLEX_DEBUG_LOGGING'): self.check_absence_input,
            Optional('AIM_DEBUG_LOGGING'): self.check_absence_input,
            Optional('LOGGING_FORMAT_PLAIN'): self.check_absence_input,
            Optional('LOGGING_FORMAT_JSON'): self.check_absence_input,
            Optional('elk_rotation_frequency'): self.check_absence_input,
            Optional('elk_rotation_size'): self.check_absence_input,
            Optional('external_lb_vip_cert'): self.check_absence_input,
            Optional('external_lb_vip_cacert'): self.check_absence_input,
            Optional('SWIFTSTACK'): self.check_swiftstack_input,
            Optional('SOLIDFIRE'): self.check_solidfire_input,
            Optional('NETAPP'): self.check_netapp_input,
            Optional('ZADARA'): self.check_zadara_input,
            Optional('vim_admins'): self.check_vim_admins_input,
            Optional('CLOUD_DEPLOY'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('permit_root_login'): self.check_permit_root_login,
            Optional('ssh_banner'): str,
            Optional('SNMP'): self.check_snmp_settings,
            Optional('SERVER_MON'): self.check_server_mon_settings,
            Optional('ENABLE_TTY_LOGGING'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('MGMTNODE_EXTAPI_REACH'): \
                self.check_mgmtnode_extapi_reach_status,
            Optional('VAULT'): self.check_vault_enabled,
            Optional('ENABLE_VM_EMULATOR_PIN'): \
                self.check_enable_vm_emulator_pin,
            Optional('VM_EMULATOR_PCORES_PER_SOCKET'): \
                self.check_vm_emulator_pcore_per_socket,
            Optional('NOVA_OPT_FOR_LOW_LATENCY'): \
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('ENABLE_RT_KERNEL'): \
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('BASE_MACADDRESS'): self.check_base_macaddress,
            Optional('vim_apic_networks'): self.check_vim_apic_networks,
            Optional('INTEL_RDT'): self.check_intel_rdt_settings,
            Optional('INVENTORY_DISCOVERY'): self.validate_inventory_discovery,
            Optional('SRIOV_SLOT_ORDER'): self.check_sriov_slot_order,
            Optional('IPA_INFO'): self.check_ipa_input,
            Optional('cloud_settings'): self.check_cloud_settings,
            Optional('PASSWORD_MANAGEMENT'): self.check_password_mgmt_input,
            Optional('SSH_ACCESS_OPTIONS'): self.check_ssh_access_options,
            Optional('OCTAVIA_DEPLOYMENT'): self.check_octavia_options,
            Optional('MGMTNODE_EXTAPI_FQDN'): self.check_ext_api_fqdn_entry,
        }, extra=True)

        vlan_range_common = Schema({
            Required('TENANT_VLAN_RANGES'): self.check_vlan_info,
        }, extra=True)

        vts_common = Schema({
            Required('VTS_USERNAME'): self.is_input_in_plain_str,
            Required('VTS_PASSWORD'): self.check_password_syntax,
            Required('VTS_NCS_IP'): self.check_ncsip_validity,
            Optional('VTC_SSH_USERNAME'): self.is_input_in_plain_str,
            Optional('VTC_SSH_PASSWORD'): self.check_password_syntax,
            Optional('VTS_VTC_API_VIP'): self.is_ip_syntax_valid,
            Optional('VTS_VTC_API_IP'): self.validate_vts_vts_api_entry,
            Optional('VTS_XRNC_TENANT_IPS'): self.validate_xrnc_tenant_ips,
            Optional('VTS_DAY0'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('MANAGED'): \
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('BGP_ASN'): All(int, Range(min=1, max=65535)),
            Required('VTS_SITE_UUID'): self.is_input_in_plain_str,
        }, extra=True)

        vts_day0_common = Schema({
            Required('VTS_USERNAME'): self.is_input_in_plain_str,
            Required('VTS_PASSWORD'): self.check_password_syntax,
            Required('VTS_NCS_IP'): self.check_ncsip_validity,
            Required('VTC_SSH_USERNAME'): self.is_input_in_plain_str,
            Required('VTC_SSH_PASSWORD'): self.check_password_syntax,
            Optional('VTS_VTC_API_VIP'): self.is_ip_syntax_valid,
            Optional('VTS_VTC_API_IP'): self.validate_vts_vts_api_entry,
            Optional('VTS_XRNC_TENANT_IPS'): self.validate_xrnc_tenant_ips,
            Required('VTS_DAY0'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('MANAGED'): \
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('BGP_ASN'): All(int, Range(min=1, max=65535)),
            Required('VTS_SITE_UUID'): self.is_input_in_plain_str,
        }, extra=True)

        vts_vmtp_common = Schema({
            Required('VTS_USERNAME'): self.is_input_in_plain_str,
            Required('VTS_PASSWORD'): self.check_password_syntax,
            Required('VTS_NCS_IP'): self.check_ncsip_validity,
            Optional('VTS_VTC_API_VIP'): self.is_ip_syntax_valid,
            Optional('VTS_VTC_API_IP'): self.validate_vts_vts_api_entry,
            Required('VTC_SSH_USERNAME'): self.is_input_in_plain_str,
            Required('VTC_SSH_PASSWORD'): self.check_password_syntax,
            Optional('VTS_XRNC_TENANT_IPS'): self.validate_xrnc_tenant_ips,
            Optional('VTS_DAY0'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('MANAGED'): \
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('BGP_ASN'): All(int, Range(min=1, max=65535)),
            Required('VTS_SITE_UUID'): self.is_input_in_plain_str,
        }, extra=True)

        vts_vmtp_day0_common = Schema({
            Required('VTS_USERNAME'): self.is_input_in_plain_str,
            Required('VTS_PASSWORD'): self.check_password_syntax,
            Required('VTS_NCS_IP'): self.check_ncsip_validity,
            Optional('VTS_VTC_API_VIP'): self.is_ip_syntax_valid,
            Optional('VTS_VTC_API_IP'): self.validate_vts_vts_api_entry,
            Required('VTC_SSH_USERNAME'): self.is_input_in_plain_str,
            Required('VTC_SSH_PASSWORD'): self.check_password_syntax,
            Optional('VTS_XRNC_TENANT_IPS'): self.validate_xrnc_tenant_ips,
            Required('VTS_DAY0'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('MANAGED'): \
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('BGP_ASN'): All(int, Range(min=1, max=65535)),
            Required('VTS_SITE_UUID'): self.is_input_in_plain_str,
        }, extra=True)

        complete_vts_schema = Schema({
            Required('VTS_PARAMETERS'): vts_common,
            Required('TENANT_VLAN_RANGES'): self.check_vlan_info,
        }, extra=True)

        complete_vts_day0_schema = Schema({
            Required('VTS_PARAMETERS'): vts_day0_common,
            Required('TENANT_VLAN_RANGES'): self.check_vlan_info,
        }, extra=True)

        complete_vts_vmtp_schema = Schema({
            Required('VTS_PARAMETERS'): vts_vmtp_common,
            Required('TENANT_VLAN_RANGES'): self.check_vlan_info,
        }, extra=True)

        complete_vts_day0_vmtp_schema = Schema({
            Required('VTS_PARAMETERS'): vts_vmtp_day0_common,
            Required('TENANT_VLAN_RANGES'): self.check_vlan_info,
        }, extra=True)

        ccp_mandatory_schema = Schema({
            Required('CCP_DEPLOYMENT'): self.check_ccp_deployment,
        }, extra=True)

        ccp_optional_schema = Schema({
            Optional('CCP_DEPLOYMENT'): self.check_ccp_deployment,
        }, extra=True)

        testing_schema = Schema({
            Optional('TESTING_TESTBED_NAME'): str,
            Optional('TESTING_MGMT_NODE_CIMC_IP'): self.check_ipv4_or_v6_syntax,
            Optional('TESTING_MGMT_CIMC_USERNAME'): str,
            Optional('TESTING_MGMT_CIMC_PASSWORD'): str,
            Optional('TESTING_MGMT_NODE_API_IP'): str,
            Optional('TESTING_MGMT_NODE_API_GW'): self.is_ip_syntax_valid,
            Optional('TESTING_MGMT_NODE_MGMT_IP'): str,
            Optional('TESTING_MGMT_NODE_TIMEZONE'): str,
            Optional('TESTING_MGMT_NODE_IPV6_ENABLE'): str,
            Optional('TESTING_MGMT_NODE_API_IPV6'): str,
            Optional('TESTING_MGMT_NODE_API_GW_IPV6'): self.is_ipv6_syntax_valid,
            Optional('TESTING_MGMT_NODE_MGMT_IPV6'): str,
            Optional('TESTING_HPE_COMPUTE'): bool,
            Optional('TESTING_MGMT_NODE_USE_TEAMING'): str,
            Optional('TESTING_MGMT_NODE_PUBLIC_API_IP'):
                self.check_ipv4_or_v6_syntax,
            Optional('TESTING_MGMT_NODE_PUBLIC_API_GW'):
                self.check_ipv4_or_v6_syntax,
            Optional('TESTING_MGMT_NODE_MODE'):
                In(frozenset(["STANDARD", "UM", "SDS"]), \
                   msg='only values of STANDARD, UM, SDS allowed'),
        }, extra=True)

        apicinfo_parameters = Schema({
            Required('apic_hosts'): self.check_apic_host_info,
            Required('apic_username'): self.is_input_in_plain_str,
            Required('apic_password'): self.check_password_syntax,
            Required('apic_system_id'): All(str, Length(min=1, max=8)),
            Required('apic_resource_prefix'): All(str, Length(min=1, max=6)),
            Optional('apic_tep_address_pool'): self.check_apic_tep_address_pool,
            Optional('multicast_address_pool'): self.check_multicast_address_pool,
            Required('apic_pod_id'): All(int, Range(min=0, max=65535)),
            Required('apic_installer_tenant'): self.check_apic_installer_tenant,
            Required('apic_installer_vrf'): self.check_apic_installer_vrf,
            Optional('apic_installer_vlan_pool'):
                self.check_apic_installer_vlan_pool,
            Optional('apic_installer_physdom'): self.check_apic_installer_physdom,
            Optional('apic_installer_app_profile'):
                self.check_apic_installer_app_profile,
            Optional('apic_installer_aep'): self.check_apic_installer_aep,
            Optional('api_l3out_network'): self.check_api_l3out_network,
            Optional('mgmt_l3out_network'): self.check_mgmt_l3out_network,
            Optional('mgmt_l3out_vrf'): self.check_mgmt_l3out_vrf,
            Optional('prov_l3out_network'): self.check_prov_l3out_network,
            Optional('prov_l3out_vrf'): self.check_prov_l3out_vrf,
            Optional('mgmt_l2out_network'): self.check_mgmt_l2out_network,
            Optional('api_l2out_network'): self.check_api_l2out_network,
            Optional('prov_l2out_network'): self.check_prov_l2out_network,
            Optional('ext_l2out_network'): self.check_ext_l2out_network,
            Optional('configure_fabric'):
                All(Boolean(str),
                    msg="Only Boolean value True/False, default is true"),
        })

        apicinfo_ceph_parameters = Schema({
            Required('apic_hosts'): self.check_apic_host_info,
            Required('apic_username'): self.is_input_in_plain_str,
            Required('apic_password'): self.check_password_syntax,
            Required('apic_system_id'): All(str, Length(min=1, max=8)),
            Required('apic_resource_prefix'): All(str, Length(min=1, max=6)),
            Optional('apic_tep_address_pool'): self.check_apic_tep_address_pool,
            Optional('multicast_address_pool'): self.check_multicast_address_pool,
            Required('apic_pod_id'): All(int, Range(min=0, max=65535)),
            Required('apic_installer_tenant'): self.check_apic_installer_tenant,
            Required('apic_installer_vrf'):
                self.check_apic_installer_vrf,
            Optional('apic_installer_vlan_pool'):
                self.check_apic_installer_vlan_pool,
            Optional('apic_installer_physdom'): self.check_apic_installer_physdom,
            Optional('apic_installer_app_profile'):
                self.check_apic_installer_app_profile,
            Optional('apic_installer_aep'): self.check_apic_installer_aep,
            Optional('mgmt_l3out_network'): self.check_mgmt_l3out_network,
            Optional('mgmt_l3out_vrf'): self.check_mgmt_l3out_vrf,
            Optional('mgmt_l2out_network'): self.check_mgmt_l2out_network,
            Optional('configure_fabric'):
                All(Boolean(str),
                    msg="Only Boolean value True/False, default is true"),
        })

        apicinfo_schema = Schema({
            Required('APICINFO'): apicinfo_parameters,
        }, extra=True)

        apicinfo_schema_ceph = Schema({
            Required('APICINFO'): apicinfo_ceph_parameters,
        }, extra=True)

        ceph_common = Schema({
            Required('COBBLER'): self.check_cobbler_input,
            Required('NETWORKING'): self.check_networking_input,
            Required('ROLES'): self.validate_roles,
            Required('SERVER_COMMON'): self.check_server_common,
            Required('ADMIN_USER'): self.is_input_in_plain_str,
            Required('ADMIN_TENANT_NAME'): self.is_input_in_plain_str,
            Optional('ADMIN_USER_PASSWORD'): self.check_absence_input,
            Optional('PODNAME'): self.is_input_in_plain_str,
            Optional('CISCO_VIC_SUPPORT'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('INTEL_NIC_SUPPORT'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('COMBINE_CPDP'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('autobackup'):
                All(Boolean(str), msg="Only Boolean value True/False"),
            Optional('REGISTRY_NAME'): self.is_dns_valid,
            Required('REGISTRY_USERNAME'): self.is_input_in_plain_str,
            Required('REGISTRY_PASSWORD'): All(str, Length(min=1)),
            Required('REGISTRY_EMAIL'): self.validate_email,
            Optional('ENABLE_JUMBO_FRAMES'): self.jumbo_frame_check_list,
            Optional('INSTALL_MODE'):
                In(frozenset(["connected", "disconnected"]),
                   msg='only connected, disconnected allowed \
                   as values'),
            Required('PODTYPE'): In(frozenset(["ceph"]), \
               msg='only ceph allowed as values'),
            Optional('vim_admins'): self.check_vim_admins_input,
            Optional('permit_root_login'): self.check_permit_root_login,
            Optional('ssh_banner'): str,
            Optional('SNMP'): self.check_snmp_settings,
            Optional('SERVER_MON'): self.check_server_mon_settings,
            Required('VOLUME_DRIVER'): All(str, Any('ceph')),
            Required('STORE_BACKEND'): All(str, Any('ceph')),
            Required('CIMC-COMMON'): cimc_common,
            Required('SERVERS'): self.validate_server_syntax,
            Optional('CVIM_MON'): cvimmon_properties_schema,
            Optional('vim_ldap_admins'): self.check_vim_ldap_admins,
            Optional('SYSLOG_EXPORT_SETTINGS'): self.check_syslog_export_settings,
            Optional('APICINFO'): apicinfo_ceph_parameters,
            Optional('TORSWITCHINFO'): self.check_torswitch_aci_input,
            Optional('IPA_INFO'): self.check_ipa_input,
            Optional('NIC_LEVEL_REDUNDANCY'): self.check_nic_level_redundancy,
            Optional('PASSWORD_MANAGEMENT'): self.check_password_mgmt_input,
            Optional('SSH_ACCESS_OPTIONS'): self.check_ssh_access_options,
            Optional('VIRTUAL_ROUTER_ID'): self.check_ceph_virtual_router_id,
            Optional('external_lb_vip_address'): self.validate_external_lb_vip_entry,
            Optional('external_lb_vip_ipv6_address'):
                self.validate_external_lb_ipv6_vip_entry,
            Optional('external_lb_vip_fqdn'): self.check_hostname_syntax,
            Optional('external_lb_vip_key'): self.check_absence_input,
            Optional('external_lb_vip_cert'): self.check_absence_input,
            Optional('external_lb_vip_cacert'): self.check_absence_input,
            Optional('external_lb_vip_tls'):
                All(Boolean(str), msg="Only Boolean value True/False"),
        })

        ceph_common_testing = ceph_common.extend({
            Optional('TESTING_TESTBED_NAME'): str,
            Optional('TESTING_MGMT_NODE_CIMC_IP'): self.check_ipv4_or_v6_syntax,
            Optional('TESTING_MGMT_CIMC_USERNAME'): str,
            Optional('TESTING_MGMT_CIMC_PASSWORD'): str,
            Optional('TESTING_MGMT_NODE_API_IP'): str,
            Optional('TESTING_MGMT_NODE_API_GW'): self.is_ip_syntax_valid,
            Optional('TESTING_MGMT_NODE_MGMT_IP'): str,
            Optional('TESTING_MGMT_NODE_TIMEZONE'): str,
            Optional('TESTING_MGMT_NODE_IPV6_ENABLE'): str,
            Optional('TESTING_MGMT_NODE_API_IPV6'): str,
            Optional('TESTING_MGMT_NODE_API_GW_IPV6'): self.is_ipv6_syntax_valid,
            Optional('TESTING_MGMT_NODE_MGMT_IPV6'): str,
            Optional('TESTING_HPE_COMPUTE'): bool,
            Optional('TESTING_MGMT_NODE_USE_TEAMING'): str,
            Optional('TESTING_MGMT_NODE_PUBLIC_API_IP'):
                self.check_ipv4_or_v6_syntax,
            Optional('TESTING_MGMT_NODE_PUBLIC_API_GW'):
                self.check_ipv4_or_v6_syntax,
            Optional('TESTING_MGMT_NODE_MODE'):
                In(frozenset(["STANDARD", "UM", "SDS"]), \
                   msg='only values of STANDARD, UM, SDS allowed'),
        })

        internal_lb_vip_ipv6_schema = Schema({
            Required('internal_lb_vip_ipv6_address'):
                self.validate_internal_lb_ipv6_vip_entry,
        }, extra=True)

        external_lb_vip_ipv4_schema = Schema({
            Required('external_lb_vip_address'): self.validate_external_lb_vip_entry,
        }, extra=True)

        external_lb_vip_ipv6_schema = Schema({
            Required('external_lb_vip_ipv6_address'):
                self.validate_external_lb_ipv6_vip_entry,
        }, extra=True)

        argus_info = Schema({
            Required('PODTYPE'): In(frozenset(["cvimmon"])),
            Optional('DHCP_MODE'): In(frozenset(["v4", "v6"])),
            Required('ISO'): self.check_iso,
            Required('SITE_CONFIG'): self.check_site_schema,
        })

        cvimmonha_common = Schema({
            Required('PODTYPE'): All(str, Any('CVIMMONHA')),
            Optional('REGISTRY_NAME'): self.is_dns_valid,
            Required('REGISTRY_EMAIL'): self.validate_email,
            Required('REGISTRY_PASSWORD'): All(str, Length(min=1)),
            Required('REGISTRY_USERNAME'): self.is_input_in_plain_str,
            Required('internal_loadbalancer_ip'): self.check_loadbalancer_ip,
            Required('external_loadbalancer_ip'): self.check_loadbalancer_ip,
            Optional('INSTALL_MODE'):
                In(frozenset(["connected", "disconnected"]),
                   msg='only connected or disconnected allowed as values'),
            Required('VIRTUAL_ROUTER_ID'): All(int, Range(min=1, max=255)),
            Required('domain_name_servers'): self.validate_networking_entry,
            Required('ntp_servers'): self.check_ntp_syntax,
            Required('cvimmon_domain_suffix'): self.check_domain_suffix,
            Optional('cvimmon_domain_ca_cert'):
                All(str, self.is_certificate_file(check_cert_path=True)),
            Optional('https_proxy_server'): self.check_http_syntax,
            Required('log_rotation_frequency'):
                In(frozenset(["daily", "weekly", "monthly", "yearly"]),
                   msg='only daily, weekly, monthly or yearly allowed'),
            Required('log_rotation_size'): self.check_log_rotation_size,
            Required('log_rotation_del_older'): self.check_log_rotation_del_older,
            Required('cvim-mon-stacks'): self.cvimmonha_properties_schema,
            Required('ARGUS_BAREMETAL'): argus_info,
            Optional('CVIMMONHA_CLUSTER_MONITOR'): self.cvimmonha_monitor_schema,
            Optional('INVENTORY_DISCOVERY'):
                self.validate_inventory_discovery_cvimmon_ha,

        })

        cm_project_info_schema = Schema({
            Required('username'): self.check_cm_username,
            Required('password'): All(str, Length(min=1)),
        })

        mgmt_central_common_base_schema = Schema({
            Required('PODTYPE'): In(frozenset(["MGMT_CENTRAL"])),
            Required('NETWORKS'): self.check_mn_central_networks,
            Required('IMAGES'): self.check_mn_central_images,
            Required('FLAVORS'): self.check_mn_central_flavors,
            Required('KEYPAIRS'): self.check_mn_central_keypairs,
            Optional('CENTRAL_MGMT_AGGREGATE'): self.check_aggr_host_validity,
            Required('CENTRAL_MGMT_USER_INFO'): cm_project_info_schema,
            Optional('TIMEZONE'): self.check_timezone_validity,
            Optional('CVIMADMIN_PASSWORD_HASH'): self.check_password_hash_pat,
            Optional('VOLUME_BACKEND'): In(frozenset(["HDD", "SSD"])),
        })

        mgmt_central_common = mgmt_central_common_base_schema.extend({
            Required('SERVERS_IN_VMS'): self.check_mn_central_servers_syntax,
        })

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        # Check for Virtual Management VM
        if podtype == 'MGMT_CENTRAL':
            try:
                if 'all' in self.vm_list and self.curr_action == 'delete_vms':
                    mgmt_central_common_base_schema(yaml_input)
                else:
                    mgmt_central_common(yaml_input)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))

            if err_list:
                return err_list

            if self.curr_action == 'delete_vms' and 'all' in self.vm_list:
                pass
            else:
                server_check = \
                    self.check_mn_central_servers(yaml_input.get('SERVERS_IN_VMS'))

                if server_check:
                    err_list.append(server_check)

            dup_central_image_name_list = \
                self.check_for_dups_in_list(self.central_image_name_list)
            if dup_central_image_name_list:
                err_str = "Repeating IMAGES:name found: %s" \
                          % (','.join(dup_central_image_name_list))
                err_list.append(err_str)

            dup_central_flavor_name_list = \
                self.check_for_dups_in_list(self.central_flavor_name_list)
            if dup_central_flavor_name_list:
                err_str = "Repeating FLAVORS:name found: %s" \
                          % (','.join(dup_central_flavor_name_list))
                err_list.append(err_str)

            dup_central_keypair_name_list = \
                self.check_for_dups_in_list(self.central_keypair_name_list)
            if dup_central_keypair_name_list:
                err_str = "Repeating KEYPAIRS:keypair found: %s" \
                          % (','.join(dup_central_keypair_name_list))
                err_list.append(err_str)

            dup_central_network_name_list = \
                self.check_for_dups_in_list(self.central_network_name_list)
            if dup_central_network_name_list:
                err_str = "Repeating NETWORKS:name found: %s" \
                          % (','.join(dup_central_network_name_list))
                err_list.append(err_str)

            dup_central_network_vlanid_list = \
                self.check_for_dups_in_list(self.central_network_vlanid_list)
            if dup_central_network_vlanid_list:
                err_str = "Repeating NETWORKS:vlan_id found: %s" \
                          % (','.join(dup_central_network_vlanid_list))
                err_list.append(err_str)

            dup_central_server_name_list = \
                self.check_for_dups_in_list(self.central_server_name_list)
            if dup_central_server_name_list:
                err_str = "Repeating SERVERS_IN_VM:name found: %s" \
                          % (','.join(dup_central_server_name_list))
                err_list.append(err_str)

            dup_central_nic_name_list = \
                self.check_for_dups_in_list(self.central_nic_name_list)
            if dup_central_nic_name_list:
                err_str = "Repeating SERVERS_IN_VM:nic:name found: %s" \
                          % (','.join(dup_central_nic_name_list))
                err_list.append(err_str)

            return err_list

        if podtype == 'CVIMMONHA':

            try:
                cvimmonha_common(yaml_input)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))

            return err_list

        self.testbed_type = testbed_type
        intel_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT'])

        vic_nic_check = \
            self.ymlhelper.get_data_from_userinput_file(['CISCO_VIC_INTEL_SRIOV'])

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        # login to APIC
        if self.cd_cfgmgr.extend_auto_tor_to_aci_fabric() \
                or (mechanism_driver is not None \
                and mechanism_driver.lower() == 'aci'):
            api_login_stat = self.ymlhelper.login_to_apic()

            if re.search(r'ERROR', api_login_stat):
                err_list.append(api_login_stat)

        if err_list:
            return err_list

        podtype = self.ymlhelper.get_pod_type()

        # common validation
        if self.ymlhelper.get_pod_type() == 'ceph':
            found_testing_section = 0
            try:
                testing_schema(yaml_input)
                err_str_info = self.is_testing_section_defined()
                if re.search(r'ERROR', err_str_info):
                    err_list.append(err_str_info)
                else:
                    found_testing_section = 1
            except MultipleInvalid as e:
                for err in e.errors:
                    err_list.append(str(err))

            try:
                if found_testing_section:
                    ceph_common_testing(yaml_input)
                else:
                    ceph_common(yaml_input)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))
        else:
            try:
                mercury_common(yaml_input)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))

        if err_list:
            return err_list

        # testbed specific validation
        try:
            if re.match(r'UCSM', self.testbed_type):
                if self.is_tor_config_enabled():
                    ucsm_tor_schema(yaml_input)
                else:
                    ucsm_schema(yaml_input)
                    if intel_nic_check or vic_nic_check:
                        err_msg = "Intel NIC is not compatible with B-series server"
                        err_list.append(err_msg)
            else:
                if podtype is not None and podtype == 'ceph' and \
                        self.is_cvimmon_enabled() and \
                        self.is_central_cvimmon():
                    external_lb_vip_ipv4_schema(yaml_input)
                    if self.cd_cfgmgr.is_pod_targeted_with_ipv6():
                        external_lb_vip_ipv6_schema(yaml_input)
                elif podtype is not None and podtype == 'ceph':
                    pass
                else:
                    standalone_schema(yaml_input)
                    if self.cd_cfgmgr.is_pod_targeted_with_ipv6():
                        external_lb_vip_ipv6_schema(yaml_input)
                        internal_lb_vip_ipv6_schema(yaml_input)

# get the list of all `Invalid` exceptions caught
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))
        except Exception as e:
            try:
                for x in e.errors:
                    err_list.append(str(x))
            except AttributeError:
                err_list.append(str(e))

        if err_list:
            return err_list

        if self.is_network_segment_defined('vxlan-tenant') and \
                not self.cd_cfgmgr.is_network_option_enabled('vxlan-tenant'):
            err_msg = "vxlan-tenant segment defined without vxlan-tenant " \
                      "as NETWORK_OPTIONS"
            err_list.append(err_msg)
        elif not self.is_network_segment_defined('vxlan-tenant') and \
                self.cd_cfgmgr.is_network_option_enabled('vxlan-tenant'):
            err_msg = "vxlan-tenant NETWORK_OPTIONS defined without " \
                      "vxlan-tenant segment"
            err_list.append(err_msg)

        if self.is_network_segment_defined('vxlan-ecn') and \
                not self.cd_cfgmgr.is_network_option_enabled('vxlan-ecn'):
            err_msg = "vxlan-ecn segment defined without vxlan-ecn " \
                      "as NETWORK_OPTIONS"
            err_list.append(err_msg)
        elif not self.is_network_segment_defined('vxlan-ecn') and \
                self.cd_cfgmgr.is_network_option_enabled('vxlan-ecn'):
            err_msg = "vxlan-ecn NETWORK_OPTIONS defined without " \
                      "vxlan-ecn segment"
            err_list.append(err_msg)

        if self.is_tor_type_ncs5500():
            err_msg = ""
            freta_tor_check = 0
            if not intel_nic_check:
                freta_tor_check = 1
                err_msg = "For NCS-5500 as TOR, Pod has to be running Intel NIC only"
            elif vic_nic_check:
                freta_tor_check = 1
                err_msg = "For NCS-5500 as TOR, Pod has to be running " \
                    "Intel NIC only, currently found to be running " \
                    "with VIC/NIC combo"

            if freta_tor_check:
                err_list.append(err_msg)

                if not self.is_network_segment_defined('sr-mpls-tenant') and \
                        self.cd_cfgmgr.is_network_option_enabled('sr-mpls-tenant'):
                    err_msg = "sr-mpls-tenant NETWORK_OPTIONS defined without " \
                              "sr-mpls-tenant segment"
                    err_list.append(err_msg)

        else:
            if self.cd_cfgmgr.is_network_option_enabled('sr-mpls-tenant'):
                err_msg = "sr-mpls-tenant as NETWORK_OPTIONS defined outside of " \
                    "NCS-5500 setup"
                err_list.append(err_msg)

            if vic_nic_check and mechanism_driver == 'vpp':
                err_msg = "Mechanism Driver of %s not supported " \
                    "with CISCO_VIC_INTEL_SRIOV" % (mechanism_driver)
                err_list.append(err_msg)

        if self.ccp_check:
            try:
                ccp_mandatory_schema(yaml_input)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))
        else:
            try:
                ccp_optional_schema(yaml_input)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))

        # Extra checks for TLS Certificates
        tls_on = Schema({
            Required('external_lb_vip_tls'): All(Boolean(str), IsTrue()),
        }, extra=True)

        tls_off = Schema({
            Required('external_lb_vip_tls'): All(Boolean(str), IsFalse()),
        }, extra=True)

        tls_default = Schema({
            Required('external_lb_vip_tls', default='False'):
                All(Boolean(str), IsFalse()),
        }, extra=True)

        tls_schema = All(Any(tls_on, tls_off, tls_default))
        try:
            tls_schema(yaml_input)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        sriov_multivlan_trunk_schema = Schema({
            Optional('SRIOV_MULTIVLAN_TRUNK'): self.validate_sriov_multivlan_trunk,
        }, extra=True)

        if self.check_ucsm_plugin_presence():
            try:
                sriov_multivlan_trunk_schema(yaml_input)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))

        if mechanism_driver == 'vts':
            huge_page = \
                self.ymlhelper.get_data_from_userinput_file(['VM_HUGEPAGE_SIZE'])
            if huge_page is None or huge_page != '1G':
                err_info = "For VTS mode, VM_HUGEPAGE_SIZE of 1G needs to be set"
                err_list.append(err_info)

            if re.match(r'UCSM', self.testbed_type):
                err_info = "For VTS mode, @ data['VTS_PARAMETERS'] is only \
                           supported on the C-Series"
                err_list.append(err_info)

            elif self.check_no_vts_presence():
                err_info = "VTS mode is enabled, but @ data['VTS_PARAMETERS'] \
                           config stanza missing"
                err_list.append(err_info)

            elif not self.ymlhelper.get_data_from_userinput_file(['NFV_HOSTS']):
                err_info = "VTS mode is enabled, but @ data['NFV_HOSTS'] \
                           is missing"
                err_list.append(err_info)
            elif vic_nic_check:
                err_msg = "Intel NIC is not compatible with mechanism driver vts"
                err_list.append(err_msg)
            else:
                try:
                    if self.is_vmtp_vts_present():
                        if self.is_vmtp_vts_present():
                            if self.check_vts_day0_config():
                                complete_vts_day0_vmtp_schema(yaml_input)
                            else:
                                complete_vts_vmtp_schema(yaml_input)
                    else:
                        if self.check_vts_day0_config():
                            complete_vts_day0_schema(yaml_input)
                        else:
                            complete_vts_schema(yaml_input)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))

            if self.check_managed_vts_config():
                if self.is_tor_config_enabled():
                    err_str = "Auto TOR Configuration cannot be " \
                              "true for Managed VTS"
                    err_list.append(err_str)

        else:
            if not self.check_no_vts_presence():
                err_info = "VTS Parameters exists when mechanism driver is " + \
                    mechanism_driver
                err_list.append(err_info)
            elif self.check_vts_day0_config():
                err_info = "VTS_DAY0 Parameters exists when mechanism driver is " + \
                    mechanism_driver
                err_list.append(err_info)

        # add ACI check
        if mechanism_driver == 'aci' or \
                self.cd_cfgmgr.extend_auto_tor_to_aci_fabric():
            network_type = self.get_network_type()

            if intel_nic_check and not self.is_jumbo_frame_enabled():
                err_msg = "Jumbo Frame has to be enabled in an Intel " \
                    "NIC testbed with ACI as the mechanism driver"
                err_list.append(err_msg)

            elif vic_nic_check and mechanism_driver == 'aci':
                err_msg = "Intel VIC/NIC is not compatible with mechanism driver " \
                    "APIC"
                err_list.append(err_msg)

            elif network_type is not None and network_type.lower() != "vlan":
                err_info = "Only TENANT_NETWORK_TYPES of VLAN allowed for ACI"
                err_list.append(err_info)
            else:
                try:
                    if self.ymlhelper.get_pod_type() == 'ceph':
                        apicinfo_schema_ceph(yaml_input)
                    else:
                        apicinfo_schema(yaml_input)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))

            if self.l2_out_defined and self.l3_out_defined:
                err_msg = "Conflicting L2:%s and L3:%s out " \
                    "network information is defined" \
                    % (','.join(self.l2_out_list), ','.join(self.l3_out_list))
                err_list.append(err_msg)
            elif not self.l2_out_defined and not self.l3_out_defined:
                err_msg = "Neither L2 or L3 out network information is defined"
                err_list.append(err_msg)

            if self.cd_cfgmgr.extend_auto_tor_to_aci_fabric():
                is_vim_apic_networks_defined = \
                    self.ymlhelper.get_data_from_userinput_file(\
                        ["vim_apic_networks"])

                cfg_fabric_chk = ['APICINFO', 'configure_fabric']
                is_configure_fabric_defined = \
                    self.ymlhelper.get_deepdata_from_userinput_file(cfg_fabric_chk)

                if is_configure_fabric_defined is not None and \
                        is_configure_fabric_defined:
                    pass
                elif self.ymlhelper.get_pod_type() == 'ceph' and \
                        is_vim_apic_networks_defined is None:
                    pass
                elif self.ymlhelper.get_pod_type() == 'ceph' and \
                        is_vim_apic_networks_defined is not None:
                    err_str = "vim_apic_networks section definition not " \
                        "allowed when TOR configuration via ACI API is " \
                        "enabled for PODTYPE ceph"
                    err_list.append(err_str)
                elif is_vim_apic_networks_defined is None:
                    err_str = "vim_apic_networks section has to be defined when " \
                        "TOR configuration via ACI API is enabled"
                    err_list.append(err_str)

        network_type = self.get_network_type()
        if self.ymlhelper.get_pod_type() == 'ceph':
            pass
        elif network_type is not None and \
                network_type.lower() == "vlan" and \
                mechanism_driver is not None and \
                re.match(r'openvswitch|vpp|aci', mechanism_driver):
            try:
                vlan_range_common(yaml_input)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))

            nfv_hosts_info = \
                self.ymlhelper.get_data_from_userinput_file(['NFV_HOSTS'])
            if mechanism_driver == 'vpp':
                if re.match(r'UCSM', self.testbed_type):
                    err_info = "Mechanism driver vpp, not supported on B-series"
                    err_list.append(err_info)

                if not nfv_hosts_info:
                    err_info = "Mechanism driver is vpp, \
                        but @ data['NFV_HOSTS'] is missing, \
                        and needs to be set to ALL"
                    err_list.append(err_info)
                elif nfv_hosts_info != 'ALL':
                    err_info = "Mechanism driver is vpp, but @ data['NFV_HOSTS'] " \
                               "is not set to ALL"
                    err_list.append(err_info)

        if mechanism_driver == 'aci' or \
                self.cd_cfgmgr.extend_auto_tor_to_aci_fabric():
            if self.check_nfvimon_presence():
                try:
                    complete_nfvimon_aci_schema(yaml_input)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))

                try:
                    podname_schema(yaml_input)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))

            elif self.cd_cfgmgr.check_nfvbench_presence():
                try:
                    tor_switch_mand_aci_schema(yaml_input)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))

            else:
                try:
                    tor_switch_aci_schema(yaml_input)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))
        else:
            if self.check_nfvimon_presence():
                try:
                    complete_nfvimon_schema(yaml_input)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))

                try:
                    podname_schema(yaml_input)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))

            elif self.is_vmtp_vts_present():
                try:
                    tor_switch_mand_schema(yaml_input)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))

            elif self.cd_cfgmgr.check_nfvbench_presence():
                try:
                    tor_switch_schema(yaml_input)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))
            else:
                try:
                    tor_switch_schema(yaml_input)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))

        if mechanism_driver == 'aci' or \
                self.cd_cfgmgr.extend_auto_tor_to_aci_fabric():
            if self.l2_out_defined:
                if self.api_l2out_network_tor and not self.api_l2out_network:
                    err_msg = "api_l2out_network defined at ToR " \
                        "but not at APICINFO section"
                    err_list.append(err_msg)
                elif not self.api_l2out_network_tor and self.api_l2out_network:
                    err_msg = "api_l2out_network defined at APICINFO " \
                        "but not at ToR section"
                    err_list.append(err_msg)

                if self.mgmt_l2out_network_tor and not self.mgmt_l2out_network:
                    err_msg = "mgmt_l2out_network defined at ToR " \
                        "but not at APICINFO section"
                    err_list.append(err_msg)
                elif not self.mgmt_l2out_network_tor and self.mgmt_l2out_network:
                    err_msg = "mgmt_l2out_network defined at " \
                        "APICINFO but not at ToR section"
                    err_list.append(err_msg)

                if self.ext_l2out_network_tor and not self.ext_l2out_network:
                    err_msg = "ext_l2out_network defined at " \
                        "ToR but not at APICINFO section"
                    err_list.append(err_msg)
                elif not self.ext_l2out_network_tor and self.ext_l2out_network:
                    err_msg = "ext_l2out_network defined at " \
                        "APICINFO but not at ToR section"
                    err_list.append(err_msg)

                if self.prov_l2out_network_tor and not self.prov_l2out_network:
                    err_msg = "prov_l2out_network defined at ToR " \
                        "but not at APICINFO section"
                    err_list.append(err_msg)
                elif not self.prov_l2out_network_tor and self.prov_l2out_network:
                    err_msg = "prov_l2out_network defined at " \
                        "APICINFO but not at ToR section"
                    err_list.append(err_msg)

        if self.check_nfvimon_presence() and \
                self.check_for_optional_enabled('ceilometer'):
            err_str = "NFVIMON and ceilometer are mutually incompatible; " \
                "If you want to use ceilometer, " \
                "please use CVIM_MON as an option instead"
            err_list.append(err_str)

        # Multi-backend ceph check
        if self.is_ceph_multi_backend():
            mbc_err_list = self.check_multi_backend_ceph()
            if mbc_err_list:
                for item in mbc_err_list:
                    err_list.append(item)

            if not re.search(r'DEDICATED_CEPH', \
                    self.get_storage_deployment_info()):
                err_str = "Multi-Backend Ceph only supported " \
                    "with DEDICATED_CEPH"
                err_list.append(err_str)

            solidfire_info = \
                self.ymlhelper.get_data_from_userinput_file(["SOLIDFIRE"])
            if solidfire_info is not None:
                err_str = "Multi-Backend Ceph not supported " \
                    "with SOLIDFIRE"
                err_list.append(err_str)

            nova_boot_from = \
                self.ymlhelper.get_data_from_userinput_file(['NOVA_BOOT_FROM'])
            if nova_boot_from is not None and nova_boot_from == 'ceph':
                err_str = "Multi-Backend Ceph not supported " \
                    "with NOVA_BOOT_FROM: ceph, " \
                    "please change the value to local"
                err_list.append(err_str)
        else:
            if self.global_multi_backend_ssd_ceph and \
                    not self.global_multi_backend_hdd_ceph:
                err_str = "In a single backend ceph, osd_disk_type: " \
                    "SSD is not allowed, please leave it empty; " \
                    "CVIM has the intelligence to sort out the osd disk type"
                err_list.append(err_str)

        # CHeck on the ironic tor switch info
        if self.check_for_optional_enabled('ironic'):
            try:
                ironic_schema(yaml_input)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))
        else:
            ironic_section = \
                self.ymlhelper.get_data_from_userinput_file(['IRONIC'])
            if ironic_section is not None:
                err_str = "IRONIC section is defined when ironic is " \
                    "not in OPTIONAL_SERVICE_LIST"
                err_list.append(err_str)

        if self.is_tor_type_ncs5500():
            num_ncs5k = self.get_num_ncs5500_tor()
            if num_ncs5k == 2:
                try:
                    msr_schema(yaml_input)
                    if self.is_msr_routing_info_defined():
                        msr_routing_info = \
                            self.ymlhelper.get_data_from_userinput_file( \
                                ['MULTI_SEGMENT_ROUTING_INFO'])

                        api_bundle_id = msr_routing_info.get('api_bundle_id')
                        api_bd = msr_routing_info.get('api_bridge_domain')
                        if api_bundle_id and api_bd:
                            err_msg = "Definition of api_bundle_id and " \
                                "api_bridge_domain are mutually exclusive"
                            err_list.append(err_msg)
                except MultipleInvalid as e:
                    for x in e.errors:
                        err_list.append(str(x))

        try:
            cvimmon_schema(yaml_input)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        if self.check_cvimmon_presence():
            try:
                podname_schema(yaml_input)
            except MultipleInvalid as e:
                for x in e.errors:
                    err_list.append(str(x))

        check_nfvimon_ha_def = self.check_nfvimon_2nd_instance_present()
        if re.search(r'ERROR', check_nfvimon_ha_def):
            err_list.append(check_nfvimon_ha_def)

        storage_schema_chk = self.check_storage_schema(yaml_input)
        if storage_schema_chk:
            err_list.append(storage_schema_chk)

        try:
            testing_schema(yaml_input)
            err_str_info = self.is_testing_section_defined()
            if re.search(r'ERROR', err_str_info):
                err_list.append(err_str_info)
        except MultipleInvalid as e:
            for err in e.errors:
                err_list.append(str(err))

        prov_vlan_info = \
            self.ymlhelper.get_data_from_userinput_file(['PROVIDER_VLAN_RANGES'])
        auto_tor_via_aci = self.cd_cfgmgr.extend_auto_tor_to_aci_fabric()

        if auto_tor_via_aci:
            if prov_vlan_info is None and \
                    self.ymlhelper.get_pod_type() == 'ceph':
                pass

            elif prov_vlan_info is None:
                err_str = "PROVIDER_VLAN_RANGES is not defined when " \
                    "TOR configuration via ACI API is enabled"
                err_list.append(err_str)
        else:
            intel_nic_sriov_check = \
                self.ymlhelper.get_data_from_userinput_file(['INTEL_SRIOV_VFS'])

            intel_sriov_phys_ports = \
                self.ymlhelper.get_data_from_userinput_file(\
                    ['INTEL_SRIOV_PHYS_PORTS'])
            if (intel_nic_sriov_check is not None) or \
                    (intel_sriov_phys_ports is not None):
                if prov_vlan_info is None:
                    err_str = "PROVIDER_VLAN_RANGES is not defined even " \
                        "though SRIOV is chosen as an option"
                    err_list.append(err_str)

        if self.cd_cfgmgr.is_l3_fabric_enabled():
            l3_prov_vni_info = \
                self.ymlhelper.get_data_from_userinput_file(\
                    ['L3_PROVIDER_VNI_RANGES'])

            if l3_prov_vni_info is None:
                err_str = "L3_PROVIDER_VNI_RANGES is not defined when " \
                    "l3 fabric is enabled"
                err_list.append(err_str)

        dup_l3_vni_list = \
            self.check_for_dups_in_list(self.l3_fabric_vni_list)
        if dup_l3_vni_list:
            err_str = "Repeating l3_fabric_vnis in " \
                "setup_data.yaml: %s" \
                % (','.join(dup_l3_vni_list))
            err_list.append(err_str)

        dup_vxlan_tenant_ip_list = \
            self.check_for_dups_in_list(self.global_vxlan_tenant_ip_list)
        if dup_vxlan_tenant_ip_list:
            err_str = "Repeating vxlan_bgp_speaker IPs in " \
                "vxlan-tenant network in setup_data.yaml: %s" \
                % (','.join(dup_vxlan_tenant_ip_list))
            err_list.append(err_str)

        dup_vxlan_ecn_ip_list = \
            self.check_for_dups_in_list(self.global_vxlan_ecn_ip_list)
        if dup_vxlan_ecn_ip_list:
            err_str = "Repeating vxlan_bgp_speaker IPs in " \
                "vxlan-ecn network in setup_data.yaml: %s" \
                % (','.join(dup_vxlan_ecn_ip_list))
            err_list.append(err_str)

        dup_vxlan_tenant_vtep_ip_list = \
            self.check_for_dups_in_list(self.global_vxlan_tenant_vtep_ip_list)
        if dup_vxlan_tenant_vtep_ip_list:
            err_str = "Repeating vxlan vtep_ip(s) in " \
                "vxlan-tenant network in setup_data.yaml: %s" \
                % (','.join(dup_vxlan_tenant_vtep_ip_list))
            err_list.append(err_str)

        dup_vxlan_ecn_vtep_ip_list = \
            self.check_for_dups_in_list(self.global_vxlan_ecn_vtep_ip_list)
        if dup_vxlan_ecn_vtep_ip_list:
            err_str = "Repeating vxlan vtep_ip(s) in " \
                "vxlan-ecn network in setup_data.yaml: %s" \
                % (','.join(dup_vxlan_ecn_vtep_ip_list))
            err_list.append(err_str)

        dup_sr_mpls_tenant_ip_list = \
            self.check_for_dups_in_list(self.global_sr_mpls_tenant_ip_list)
        if dup_sr_mpls_tenant_ip_list:
            err_str = "Repeating vtep_ip(s) in " \
                "mpls-sr-tenant network in setup_data.yaml: %s" \
                % (','.join(dup_sr_mpls_tenant_ip_list))
            err_list.append(err_str)

        dup_sr_mpls_prefix_sid_list = \
            self.check_for_dups_in_dict(self.global_sr_mpls_block_info)
        if dup_sr_mpls_prefix_sid_list:
            err_str = "Repeating sr_global_block (prefix_sid_index + base) " \
                "value for servers in setup_data.yaml: %s" \
                % (', '.join(dup_sr_mpls_prefix_sid_list))
            err_list.append(err_str)

        dup_vlan_list = \
            self.check_for_dups_in_dict(self.global_vlan_info)
        if dup_vlan_list:
            err_str = "Repeating VLANs in %s setup_data.yaml" \
                % (', '.join(dup_vlan_list))
            err_list.append(err_str)

        dup_bgp_asn_num = self.check_for_dups_in_list(self.global_bgp_asn_num)
        if dup_bgp_asn_num:
            err_str = "Repeating bgp_as_num:%s found " \
                "in setup_data.yaml" % (','.join(dup_bgp_asn_num))
            err_list.append(err_str)

        dup_physnet_name = self.check_for_dups_in_list(self.global_physnet_name)
        if dup_physnet_name:
            err_str = "Repeating physnet_name:%s found under " \
                "NETWORK_OPTIONS:vxlan/sr-mpls section in setup_data.yaml" \
                % (','.join(dup_physnet_name))
            err_list.append(err_str)

        dup_storage_ip_list = \
            self.check_for_dups_in_list(self.global_storage_ip_list)
        if dup_storage_ip_list:
            err_str = "Repeating IPs in Storage Network in setup_data.yaml: %s" \
                % (','.join(dup_storage_ip_list))
            err_list.append(err_str)

        dup_cluster_ip_list = \
            self.check_for_dups_in_list(self.global_cluster_ip_list)
        if dup_cluster_ip_list:
            err_str = "Repeating IPs in cluster Network in setup_data.yaml: %s" \
                % (','.join(dup_cluster_ip_list))
            err_list.append(err_str)

        dup_mgmt_ip_list = \
            self.check_for_dups_in_list(self.global_mgmt_ip_list)
        if dup_mgmt_ip_list:
            err_str = "Repeating IPs in br_mgmt Network in setup_data.yaml: %s" \
                % (','.join(dup_mgmt_ip_list))
            err_list.append(err_str)

        dup_mgmt_ipv6_list = \
            self.check_for_dups_in_list(self.global_mgmt_ipv6_list)
        if dup_mgmt_ipv6_list:
            err_str = "Repeating IPv6s in br_mgmt Network in setup_data.yaml: %s" \
                % (','.join(dup_mgmt_ipv6_list))
            err_list.append(err_str)

        dup_tenant_ip_list = \
            self.check_for_dups_in_list(self.global_tenant_ip_list)
        if dup_tenant_ip_list:
            err_str = "Repeating IPs in tenant Network in setup_data.yaml: %s" \
                % (','.join(dup_tenant_ip_list))
            err_list.append(err_str)

        dup_admin_ip_list = \
            self.check_for_dups_in_list(self.global_admin_ip_list)
        if dup_admin_ip_list:
            err_str = "Repeating IPs in br_api network in setup_data.yaml: %s" \
                % (','.join(dup_admin_ip_list))
            err_list.append(err_str)

        dup_admin_ipv6_list = \
            self.check_for_dups_in_list(self.global_admin_ipv6_list)
        if dup_admin_ipv6_list:
            err_str = "Repeating IPv6s in br_api network in setup_data.yaml: %s" \
                % (','.join(dup_admin_ipv6_list))
            err_list.append(err_str)

        dup_nfvimon_master_admin_ip = \
            self.check_for_dups_in_list(self.global_nfvimon_master_admin_ip)
        if dup_nfvimon_master_admin_ip:
            err_str = "Repeating NFVIMON master admin_ip in setup_data.yaml: %s" \
                % (','.join(dup_nfvimon_master_admin_ip))
            err_list.append(err_str)

        if self.cd_cfgmgr.extend_auto_tor_to_aci_fabric():
            self.ymlhelper.logout_from_apic()

        return err_list
