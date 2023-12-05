#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Validations:
==============

Validations Module:
---------------------------------------
The First step to the installer is to perform a validation on the user input
file. Most often when an install fails it is likely due to a misconfiguration
or mis-representation of some data that is needed by the installer.

Running a validation on the user input file will help avoid such issues and in
turn improve customer satisfaction.

Validations:
------------------
 1. Check if User-input data is located in the expect place and
    all user input files are available.

"""
import argparse
from collections import Counter
import copy
from fnmatch import fnmatch
import hashlib
import json
import os
import re
import shutil
import socket
import sys
import subprocess
import textwrap
from threading import Thread
import time
import urllib2
import xmlrpclib  # nosec
import multiprocessing

from multiprocessing.pool import ThreadPool
from functools import partial
from copy import deepcopy

import requests
import prettytable
import ipaddr
import netaddr

try:
    import hvac
except ImportError:
    pass


import paramiko
import yaml
import yaml.parser
from yaml.nodes import ScalarNode
from yaml.nodes import SequenceNode
from yaml.nodes import MappingNode

import netifaces
from OpenSSL import crypto, SSL

sys.path.insert(1, os.path.dirname(\
    os.path.dirname(os.path.realpath(__file__))))

from baremetal.common import constants as bmconstants
import baremetal.cobbler.cobbler as cobblerutils
from bootstrap import build_orchestration
import clouddeploy.buildnode_validations as bn_validations
import clouddeploy.config_manager as config_manager
import clouddeploy.orchestrator as orchestrator
import clouddeploy.reconfigure_params as reconfigure_params
import clouddeploy.schema_validation as schema_validation
import utils.common as common
import utils.config_parser as config_parser
import utils.logger as logger
from utils.vtc_cfg.vtc_client import VtcClient
from baremetal.apic import apic_orchestration


cimc_black_list = []
try:
    cimc_black_list = bmconstants.CIMC_BLACK_LIST
except AttributeError:
    pass

try:
    from apic_api import apic_api as apic_api
except ImportError:
    import apic_api as apic_api
try:
    import clouddeploy.hw_validations as hw_validations
except ImportError:
    print "Possible import failure due to upgrade ignore"
try:
    import baremetal.ucs_b.ucsm_utils as ucsmutils
except:
    print "Possible import failure due to upgrade ignore"
try:
    import baremetal.ucs_c.cimc_utils as cimcutils
except:
    print "Possible import failure due to upgrade ignore"

INSTALLER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CFG_DIR = "openstack-configs"
DEFAULT_OS_CFG_FILE = "openstack_config.yaml"
DEFAULT_SETUP_FILE = "setup_data.yaml"
SETUP_FILE_DIR = "/root/openstack-configs/setup_data.yaml"
BACKUP_SETUP_FILE = ".backup_setup_data.yaml"
DEFAULTS_FILE = "defaults.yaml"
SECRETS_FILE = "secrets.yaml"
VAULT_FILE = "/opt/cisco/vault/key.yaml"
VAULT_SECRETS_PATH = "secret/data/cvim-secrets"
APIC_MAJOR_VERSION = '2.2'
NEXUS_TOR_TYPE = "Nexus"
NCS_TOR_TYPE = "NCS-5500"
CVIM_RESERVED_NETWORK = ['192.168.1.0/24', '192.168.2.0/24']
_PEM_RE = re.compile(b'-----BEGIN CERTIFICATE-----\r?.+?\r?-----END CERTIFICATE-----\r?\n?', re.DOTALL)


STATUS_FAIL = 'FAIL'
STATUS_PASS = 'PASS'

THREAD_POOL_SIZE = 50

class ExecThread(Thread):
    '''
    Thread for performing operations on hosts.
    '''
    def __init__(self, curr_ip, operation_func, **kwargs):
        super(ExecThread, self).__init__()
        self.oper_func = operation_func
        self.oper_status = None
        self.host_ip = curr_ip
        self.kwargs = kwargs
        self.fin_arg_str = ""
        self.loginst = logger.Logger(name=__name__)
        self.log = self.loginst.get_logger()
        self.log.debug("Threading Initialized")

    def run(self):
        '''run the command in thread'''

        self.oper_status = self.oper_func(self.host_ip, **self.kwargs)
        if self.oper_status:
            self.log.info("[%s] Status of %s is: %s", \
                self.host_ip, self.oper_func, self.oper_status)


class Validator(object):
    '''
    Validator class.
    '''
    OPER_STAGE = "INIT"
    STAGE_COUNT = 0

    def __init__(self, setupfileloc, test_type='all', viaCLI=False, cvimmonha_setup=None, bkp_cvimmonha_setup=None):
        '''
        Initialize validator
        '''
        # ###############################################
        # Set up logging
        # ###############################################
        self.loginst = logger.Logger(name=__name__)
        self.log = self.loginst.get_logger()
        self.ymlhelper = None
        self.validation_results = []

        homedir = self.get_homedir()
        self.cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)
        cfgd = os.path.join("/bootstrap/", DEFAULT_CFG_DIR)

        if viaCLI:
            pass
        elif not os.path.exists(self.cfg_dir):
            os.symlink(os.getcwd() + cfgd, self.cfg_dir)

        if setupfileloc is not None:
            self.setup_file = setupfileloc
        else:
            self.setup_file = os.path.join(self.cfg_dir, DEFAULT_SETUP_FILE)

        self.secrets_file = os.path.join(self.cfg_dir, SECRETS_FILE)
        self.cobbler_file = common.get_cobbler_data_file_path()
        self.backup_setup_file = os.path.join(self.cfg_dir, BACKUP_SETUP_FILE)
        self.ucsm_access = 1

        if not os.path.exists(self.cfg_dir):
            self.cfgmgr = config_manager.ConfigManager(\
                userinput=self.setup_file, via_softlink=0)

            file_name_list = common.find_file_path(INSTALLER_ROOT, "defaults.yaml")
            default_file_abs_path = ""

            for item in file_name_list:
                if os.path.basename(item) == 'defaults.yaml':
                    default_file_abs_path = item
                    break

            if not default_file_abs_path:
                curr_msg = "defaults.yaml file not found, " \
                           "cant verify Installer workspace"
                self.log.info(curr_msg)
            else:
                self.defaults_file = default_file_abs_path

        else:
            self.cfgmgr = config_manager.ConfigManager(userinput=self.setup_file)
            self.defaults_file = os.path.join(self.cfg_dir, DEFAULTS_FILE)

        self.ymlhelper = config_parser.YamlHelper(
            user_input_file=self.setup_file)

        self.vault_config = self.ymlhelper.get_vault_info()
        self.skip_vault = 0
        if self.vault_config is not None and \
                self.vault_config.get('enabled', None) is not None:
            mgmt_ip = self.cfgmgr.get_build_node_ip('management')

            if mgmt_ip is not None:
                try:
                    with open(VAULT_FILE, 'r') as f:
                        data = yaml.safe_load(f.read())
                        token = data['root_token']
                    if ipaddr.IPAddress(mgmt_ip).version == 6:
                        mgmt_ip = "[%s]" % mgmt_ip
                    self.hvac_client = hvac.Client(url='http://' + mgmt_ip + ':8200',
                                                   token=token)
                except IOError:
                    self.skip_vault = 1
            else:
                self.skip_vault = 1

        self.pod_pv_count_per_switch = {}
        self.cvim_mon_target_fail_list = []
        self.cvim_mon_target_cert_fail_list = []
        self.cvim_mon_target_connection_fail_list = []

        self.test_type = test_type

        self.backup_cm_setup_file = \
            os.path.join(self.cfg_dir, common.BACKUP_CENTRAL_MGMT_SETUP_FILE)

        self.cvimmonha_setup = cvimmonha_setup
        self.bkp_cvimmonha_setup = bkp_cvimmonha_setup

        self.validation_error_code = {}

        self.validation_error_code['UNSUPPORTED_KEY'] = "VE10000"
        self.validation_error_code['CIMC-COMMON'] = "VE5000"
        self.validation_error_code['cimc_username'] = "VE5001"
        self.validation_error_code['cimc_password'] = "VE5002"
        self.validation_error_code['SKU_id'] = "VE5003"

        self.validation_error_code['UCSMCOMMON'] = "VE5021"
        self.validation_error_code['ucsm_username'] = "VE5022"
        self.validation_error_code['ucsm_password'] = "VE5023"
        self.validation_error_code['ucsm_ip'] = "VE5024"
        self.validation_error_code['ucsm_resource_prefix'] = "VE5025"
        self.validation_error_code['MRAID_CARD'] = "VE5026"
        self.validation_error_code['ENABLE_PROV_FI_PIN'] = "VE5082"
        self.validation_error_code['MAX_VF_COUNT'] = "VE5027"
        self.validation_error_code['ENABLE_VF_PERFORMANCE'] = "VE5028"

        self.validation_error_code['COBBLER'] = "VE5031"
        self.validation_error_code['host_profile'] = "VE5032"
        self.validation_error_code['cobbler_username'] = "VE5033"
        self.validation_error_code['cobbler_password'] = "VE5034"
        self.validation_error_code['admin_password_hash'] = "VE5035"
        self.validation_error_code['admin_ssh_keys'] = "VE5036"
        self.validation_error_code['kickstart'] = "VE5037"
        self.validation_error_code['control'] = "VE5038"
        self.validation_error_code['compute'] = "VE5039"
        self.validation_error_code['block_storage'] = "VE5040"
        self.validation_error_code['pxe_timeout'] = "VE5041"
        self.validation_error_code['hw_raid'] = "VE5042"
        self.validation_error_code['use_teaming'] = "VE5043"
        self.validation_error_code['enable_ipv6_pxe'] = "VE5044"

        self.validation_error_code['NETWORKING'] = "VE6000"
        self.validation_error_code['domain_name'] = "VE6001"
        self.validation_error_code['ntp_servers'] = "VE6002"
        self.validation_error_code['domain_name_servers'] = "VE6003"
        self.validation_error_code['http_proxy_server'] = "VE6004"
        self.validation_error_code['https_proxy_server'] = "VE6005"
        self.validation_error_code['networks'] = "VE6006"
        self.validation_error_code['admin_source_networks'] = "VE6009"

        self.validation_error_code['tenant'] = "VE6007"
        self.validation_error_code['pool'] = "VE6008"
        self.validation_error_code['tenant_ip'] = "VE6011"

        self.validation_error_code['ROLES'] = "VE7000"

        self.validation_error_code['SERVER_COMMON'] = "VE7001"
        self.validation_error_code['server_username'] = "VE7002"

        self.validation_error_code['SERVERS'] = "VE8000"
        self.validation_error_code['rack_info'] = "VE8001"
        self.validation_error_code['rack_id'] = "VE8002"
        self.validation_error_code['ucsm_info'] = "VE8003"
        self.validation_error_code['server_type'] = "VE8004"
        self.validation_error_code['chassis_id'] = "VE8005"
        self.validation_error_code['blade_id'] = "VE8006"
        self.validation_error_code['server_type'] = "VE8007"
        self.validation_error_code['rack-unit_id'] = "VE8008"

        self.validation_error_code['cimc_info'] = "VE8009"
        self.validation_error_code['cimc_ip'] = "VE8010"
        self.validation_error_code['hardware_info'] = "VE8011"
        self.validation_error_code['VIC_slot'] = "VE8012"
        self.validation_error_code['num_root_drive'] = "VE8013"
        self.validation_error_code['root_drive_type'] = "VE8014"
        self.validation_error_code['vendor'] = "VE8026"
        self.validation_error_code['root_drive_raid_level'] = "VE8027"
        self.validation_error_code['root_drive_raid_spare'] = "VE8028"
        self.validation_error_code['control_bond_mode'] = "VE8029"
        self.validation_error_code['data_bond_mode'] = "VE8030"

        self.validation_error_code['external_lb_vip_address'] = "VE8050"
        self.validation_error_code['internal_lb_vip_address'] = "VE8051"

        self.validation_error_code['ADMIN_USER'] = "VE8053"
        self.validation_error_code['ADMIN_USER_PASSWORD'] = "VE8054"
        self.validation_error_code['ADMIN_TENANT_NAME'] = "VE8055"

        self.validation_error_code['TENANT_NETWORK_TYPES'] = "VE8056"
        self.validation_error_code['MECHANISM_DRIVERS'] = "VE8057"
        self.validation_error_code['TENANT_VLAN_RANGES'] = "VE8058"

        self.validation_error_code['GLANCE_RBD_POOL'] = "VE8059"
        self.validation_error_code['GLANCE_CLIENT_KEY'] = "VE8060"
        self.validation_error_code['STORE_BACKEND'] = "VE8061"

        self.validation_error_code['VOLUME_DRIVER'] = "VE8062"
        self.validation_error_code['VOLUME_GROUP'] = "VE8063"

        self.validation_error_code['CINDER_RBD_POOL'] = "VE8064"
        self.validation_error_code['CINDER_CLIENT_KEY'] = "VE8065"
        self.validation_error_code['CLUSTER_ID'] = "VE8067"
        self.validation_error_code['MON_MEMBERS'] = "VE8068"
        self.validation_error_code['SECRET_UUID'] = "VE8069"

        self.validation_error_code['MON_HOSTS'] = "VE8070"
        self.validation_error_code['ENABLE_JUMBO_FRAMES'] = "VE8071"
        self.validation_error_code['ENABLE_UCSM_PLUGIN'] = "VE8073"
        self.validation_error_code['external_lb_vip_tls'] = "VE8074"
        self.validation_error_code['NOVA_BOOT_FROM'] = "VE8077"
        self.validation_error_code['NOVA_RBD_POOL'] = "VE8078"
        self.validation_error_code['external_lb_vip_fqdn'] = "VE8080"
        self.validation_error_code['NFV_HOSTS'] = "VE8079"
        self.validation_error_code['VM_HUGEPAGE_SIZE'] = "VE8081"
        self.validation_error_code['VM_HUGEPAGE_PERCENTAGE'] = "VE8082"
        self.validation_error_code['HORIZON_ALLOWED_HOSTS'] = "VE8083"

        self.validation_error_code['VMTP_VALIDATION'] = "VE9000"
        self.validation_error_code['PROV_NET'] = "VE9001"
        self.validation_error_code['EXT_NET'] = "VE9002"
        self.validation_error_code['NET_SUBNET'] = "VE9003"
        self.validation_error_code['DNS_SERVER'] = "VE9004"
        self.validation_error_code['NET_IP_START'] = "VE9005"
        self.validation_error_code['NET_IP_END'] = "VE9006"
        self.validation_error_code['NET_GATEWAY'] = "VE9007"
        self.validation_error_code['SEGMENTATION_ID'] = "VE9008"
        self.validation_error_code['VNIC_TYPE'] = "VE9029"
        self.validation_error_code['PHYSNET_NAME'] = "VE9081"

        self.validation_error_code['OPTIONAL_SERVICE_LIST'] = "VE9009"

        self.validation_error_code['REGISTRY_NAME'] = "VE9013"
        self.validation_error_code['REGISTRY_USERNAME'] = "VE9014"
        self.validation_error_code['REGISTRY_PASSWORD'] = "VE9015"
        self.validation_error_code['REGISTRY_EMAIL'] = "VE9016"

        self.validation_error_code['SRIOV_MULTIVLAN_TRUNK'] = "VE9017"
        self.validation_error_code['ENABLE_QOS_POLICY'] = "VE9018"
        self.validation_error_code['ENABLE_QOS_FOR_PORT_PROFILE'] = "VE9019"
        self.validation_error_code['QOS_POLICY_TYPE'] = "VE9021"

        self.validation_error_code['NFVIMON'] = "VE9030"
        self.validation_error_code['hostname'] = "VE9031"   # nosec
        self.validation_error_code['MASTER'] = "VE9032"
        self.validation_error_code['management_vip'] = "VE9033"
        self.validation_error_code['password'] = "VE9034"   # nosec
        self.validation_error_code['ccuser_password'] = "VE9061"   # nosec
        self.validation_error_code['admin_ip'] = "VE9035"
        self.validation_error_code['management_ip'] = "VE9036"
        self.validation_error_code['COLLECTOR'] = "VE9037"
        self.validation_error_code['DISPATCHER'] = "VE9038"
        self.validation_error_code['rabbitmq_username'] = "VE9039"
        self.validation_error_code['PODNAME'] = "VE9040"
        self.validation_error_code['Collector_VM_Info'] = "VE9058"

        self.validation_error_code['TORSWITCHINFO'] = "VE9041"
        self.validation_error_code['ssh_ip'] = "VE9044"
        self.validation_error_code['ssn_num'] = "VE9045"
        self.validation_error_code['vpc_domain'] = "VE9046"
        self.validation_error_code['br_mgmt_port_info'] = "VE9046"
        self.validation_error_code['vpc_peer_port_info'] = "VE9047"
        self.validation_error_code['br_mgmt_po_info'] = "VE9048"
        self.validation_error_code['vpc_peer_vlan_info'] = "VE9042"
        self.validation_error_code['vpc_peer_keepalive'] = "VE9043"

        self.validation_error_code['CUSTOM_CONFIG'] = "VE9050"
        self.validation_error_code['GLOBAL'] = "VE9051"
        self.validation_error_code['PORTCHANNEL'] = "VE9052"
        self.validation_error_code['SWITCHPORT'] = "VE9053"
        self.validation_error_code['tor_info'] = "VE9054"
        self.validation_error_code['dp_tor_info'] = "VE9055"
        self.validation_error_code['tor_info_fi'] = "VE9056"
        self.validation_error_code['tor_info_fi_redundant'] = "VE9057"
        self.validation_error_code['tor_info_egress'] = "VE9059"

        self.validation_error_code['VTS_USERNAME'] = "VE9060"
        self.validation_error_code['VTS_NCS_IP'] = "VE9068"
        self.validation_error_code['VTS_VTC_API_IP'] = "VE9069"
        self.validation_error_code['VTS_PASSWORD'] = "VE9074"
        self.validation_error_code['VTS_PARAMETERS'] = "VE9075"
        self.validation_error_code['VTC_SSH_USERNAME'] = "VE9062"
        self.validation_error_code['VTC_SSH_PASSWORD'] = "VE9063"

        self.validation_error_code['SYSLOG_EXPORT_SETTINGS'] = "VE9079"
        self.validation_error_code['remote_host'] = "VE9080"
        self.validation_error_code['protocol'] = "VE9081"
        self.validation_error_code['facility'] = "VE9082"
        self.validation_error_code['port'] = "VE9083"
        self.validation_error_code['clients'] = "VE9084"
        self.validation_error_code['severity'] = "VE9085"
        self.validation_error_code['ES_REMOTE_BACKUP'] = "VE9101"
        self.validation_error_code['service'] = "VE9102"
        self.validation_error_code['remote_host'] = "VE9103"
        self.validation_error_code['remote_path'] = "VE9104"

        self.validation_error_code['enabled'] = "VE9077"
        self.validation_error_code['DISABLE_HYPERTHREADING'] = "VE9078"

        self.validation_error_code['INSTALL_MODE'] = "VE9808"

        self.validation_error_code['INTEL_NIC_SUPPORT'] = "VE9090"
        self.validation_error_code['NIC_LEVEL_REDUNDANCY'] = "VE9100"
        self.validation_error_code['CISCO_VIC_INTEL_SRIOV'] = "VE10060"
        self.validation_error_code['INTEL_SRIOV_VFS'] = "VE10058"
        self.validation_error_code['sriov_tor_info'] = "VE10059"
        self.validation_error_code['INTEL_SRIOV_PHYS_PORTS'] = "VE10061"

        self.validation_error_code['PROVIDER_VLAN_RANGES'] = "VE10062"
        self.validation_error_code['provider'] = "VE10063"
        self.validation_error_code['vlan_id'] = "VE10064"
        self.validation_error_code['INTEL_FPGA_VFS'] = "VE10065"
        self.validation_error_code['CISCO_VIC_SUPPORT'] = "VE10100"
        self.validation_error_code['VIC_admin_fec_mode'] = "VE10101"
        self.validation_error_code['COMBINE_CPDP'] = "VE10102"
        self.validation_error_code['VIC_port_channel_enable'] = "VE10103"
        self.validation_error_code['VIC_link_training'] = "VE10109"
        self.validation_error_code['VIC_admin_speed'] = "VE10110"

        self.validation_error_code['INTEL_N3000_FIRMWARE'] = "VE10104"
        self.validation_error_code['user_image_bitstream_id'] = "VE10105"
        self.validation_error_code['user_image_file'] = "VE10106"
        self.validation_error_code['xl710_config_file'] = "VE10107"
        self.validation_error_code['xl710_image_file'] = "VE10108"

        self.validation_error_code['LDAP'] = "VE9091"
        self.validation_error_code['user'] = "VE9092"
        self.validation_error_code['suffix'] = "VE9093"
        self.validation_error_code['user_tree_dn'] = "VE9094"
        self.validation_error_code['user_objectclass'] = "VE9095"
        self.validation_error_code['group_tree_dn'] = "VE9096"
        self.validation_error_code['group_objectclass'] = "VE9097"
        self.validation_error_code['domain'] = "VE9098"
        self.validation_error_code['url'] = "VE9099"
        self.validation_error_code['group_name_attribute'] = "VE10060"
        self.validation_error_code['user_mail_attribute'] = "VE10061"
        self.validation_error_code['user_id_attribute'] = "VE10062"
        self.validation_error_code['user_name_attribute'] = "VE10063"
        self.validation_error_code['user_filter'] = "VE10064"
        self.validation_error_code['group_filter'] = "VE11111"
        self.validation_error_code['group_member_attribute'] = "VE11112"
        self.validation_error_code['group_id_attribute'] = "VE11113"
        self.validation_error_code['group_members_are_ids'] = "VE11114"

        self.validation_error_code['TESTING_TESTBED_NAME'] = "VE10050"
        self.validation_error_code['TESTING_MGMT_NODE_CIMC_IP'] = "VE10051"
        self.validation_error_code['TESTING_MGMT_CIMC_USERNAME'] = "VE10052"
        self.validation_error_code['TESTING_MGMT_CIMC_PASSWORD'] = "VE10053"
        self.validation_error_code['TESTING_MGMT_NODE_API_IP'] = "VE10054"
        self.validation_error_code['TESTING_MGMT_NODE_API_GW'] = "VE10055"
        self.validation_error_code['TESTING_MGMT_NODE_MGMT_IP'] = "VE10056"
        self.validation_error_code['TESTING_MGMT_NODE_TIMEZONE'] = "VE10057"
        self.validation_error_code['TESTING_MGMT_NODE_IPV6_ENABLE'] = "VE10065"
        self.validation_error_code['TESTING_MGMT_NODE_API_IPV6'] = "VE10066"
        self.validation_error_code['TESTING_MGMT_NODE_API_GW_IPV6'] = "VE10067"
        self.validation_error_code['TESTING_MGMT_NODE_MGMT_IPV6'] = "VE10068"
        self.validation_error_code['TESTING_HPE_COMPUTE'] = "VE10069"
        self.validation_error_code['TESTING_MGMT_NODE_USE_TEAMING'] = "VE10099"

        #self.validation_error_code['SWIFTSTACK'] = "VE8015"
        self.validation_error_code['cluster_api_endpoint'] = "VE8016"
        self.validation_error_code['reseller_prefix'] = "VE8017"
        self.validation_error_code['admin_user'] = "VE8018"
        self.validation_error_code['admin_password'] = "VE8019"
        self.validation_error_code['admin_tenant'] = "VE8020"

        self.validation_error_code['PODTYPE'] = "VE8021"
        self.validation_error_code['NFVBENCH'] = "VE8022"
        self.validation_error_code['vtep_vlans'] = "VE8023"
        self.validation_error_code['nic_slot'] = "VE11104"
        self.validation_error_code['nic_ports'] = "VE8024"

        self.validation_error_code['autobackup'] = "VE8025"
        self.validation_error_code['CEPH_NAT'] = "VE8026"

        self.validation_error_code['admin_username'] = "VE11000"
        self.validation_error_code['subnet'] = "VE11001"
        self.validation_error_code['segments'] = "VE11002"
        self.validation_error_code['gateway'] = "VE11003"
        self.validation_error_code['vlan_id'] = "VE11004"
        self.validation_error_code['networker'] = "VE11005"
        self.validation_error_code['object_storage'] = "VE11006"
        self.validation_error_code['NET_NAME'] = "VE11007"
        self.validation_error_code['CONFIGURE_TORS'] = "VE11008"
        self.validation_error_code['SWITCHDETAILS'] = "VE11009"
        self.validation_error_code['po'] = "VE11010"
        self.validation_error_code['username'] = "VE11011"

        self.validation_error_code['vts'] = "VE11012"
        self.validation_error_code['VTS_TIMEZONE'] = "VE11013"
        self.validation_error_code['VTS_VTC_MGMT_IPS'] = "VE11014"
        self.validation_error_code['VTS_XRVR_MGMT_IPS'] = "VE11015"
        self.validation_error_code['VTS_VTC_API_VIP'] = "VE11016"
        self.validation_error_code['VTS_XRNC_MGMT_IPS'] = "VE11017"
        self.validation_error_code['VTS_VTC_API_IPS'] = "VE11018"
        self.validation_error_code['VTS_XRNC_TENANT_IPS'] = "VE11019"
        self.validation_error_code['VTS_XRVR_TENANT_IPS'] = "VE11020"
        self.validation_error_code['VTS_VNI_RANGE'] = "VE11021"
        self.validation_error_code['VTS_DAY0'] = "VE11022"

        self.validation_error_code['apic_hosts'] = "VE11023"
        self.validation_error_code['apic_username'] = "VE11024"
        self.validation_error_code['apic_password'] = "VE11025"
        self.validation_error_code['apic_system_id'] = "VE11026"
        self.validation_error_code['apic_resource_prefix'] = "VE11027"
        self.validation_error_code['apic_tep_address_pool'] = "VE11036"
        self.validation_error_code['multicast_address_pool'] = "VE11037"
        self.validation_error_code['apic_pod_id'] = "VE11038"
        self.validation_error_code['apic_installer_tenant'] = "VE11039"
        self.validation_error_code['apic_installer_vrf'] = "VE11040"
        self.validation_error_code['api_l3out_network'] = "VE11045"

        self.validation_error_code['APICINFO'] = "VE11033"
        self.validation_error_code['node_id'] = "VE11034"
        self.validation_error_code['aciinfra'] = "VE11035"

        self.validation_error_code['ipv6_subnet'] = "VE11041"
        self.validation_error_code['ipv6_gateway'] = "VE11042"
        self.validation_error_code['ipv6_pool'] = "VE11043"
        self.validation_error_code['management_ipv6'] = "VE11044"
        self.validation_error_code['external_lb_vip_ipv6_address'] = "VE11045"
        self.validation_error_code['internal_lb_vip_ipv6_address'] = "VE11046"

        self.validation_error_code['vim_admins'] = "VE11050"
        self.validation_error_code['vim_admin_username'] = "VE11051"
        self.validation_error_code['vim_admin_password_hash'] = "VE11052"
        self.validation_error_code['mgmt_l3out_network'] = "VE11053"
        self.validation_error_code['mgmt_l3out_vrf'] = "VE11054"
        self.validation_error_code['CCP_DEPLOYMENT'] = "VE11055"

        self.validation_error_code['TOR_TYPE'] = "VE11056"
        self.validation_error_code['MULTI_SEGMENT_ROUTING_INFO'] = "VE11057"
        self.validation_error_code['isis_area_tag'] = "VE11058"
        self.validation_error_code['bgp_as_num'] = "VE11059"
        self.validation_error_code['loopback_name'] = "VE11060"
        self.validation_error_code['isis_loopback_addr'] = "VE11061"
        self.validation_error_code['isis_net_entity_title'] = "VE11062"
        self.validation_error_code['vpc_peer_port_address'] = "VE11063"
        self.validation_error_code['api_bundle_id'] = "VE11064"
        self.validation_error_code['api_bridge_domain'] = "VE11066"
        self.validation_error_code['isis_prefix_sid'] = "VE11067"
        self.validation_error_code['ext_bridge_domain'] = "VE11068"
        self.validation_error_code['ENABLE_ESC_PRIV'] = "VE11069"
        self.validation_error_code['SOLIDFIRE'] = "VE11070"
        self.validation_error_code['cluster_mvip'] = "VE11071"
        self.validation_error_code['cluster_svip'] = "VE11072"
        self.validation_error_code['VTS_XRNC_TENANT_IPS'] = "VE11073"
        self.validation_error_code['IRONIC'] = "VE11074"
        self.validation_error_code['IRONIC_SWITCHDETAILS'] = "VE11075"
        self.validation_error_code['CVIM_MON'] = "VE9105"
        self.validation_error_code['polling_intervals'] = "VE9106"
        self.validation_error_code['low_frequency'] = "VE91061"
        self.validation_error_code['medium_frequency'] = "VE91062"
        self.validation_error_code['high_frequency'] = "VE91063"
        self.validation_error_code['KEYSTONE_MINIMUM_PASSWORD_AGE'] = "VE9107"
        self.validation_error_code['KEYSTONE_UNIQUE_LAST_PASSWORD_COUNT'] = "VE9108"
        self.validation_error_code['KEYSTONE_LOCKOUT_DURATION'] = "VE9109"
        self.validation_error_code['KEYSTONE_LOCKOUT_FAILURE_ATTEMPTS'] = "VE9110"
        self.validation_error_code['CLOUD_DEPLOY'] = "VE11076"
        self.validation_error_code['vim_admin_public_key'] = "VE11079"
        self.validation_error_code['ENABLE_READONLY_ROLE'] = "VE11108"

        self.validation_error_code['server_hostname'] = "VE11089"
        self.validation_error_code['server_port'] = "VE11090"
        self.validation_error_code['transport_type'] = "VE11091"
        self.validation_error_code['vserver'] = "VE11080"
        self.validation_error_code['cinder_nfs_server'] = "VE11081"
        self.validation_error_code['cinder_nfs_path'] = "VE11082"
        self.validation_error_code['glance_nfs_server'] = "VE11083"
        self.validation_error_code['glance_nfs_path'] = "VE11084"
        self.validation_error_code['nova_nfs_server'] = "VE11085"
        self.validation_error_code['nova_nfs_path'] = "VE11086"
        self.validation_error_code['netapp_cert_file'] = "VE11087"
        self.validation_error_code['NETAPP'] = "VE11088"
        self.validation_error_code['permit_root_login'] = "VE9111"
        self.validation_error_code['ssh_banner'] = "VE9112"

        self.validation_error_code['CEPH_PG_INFO'] = "VE9112"
        self.validation_error_code['cinder_percentage_data'] = "VE9113"
        self.validation_error_code['glance_percentage_data'] = "VE9114"
        self.validation_error_code['nova_percentage_data'] = "VE9115"
        self.validation_error_code['gnocchi_percentage_data'] = "VE9116"

        self.validation_error_code['SRIOV_CARD_TYPE'] = "VE11092"
        self.validation_error_code['BGP_ASN'] = "VE11093"
        self.validation_error_code['grpc_username'] = "VE11094"
        self.validation_error_code['grpc_password'] = "VE11095"
        self.validation_error_code['grpc_timeout'] = "VE11096"
        self.validation_error_code['grpc_port'] = "VE11097"
        self.validation_error_code['NETWORK_OPTIONS'] = "VE11098"
        self.validation_error_code['bgp_peers'] = "VE11099"
        self.validation_error_code['vxlan'] = "VE11100"
        self.validation_error_code['l3vpn'] = "VE11101"
        self.validation_error_code['sr'] = "VE11102"
        self.validation_error_code['bgp_speaker_addresses'] = "VE11103"
        self.validation_error_code['NR_RESERVED_VSWITCH_PCORES'] = "VE11104"
        self.validation_error_code['COLLECTOR_TORCONNECTIONS'] = "VE11105"
        self.validation_error_code['splitter_opt_4_10'] = "VE11106"
        self.validation_error_code['bgp_router_id'] = "VE11107"

        self.validation_error_code['SNMP'] = "VE11200"
        self.validation_error_code['managers'] = "VE1121"
        self.validation_error_code['address'] = "VE1122"
        self.validation_error_code['community'] = "VE1123"
        self.validation_error_code['TESTING_MGMT_NODE_MODE'] = "VE1124"
        self.validation_error_code['ENABLE_TTY_LOGGING'] = "VE1125"
        self.validation_error_code['MGMTNODE_EXTAPI_REACH'] = "VE1126"
        self.validation_error_code['version'] = "VE1127"
        self.validation_error_code['name'] = "VE1128"
        self.validation_error_code['users'] = "VE1129"
        self.validation_error_code['authentication'] = "VE1130"
        self.validation_error_code['privacy_key'] = "VE1131"
        self.validation_error_code['encryption'] = "VE1132"
        self.validation_error_code['auth_key'] = "VE1133"
        self.validation_error_code['osd_disk_type'] = "VE1134"
        self.validation_error_code['engine_id'] = "VE1135"
        self.validation_error_code['MANAGED'] = "VE1136"
        self.validation_error_code['VTS_NET'] = "VE1137"
        self.validation_error_code['ENABLED'] = "VE1138"
        self.validation_error_code['physnet_name'] = "VE1139"
        self.validation_error_code['vxlan-tenant'] = "VE1140"
        self.validation_error_code['vxlan-ecn'] = "VE1141"
        self.validation_error_code['SERVER_MON'] = "VE1142"
        self.validation_error_code['host_info'] = "VE1143"
        self.validation_error_code['rsyslog_severity'] = "VE1143"
        self.validation_error_code['VTS_SITE_UUID'] = "VE1144"
        self.validation_error_code['CEPH_OSD_RESERVED_PCORES'] = "VE11145"
        self.validation_error_code['MASTER_2'] = "VE11146"
        self.validation_error_code['COLLECTOR_2'] = "VE11147"
        self.validation_error_code['TESTING_MGMT_NODE_PUBLIC_API_IP'] = "VE11148"
        self.validation_error_code['TESTING_MGMT_NODE_PUBLIC_API_GW'] = "VE11149"
        self.validation_error_code['VSWITCH_WORKER_PROFILE'] = "VE11110"
        self.validation_error_code['head_end_replication'] = "VE11111"
        self.validation_error_code['cephcontrol'] = "VE11112"
        self.validation_error_code['cephosd'] = "VE11113"

        self.validation_error_code['ldap_uri'] = "VE11114"
        self.validation_error_code['ldap_search_base'] = "VE11142"
        self.validation_error_code['ldap_schema'] = "VE11115"
        self.validation_error_code['ldap_user_object_class'] = "VE11116"
        self.validation_error_code['ldap_user_uid_number'] = "VE11117"
        self.validation_error_code['ldap_user_gid_number'] = "VE11118"
        self.validation_error_code['ldap_group_member'] = "VE11119"
        self.validation_error_code['vim_ldap_admins'] = "VE11120"
        self.validation_error_code['vtep_ips'] = "VE11121"
        self.validation_error_code['ESI_PREFIX'] = "VE11113"
        self.validation_error_code['rt_prefix'] = "VE11114"
        self.validation_error_code['rt_suffix'] = "VE11115"
        self.validation_error_code['vnis'] = "VE11116"
        self.validation_error_code['vteps'] = "VE11117"
        self.validation_error_code['VAULT'] = "VE1145"
        self.validation_error_code['NFVIMON_ADMIN'] = "VE11118"
        self.validation_error_code['IPV6_MODE'] = "VE11119"
        self.validation_error_code['bgp_mgmt_addresses'] = "VE11120"
        self.validation_error_code['chase_referrals'] = "VE11120"
        self.validation_error_code['ui_access'] = "VE11121"
        self.validation_error_code['ENABLE_VM_EMULATOR_PIN'] = "VE11122"
        self.validation_error_code['VM_EMULATOR_PCORES_PER_SOCKET'] = "VE11123"
        self.validation_error_code['CCP_CONTROL'] = "VE11124"
        self.validation_error_code['CCP_TENANT'] = "VE11125"
        self.validation_error_code['CCP_INSTALLER_IMAGE'] = "VE11126"
        self.validation_error_code['CCP_TENANT_IMAGE'] = "VE11127"
        self.validation_error_code['UI_PASSWORD'] = "VE11128"
        self.validation_error_code['private_key'] = "VE11129"
        self.validation_error_code['public_key'] = "VE11130"
        self.validation_error_code['project_name'] = "VE11131"
        self.validation_error_code['workers'] = "VE11132"
        self.validation_error_code['NOVA_OPT_FOR_LOW_LATENCY'] = "VE11133"
        self.validation_error_code['ENABLE_RT_KERNEL'] = "VE11180"
        self.validation_error_code['trusted_vf'] = "VE11134"
        self.validation_error_code['BASE_MACADDRESS'] = "VE11135"
        self.validation_error_code['switch_type'] = "VE11136"
        self.validation_error_code['inspector_pool'] = "VE11137"
        self.validation_error_code['switch_ports'] = "VE11138"
        self.validation_error_code['FABRIC_INTERFACE_POLICIES'] = "VE11139"
        self.validation_error_code['vim_apic_networks'] = "VE11140"
        self.validation_error_code['global'] = "VE11141"
        self.validation_error_code['scope'] = "VE11142"
        self.validation_error_code['gateway_cidr'] = "VE11143"
        self.validation_error_code['subnets'] = "VE11144"
        self.validation_error_code['l3-out'] = "VE11145"
        self.validation_error_code['description'] = "VE11146"
        self.validation_error_code['app_profile'] = "VE11147"
        self.validation_error_code['phys_dom'] = "VE11148"
        self.validation_error_code['mode'] = "VE11159"
        self.validation_error_code['vlan_ids'] = "VE11150"
        self.validation_error_code['vlan_pools'] = "VE11151"
        self.validation_error_code['vrf'] = "VE11152"
        self.validation_error_code['EPG_NAME'] = "VE11153"
        self.validation_error_code['BD_NAME'] = "VE11154"
        self.validation_error_code['PROVIDER'] = "VE11155"
        self.validation_error_code['TENANT'] = "VE11156"
        self.validation_error_code['PROVIDER'] = "VE11157"
        self.validation_error_code['INTEL_RDT'] = "VE11158"
        self.validation_error_code['ENABLE_CAT'] = "VE11159"
        self.validation_error_code['RESERVED_L3_CACHELINES_PER_SOCKET'] = "VE11160"
        self.validation_error_code['central'] = "VE11161"
        self.validation_error_code['api_l2out_network'] = "VE11162"
        self.validation_error_code['mgmt_l2out_network'] = "VE11163"
        self.validation_error_code['prov_l2out_network'] = "VE11164"
        self.validation_error_code['ext_l2out_network'] = "VE11165"
        self.validation_error_code['MULTICAST_SNOOPING'] = "VE11166"
        self.validation_error_code['INVENTORY_DISCOVERY'] = "VE11167"
        self.validation_error_code['INTEL_VC_SRIOV_VFS'] = "VE11168"
        self.validation_error_code['sriov_access_vlan'] = "VE11169"
        self.validation_error_code['prov_l3out_network'] = "VE11171"
        self.validation_error_code['prov_l3out_vrf'] = "VE11172"
        self.validation_error_code['EPG_POLICIES'] = "VE11173"
        self.validation_error_code['management'] = "VE11174"
        self.validation_error_code['apic_installer_vlan_pool'] = "VE11175"
        self.validation_error_code['apic_installer_physdom'] = "VE11176"
        self.validation_error_code['apic_installer_app_profile'] = "VE11177"
        self.validation_error_code['apic_installer_aep'] = "VE11178"
        self.validation_error_code['config_type'] = "VE11179"
        self.validation_error_code['HA'] = "VE11180"

        self.validation_error_code['PUBLIC_NETWORK_UUID'] = "VE11200"
        self.validation_error_code['KUBE_VERSION'] = "VE11201"
        self.validation_error_code['NETWORK_TYPE'] = "VE11202"
        self.validation_error_code['NETWORK_TYPE'] = "VE11203"
        self.validation_error_code['ccp_subnet_cidr'] = "VE11204"
        self.validation_error_code['installer_subnet_cidr'] = "VE11205"
        self.validation_error_code['installer_subnet_gw'] = "VE11206"
        self.validation_error_code['POD_CIDR'] = "VE11207"
        self.validation_error_code['subnet_cidr'] = "VE11208"
        self.validation_error_code['sriov0'] = "VE11209"
        self.validation_error_code['sriov1'] = "VE11210"
        self.validation_error_code['sriov2'] = "VE11211"
        self.validation_error_code['sriov3'] = "VE11212"
        self.validation_error_code['limit_ip_learning'] = "VE11213"
        self.validation_error_code['arp_flood'] = "VE11214"
        self.validation_error_code['unicast_routing'] = "VE11215"
        self.validation_error_code['nd_policy'] = "VE11216"
        self.validation_error_code['l2_unknown_unicast'] = "VE11217"
        self.validation_error_code['configure_fabric'] = "VE11218"
        self.validation_error_code['storage_ip'] = "VE11219"
        self.validation_error_code['preferred_group_member'] = "VE11220"
        self.validation_error_code['rx_tx_queue_size'] = "VE11221"
        self.validation_error_code['ctrl'] = "VE11222"
        self.validation_error_code['ldap_default_bind_dn'] = "VE11223"
        self.validation_error_code['ldap_default_authtok'] = "VE11224"
        self.validation_error_code['ldap_default_authtok_type'] = "VE11225"
        self.validation_error_code['ldap_group_search_base'] = "VE11226"
        self.validation_error_code['ldap_user_search_base'] = "VE11227"
        self.validation_error_code['access_provider'] = "VE11228"
        self.validation_error_code['simple_allow_groups'] = "VE11229"
        self.validation_error_code['ldap_id_use_start_tls'] = "VE11230"
        self.validation_error_code['ldap_tls_reqcert'] = "VE11231"
        self.validation_error_code['chpass_provider'] = "VE11232"
        self.validation_error_code['cluster_ip'] = "VE11233"
        self.validation_error_code['CCP_FLAVOR'] = "VE11234"
        self.validation_error_code['seccomp_sandbox'] = "VE11235"

        self.validation_error_code['ldap'] = "VE11181"
        self.validation_error_code['group_mappings'] = "VE11182"
        self.validation_error_code['domain_mappings'] = "VE11183"
        self.validation_error_code['attributes'] = "VE11184"
        self.validation_error_code['bind_dn'] = "VE11185"
        self.validation_error_code['bind_password'] = "VE11186"
        self.validation_error_code['search_base_dns'] = "VE11187"
        self.validation_error_code['search_filter'] = "VE11188"
        self.validation_error_code['email'] = "VE11189"
        self.validation_error_code['member_of'] = "VE11190"
        self.validation_error_code['surname'] = "VE11191"
        self.validation_error_code['group_dn'] = "VE11192"
        self.validation_error_code['org_role'] = "VE11193"
        self.validation_error_code['group_search_filter'] = "VE11194"
        self.validation_error_code['group_search_base_dns'] = "VE21195"
        self.validation_error_code['group_search_filter_user_attribute'] = "VE21196"
        self.validation_error_code['start_tls'] = "VE21197"
        self.validation_error_code['use_ssl'] = "VE21198"
        self.validation_error_code['client_cert'] = "VE21181"
        self.validation_error_code['root_ca_cert'] = "VE21182"
        self.validation_error_code['client_key'] = "VE21183"
        self.validation_error_code['group_attribute_is_dn'] = "VE21184"
        self.validation_error_code['group_attribute'] = "VE21185"

        self.validation_error_code['log_rotation_frequency'] = "VE11195"
        self.validation_error_code['log_rotation_size'] = "VE11196"
        self.validation_error_code['log_rotation_del_older'] = "VE11197"

        self.validation_error_code['internal_loadbalancer_ip'] = "VE12001"
        self.validation_error_code['external_loadbalancer_ip'] = "VE12002"
        self.validation_error_code['VIRTUAL_ROUTER_ID'] = "VE12003"
        self.validation_error_code['cvimmon_domain_suffix'] = "VE12005"
        self.validation_error_code['grafana_admin_user'] = "VE12006"
        self.validation_error_code['grafana_admin_password'] = "VE12007"
        self.validation_error_code['cvim-mon-stacks'] = "VE12008"
        self.validation_error_code['name'] = "VE12009"
        self.validation_error_code['metrics_retention'] = "VE12010"
        self.validation_error_code['metrics_volume_size_gb'] = "VE12011"
        self.validation_error_code['scrape_interval'] = "VE12012"
        self.validation_error_code['regions'] = "VE12013"
        self.validation_error_code['metros'] = "VE12014"
        self.validation_error_code['pods'] = "VE120415"
        self.validation_error_code['cert'] = "VE12016"
        self.validation_error_code['ip'] = "VE12017"
        self.validation_error_code['cvim_mon_proxy_password'] = "VE12018"
        self.validation_error_code['username'] = "VE12019"
        self.validation_error_code['CVIMMONHA_CLUSTER_MONITOR'] = "VE12020"
        self.validation_error_code['cvimmon_domain_ca_cert'] = "VE12021"
        self.validation_error_code['max_node_count'] = "VE12022"

        self.validation_error_code['ARGUS_BAREMETAL'] = "VE12051"
        self.validation_error_code['DHCP_MODE'] = "VE12052"
        self.validation_error_code['ISO'] = "VE12053"
        self.validation_error_code['cvim-mon'] = "VE12054"
        self.validation_error_code['sds'] = "VE12055"
        self.validation_error_code['SITE_CONFIG'] = "VE12056"
        self.validation_error_code['name'] = "VE12057"
        self.validation_error_code['info'] = "VE12058"
        self.validation_error_code['servers'] = "VE12059"
        self.validation_error_code['oob_ip'] = "VE12060"
        self.validation_error_code['ip_address'] = "VE12061"
        self.validation_error_code['common_info'] = "VE12062"
        self.validation_error_code['oob_username'] = "VE12063"
        self.validation_error_code['oob_password'] = "VE12064"
        self.validation_error_code['time_zone'] = "VE12065"
        self.validation_error_code['flavor'] = "VE12066"
        self.validation_error_code['password_hash'] = "VE12067"
        self.validation_error_code['clusters'] = "VE12068"
        self.validation_error_code['boot_network'] = "VE12069"

        self.validation_error_code['enable_ecmp'] = "VE12101"
        self.validation_error_code['sr-mpls'] = "VE120102"
        self.validation_error_code['sr-mpls-tenant'] = "VE12103"
        self.validation_error_code['prefix_sid_index'] = "VE12104"
        self.validation_error_code['ecmp_private_pool'] = "VE12105"
        self.validation_error_code['base'] = "VE12106"
        self.validation_error_code['sr_global_block'] = "VE12107"
        self.validation_error_code['SRIOV_SLOT_ORDER'] = "VE11223"
        self.validation_error_code['IPA_INFO'] = "VE11225"
        self.validation_error_code['ipa_servers'] = "VE11226"
        self.validation_error_code['enroller_user'] = "VE11227"
        self.validation_error_code['enroller_password'] = "VE11228"
        self.validation_error_code['ipa_domain_name'] = "VE11229"
        self.validation_error_code['ipaddresses'] = "VE11230"
        self.validation_error_code['provision'] = "VE11231"
        self.validation_error_code['NOVA_CPU_ALLOCATION_RATIO'] = "VE11232"
        self.validation_error_code['NOVA_RAM_ALLOCATION_RATIO'] = "VE11233"

        self.validation_error_code['cloud_settings'] = "VE13000"
        self.validation_error_code['keystone_lockout_failure_attempts'] = "VE13001"
        self.validation_error_code['keystone_lockout_duration'] = "VE13002"
        self.validation_error_code['keystone_unique_last_password_count'] = "VE13003"
        self.validation_error_code['keystone_minimum_password_age'] = "VE13004"
        self.validation_error_code['horizon_session_timeout'] = "VE13008"
        self.validation_error_code['NUM_GPU_CARDS'] = "VE13009"
        self.validation_error_code['external_servers'] = "VE13010"
        self.validation_error_code['NR_RESERVED_HOST_PCORES'] = "VE13011"
        self.validation_error_code['api_1_vlan_id'] = "VE13012"

        self.validation_error_code['FLAVORS'] = "VE13012"
        self.validation_error_code['KEYPAIRS'] = "VE13013"
        self.validation_error_code['IMAGES'] = "VE13014"
        self.validation_error_code['SERVERS_IN_VMS'] = "VE13015"
        self.validation_error_code['NETWORKS'] = "VE13016"
        self.validation_error_code['IGNORE_GW_PING'] = "VE13017"

        self.validation_error_code['disk'] = "VE13018"
        self.validation_error_code['disk_vol_size'] = "VE13019"
        self.validation_error_code['node_type'] = "VE13020"
        self.validation_error_code['nics'] = "VE13021"

        self.validation_error_code['ZADARA'] = "VE13022"
        self.validation_error_code['access_key'] = "VE13023"
        self.validation_error_code['vpsa_host'] = "VE13024"
        self.validation_error_code['vpsa_poolname'] = "VE13024"
        self.validation_error_code['glance_nfs_name'] = "VE13025"
        self.validation_error_code['glance_nfs_path'] = "VE13026"

        self.validation_error_code['PASSWORD_MANAGEMENT'] = "VE13027"
        self.validation_error_code['strength_check'] = "VE13028"
        self.validation_error_code['maximum_days'] = "VE13029"
        self.validation_error_code['warning_age'] = "VE13030"
        self.validation_error_code['history_check'] = "VE13031"

        self.validation_error_code['SSH_ACCESS_OPTIONS'] = "VE13032"
        self.validation_error_code['session_idle_timeout'] = "VE13033"
        self.validation_error_code['enforce_single_session'] = "VE13034"
        self.validation_error_code['session_login_attempt'] = "VE13035"
        self.validation_error_code['session_lockout_duration'] = "VE13036"
        self.validation_error_code['session_root_lockout_duration'] = "VE13037"
        self.validation_error_code['lockout_inactive_users'] = "VE13038"

        self.validation_error_code['remote_management'] = "VE13039"
        self.validation_error_code['CENTRAL_MGMT_AGGREGATE'] = "VE13040"
        self.validation_error_code['MGMTNODE_EXTAPI_FQDN'] = "VE13041"

        self.validation_error_code['file_location'] = "VE13043"
        self.validation_error_code['CENTRAL_MGMT_USER_INFO'] = "VE13044"

        self.validation_error_code['l3_fabric_vni'] = "VE13045"
        self.validation_error_code['l3_fabric_loopback'] = "VE13046"
        self.validation_error_code['L3_PROVIDER_VNI_RANGES'] = "VE13047"

        self.validation_error_code['VGPU_TYPE'] = "VE13048"

        self.validation_error_code['TIMEZONE'] = "VE13049"
        self.validation_error_code['timezone'] = "VE13050"
        self.validation_error_code['fixed_ips'] = "VE13051"

        self.validation_error_code['CVIMADMIN_PASSWORD_HASH'] = "VE13052"
        self.validation_error_code['cvimadmin_password_hash'] = "VE13053"

        self.validation_error_code['OCTAVIA_DEPLOYMENT'] = "VE13054"
        self.validation_error_code['name'] = "VE13055"
        self.validation_error_code['image_path'] = "VE13056"
        self.validation_error_code['image_tag'] = "VE13057"
        self.validation_error_code['amp_boot_network_list'] = "VE13058"
        self.validation_error_code['amp_flavor'] = "VE13059"
        self.validation_error_code['amp_secgroup_list'] = "VE13060"
        self.validation_error_code['amp_ssh_key'] = "VE13061"
        self.validation_error_code['amphora_image'] = "VE13062"
        self.validation_error_code['ca_certificate'] = "VE13063"
        self.validation_error_code['ca_private_key'] = "VE13064"
        self.validation_error_code['ca_private_key_passphrase'] = "VE13065"
        self.validation_error_code['client_cert'] = "VE13066"
        self.validation_error_code['dns_server'] = "VE13067"
        self.validation_error_code['nw_gateway'] = "VE13068"
        self.validation_error_code['nw_ip_end'] = "VE13069"
        self.validation_error_code['nw_ip_start'] = "VE13070"
        self.validation_error_code['nw_name'] = "VE13071"
        self.validation_error_code['segmentation_id'] = "VE13072"
        self.validation_error_code['ipv6_mode'] = "VE13073"

        self.validation_error_code['vpn_labels'] = "VE13074"
        self.validation_error_code['transport_labels'] = "VE13075"
        self.validation_error_code['transport_labels_prefixes'] = "VE13076"
        self.validation_error_code['vtep_gateway_networks'] = "VE13077"

        self.validation_error_code['VOLUME_BACKEND'] = "VE13078"
        self.validation_error_code['VPP_ENABLE_AVF'] = "VE13079"

        self.validation_error_code['MANAGE_LACP'] = "VE13080"

        self.log.debug("Validator Initialized")

    def set_oper_stage(self, msg):
        '''
        Set Operation stage status.
        '''
        Validator.OPER_STAGE = msg
        Validator.STAGE_COUNT += 1

    def get_homedir(self):
        '''
        Get the current username
        '''
        homedir = os.path.expanduser("~")
        return homedir

    def set_validation_results(self, name, status=STATUS_PASS, err=None, \
                               error_code_list=[]):
        '''
        Set the validations, for the rules.
        '''
        result = {}
        result['name'] = name
        result['err'] = err
        result['error_code_list'] = error_code_list
        if status is STATUS_PASS:
            status = "\033[92mPASS\033[0m"
        else:
            status = "\033[91mFAIL\033[0m"
        result['status'] = status
        self.validation_results.append(result)

    def display_validation_results(self, check_type):
        '''
        Print the validation results
        '''
        ptable = prettytable.PrettyTable(["Rule", "Status", "Error"])
        ptable.align["Rule"] = "l"
        ptable.align["Error"] = "l"

        if re.match(r'static', check_type):
            check_type = "Input File"
        else:
            check_type = check_type.upper()

        for rule in self.validation_results:
            err_str = None
            if rule['err']:
                err_str = textwrap.fill(rule['err'].strip(), width=40)

            name_str = textwrap.fill(rule['name'].strip(), width=40)

            ptable.add_row([name_str, rule['status'], err_str])

        print "\n"
        self.log.info("\n")
        print " %s Validations!" % (check_type)
        self.log.info("**** %s Validations! ****", check_type)
        print ptable
        self.log.info(ptable)
        self.log.info("**** Done Dumping %s Validations! ****", check_type)

    def generate_sw_validation_array(self):
        '''Generates the array for sw validation'''
        val_results = {}
        ucase_results = {}

        """ Iterating over  consolidated dictionary to construct
        the sub dictionaries to form the nested JSON format """

        for rule in self.validation_results:
            ucase_results['reason'] = 'None'
            ucase_results['ve_error_code'] = []
            if rule['err']:
                if re.search(r'WARNING', rule['err']):
                    ucase_results['status'] = "Pass"
                else:
                    ucase_results['status'] = "Fail"
                tmp_err = re.sub(' +', ' ', rule['err'])
                ucase_results['reason'] = tmp_err
                ucase_results['ve_error_code'] = rule['error_code_list']
            else:
                ucase_results['status'] = "Pass"
            key = rule['name']
            val_results[key] = ucase_results
            ucase_results = {}

        overall_sw_result = self.check_validation_results()
        ucase_results['reason'] = 'None'
        if re.match(r'PASS', overall_sw_result['status']):
            ucase_results['status'] = STATUS_PASS
        else:
            ucase_results['status'] = STATUS_FAIL
        val_results['Overall_SW_Result'] = ucase_results
        return val_results

    def get_validation_report_in_array(self, *statuses):
        "Display final validation report in array format"
        statuses_list = list(statuses)

        sw_val_results = self.generate_sw_validation_array()
        statuses_list.append({'Software Validation': sw_val_results})

        overall_dict = {}
        for status in statuses_list:
            if status:
                overall_dict.update(status)

        return overall_dict

    def check_validation_results(self):
        '''
        Checks the validation info and returns overall Pass/Fail
        '''

        result = {}
        result['status'] = STATUS_PASS

        for rule in self.validation_results:
            if re.search(r'FAIL', rule['status']):
                result['status'] = STATUS_FAIL
        return result

    def is_ip_valid(self, ip_addr):
        '''checks if ip address is valid'''

        try:
            parts = ip_addr.split('.')
            return len(parts) == 4 and all(0 <= int(part) < 256 for part in parts)
        except ValueError:
            return False  # one of the 'parts' not convertible to integer
        except (AttributeError, TypeError):
            return False  # `ip` isn't even a string

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
            if common.is_valid_ipv6_address(input_str):
                found_v6 = 1

        if found_v4 or found_v6:
            return True

        return False

    def is_input_in_ascii(self, rhs_value):
        '''checks if input is in ASCII'''
        try:
            str(rhs_value).decode('ascii')
            return 1
        except UnicodeDecodeError:
            return 0
        except ValueError:
            return 0

    def is_dns_valid(self, dns_name):
        '''Checks if DNS is valid '''

        if not self.is_ipv4v6_valid(dns_name) and \
                common.is_valid_hostname(dns_name):
            try:
                _ = socket.getaddrinfo(dns_name, None)
                return 1
            except socket.gaierror, err:
                self.log.info("cannot resolve hostname: %s err:%s",
                              dns_name, err)
                return 0

        if common.is_valid_ipv6_address(dns_name):
            try:
                ipv6_addr_det = \
                    socket.getaddrinfo(dns_name, None, 0, socket.SOCK_STREAM)[0][4]
                _ = ipv6_addr_det[0]
            except socket.gaierror, err:
                self.log.info("cannot resolve hostname: %s err:%s",
                              dns_name, err)
                return 0
            return common.is_valid_ipv6_address(dns_name)

        else:
            try:
                ip_addr = socket.gethostbyname(dns_name)
            except socket.gaierror, err:
                self.log.info("cannot resolve hostname: %s err:%s",
                              dns_name, err)
                return 0

            return self.is_ip_valid(ip_addr)

    def is_input_an_integer(self, my_info):
        '''Check if the input is an integer'''

        try:
            _ = int(my_info)
            return True
        except ValueError:
            return False

    def is_input_range_valid(self, my_info, lower_limit, upper_limit):
        ''' is input range valid '''

        if not self.is_input_an_integer(my_info):
            return False
        if upper_limit < my_info or lower_limit > my_info:
            return False
        else:
            return True

    def check_user_config_location(self):
        '''Make sure user configs are present'''
        result = {}

        self.log.debug("User config directory and file validation")
        ks_config = "Check User Config Location"

        if not os.path.exists(self.cfg_dir):
            result['status'] = STATUS_FAIL
            msg = "%s Directory does not exist." % (self.cfg_dir)
            cmsg = logger.stringc(msg, 'red')
            self.log.error(cmsg)
            print cmsg
            self.set_validation_results(ks_config, status=STATUS_FAIL, err=msg)
            return

        if not os.path.exists(self.setup_file) or \
                not os.path.exists(self.defaults_file):
            result['status'] = STATUS_FAIL
            msg = "Provide user input files %s, %s " % (self.setup_file, \
                                                        self.defaults_file)
            cmsg = logger.stringc(msg, 'red')
            self.log.error(cmsg)
            print cmsg
            self.set_validation_results(ks_config, status=STATUS_FAIL, err=msg)
            return

        self.log.debug("User Config location validation: Successful")
        self.set_validation_results(ks_config)
        return

    def check_user_custom_config_file(self, config_file_name, docker_name, pod_type, stack_name):
        '''
        Check/Validate config files (alertmanager, alerting rules, etc)
        The inputs are the Default name of the config file, and the docker
        which will perform the validation.
        '''

        # Check custom configuration
        check_name = "Check %s Custom Config File" % (config_file_name)
        if config_file_name == "alertmanager_custom_config.yml":
            if pod_type == 'CVIMMONHA':
                config_file_path = \
                    "/opt/cisco/cvimmon-metro/" + stack_name + "/alertmanager_custom_config.yaml"
            else:
                config_file_path = \
                    os.path.join("/var/lib/cvim_mon/", config_file_name)
        elif config_file_name == "alerting_custom_rules.yml":
            if pod_type == 'CVIMMONHA':
                config_file_path = \
                    "/opt/cisco/cvimmon-metro/" + stack_name + "/alerting_custom_rules.yaml"
            else:
                config_file_path = \
                    os.path.join("/var/lib/prometheus/", config_file_name)

        # Only Check file if exists
        # This is the way to check if there is a new custom config
        if not os.path.exists(config_file_path):
            return

        cmd_rm = "/usr/bin/rm " + config_file_path

        if pod_type != 'CVIMMONHA':
            cmd = "/usr/bin/docker ps"

            # Get the docker tag, and Fail if the container is not running
            try:
                output = subprocess.check_output(cmd.split())
            except subprocess.CalledProcessError as e:
                subprocess.check_output(cmd_rm.split())
                err = "Could not get list of docker containers"
                self.log.error(err)
                self.set_validation_results(check_name, status=STATUS_FAIL, err=err)
                return

            c_name = ''
            for line in output.splitlines():
                if docker_name in line:
                    c_name = line.split()[-1]
            if not c_name:
                subprocess.check_output(cmd_rm.split())
                err = "Could not get the %s number configured" % (docker_name)
                self.log.error(err)
                self.set_validation_results(check_name, status=STATUS_FAIL, err=err)
                return

            # Copy the file to the folder that is shared within the container
            if config_file_name == "alertmanager_custom_config.yml":
                shared_file_path = "/var/lib/cvim_mon/" + config_file_name
                dest_file_path = "/opt/cisco/alertmanager/custom_config.yml"
                cmd_check = "/usr/bin/docker exec -u root %s /bin/bash -c \
                            'amtool check-config  %s \
                            > /dev/null 2>/dev/null; exit $?'" % (c_name, \
                                                              shared_file_path)
                err_check = "Could not run the amtool inside %s " \
                            "container" % (docker_name)
            elif config_file_name == "alerting_custom_rules.yml":
                shared_file_path = "/prometheus/" + config_file_name
                dest_file_path = "/opt/cisco/cvim_mon/alerting_custom_rules.yml"
                cmd_check = "/usr/bin/docker exec -u root %s /bin/bash -c \
                        'python /usr/bin/check_promtool.py -v %s' | \
                        grep -cq success" % (c_name, shared_file_path)
                err_check = "Could not run the promtool inside %s " \
                    "container" % (docker_name)

        else:
            if config_file_name == "alertmanager_custom_config.yml":
                cmd_check = \
                    "/opt/cisco/amtool check-config %s" % (config_file_path)
                err_check = "Could not run amtool"
            elif config_file_name == "alerting_custom_rules.yml":
                cmd_check = \
                    "/opt/cisco/check_promtool.py -v %s" % (config_file_path)
                err_check = "Could not run promtool"

        # Perform validation of the custom configuration
        try:
            devnull = open(os.devnull, 'w')
            cmd_to_exec = cmd_check.split(" ")
            output = subprocess.call(\
                cmd_to_exec, shell=False, stdout=devnull, stderr=devnull)
        except subprocess.CalledProcessError as e:
            subprocess.check_output(cmd_rm.split())
            self.log.error(err_check)
            self.set_validation_results(check_name, status=STATUS_FAIL, err=err_check)
            return

        # Check if the file is valid or not
        if output != 0:
            subprocess.check_output(cmd_rm.split())
            if pod_type == 'CVIMMONHA':
                if config_file_name == "alertmanager_custom_config.yml":
                    msg = "Invalid custom alertmanager config\n" \
                          "Please validate using /opt/cisco/amtool check-config" \
                          "<input_alertmanager_custom_config>"
                elif config_file_name == "alerting_custom_rules.yml":
                    msg = "Invalid custom alerts file\n" \
                          "Please validate using /opt/cisco/check_promtool.py " \
                          "-v <input_custom_alerts>"
            else:
                msg = "Invalid %s custom config file " % (config_file_name)
            self.log.error(msg)
            self.set_validation_results(check_name, status=STATUS_FAIL, err=msg)
            return

        if pod_type != 'CVIMMONHA':
            with open(config_file_path, 'r') as f:
                file_content = f.read()
            with open(dest_file_path, 'w') as f:
                f.write(file_content)

        self.set_validation_results(check_name)

    def check_user_tls_certificate(self):
        '''
        Make sure that the private key and the certificate provided by
        the user are valid and match up
        '''

        if not os.path.exists(self.cfg_dir):
            return

        sec_name = "User TLS certificates check"
        crt_file = os.path.join(self.cfg_dir, "mercury.crt")
        key_file = os.path.join(self.cfg_dir, "mercury.key")
        if (not os.path.exists(crt_file)) and (not os.path.exists(key_file)):
            return

        self.log.debug("Check user certificate and private key files")
        if ((os.path.exists(crt_file) and not os.path.exists(key_file)) or
                (not os.path.exists(key_file) and os.path.exists(crt_file))):
            msg = "Both files needed: %s and %s" % (crt_file, key_file)
            self.log.error(msg)
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=msg)
            return

        # Verify the certificate
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        try:
            context.use_certificate_file(crt_file)
        except:
            msg = "Invalid User TLS Certificate"
            self.log.error(msg)
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=msg)
            return

        try:
            context.use_privatekey_file(key_file)
        except:
            msg = "Invalid User TLS Key"
            self.log.error(msg)
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=msg)
            return

        # Check that the private key and certificate match up
        try:
            context.check_privatekey()
        except SSL.Error:
            msg = "User TLS certificate and private key do not match"
            self.log.error(msg)
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=msg)
            return
        self.set_validation_results("User Provided Certificate Check")

    def check_cert_trust_chain(self):
        '''
        Verify X.509 Certificate Chain of Trust
        '''

        def parse_chain(chain):
            return [c.group() for c in _PEM_RE.finditer(chain)]

        if not os.path.exists(self.cfg_dir):
            return

        sec_name = "certificate trust chain check"
        crt_file = os.path.join(self.cfg_dir, "mercury.crt")
        ca_file = os.path.join(self.cfg_dir, "mercury-ca.crt")
        if ((not os.path.exists(crt_file)) and (not os.path.exists(ca_file))):
            return

        self.log.debug("Check certificate trust chain")
        if ((os.path.exists(crt_file) and not os.path.exists(ca_file)) or
                (not os.path.exists(ca_file) and os.path.exists(crt_file))):
            msg = "Both files needed: %s and %s" % (crt_file, ca_file)
            self.log.error(msg)
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=msg)
            return

        # load the TLS certificate in PEM format
        with open(crt_file, 'r') as f:
            try:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            except:
                err = "Failed to load certificate"
                self.log.error(err)
                self.set_validation_results(sec_name, status=STATUS_FAIL, err=err)
                return

        with open(ca_file, 'r') as f:
            ca_file_data = f.read()

        # load the CA certificate(s) in PEM format
        # creating a list to support multiple trusted CA certificates
        t_cacerts = []
        try:
            for cr in parse_chain(ca_file_data):
                t_cacerts.append(crypto.load_certificate(crypto.FILETYPE_PEM, cr))
        except:
            err = "Invalid TLS CA certificate"
            self.log.error(err)
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=err)
            return

        # raises X509StoreContextError If an error occurred
        # when validating a certificate in the context
        try:
            # Create an X.509 store
            store = crypto.X509Store()

            # Add all trusted certificate(s) to this store
            for t_cert in t_cacerts:
                store.add_cert(t_cert)

            # An X.509 store context
            store_ctx = crypto.X509StoreContext(store, cert)

            # Verify the certificate in a context
            store_ctx.verify_certificate()

        # certificate verification failed
        except Exception as e:
            err = "Failed(%s) to validate all trusted certificates" % e
            self.log.error(err)
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=err)
            return
        self.set_validation_results("User Certificate Chain of Trust")

    def check_server_list(self):
        '''
        Check the Userdata for server info.
        '''

        svr_list = self.ymlhelper.get_server_list(role='control')
        section_name = "Section ROLES:"

        err_code_list = []
        role_ve_code = self.validation_error_code['ROLES']
        control_ve_code = self.validation_error_code['control']
        control_segment = role_ve_code + ":" + control_ve_code

        err_code_list.append(control_segment)
        if svr_list is None:
            # No control nodes specified.
            self.log.error("No control nodes found in user input %s",
                           self.setup_file)
            self.set_validation_results("Control node check",
                                        status=STATUS_FAIL,
                                        err=section_name +
                                        "No control nodes found",
                                        error_code_list=err_code_list)
        else:
            self.set_validation_results("Control node check")

        err_code_list = []
        compute_ve_code = self.validation_error_code['compute']
        compute_segment = role_ve_code + ":" + compute_ve_code
        err_code_list.append(compute_segment)
        svr_list = self.ymlhelper.get_server_list(role="compute")
        if svr_list is None:
            # No computes specified.
            self.log.error("No compute nodes found in user input %s",
                           self.setup_file)
            self.set_validation_results("Compute node check",
                                        status=STATUS_FAIL,
                                        err=section_name +
                                        "No compute nodes found",
                                        error_code_list=err_code_list)
        else:
            self.set_validation_results("Compute node check")


    def remove_values_from_list(self, the_list, val):
        ''' removes all instances of a given entry from a list'''
        return [value for value in the_list if value != val]

    def dump_setup_data_contents(self):
        '''dump contents of setup_data in the log'''
        new_str = []
        new_str.append("\n*******************************************\n")
        new_str.append("** Beginning Output of setup_data.yaml file **\n")
        new_str.append("*******************************************\n")
        with open(self.setup_file) as f:
            data = f.readlines()

            for line in data:
                if not re.search(r'password', line, re.IGNORECASE):
                    new_str.append(line)

        new_str.append("*******************************************\n")
        new_str.append("** End of Output of setup_data.yaml file **\n")
        new_str.append("*******************************************\n")
        self.log.info("".join(new_str))

        return

    def report_nonunique_keys(self, filename):
        '''YAML duplicate key spotter for the setup data'''

        repeated_keys = []

        def root_ctxt():
            '''root context'''
            return ('keys:',)

        def join_ctxt(ctxt, ct):
            '''joins the recursion'''
            return ctxt + (ct,)

        def print_ctxt(ctxt):
            '''prints the output'''
            return ''.join([str(x) for x in ctxt])

        def process_modelnode(ctxt, node):
            '''Processes the modelnode'''
            if isinstance(node, ScalarNode):
                return node.value
            elif isinstance(node, SequenceNode):
                return process_listnodes(ctxt, node.value)
            elif isinstance(node, MappingNode):
                ks = process_mapnodes(ctxt, node.value)
                # This is a list k, v, k, v, ...
                # Should have unique k's
                u_ks = set(ks)
                for f in u_ks:
                    ks.remove(f)

                if ks:
                    for x in ks:
                        repeated_keys.append("%s{'%s'}" % (print_ctxt(ctxt),
                                                           str(x)))

        def process_listnodes(ctxt, nodes):
            '''Process the nddes locally'''
            vals = []
            for ct, node in zip(xrange(0, len(nodes)), nodes):
                vals.append(process_modelnode(join_ctxt(ctxt, '[%d]' % ct), node))
            return vals

        def process_mapnodes(ctxt, nodes):
            '''Processes each section in recursion'''
            ks = []
            for k, v in nodes:
                k = process_modelnode(join_ctxt(ctxt, ' - key name'), k)
                ks.append(k)
                v = process_modelnode(join_ctxt(ctxt, "{'%s'}" % str(k)), v)
            return ks

        with open(filename, 'r') as ff:
            model = yaml.compose(ff)

        process_modelnode(root_ctxt(), model)
        return repeated_keys

    def check_for_duplicate_info(self):
        '''Checks for duplicate keys within input file.
        This is a check to look for duplicate keys in maps in the
        input file where a user might have accidentially copied
        lines.  It works by using the YAML parser to create a parse
        tree for the file and spotting duplicate keys in maps.

        Maps are permitted to have duplicate keys per the YAML spec
        - so the parser will never throw an error on them itself -
        but this is not meaningful in our config files and the
        behaviour in such cases is undefined; plus it's typically
        a user cut and paste error.
        '''

        chk_config = "Check for duplicate keys"
        duplicate_list = self.report_nonunique_keys(self.setup_file)

        curr_err_list = []
        err_code_list = []
        expected_keys = self.validation_error_code.keys()

        search_pat = "keys:{'([A-Za-z0-9_-]+)'.*"
        if duplicate_list:
            key_count = 1
            for item in duplicate_list:
                try:
                    curr_key = re.search(search_pat, item).group(1)
                    if curr_key and \
                            curr_key in expected_keys and \
                            self.validation_error_code[curr_key] \
                            not in curr_err_list:
                        curr_err_list.append(self.validation_error_code[curr_key])
                except AttributeError:
                    pass

                if re.search(r'keys:', item):
                    rep_item = "key" + str(key_count)
                    new_item = re.sub('keys', rep_item, item)
                    duplicate_list[key_count - 1] = new_item
                    key_count += 1

        if curr_err_list:
            ve_str = '^'.join(curr_err_list)
            err_code_list.append(ve_str)

        if duplicate_list:
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err="Duplicate Info for: " + \
                                            ','.join(duplicate_list),
                                        error_code_list=err_code_list)

        else:
            self.set_validation_results(chk_config)

        return

    def check_for_duplicate_cimc_ip(self):
        """Checks for duplicate CIMC IPs v4 or v6
        This is a check for CIMC IPs that appear more than once.
        It reads the file linewise and checks cimc_info lines.
        """

        err_code_list = []
        err_code_list.append(self.validation_error_code['SERVERS'])

        chk_config = "Check Duplicate CIMC IP"
        cimc_ip_list = []
        # Get all non-management servers
        servers = self.ymlhelper.get_server_list()
        for server in servers:
            cimc_ip = self.ymlhelper.get_server_cimc_ip(server)

            if cimc_ip is not None:
                curr_ip = cimc_ip
                if common.is_valid_ipv6_address(cimc_ip):
                    curr_ip = ipaddr.IPv6Address(cimc_ip).exploded

            cimc_ip_list.append(curr_ip.lower())

        dup_cimc_ip_list = common.get_duplicate_entry_in_list(cimc_ip_list)
        if dup_cimc_ip_list:
            err_msg = "Duplicate CIMC IP(s) %s" % (', '.join(dup_cimc_ip_list))
            self.log.error(err_msg)

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_msg,
                                        error_code_list=err_code_list)

        else:
            self.set_validation_results(chk_config)

        return

    def check_thirdparty_bios_configuration_utility(self):
        '''check the existence of thirdparty BIOS configuration utility'''
        chk_status = False
        ami_util = self.cfgmgr.parsed_defaults.parsed_config.get(
            "ami_bios_utilities", False)

        if ami_util:
            zipfile = ami_util["zipfile"]

            # if softlink is not there
            if not os.path.isfile(zipfile):
                curr_install_dir = common.get_curr_installer_dir(send_info=1)

                if not re.match('ERROR:', curr_install_dir):
                    file_suffix = zipfile.split('root')[1]
                    zipfile_new = "%s%s" % (curr_install_dir, file_suffix)
                    zipfile = zipfile_new

            if os.path.isfile(zipfile):
                sha1 = hashlib.sha1()
                with open(zipfile, "r") as f:
                    chunk = 0
                    while chunk != b"":
                        chunk = f.read(4096)
                        sha1.update(chunk)
                if sha1.hexdigest() == ami_util["sha1sum"]:
                    chk_status = True
        chk_msg = "Check for thirdparty BIOS configuration utility"
        if chk_status:
            self.set_validation_results(chk_msg)
        else:
            self.set_validation_results(chk_msg, status=STATUS_FAIL, \
                err=("BIOS configuration utility not found or invalid, \
                place zip file here: %s" % zipfile))

    def check_controller_placement(self):
        ''' Check if unique Rack name is associated to controllers'''

        servers = self.ymlhelper.get_server_list(role='control')
        rack_id_list = []

        err_code_list = []
        server_ve_code = self.validation_error_code['SERVERS']
        err_code = server_ve_code
        err_code_list.append(err_code)

        duplicate_rack_id_list = []
        missing_rack_id = []
        invalid_value_format = []
        error_found = 0
        chk_config = "Rack Placement of Controller"
        for item in servers:
            rack_id = self.ymlhelper.get_server_rack_id(item)
            if rack_id is None:
                missing_rack_id.append(item)
            elif not self.is_input_in_ascii(rack_id):
                invalid_value_format.append(item)
            elif rack_id not in rack_id_list:
                rack_id_list.append(rack_id)
            else:
                duplicate_rack_id_list.append(rack_id)

        if missing_rack_id:
            error_found = 1
            self.log.error("Missing Rack Id for controller %s",
                           str(missing_rack_id))

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err="Missing Rack Id for Controller " +
                                        str(missing_rack_id),
                                        error_code_list=err_code_list)

        if invalid_value_format:
            error_found = 1
            self.log.error("Rack id are not in ASCII for: %s",
                           str(invalid_value_format))

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err="Rack ids are not in ASCII: " +
                                        str(invalid_value_format),
                                        error_code_list=err_code_list)

        if duplicate_rack_id_list:
            error_found = 1
            self.log.error("Multiple Controllers have the same Rack id %s",
                           str(duplicate_rack_id_list))

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err="Multiple Controllers have the \
                                        same Rackid: " +
                                        str(duplicate_rack_id_list),
                                        error_code_list=err_code_list)

        if not error_found:
            self.set_validation_results(chk_config)
        return

    def check_input_format(self, curr_input, lhs_str):
        '''checks if enterits of input list is in ASCII'''

        invalid_value_format = []
        valid_ascii_flag = 1

        for entry in curr_input:
            if not self.is_input_in_ascii(entry):
                invalid_value_format.append(lhs_str)
                valid_ascii_flag = 0

        return valid_ascii_flag, invalid_value_format

    def get_her_vtep_info(self, vxlan_option):
        '''Check if her is enabled'''

        vtep_list = []
        if not self.cfgmgr.is_network_option_enabled(vxlan_option):
            return vtep_list

        try:
            ntwrk_opt_info = \
                self.ymlhelper.get_data_from_userinput_file( \
                    ['NETWORK_OPTIONS'])
            if not ntwrk_opt_info:
                return []
            for key in ntwrk_opt_info.iterkeys():
                if key == 'vxlan':
                    vxlan_info = ntwrk_opt_info.get(key)
                    if vxlan_info is None:
                        return []
                    for key1 in vxlan_info.iterkeys():
                        if key1 == vxlan_option:
                            vxlan_option_detail = vxlan_info.get(key1)
                            for key2 in vxlan_option_detail.iterkeys():
                                if key2 == 'head_end_replication':
                                    her_info = vxlan_option_detail.get(key2)
                                    for vtep_ips in her_info.iterkeys():
                                        vtep_list.append(vtep_ips)

        except AttributeError:
            return []

        return vtep_list

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

    def check_network_input(self):
        '''
        Check if content to network section is valid or not
        '''

        err_code_list = []
        err_code_list.append(self.validation_error_code['NETWORKING'])
        curr_mech_driver = self.ymlhelper.check_section_exists('MECHANISM_DRIVERS')

        if self.ymlhelper.get_pod_type() == 'ceph':
            base_segment_list = ['management', 'provision', 'cluster']
            segment_list = ['management', 'provision', 'cluster']
            network_skip_list = []
        else:
            base_segment_list = ['management', 'provision', 'api', 'tenant',
                                 'storage', 'provider', 'external']
            segment_list = ['management', 'provision', 'api', 'tenant', 'external']
            network_skip_list = ['provider', 'external', 'api']

        if curr_mech_driver == 'aci':
            base_segment_list.append('aciinfra')
            network_skip_list.append('aciinfra')
            segment_list.append('aciinfra')

        if self.cfgmgr.is_network_option_enabled('vxlan-tenant'):
            base_segment_list.append('vxlan-tenant')
            network_skip_list.append('vxlan-tenant')
            segment_list.append('vxlan-tenant')

        if self.check_for_optional_enabled('ironic'):
            base_segment_list.append('ironic')
            network_skip_list.append('ironic')
            segment_list.append('ironic')

        if self.cfgmgr.is_network_option_enabled('vxlan-ecn'):
            base_segment_list.append('vxlan-ecn')
            network_skip_list.append('vxlan-ecn')
            segment_list.append('vxlan-ecn')

        if self.cfgmgr.is_network_option_enabled('sr-mpls-tenant'):
            base_segment_list.append('sr-mpls-tenant')
            network_skip_list.append('sr-mpls-tenant')
            segment_list.append('sr-mpls-tenant')

        # Get the management network type
        curr_mgmt_network = self.ymlhelper.get_management_network_type()

        invalid_segments = []
        unsupported_segments = []
        invalid_value_format = []

        overlapping_network = []
        segment_network_list = []
        segment_with_dup_network = []
        network_list = []

        overlapping_ip_pool = []
        segment_ip_pool_list = []
        segment_with_dup_ip_pool = []
        ip_pool_list = []

        gw_list = []
        segment_gw_list = []
        overlapping_gw_info = []
        segment_with_dup_gw = []

        vlan_list = []
        segment_vlan_list = []
        overlapping_vlan = []
        segment_with_dup_vlan = []
        error = 0
        mgmt_check_status = 0
        overlap_with_reserved_network = []

        testbed_type = self.get_testbed_type()
        if re.match(r'UCSM', testbed_type):
            base_segment_list.append('cimc')
            segment_list.append('cimc')

        ceph_server_list = []
        if self.ymlhelper.get_pod_type() != 'ceph':
            ceph_server_list = self.ymlhelper.get_server_list(role="block_storage")
        if ceph_server_list:
            base_segment_list.append('storage')
            segment_list.append('storage')

        segments = self.ymlhelper.nw_get_server_vnic_segment()
        if re.match(r'Missing_Segment', str(segments)):
            chk_config = "Check Network provided"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err="Sytax Error in Segment Info",
                                        error_code_list=err_code_list)
            return

        networking_block = self.ymlhelper.nw_get_networking_blocks()
        if not networking_block:
            chk_config = "Check Network provided"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err="Missing Networking blocks",
                                        error_code_list=err_code_list)
            return

        for item in networking_block:

            curr_segment = item['segments']
            str_curr_segment = ''.join(curr_segment)

            if re.match(r'StandAlone', testbed_type) and \
                    "cimc" in curr_segment:
                unsupported_segments.append(curr_segment)
            elif re.match(r'UCSM', testbed_type) and \
                    "cimc" in curr_segment and len(curr_segment) > 1:
                unsupported_segments.append(curr_segment)

            # check for overlapping subnet, except for CIMC
            try:
                subnet_ascii_flag = 1
                curr_network = item['subnet']
                lhs_str = str_curr_segment + ":subnet"
                subnet_ascii_flag, invalid_ascii_format = \
                    self.check_input_format(curr_network, lhs_str)
                if not subnet_ascii_flag:
                    invalid_value_format.append(invalid_ascii_format)

                if subnet_ascii_flag:
                    if curr_segment:
                        for vmtp_entry in CVIM_RESERVED_NETWORK:
                            n1 = ipaddr.IPNetwork(vmtp_entry)
                            n2 = ipaddr.IPNetwork(curr_network)
                            if n1.overlaps(n2):
                                tmp = str_curr_segment + ":" + str(curr_network)
                                overlap_with_reserved_network.append(tmp)

                    if len(curr_segment) == 1 and "cimc" in curr_segment:
                        continue
                    else:
                        if curr_network not in network_list:
                            network_list.append(curr_network)
                            segment_network_list.append(curr_segment)
                        else:
                            net_index = network_list.index(curr_network)
                            overlapping_seg_info = segment_network_list[net_index]
                            overlapping_network.append(curr_network)
                            segment_with_dup_network.append(curr_segment)
                            segment_with_dup_network.append(overlapping_seg_info)
            except KeyError:
                curr_network = "skip"

            # check for overlapping vlanid, except for CIMC, provider, external
            try:
                vlan_ascii_flag = 1
                curr_vlan = item['vlan_id']
                lhs_str = str_curr_segment + ":vlan_id"
                vlan_ascii_flag, invalid_ascii_format = \
                    self.check_input_format(str(curr_vlan), lhs_str)
                if not vlan_ascii_flag:
                    invalid_value_format.append(invalid_ascii_format)

                if vlan_ascii_flag:
                    if len(curr_segment) == 1 and "cimc" in curr_segment:
                        continue
                    else:
                        if curr_vlan in vlan_list:
                            net_index = vlan_list.index(curr_vlan)

                        if self.check_ucsm_plugin_presence() and \
                                curr_mech_driver is not None and \
                                re.match(r'openvswitch|vpp|aci', curr_mech_driver) \
                                and str(curr_vlan) == 'None' and \
                                (('provider' in curr_segment) \
                                 or ('tenant' in curr_segment)):
                            continue
                        elif re.match(r'StandAlone', testbed_type) and \
                                curr_mech_driver is not None and \
                                re.match(r'openvswitch|vpp|aci', curr_mech_driver) \
                                and re.match(r'None', str(curr_vlan)) and \
                                (('provider' in curr_segment) \
                                 or ('tenant' in curr_segment)):
                            continue
                        elif curr_vlan not in vlan_list:
                            vlan_list.append(curr_vlan)
                            segment_vlan_list.append(curr_segment)
                        else:
                            net_index = vlan_list.index(curr_vlan)
                            overlapping_seg_info = segment_vlan_list[net_index]
                            overlapping_vlan.append(curr_vlan)
                            segment_with_dup_vlan.append(curr_segment)
                            segment_with_dup_vlan.append(overlapping_seg_info)
            except KeyError:
                curr_vlan = "skip"

            #check for overlapping gateway, except for CIMC
            try:
                gw_ascii_flag = 1
                curr_gw = item['gateway']
                lhs_str = str_curr_segment + ":Gateway"
                gw_ascii_flag, invalid_ascii_format = \
                    self.check_input_format(curr_gw, lhs_str)
                if not gw_ascii_flag:
                    invalid_value_format.append(invalid_ascii_format)

                if len(curr_segment) == 1 and "cimc" in curr_segment:
                    continue
                else:
                    if curr_gw not in gw_list:
                        gw_list.append(curr_gw)
                        segment_gw_list.append(curr_segment)
                    else:
                        net_index = gw_list.index(curr_gw)
                        overlapping_seg_info = segment_gw_list[net_index]
                        overlapping_gw_info.append(curr_gw)
                        segment_with_dup_gw.append(curr_segment)
                        segment_with_dup_gw.append(overlapping_seg_info)
            except KeyError:
                curr_gw = "skip"

            #check for overlapping IP Pool
            try:
                pool_ascii_flag = 1
                curr_ip_pool = item['pool']
                lhs_str = str_curr_segment + ":pool"
                pool_ascii_flag, invalid_ascii_format = \
                    self.check_input_format(curr_ip_pool, lhs_str)
                if not pool_ascii_flag:
                    invalid_value_format.append(invalid_ascii_format)

                curr_ip_pool = item['pool']
                if curr_ip_pool not in ip_pool_list:
                    ip_pool_list.append(curr_ip_pool)
                    segment_ip_pool_list.append(curr_segment)
                else:
                    index_info = ip_pool_list.index(curr_ip_pool)
                    overlapping_segment_info = segment_ip_pool_list[index_info]
                    overlapping_ip_pool.append(curr_ip_pool)
                    segment_with_dup_ip_pool.append(curr_segment)
                    segment_with_dup_ip_pool.append(overlapping_segment_info)
            except KeyError:
                curr_ip_pool = "skip"

        # check if nw, gw or pool is not in ASCII, return
        if invalid_value_format:
            error = 1
            chk_config = "Check Network provided for " + str(lhs_str)
            err_segment = "Invalid ASCII Format:" + str(invalid_ascii_format)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)
            return

        segments = self.ymlhelper.nw_get_server_vnic_segment()
        network_validate_flag = 1
        for segment in segments:
            curr_segment = segments[segment]['segments']
            str_curr_segment = str(curr_segment)

            try:
                curr_network = segments[segment]['subnet']

                # Check if mgmt network is not same as br_mgmt network
                if not mgmt_check_status and 'management' in curr_segment:
                    mgmt_check_status = 1
                    br_mgmt_ip = common.get_ip_info('br_mgmt')
                    addrs = netifaces.ifaddresses("br_mgmt")
                    br_mgmt_mask = addrs[netifaces.AF_INET][0]['netmask']

                    br_mgmt_cidr = str(br_mgmt_ip) + "/" + str(br_mgmt_mask)
                    br_mgmt_network = str(netaddr.IPNetwork(br_mgmt_cidr).cidr)
                    chk_config = "Mgmt Node/Setup Data Network Consistency Check"
                    if str(curr_network) != br_mgmt_network and \
                            curr_mgmt_network == 'layer2':
                        err_str = "br_mgmt network:%s on management node does not " \
                            "match the management segment info:%s in " \
                            "setup_data.yaml" % (br_mgmt_network, curr_network)
                        error = 1
                        self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                    err=err_str,
                                                    error_code_list=err_code_list)

                    elif str(curr_network) == br_mgmt_network and \
                            curr_mgmt_network == 'layer3':
                        err_str = "br_mgmt network:%s on management node matches " \
                            "the management segment info:%s in layer3 environment" \
                            "setup_data.yaml" % (br_mgmt_network, curr_network)
                        error = 1
                        self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                    err=err_str,
                                                    error_code_list=err_code_list)

            except KeyError:
                curr_network = "skip"

            # check for invalid segments
            listt4 = [0 if i in base_segment_list else i for i in curr_segment]
            listt4 = self.remove_values_from_list(listt4, 0)
            if listt4:
                invalid_segments.append(listt4)

            # check for missing segments
            listt3 = [0 if i in curr_segment else i for i in segment_list]
            listt3 = self.remove_values_from_list(listt3, 0)
            segment_list = listt3

            if curr_segment[0] not in network_skip_list and \
                    not self.validate_network(curr_network):
                network_validate_flag = 0
                chk_config = "Check Network provided for " + str_curr_segment
                self.set_validation_results(chk_config, status=STATUS_FAIL,
                                            err="Incorrect Network " +
                                            str(curr_network) + " provided",
                                            error_code_list=err_code_list)
            else:
                self.set_validation_results("Check Network provided for " +
                                            str_curr_segment)

            try:
                def_route_value = segments[segment]['defroute']
                def_route_exists = 1
            except KeyError:
                def_route_exists = 0
            if def_route_exists and def_route_value is not True:
                chk_config = "Check Default Route " + str_curr_segment
                self.set_validation_results(chk_config, status=STATUS_FAIL,
                                            err="Default Route \"" +
                                            str(def_route_value) +
                                            "\" is incorrect",
                                            error_code_list=err_code_list)
            else:
                self.set_validation_results("Check Default Route " +
                                            str_curr_segment)

            try:
                curr_vlan = segments[segment]['vlan_id']
            except KeyError:
                curr_vlan = "UnDefined"

                # do not validate VLAN, gateway, or IP
            mech_driver_ve_code = self.validation_error_code['MECHANISM_DRIVERS']
            mech_driver_err_list = []
            mech_driver_err_list.append(mech_driver_ve_code)
            network_type = self.get_network_type()

            if curr_mech_driver is None:
                if curr_segment[0] == "tenant":

                    chk_config = "Check VLAN provided for " \
                                 + str_curr_segment
                    self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                err="Can't Validate if VLAN " +
                                                str(curr_vlan) + " is correct, \
                                                as MECHANISM_DRIVERS is not \
                                                defined",
                                                error_code_list=mech_driver_err_list)

            elif curr_mech_driver is not None and \
                    re.match(r'openvswitch|vpp|aci', curr_mech_driver) and \
                    curr_segment[0] == "tenant":
                if re.match(r'UCSM', testbed_type):

                    tenant_vlan_info = self.ymlhelper.check_section_exists(
                        'TENANT_VLAN_RANGES')

                    if self.check_ucsm_plugin_presence() and \
                            str(curr_vlan) == "None":
                        pass
                    elif self.check_ucsm_plugin_presence() and \
                            str(curr_vlan) != "None":
                        chk_config = "Check Segment Info "
                        self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                    err="Incorrect VLAN " +
                                                    str(curr_vlan) + " provided, \
                                                    should be None, when \
                                                    UCSM plugin is enabled",
                                                    error_code_list=err_code_list)

                    elif str(curr_vlan) == "None":
                        chk_config = "Check VLAN provided for " + \
                            str_curr_segment
                        self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                    err="Incorrect VLAN " +
                                                    str(curr_vlan) + " provided, \
                                                    shouldn't be None, needs to \
                                                    match TENANT_VLAN_RANGES",
                                                    error_code_list=err_code_list)
                    elif str(tenant_vlan_info) != str(curr_vlan):
                        chk_config = "Check VLAN provided for " + \
                            str_curr_segment
                        self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                    err="Incorrect VLAN " +
                                                    str(curr_vlan) + " provided; \
                                                    Needs to match \
                                                    TENANT_VLAN_RANGES " + \
                                                    str(tenant_vlan_info),
                                                    error_code_list=err_code_list)
                # NOTE:
                #    Not checking VLAN is setup for tenant network segment
                #    for carrying VXLAN traffic (Linuxbridge, VTS scenarios)
                else:
                    if curr_mech_driver is not None and \
                            re.match(r'openvswitch', curr_mech_driver) \
                            and re.match(r'VXLAN', network_type):
                        if str(curr_vlan) == "None":
                            chk_config = "Check VLAN provided for %s" \
                                % (str_curr_segment)
                            err_str = "Incorrect VLAN %s provided; " \
                                "should be an integer between 1 and 4094" \
                                % (curr_vlan)
                            self.set_validation_results(chk_config, status=STATUS_FAIL, \
                                err=err_str, error_code_list=err_code_list)

                    elif str(curr_vlan) != "None":
                        chk_config = "Check VLAN provided for " + \
                            str_curr_segment
                        self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                    err="Incorrect VLAN " +
                                                    str(curr_vlan) + " provided, \
                                                    should be None",
                                                    error_code_list=err_code_list)
            elif curr_segment[0] != "provider" and curr_segment[0] != "aciinfra":
                if not self.validate_vlan_id(curr_vlan):
                    chk_config = "Check VLAN provided for " + str_curr_segment
                    self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                err="Incorrect VLAN " +
                                                str(curr_vlan) + " provided",
                                                error_code_list=err_code_list)
                else:
                    self.set_validation_results("Check VLAN provided for " +
                                                str_curr_segment)
                if "external" not in curr_segment:
                    try:
                        curr_gw = segments[segment]['gateway']
                    except KeyError:
                        curr_gw = False
                else:
                    curr_gw = True

                if not curr_gw:
                    chk_config = "Check Gateway provided for " + str_curr_segment
                    self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                err="Incorrect GATEWAY " +
                                                str(curr_gw) + " provided",
                                                error_code_list=err_code_list)

                if "external" not in curr_segment:
                    if network_validate_flag and \
                        not self.validate_ip_for_a_given_network(curr_gw, \
                                                                 curr_network):
                        chk_config = "Check IP provided for " + str_curr_segment
                        self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                    err="Incorrect Gateway IP " +
                                                    str(curr_gw) + " provided",
                                                    error_code_list=err_code_list)
                    else:
                        self.set_validation_results("Check Gateway provided for " +
                                                    str_curr_segment)

        chk_config = "Check Segment Info"

        if config_parser.PlatformDiscovery(
                self.setup_file).contain_thirdparties_platform():
            if curr_mech_driver is not None and \
                    not re.match(r'openvswitch', curr_mech_driver):
                chk_config = "Mechanism Driver and 3rd Party " \
                    "Compute Compatibility Check"
                error = 1
                err_segment = "Mechanism Driver %s not supported for " \
                    "deployments with 3rd Party Computes; supported " \
                    "mechanism driver is openvswitch" \
                    % (curr_mech_driver)
                self.set_validation_results(chk_config, status=STATUS_FAIL,
                                            err=err_segment,
                                            error_code_list=err_code_list)

        if segment_list or invalid_segments:
            err_segment = ""
            if segment_list:
                err_segment = "Missing Info:" + str(segment_list) + "; "
            if invalid_segments:
                err_segment += "Invalid Segment:" + str(invalid_segments)

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment + " not provided",
                                        error_code_list=err_code_list)
            error = 1

        if overlap_with_reserved_network:
            chk_config_1 = "Reserved Network Check"
            err_segment = "WARNING: Network(s) %s overlap with one of the " \
                          "reserved network:%s; Please use a " \
                          "non-overlapping network" \
                          % (','.join(overlap_with_reserved_network),
                             ','.join(CVIM_RESERVED_NETWORK))
            self.set_validation_results(chk_config_1, status=STATUS_PASS,
                                        err=err_segment)

        if overlapping_network:
            error = 1
            err_segment = "Overlapping Network:" + str(overlapping_network) + \
                " found for segments: " + \
                str(segment_with_dup_network)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if overlapping_vlan:
            error = 1
            err_segment = "Overlapping VLAN ID:" + str(overlapping_vlan) + \
                " found for segments: " + \
                str(segment_with_dup_vlan)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if overlapping_gw_info:
            error = 1
            err_segment = "Overlapping Gateway:" + str(overlapping_gw_info) + \
                " found for segments: " + \
                str(segment_with_dup_gw)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if overlapping_ip_pool:
            error = 1
            err_segment = "Overlapping IP Pool:" + str(overlapping_ip_pool) + \
                " found for segments:  " + \
                str(segment_with_dup_ip_pool)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if unsupported_segments:
            error = 1
            err_segment = "Unsupported Segment:" + str(unsupported_segments) + \
                " for testbed type " + testbed_type
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if not error:
            self.set_validation_results(chk_config)

        return

    def check_zadara_glance_nfs_name(self):
        """Check Glance NFS Name"""

        section_name = "Check Zadara Glance NFS Name"
        err_code_list = []
        err_code_list.append(self.validation_error_code['ZADARA'])
        is_zadara_present = self.ymlhelper.check_section_exists('ZADARA')

        if is_zadara_present is None:
            return STATUS_PASS

        glance_nfsname = ['ZADARA', 'glance_nfs_name']
        glance_nfsname_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(glance_nfsname)

        access_key = ['ZADARA', 'access_key']
        access_key_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(access_key)

        vpsa_host = ['ZADARA', 'vpsa_host']
        vpsa_host_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(vpsa_host)

        if vpsa_host_info is None:
            err_str = "vpsa_host info is not defined in ZADARA section"
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return STATUS_FAIL

        if glance_nfsname_info is None:
            err_str = "ERROR: glance_nfsname_info info is not " \
                "defined in ZADARA section"
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return STATUS_FAIL

        if access_key_info is None:
            err_str = "ERROR: access_key_info info is not defined in ZADARA section"
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return STATUS_FAIL

        url = "https://%s/api/volumes/%s.json" \
            % (vpsa_host_info, glance_nfsname_info)
        access_key = "X-Access-Key:%s" % access_key_info

        content_info = "\"Content-Type: application/json\""

        complete_cmd = ['/usr/bin/curl', '-v', '-X', 'GET', '-H',
                        content_info, '-H', access_key, '%(url)s'
                        % {'url': url}]

        status, msg = common.check_zadara_end_point(section_name, complete_cmd)
        if status == STATUS_FAIL:
            self.log.error(msg)
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err=msg,
                                        error_code_list=err_code_list)
        else:
            self.log.info(msg)
            self.set_validation_results(section_name)

        return status

    def check_zadara_vpsa_poolname(self):
        """Check VPSA Poolname"""

        section_name = "Check Zadara VPSA Pool Name"
        err_code_list = []
        err_code_list.append(self.validation_error_code['ZADARA'])
        is_zadara_present = self.ymlhelper.check_section_exists('ZADARA')

        if is_zadara_present is None:
            return STATUS_PASS

        vpsa_poolname = ['ZADARA', 'vpsa_poolname']
        vpsa_poolname_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(vpsa_poolname)

        access_key = ['ZADARA', 'access_key']
        access_key_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(access_key)

        vpsa_host = ['ZADARA', 'vpsa_host']
        vpsa_host_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(vpsa_host)

        if vpsa_host_info is None:
            err_str = "vpsa_host info is not defined in ZADARA section"
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return STATUS_FAIL

        if vpsa_poolname_info is None:
            err_str = "ERROR: vpsa_poolname info is not defined in ZADARA section"
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return STATUS_FAIL

        if access_key_info is None:
            err_str = "ERROR: access_key_info info is not defined in ZADARA section"
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return STATUS_FAIL

        url = "https://%s/api/pools/%s.json" % (vpsa_host_info, vpsa_poolname_info)
        access_key = "X-Access-Key:%s" % access_key_info
        content_info = "\"Content-Type: application/json\""

        complete_cmd = ['/usr/bin/curl', '-v', '-X', 'GET', '-H',
                        content_info, '-H', access_key, '%(url)s'
                        % {'url': url}]

        status, msg = common.check_zadara_end_point(section_name, complete_cmd)
        if status == STATUS_FAIL:
            self.log.error(msg)
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err=msg,
                                        error_code_list=err_code_list)
        else:
            self.log.info(msg)
            self.set_validation_results(section_name)

        return status

    def check_zadara_vpsa_endpoint(self):
        """Check VPSA endpoint"""

        section_name = "Check Zadara VPSA End Point"
        err_code_list = []
        err_code_list.append(self.validation_error_code['ZADARA'])
        is_zadara_present = self.ymlhelper.check_section_exists('ZADARA')

        if is_zadara_present is None:
            return

        vpsa_host = ['ZADARA', 'vpsa_host']
        vpsa_host_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(vpsa_host)

        access_key = ['ZADARA', 'access_key']
        access_key_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(access_key)

        if vpsa_host_info is None:
            err_str = "vpsa_host info is not defined in ZADARA section"
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        if access_key_info is None:
            err_str = "access_key_info info is not defined in ZADARA section"
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        access_key = "X-Access-Key:%s" % access_key_info
        url = "https://%s/api/vcontrollers.json" % vpsa_host_info
        content_info = "\"Content-Type: application/json\""

        complete_cmd = ['/usr/bin/curl', '-v', '-X', 'GET', '-H',
                        content_info, '-H', access_key, '%(url)s'
                        % {'url': url}]

        status, msg = common.check_zadara_end_point(section_name, complete_cmd)
        if status == STATUS_FAIL:
            self.log.error(msg)
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err=msg,
                                        error_code_list=err_code_list)
        else:
            self.log.info(msg)
            self.set_validation_results(section_name)

        return status

    def check_zadara_vpsa_nslookup_validity(self):
        """Check Zadara validity"""

        section_name = "Check Zadara VPSA nslookup"
        err_code_list = []
        err_code_list.append(self.validation_error_code['ZADARA'])
        is_zadara_present = self.ymlhelper.check_section_exists('ZADARA')

        if is_zadara_present is None:
            return

        vpsa_host = ['ZADARA', 'vpsa_host']
        vpsa_host_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(vpsa_host)

        if vpsa_host_info is None:
            err_str = "vpsa_host info is not defined in ZADARA section"
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        show_command = ['/usr/bin/nslookup', vpsa_host_info]
        show_v6_command = ['/usr/bin/nslookup', '-q=AAAA', vpsa_host_info]
        error_found = 0

        err_det = ""
        try:
            output = subprocess.check_output(show_command)
        except subprocess.CalledProcessError as e:
            err_det = e.output
            error_found = 1

        if error_found:
            err_str = "nslookup failed for %s;\n Error Details: %s" \
                % (vpsa_host_info, err_det)
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        # nslookup via V6
        try:
            output_v6 = subprocess.check_output(show_v6_command)
        except subprocess.CalledProcessError as e:
            err_det = e.output_v6
            error_found = 1

        if error_found:
            err_str = "nslookup failed for %s;\n Error Details: %s" \
                % (vpsa_host_info, err_det)
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        vpsa_host_v4_address = "UNKNOWN"
        vpsa_host_v6_address = "UNKNOWN"
        vpsa_host_address = "UNKNOWN"

        found_vpsa_name = 0
        for item in output.splitlines():
            if re.search(vpsa_host_info, item) and re.search(r'Name:', item):
                found_vpsa_name = 1
            if found_vpsa_name and re.search(r'Address:', item):
                vpsa_host_v4_address = item.split(":")[1].strip()
                vpsa_host_address = vpsa_host_v4_address
                break

        # Check for v6 nfs look up
        if vpsa_host_v4_address == "UNKNOWN":
            for item in output_v6.splitlines():
                if re.search(vpsa_host_info, item) \
                        and re.search(r'AAAA address', item):
                    vpsa_host_v6_address = \
                        item.split("AAAA address")[1].strip()
                    vpsa_host_address = vpsa_host_v6_address
                    break

        if vpsa_host_v4_address == "UNKNOWN" and \
                vpsa_host_v6_address == "UNKNOWN":
            err_str = "Couldnt resolve IP address for " \
                "vpsa_host:%s via nslookup via v4/v6" % vpsa_host_info
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL, err=err_str,
                                        error_code_list=err_code_list)
            return

        if vpsa_host_v4_address != "UNKNOWN" and \
                not self.is_ipv4v6_valid(vpsa_host_v4_address):
            err_str = "Address %s for vpsa_host:%s is " \
                "Invalid" % (vpsa_host_v4_address, vpsa_host_info)
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL, err=err_str,
                                        error_code_list=err_code_list)
            return

        if vpsa_host_v6_address != "UNKNOWN" and \
                not self.is_ipv4v6_valid(vpsa_host_v6_address):
            err_str = "Address %s for vpsa_host:%s is " \
                "Invalid" % (vpsa_host_v6_address, vpsa_host_info)
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL, err=err_str,
                                        error_code_list=err_code_list)
            return

        subnet_family = "ipv6_subnet" if ipaddr.IPAddress(\
            vpsa_host_address).version == 6 else "subnet"
        mgmt_network_info = self.ymlhelper.nw_get_specific_vnic_info(\
            'management', subnet_family)

        pool_family = "ipv6_pool" if ipaddr.IPAddress( \
            vpsa_host_address).version == 6 else "pool"
        mgmt_pool_info = self.ymlhelper.nw_get_specific_vnic_info(\
            'management', pool_family)

        if mgmt_pool_info is not None and \
                (self.check_ip_exists_in_a_pool(\
                    vpsa_host_address, mgmt_pool_info) == 1):
            error_found = 1
            err_str = "Address %s for vpsa_host:%s " \
                "belongs in management network IP pool %s" \
                % (vpsa_host_address, vpsa_host_info, mgmt_pool_info)

        if error_found:
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err=err_str, \
                                        error_code_list=err_code_list)
            return

        self.set_validation_results(section_name)

    def is_servermon_enabled(self):
        '''Check if SERVER_MON is enabled'''

        key = ["SERVER_MON", "enabled"]
        ret_value = self.ymlhelper.get_data_from_userinput_file(key)
        if ret_value is not None and ret_value is True:
            return 1

        return 0

    def check_server_mon_validity(self):
        '''Check if only Cisco C-series servers is listed'''

        section_name = "Check SERVER_MON Validity"
        unsupported_servermon_list = []
        err_code_list = []
        err_code_list.append(self.validation_error_code['SERVER_MON'])

        if not self.is_servermon_enabled():
            return

        CIMC_SEVERITIES = ['emergency', 'alert', 'critical', 'error',
                           'warning', 'notice', 'informational', 'debug']
        key = ["SERVER_MON", "rsyslog_severity"]
        server_mon_sev = self.ymlhelper.get_data_from_userinput_file(key)
        if server_mon_sev and server_mon_sev not in CIMC_SEVERITIES:
            err_segment = ("SERVER_MON:rsyslog_severity only allowed values: %s" %
                           (str(CIMC_SEVERITIES)))
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)
            return

        CIMC_SEVERITIES = ['emergency', 'alert', 'critical', 'error',
                           'warning', 'notice', 'informational', 'debug']
        key = ["SERVER_MON", "rsyslog_severity"]
        server_mon_sev = self.ymlhelper.get_data_from_userinput_file(key)
        if server_mon_sev and server_mon_sev not in CIMC_SEVERITIES:
            err_segment = ("SERVER_MON:rsyslog_severity only allowed values: %s" %
                           (str(CIMC_SEVERITIES)))
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)
            return

        key = ["SERVER_MON", "host_info"]
        server_mon_list = self.ymlhelper.get_data_from_userinput_file(key)
        if server_mon_list is None:
            err_segment = "SERVER_MON not defined"
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)
            return

        if not config_parser.PlatformDiscovery(
                self.setup_file).contain_thirdparties_platform():
            self.set_validation_results(section_name)
            return
        elif 'ALL' in server_mon_list:
            err_segment = "SERVER_MON:host_info value of ALL not " \
                "supported in pod having 3rd party server(s)"
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)
            return
        else:
            for item in server_mon_list:
                cimc_ip = self.ymlhelper.get_server_cimc_ip(item, return_value=1)
                if config_parser.PlatformDiscovery(
                        self.setup_file).is_thirdparties(cimc_ip):
                    unsupported_servermon_list.append(item)

            if unsupported_servermon_list:
                err_segment = "SERVER_MON:host_info includes following " \
                    "non-Cisco Server(s) %s" \
                    % (','.join(unsupported_servermon_list))
                self.set_validation_results(section_name, status=STATUS_FAIL,
                                            err=err_segment,
                                            error_code_list=err_code_list)

                return

        self.set_validation_results(section_name)
        return

    def check_ip_exists_in_a_pool(self, ip_to_check, ip_pool):
        '''Checks if ip exists in an IP pool'''

        if not self.is_ip_valid(ip_to_check):
            self.log.error("incorrect IP %s entered", ip_to_check)
            return 60

        ip_exists_in_pool = 0
        for item in ip_pool:
            pool_range_list = []
            try:
                pool_range_list = item.split("to")
            except ValueError:
                self.log.error("incorrect IP pool %s entered", ip_pool)
                return 60

            if not pool_range_list or len(pool_range_list) > 2:
                self.log.error("incorrect IP pool %s entered", ip_pool)
                return 60

            elif len(pool_range_list) == 1 and ip_to_check in pool_range_list:
                ip_exists_in_pool = 1
                break

            elif len(pool_range_list) == 2:
                start = ipaddr.IPv4Address(pool_range_list[0].strip())
                end = ipaddr.IPv4Address(pool_range_list[1].strip())
                to_check = ipaddr.IPv4Address(ip_to_check)
                if (to_check >= start) and (end > to_check):
                    self.log.info("IP %s is in pool %s", ip_to_check, ip_pool)
                    ip_exists_in_pool = 1
                    break

        return ip_exists_in_pool

    def validate_ip_for_a_given_network(self, addrString, network_with_mask):
        '''validates if the IP address is correct given the network and mask'''

        addr = netaddr.IPAddress(addrString)
        cidr = netaddr.IPNetwork(network_with_mask)
        if addr not in cidr:
            self.log.error("IP address not in given network")
            return 0
        if addr == cidr[0]:
            self.log.error("IP address is a prefix address")
            return 0
        if addr == cidr[-1]:
            self.log.error("IP address is a broadcast address")
            return 0
        return 1

    def validate_network(self, network_with_mask):
        ''' validates if the input of the network is correct'''

        if network_with_mask is None:
            self.log.error("Network info is missing")
            return 0
        elif not re.search(r'/', network_with_mask):
            self.log.error("Network info does not have the right pattern")
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

    def validate_vlan_id(self, vlan_id):
        ''' validates if the input of vlan is correct'''

        if vlan_id is None:
            self.log.error("vlan_id is missing")
            return 0

        try:
            _ = int(vlan_id)
        except ValueError:
            self.log.error("incorrect vlan_id %s entered", vlan_id)
            return 0

        if int(vlan_id) > 4096 or int(vlan_id) < 1:
            self.log.error("incorrect vlan_id %s entered", vlan_id)
            return 0

        return 1

    def check_pool_range(self):
        """
        Method to verify the given pool range
        """
        # get all the roles defined in the setup
        section_name = "Section NETWORKING:"

        # Get the management network type
        curr_mgmt_network = self.ymlhelper.get_management_network_type()

        testbed_type = self.get_testbed_type()
        seg_dict = {}
        chk_ip_pool_list = []
        undefined_ip_pool_list = []

        err_code_list = []
        err_code_list.append(self.validation_error_code['NETWORKING'])

        servers = self.ymlhelper.get_server_list()

        if servers:
            # remember the server count based on role
            for server in servers:
                if re.match(r'UCSM', testbed_type):
                    networks = self.ymlhelper.nw_get_server_vnic_networks(\
                        server, "no")
                else:
                    networks = self.ymlhelper.nw_get_server_vnic_networks(server)

                # find out the number of available IPs in each pool
                for network in networks:

                    if "external" in networks[network]['segments'] \
                            or "api" in networks[network]['segments']\
                            or "aciinfra" in networks[network]['segments']\
                            or "provider" in networks[network]['segments']:
                        continue
                    elif curr_mgmt_network == 'layer3' \
                            and "provision" in networks[network]['segments']:
                        continue

                    my_segment = networks[network]['segments']
                    my_segment_str = ' '.join(my_segment)
                    if 'management' in my_segment and 'provision' in my_segment:
                        my_segment_str = "management"
                    curr_network = \
                        self.ymlhelper.nw_get_specific_vnic_info(my_segment_str,
                                                                 'subnet')

                    try:
                        ip_pool = networks[network]['pool']
                    # check if the ip syntax and input is correct
                        for item in ip_pool:
                            ip_pool_list = []
                            check_ip_entry = 0
                            try:
                                check_ip_entry = 1
                                from_, to_ = item.split("to")
                                ip_pool_list.append(from_)
                                ip_pool_list.append(to_)
                            except ValueError:
                                try:
                                    _, _ = item.split()
                                    if item not in chk_ip_pool_list:
                                        chk_ip_pool_list.append(item)
                                        check_ip_entry = 0
                                except ValueError:
                                    ip_pool_list.append(item)

                            if check_ip_entry:
                                for curr_ip in ip_pool_list:
                                    curr_ip = curr_ip.strip()
                                    if not self.validate_ip_for_a_given_network(\
                                            curr_ip, curr_network):
                                        if curr_ip not in chk_ip_pool_list:
                                            chk_ip_pool_list.append(curr_ip)
                    except KeyError:
                        curr_segment = networks[network]['segments']
                        curr_segment_str = ''.join(curr_segment)
                        undefined_ip_pool_list.append(curr_segment_str)

                    if not chk_ip_pool_list:
                        segments = networks[network]['segments']
                        for segment in segments:
                            seg_dict[segment] = \
                                len(common.create_list_of_available_ips(
                                    ip_pool))

        if undefined_ip_pool_list:
            self.set_validation_results("IP Pool Check", status=STATUS_FAIL,
                                        err=section_name +
                                        " Undefined IP Pool for segment: " +
                                        ", ".join(set(undefined_ip_pool_list)),
                                        error_code_list=err_code_list)
            return

        if chk_ip_pool_list:
            self.set_validation_results("IP Pool Check", status=STATUS_FAIL,
                                        err=section_name +
                                        " InCorrect IP Entry: " +
                                        ", ".join(set(chk_ip_pool_list)),
                                        error_code_list=err_code_list)
            return

        error = []

        try:
            for server in servers:
                # get the segment and network info for each server
                if re.match(r'UCSM', testbed_type):
                    segments = \
                        self.ymlhelper.role_get_vnic_segments(
                            server,
                            remove_cimc_segment="no")
                else:
                    segments = self.ymlhelper.role_get_vnic_segments(server)
                for segment in segments:
                    if seg_dict.get(segment) >= 0:
                        seg_dict[segment] -= 1
                        if seg_dict[segment] < -1:
                            self.log.error("Not enough IP in the pool for %s ",
                                           segment)
                            error.append(segment)
            if error:
                self.set_validation_results("IP Pool Check", status=STATUS_FAIL,
                                            err="Not enough IPs in " +
                                            ", ".join(set(error)) + " pool",
                                            error_code_list=err_code_list)
                return
        except TypeError:
            self.set_validation_results("IP Pool Check", status=STATUS_FAIL,
                                        err="Server Role Missing",
                                        error_code_list=err_code_list)
            return

        self.set_validation_results("IP Pool Check")
        return None

    def check_ntp_servers_provided(self):
        '''
        Verify if the user has provided at least one NTP server
        '''
        section_name = "Section NETWORKING:"
        key = ["NETWORKING", "ntp_servers"]
        cvim_mon_ha_key = ["ntp_servers"]
        if self.ymlhelper.get_pod_type() == 'CVIMMONHA':
            key = cvim_mon_ha_key
        ntp_servers = self.ymlhelper.get_data_from_userinput_file(key)

        invalid_ntp_servers = []
        invalid_value_format = []

        err_code_list = []
        net_ve_code = self.validation_error_code['NETWORKING']
        ntp_ve_code = self.validation_error_code['ntp_servers']
        ntp_segment = net_ve_code + ":" + ntp_ve_code
        err_code_list.append(ntp_segment)

        num_ntp_defined = 0

        chk_dns_alive = " , also check if your DNS server is alive"
        if ntp_servers is None or len(ntp_servers) is 0:
            self.log.error("No NTP servers found in setup_data")
            self.set_validation_results("NTP servers Check",
                                        status=STATUS_FAIL,
                                        err=section_name +
                                        "No NTP servers provided",
                                        error_code_list=err_code_list)
            return
        elif not self.is_input_in_ascii(ntp_servers):
            invalid_value_format.append(key)
        else:
            for item in ntp_servers:
                num_ntp_defined = num_ntp_defined + 1
                if not self.is_dns_valid(item):
                    invalid_ntp_servers.append(item)

        if invalid_value_format:
            self.log.error("NTP servers value is not in ASCII")
            self.set_validation_results("NTP servers Check",
                                        status=STATUS_FAIL,
                                        err=section_name +
                                        "Invalid Data Format " +
                                        str(invalid_value_format),
                                        error_code_list=err_code_list)
            return
        elif invalid_ntp_servers:
            self.log.error("DNS Resolution of NTP servers failed %s",
                           str(invalid_ntp_servers))
            err_str = section_name + "Invalid DNS for " + \
                str(invalid_ntp_servers) + chk_dns_alive
            self.set_validation_results("NTP servers Check",
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return
        elif num_ntp_defined > 4:
            self.log.error("Number of supports NTP is 4, got %s",
                           str(num_ntp_defined))
            ntp_support_str = " Max Num of NTP servers Supported:4; Found:"
            self.set_validation_results("NTP servers Check",
                                        status=STATUS_FAIL,
                                        err=section_name +
                                        ntp_support_str +
                                        str(num_ntp_defined),
                                        error_code_list=err_code_list)
            return
        else:
            self.set_validation_results("NTP servers Check")
        return

    def run_cloud_sanity(self):
        """Run Cloud Sanity"""

        section_name = "Run Cloud Sanity"
        os_cfg_loc = self.get_openstack_configs_loc()

        if not os_cfg_loc:
            err_str = "Couldnt find openstack-configs dir, " \
                "skipping cloud-sanity check"
            self.log.info(err_str)
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return

        else:
            openrc_loc = os_cfg_loc + "/openstack-configs/openrc"
            if not os.path.isfile(openrc_loc):
                err_str = "Couldnot find %s, skipping cloud-sanity check" \
                    % (openrc_loc)
                self.log.info(err_str)
                self.set_validation_results(section_name,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return

            else:
                cloud_sanity_status = self.execute_cloud_sanity()
                if re.search(r'ERROR:', cloud_sanity_status):
                    chk_str = "ERROR: Cloud Sanity failed with %s " \
                        % cloud_sanity_status
                    self.set_validation_results(section_name,
                                                status=STATUS_FAIL,
                                                err=chk_str)
                    return

        self.set_validation_results(section_name)
        return

    def check_es_snapshot_settings_for_vm(self):
        """Check ES_SNAPSHOT_AUTODELETE for Central VM"""

        section_name = "Check ES_SNAPSHOT_AUTODELETE Check"

        homedir = os.path.expanduser("~")
        cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)

        host_os_cfg_file = os.path.join(cfg_dir, DEFAULT_OS_CFG_FILE)

        if not os.path.isfile(host_os_cfg_file):
            err_msg = "%s file for hosted cloud not found" % host_os_cfg_file
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_msg)
            return

        oc_parser = config_parser.YamlHelper( \
            user_input_file=host_os_cfg_file)
        exp_auto_del = {'threshold_warning': 40,
                        'threshold_low': 30,
                        'threshold_high': 50}

        curr_es_auto_del = \
            oc_parser.get_data_from_userinput_file(['ES_SNAPSHOT_AUTODELETE'])

        es_auto_del_chk_list = []
        for key, value in common.get_items(exp_auto_del):
            if curr_es_auto_del[key] > value:
                tmp = "%s value: Current: %s, Expected:%s;" \
                    % (key, curr_es_auto_del[key], value)
                es_auto_del_chk_list.append(tmp)

        if es_auto_del_chk_list:
            err_msg = "ES_SNAPSHOT_AUTODELETE check failed for " \
                "Virtual Management Node: %s Please set the value at or below the " \
                "expected value in %s" % (' '.join(es_auto_del_chk_list),
                                          host_os_cfg_file)
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_msg)
            return

        self.set_validation_results(section_name)

    def check_openrc_project_status(self):
        """Check if the openrc and project status for
        Central Mgmt is valid"""

        section_name = "Check Project Status for CENTRAL_MGMT"

        home_dir = os.path.expanduser("~")
        openrc_loc = "%s/openstack-configs/%s" % (home_dir, common.CM_OPENRC_FILE)

        if not os.path.isfile(openrc_loc):
            err_msg = "openrc file %s for project central_mgmt not found, " \
                "in cannot proceed" % (openrc_loc)
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_msg)
            return
        project_status = common.check_project_details(openrc_loc)

        if re.search(r'ERROR:', project_status):
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=project_status)
            return

        self.set_validation_results(section_name)

    def check_hosted_cloud_ram_status(self):
        """Check if the RAM allocation of the Hosted cloud is correct"""

        section_name = "Check Hosted Cloud RAM Status"

        homedir = os.path.expanduser("~")
        cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)

        host_os_cfg_file = os.path.join(cfg_dir, DEFAULT_OS_CFG_FILE)

        if not os.path.isfile(host_os_cfg_file):
            err_msg = "%s file for hosted cloud not found" % host_os_cfg_file
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_msg)
            return

        hc_oc_parser = config_parser.YamlHelper( \
            user_input_file=host_os_cfg_file)

        global_current_ram_ratio = \
            hc_oc_parser.get_data_from_userinput_file(["NOVA_RAM_ALLOCATION_RATIO"])

        central_mgmt_aggr_name = \
            self.ymlhelper.get_data_from_userinput_file(["CENTRAL_MGMT_AGGREGATE"])

        if central_mgmt_aggr_name is None and global_current_ram_ratio not in (1.0, 1):
            err_msg = "Centralized Management Node cannot be " \
                "hosted in Pod Oversubscribed with Memory; Currently global " \
                "setting of %s found for NOVA_RAM_ALLOCATION_RATIO" \
                % global_current_ram_ratio
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_msg)
            return

        base_cloud_setup_data = \
            os.path.join(self.cfg_dir, common.DEFAULT_SETUPFILE)
        base_cloud_parser = config_parser.YamlHelper( \
            user_input_file=base_cloud_setup_data)

        if central_mgmt_aggr_name is not None:
            oversubs_ram_list = []
            int_lb_info = base_cloud_parser.get_data_from_userinput_file( \
                ['internal_lb_vip_ipv6_address'])

            via_v6 = 1
            if int_lb_info is None:
                int_lb_info = base_cloud_parser.get_data_from_userinput_file(
                    ['internal_lb_vip_address'])
                via_v6 = 0
            az_host = common.get_info_from_az(\
                central_mgmt_aggr_name, 'hosts', int_lb_info, via_v6)
            if re.search(r'ERROR:', az_host):
                self.set_validation_results(section_name,
                                            status=STATUS_FAIL,
                                            err=az_host)
                return

            az_host_list = az_host.split(",")
            # Check if RAM/server is set
            for host_name in az_host_list:
                ram_server_info = base_cloud_parser.get_server_attribute_info(\
                    host_name, 'NOVA_RAM_ALLOCATION_RATIO')

                if ram_server_info is not None and ram_server_info not in (1.0, 1):
                    tmp = "%s:%s" % (host_name, ram_server_info)
                    oversubs_ram_list.append(tmp)
                if ram_server_info is None and \
                        global_current_ram_ratio not in (1.0, 1):
                    tmp = "globally:%s" % global_current_ram_ratio
                    if tmp not in oversubs_ram_list:
                        oversubs_ram_list.append(tmp)

            if oversubs_ram_list:
                err_msg = "Centralized Management Node cannot be " \
                    "hosted in Pod Oversubscribed with Memory; Currently " \
                    "NOVA_RAM_ALLOCATION_RATIO is %s" \
                    % (', '.join(oversubs_ram_list))
                self.set_validation_results(section_name,
                                            status=STATUS_FAIL,
                                            err=err_msg)
                return

        self.set_validation_results(section_name)

    def check_hosted_cloud_pod_status(self):
        """Check if the PODTYPE and Ceph allocation of the
        Hosted cloud is correct"""

        section_name = "Check Hosted Cloud Resource Status"

        homedir = os.path.expanduser("~")
        cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)
        host_setup_file = os.path.join(cfg_dir, DEFAULT_SETUP_FILE)

        if not os.path.isfile(host_setup_file):
            err_msg = "%s file for hosted cloud not found" % host_setup_file
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_msg)
            return

        hc_setup_parser = config_parser.YamlHelper( \
            user_input_file=host_setup_file)

        podtype = hc_setup_parser.get_data_from_userinput_file(["PODTYPE"])
        if podtype is None:
            podtype = "fullon"

        if podtype in ('ceph', 'edge', 'nano'):
            err_msg = "Centralized Management Node cannot be " \
                "hosted in Podtype :%s; Allowed pods are fullon, micro, " \
                "UMHC and NGENAHC" % (podtype)
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_msg)
            return

        if podtype in ('micro', 'UMHC', 'NGENAHC'):
            ceph_osd_core = \
                hc_setup_parser.get_data_from_userinput_file(\
                    ["CEPH_OSD_RESERVED_PCORES"])
            err_msg = "Minimum of 6 CEPH OSD CORES needed to host " \
                "Centralized Management Nodes in podtype %s" % podtype
            if ceph_osd_core is None:
                self.set_validation_results(section_name,
                                            status=STATUS_FAIL,
                                            err=err_msg)
                return
            if ceph_osd_core < 6:
                err_msg = "%s; Found to be %s" % (err_msg, ceph_osd_core)
                self.set_validation_results(section_name,
                                            status=STATUS_FAIL,
                                            err=err_msg)
                return

            cinder_percent = ['CEPH_PG_INFO', 'cinder_percentage_data']
            cinder_percent_info = \
                hc_setup_parser.get_deepdata_from_userinput_file(cinder_percent)

            curr_cinder_value = 60
            err_msg = "Cinder percentage has to be set to min of 80% or higher, " \
                "for hosting Centralized Management Nodes; current value is"
            if cinder_percent_info is None:
                err_msg = "%s %s" % (err_msg, curr_cinder_value)

                self.set_validation_results(section_name,
                                            status=STATUS_FAIL,
                                            err=err_msg)
                return
            if cinder_percent_info < 80:
                err_msg = "%s %s" % (err_msg, cinder_percent_info)

                self.set_validation_results(section_name,
                                            status=STATUS_FAIL,
                                            err=err_msg)
                return

        self.set_validation_results(section_name)

    def check_mgmt_central_dns_servers_provided(self):
        """Verify if DNS servers are alive"""

        section_name = "Check DNS Availability"
        err_code_list = []
        err_code_list.append(self.validation_error_code['NETWORKS'])
        networks = \
            self.ymlhelper.get_data_from_userinput_file(["NETWORKS"])

        dns_server_list = []
        for item in networks:
            subnet_info_list = item.get('subnets', None)

            if subnet_info_list is not None:
                for subnet_info in subnet_info_list:
                    dns_info = subnet_info.get('dns_nameservers', None)

                    if dns_info is not None:
                        dns_server_list.extend(dns_info)

        unreachable_ip_list = []
        unique_server_dup_list = list(dict.fromkeys(dns_server_list))
        for item in unique_server_dup_list:
            if not self.is_dns_valid(item):
                unreachable_ip_list.append(item)

        if unreachable_ip_list:
            err_str = "Non Reachable DNS %s" % (','.join(unreachable_ip_list))
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
        else:
            self.set_validation_results(section_name)

        return

    def check_dns_servers_provided(self):
        '''
        Verify if the user has provided at least one Proxy and DNS server
        '''

        section_name = "Section NETWORKING:"
        server_type = ["domain_name",
                       "domain_name_servers"]

        invalid_server_type = []
        invalid_dns_servers = []
        invalid_value_format = []

        err_code_list = []
        err_code_list.append(self.validation_error_code['NETWORKING'])

        error_found = 0
        for item in server_type:
            key = ["NETWORKING", item]
            curr_server = self.ymlhelper.get_data_from_userinput_file(key)

            if curr_server is None or not curr_server:
                self.log.error("No %s found in setup_data", item)
                invalid_server_type.append(item)
            elif not self.is_input_in_ascii(curr_server):
                invalid_value_format.append(item)
            else:
                if not re.match(r'domain_name_servers', item) and \
                        re.match(r'domain_name', item):
                    continue

                else:
                    for entry in curr_server:
                        dns_check_entry = entry
                        if not self.is_dns_valid(dns_check_entry):
                            if item == 'domain_name_servers':
                                invalid_dns_servers.append(dns_check_entry)

        if invalid_value_format:
            self.log.error("Undefined info for %s",
                           str(invalid_value_format))
            error_found = 1
            self.set_validation_results("DNS Input Value Check",
                                        status=STATUS_FAIL,
                                        err=section_name +
                                        "Invalid Data Format " +
                                        str(invalid_value_format),
                                        error_code_list=err_code_list)

        if invalid_server_type:
            self.log.error("Undefined info for %s",
                           str(invalid_server_type))
            error_found = 1
            self.set_validation_results("DNS server Type Check",
                                        status=STATUS_FAIL,
                                        err=section_name +
                                        "Invalid Server Type " +
                                        str(invalid_server_type),
                                        error_code_list=err_code_list)

        net_ve_code = self.validation_error_code['NETWORKING']
        dname_ve_code = self.validation_error_code['domain_name_servers']
        dname_segment = net_ve_code + ":" + dname_ve_code
        err_code_list.append(dname_segment)

        chk_dns_alive = " , also check if your DNS server is alive"
        if invalid_dns_servers:
            error_found = 1
            self.log.error("DNS Resolution of Domain Name servers failed %s",
                           str(invalid_dns_servers))
            err_str = section_name + "Invalid DNS for " + \
                str(invalid_dns_servers) + chk_dns_alive
            self.set_validation_results("Domain Name server Check",
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)

        if not error_found:
            self.set_validation_results("DNS servers Check")

        return

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

    def verify_servers_in_roles_and_servers(self, curr_action):
        """
        Compare servers specified in ROLES and SERVERS match
        """

        if self.ymlhelper.get_pod_type() == 'CVIMMONHA':
            return

        err_code_list = []
        err_code_list.append(self.validation_error_code['ROLES'])
        try:
            servers = self.ymlhelper.get_server_list()
        except TypeError:
            self.set_validation_results(
                "Check servers in ROLES and SERVERS match", status=STATUS_FAIL,
                err="Missing Server Roles")
            return

        servers_in_roles = []

        if self.ymlhelper.get_pod_type() == 'ceph':
            control_server_list = self.ymlhelper.get_server_list(role="cephcontrol")
        else:
            control_server_list = self.ymlhelper.get_server_list(role="control")
            compute_server_list = self.ymlhelper.get_server_list(role="compute")
        role_profiles = self.ymlhelper.rp_get_all_roles()

        for role in role_profiles:
            svr_list = self.ymlhelper.get_server_list(role=role)
            if svr_list is None:
                continue
            else:
                servers_in_roles.extend(svr_list)

        try:
            for svr in servers:
                if svr in servers_in_roles:
                    servers_in_roles = filter(lambda a: a != svr, servers_in_roles)
                    servers = filter(lambda a: a != svr, servers)
                else:
                    servers_in_roles = filter(lambda a: a != svr, servers_in_roles)
        except TypeError:
            self.set_validation_results(
                "check servers in ROLES and SERVERS match", status=STATUS_FAIL,
                err="Missing Server to Roles Mapping", error_code_list=err_code_list)
            return

        if servers or servers_in_roles:
            self.log.error("Servers in ROLES and SERVERS does not match %s",
                           self.setup_file)

            err_msg = "Missing Server to Roles Mapping: "
            if servers_in_roles:
                server_info = ','.join(servers_in_roles)
            elif servers:
                server_info = ','.join(servers)
            err_msg = err_msg + str(server_info)
            self.set_validation_results(
                "check servers in ROLES and SERVERS match", status=STATUS_FAIL,
                err=err_msg, error_code_list=err_code_list)
            return

        role_ve_code = self.validation_error_code['ROLES']
        control_ve_code = self.validation_error_code['control']
        control_segment = role_ve_code + ":" + control_ve_code

        compute_ve_code = self.validation_error_code['compute']
        compute_segment = role_ve_code + ":" + compute_ve_code

        bstroage_ve_code = self.validation_error_code['block_storage']
        bstorage_segment = role_ve_code + ":" + bstroage_ve_code

        err_code_list = []
        if self.ymlhelper.get_pod_type() == 'ceph':
            bstroage_ve_code = self.validation_error_code['cephosd']
            bstorage_segment = role_ve_code + ":" + bstroage_ve_code
            control_ve_code = self.validation_error_code['cephcontrol']
            control_segment = role_ve_code + ":" + control_ve_code

        err_code_list.append(bstorage_segment)

        if self.ymlhelper.get_pod_type() == 'ceph':
            ceph_server_list = self.ymlhelper.get_server_list(role="cephosd")
        else:
            ceph_server_list = self.ymlhelper.get_server_list(role="block_storage")

        if ceph_server_list and len(ceph_server_list) < 2:
            self.log.error("Min # of Dedicated Ceph Server is 2 found %s",
                           str(len(ceph_server_list)))
            self.set_validation_results(
                "Min # of Dedicated Ceph Server:", status=STATUS_FAIL,
                err="Expected:>=2; Found:" + \
                str(len(ceph_server_list)) + " Server Details: " + \
                str(ceph_server_list),
                error_code_list=err_code_list)
            return

        cfg_section = "Check server count and ROLES"
        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])
        if podtype is None:
            podtype = "fullon"

        found_error = 0
        curr_code_list = []
        err_list = []

        if podtype is not None and podtype == 'nano':
            if len(control_server_list) != 1:
                found_error = 1
                if control_segment not in curr_code_list:
                    curr_code_list.append(control_segment)
                err_msg = "Num of %s Controllers Expected: 1, Found: %s" \
                    % (podtype, len(control_server_list))
                err_list.append(err_msg)

            if len(compute_server_list) != 1:
                found_error = 1
                if compute_segment not in curr_code_list:
                    curr_code_list.append(compute_segment)
                err_msg = "Num of nano compute Expected: 1, Found: " + \
                    str(len(compute_server_list))
                err_list.append(err_msg)

            if control_server_list != compute_server_list:
                found_error = 1
                curr_code_list.append(compute_segment)
                err_msg = "Entry for compute %s and control %s node are not " \
                    "identical" % (','.join(compute_server_list), \
                    ','.join(control_server_list))
                err_list.append(err_msg)

            if ceph_server_list:
                found_error = 1
                if bstorage_segment not in curr_code_list:
                    curr_code_list.append(bstorage_segment)
                err_msg = "Ceph is not supported for Nano pod"
                err_list.append(err_msg)

        elif podtype is not None and \
                re.match(r'micro|UMHC|NGENAHC|edge|ceph', podtype):
            # Check for right num of nodes
            if len(control_server_list) != 3:
                found_error = 1
                if control_segment not in curr_code_list:
                    curr_code_list.append(control_segment)
                err_msg = "Num of %s Controllers Expected: 3, Found: %s" \
                    % (podtype, len(control_server_list))
                err_list.append(err_msg)

            if re.match(r'micro|UMHC|NGENAHC|ceph', podtype):
                min_ceph_server_count = 3
                if curr_action == 'remove_osd':
                    min_ceph_server_count = 2
                if len(ceph_server_list) < min_ceph_server_count:
                    found_error = 1
                    if bstorage_segment not in curr_code_list:
                        curr_code_list.append(bstorage_segment)
                    err_msg = "Num of %s Ceph OSDs Expected: 3, Found: %s" \
                        % (podtype, len(ceph_server_list))
                    err_list.append(err_msg)

        missing_umhc_ceph_servers = []
        if podtype is not None and re.match(r'UMHC|NGENAHC', podtype):
            for ceph_svr in ceph_server_list:
                if ceph_svr not in compute_server_list:
                    found_error = 1
                    missing_umhc_ceph_servers.append(ceph_svr)

            if missing_umhc_ceph_servers:
                err_msg = "Missing %s Ceph servers as computes: %s" \
                    % (podtype, ','.join(missing_umhc_ceph_servers))
                err_list.append(err_msg)
                if bstorage_segment not in curr_code_list:
                    curr_code_list.append(bstorage_segment)

        if podtype is not None and re.match(r'edge', podtype):
            if len(compute_server_list) < 3:
                found_error = 1
                if compute_segment not in curr_code_list:
                    curr_code_list.append(compute_segment)
                err_msg = "Min. Num of Edge computes Expected: 3, Found: " + \
                          str(len(compute_server_list))
                err_list.append(err_msg)

            missing_edge_cmpt_servers = []
            for cntl_svr in control_server_list:
                # Check if all controllers are in the compute node
                if cntl_svr not in compute_server_list:
                    found_error = 1
                    missing_edge_cmpt_servers.append(cntl_svr)

            if missing_edge_cmpt_servers:
                err_msg = "Missing Edge Compute servers: " + \
                          ','.join(missing_edge_cmpt_servers)
                err_list.append(err_msg)
                if compute_segment not in curr_code_list:
                    curr_code_list.append(compute_segment)

        if podtype is not None and re.match(r'micro', podtype):
            if len(compute_server_list) < 3:
                found_error = 1
                if compute_segment not in curr_code_list:
                    curr_code_list.append(compute_segment)
                err_msg = "Min Num of AIO computes Expected: 3, Found: " + \
                          str(len(compute_server_list))
                err_list.append(err_msg)

            missing_aio_cmpt_servers = []
            missing_aio_ceph_servers = []

            for cntl_svr in control_server_list:
                # Check if all controllers are in the compute node
                if cntl_svr not in compute_server_list:
                    found_error = 1
                    missing_aio_cmpt_servers.append(cntl_svr)

                # Check if all controllers are in the ceph node
                if cntl_svr not in ceph_server_list:
                    found_error = 1
                    missing_aio_ceph_servers.append(cntl_svr)

            if missing_aio_cmpt_servers:
                err_msg = "Missing AIO Compute servers: " + \
                    ','.join(missing_aio_cmpt_servers)
                err_list.append(err_msg)
                if compute_segment not in curr_code_list:
                    curr_code_list.append(compute_segment)

            if missing_aio_ceph_servers:
                err_msg = "Missing AIO Ceph servers: " + \
                          ','.join(missing_aio_ceph_servers)
                err_list.append(err_msg)
                if bstorage_segment not in curr_code_list:
                    curr_code_list.append(bstorage_segment)

        elif podtype is None or re.match(r'fullon', podtype):
            dup_cntrl_cmpt_servers = []
            dup_cntrl_ceph_servers = []
            dup_ceph_cmpt_servers = []

            for cntl_svr in control_server_list:
                # Check if no controllers are in the compute node
                if cntl_svr in compute_server_list:
                    found_error = 1
                    dup_cntrl_cmpt_servers.append(cntl_svr)

                # Check if no controllers are in the ceph node
                if ceph_server_list and cntl_svr in ceph_server_list:
                    found_error = 1
                    dup_cntrl_ceph_servers.append(cntl_svr)

            for cmpt_svr in compute_server_list:
                # Check if no compute are in the ceph node
                if ceph_server_list and cmpt_svr in ceph_server_list:
                    found_error = 1
                    dup_ceph_cmpt_servers.append(cmpt_svr)

            if dup_cntrl_ceph_servers:
                err_msg = "Duplicate Servers between Controller and Ceph Roles: " + \
                    ','.join(dup_cntrl_ceph_servers)
                err_list.append(err_msg)
                if control_segment not in curr_code_list:
                    curr_code_list.append(control_segment)

            if dup_cntrl_cmpt_servers:
                err_msg = "Duplicate Servers between Controller and \
                    Compute Roles: " + ','.join(dup_cntrl_cmpt_servers)
                err_list.append(err_msg)
                if control_segment not in curr_code_list:
                    curr_code_list.append(control_segment)

            if dup_ceph_cmpt_servers:
                err_msg = "Duplicate Servers between Compute and Compute Roles: " + \
                          ','.join(dup_ceph_cmpt_servers)
                err_list.append(err_msg)
                if compute_segment not in curr_code_list:
                    curr_code_list.append(compute_segment)

        elif podtype is not None and podtype == 'ceph':
            missing_aio_ceph_servers = []

            for cntl_svr in control_server_list:
                # Check if all controllers are in the ceph node
                if cntl_svr not in ceph_server_list:
                    found_error = 1
                    missing_aio_ceph_servers.append(cntl_svr)

            if missing_aio_ceph_servers:
                err_msg = "Missing AIO Ceph servers: " + \
                          ','.join(missing_aio_ceph_servers)
                err_list.append(err_msg)
                if bstorage_segment not in curr_code_list:
                    curr_code_list.append(bstorage_segment)

        if podtype == 'nano' and control_server_list and \
                len(control_server_list) != 1:
            err_msg = "Only 1 controller expected in a non pod; found to be %s" \
                % (len(control_server_list))
            found_error = 1
            err_list.append(err_msg)
        elif podtype != 'nano' and control_server_list \
                and len(control_server_list) != 3:
            err_msg = "Only 3 controllers are expected; found to be %s" \
                % (len(control_server_list))
            found_error = 1
            err_list.append(err_msg)

        if podtype == "micro" and ceph_server_list and \
                len(ceph_server_list) > 3:
            err_msg = "Max num of OSDs supported is 3 for podtype %s" % (podtype)
            found_error = 1
            err_list.append(err_msg)
        elif (podtype == "NGENAHC" or podtype == "UMHC") and \
                ceph_server_list and len(ceph_server_list) > 15:
            err_msg = "Max num of OSDs supported is 15 for podtype %s" % (podtype)
            found_error = 1
            err_list.append(err_msg)
        elif podtype == "fullon" and ceph_server_list and len(ceph_server_list) > 25:
            err_msg = "Max num of OSDs supported is 25 for podtype %s" % (podtype)
            found_error = 1
            err_list.append(err_msg)

        if found_error:
            err_str = ','.join(err_list)

            if curr_code_list:
                ve_str = "^".join(curr_code_list)
                err_code_list.append(ve_str)

            self.set_validation_results(cfg_section, status=STATUS_FAIL, \
                                        err=err_str, \
                                        error_code_list=err_code_list)
        else:
            if podtype == "fullon" and ceph_server_list and \
                    len(ceph_server_list) > 20:
                warn_msg = "WARNING!!! Exceeding the maximum num of officially " \
                    "supported OSDs of 20; found to be %s; Strict upper limit is " \
                    "25" % (len(ceph_server_list))
                self.set_validation_results(cfg_section, status=STATUS_PASS, err=warn_msg)
            else:
                self.set_validation_results(cfg_section, status=STATUS_PASS)
        return

    def verify_kickstart_files_and_host_profile(self):
        '''
        Method to verify kickstart files in Cobbler
        '''
        section_name = "Verify Kickstart Files exist in Cobbler"
        found_error = 0
        parsed_secrets_file = config_parser.YamlHelper(
            user_input_file=self.secrets_file)

        cobbler_ip = self.cfgmgr.get_build_node_ip('management')
        cobbler_uname = self.ymlhelper.cobbler_get_server_username()

        if self.vault_config is not None and self.vault_config['enabled'] \
                and not self.skip_vault:
            cobbler_pwd = self.hvac_client.read(VAULT_SECRETS_PATH + \
                '/COBBLER_PASSWORD')['data']['data']['value']
        else:
            parsed_secrets_file = config_parser.YamlHelper(
                user_input_file=self.secrets_file)
            cobbler_pwd = parsed_secrets_file.get_data_from_userinput_file(\
                ['COBBLER_PASSWORD'])

        try:
            ip_addr = ipaddr.IPAddress(cobbler_ip)
            if ip_addr.version == 6:
                ip_addr = "[%s]" % ip_addr
            api_url = "http://%s/cobbler_api" % ip_addr
            cobbler_api = cobblerutils.Cobbler(api_url, \
                                               cobbler_uname, \
                                               cobbler_pwd)
            cobbler_kickstarts = cobbler_api.cobbler_kickstart_templates()
            for role in ['control', 'compute', 'block_storage']:
                input_ks = self.ymlhelper.cobbler_get_kickstart_file(role)
                if input_ks not in cobbler_kickstarts:
                    found_error = 1
                    self.set_validation_results(section_name,
                                                status=STATUS_FAIL,
                                                err="Invalid " +
                                                input_ks + " kickstart provided")
        except ValueError:
            found_error = 1
            self.set_validation_results(section_name, \
                                        status=STATUS_FAIL, \
                                        err="Cobbler IP not Accessible " + \
                                        str(cobbler_ip))

        except Exception as ex:
            found_error = 1
            err_msg = 'Cobbler IP not Accessible: {msg}'.format(msg=ex.message)
            self.log.info(err_msg)
            self.set_validation_results(section_name, \
                                        status=STATUS_FAIL, \
                                        err="Cobbler IP not Accessible " + \
                                        str(cobbler_ip))


        if not found_error:
            self.set_validation_results(section_name)
        return

    def check_tftp_server_status(self):
        '''
        Verify if tftp_server is up
        '''

        section_name = "Verify tftp server presence"

        show_command = ['/usr/sbin/ss', '-panu']
        output = subprocess.check_output(show_command)
        error_found = 0

        try:
            output = subprocess.check_output(show_command)
        except subprocess.CalledProcessError:
            error_found = 1

        if error_found:
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err="Couldnt check for for tftp server")
            return

        tftp_port_missing = 0
        tftp_found = 0
        for item in output.splitlines():
            if re.search(r'tftpd', item):
                tftp_found = 1
                if not re.search(r':69', item.strip()):
                    tftp_port_missing = 1

                if tftp_port_missing:
                    self.set_validation_results(section_name,
                                                status=STATUS_FAIL,
                                                err="tftp port not available")
                    return

        if not tftp_found:
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err="tftpd not available")
            return

        if not tftp_port_missing:
            self.set_validation_results(section_name)
        return

    def check_api_server_status(self, target_type="Cobbler"):
        '''
        Verify if api server for a given target is up
        '''

        section_name = "Cobbler API Check"
        found_error = 0
        param = "Cobbler IP"
        chk_config = "Cobbler API Server Status"
        parsed_secrets_file = config_parser.YamlHelper(
            user_input_file=self.secrets_file)

        cobbler_uname = self.ymlhelper.cobbler_get_server_username()

        if self.vault_config is not None and self.vault_config['enabled'] \
                and not self.skip_vault:
            cobbler_pwd = self.hvac_client.read(VAULT_SECRETS_PATH + \
                '/COBBLER_PASSWORD')['data']['data']['value']
        else:
            parsed_secrets_file = config_parser.YamlHelper(
                user_input_file=self.secrets_file)
            cobbler_pwd = parsed_secrets_file.get_data_from_userinput_file(\
                ['COBBLER_PASSWORD'])

        ret_value = self.cfgmgr.get_build_node_ip('management')

        if ret_value is None:
            found_error = 1
            self.log.error("%s not found in setup data", param)
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=section_name + " Invalid " +
                                        param + " provided")
        else:
            try:
                ip_addr = ipaddr.IPAddress(ret_value)
                if ip_addr.version == 6:
                    ip_addr = "[%s]" % ip_addr
                api_url = "http://%s/cobbler_api" % ip_addr
                try:
                    cobbler_api = cobblerutils.Cobbler(
                        api_url, cobbler_uname, cobbler_pwd)
                    _ = cobbler_api.cobbler_discover_profiles()

                except xmlrpclib.ProtocolError as err:
                    found_error = 1
                    self.log.error("Cobbler API %s not Up: error: %s", \
                                   api_url, err.errcode)

                    self.set_validation_results(chk_config, status=STATUS_FAIL, \
                                                err=section_name + \
                                                " Failed: for " + \
                                                api_url + " [ERROR Code:" \
                                                + str(err.errcode) + "]")
                except xmlrpclib.Fault as err:
                    found_error = 1
                    self.log.error("Cobbler API %s not Up: error: %s", \
                                   api_url, err.faultString)
                    self.set_validation_results(chk_config, status=STATUS_FAIL, \
                                                err=section_name + \
                                                " Failed for " + api_url +\
                                                "msg: " + str(err.faultString))
                except socket.error, msg:
                    found_error = 1
                    self.log.error("Cobbler API %s not Up: error:%s", \
                                   api_url, msg)
                    self.set_validation_results(chk_config, status=STATUS_FAIL, \
                                                err=section_name + \
                                                " Failed for " + api_url +\
                                                " msg: " + str(msg))

            except ValueError:
                found_error = 1
                self.log.error("Incorrect %s value in setup data", param)
                self.set_validation_results(chk_config, status=STATUS_FAIL,
                                            err=section_name + "Wrong Cobbler " +
                                            param + " value of " + ret_value +
                                            " provided")

        if not found_error:
            self.set_validation_results(chk_config)
        return

    def check_fluentd_aggr_status(self):
        '''
        Verify if fluentd_aggr service is up and listening to 7081 port
        '''
        section_name = "Verify fluentd-aggr service is up"
        try:
            output = subprocess.check_output(['/usr/sbin/ss', '-panu'])
        except subprocess.CalledProcessError:
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err="Couldn't check for fluend-aggr port")
            return

        fluentd_found = False
        for item in output.splitlines():
            if re.search(r'ruby', item):
                fluentd_found = True
                if re.search(r':7081', item.strip()):
                    # Success case
                    self.set_validation_results(section_name)
                    return
                else:
                    continue
        if fluentd_found:
            self.set_validation_results(section_name, status=STATUS_FAIL, \
                err="Port for fluentd-aggr service not opened")
        else:
            self.set_validation_results(section_name, status=STATUS_FAIL, \
                err="Fluentd-aggr service not available")
        return

    def is_apache_up(self, web_output):
        ''' Check from the contents if Apache is up'''

        for line in web_output.splitlines():
            # Expected success line (something like "HTTP/1.1 200 OK$")
            if re.search(r'^HTTP', line) and re.search(r'200 OK', line):
                return 1
        return 0

    def get_mgmt_node_info(self, intf_name):
        '''Gets the Mgmt Node Info'''

        curr_info = ""
        cmd = ['ip', 'addr', 'show', intf_name]

        try:
            response = subprocess.Popen(cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT)
            output = response.stdout.read()
        except OSError:
            return curr_info

        search_pat = r'inet.* ([0-9.]+)\/.* brd.* global.*' + str(intf_name)
        for item in output.splitlines():
            if re.search(search_pat, item):
                curr_info = re.search(search_pat, item).group(1)
                return curr_info

        return curr_info

    def get_ipv6_addr(self, net_type):
        """ Get br_mgmt ipv6 addr """
        ipaddr = None
        ifcfg_file = "/etc/sysconfig/network-scripts/ifcfg-" + net_type
        try:
            with open(ifcfg_file, 'r') as f:
                for line in f:
                    if "IPV6ADDR=" not in line:
                        continue
                    ipaddr = line.split("IPV6ADDR=")[1].strip('\n').split("/")[0]
                    break
        except IOError as e:
            return

        return ipaddr

    def check_local_management_network_gw_reachability(self):
        """Check Management network Gateway Reachability in Layer3 Environment"""

        # Get the management network type
        curr_mgmt_network = self.ymlhelper.get_management_network_type()
        if curr_mgmt_network == 'layer2':
            return

        err_code_list = []
        ve_code = self.validation_error_code['remote_management']
        err_code_list.append(ve_code)

        sec_name = "Check br_mgmt Gateway Reachability"

        rmt_mgmt_info = ['NETWORKING', 'remote_management']
        rmt_mgmt_flag = \
            self.ymlhelper.get_deepdata_from_userinput_file(rmt_mgmt_info)

        if rmt_mgmt_flag is None:
            err_str = "Section NETWORKING:remote_management not " \
                "defined for L3 deployment"
            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        prov_v6_gateway_info = rmt_mgmt_flag.get('ipv6_gateway', None)
        prov_gateway_info = rmt_mgmt_flag.get('gateway', None)

        err_list = []
        # Skip IPv4 ping check in Layer 3 for QCT
        vendor_name = "UNKNOWN"
        if config_parser.PlatformDiscovery(
                self.setup_file).contain_quanta_platform():
            vendor_name = "QCT"

        if prov_v6_gateway_info is not None and \
                not common.is_ipv4v6_reachable(prov_v6_gateway_info):
            err_list.append(prov_v6_gateway_info)

        if vendor_name == 'QCT' and prov_v6_gateway_info is not None:
            pass
        else:
            if not common.is_ipv4v6_reachable(prov_gateway_info):
                err_list.append(prov_gateway_info)

        if err_list:
            err_str = "Gateway %s of br_mgmt is not reachable " \
                "from the Management Node, a pre-req for Layer3 deployment " \
                "of CVIM" % (','.join(err_list))
            self.log.error(err_str)

            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        self.set_validation_results(sec_name)
        return

    def check_pod_management_network_gw_reachability(self):
        """Check Management network Gateway Reachability in Layer3 Environment"""

        # Get the management network type
        curr_mgmt_network = self.ymlhelper.get_management_network_type()
        if curr_mgmt_network == 'layer2':
            return

        err_code_list = []
        ve_code = self.validation_error_code['remote_management']
        err_code_list.append(ve_code)

        sec_name = "Check Pod Management Network Gateway Reachability"

        rmt_mgmt_info = ['NETWORKING', 'remote_management']
        rmt_mgmt_flag = \
            self.ymlhelper.get_deepdata_from_userinput_file(rmt_mgmt_info)

        if rmt_mgmt_flag is None:
            err_str = "Section NETWORKING:remote_management not " \
                "defined for L3 deployment"
            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        mgmtv6_gateway_info = self.ymlhelper.nw_get_specific_vnic_info(
            'management', 'ipv6_gateway')

        mgmt_gateway_info = self.ymlhelper.nw_get_specific_vnic_info(
            'management', 'gateway')

        err_list = []
        # Ping the gateway to PXE boot
        self.ymlhelper = config_parser.YamlHelper(\
            user_input_file=self.setup_file)

        if self.ymlhelper.check_for_ipv6_enable():
            if mgmtv6_gateway_info is None:
                err_str = "Section NETWORKING:management:ipv6_gateway not " \
                          "defined for L3 deployment"
                self.set_validation_results(sec_name, status=STATUS_FAIL,
                                            err=err_str,
                                            error_code_list=err_code_list)
                return

            if not common.is_ipv4v6_reachable(mgmtv6_gateway_info, "br_mgmt"):
                err_list.append(mgmtv6_gateway_info)

        else:
            if not common.is_ipv4v6_reachable(mgmt_gateway_info, "br_mgmt"):
                err_list.append(mgmt_gateway_info)

        if err_list:

            ignore_gw_ping = \
                self.ymlhelper.get_data_from_userinput_file(['IGNORE_GW_PING'])

            err_str = "Management Network Gateway %s of target pod is not " \
                "reachable from the Management Node, a pre-req for " \
                "Layer3 deployment of CVIM" % (','.join(err_list))

            self.log.error(err_str)

            if ignore_gw_ping is not None and ignore_gw_ping:
                err_str = "WARNING: %s" % (err_str)
                self.set_validation_results(sec_name, status=STATUS_PASS,
                                            err=err_str,
                                            error_code_list=err_code_list)

            else:
                self.set_validation_results(sec_name, status=STATUS_FAIL,
                                            err=err_str,
                                            error_code_list=err_code_list)
            return

        self.set_validation_results(sec_name)
        return

    def check_gpu_rpm(self):
        """Check if the GPU RMP file is in the right location and
        the checksum is consistent"""

        err_msg = ""
        sec_name = "GPU RPM Check"
        error_found = 0
        err_code_list = []
        gpu_error_info = self.validation_error_code['VGPU_TYPE']
        err_code_list.append(gpu_error_info)
        if not self.cfgmgr.is_vgpu_enabled():
            return

        defaults_yaml = common.get_contents_of_file(self.defaults_file)
        if not defaults_yaml:
            error_found = 1
            err_msg = "ERROR: Contents of %s is empty, can't proceed" \
                % (defaults_yaml)

        rpm_prefix = defaults_yaml.get('NVIDIA_VGPU_RPM', None)
        if not error_found and rpm_prefix is None:
            error_found = 1
            err_msg = "ERROR: GPU RPM info not found in %s, can't proceed" \
                % (self.defaults_file)

        rpm_name = "%s.rpm" % rpm_prefix
        file_check = common.find_file_path(INSTALLER_ROOT, rpm_name)

        if not error_found and not file_check:
            error_found = 1
            err_msg = "ERROR: GPU rpm %s not found in %s dir, " \
                "can't proceed" % (rpm_name, INSTALLER_ROOT)

        rpm_checksum_info = defaults_yaml.get('NVIDIA_VGPU_RPM_sha1', None)
        if not error_found and rpm_checksum_info is None:
            error_found = 1
            err_msg = "ERROR: Unable to evaluate the sha1 checksum of " \
                "the GPU rpm %s, can't proceed" % rpm_name

        if not error_found:
            try:
                current_file_checksum = \
                    common.get_checksum_file(file_check[0])
                if current_file_checksum != rpm_checksum_info:
                    error_found = 1
                    err_msg = "Mismatch in sha1 checksum of %s; " \
                        "Expected:%s Found:%s" \
                        % (file_check[0], rpm_checksum_info,
                           current_file_checksum)
            except IndexError:
                err_msg = "sha1 checksum of %s Failed " % rpm_name
                error_found = 1

        if error_found:
            self.log.info(err_msg)
            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_msg,
                                        error_code_list=err_code_list)
            return

        self.set_validation_results(sec_name)

    def check_ipa_server_reachability(self, input_str):
        """Check Server Reachability"""

        hostname = input_str.get('hostname')
        ipaddresses = input_str.get('ipaddresses')

        unreachable_ip_list = []
        if ipaddresses is not None:
            for item in ipaddresses:
                if not common.is_ipv4v6_reachable(item):
                    tmp = hostname + ":" + item
                    unreachable_ip_list.append(tmp)
        else:
            if not self.is_dns_valid(hostname):
                unreachable_ip_list.append(hostname)

        if unreachable_ip_list:
            unreachable_ip_str = ', '.join(unreachable_ip_list)
            return unreachable_ip_str

        return ""

    def check_ipa_server_name_compatibility(self, target_servers=[]):
        """Check that there is no uppercase in servers for fresh install
        and add actions"""

        ipa_info = self.ymlhelper.get_data_from_userinput_file(["IPA_INFO"])
        if ipa_info is None:
            return

        ipa_domain = ['IPA_INFO', 'ipa_domain_name']
        ipa_domain_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(ipa_domain)

        err_code_list = []
        ipa_ve_code = self.validation_error_code['IPA_INFO']
        err_code_list.append(ipa_ve_code)

        sec_name = "Check Server Hostname Compatibility for IPA"

        invalid_server_list = []
        servers = self.ymlhelper.get_server_list()
        if not target_servers:
            for server in servers:

                if not server.islower() and server not in invalid_server_list:
                    invalid_server_list.append(server)
                elif not re.search(r'\.', server) \
                        and server not in invalid_server_list:
                    invalid_server_list.append(server)
                elif not server.endswith(ipa_domain_info) and \
                        server not in invalid_server_list:
                    invalid_server_list.append(server)

            cmd_list = ['hostname']
            output = common.fetch_output_on_host(cmd_list)
            for item in output.splitlines():
                if item != 'NotFound' and not item.islower() \
                        and item not in invalid_server_list:
                    invalid_server_list.append(item)
                elif item != 'NotFound' and not re.search(r'\.', item) \
                        and item not in invalid_server_list:
                    invalid_server_list.append(item)
                elif item != 'NotFound' and not item.endswith(ipa_domain_info) and \
                        item not in invalid_server_list:
                    invalid_server_list.append(item)

        elif target_servers:
            for server in target_servers:
                if not server.islower() and server not in invalid_server_list:
                    invalid_server_list.append(server)
                elif not re.search(r'\.', server) \
                        and server not in invalid_server_list:
                    invalid_server_list.append(server)
                elif not server.endswith(ipa_domain_info) and \
                        server not in invalid_server_list:
                    invalid_server_list.append(server)

        if invalid_server_list:
            err_str = "Server Hostnames: %s have uppercases or non lowercase " \
                "FQDN in it, which violates RFC4120, and is not compatible " \
                "to IPA; Please change the hostnames to " \
                "lowercase with FQDN and servers have to belong to %s" \
                % (', '.join(invalid_server_list), ipa_domain_info)
            self.log.error(err_str)
            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
        else:
            self.set_validation_results(sec_name)

        return

    def check_ipa_server_status(self):
        """Check IPA server Status"""

        err_code_list = []
        ipa_ve_code = self.validation_error_code['IPA_INFO']
        server_ve_code = self.validation_error_code['ipa_servers']
        ipa_server_ve_code = ipa_ve_code + ":" + server_ve_code
        err_code_list.append(ipa_server_ve_code)

        sec_name = "Check IPA Server(s) Status"

        ipa_info = self.ymlhelper.get_data_from_userinput_file(["IPA_INFO"])
        if ipa_info is None:
            return

        ipa_server = ['IPA_INFO', 'ipa_servers']
        ipa_server_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(ipa_server)

        server_unreach_list = []
        for item in ipa_server_info:
            server_reach_status = self.check_ipa_server_reachability(item)
            if server_reach_status:
                server_unreach_list.append(server_reach_status)

        if server_unreach_list:
            err_str = ', '.join(server_unreach_list)
            err_str = "IPA_SERVER(s) not reachable %s" % (err_str)
            self.log.error(err_str)
            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        else:
            self.set_validation_results(sec_name)

        return

    def check_ldap_for_vim_admins(self):
        '''Check LDAP for VIM admins'''

        error_found = 0
        err_code_list = []
        ss_ve_code = self.validation_error_code['vim_ldap_admins']
        url_ve_code = self.validation_error_code['ldap_uri']
        ss_url_ve_code = ss_ve_code + ":" + url_ve_code
        err_code_list.append(ss_url_ve_code)

        sec_name = "Check LDAP for VIM Admins"

        vim_ldap_sec = \
            self.ymlhelper.get_data_from_userinput_file(["vim_ldap_admins"])
        if vim_ldap_sec is None:
            return

        ldap_uri_list = []
        err_list = []

        for item in vim_ldap_sec:
            ldap_info = item.get('ldap_uri')
            if ldap_info is not None:
                tmp = ldap_info.split(",")
                ldap_uri_list.extend(tmp)

        for item in ldap_uri_list:
            ldap_check = common.check_ldap_connectivity(item)
            if re.search(r'ERROR', ldap_check):
                err_list.append(ldap_check)
                error_found = 1

        if error_found:
            err_str = ', '.join(err_list)
            self.log.error(err_str)
            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        if not error_found:
            self.set_validation_results(sec_name)
        return

    def check_ext_server_for_cvim_mon(self):
        """Check external server for CVIM MON"""

        error_found = 0
        err_code_list = []
        ss_ve_code = self.validation_error_code['CVIM_MON']
        url_ve_code = self.validation_error_code['external_servers']
        ss_url_ve_code = ss_ve_code + ":" + url_ve_code
        err_code_list.append(ss_url_ve_code)

        sec_name = "Check Ext. Server Reachability for CVIMMON"

        cvim_mon_chk = self.ymlhelper.get_data_from_userinput_file(["CVIM_MON"])
        if cvim_mon_chk is None:
            return

        cvimmon_ext_serv_info = ['CVIM_MON', 'external_servers']

        cvimmon_ext_serv_chk = \
            self.ymlhelper.get_deepdata_from_userinput_file(cvimmon_ext_serv_info)

        if cvimmon_ext_serv_chk is None:
            return

        unreachable_ext_serv_list = []
        for item in cvimmon_ext_serv_chk:
            if not common.is_ipv4v6_reachable(item):
                error_found = 1
                unreachable_ext_serv_list.append(item)

        if unreachable_ext_serv_list:
            err_str = "Server(s) %s targeted for montioring by CVIMMON are " \
                "not reachable" % '.'.join(unreachable_ext_serv_list)
            self.log.error(err_str)
            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        if not error_found:
            self.set_validation_results(sec_name)

        return

    def check_ldap_for_cvim_mon(self):
        '''Check LDAP for CVIMMON'''

        error_found = 0
        err_code_list = []
        ss_ve_code = self.validation_error_code['CVIM_MON']
        url_ve_code = self.validation_error_code['domain_mappings']
        ss_url_ve_code = ss_ve_code + ":" + url_ve_code
        err_code_list.append(ss_url_ve_code)

        sec_name = "Check LDAP servers provided for CVIMMON"

        cvim_mon_chk = self.ymlhelper.get_data_from_userinput_file(["CVIM_MON"])
        if cvim_mon_chk is None:
            return

        cvimmon_ldap_info = ['CVIM_MON', 'ldap']

        cvimmon_ldap_chk = \
            self.ymlhelper.get_deepdata_from_userinput_file(cvimmon_ldap_info)

        if cvimmon_ldap_chk is None:
            return

        domain_info = cvimmon_ldap_chk.get('domain_mappings')

        ldap_uri_list = []
        err_list = []
        for item in domain_info:
            ldap_info = item.get('ldap_uri')
            if ldap_info is not None:
                tmp = ldap_info.split(",")
                ldap_uri_list.extend(tmp)

        for item in ldap_uri_list:
            ldap_check = common.check_ldap_connectivity(item)
            if re.search(r'ERROR', ldap_check):
                err_list.append(ldap_check)
                error_found = 1

        if error_found:
            err_str = ', '.join(err_list)
            self.log.error(err_str)
            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        if not error_found:
            self.set_validation_results(sec_name)
        return

    def check_cvimmon_nodes_status(self, ks_config, node):
        '''Checks if all the other nodes are in ready status'''
        kubectl_cmd = "/usr/bin/kubectl get nodes --no-headers"
        child = subprocess.Popen(kubectl_cmd.split(),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        response = child.communicate()[0]
        node_status = response.strip().split("\n")
        rc = child.returncode
        if rc == 1:
            err_str = "Could not get node status from Kubernetes"
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False

        faulty_nodes = filter(lambda s: not(' Ready ' in s or node in s),
                              node_status)

        faulty_node_names = [x.split(' ')[0] for x in faulty_nodes]
        if faulty_node_names:
            err_str = "The following nodes are not in Ready state. Please "\
                      "run remove-worker or replace-master to rectify them: "\
                      "%s" % ','.join(faulty_node_names)

            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False
        return True

    def check_swiftstack_server_status(self):
        '''Checks for Swiftstack server connectivity'''

        error_found = 0
        sec_name = "Check SwiftStack status"
        err_code_list = []

        ss_info = self.ymlhelper.get_data_from_userinput_file(["SWIFTSTACK"])
        if ss_info is None:
            return

        ss_ve_code = self.validation_error_code['SWIFTSTACK']
        url_ve_code = self.validation_error_code['cluster_api_endpoint']
        ss_url_ve_code = ss_ve_code + ":" + url_ve_code
        err_code_list.append(ss_url_ve_code)

        ss_endpoint = ss_info.get('cluster_api_endpoint')
        ss_protocol = ss_info.get('protocol')
        input_contents = ss_endpoint.split("/")
        ss_url = ss_protocol + "://" + input_contents[0] + "/console/"

        complete_cmd = ['/usr/bin/curl', '-v', '-k', '%(url)s' % {'url': ss_url}]

        response = subprocess.Popen(complete_cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
        output = response.stdout.read()

        pat1 = "Failed connect to"
        pat2 = "Operation timed out"
        pat3 = "HTTP.* 400 Bad Request"
        pat4 = "Issuer certificate is invalid"
        pat5 = "Could not resolve host"
        pat_str = pat1 + "|" + pat2 + "|" + pat3 + "|" + pat4 + "|" + pat5

        for item in output.splitlines():
            if re.search(pat_str, item):
                err_str = "Check IP connectivity to SwiftStack from Mgmt Node; " + \
                          " ERROR info: " + item.strip()
                error_found = 1
            elif re.search(r'HTTP.* 200 OK', item):
                break

        if error_found:
            self.log.error(err_str)
            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        if not error_found:
            self.set_validation_results(sec_name)
        return

    def cimc_get_version(self):
        """
        Get the CIMC version
        """
        # storing the xml handle, first entry
        version = None
        api_connection = self.__cimc_get_api_connection()

        if api_connection is not None:
            output = api_connection.get_firmware_version()
            if output is None:
                return version
            else:
                version = {}
                versions = str(output).split('.')
                major = versions[1]
                minor = versions[3]
                version['major'] = float(major)
                version['minor'] = minor

        return version

    def check_api_host_connectivity(self, apic_ip, check_type="l3out"):
        '''checks if each apic host can be reached
        return values: login_status and test_status
            1 : success
            0: fail
            2: Skip'''

        apicinfo = self.ymlhelper.get_data_from_userinput_file(['APICINFO'])
        vmtp_present = \
            self.ymlhelper.get_data_from_userinput_file(['VMTP_VALIDATION'])

        if check_type == 'external' and vmtp_present is None:
            return 1, 2

        ext_net_name = 'UNKNOWN'
        if vmtp_present is not None and check_type == 'external':
            ext_net_section = vmtp_present.get('EXT_NET')
            if ext_net_section is None:
                return 1, 2
            else:
                ext_net_name = ext_net_section.get('NET_NAME')

        apic_uname = apicinfo.get('apic_username')
        apic_pwd = apicinfo.get('apic_password')

        apicapi_hdl = apic_api.APICAPI(apic_ip, apic_uname, apic_pwd)
        login_stat = apicapi_hdl.do_login()
        if login_stat != 200:
            return 0, 0

        apic_response = ""
        apic_l3out = apicinfo.get('api_l3out_network', None)
        if check_type == 'l3out' and apic_l3out is not None:
            apic_tenant = apicinfo.get('apic_installer_tenant')
            apic_response = apicapi_hdl.query_l3out_network(apic_tenant, apic_l3out)

        if check_type == 'external':
            apic_response = apicapi_hdl.query_l3out_network("common", ext_net_name)

        if check_type == 'version_check':
            apic_full_response = apicapi_hdl.get_apic_version()
            apic_response = apic_full_response[apic_ip].decode()

        if check_type == 'opflex_client_auth':
            apic_response = apicapi_hdl.opflexp_client_auth()

        apicapi_hdl.do_logout()

        if apic_response is None:
            return 1, 0

        if check_type == 'opflex_client_auth':
            if apic_response is False:
                return 1, 1

            return 1, 0

        if check_type == 'version_check':
            if not apic_response or apic_response == 'None':
                self.log.error("Missing APIC version on <%s>", apic_ip)
                return 1, 0

            return self.apic_version_check(apic_ip, apic_response)

        if not self.ymlhelper.check_api_response(apic_response):
            err_msg = "ERROR: Invalid API response for %s via %s; " \
                "Response details:%s" \
                % (check_type, apic_ip, apic_response)
            self.log.info(err_msg)
            return 1, 0

        return 1, 1

    def apic_version_check(self, apic_ip, apic_response):
        '''APIC version check'''

        deci_num_checker = re.compile(r"""^[0-9]+(\.[0-9]{1,2})?$""")
        apic_version = {}
        apic_res_str = str(apic_response).decode()
        major, minor = str(apic_res_str).split('(')
        apic_version['minor'] = minor.replace(')', '')
        apic_major_version = \
            self.cfgmgr.parsed_defaults.parsed_config['APIC_MIN_VERSION']

        try:
            apic_version['major'] = major
        except ValueError, e:
            err_msg = "Found error: %s for %s" % (e, major)
            self.log.info(err_msg)
            return 1, 0

        if not apic_version['major']:
            self.log.error("Missing major APIC version on <%s>",
                           apic_ip)
            return 1, 0

        elif not apic_version['minor']:
            self.log.error("Missing minor APIC version on <%s>",
                           apic_ip)
            return 1, 0

        elif not deci_num_checker.match(str(apic_version['major'])):
            self.log.error("Incorrect major APIC version syntax on <%s>: %s",
                           apic_ip, apic_version['major'])
            return 1, 0

        elif apic_version['major'] != str(apic_major_version):
            self.log.error("Incorrect Major APIC version on <%s>: %s, " \
                "expected version:%s", apic_ip, apic_version['major'], \
                apic_major_version)
            return 1, 0

        return 1, 1

    def check_vmtp_gw_connectivity(self):
        """Check VMTP GW connectivity"""

        err_code_list = []
        ignore_ve_code = self.validation_error_code['IGNORE_GW_PING']
        err_code_list.append(ignore_ve_code)

        sec_name = "VMTP Gateway Reachability Check"
        vmtp_present = \
            self.ymlhelper.get_data_from_userinput_file(['VMTP_VALIDATION'])
        if vmtp_present is None:
            return

        error_found = 0
        msg_list = []
        ext_net_section = vmtp_present.get('EXT_NET', None)

        ignore_gw_ping = \
            self.ymlhelper.get_data_from_userinput_file(['IGNORE_GW_PING'])

        if ext_net_section is not None:
            ext_net_gw = ext_net_section.get('NET_GATEWAY')

            if ignore_gw_ping is not None and ignore_gw_ping \
                    and not common.is_ip_reachable(ext_net_gw):
                msg = "WARNING: VMTP Gateway %s is not reachable" % ext_net_gw
                msg_list.append(msg)

            error_found = 1

        prov_net_section = vmtp_present.get('PROV_NET', None)
        if prov_net_section is not None:
            prov_net_gw = prov_net_section.get('NET_GATEWAY')

            if ignore_gw_ping is not None and ignore_gw_ping \
                    and not common.is_ipv4v6_reachable(prov_net_gw):
                msg = "WARNING: VMTP provider network Gateway %s is not " \
                    "reachable" % prov_net_gw
                msg_list.append(msg)

            error_found = 1

        if error_found:
            msg = ",".join(msg_list)
            self.set_validation_results(sec_name, status=STATUS_PASS,
                                        err=msg,
                                        error_code_list=err_code_list)
            return

        self.set_validation_results(sec_name)
        return

    def check_apic_hosts_connectivity(self):
        '''Check APIC hosts connectivity'''

        err_code_list = []
        apicinfo_ve_code = self.validation_error_code['APICINFO']
        apichosts_ve_code = self.validation_error_code['apic_hosts']
        apic_combo_ve_code = apicinfo_ve_code + ":" + apichosts_ve_code
        err_code_list.append(apic_combo_ve_code)
        apic_major_version = \
            self.cfgmgr.parsed_defaults.parsed_config['APIC_MIN_VERSION']

        sec_name = "Check APIC Hosts Connectivity"
        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        auto_tor_via_aci = self.cfgmgr.extend_auto_tor_to_aci_fabric()

        if (mechanism_driver != 'aci') and (not auto_tor_via_aci):
            return

        pod_type = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        if pod_type is not None and \
                (pod_type == 'UMHC' or pod_type == 'NGENAHC'):
            return

        apic_check_type = ['version_check']
        apicinfo = self.ymlhelper.get_data_from_userinput_file(['APICINFO'])

        vmtp_present = \
            self.ymlhelper.get_data_from_userinput_file(['VMTP_VALIDATION'])
        ext_net_name = 'UNKNOWN'
        if vmtp_present is not None:
            ext_net_section = vmtp_present.get('EXT_NET')
            if ext_net_section is not None:
                ext_net_name = ext_net_section.get('NET_NAME')
                apic_check_type.append('external')

        apic_l3out = apicinfo.get('api_l3out_network', None)
        if apic_l3out is not None:
            apic_check_type.append('l3out')

        if mechanism_driver == 'aci':
            apic_check_type.append('opflex_client_auth')

        apic_host_list = apicinfo.get('apic_hosts')

        if apic_host_list is None:
            err_str = "apic_hosts not defined in section APICINFO"
            self.log.error(err_str)
            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        apic_host_login_issue_list = []
        apic_host_l3out_issue_list = []
        apic_host_extobj_issue_list = []
        apic_host_ver_check_list = []
        opflex_client_auth_check_list = []

        for chk_item in apic_check_type:
            self.log.info("Executing apic connectivity check for %s" % (chk_item))
            for item in apic_host_list:
                login_stat, test_stat = \
                    self.check_api_host_connectivity(item, chk_item)

                if not login_stat:
                    if item not in apic_host_login_issue_list:
                        apic_host_login_issue_list.append(item)
                if chk_item == 'l3out' and test_stat == 0:
                    if item not in apic_host_l3out_issue_list:
                        apic_host_l3out_issue_list.append(item)
                elif chk_item == 'external' and test_stat == 0:
                    if item not in apic_host_extobj_issue_list:
                        apic_host_extobj_issue_list.append(item)
                elif chk_item == 'version_check' and test_stat == 0:
                    if item not in apic_host_ver_check_list:
                        apic_host_ver_check_list.append(item)
                elif chk_item == 'opflex_client_auth' and test_stat == 0:
                    if item not in opflex_client_auth_check_list:
                        opflex_client_auth_check_list.append(item)

        sec_name = "APIC Connectivity Check"
        if apic_host_login_issue_list:
            apic_host_login_issue_str = ','.join(apic_host_login_issue_list)
            err_str = "Login to apic_hosts: %s " \
                      "defined in APICINFO section FAILED" \
                      % (apic_host_login_issue_str)
            self.log.error(err_str)
            self.set_validation_results(sec_name, status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
        else:
            self.set_validation_results(sec_name)

        for chk_item in apic_check_type:
            if chk_item == 'opflex_client_auth':
                sec_name = "APIC Opflex Client Authentication"
                if opflex_client_auth_check_list:
                    opflex_client_auth_check_str = \
                        ','.join(opflex_client_auth_check_list)
                    err_str = "Opflex Client Authentication is not currently " \
                        "supported, please turn it off in %s under the option " \
                        "Systems -> System Settings -> Fabric Wide Setting" \
                        % (opflex_client_auth_check_str)
                    self.log.error(err_str)
                    self.set_validation_results(sec_name, status=STATUS_FAIL,
                                                err=err_str,
                                                error_code_list=err_code_list)
                else:
                    self.set_validation_results(sec_name)

            if chk_item == 'l3out':
                sec_name = "APIC api_l3out_network object check"
                if apic_host_l3out_issue_list:
                    apic_host_l3out_issue_str = ','.join(apic_host_l3out_issue_list)
                    err_str = "%s object missing from apic_hosts: %s " \
                        "defined in APICINFO section " \
                        % (apic_l3out, apic_host_l3out_issue_str)
                    self.log.error(err_str)
                    self.set_validation_results(sec_name, status=STATUS_FAIL,
                                                err=err_str,
                                                error_code_list=err_code_list)
                else:
                    self.set_validation_results(sec_name)

            if chk_item == 'external':
                sec_name = "APIC external object check"
                if apic_host_extobj_issue_list:
                    apic_host_extobj_issue_str = \
                        ','.join(apic_host_extobj_issue_list)
                    err_str = "%s object missing from apic_hosts: %s " \
                        "defined in APICINFO section" \
                        % (ext_net_name, apic_host_extobj_issue_str)
                    self.log.error(err_str)

                    self.set_validation_results(sec_name, status=STATUS_FAIL,
                                                err=err_str,
                                                error_code_list=err_code_list)
                else:
                    self.set_validation_results(sec_name)

            if chk_item == 'version_check':
                sec_name = "APIC Version Check"
                expt_str = "; Expected Major Version: %s" \
                    % (apic_major_version)
                if apic_host_ver_check_list:
                    err_str = "APIC version check Failed for: %s " \
                              % (apic_host_ver_check_list) + expt_str
                    self.log.error(err_str)

                    self.set_validation_results(sec_name, status=STATUS_FAIL,
                                                err=err_str,
                                                error_code_list=err_code_list)
                else:
                    self.set_validation_results(sec_name)
        return

    def check_es_remote_snapshot_status(self):
        '''Check the remote snapshot status'''
        sec_name = "Elasticsearch remote check"
        with open(self.setup_file) as f:
            try:
                dic = yaml.safe_load(f)
            except yaml.error.YAMLError as err:
                self.log_error("Error[%s] Failed to load file '%s'" %
                               (err, self.setup_file))
                self.set_validation_results(sec_name, status=STATUS_FAIL,
                                            err=err)
                return
        if not dic.get('ES_REMOTE_BACKUP'):
            self.set_validation_results(sec_name)
            return

        # Check if we have access to the remote path from local
        fname = "/mnt/es_remote/es_backup/test1"
        try:
            f = open(fname, 'a')
        except IOError as e:
            err = "Failed(%s) to open file in nfs local path" % str(e)
            self.log.error(err)
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=err)
        else:
            with f:
                try:
                    os.utime(fname, None)
                    os.remove(fname)
                except Exception as e:
                    err = "Error[%s] validating es_remote" % str(e)
                    self.log.error(err)
                    self.set_validation_results(sec_name, status=STATUS_FAIL, err=err)
                    return

        # Check if elasticsearch container has permisions to
        # write in the NFS location
        cmd = "/usr/bin/docker ps"
        try:
            output = subprocess.check_output(cmd.split())
        except subprocess.CalledProcessError as e:
            err = "Could not get list of docker containers"
            self.log.error(err)
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=err)
            return

        c_name = ''
        for line in output.splitlines():
            if "elasticsearch" in line:
                c_name = line.split()[-1]
        if not c_name:
            err = "Could not get the elasticsearch number configured"
            self.log.error(err)
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=err)
            return

        err = ("Don't have write permissions to write under the NFS path. "
               "Make sure user 2020 and group 500 have read and write permissions "
               "the files on the remote path/server.")
        fname = '/mnt/es_remote/es_backup/test2'
        cmd = "/usr/bin/docker exec %s touch %s" % (c_name, fname)
        try:
            _ = subprocess.check_output(cmd.split())
        except subprocess.CalledProcessError as e:
            err = ("Error[%s]: %s" % (cmd, err))
            self.log.error("Error[%s]: %s" % (cmd, err))
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=err)
            return

        try:
            os.remove(fname)
        except Exception as e:
            err = "Error[%s] trying to remove temporal file for es remote" % str(e)
            self.log.err(err)
            self.set_validation_results(sec_name, status=STATUS_FAIL, err=err)
            return
        self.set_validation_results(sec_name)
        return

    def check_web_server_status(self, target_type="Cobbler", port_no=0):
        '''
        Verify if the web server for the given target is up
        '''

        sec_name = target_type + " Server Status"
        found_error = 0
        chk_config = sec_name
        ret_value = self.cfgmgr.get_build_node_ip('management')
        api_ret_value = self.get_mgmt_node_info('br_api')

        if not api_ret_value:
            self.log.error("Incorrect %s value in setup data", api_ret_value)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=sec_name +
                                        " br_api value not found")
            return

        if self.vault_config is not None and self.vault_config['enabled'] \
                and not self.skip_vault:
            kibana_pwd = self.hvac_client.read(VAULT_SECRETS_PATH + \
                '/KIBANA_PASSWORD')['data']['data']['value']
            cvim_mon = self.ymlhelper.get_data_from_userinput_file(["CVIM_MON"])
            if cvim_mon and cvim_mon.get('enabled', False) and \
                    not cvim_mon.get('central', False):
                cvim_mon_server_pwd = self.hvac_client.read(VAULT_SECRETS_PATH + \
                    '/CVIM_MON_SERVER_PASSWORD')['data']['data']['value']
                cvim_mon_pwd = self.hvac_client.read(VAULT_SECRETS_PATH + \
                    '/CVIM_MON_PASSWORD')['data']['data']['value']
        else:
            parsed_secrets_file = config_parser.YamlHelper(
                user_input_file=self.secrets_file)
            kibana_pwd = parsed_secrets_file.get_data_from_userinput_file(\
                ['KIBANA_PASSWORD'])
            cvim_mon_server_pwd = parsed_secrets_file.get_data_from_userinput_file(
                ['CVIM_MON_SERVER_PASSWORD'])
            cvim_mon_pwd = parsed_secrets_file.get_data_from_userinput_file(
                ['CVIM_MON_PASSWORD'])

        if ret_value is None:
            found_error = 1
            self.log.error("%s IP not found in setup data", target_type)
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=sec_name + " MissingIP for " +
                                        target_type + " provided")
        else:
            try:
                ip_addr = ipaddr.IPAddress(ret_value)
                if ip_addr.version == 6:
                    ip_addr = "[%s]" % ip_addr
                api_ip_addr = ipaddr.IPAddress(api_ret_value)
                if api_ip_addr.version == 6:
                    api_ip_addr = "[%s]" % api_ip_addr

                if re.search(r'Cobbler', target_type, re.IGNORECASE):
                    url = ("http://%s/repofiles/mercury-rhel.repo" % str(ip_addr))
                    complete_cmd = [url]

                elif re.search(r'kibana', target_type, re.IGNORECASE):
                    url = ("https://admin:%s@%s:%s/status" %
                           (str(kibana_pwd), str(api_ip_addr), str(port_no)))
                    complete_cmd = ['/usr/bin/curl', '-Ik', url]

                elif re.search(r'Prometheus', target_type, re.IGNORECASE):
                    url = ("https://admin:%s@%s:%s/status" % \
                        (str(cvim_mon_server_pwd), str(api_ip_addr), str(port_no)))
                    complete_cmd = ['/usr/bin/curl', '-ikv', url]

                elif re.search(r'Alertmanager', target_type, re.IGNORECASE):
                    url = ("https://admin:%s@%s:%s/#/status" % \
                        (str(cvim_mon_server_pwd), str(api_ip_addr), str(port_no)))
                    complete_cmd = ['/usr/bin/curl', '-ikv', url]

                elif re.search(r'ElasticSearch', target_type, re.IGNORECASE):
                    url = "http://localhost:" + str(port_no)
                    complete_cmd = ['/usr/bin/curl', '-Ik', url]

                elif re.search(r'Docker', target_type, re.IGNORECASE):
                    url = "systemctl status docker"
                    complete_cmd = ['systemctl', 'status', 'docker']

                elif re.search(r'Grafana', target_type, re.IGNORECASE):
                    url = ("https://admin:%s@%s:%s" % \
                        (str(cvim_mon_pwd), str(api_ip_addr), str(port_no)))
                    complete_cmd = ['/usr/bin/curl', '-ikv', url]

                else:
                    url = ("http://%s:%s" % (str(ip_addr), str(port_no)))
                    complete_cmd = [url]

                process_str = \
                    'kibana|elasticsearch|docker|prometheus|alertmanager|grafana'
                count = 1
                tot_count = 60
                sleep_time = 10
                while count <= tot_count:
                    found_error = 0
                    try:
                        if re.search(process_str, target_type, re.IGNORECASE):

                            response = subprocess.Popen(complete_cmd,
                                                        stdout=subprocess.PIPE,
                                                        stderr=subprocess.STDOUT)
                            output = response.stdout.read()

                            if re.search(r'docker',
                                         target_type, re.IGNORECASE):
                                service_status = 0
                                look_for = 'active.*running'
                                for item in output.splitlines():
                                    if re.search(look_for, item):
                                        service_status = 1
                                        break

                                if not service_status:
                                    found_error = 1
                                    if count == tot_count:
                                        self.log.error("Service %s not Up for %s:", \
                                                       url, target_type)

                                        self.set_validation_results(chk_config,
                                                                    status=STATUS_FAIL,
                                                                    err=sec_name +
                                                                    " is not up, "
                                                                    "FAILED")

                            elif not self.is_apache_up(output):
                                found_error = 1
                                if count == tot_count:
                                    self.log.error("Web Server %s not Up for %s:", \
                                                   url, target_type)

                                    self.set_validation_results(chk_config,
                                                                status=STATUS_FAIL,
                                                                err=sec_name +
                                                                " is not up, FAILED")

                        else:
                            _ = urllib2.urlopen(url)  # nosec safe url only

                    except urllib2.HTTPError, e:
                        found_error = 1
                        if count == tot_count:
                            self.log.error("Web Server %s not Up for %s: error %s", \
                                           url, target_type, e.code)
                            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                        err=sec_name + " " + url +
                                                        " Failed " + str(e.code))
                    except urllib2.URLError, e:
                        found_error = 1
                        if count == tot_count:
                            self.log.error("Web Server %s not Up for %s: error %s", \
                                           url, target_type, e.reason)
                            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                        err=sec_name + " " + url +
                                                        " Failed " + str(e.reason))

                    count += 1
                    if not found_error:
                        break
                    else:
                        self.log.info("Will re-check %s status, "
                                      "Attempt Count:%s/%s", \
                                      target_type, count, tot_count)
                        time.sleep(sleep_time)

            except ValueError:
                found_error = 1
                self.log.error("Incorrect %s value in setup data", ret_value)
                self.set_validation_results(chk_config, status=STATUS_FAIL,
                                            err=sec_name +
                                            "Wrong " + target_type +
                                            " value of " + ret_value +
                                            " provided")

        if not found_error:
            self.set_validation_results(sec_name)
        return

    def check_ironic_inventory_yaml(self, target_type="Ironic Inventory File"):
        '''
        Verify ironic_inventory.yaml
        '''
        sec_name = target_type + " validation"

        homedir = os.path.expanduser("~")
        cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)
        ipmi_inv_file = os.path.join(cfg_dir, hw_validations.DEFAULT_IPMI_FILE)
        if not os.path.exists(ipmi_inv_file):
            warn_msg = "WARNING: Missing ironic_inventory.yaml when optional" + \
                       " service ironic is enabled. Please look at " + \
                       "ironic_inventory.yaml.EXAMPLE and add the file."
            self.set_validation_results(sec_name, status=STATUS_PASS, err=warn_msg)
        else:
            hw_validator = hw_validations.HWValidator(ironic=True)
            hw_status = hw_validator.validate_hw_details(ironic_validation=True)

            if not hw_status.get('Hardware Validation'):
                self.set_validation_results(sec_name, status=STATUS_FAIL, \
                    err="Ironic H/W Validation Failed")
            else:
                hw_result_info = \
                    hw_status['Hardware Validation']['Overall_HW_Result']['status']
                if re.search(r'FAIL', hw_result_info):
                    self.set_validation_results(sec_name, status=STATUS_FAIL, \
                        err="Ironic H/W Validation Failed")
                else:
                    self.set_validation_results(sec_name)

        return

    def get_testbed_type(self):
        '''Determine the testbed type being validated against'''

        standalone_check = self.ymlhelper.check_section_exists('CIMC-COMMON')
        ucsm_check = self.ymlhelper.check_section_exists('UCSMCOMMON')
        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        if standalone_check and ucsm_check:
            self.log.error("Both CIMC-COMMON (for C-series) and \
                           UCSMCOMMON for B series defined, Can't proceed")
            return "IncorrectInput"
        elif standalone_check is not None:
            return "StandAlone"
        elif ucsm_check is not None:
            return "UCSM"
        elif podtype is not None and podtype == 'CVIMMONHA':
            return "CVIMMONHA"
        else:
            self.log.error("Neither CIMC-COMMON (for C-series) or \
                           UCSMCOMMON for B series defined, Can't proceed")
            return "InvalidInput"

    def get_vts_option(self):
        '''Gets VTS option'''
        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])
        vts_params = \
            self.ymlhelper.check_section_exists('VTS_PARAMETERS')
        if (mechanism_driver == 'vts') and vts_params:
            return 1
        else:
            return 0

    def findDiff2(self, d1, d2, return_list, path=""):
        '''Recursively Diffs the Networking dict'''

        for k in d1.keys():
            if k not in d2:
                continue
            else:
                if isinstance(d1[k], dict):
                    if path == "":
                        path = k
                    else:
                        path = path + "->" + k
                    self.findDiff2(d1[k], d2[k], return_list, path)
                else:
                    if d1[k] != d2[k]:
                        return_list.append(k)
        return

    def diffList(self, list1, list2):
        '''finds difference between 2 lists'''
        return list(set(list1) - set(list2))

    def findDiffKeys(self, d1, d2, return_list, ctx=""):
        '''find diff in Key'''
        try:
            for k in d1.keys():
                if k not in d2:
                    return_list.append(str(k))
            for k in d2.keys():
                if k not in d1:
                    return_list.append(str(k))
                    continue
                if d2[k] != d1[k]:
                    if isinstance(d2[k], dict):
                        self.findDiffKeys(d1.get(k), d2.get(k), return_list, k)
                        continue
        except AttributeError:
            return

        return

    def findDiffKey_Value(self, d1, d2, return_list, ctx=""):
        '''find diff in Key'''
        try:
            for k in d1.keys():
                if k not in d2:
                    return_list.append(str(k))
            for k in d2.keys():
                if k not in d1:
                    return_list.append(str(k))
                    continue
                if d2[k] != d1[k]:
                    if isinstance(d2[k], dict):
                        self.findDiffKeys(d1.get(k), d2.get(k), return_list, k)
                        continue
                else:
                    return_list.append(str(k))
        except AttributeError:
            return

        return

    def check_allowed_operations(self, curr_action,
                                 server_list=[]):
        '''Check if operation is allowed'''

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        ks_config = "Valid Operation Check"
        found_error = 0

        if podtype is not None and podtype == 'MGMT_CENTRAL' and \
                not re.match(r'add_vms|delete_vms|nodelist', curr_action):
            found_error = 1
            err_str = "%s not allowed for %s pod; Exiting!!!" % (curr_action, podtype)

        elif podtype is not None and re.match(r'micro', podtype) and \
                re.match(r'add_computes|remove_computes', curr_action):

            control_server_list = self.ymlhelper.get_server_list(role="control")
            ceph_server_list = self.ymlhelper.get_server_list(role="block_storage")
            invalid_server_list = []
            for server in server_list:
                if (server in control_server_list) or (server in ceph_server_list):
                    found_error = 1
                    if server not in invalid_server_list:
                        invalid_server_list.append(server)

            if found_error:
                err_str = "%s not allowed for %s in micropod, as it appear in " \
                    "multiple roles; Exiting!!!" \
                    % (curr_action, ','.join(invalid_server_list))

        elif podtype is not None and re.match(r'edge', podtype) and \
                re.match(r'add_computes|remove_computes', curr_action):

            control_server_list = self.ymlhelper.get_server_list(role="control")
            invalid_server_list = []
            for server in server_list:
                if (server in control_server_list):
                    found_error = 1
                    if server not in invalid_server_list:
                        invalid_server_list.append(server)

            if found_error:
                err_str = "%s not allowed for %s in edgepod, as it appear in " \
                    "multiple roles; Exiting!!!" \
                    % (curr_action, ','.join(invalid_server_list))

        elif podtype is not None and re.match(r'ceph', podtype) and \
                re.match(r'add_osd|remove_osd', curr_action):

            control_server_list = \
                self.ymlhelper.get_server_list(role="cephcontrol")
            invalid_server_list = []
            for server in server_list:
                if (server in control_server_list):
                    found_error = 1
                    if server not in invalid_server_list:
                        invalid_server_list.append(server)

            if found_error:
                err_str = "%s not allowed for %s in ceph pod, as it appear in " \
                    "multiple roles; Exiting!!!" \
                    % (curr_action, ','.join(invalid_server_list))

        elif podtype is not None and re.match(r'micro|edge|nano', podtype) and \
                re.match(r'add_osd|remove_osd', curr_action):
            found_error = 1
            err_str = "%s not allowed for %spod; Exiting!!!" % (curr_action, podtype)

        elif podtype is not None and re.match(r'ceph|nano', podtype) and \
                re.match(r'add_computes|remove_computes', curr_action):
            found_error = 1
            err_str = "%s not allowed for %spod; Exiting!!!" % (curr_action, podtype)

        elif podtype is not None and re.match(r'UMHC|NGENAHC|nano', podtype) and \
                re.match(r'add_computes|remove_computes', curr_action):
            invalid_ceph_srv_list = []

            ceph_server_list = self.ymlhelper.get_server_list(role="block_storage")

            if re.match(r'remove_computes', curr_action):
                # Read the info from backup as that is how we can find out the
                # true storage list from before
                with open(self.backup_setup_file, 'r') as f:
                    try:
                        doc_backup = yaml.safe_load(f)
                    except yaml.parser.ParserError as e:
                        found_error = 1
                    except yaml.scanner.ScannerError as e:
                        found_error = 1

                if found_error:
                    err_str = "InCorrect baseline setup_data.yaml syntax; \
                              Error Info: " + str(e)
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False

                if 'ROLES' in doc_backup.keys():
                    role_info = doc_backup['ROLES']
                    if 'block_storage' in role_info.keys():
                        ceph_server_list = doc_backup['ROLES']['block_storage']

            for serv in server_list:
                if serv in ceph_server_list:
                    invalid_ceph_srv_list.append(serv)

            if invalid_ceph_srv_list:
                found_error = 1
                err_str = "Cannot do %s of %s ceph servers: %s. " \
                    "Please try ceph management of UMHC/NGENAHC nodes" \
                    % (curr_action, podtype, ", ".join(invalid_ceph_srv_list))

        if found_error:
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False

        self.set_validation_results(ks_config)
        return True

    def report_unsupported_keys(self, filename):
        '''YAML look for unsupported Keys'''

        expected_keys = self.validation_error_code.keys()
        extra_keys_found = []

        servers = self.ymlhelper.get_data_from_userinput_file(['SERVERS'])
        torswitchinfo = \
            self.ymlhelper.get_data_from_userinput_file(['TORSWITCHINFO'])

        ironic_torswitchinfo = \
            self.ymlhelper.get_data_from_userinput_file(['IRONIC'])

        sriov_mvlan_trunk_info = \
            self.ymlhelper.get_data_from_userinput_file(['SRIOV_MULTIVLAN_TRUNK'])

        if self.cvimmonha_setup:
            argus_list = []
            argus_info = self.get_data_from_cvimmonha_setup('ARGUS_BAREMETAL', self.cvimmonha_setup)
            if argus_info:
                argus_site_info = self.get_data_from_cvimmonha_setup('SITE_CONFIG', argus_info)
                if argus_site_info:
                    argus_clusters_info = self.get_data_from_cvimmonha_setup('clusters', argus_site_info)
                    if argus_clusters_info:
                        argus_servers = argus_clusters_info[0].get('servers', None)
                        if argus_servers is not None:
                            for matrix in argus_servers:
                                for keys in matrix['ip_address']:
                                    argus_list.append(keys)

        switch_list = []
        if torswitchinfo is not None:
            switchdetails = torswitchinfo.get('SWITCHDETAILS', None)
            if switchdetails is not None:
                for item in switchdetails:
                    curr_hostname = item.get('hostname')
                    if curr_hostname is not None and \
                            curr_hostname not in switch_list:
                        switch_list.append(curr_hostname)

        if ironic_torswitchinfo is not None:
            ironic_switchdetails = \
                ironic_torswitchinfo.get('IRONIC_SWITCHDETAILS', None)
            if ironic_switchdetails is not None:
                for item in ironic_switchdetails:
                    curr_hostname = item.get('hostname')
                    if curr_hostname is not None and \
                            curr_hostname not in switch_list:
                        switch_list.append(curr_hostname)

        sriov_mvlan_trunk_list = []
        if sriov_mvlan_trunk_info is not None:
            for item in sriov_mvlan_trunk_info:
                for key in item.iterkeys():
                    if key not in sriov_mvlan_trunk_info:
                        sriov_mvlan_trunk_list.append(key)

        vtep_ip_list = []
        curr_vtep_list = self.get_her_vtep_info('vxlan-ecn')
        if curr_vtep_list:
            vtep_ip_list.extend(curr_vtep_list)
        curr_vtep_list = self.get_her_vtep_info('vxlan-tenant')
        if curr_vtep_list:
            vtep_ip_list.extend(curr_vtep_list)

        def root_ctxt():
            '''root context'''
            return ('keys:',)

        def join_ctxt(ctxt, ct):
            '''joins the recursion'''
            return ctxt + (ct,)

        def process_modelnode(ctxt, node):
            '''Processes the modelnode'''
            if isinstance(node, ScalarNode):
                return node.value
            elif isinstance(node, SequenceNode):
                return process_listnodes(ctxt, node.value)
            elif isinstance(node, MappingNode):
                ks = process_mapnodes(ctxt, node.value)
                # This is a list k, v, k, v, ...
                # Should have unique k's
                u_ks = set(ks)
                for f in u_ks:
                    if f not in expected_keys and \
                            f not in extra_keys_found:
                        if servers is not None:
                            if f in servers.keys() or f in switch_list \
                                    or f in sriov_mvlan_trunk_list or \
                                    f in vtep_ip_list:
                                pass
                            else:
                                extra_keys_found.append(f)
                        '''else:
                            if f in cvim_mon_ha_list or f in argus_list:
                                pass
                            else:
                                extra_keys_found.append(f)'''

        def process_listnodes(ctxt, nodes):
            '''Process the nddes locally'''
            vals = []
            for ct, node in zip(xrange(0, len(nodes)), nodes):
                vals.append(process_modelnode(join_ctxt(ctxt, '[%d]' % ct), node))
            return vals

        def process_mapnodes(ctxt, nodes):
            '''Processes each section in recursion'''
            ks = []
            for k, v in nodes:
                k = process_modelnode(join_ctxt(ctxt, ' - key name'), k)
                ks.append(k)
                v = process_modelnode(join_ctxt(ctxt, "{'%s'}" % str(k)), v)
            return ks

        with open(filename, 'r') as ff:
            model = yaml.compose(ff)

        process_modelnode(root_ctxt(), model)
        return extra_keys_found

    def check_for_valid_keys(self):
        '''Check to see if all keys are valid'''

        ks_config = "Check for Valid Keys"
        err_str = ""
        found_error = 0

        with open(self.setup_file, 'r') as f:
            try:
                doc = yaml.safe_load(f)
            except yaml.parser.ParserError as e:
                found_error = 1
            except yaml.scanner.ScannerError as e:
                found_error = 1

        if found_error:
            err_str = "InCorrect setup_data.yaml syntax; Error Info: " + str(e)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False

        expected_keys = self.validation_error_code.keys()
        extra_keys_found = []

        # will get us the sub keys as well
        unsupported_keys = self.report_unsupported_keys(self.setup_file)

        # get all the missing keys
        for key in doc.keys():
            if key not in expected_keys:
                extra_keys_found.append(key)

        for key in unsupported_keys:
            if key not in expected_keys and key not in extra_keys_found:
                extra_keys_found.append(key)

        if extra_keys_found:
            found_error = 1
            err_str = "Extra Keys found in setup_data.yaml: " + \
                      ','.join(extra_keys_found)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)

        if not found_error:
            self.set_validation_results(ks_config)

        return True

    def is_change_a_subset(self, key, target_tv, backup_tv):
        '''Checks if the change in tenant/provider VLAN is a subset'''

        target_vlan_list = common.expand_vlan_range(target_tv)
        backup_vlan_list = common.expand_vlan_range(backup_tv)

        # Check if VLAN is a subset of the backup_vlan_list
        missing_subset_entry = list(set(target_vlan_list) - set(backup_vlan_list))

        if missing_subset_entry:
            missing_subset_str_list = map(str, missing_subset_entry)
            missing_subset_str = ','.join(missing_subset_str_list)
            err_str = "Target %s:%s is not a sub or superset of the " \
                "original %s:%s; i.e. the new VLAN extensions have to " \
                "be defined either as new dedicated block on top of existing " \
                "block separated by a , e.g old_vlan_block,new_vlan_block " \
                "(a:b,c:d) or as a subset of the original; " \
                "VLANs not in the original list:%s" \
                % (key, target_tv, key, backup_tv, missing_subset_str)

            return err_str

        else:
            # Check and esnure that VLAN is not being used in the stack
            if key == 'L3_PROVIDER_VNI_RANGES':
                curr_vlans_in_use = []
            else:
                curr_vlans_in_use = self.cfgmgr.fetch_vlans_being_used()

            unconfig_vlan_list = list(set(backup_vlan_list) - set(target_vlan_list))

            vlans_still_being_used = \
                list(set(curr_vlans_in_use) & set(unconfig_vlan_list))

            vlans_still_being_used_str_list = map(str, vlans_still_being_used)
            vlans_still_being_used_str = ','.join(vlans_still_being_used_str_list)
            if vlans_still_being_used:
                err_str = "Unconfigure of %s is not possible as the following " \
                    "vlan(s) %s is/are still being used" \
                    % (key, vlans_still_being_used_str)
                return err_str

            return ""

    def check_tv_entry_change(self, key, target_tv, backup_tv):
        '''Checks if the change in tenant VLAN change is a superset'''

        err_str = "Target %s:%s is not a syntactical superset of the " \
                  "original %s:%s; i.e. the new VLAN extensions have to " \
                  "be defined as new dedicated block on top of existing " \
                  "block separated by a , e.g old_vlan_block,new_vlan_block " \
                  "(a:b,c:d)" % (key, target_tv, key, backup_tv)

        if not re.search(r',', str(target_tv)) and \
                str(target_tv) != str(backup_tv):
            self.log.info(err_str)
            return err_str

        target_tv_list = [x.strip() for x in target_tv.split(',')]
        backup_tv_list = [x.strip() for x in backup_tv.split(',')]

        missing_tv_list = []
        for item in backup_tv_list:
            if item.strip() not in target_tv_list:
                missing_tv_list.append(item)

        if missing_tv_list:
            self.log.info(err_str)
            return err_str

        return ""

    def validate_server_change(self, action,
                               curr_setup_dict,
                               backup_setup_dict,
                               rma_tor_list):
        '''Validate SERVER changes'''

        unmatched_server_list = []
        unsupported_change_list = []
        tmp_key_diff_list = []

        chk_str = ""
        for k, _ in curr_setup_dict.items():
            if backup_setup_dict.get(k) is None:
                unmatched_server_list.append(k)
                continue

            else:
                self.diffDict(curr_setup_dict[k],
                              backup_setup_dict[k],
                              tmp_key_diff_list)

        if action == 'reconfigure' and rma_tor_list:
            if unmatched_server_list:
                chk_str = "ERROR: Cannot add/remove server %s info " \
                    "during RMA of TOR" % (','.join(unmatched_server_list))
                return chk_str

            for item in tmp_key_diff_list:
                if not re.search(r'tor_info|dp_tor_info|sriov_tor_info', item):
                    if item not in unsupported_change_list:
                        unsupported_change_list.append(item)

            if unsupported_change_list:
                chk_str = "ERROR: Cannot change %s info " \
                    "during RMA of TOR" % (','.join(unsupported_change_list))
                return chk_str

        return chk_str

    def validate_tor_change(self, curr_setup_dict,
                            backup_setup_dict,
                            rma_tor_list=[]):
        '''validates TOR config changes'''

        change_not_allowed = []

        tmp_list = []
        missed_rma_tor = []
        curr_swt_hostname = []
        bkup_swt_hostname = []

        schema_validator = schema_validation.SchemaValidator(self.setup_file, \
                                                             "reconfigure")
        peer_switch_info = schema_validator.get_tor_switch_peer_info()
        if not schema_validator.is_tor_config_enabled():
            tmp_str = 'RMA of TORS not allowed when CONFIGURE_TOR is False'
            change_not_allowed.append(tmp_str)
            return change_not_allowed

        for item1 in backup_setup_dict.get('SWITCHDETAILS'):
            if item1.get('hostname') not in bkup_swt_hostname:
                bkup_swt_hostname.append(item1.get('hostname'))

        for item2 in curr_setup_dict.get('SWITCHDETAILS'):
            if item2.get('hostname') not in curr_swt_hostname:
                curr_swt_hostname.append(item2.get('hostname'))

        for key in curr_setup_dict:
            if key == 'CONFIGURE_TORS':
                if curr_setup_dict.get(key) is True and \
                        curr_setup_dict.get(key) != backup_setup_dict.get(key):
                    diff_info = 'TORSWITCHINFO:' + key
                    change_not_allowed.append(diff_info)

            elif key == 'SWITCHDETAILS':
                for item1 in backup_setup_dict.get(key):

                    found_switch = 0
                    for item2 in curr_setup_dict.get(key):
                        if item1.get('hostname') == item2.get('hostname'):
                            found_switch = 1
                            sw_hostname = item1.get('hostname')
                            peer_hostname = peer_switch_info.get(sw_hostname)

                            if rma_tor_list and \
                                    (sw_hostname in rma_tor_list \
                                    or peer_hostname in rma_tor_list) \
                                    and item1 != item2:
                                pass
                            elif rma_tor_list and \
                                    (sw_hostname in rma_tor_list \
                                    or peer_hostname in rma_tor_list):
                                pass
                            elif item1 != item2 and sw_hostname not in tmp_list:
                                tmp_list.append(sw_hostname)
                            break

                    if not found_switch and rma_tor_list:
                        if item1.get('hostname') not in rma_tor_list:
                            found_switch = 1

                    if not found_switch:
                        sw_hostname = item1.get('hostname')
                        if sw_hostname is not None and sw_hostname not in tmp_list:
                            tmp_list.append(sw_hostname)

            elif key == 'TOR_TYPE':
                if curr_setup_dict.get(key) != backup_setup_dict.get(key):
                    diff_info = 'TORSWITCHINFO:' + key
                    change_not_allowed.append(diff_info)
            else:
                for item1 in backup_setup_dict.get(key):
                    for item2 in curr_setup_dict.get(key):
                        if item1 != item2 and key not in tmp_list:
                            tmp_list.append(key)
                        else:
                            break

        if tmp_list:
            tmp_str = ','.join(tmp_list)
            tmp_str = 'TORSWITCHINFO:' + tmp_str
            change_not_allowed.append(tmp_str)

        for key in backup_setup_dict:
            if key == 'CONFIGURE_TORS':
                if backup_setup_dict.get(key) is True and \
                        curr_setup_dict.get(key) != backup_setup_dict.get(key):
                    diff_info = 'TORSWITCHINFO:' + key
                    change_not_allowed.append(diff_info)


        # Ensure that new switches are part of RMA list
        if rma_tor_list:
            for item in curr_swt_hostname:
                if item not in rma_tor_list and \
                        item not in bkup_swt_hostname:
                    missed_rma_tor.append(item)

        if missed_rma_tor:
            tmp_str = ','.join(missed_rma_tor)
            tmp_str = 'Missing user supplied target RMA TORS:' + tmp_str
            change_not_allowed.append(tmp_str)

        return change_not_allowed

    def validate_tor_change_aci(self, curr_setup_dict,
                                backup_setup_dict,
                                rma_tor_list):
        '''validates TOR config changes'''

        change_not_allowed = []
        tmp_list = []
        missed_rma_tor = []

        curr_swt_hostname = []
        bkup_swt_hostname = []

        for item1 in backup_setup_dict.get('SWITCHDETAILS'):
            if item1.get('hostname') not in bkup_swt_hostname:
                bkup_swt_hostname.append(item1.get('hostname'))

        for item2 in curr_setup_dict.get('SWITCHDETAILS'):
            if item2.get('hostname') not in curr_swt_hostname:
                curr_swt_hostname.append(item2.get('hostname'))

        # every item of backup has to be in curr
        for item1 in backup_setup_dict.get('SWITCHDETAILS'):
            found_switch = 0
            for item2 in curr_setup_dict.get('SWITCHDETAILS'):
                if item1.get('hostname') == item2.get('hostname'):
                    found_switch = 1
                    sw_hostname = item1.get('hostname')
                    peer_hostname = item2.get('vpc_peer_keepalive')

                    if rma_tor_list and \
                            (sw_hostname in rma_tor_list \
                            or peer_hostname in rma_tor_list) \
                            and item1 != item2:
                        pass
                    elif rma_tor_list and \
                            (sw_hostname in rma_tor_list \
                            or peer_hostname in rma_tor_list):
                        pass
                    elif item1 != item2 and sw_hostname not in tmp_list:
                        tmp_list.append(sw_hostname)
                    break

            if not found_switch and rma_tor_list:
                if item1.get('hostname') not in rma_tor_list:
                    found_switch = 1

            if not found_switch:
                sw_hostname = item1.get('hostname')
                if sw_hostname is not None and sw_hostname not in tmp_list:
                    tmp_list.append(sw_hostname)

        if tmp_list:
            tmp_str = ','.join(tmp_list)
            tmp_str = 'SWITCHDETAILS:' + tmp_str
            change_not_allowed.append(tmp_str)

        # Ensure that new switches are part of RMA list
        if rma_tor_list:
            for item in curr_swt_hostname:
                if item not in rma_tor_list and \
                        item not in bkup_swt_hostname:
                    missed_rma_tor.append(item)

        if missed_rma_tor:
            tmp_str = ','.join(missed_rma_tor)
            tmp_str = 'Missing user supplied target RMA TORS:' + tmp_str
            change_not_allowed.append(tmp_str)

        return change_not_allowed


    def check_cimc_pwd_validity(self, cimc_dict_info):
        '''Checks that the CIMC password meets the criteria'''

        pwd_criteria = "Satisfy at least 3 of the following conditions: " \
            "at least 1 letter between a to z, " \
            "at least 1 letter between A to Z, " \
            "at least 1 number between 0 to 9, " \
            "at least 1 character from !$#@%^-_+=*&, " \
            "and password length between 8 and 20 characters."

        error_found = 0
        incorrect_cimc_pwd_list = []
        for host_name, host_info in cimc_dict_info.items():
            if len(host_info) != 3:
                err_str = "Missing info for %s " % (host_name)
                incorrect_cimc_pwd_list.append(err_str)
            else:
                p = host_info[2]
                match_count = 0

                if (len(p) >= 8 and len(p) <= 20):
                    match_count += 1
                    pwd_length_check = 1
                else:
                    pwd_length_check = 0
                    self.log.info("CIMC Password length needs to be " \
                        "between 8 and 20 characters for %s, " \
                        "found to be %s", host_name, len(p))

                if re.search("[a-z]", p):
                    match_count += 1
                else:
                    self.log.info("CIMC Password for %s needs to have, " \
                        "at least 1 letter between [a - z]" % host_name)

                if re.search("[0-9]", p):
                    match_count += 1
                else:
                    self.log.info("CIMC Password for %s needs to have, " \
                        "at least 1 number between [0 - 9]" % host_name)

                if re.search("[A-Z]", p):
                    match_count += 1
                else:
                    self.log.info("CIMC Password for %s needs to have, " \
                        "at least 1 letter between [A - Z]" % host_name)

                if re.search("[!$#@$%^-_+=*&]", p):
                    match_count += 1
                else:
                    char_info = '!$#@%^-_+=*&'
                    self.log.info("Password for %s needs to have, " \
                        "at least 1 character from %s", host_name, char_info)

                if match_count < 3 or (not pwd_length_check):
                    error_found = 1
                    incorrect_cimc_pwd_list.append(host_name)

        ks_config = "CIMC New Password Validity"
        if error_found:
            server_info = ', '.join(incorrect_cimc_pwd_list)
            err_str = "New CIMC Password Criteria for %s not met; " \
                "Expected CIMC Password Criteria to %s" \
                % (server_info, pwd_criteria)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False
        else:
            self.set_validation_results(ks_config)

        return True

    def diffDict(self, dict_a, dict_b, return_list):
        '''find differences between 2 dictionaries'''

        if (not isinstance(dict_a, dict) or not isinstance(dict_b, dict)):
            return

        diff = dict([
            (key, dict_b.get(key, dict_a.get(key)))
            for key in set(dict_a.keys() + dict_b.keys())
            if ((key in dict_a and \
                 (key not in dict_b or dict_a[key] != dict_b[key])) \
                or (key in dict_b and \
                    (key not in dict_a or dict_a[key] != dict_b[key]))) \
        ])

        if not diff:
            return
        for k in diff.keys():
            return_list.append(k)

    def splitter_opt_allowed(self, check_for, base_line, action):
        '''Ensure all entries of check_for are in the baseline'''

        err_str = "Input of None not allowed for " \
            "splitter_options with action:%s" % action

        if check_for is None:
            self.log.info(err_str)
            return err_str

        if base_line is None:
            self.log.info(err_str)
            return err_str

        check_for_list = check_for.split(",")

        item_list = []
        for item in check_for_list:
            if item not in base_line:
                self.log.info("Item:%s not found in %s for %s" \
                    % (item, base_line, action))
                item_list.append(item)

        if item_list:
            err_str = ','.join(item_list)
            return err_str

        return ""

    def check_server_info_diff(self,
                               server_info,
                               backup_server_info,
                               search_item,
                               enable_disable=0):
        '''Check if changes in SERVERS sub key are allowed'''

        invalid_change_list = []
        for item in server_info:
            curr_info = server_info[item].get(search_item)
            backup_info = backup_server_info[item].get(search_item)

            if curr_info is not None and backup_info is None \
                    and not enable_disable:
                pass
            elif curr_info is None and backup_info is not None \
                    and not enable_disable:
                if search_item not in invalid_change_list:
                    invalid_change_list.append(search_item)

        return invalid_change_list

    def check_hardware_info_diff(self,
                                 server_info,
                                 backup_server_info,
                                 search_pattern,
                                 skip_pattern):
        '''Check if changes in SERVERS sub key are allowed'''

        invalid_change_list = []
        for item in server_info:
            curr_info = server_info[item].get(search_pattern)
            backup_info = backup_server_info[item].get(search_pattern)

            if curr_info is not None and backup_info is None:
                for my_item in curr_info:
                    if not re.search(skip_pattern, my_item) and \
                            my_item not in invalid_change_list:
                        invalid_change_list.append(my_item)
            elif curr_info is None and backup_info is not None:
                for my_item in backup_info:
                    if not re.search(skip_pattern, my_item) and \
                            my_item not in invalid_change_list:
                        invalid_change_list.append(my_item)

            else:
                tmp_key_diff_list = []
                self.diffDict(curr_info, backup_info, tmp_key_diff_list)
                if tmp_key_diff_list:
                    for ind_item in tmp_key_diff_list:
                        if re.search(skip_pattern, ind_item):
                            continue
                        elif ind_item not in invalid_change_list:
                            invalid_change_list.append(ind_item)

        return invalid_change_list

    def tor_rma_sanity_check(self, rma_tor_list):
        '''Check if the RMA of the TORs supplied are valid'''
        # Check if TORs to be RMAed are not in pair
        # Check and ensure that the TORs are legit ones

        err_str = ""
        torswitchinfo = \
            self.ymlhelper.get_data_from_userinput_file(['TORSWITCHINFO'])

        if torswitchinfo is None:
            err_str = "ERROR: TORSWITCHINFO not defined for RMA of TOR"
            return err_str

        switch_list = []
        invalid_rma_swtich_list = []
        switchdetails = torswitchinfo.get('SWITCHDETAILS')
        for item in switchdetails:
            curr_hostname = item.get('hostname')
            if curr_hostname is not None and \
                    curr_hostname not in switch_list:
                switch_list.append(curr_hostname)

        if len(switch_list) == 1:
            err_str = "ERROR: Auto RMA of TOR where the POD is hanging " \
                "off 1 swtich not allowed"
            return err_str

        for item in rma_tor_list:
            if item not in switch_list:
                invalid_rma_swtich_list.append(item)

        if invalid_rma_swtich_list:
            err_str = "ERROR: Info for TORs:%s targeted for RMA not provided" \
                % (','.join(invalid_rma_swtich_list))
            return err_str

        schema_validator = schema_validation.SchemaValidator(self.setup_file, \
                                                             "reconfigure")
        peer_switch_info = schema_validator.get_tor_switch_peer_info()

        for item in rma_tor_list:
            curr_peer_swtich_info = peer_switch_info.get(item)
            if curr_peer_swtich_info is not None and \
                    curr_peer_swtich_info in rma_tor_list:
                invalid_rma_swtich_list.append(curr_peer_swtich_info)

        if invalid_rma_swtich_list:
            err_str = "ERROR: RMA of Peer TORs:%s not allowed" \
                % (','.join(invalid_rma_swtich_list))
            return err_str

        return err_str

    def vim_apic_nwrk_change(self, dict_item, list_of_backup_dict):
        '''' Check if vim_apic_nwrk_change allowed'''

        curr_vlan_id = dict_item.get('vlan_ids')
        is_input_l3 = dict_item.get('subnets')

        change_list = []
        # if any item other than vlan has changed we need to flag that as failure
        for item in list_of_backup_dict:
            backup_vlan_id = item.get('vlan_ids')
            if str(curr_vlan_id) == str(backup_vlan_id):
                tmp = "vim_apic_networks:" + str(curr_vlan_id)
                change_list.append(tmp)

        if is_input_l3 is None:
            for backup_item in list_of_backup_dict:
                backup_vlan_id = backup_item.get('vlan_ids')
                if re.search(backup_vlan_id, curr_vlan_id):
                    tmp_key_diff_list = []
                    self.diffDict(dict_item, backup_item, tmp_key_diff_list)
                    if len(tmp_key_diff_list) == 1 \
                            and 'vlan_ids' in tmp_key_diff_list:
                        continue
                    elif len(tmp_key_diff_list) > 1:
                        for entry in tmp_key_diff_list:
                            if 'vlan_ids' not in tmp_key_diff_list:
                                tmp = "vim_apic_networks:" \
                                      + str(curr_vlan_id) + ":" + str(entry)
                                change_list.append(tmp)

        return change_list

    def check_vtep_ip_consistency(self):
        '''Check vtep ip consistency'''

        err_msg = ""
        found_error = 0
        try:
            parsed_cobbler_file = config_parser.YamlHelper(
                user_input_file=self.cobbler_file)
            cobbler_dict = \
                parsed_cobbler_file.create_parsed_yaml(self.cobbler_file)

        except yaml.parser.ParserError as e:
            found_error = 1
            err_msg = str(e)
        except yaml.scanner.ScannerError as e:
            found_error = 1
            err_msg = str(e)

        if found_error:
            return "ERROR: %s" % (err_msg)

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        compute_list = self.ymlhelper.get_server_list(role="compute")

        if podtype is None or podtype == 'fullon':
            control_list = self.ymlhelper.get_server_list(role="control")
            compute_control_list = list(set(compute_list) | set(control_list))
        else:
            compute_control_list = copy.deepcopy(compute_list)

        cobbler_data = {}

        vxlan_ecn_setup_data = {}
        vxlan_tenant_setup_data = {}

        vxlan_tenant_cobbler = {}
        vxlan_ecn_cobbler = {}

        try:
            for host in compute_control_list:
                val = {k: cobbler_dict[host]['bonds'][k]['compute']['ipaddress']
                       for k in cobbler_dict[host]['bonds'] if k[:5] == 'vxlan'}
                cobbler_data[host] = val
        except Exception:
            err_str = "vxlan info for computes not generated in cobbler"
            return "ERROR: %s" % (err_str)

        server_info = \
            self.ymlhelper.get_data_from_userinput_file(\
                ['SERVERS'])

        if server_info is None:
            err_str = "SERVERS section missing in setup_data"
            return "ERROR: %s" % (err_str)

        for key, value in server_info.iteritems():
            if key in compute_control_list:
                vtep_ip_info = value.get('vtep_ips')
                if vtep_ip_info is not None:
                    vxlan_ecn_setup_data[key] = vtep_ip_info.get('vxlan-ecn')
                    vxlan_tenant_setup_data[key] = vtep_ip_info.get('vxlan-tenant')
                else:
                    vxlan_ecn_setup_data[key] = None
                    vxlan_tenant_setup_data[key] = None

        for key, value in cobbler_data.iteritems():
            if key in compute_control_list:
                vxlan_ecn_cobbler[key] = value.get('vxlan-ecn')
                vxlan_tenant_cobbler[key] = value.get('vxlan-tenant')

        vxlan_ecn_err_list = []
        vxlan_tenant_err_list = []

        for key, value in vxlan_ecn_cobbler.iteritems():
            if vxlan_ecn_setup_data[key] is not None \
                    and vxlan_ecn_setup_data[key] != value:
                tmp = "%s: Expected:%s, Found:%s" \
                    % (key, value, vxlan_ecn_setup_data[key])
                vxlan_ecn_err_list.append(tmp)

        for key, value in vxlan_tenant_cobbler.iteritems():
            if vxlan_tenant_setup_data[key] is not None and \
                    vxlan_tenant_setup_data[key] != value:
                tmp = "%s: Expected:%s, Found:%s" \
                    % (key, value, vxlan_tenant_setup_data[key])
                vxlan_tenant_err_list.append(tmp)

        vxlan_ecn_err_info = ""
        if vxlan_ecn_err_list:
            vxlan_ecn_err_info = "vtep_ips for vxlan_ecn: %s" \
                % (', '.join(vxlan_ecn_err_list))

        vxlan_ten_err_info = ""
        if vxlan_tenant_err_list:
            vxlan_ten_err_info = "vtep_ips for vxlan_tenant: %s" \
                % (', '.join(vxlan_tenant_err_list))

        if vxlan_ecn_err_list or vxlan_tenant_err_list:
            err_msg = "ERROR %s %s" % (vxlan_ecn_err_info, vxlan_ten_err_info)
            return err_msg

        return ""

    def check_cert_expiry(self):
        """Check if Cerificate has expired"""

        external_tls = self.ymlhelper.get_data_from_userinput_file(\
            ['external_lb_vip_tls'])

        external_ip = self.ymlhelper.get_data_from_userinput_file(\
            ['external_lb_vip_address'])

        external_ipv6 = self.ymlhelper.get_data_from_userinput_file(\
            ['external_lb_vip_ipv6_address'])

        check_list = []
        port = 5000
        name = 'OpenStack'

        if external_tls:
            if external_ip:
                server = external_ip
                ext_ip_check = \
                    common.check_certificate_validity(server, port, name)
                check_list.append(ext_ip_check)

            if external_ipv6:
                server = external_ipv6
                ext_ipv6_check = \
                    common.check_certificate_validity(server, port, name)
                check_list.append(ext_ipv6_check)

            cert_check_msg = ','.join(check_list)
            return cert_check_msg
        else:
            return "VALID"

    def check_cm_config_change(self, curr_action, target_vm_list=[]):
        '''Check if config change is allowed'''

        ks_config = "Config Change in Central Mgmt Setup Data"
        if not os.path.isfile(self.backup_cm_setup_file):
            return

        if curr_action == 'delete_vms' and 'all' in target_vm_list:
            return

        found_error = 0

        with open(self.setup_file, 'r') as f:
            try:
                doc = yaml.safe_load(f)
            except yaml.parser.ParserError as e:
                found_error = 1
            except yaml.scanner.ScannerError as e:
                found_error = 1

        if found_error:
            err_str = "InCorrect setup_data.yaml syntax; Error Info: " + str(e)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return

        with open(self.backup_cm_setup_file, 'r') as f:
            try:
                doc_backup = yaml.safe_load(f)
            except yaml.parser.ParserError as e:
                found_error = 1
            except yaml.scanner.ScannerError as e:
                found_error = 1

        if found_error:
            err_str = "InCorrect baseline %s syntax; \
                Error Info: %s" % (self.backup_cm_setup_file, str(e))
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return

        unsupported_key_change = []
        for key in doc.keys():
            if key not in doc_backup:
                unsupported_key_change.append(key)

        for key in doc_backup.keys():
            if key not in doc:
                unsupported_key_change.append(key)

        if unsupported_key_change:
            chk_str = "ERROR: Change of key %s not allowed " \
                "during %s of %s" % (','.join(unsupported_key_change),
                                     curr_action,
                                     ','.join(target_vm_list))
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=chk_str)
            return

        new_change_key_value_list = []
        for key in doc.keys():
            if doc.get(key, None) != doc_backup.get(key, None):
                if key == 'SERVERS_IN_VMS':
                    continue
                else:
                    new_change_key_value_list.append(key)

        # Check if value compared to backup_setup data has changed
        for key in new_change_key_value_list:
            if not all([z in doc[key] for z in doc_backup[key]]):
                unsupported_key_change.append(key)

        if unsupported_key_change:
            chk_str = "ERROR: Change of old key/value in %s not allowed " \
                "during %s of %s" % (','.join(unsupported_key_change),
                                     curr_action,
                                     ','.join(target_vm_list))
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=chk_str)
            return

        self.set_validation_results(ks_config)

    def check_config_change(self, curr_action,
                            target_server_list=[],
                            rma_tor_list=[],
                            ccp_check=0, delete_ccp=0,
                            upgrade_ccp=0, skip_cloud_sanity=0):
        '''Check if config change for pool is allowed'''

        ks_config = "Config Change in Setup Data"

        err_str = ""
        if curr_action == 'reconfigure_cimc_password' and \
                not os.path.isfile(self.backup_setup_file):
            ks_config = "Config Change in Setup Data for %s " % (curr_action)
            err_str = "Fatal Error; Can't proceed; " \
                      "As backup_setup_data.yaml does not exist"
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False

        if ccp_check and not os.path.isfile(self.backup_setup_file):
            err_str = ".backup_setup_data.yaml file missing in " \
                "/root/openstack_configs/"
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False

        if not os.path.isfile(self.backup_setup_file):
            return

        curr_code_list = []
        err_code_list = []
        err_code_list2 = []
        err_code_list2.append(self.validation_error_code['NETWORKING'])
        err_code_list4 = []
        err_code_list4.append(self.validation_error_code['ROLES'])
        err_code_list5 = []
        err_code_list5.append(self.validation_error_code['SERVERS'])
        err_code_list6 = []
        err_code_list6.append(self.validation_error_code['NFV_HOSTS'])

        err_code_list9 = []
        err_code_list9.append(self.validation_error_code['APICINFO'])

        found_error = 0

        with open(self.setup_file, 'r') as f:
            try:
                doc = yaml.safe_load(f)
            except yaml.parser.ParserError as e:
                found_error = 1
            except yaml.scanner.ScannerError as e:
                found_error = 1

        if found_error:
            err_str = "InCorrect setup_data.yaml syntax; Error Info: " + str(e)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False

        with open(self.backup_setup_file, 'r') as f:
            try:
                doc_backup = yaml.safe_load(f)
            except yaml.parser.ParserError as e:
                found_error = 1
            except yaml.scanner.ScannerError as e:
                found_error = 1

        if found_error:
            err_str = "InCorrect baseline setup_data.yaml syntax; \
                      Error Info: " + str(e)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False

        new_key_list = []
        new_change_key_value_list = []
        unsupported_key_list = []
        ip_pool_reconfig_mismatch = []
        segment_reconfig_mismatch = []
        ip_pool_reconfig_disallowed = []
        segment_reconfig_disallowed = []
        role_diff_list = []
        server_diff_list = []
        change_role_list = []
        change_server_list = []
        replace_cntrl_reconfig_mismatch = []
        aci_value_diff_list = []

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        diff_change_pat1 = "LDAP|SWIFTSTACK|NFVBENCH|NETAPP|NFVIMON"
        diff_change_pat2 = "VTS_PARAMETERS|VMTP|NETWORKING|CVIM_MON"
        diff_change_pat3 = "SERVER_MON|COBBLER|IRONIC|vim_ldap_admins"
        diff_change_pat4 = "INVENTORY_DISCOVERY|IPA_INFO|VAULT"
        diff_change_pat = diff_change_pat1 + "|" + diff_change_pat2 + \
            "|" + diff_change_pat3 + "|" + diff_change_pat4

        sp1 = "NFVIMON|PODNAME|ENABLE_ESC_PRIV|SNMP|CCP_DEPLOYMENT|"
        sp2 = "LDAP|SWIFTSTACK|SYSLOG_EXPORT_SETTINGS|NFVBENCH|CVIM_MON|"
        sp3 = "INSTALL_MODE|VMTP|admin_source_networks|autobackup|vim_admins|"
        sp4 = "PROVIDER_VLAN_RANGES|external_lb_vip_tls|external_lb_vip_fqdn|"
        sp5 = "NETWORKING|ES_REMOTE_BACKUP|permit_root_login|SRIOV_CARD_TYPE|"
        sp6 = "ssh_banner|SERVER_MON|REGISTRY_NAME|ENABLE_READONLY_ROLE|IRONIC|"
        sp7 = "vim_ldap_admins|HORIZON_ALLOWED_HOSTS|BASE_MACADDRESS|"
        sp8 = "INVENTORY_DISCOVERY|IPA_INFO|cloud_settings|VAULT|SSH_ACCESS_OPTIONS|"
        sp9 = "PASSWORD_MANAGEMENT|MGMTNODE_EXTAPI_FQDN|OCTAVIA_DEPLOYMENT"
        skip_key_pattern = sp1 + sp2 + sp3 + sp4 + sp5 + sp6 + sp7 + sp8 + sp9
        skip_subkeys1 = "VTC_SSH_USERNAME|VTC_SSH_PASSWORD|VTS_DAY0|netapp_cert_file"
        skip_subkeys2 = "protocol|facility|severity|port|clients|user_mail_attribute"
        #skip_subkeys3 = "COLLECTOR_2|MASTER_2|NFVIMON_ADMIN"
        skip_subkeys3 = "NFVIMON_ADMIN"
        skip_subkeys = skip_subkeys1 + "|" + skip_subkeys2 + "|" + skip_subkeys3
        ldap_subkeys = "user|password"
        her_subkeys = "vtep_ips"
        l3_bgp_subkeys1 = "bgp_mgmt_addresses|trusted_vf"
        l3_bgp_subkeys2 = "NOVA_CPU_ALLOCATION_RATIO|NOVA_RAM_ALLOCATION_RATIO"

        l3_bgp_subkeys = l3_bgp_subkeys1 + "|" + l3_bgp_subkeys2
        ldap_anon1 = "group_filter|group_member_attribute|"
        ldap_anon2 = "group_members_are_ids|group_id_attribute|"
        ldap_anon3 = "user_filter|chase_referrals"
        ldap_anon_subkeys = ldap_anon1 + ldap_anon2 + ldap_anon3
        netapp_pat = "server_port|netapp_cert_file|transport_type"
        cobbler_pat = "admin_password_hash"
        nw_option_subkeys = 'head_end_replication'
        nw_option_mand_subkeys = 'bgp_peers|bgp_router_id|bgp_as_num'

        uncfg_pat = "SYSLOG_EXPORT_SETTINGS|admin_source_networks|autobackup|"\
                    "external_lb_vip_tls|external_lb_vip_fqdn|vim_admins|" \
                    "ES_REMOTE_BACKUP|permit_root_login|ssh_banner|REGISTRY_NAME|"\
                    "ENABLE_READONLY_ROLE|HORIZON_ALLOWED_HOSTS|NFVIMON|"\
                    "cloud_settings|MGMTNODE_EXTAPI_FQDN"
        uncfg_pat_central = "SNMP"

        vmtp_subkeys = "EXT_NET|PROV_NET"
        networking_subkeys = "http_proxy_server|https_proxy_server|ntp_servers|" \
                             "domain_name_servers"
        cobbler_subkeys = "admin_password_hash"

        cvimmon_subkeys1 = "polling_intervals|low_frequency|central|ldap"
        cvimmon_subkeys2 = "medium_frequency|high_frequency|ui_access"
        cvimmon_subkeys3 = "external_servers"
        cvimmon_subkeys = cvimmon_subkeys1 + "|" + cvimmon_subkeys2 + "|" \
            + cvimmon_subkeys3
        nfvimon_torkey = "COLLECTOR_TORCONNECTIONS"
        nfvbench_subkeys1 = "nic_slot|nic_ports|vnis|vteps"
        nfvbench_subkeys2 = "vtep_gateway_networks|vpn_labels"
        nfvbench_subkeys3 = "transport_labels|transport_labels_prefixes"
        nfvbench_subkeys = nfvbench_subkeys1 + "|" + nfvbench_subkeys2 + "|" \
            + nfvbench_subkeys3

        snmp_subkeys = "address|port|community|users|engine_id"
        ccp_subkeys = "PUBLIC_NETWORK_UUID|CCP_FLAVOR"

        cloud_settings_subkeys = ['keystone_lockout_failure_attempts',
                                  'keystone_lockout_duration',
                                  'keystone_unique_last_password_count',
                                  'keystone_minimum_password_age',
                                  'keystone_disable_inactive_account',
                                  'horizon_session_timeout']

        pwd_mgmt_subkeys = ['strength_check',
                            'maximum_days',
                            'warning_age',
                            'history_check']

        ssh_access_subkeys = ['session_idle_timeout',
                              'enforce_single_session',
                              'session_login_attempt',
                              'session_lockout_duration',
                              'session_root_lockout_duration',
                              'lockout_inactive_users']

        pod_mgmt_str1 = "add_computes|add_osds|remove_osd"
        pod_mgmt_str2 = "remove_computes|replace_controller"
        pod_mgmt_str = pod_mgmt_str1 + "|" + pod_mgmt_str2
        pod_mgmt_add_str = "add_computes|add_osds"
        pod_mgmt_rm_str = "remove_osd|remove_computes"
        rep_cont_str = "replace_controller"
        vip_pattern = \
            'external_lb_vip_address|external_lb_vip_fqdn|' \
            'external_lb_vip_ipv6_address'

        vlan_vni_key = 'TENANT_VLAN_RANGES|PROVIDER_VLAN_RANGES|L3_PROVIDER_VNI_RANGES'

        check_vtep_info_status = 0
        chk_vtep_consistency = ""

        if self.ymlhelper.get_pod_type() == 'nano' \
                and re.search(pod_mgmt_str, curr_action):
            chk_str = "%s not supported on nano pod" % (curr_action)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=chk_str)
            return

        # Check on basic Sanity of RMA_TOR
        # Also nothing else is allowed to be changed
        if curr_action == 'reconfigure' and rma_tor_list:
            chk_str = self.tor_rma_sanity_check(rma_tor_list)
            if re.search("ERROR", chk_str):
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=chk_str)
                return

            chk_str = self.validate_server_change(curr_action,
                                                  doc['SERVERS'],
                                                  doc_backup['SERVERS'],
                                                  rma_tor_list)
            if re.search("ERROR", chk_str):
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=chk_str)
                return

            unsupported_key_change = []
            for key in doc.keys():
                if key not in doc_backup:
                    unsupported_key_change.append(key)

            for key in doc_backup.keys():
                if key not in doc:
                    unsupported_key_change.append(key)

            if unsupported_key_change:
                chk_str = "ERROR: Change of key %s not allowed " \
                    "during TOR RMA" % (','.join(unsupported_key_change))
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=chk_str)
                return

        # Run cloud Sanity for ccp_check or curr_action as install
        if (ccp_check or curr_action == 'install') and not skip_cloud_sanity:
            os_cfg_loc = self.get_openstack_configs_loc()

            if not os_cfg_loc:
                self.log.info("Couldnt find openstack-configs dir, "
                              "skipping cloud-sanity check")
            else:
                openrc_loc = os_cfg_loc + "/openstack-configs/openrc"
                if not os.path.isfile(openrc_loc):
                    msg = "Couldnot find %s, skipping cloud-sanity check" \
                        % (openrc_loc)
                    self.log.info(msg)
                else:
                    # Check if certificate has expired
                    cert_exp_status = self.check_cert_expiry()
                    if re.search(r'ERROR|has expired', cert_exp_status):
                        skip_cloud_sanity = 1

                    if not skip_cloud_sanity:
                        # Check if FQDN or VIP has changed
                        curr_key_diff = []
                        self.diffDict(doc, doc_backup, curr_key_diff)
                        for item in curr_key_diff:
                            if re.search(item, vip_pattern):
                                skip_cloud_sanity = 1
                                break

                    if not skip_cloud_sanity:
                        cloud_sanity_status = self.execute_cloud_sanity()
                        if re.search(r'ERROR:', cloud_sanity_status):
                            chk_str = "ERROR: Reconfigure not allowed as Cloud " \
                                "Sanity failed with %s " % cloud_sanity_status
                            self.set_validation_results(ks_config,
                                                        status=STATUS_FAIL,
                                                        err=chk_str)
                            return

        # if ccp_check is set, then only ensure that CCP aspects can only change
        found_ccp_tenant_image_change = 0
        found_ccp_installer_image_change = 0
        if ccp_check:
            unsupported_key_change = []
            for key in doc.keys():
                if upgrade_ccp:
                    if key not in doc_backup:
                        if key not in unsupported_key_change:
                            unsupported_key_change.append(key)
                    elif key == 'CCP_DEPLOYMENT':
                        for item in doc[key]:
                            if item == 'CCP_TENANT_IMAGE' and \
                                    doc[key].get(item) != doc_backup[key].get(item):
                                found_ccp_tenant_image_change = 1
                            elif item == 'KUBE_VERSION':
                                continue
                            elif item == 'CCP_INSTALLER_IMAGE' and \
                                    doc[key].get(item) != doc_backup[key].get(item):
                                found_ccp_installer_image_change = 1
                            elif doc[key].get(item) != doc_backup[key].get(item):
                                tmp = key + ":" + item
                                if tmp not in new_change_key_value_list:
                                    new_change_key_value_list.append(tmp)
                    elif doc[key] != doc_backup[key]:
                        if key not in new_change_key_value_list:
                            new_change_key_value_list.append(key)

                elif delete_ccp:
                    if key not in doc_backup:
                        if key not in unsupported_key_change:
                            unsupported_key_change.append(key)
                    elif key == 'CCP_DEPLOYMENT':
                        if key not in new_change_key_value_list:
                            new_change_key_value_list.append(key)
                    elif doc.get(key) != doc_backup.get(key):
                        if key not in new_change_key_value_list:
                            new_change_key_value_list.append(key)

                else:
                    if key not in doc_backup:
                        if re.search('CCP_DEPLOYMENT', key):
                            continue
                        else:
                            if key not in unsupported_key_change:
                                unsupported_key_change.append(key)

                    elif key == 'CCP_DEPLOYMENT':
                        for item in doc[key]:
                            if item == 'PUBLIC_NETWORK_UUID':
                                continue
                            elif item == 'CCP_FLAVOR':
                                continue
                            elif doc[key].get(item) != doc_backup[key].get(item):
                                tmp = key + ":" + item
                                if tmp not in new_change_key_value_list:
                                    new_change_key_value_list.append(tmp)
                    elif doc[key] != doc_backup[key]:
                        if key not in new_change_key_value_list:
                            new_change_key_value_list.append(key)

            for key in doc_backup.keys():
                if delete_ccp:
                    if key not in doc and key != 'CCP_DEPLOYMENT':
                        if key not in unsupported_key_change:
                            unsupported_key_change.append(key)
                    elif key not in doc and key == 'CCP_DEPLOYMENT':
                        continue
                    elif doc.get(key) != doc_backup.get(key):
                        if key not in new_change_key_value_list:
                            new_change_key_value_list.append(key)
                elif upgrade_ccp:
                    continue
                else:
                    if key not in doc:
                        if key not in unsupported_key_change:
                            unsupported_key_change.append(key)

                    elif key == 'CCP_DEPLOYMENT':
                        for item in doc_backup[key]:
                            if doc[key].get(item) is None:
                                tmp = key + ":" + item
                                if tmp not in new_key_list:
                                    new_key_list.append(key)
                    elif doc[key] != doc_backup[key]:
                        if key not in new_change_key_value_list:
                            new_change_key_value_list.append(key)

            missing_key_list = []
            self.findDiffKeys(doc, doc_backup, missing_key_list)

            for item in missing_key_list:
                if item == 'CCP_DEPLOYMENT':
                    continue
                elif item not in new_key_list and re.search(ccp_subkeys, item):
                    continue
                else:
                    new_key_list.append(item)

            if new_key_list:
                chk_str = "ERROR: Addition of new key %s not allowed " \
                    "for CCP CONFIG" % (','.join(new_key_list))
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=chk_str)
                return

            elif unsupported_key_change:
                chk_str = "ERROR: Unsupported change of key %s not allowed " \
                    "during CCP CONFIG" % (','.join(unsupported_key_change))
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=chk_str)
                return

            elif new_change_key_value_list:
                chk_str = "ERROR: Change of value for key %s not allowed " \
                    "for CCP CONFIG" % (','.join(new_change_key_value_list))
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=chk_str)
                return

            elif upgrade_ccp and \
                    (not found_ccp_tenant_image_change or \
                     not found_ccp_installer_image_change):
                err_list = []
                if not found_ccp_tenant_image_change:
                    msg = "CCP_TENANT_NAME"
                    err_list.append(msg)

                if not found_ccp_installer_image_change:
                    msg = "CCP_INSTALLER_NAME"
                    err_list.append(msg)

                if err_list:
                    err_str = ', '.join(err_list)
                    err_str = "%s not changed for ccp_upgrade" % err_str
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return

            else:
                self.set_validation_results(ks_config)

                return

        auto_tor_via_aci = self.cfgmgr.extend_auto_tor_to_aci_fabric()

        target_key_change = []
        # get all the missing keys
        for key in doc.keys():
            if key not in doc_backup:

                # Keep list of keys that need to be changed
                if key not in target_key_change:
                    target_key_change.append(key)

                if podtype is not None and podtype == 'ceph' \
                        and key == 'VIRTUAL_ROUTER_ID' \
                        or key == 'external_lb_vip_address' \
                        or key == 'external_lb_vip_ipv6_address':
                    continue

                if re.search(skip_key_pattern, key):
                    continue
                elif re.search('TORSWITCHINFO', key):
                    tor_config = self.ymlhelper.get_tor_config()
                    if tor_config is None or not tor_config['CONFIGURE_TORS']:
                        continue
                    else:
                        new_key_list.append(key)
                elif re.search(r'DISABLE_HYPERTHREADING', key) and \
                        re.search(r'add_computes', curr_action):
                    continue
                # Forbid from enabling ceilometer on POD operation (except install)
                elif key == 'OPTIONAL_SERVICE_LIST':
                    if 'ceilometer' in doc[key]:
                        unsupported_key_list.append('ceilometer')
                    else:
                        continue
                else:
                    new_key_list.append(key)
            elif key == 'LDAP':
                if doc['LDAP'].get('user') != \
                        doc_backup['LDAP'].get('user'):
                    continue
                elif doc['LDAP'].get('password') != \
                        doc_backup['LDAP'].get('password'):
                    continue
                elif doc['LDAP'].get('user_mail_attribute') != \
                        doc_backup['LDAP'].get('user_mail_attribute'):
                    continue
            elif key == 'NETAPP':
                if doc['NETAPP'].get('netapp_cert_file') != \
                        doc_backup['NETAPP'].get('netapp_cert_file'):
                    continue
                else:
                    new_change_key_value_list.append(key)
            elif key == 'NFVBENCH':
                if doc['NFVBENCH'].get('enabled') is True and \
                        doc_backup['NFVBENCH'].get('enabled') is False:
                    continue
                elif doc['NFVBENCH'].get('enabled') is True and \
                        doc_backup['NFVBENCH'].get('enabled') is None:
                    continue
                elif doc['NFVBENCH'].get('enabled') is True and \
                        doc_backup['NFVBENCH'].get('enabled') is True:
                    continue
                elif doc['NFVBENCH'].get('enabled') is False and \
                        doc_backup['NFVBENCH'].get('enabled') is False:
                    continue
                else:
                    new_change_key_value_list.append(key)

            elif key == 'SERVER_MON':
                if doc['SERVER_MON'].get('enabled') is False and \
                        doc_backup['SERVER_MON'].get('enabled') is True:
                    new_change_key_value_list.append(key)
                else:
                    continue
            elif key == 'ES_REMOTE_BACKUP':
                continue
            elif key == 'SNMP':
                if doc[key].get('enabled') is True and \
                        doc_backup[key].get('enabled') is False:
                    continue
                elif doc[key].get('enabled') is False and \
                        doc_backup[key].get('enabled') is True:
                    new_change_key_value_list.append(key)
                else:
                    if doc[key].get('managers') != \
                            doc_backup[key].get('managers'):

                        for item, item_backup in \
                                zip(doc[key].get('managers'), \
                                    doc_backup[key].get('managers')):
                            item_key_diff = []
                            self.diffDict(item, item_backup, item_key_diff)
                            if item_key_diff:
                                for ind_item in item_key_diff:
                                    if ind_item == 'version' and \
                                            item_backup.get('version') == 'v3':
                                        new_change_key_value_list.append(key)
                                    else:
                                        continue
                    else:
                        continue
            elif key == 'REGISTRY_PASSWORD' or key == 'REGISTRY_USERNAME' \
                    or key == 'REGISTRY_NAME' or key == 'REGISTRY_EMAIL':
                continue
            elif podtype is not None and podtype == 'ceph' \
                and (key == 'external_lb_vip_address' \
                    or key == 'external_lb_vip_ipv6_address'):
                continue
            elif re.search(r'TORSWITCHINFO', key) and \
                    re.search(pod_mgmt_str, curr_action) and \
                    self.is_tor_type_ncs5500():

                curr_key_diff = []
                self.diffDict(doc[key], doc_backup[key], curr_key_diff)

                if curr_key_diff:
                    if 'SWITCHDETAILS' in curr_key_diff and \
                            len(curr_key_diff) == 1:
                        for item, item_backup in \
                                zip(doc[key].get('SWITCHDETAILS'), \
                                    doc_backup[key].get('SWITCHDETAILS')):
                            item_key_diff = []
                            self.diffDict(item, item_backup, item_key_diff)

                            if item_key_diff:
                                # only item that is changing is slitter option
                                if 'splitter_opt_4_10' in item_key_diff and \
                                        len(item_key_diff) == 1:
                                    if item.get('splitter_opt_4_10') is None and \
                                            re.search(pod_mgmt_rm_str, curr_action):
                                        # with remove all splitter option can go
                                        continue
                                    elif item_backup.get('splitter_opt_4_10') is \
                                            None and re.search(pod_mgmt_add_str, \
                                            curr_action):
                                        # with add, splitter option can be new
                                        continue
                                    elif re.search(pod_mgmt_add_str, curr_action):
                                        # check if backup opt is a subset
                                        splt_check = self.splitter_opt_allowed(\
                                            item_backup.get('splitter_opt_4_10'), \
                                            item.get('splitter_opt_4_10'), \
                                            curr_action)
                                        if not splt_check:
                                            continue
                                        else:
                                            self.log.info(splt_check)
                                            if key not in new_change_key_value_list:
                                                new_change_key_value_list.append(key)

                                    elif re.search(pod_mgmt_rm_str, curr_action):
                                        # check if main opt is a subset
                                        splt_check = self.splitter_opt_allowed(\
                                            item.get('splitter_opt_4_10'), \
                                            item_backup.get('splitter_opt_4_10'), \
                                            curr_action)
                                        if not splt_check:
                                            continue
                                        else:
                                            self.log.info(splt_check)
                                            if key not in new_change_key_value_list:
                                                new_change_key_value_list.append(key)
                                    elif re.search(rep_cont_str, curr_action):
                                        continue
                                    else:
                                        if key not in new_change_key_value_list:
                                            new_change_key_value_list.append(key)
                                else:
                                    if key not in new_change_key_value_list:
                                        new_change_key_value_list.append(key)
                            else:
                                continue
                    else:
                        if key not in new_change_key_value_list:
                            new_change_key_value_list.append(key)
                else:
                    continue

            elif doc.get(key) != doc_backup.get(key):
                new_change_key_value_list.append(key)

        for key in doc_backup.keys():
            if key not in doc:

                # Keep list of keys that need to be changed
                if key not in target_key_change:
                    target_key_change.append(key)

                if re.search(uncfg_pat, key):
                    continue
                elif re.search(uncfg_pat_central, key):
                    if 'CVIM_MON' not in doc:
                        new_key_list.append(key)
                    elif doc['CVIM_MON'].get('central'):
                        continue
                else:
                    new_key_list.append(key)

            elif key == 'CVIM_MON':
                if doc_backup['CVIM_MON'].get('central') and \
                        not doc['CVIM_MON'].get('central'):
                    new_key_list.append(key)

        if re.search(r'replace', curr_action):
            missing_key_list = []
            self.findDiffKeys(doc, doc_backup, missing_key_list)
            for item in missing_key_list:
                check_str = "cimc_info|rack_info|hardware_info|" \
                    "ucsm_info|cimc_password|cimc_username|tor_info|" \
                    "dp_tor_info|sriov_tor_info|DISABLE_HYPERTHREADING|" \
                    "num_root_drive|root_drive_type|VIC_admin_fec_mode|" \
                    "VIC_port_channel_enable|NOVA_CPU_ALLOCATION_RATIO|" \
                    "NOVA_RAM_ALLOCATION_RATIO|control_bond_mode|" \
                    "data_bond_mode|rack_id|VIC_link_training|VIC_admin_speed"

                if self.ymlhelper.get_pod_type() == 'micro' or \
                        self.ymlhelper.get_pod_type() == 'edge':
                    check_str = "cimc_info|rack_info|hardware_info|" \
                        "ucsm_info|cimc_password|cimc_username|tor_info|" \
                        "dp_tor_info|sriov_tor_info|DISABLE_HYPERTHREADING|" \
                        "num_root_drive|root_drive_type|trusted_vf|" \
                        "INTEL_SRIOV_VFS|MULTICAST_SNOOPING|VIC_admin_fec_mode|" \
                        "VM_HUGEPAGE_SIZE|VM_HUGEPAGE_PERCENTAGE|rx_tx_queue_size|" \
                        "VIC_port_channel_enable|seccomp_sandbox|" \
                        "RESERVED_L3_CACHELINES_PER_SOCKET|NUM_GPU_CARDS|" \
                        "ENABLE_VM_EMULATOR_PIN|VM_EMULATOR_PCORES_PER_SOCKET|" \
                        "NOVA_CPU_ALLOCATION_RATIO|NOVA_RAM_ALLOCATION_RATIO|" \
                        "control_bond_mode|data_bond_mode|rack_id|" \
                        "VIC_link_training|VIC_admin_speed"

                if auto_tor_via_aci:
                    curr_swt_list = self.cfgmgr.get_torswitch_list()
                    if item not in curr_swt_list:
                        new_key_list.append(item)
                elif not re.search(check_str, item) \
                        and item not in new_key_list:
                    new_key_list.append(item)

        elif re.search(r'install', curr_action):
            # find missing keys
            missing_key_list = []
            self.findDiffKeys(doc, doc_backup, missing_key_list)

            found_change_in_hw_info = 0
            for item in missing_key_list:

                # Keep list of keys that need to be changed
                if item not in target_key_change:
                    target_key_change.append(item)

                if item not in new_key_list:
                    if re.search(skip_key_pattern, item):
                        continue
                    elif re.search(skip_subkeys, item):
                        continue
                    elif item in cloud_settings_subkeys:
                        continue
                    elif item in pwd_mgmt_subkeys:
                        extra_item_in_backup_list = \
                            common.check_setup_data_input_info_diff(\
                                doc['PASSWORD_MANAGEMENT'], \
                                doc_backup['PASSWORD_MANAGEMENT'], \
                                item)

                        if extra_item_in_backup_list and \
                                item not in new_key_list:
                            new_key_list.append(item)

                    elif item in ssh_access_subkeys:
                        extra_item_in_backup_list = \
                            common.check_setup_data_input_info_diff(\
                                doc['SSH_ACCESS_OPTIONS'], \
                                doc_backup['SSH_ACCESS_OPTIONS'], \
                                item)

                        if extra_item_in_backup_list and \
                                item not in new_key_list:
                            new_key_list.append(item)

                    elif re.search(ldap_subkeys, item) and \
                            'user' in missing_key_list and \
                            'password' in missing_key_list:
                        continue
                    elif re.search(nw_option_subkeys, item):
                        if not check_vtep_info_status:
                            check_vtep_info_status = 1
                            chk_vtep_consistency = self.check_vtep_ip_consistency()
                        continue
                    elif re.search(l3_bgp_subkeys, item):
                        tmp_key_list = \
                            self.check_server_info_diff(doc['SERVERS'], \
                                                        doc_backup['SERVERS'],
                                                        item)
                        if tmp_key_list:
                            for tmp_item in tmp_key_list:
                                if tmp_item not in new_key_list:
                                    new_key_list.append(tmp_item)
                    elif re.search(her_subkeys, item):
                        continue
                    elif re.search(ldap_anon_subkeys, item):
                        continue
                    elif re.search(vmtp_subkeys, item):
                        continue
                    elif re.search(networking_subkeys, item):
                        continue
                    elif re.search(cobbler_subkeys, item):
                        continue
                    elif re.search(cvimmon_subkeys, item):
                        continue
                    elif re.search(nfvbench_subkeys, item):
                        continue
                    elif item == 'OPTIONAL_SERVICE_LIST':
                        if ('ceilometer' in doc.get(item) and \
                                doc_backup.get(item) is None):
                            if 'ceilometer' not in unsupported_key_list:
                                unsupported_key_list.append('ceilometer')

                        elif ('ceilometer' in doc.get(item) and \
                                'ceilometer' not in doc_backup.get(item)):
                            if 'ceilometer' not in unsupported_key_list:
                                unsupported_key_list.append('ceilometer')
                        else:
                            continue
                    elif re.search('hardware_info', item):
                        if not found_change_in_hw_info:
                            tmp_key_list = \
                                self.check_hardware_info_diff(doc['SERVERS'], \
                                    doc_backup['SERVERS'], item, 'SRIOV_CARD_TYPE')

                            found_change_in_hw_info = 1
                            if tmp_key_list:
                                for tmp_item in tmp_key_list:
                                    if tmp_item not in new_key_list:
                                        new_key_list.append(tmp_item)
                        else:
                            continue

                    elif re.search('TORSWITCHINFO', item):
                        tor_config = self.ymlhelper.get_tor_config()
                        if tor_config is None or \
                                ('CONFIGURE_TORS' in tor_config.keys() and \
                                not tor_config['CONFIGURE_TORS']):
                            continue
                        else:
                            new_key_list.append(item)
                    elif item == 'cimc_password' and \
                            curr_action == 'reconfigure_cimc_password':
                        continue
                    elif item == 'cimc_admin' and \
                            curr_action == 'reconfigure_cimc_password':
                        continue
                    elif 'NETWORK_OPTIONS' in new_change_key_value_list \
                            and self.is_ip_valid(item):
                        continue
                    elif podtype is not None and podtype == 'ceph' \
                            and item == 'VIRTUAL_ROUTER_ID' \
                            or item == 'external_lb_vip_address' \
                            or item == 'external_lb_vip_ipv6_address':
                        continue
                    else:
                        new_key_list.append(item)

        # check for value changes
        key_value_diff_list = []
        for key in new_change_key_value_list:

            # Keep list of keys that need to be changed
            if key not in target_key_change:
                target_key_change.append(key)

            if podtype is not None and podtype == 'edge' \
                    and key == 'GLANCE_CLIENT_KEY':
                continue
            elif podtype is not None and podtype == 'edge' \
                    and key == 'CLUSTER_ID':
                continue
            elif podtype is not None and podtype == 'ceph' \
                    and (key == 'external_lb_vip_address' or \
                        key == 'external_lb_vip_ipv6_address'):
                continue
            elif key == 'MGMTNODE_EXTAPI_FQDN':
                continue
            elif key == 'ZADARA':
                return_list = []
                self.findDiff2(doc[key], doc_backup[key], return_list)
                if not return_list:
                    continue
                if return_list and len(return_list) == 1 \
                        and 'access_key' in return_list:
                    continue

                if 'access_key' in return_list:
                    return_list.remove('access_key')

                return_str = ','.join(return_list)
                tmp = "ZADARA: %s" % return_str
                unsupported_key_list.append(tmp)
            elif key == 'PASSWORD_MANAGEMENT':

                curr_str_chk = \
                    doc['PASSWORD_MANAGEMENT'].get('strength_check', None)
                back_str_check = \
                    doc_backup['PASSWORD_MANAGEMENT'].get('strength_check', None)

                if curr_str_chk is False and back_str_check is True:
                    curr_key = 'PASSWORD_MANAGEMENT:strength_check'
                    if curr_key not in unsupported_key_list:
                        unsupported_key_list.append(curr_key)
                else:
                    continue
            elif key == 'SSH_ACCESS_OPTIONS':
                continue
            elif re.search(r'TORSWITCHINFO', key) and \
                    auto_tor_via_aci:
                tmp_key_list = \
                    self.validate_tor_change_aci(doc[key],
                                                 doc_backup[key],
                                                 rma_tor_list)
                unsupported_key_list.extend(tmp_key_list)

            elif re.search(r'TORSWITCHINFO', key) and \
                    not re.search(r'install', curr_action) and \
                    mechanism_driver != 'aci':
                tmp_key_list = \
                    self.validate_tor_change(doc[key], doc_backup[key], rma_tor_list)
                unsupported_key_list.extend(tmp_key_list)

            elif re.search(r'TORSWITCHINFO', key) and \
                    mechanism_driver == 'aci':
                tmp_key_list = \
                    self.validate_tor_change_aci(doc[key],
                                                 doc_backup[key],
                                                 rma_tor_list)
                unsupported_key_list.extend(tmp_key_list)

            elif re.search(r'TENANT_VLAN_RANGES|PROVIDER_VLAN_RANGES', key) and \
                    re.match(r'UCSM', self.get_testbed_type()) and \
                    not self.check_ucsm_plugin_presence():
                err_str = "Reconfigure of %s is not supported on %s " \
                          "without UCSM Plugin enabled" \
                          % (key, 'B-series')
                unsupported_key_list.append(err_str)

            elif re.search(r'SYSLOG_EXPORT_SETTINGS', key):
                return_list = []
                if (not isinstance(doc[key], list) or \
                        not isinstance(doc_backup[key], list)):
                    err_str = "SYSLOG_EXPORT_SETTINGS must be a list"
                    unsupported_key_list.append(err_str)
                else:
                    for elem_doc, elem_doc_backup in zip(doc[key], doc_backup[key]):
                        self.diffDict(elem_doc, elem_doc_backup, return_list)
                        if return_list:
                            for item in return_list:
                                if re.search(r'remote_host|port|facility', item):
                                    continue
                                else:
                                    tmp = str(key) + ":" + str(item)
                                    if tmp not in unsupported_key_list:
                                        unsupported_key_list.append(tmp)

            elif re.search(vlan_vni_key, key):

                tv_status = self.check_tv_entry_change(key, \
                                                       doc[key], \
                                                       doc_backup[key])

                if tv_status and key == 'L3_PROVIDER_VNI_RANGES':
                    prov_key = 'PROVIDER_VLAN_RANGES'
                    incorrect_vlans_removed, incorrect_vnis_removed = \
                        common.check_right_vni_vlan_removal(\
                            doc[key], doc_backup[key], doc[prov_key], doc_backup[prov_key])

                    if incorrect_vlans_removed:
                        err_str = "Incorect VLAN:%s/VNIs:%s mapping removed" \
                            % (','.join(incorrect_vlans_removed),
                               ','.join(incorrect_vnis_removed))
                        unsupported_key_list.append(err_str)

                # Extend Check failed, now check for unconfigure
                if tv_status:
                    subset_tv_check = \
                        self.is_change_a_subset(key, doc[key], doc_backup[key])
                    if not subset_tv_check:
                        continue
                    elif subset_tv_check and \
                            subset_tv_check not in unsupported_key_list:
                        unsupported_key_list.append(subset_tv_check)

            elif re.search(r'vim_apic_networks', key):

                if ('TENANT_VLAN_RANGES' not in new_change_key_value_list) \
                        and ('PROVIDER_VLAN_RANGES' not
                             in new_change_key_value_list):
                    if key not in unsupported_key_list:
                        unsupported_key_list.append(key)

                return_list = []
                self.findDiff2(doc[key], doc_backup[key], return_list)
                if return_list:
                    for ten_prov in return_list:
                        for item in doc[key][ten_prov]:
                            if item not in doc_backup[key][ten_prov]:
                                vim_apic_n_cl = \
                                    self.vim_apic_nwrk_change(\
                                        item, doc_backup[key][ten_prov])
                                if vim_apic_n_cl:
                                    unsupported_key_list.extend(vim_apic_n_cl)
                    continue

            elif re.search(r'APICINFO', key):
                return_list = []
                self.findDiff2(doc[key], doc_backup[key], return_list)
                if return_list:
                    for item in return_list:
                        if re.search(\
                                r'apic_hosts|apic_password|apic_username', item):
                            continue
                        else:
                            aci_value_diff_list.append(item)
            elif re.search(r'NETWORKING', key):
                return_list = []
                self.findDiff2(doc[key], doc_backup[key], return_list)
                key_value_diff_list = return_list
            elif re.search(r'ROLES', key):
                return_list = []
                self.findDiff2(doc[key], doc_backup[key], return_list)
                if return_list:
                    role_diff_list = return_list
            elif re.search(r'SERVERS', key) and curr_action == 'reconfigure' \
                    and rma_tor_list:
                continue
            elif re.search(r'NETWORK_OPTIONS', key):
                return_list = []
                self.findDiff2(doc[key], doc_backup[key], return_list)
                if return_list:
                    for item in return_list:
                        if item == 'head_end_replication':
                            if not check_vtep_info_status:
                                check_vtep_info_status = 1
                                chk_vtep_consistency = \
                                    self.check_vtep_ip_consistency()
                            continue
                        elif self.is_ip_valid(item):
                            continue
                        elif re.search(nw_option_mand_subkeys, item):
                            continue
                        else:
                            tmp = key + ":" + item
                            if tmp not in unsupported_key_list:
                                unsupported_key_list.append(tmp)
                                if key in self.validation_error_code:
                                    curr_code_list.append(\
                                        self.validation_error_code[key])

            elif re.search(r'SERVERS', key):
                return_list = []
                self.findDiff2(doc[key], doc_backup[key], return_list)
                if return_list:
                    for ind_item in return_list:
                        if ind_item == 'cimc_password' and \
                                curr_action == 'reconfigure_cimc_password':
                            continue
                        elif ind_item == 'SRIOV_CARD_TYPE':
                            continue
                        elif ind_item == 'vtep_ips':
                            continue
                        elif re.search(r'sriov', ind_item):
                            continue
                        else:
                            server_diff_list.append(ind_item)

            elif re.search(r'NFV_HOSTS', key):
                if re.search(r'ALL', doc_backup[key], re.IGNORECASE):
                    if re.search(r'ALL', doc[key], re.IGNORECASE):
                        continue
                    else:
                        if key not in unsupported_key_list:
                            unsupported_key_list.append(key)
                            if key in self.validation_error_code:
                                curr_code_list.append(\
                                    self.validation_error_code[key])
                else:
                    continue

            elif re.search(\
                    r'INSTALL_MODE|autobackup|BASE_MACADDRESS|SRIOV_CARD_TYPE', key):
                continue
            elif re.search(r'CIMC-COMMON', key) and \
                    curr_action == 'reconfigure_cimc_password':
                continue
            elif re.search(r'vim_ldap_admins', key):
                for item1 in doc_backup.get(key):
                    backup_domain_name = item1.get('domain_name')
                    found_backup_domain_name = 0
                    for item2 in doc[key]:
                        curr_domain_name = item2.get('domain_name')
                        if backup_domain_name == curr_domain_name:
                            found_backup_domain_name = 1
                            break

                    if not found_backup_domain_name:
                        tmp = str(key) + ":" + str(backup_domain_name)
                        if tmp not in unsupported_key_list:
                            unsupported_key_list.append(tmp)

            elif re.search(r'SNMP', key):
                return_list = []
                self.findDiff2(doc[key], doc_backup[key], return_list)
                for item in return_list:
                    if item == 'enabled':
                        tmp = str(key) + ":" + str(item)
                        if tmp not in unsupported_key_list:
                            unsupported_key_list.append(tmp)
                    else:
                        continue

                snmp = doc['SNMP']
                if (not snmp.get('enabled')):
                    continue
                if (snmp.get('enabled') and not snmp.get('managers')):
                    err_str = "SNMP needs at least one manager configured"
                    unsupported_key_list.append(err_str)
                    continue
                bk_snmp = doc_backup.get('SNMP', False)
                if (not isinstance(snmp['managers'], list)):
                    err_str = "SNMP managers needs to be a list"
                    unsupported_key_list.append(err_str)
                bk_snmp = doc_backup.get('SNMP', False)
                if (snmp.get('enabled') and \
                        (not doc_backup.get('SNMP') or not bk_snmp or \
                        not bk_snmp.get('enabled', False))):
                    continue
                return_list = []
                for e_doc, e_bkdoc in zip(snmp['managers'], bk_snmp['managers']):
                    self.diffDict(e_doc, e_bkdoc, return_list)
                    if return_list:
                        for item in return_list:
                            if re.search(r'version', item):
                                if e_doc.get('version') == 'v2c':
                                    tmp = str(key) + ":" + str(item)
                                    if tmp not in unsupported_key_list:
                                        unsupported_key_list.append(tmp)
                                else:
                                    continue
                            elif re.search(snmp_subkeys, item):
                                continue
                            else:
                                tmp = str(key) + ":" + str(item)
                                if tmp not in unsupported_key_list:
                                    unsupported_key_list.append(tmp)

            else:
                found_mismatch = 0
                if re.search(r'OPTIONAL_SERVICE_LIST', key):
                    if ('ceilometer' in doc.get(key) and \
                            'ceilometer' not in doc_backup.get(key)):
                        found_mismatch = 1
                    elif ('ceilometer' not in doc.get(key) and \
                            'ceilometer' in doc_backup.get(key)):
                        found_mismatch = 1
                    elif not self.diffList(doc_backup[key], doc[key]):
                        continue
                    else:
                        found_mismatch = 1
                elif re.search(r'ENABLE_ESC_PRIV', key):
                    if doc_backup['ENABLE_ESC_PRIV'] is False:
                        continue
                    else:
                        found_mismatch = 1
                elif re.search(r'VTS_PARAMETERS', key):
                    if doc_backup[key]['VTS_DAY0'] is False:
                        continue
                    else:
                        found_mismatch = 1
                elif re.search('external_lb_vip_tls', key):
                    continue
                elif re.search('external_lb_vip_fqdn', key):
                    continue
                elif re.search('HORIZON_ALLOWED_HOSTS', key):
                    continue
                elif re.search('vim_admins', key):
                    continue
                elif re.search('permit_root_login', key):
                    continue
                elif re.search('ENABLE_READONLY_ROLE', key):
                    continue
                elif re.search('ssh_banner', key):
                    continue
                elif key == 'cloud_settings':
                    continue
                elif key in cloud_settings_subkeys:
                    continue
                elif re.search(diff_change_pat, key):

                    # Check that contents of the sub keys dont change
                    curr_key = key
                    curr_key_diff = []
                    self.findDiffKeys(doc[key], doc_backup[key], curr_key_diff)

                    if curr_key_diff:
                        for cur_item in curr_key_diff:
                            if re.search(skip_subkeys1, cur_item):
                                continue
                            elif re.search(skip_subkeys3, cur_item):
                                if doc_backup[key].get(cur_item) is not None and \
                                        doc[key].get(cur_item) is None:
                                    found_mismatch = 1
                                else:
                                    continue
                            elif re.search(vmtp_subkeys, cur_item):
                                if cur_item in doc_backup[key].keys():
                                    found_mismatch = 1
                            elif re.search(networking_subkeys, cur_item):
                                continue
                            elif re.search(cvimmon_subkeys, cur_item):
                                continue
                            elif re.search(cobbler_subkeys, cur_item):
                                continue
                            elif re.search(nfvbench_subkeys, cur_item):
                                continue
                            else:
                                found_mismatch = 1
                                key_str = key + ":" + cur_item
                                err_str = "Reconfiguration of %s not allowed" \
                                          % (key_str)
                                self.log.info(err_str)

                    for mykey in doc[curr_key].keys():
                        if mykey in doc_backup[curr_key].keys():
                            if re.search(r'SWIFTSTACK', key):
                                if re.search(r'admin_user|admin_tenant', mykey) \
                                        and doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                              % (key_str)
                                    self.log.info(err_str)

                            elif re.search(r'NETAPP', key):
                                if re.search(netapp_pat, mykey):
                                    continue
                                elif doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                              % (key_str)
                                    self.log.info(err_str)

                            elif re.search(r'COBBLER', key):
                                if re.search(cobbler_pat, mykey):
                                    continue
                                elif doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                              % (key_str)
                                    self.log.info(err_str)

                            elif re.search(r'LDAP', key):
                                if re.search(r'domain', mykey) \
                                        and doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                              % (key_str)
                                    self.log.info(err_str)

                            elif re.search(r'IPA_INFO', key):
                                if re.search(r'ipa_domain_name', mykey) \
                                        and doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                              % (key_str)
                                    self.log.info(err_str)

                            elif re.search(r'NFVBENCH', key):
                                if re.search(r'enabled', mykey) \
                                        and doc_backup[curr_key][mykey] is False \
                                        and doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    continue
                                elif re.search(nfvbench_subkeys, mykey):
                                    continue
                                elif doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                              % (key_str)
                                    self.log.info(err_str)

                            # Support Ironic via reconfigure
                            elif re.search(r'IRONIC', key):
                                continue

                            elif re.search(r'NFVIMON', key):
                                if re.search(r'COLLECTOR|COLLECTOR_2', mykey):
                                    if doc[curr_key][mykey].get(nfvimon_torkey) != \
                                            doc_backup[curr_key][mykey].get(\
                                                nfvimon_torkey):
                                        found_mismatch = 1
                                        key_str = curr_key + ":" + mykey + \
                                            ":" + nfvimon_torkey
                                        err_str = "Reconfiguration of %s " \
                                            "not allowed" % (key_str)
                                        self.log.info(err_str)
                                    elif doc[curr_key][mykey].get(\
                                            'management_vip') != \
                                            doc_backup[curr_key][mykey].get( \
                                                'management_vip'):
                                        found_mismatch = 1
                                        key_str = curr_key + ":" + mykey + \
                                            ":management_vip"
                                        err_str = "Reconfiguration of %s " \
                                            "not allowed" % (key_str)
                                        self.log.info(err_str)
                                    else:
                                        continue
                                elif re.search(r'MASTER|MASTER_2', mykey):
                                    continue
                                elif re.search(r'NFVIMON_ADMIN', mykey):
                                    continue
                                elif doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                        % (key_str)
                                    self.log.info(err_str)

                            elif re.search(r'INVENTORY_DISCOVERY', key):
                                if re.search(r'enabled', mykey):
                                    # 'enabled' didn't change
                                    if doc[curr_key][mykey] == doc_backup[curr_key][mykey]:
                                        continue
                                    if doc[curr_key][mykey] is True:
                                        continue
                                    else:
                                        found_mismatch = 1
                                        self.log.info("Reconfiguration of %s:%s:%s not allowed" % (key, curr_key, mykey))
                                else:
                                    found_mismatch = 1
                                    self.log.info("Reconfiguration of %s:%s:%s not allowed" % (key, curr_key, mykey))

                            elif re.search(r'VAULT', key):
                                if re.search(r'enabled', mykey) and \
                                        doc_backup[curr_key][mykey] is False \
                                        and doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    continue
                            elif re.search(r'CVIM_MON', key):
                                if re.search(r'enabled', mykey) and \
                                        doc_backup[curr_key][mykey] is False \
                                        and doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    continue
                                elif re.search(r'enabled', mykey) and \
                                        doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                              % (key_str)
                                    self.log.info(err_str)
                                elif re.search(r'central', mykey) and \
                                        doc_backup[curr_key][mykey] is False \
                                        and doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    continue
                                elif re.search(r'central', mykey) and \
                                        doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                              % (key_str)
                                    self.log.info(err_str)

                                elif re.search(r'interval', mykey):
                                    continue

                            elif re.search(r'VTS_PARAMETERS', key):
                                if doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                              % (key_str)
                                    self.log.info(err_str)

                            elif re.search(r'VMTP_VALIDATION', key):
                                if doc[curr_key][mykey] != \
                                        doc_backup[curr_key][mykey]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                              % (key_str)
                                    self.log.info(err_str)

                            elif key == 'cloud_settings':
                                continue

                            else:
                                if doc[curr_key] != doc_backup[curr_key]:
                                    found_mismatch = 1
                                    key_str = key + ":" + curr_key + ":" + mykey
                                    err_str = "Reconfiguration of %s not allowed" \
                                              % (key_str)
                                    self.log.info(err_str)

                elif re.search(r'DISABLE_HYPERTHREADING', key) and \
                        re.search(r'add_computes', curr_action):
                    if doc_backup[key] is False:
                        continue
                    else:
                        found_mismatch = 1
                else:
                    found_mismatch = 1

                if key not in unsupported_key_list and found_mismatch:
                    unsupported_key_list.append(key)
                    if key in self.validation_error_code:
                        curr_code_list.append(\
                            self.validation_error_code[key])

        # check if new keys have been added
        if new_key_list:
            for item in new_key_list:
                if item in self.validation_error_code:
                    curr_code_list.append(self.validation_error_code[item])
                unsupported_key_list.append(item)

        # see if ROLES info has changed
        for key in role_diff_list:
            tmp_list = []
            if re.search(r'add_osd|remove_osd', curr_action) \
                    and re.search(r'storage', key):
                continue
            elif re.search(r'add_computes|remove_computes', curr_action) \
                    and re.search(r'compute', key):
                continue

            if podtype is not None and re.match(r'UMHC|NGENAHC', podtype) and \
                    key == 'compute':
                continue
            else:
                tmp_list = self.diffList(doc['ROLES'][key], doc_backup['ROLES'][key])

                if podtype is not None and podtype == 'ceph':
                    pass
                elif tmp_list:
                    dup_roles = key + ":" + ','.join(tmp_list)
                    change_role_list.append(dup_roles)

        if podtype is not None and podtype == 'ceph':
            contoller_svr_list = self.ymlhelper.get_server_list(role='cephcontrol')
            ceph_svr_list = self.ymlhelper.get_server_list(role='cephosd')

        else:
            contoller_svr_list = self.ymlhelper.get_server_list(role='control')
            compute_svr_list = self.ymlhelper.get_server_list(role='compute')
            ceph_svr_list = self.ymlhelper.get_server_list(role='block_storage')

        mgmt_ip_change_list = []
        mgmt_ipv6_change_list = []
        host_name_change_list = []

        if server_diff_list:
            all_servers = doc_backup['SERVERS']
            for server in all_servers.keys():
                if re.search(r'add_osd|remove_osd', curr_action) \
                        and server in ceph_svr_list:
                    continue
                elif re.search(r'add_computes|remove_computes', curr_action) \
                        and server in compute_svr_list:
                    continue

                elif re.search(r'replace_controller', curr_action) \
                        and server in contoller_svr_list:

                    if doc['SERVERS'].get(server) and \
                            doc_backup['SERVERS'].get(server):

                        if doc['SERVERS'][server].get('management_ip') != \
                                doc_backup['SERVERS'][server].get('management_ip'):

                            mgmt_ip_change_str = \
                                doc_backup['SERVERS'][server]['management_ip'] + \
                                " to " + doc['SERVERS'][server]['management_ip']
                            mgmt_ip_change_list.append(mgmt_ip_change_str)

                        if doc['SERVERS'][server].get('management_ipv6') != \
                                doc_backup['SERVERS'][server].get('management_ipv6'):

                            mgmt_ipv6_change_str = \
                                doc_backup['SERVERS'][server]['management_ipv6'] + \
                                " to " + doc['SERVERS'][server]['management_ipv6']
                            mgmt_ipv6_change_list.append(mgmt_ipv6_change_str)

                        server_key_list = doc['SERVERS'].get(server).keys()

                        server_nest_key_list = []
                        for item in server_key_list:
                            if isinstance(doc['SERVERS'].get(server)[item], dict):
                                # Check that nested Keys are not duplicated
                                server_nest_key_list = \
                                    doc['SERVERS'].get(server).get(item).keys()
                                for item1 in server_nest_key_list:
                                    curr_item1 = \
                                        doc['SERVERS'][server][item].get(item1)
                                    backup_item1 = \
                                        doc_backup['SERVERS'][server][item].get(item1)

                                    if server not in target_server_list and \
                                            (curr_item1 != backup_item1):
                                        tmp = server + ":" + item1
                                        replace_cntrl_reconfig_mismatch.append(tmp)

                    else:
                        host_name_change_list.append(server)
                else:
                    if doc['SERVERS'].get(server) and \
                            doc_backup['SERVERS'].get(server):
                        return_list = []

                        self.findDiff2(doc['SERVERS'].get(server), \
                                       doc_backup['SERVERS'].get(server),
                                       return_list)
                        # Handle reconfigure for CPU and/or RAM OverSubs ratio
                        if 'NOVA_RAM_ALLOCATION_RATIO' in return_list:
                            return_list.remove('NOVA_RAM_ALLOCATION_RATIO')

                        if 'NOVA_CPU_ALLOCATION_RATIO' in return_list:
                            return_list.remove('NOVA_CPU_ALLOCATION_RATIO')

                        if return_list:
                            change_server_info = server + ":" + ','.join(return_list)
                            change_server_list.append(change_server_info)
                    else:
                        host_name_change_list.append(server)

        ip_pool_change_without_add = 0
        for key in key_value_diff_list:
            # Keep list of keys that need to be changed
            if key not in target_key_change:
                target_key_change.append(key)

            if key == 'admin_source_networks':
                continue
            elif key == 'external_lb_vip_tls':
                continue
            elif key == 'external_lb_vip_fqdn':
                continue
            elif key == 'external_lb_vip_address' \
                    and podtype == 'ceph':
                continue
            elif key == 'external_lb_vip_ipv6_address' \
                    and podtype == 'ceph':
                continue
            elif re.search('HORIZON_ALLOWED_HOSTS', key):
                continue
            elif key == 'cloud_settings':
                continue
            elif key in cloud_settings_subkeys:
                continue
            elif key in networking_subkeys:
                continue
            elif key != 'networks':
                if key in self.validation_error_code and \
                        key not in curr_code_list:
                    curr_code_list.append(self.validation_error_code[key])
                unsupported_key_list.append(key)
            else:
                # Check for new items
                for item in doc['NETWORKING'][key]:

                    # Get the corresponding network info for the right
                    # segment from backup setup_data
                    item_back = \
                        common.fetch_network_info(\
                            doc_backup['NETWORKING'][key], item.get('segments'))

                    # Ironic is one network that maybe absent in backup setup_data
                    if item_back is None and 'ironic' in item.get('segments'):
                        continue

                    for my_key in item.keys():
                        if my_key == 'pool' and \
                                (('management' in item['segments']) or \
                                ('cimc' in item['segments'])):

                            found_mismatch = 0
                            if not re.search(r'add', curr_action):
                                for each_it in item[my_key]:
                                    if each_it not in item_back[my_key]:
                                        ip_pool_reconfig_mismatch.append(\
                                            each_it)
                                        found_mismatch = 1
                                if found_mismatch:
                                    segment_reconfig_mismatch.append(\
                                        item['segments'])
                                    ip_pool_change_without_add = 1
                            else:
                                for each_itback in item_back[my_key]:
                                    if each_itback not in item[my_key]:
                                        ip_pool_reconfig_mismatch.append(\
                                            each_itback)
                                        found_mismatch = 1
                                if found_mismatch:
                                    segment_reconfig_mismatch.append(\
                                        item['segments'])

                        elif my_key == 'pool' and not \
                                (('management' in item['segments']) or \
                                ('cimc' in item['segments'])):
                            found_mismatch = 0
                            for each_itback in item_back[my_key]:
                                if each_itback not in item[my_key]:
                                    ip_pool_reconfig_disallowed.append(\
                                        each_itback)
                                    found_mismatch = 1
                            if found_mismatch:
                                segment_reconfig_disallowed.append(item['segments'])

                        # allow for provider vlan to change in UCSM w/o plugin
                        if my_key == 'vlan_id' and \
                                ('provider' in item['segments']) and \
                                item.get(my_key) != item_back.get(my_key):

                            if re.match(r'UCSM', self.get_testbed_type()) and \
                                    not self.check_ucsm_plugin_presence():
                                err_str2 = \
                                    "NETWORKING:" + key + ":" + str(item['segments'])
                                err_str = \
                                    "Reconfigure of %s is not supported on %s " \
                                    "without UCSM Plugin enabled for %s" \
                                    % (my_key, 'B-series', err_str2)
                                if err_str not in unsupported_key_list:
                                    unsupported_key_list.append(err_str)
                            else:
                                err_str = "NETWORKING:" + key + ":" + my_key
                                if err_str not in unsupported_key_list:
                                    unsupported_key_list.append(err_str)

                        # allow for tenant vlan to change for UCSM w/Plugin
                        elif my_key == 'vlan_id' and \
                                ('tenant' in item['segments']) and \
                                item[my_key] != item_back[my_key]:

                            if re.match(r'UCSM', self.get_testbed_type()) and \
                                    not self.check_ucsm_plugin_presence():
                                err_str2 = \
                                    "NETWORKING:" + key + ":" + str(item['segments'])
                                err_str = \
                                    "Reconfigure of %s is not supported on %s " \
                                    "without UCSM Plugin enabled for %s" \
                                    % (my_key, 'B-series', err_str2)
                                if err_str not in unsupported_key_list:
                                    unsupported_key_list.append(err_str)
                            elif re.match(r'UCSM', self.get_testbed_type()) and \
                                    self.check_ucsm_plugin_presence():
                                tv_status = \
                                    self.check_tv_entry_change(my_key, \
                                                               item[my_key], \
                                                               item_back[my_key])
                                if tv_status and \
                                        tv_status not in unsupported_key_list:
                                    unsupported_key_list.append(tv_status)
                            else:
                                err_str = "NETWORKING:" + key + ":" + my_key
                                if err_str not in unsupported_key_list:
                                    unsupported_key_list.append(err_str)

                        elif (my_key != 'pool' and my_key != 'ipv6_pool') and \
                                item_back.get(my_key) is None:
                            err_str = "NETWORKING:" + key + ":" + my_key
                            if err_str not in unsupported_key_list:
                                unsupported_key_list.append(err_str)
                        elif (my_key != 'pool' and my_key != 'ipv6_pool') and \
                                item[my_key] != item_back[my_key]:
                            err_str = "NETWORKING:" + key + ":" + my_key
                            if err_str not in unsupported_key_list:
                                unsupported_key_list.append(err_str)

                # Check that segment block in main doc hasn't been taken off
                for item_back in doc_backup['NETWORKING'][key]:
                    back_segment_info = item_back.get('segments')
                    back_gw = item_back.get('gateway')
                    back_subnet = item_back.get('subnet')
                    found_segment = 0
                    for item in doc['NETWORKING'][key]:
                        if back_segment_info == item.get('segments'):
                            found_segment = 1
                            if back_gw != item.get('gateway'):
                                net_info = str(back_segment_info) + ":gateway"
                                if net_info not in unsupported_key_list:
                                    unsupported_key_list.append(net_info)
                            if back_subnet != item.get('subnet'):
                                net_info = str(back_segment_info) + ":subnet"
                                if net_info not in unsupported_key_list:
                                    unsupported_key_list.append(net_info)

                    if not found_segment:
                        net_info = "segment:" + str(back_segment_info)
                        if net_info not in unsupported_key_list:
                            unsupported_key_list.append(net_info)

                # Check that segment block in backup hasn't been taken off
                for item in doc['NETWORKING'][key]:
                    segment_info = item.get('segments')
                    gw = item.get('gateway')
                    subnet = item.get('subnet')
                    found_segment = 0
                    for item_back in doc_backup['NETWORKING'][key]:
                        if segment_info == item_back.get('segments'):
                            found_segment = 1
                            if gw != item_back.get('gateway'):
                                net_info = str(segment_info) + ":gateway"
                                if net_info not in unsupported_key_list:
                                    unsupported_key_list.append(net_info)
                            if subnet != item_back.get('subnet'):
                                net_info = str(segment_info) + ":subnet"
                                if net_info not in unsupported_key_list:
                                    unsupported_key_list.append(net_info)

                    if not found_segment:
                        if 'ironic' in segment_info:
                            continue
                        else:
                            net_info = "segment:" + str(segment_info)
                            if net_info not in unsupported_key_list:
                                unsupported_key_list.append(net_info)

                for item_back in doc_backup['NETWORKING'][key]:
                    item = common.fetch_network_info(\
                        doc['NETWORKING'][key], item_back.get('segments'))

                    for my_key in item_back.keys():
                        if my_key != 'pool' and \
                                item.get(my_key) is None:
                            err_str = "NETWORKING:" + key + ":" + my_key
                            if err_str not in unsupported_key_list:
                                unsupported_key_list.append(err_str)

        if chk_vtep_consistency:
            unsupported_key_list.append(chk_vtep_consistency)

        if unsupported_key_list:
            err_str = "Reconfig of Keys not allowed: " + \
                      ','.join(unsupported_key_list)

            if curr_code_list:
                ve_str = "^".join(curr_code_list)
                err_code_list.append(ve_str)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        err_list = []
        err_list2 = []
        err_list4 = []
        err_list5 = []
        err_list9 = []

        # Keep list of keys that need to be changed
        if len(target_key_change) > 1 and 'IPA_INFO' in target_key_change:
            err_str = "Reconfiguration of IPA_INFO is not allowed with " \
                "any other parameters; Currently reconfiguration includes " \
                "the following %s" % (','.join(target_key_change))
            err_list.append(err_str)

        err_pre = "Change to ACIINFO other than apic_hosts not allowed"
        if aci_value_diff_list:
            err_str = err_pre + ','.join(aci_value_diff_list)
            err_list9.append(err_str)

        err_pre = " change for controller not allowed post install "
        if mgmt_ip_change_list:
            err_str = "management_ip" + err_pre + \
                      ','.join(mgmt_ip_change_list)
            err_list5.append(err_str)

        if mgmt_ipv6_change_list:
            err_str = "management_ipv6" + err_pre + \
                      ','.join(mgmt_ipv6_change_list)
            err_list5.append(err_str)

        err_pre = "Changes to non target controller not allowed during " + \
                  curr_action + " "
        if replace_cntrl_reconfig_mismatch:
            err_str = err_pre + ','.join(replace_cntrl_reconfig_mismatch)
            err_list5.append(err_str)

        err_pre = " section verified since step 1 has changed "
        if host_name_change_list:
            err_str = "Server Hostnames in SERVERS" + err_pre + \
                      ','.join(host_name_change_list)
            err_list5.append(err_str)

        if change_server_list:
            err_str = "Server details in SERVERS" + err_pre + \
                      ','.join(change_server_list)
            err_list5.append(err_str)

        if change_role_list:
            err_str = "Server Hostnames in ROLES" + err_pre + \
                      ','.join(change_role_list)
            err_list4.append(err_str)

        if ip_pool_reconfig_disallowed:
            for seg, ippool in zip(segment_reconfig_disallowed, \
                                   ip_pool_reconfig_disallowed):
                err_str = str(seg) + ":" + str(ippool)
                err_list2.append(err_str)

            if err_list2:
                err_str = "Reconfigure of following network \
                          segments not allowed: " + ','.join(err_list2)
                err_list.append(err_str)

        err_list3 = []
        if ip_pool_reconfig_mismatch:
            for seg, ippool in zip(segment_reconfig_mismatch, \
                                   ip_pool_reconfig_mismatch):
                err_str = str(seg) + ":" + str(ippool)
                err_list3.append(err_str)

            if err_list3:
                if not ip_pool_change_without_add:
                    err_str = "New IP pool can only be augmented via another \
                        sub-pool; Original sub-pool can't be modified: " + \
                        '::'.join(err_list3)
                else:
                    err_str = "IP pool can only be changed during add " \
                        "node(s) operation: " + '::'.join(err_list3)
                err_list.append(err_str)

        if err_list:
            found_error = 1
            err_str = '::'.join(err_list)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list2)
            return

        if err_list5:
            found_error = 1
            err_str = '::'.join(err_list5)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list5)

        if err_list4:
            found_error = 1
            err_str = '::'.join(err_list4)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list4)

        if err_list9:
            found_error = 1
            err_str = '::'.join(err_list9)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list9)

        if not found_error:
            self.set_validation_results(ks_config)
        return

    def check_reconfigure_options(self, check_type, curr_action="install",
                                  skip_cloud_check=0):
        '''Checks the syntax of secrets.yaml or openstack_config.yaml'''

        reconfig_check_list = []
        if re.search(r'new_cfg', check_type):
            ks_config = "Check Schema for openstack_config.yaml"
        else:
            ks_config = "Check Schema for " + check_type

        reconfigure = reconfigure_params.ReconfigParams(\
            curr_action=curr_action, skip_cloud_check=skip_cloud_check)
        reconfig_check_list = reconfigure.validate_schema(check_type, \
                                                          return_type="list")

        if reconfig_check_list:
            err_str = ":".join(reconfig_check_list)

            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False
        else:
            self.set_validation_results(ks_config)

        return True

    def check_cvim_mon_ha_config_change(self, curr_action=None, pod_oper=None, stack_name=None):
        '''Checks for valid cvim-mon-ha config changes during pod operations'''
        ks_config = "Pod operations for CVIM-MON-HA"

        found_error = 0

        if not os.path.isfile(self.setup_file):
            err_str = "Setup_data file missing "
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return

        if not os.path.isfile(self.backup_setup_file):
            err_str = "Backup setup_data file missing "
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return

        doc = copy.deepcopy(self.cvimmonha_setup)
        doc_backup = copy.deepcopy(self.bkp_cvimmonha_setup)

        if pod_oper:
            setup_wo_site = copy.deepcopy(doc)
            back_setup_wo_site = copy.deepcopy(doc_backup)
            del setup_wo_site['ARGUS_BAREMETAL']['SITE_CONFIG']['clusters']
            del back_setup_wo_site['ARGUS_BAREMETAL']['SITE_CONFIG']['clusters']
            added_servers = []
            removed_servers = []

            setup_change = cmp(setup_wo_site, back_setup_wo_site)
            if int(setup_change) != 0:
                err_str = "Only pod information can be changed in setupdata " + \
                          "while doing pod operations. Other information " + \
                          "should not be changed"
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return False
            servers_in_setupdata = [server
                                    for cluster in doc['ARGUS_BAREMETAL']['SITE_CONFIG']['clusters']
                                    for server in cluster['servers']]
            servers_in_backupsetupdata = [server
                                          for cluster in doc_backup['ARGUS_BAREMETAL']['SITE_CONFIG']['clusters']
                                          for server in cluster['servers']]
            for server in servers_in_setupdata:
                if server not in servers_in_backupsetupdata:
                    added_servers.append(server)
            for server in servers_in_backupsetupdata:
                if server not in servers_in_setupdata:
                    removed_servers.append(server)

            if 'replace_master' in pod_oper:
                server_from_cli = pod_oper['replace_master'][0]
                server_names = \
                    [server['name'] for server in servers_in_backupsetupdata]
                if server_from_cli not in server_names:
                    err_str = "Server %s not present in the cluster" \
                        % server_from_cli
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False

                for server in servers_in_backupsetupdata:
                    if server['name'] == server_from_cli and \
                            ('role' in server and server['role'] != 'master'):
                        err_str = "Replace-master can only be performed on a " \
                            "master node"
                        self.set_validation_results(ks_config,
                                                    status=STATUS_FAIL,
                                                    err=err_str)
                        return False
                if added_servers or removed_servers:
                    err_str = "Setupdata file should not be modified for " \
                        "replace-master"
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False

                if not self.check_cvimmon_nodes_status(ks_config, server_from_cli):
                    return False

            elif 'add_worker' in pod_oper:
                if not added_servers:
                    err_str = "Server to be added has to be defined in " + \
                              "setup data file before adding"
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False
                if len(added_servers) != 1:
                    no_servers = [server['name'] for server in added_servers]
                    err_str = "Only 1 worker can be added at a time. " + \
                              "Servers newly added are %s" % (str(no_servers))
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False

                server_from_setup = added_servers[0]['name']
                server_from_cli = pod_oper['add_worker'][0]
                if server_from_setup != server_from_cli:
                    err_str = "Pod Info for %s not given in " \
                        "setupdata" % (server_from_cli)
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False
                if 'role' in added_servers[0] and \
                        added_servers[0]['role'] != 'worker':
                    err_str = "Only server with role worker can be " \
                        "added in add worker option"
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False

                if not self.check_cvimmon_nodes_status(ks_config, server_from_cli):
                    return False

            elif 'remove_worker' in pod_oper:
                server_from_cli = pod_oper['remove_worker'][0]
                server_names = [server['name']
                                for server in servers_in_backupsetupdata]
                if server_from_cli not in server_names:
                    err_str = "Server %s not present in the cluster" \
                        % server_from_cli
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False

                for server in servers_in_setupdata:
                    if server['name'] == server_from_cli and \
                            ('role' not in server or server['role'] != 'worker'):
                        err_str = "Only worker can be removed with " \
                                  "remove-worker option"
                        self.set_validation_results(ks_config,
                                                    status=STATUS_FAIL,
                                                    err=err_str)
                        return False

                if not removed_servers:
                    err_str = "The info for the server to be removed " \
                        "should be removed from setupdata"
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False
                if len(removed_servers) != 1:
                    no_servers = [server['name'] for server in removed_servers]
                    err_str = "Only 1 worker can be removed at a time. " + \
                              "Servers newly removed are %s" % (str(no_servers))
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False
                server_from_setup = removed_servers[0]['name']
                server_from_cli = pod_oper['remove_worker'][0]
                if server_from_setup != server_from_cli:
                    err_str = "Pod Info for %s not removed from " \
                        "setupdata" % (server_from_cli)
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False
                if 'role' not in removed_servers[0] or \
                        removed_servers[0]['role'] != 'worker':
                    err_str = "Only server with role worker can " \
                        "be removed in remove worker option"
                    self.set_validation_results(ks_config,
                                                status=STATUS_FAIL,
                                                err=err_str)
                    return False

            self.set_validation_results(ks_config)
            return
        curr_action_option = "add-cvim-pod|delete-cvim-pod|add-stack|" \
                             "delete-stack|reconfigure-stack|reconfigure|" \
                             "reconfigure-cvim-pod|regenerate-certs"
        if not re.match(curr_action_option, curr_action):
            setup_change = cmp(doc, doc_backup)
            if setup_change != 0:
                err_str = "Setup data information does not match " + \
                    " backup setup data information. Cannot proceed with " + \
                    curr_action
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return False

        else:
            if curr_action not in ["reconfigure-cvim-pod", "reconfigure-stack",
                                   "regenerate-certs"]:
                setup_change = cmp(doc, doc_backup)
                if setup_change == 0:
                    err_str = "Setup data information is the same as " + \
                        " backup setup data information. Cannot proceed with " + \
                        curr_action
                    self.set_validation_results(ks_config,
                                                status='FAIL',
                                                err=err_str)
                    return False

        doc_stacks = doc['cvim-mon-stacks']
        doc_backup_stacks = doc_backup['cvim-mon-stacks']

        doc_modify = dict(doc)
        del doc_modify['cvim-mon-stacks']
        doc_backup_modify = dict(doc_backup)
        del doc_backup_modify['cvim-mon-stacks']
        key_diffs = set(doc_modify) ^ set(doc_backup_modify)
        if 'CVIMMONHA_CLUSTER_MONITOR' in key_diffs:
            key_diffs.remove('CVIMMONHA_CLUSTER_MONITOR')

        if (cmp(doc_modify, doc_backup_modify) and \
           (curr_action not in ["reconfigure", "regenerate-certs"])):
            err_str = ("Setup data information not including cvim-mon-stacks does " \
                "not match backup setup data information not including " \
                "cvim-mon-stacks. Cannot proceed with %s" % curr_action)
            self.set_validation_results(ks_config, status=STATUS_FAIL, err=err_str)
            return False

        # VALIDATION FOR RECONFIGURE (global fields on setup_data.yaml file)
        if ((curr_action == "reconfigure") and key_diffs):
            err_str = ("On %s, don't add/remove new fields on setup_data.yaml " \
                "file. Only values are allowed to be changed." % curr_action)
            self.set_validation_results(ks_config, status=STATUS_FAIL, err=err_str)
            return False

        if ((curr_action == "reconfigure") and cmp(doc_stacks, doc_backup_stacks)):
            err_str = ("On %s, don't change cvim-mon-stacks info" % curr_action)
            self.set_validation_results(ks_config, status=STATUS_FAIL, err=err_str)
            return False

        if (curr_action == "reconfigure"):
            # List of allowed keys to reconfigure
            allowed_recfg = ['log_rotation_frequency', 'log_rotation_del_older', \
                             'log_rotation_size', 'ntp_servers',
                             'CVIMMONHA_CLUSTER_MONITOR', 'domain_name_servers']
            changed = []
            for k, v in doc_modify.iteritems():
                if (v != doc_backup_modify.get(k, None) and k not in allowed_recfg):
                    changed.append(k)
            if changed:
                verb = 'is' if len(changed) == 1 else 'are'
                err_str = ("On %s, %s %s not allowed to be changed" \
                    % (curr_action, changed, verb))
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL, err=err_str)
                return False

        # VALIDATION FOR ADD/DELETE-CVIM-POD
        if re.match(r'add-cvim-pod|delete-cvim-pod', curr_action):
            if len(doc_stacks) != len(doc_backup_stacks):
                err_str = "Cannot add or delete stacks " + \
                    "during " + curr_action + " operations"
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return False

            invalid_stacks = list()
            for curr_stack in doc_stacks:
                for backup_stack in doc_backup_stacks:
                    if curr_stack.get('name') == backup_stack.get('name'):
                        stack_level_diff = self.get_stack_level_diff(curr_stack, backup_stack)
                        err_str = "Cannot modify stack level parameters " \
                            "in stack " + backup_stack.get('name') + \
                            " during " + curr_action + " operations"
                        if not stack_level_diff:
                            self.set_validation_results(ks_config,
                                                        status=STATUS_FAIL,
                                                        err=err_str)
                            return False
                        curr_stack_targets = \
                            self.get_cvim_mon_targets(curr_stack, curr_action)
                        backup_stack_targets = \
                            self.get_cvim_mon_targets(backup_stack, curr_action)
                        invalid_modify_list = list()
                        invalid_add_delete_list = list()
                        if re.match(r'add-cvim-pod', curr_action):
                            unallowed_action = "delete"
                            base_targets = backup_stack_targets
                            modify_targets = curr_stack_targets
                        else:
                            unallowed_action = "add"
                            base_targets = curr_stack_targets
                            modify_targets = backup_stack_targets

                        for base_key, base_value in base_targets.iteritems():
                            target_match = 0
                            for modify_key, modify_value in \
                                    modify_targets.iteritems():
                                if base_key == modify_key:
                                    target_match = 1
                                    if cmp(modify_value, base_value) != 0:
                                        diff_values = dict()
                                        diff_values[base_key] = \
                                            self.get_target_diff(
                                                modify_value, base_value)
                                        invalid_modify_list.append(diff_values)
                            if target_match == 0:
                                invalid_add_delete_list.append(base_key)

                        if invalid_add_delete_list:
                            err_str = "Cannot " + unallowed_action + \
                                " existing stack targets for stack " + \
                                backup_stack.get('name') + \
                                ", pods " + str(invalid_add_delete_list) + \
                                " during " + curr_action + " operations"
                            self.set_validation_results(ks_config,
                                                        status=STATUS_FAIL,
                                                        err=err_str)
                            return False

                        if invalid_modify_list:
                            err_str = "Cannot modify existing stack targets " \
                                "for stack " + backup_stack.get('name') + \
                                ", pods " + str(invalid_modify_list) + \
                                " during " + curr_action + " operations"
                            self.set_validation_results(ks_config,
                                                        status=STATUS_FAIL,
                                                        err=err_str)
                            return False

                        break

                else:
                    invalid_stacks.append(curr_stack.get('name'))

            if invalid_stacks:
                err_str = "Cannot add, delete, or rename existing stacks " + \
                    ', '.join(invalid_stacks) + \
                    " during " + curr_action + " operations"
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return False

        # VALIDATION CHECK FOR ADD STACK OPERATION
        if re.match(r'add-stack', curr_action):
            invalid_stacks = list()
            for backup_stack in doc_backup_stacks:
                for curr_stack in doc_stacks:
                    if backup_stack.get('name') == curr_stack.get('name'):
                        sorted_curr_stack = self.sort_cvim_mon_stack(curr_stack)
                        sorted_backup_stack = self.sort_cvim_mon_stack(backup_stack)
                        if (re.match(r'add-stack', curr_action) and
                                cmp(sorted_backup_stack, sorted_curr_stack) != 0):
                            err_str = "Cannot modify existing stack " + \
                                backup_stack.get('name') + " during " + \
                                curr_action + " operations"
                            self.set_validation_results(ks_config,
                                                        status=STATUS_FAIL,
                                                        err=err_str)
                            return False

                        break
                else:
                    invalid_stacks.append(backup_stack.get('name'))

            if invalid_stacks:
                err_str = "Cannot delete existing stacks " + \
                    ', '.join(invalid_stacks) + \
                    " during add-stack operations"
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return False

        # VALIDATION CHECK FOR DELETE STACK OPERATION
        if re.match(r'delete-stack', curr_action):
            invalid_stacks = list()
            for curr_stack in doc_stacks:
                for backup_stack in doc_backup_stacks:
                    if backup_stack.get('name') == curr_stack.get('name'):
                        sorted_curr_stack = self.sort_cvim_mon_stack(curr_stack)
                        sorted_backup_stack = self.sort_cvim_mon_stack(backup_stack)
                        if cmp(sorted_backup_stack, sorted_curr_stack) != 0:
                            err_str = "Cannot modify existing stack " + \
                                backup_stack.get('name') + \
                                " during delete-stack operations"
                            self.set_validation_results(ks_config,
                                                        status=STATUS_FAIL,
                                                        err=err_str)
                            return False

                        break
                else:
                    invalid_stacks.append(curr_stack.get('name'))

            if invalid_stacks:
                err_str = "Cannot add stacks " + \
                    ', '.join(invalid_stacks) + \
                    " during delete-stack operations"
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return False

        # VALIDATION FOR CUSTOM ALERTING RULUES
        if re.match(r'custom-alerts', curr_action):
            self.check_user_custom_config_file("alerting_custom_rules.yml",
                                               "prometheus", 'CVIMMONHA', stack_name)

        if re.match(r'custom-alert-config', curr_action):
            self.check_user_custom_config_file("alertmanager_custom_config.yml",
                                               "prometheus", 'CVIMMONHA', stack_name)

        # VALIDATION FOR RECONFIGURING STACK LEVEL DETAILS
        # AND CERTS/PASSWORDS FOR STACK TARGETS
        if re.match(r'reconfigure-stack|reconfigure-cvim-pod', curr_action):
            if len(doc_stacks) != len(doc_backup_stacks):
                err_str = "Cannot add or delete stacks " + \
                    "during " + curr_action + " operations"
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return False

            invalid_stacks = list()
            for curr_stack in doc_stacks:
                for backup_stack in doc_backup_stacks:
                    if curr_stack.get('name') == backup_stack.get('name'):
                        if curr_action == 'reconfigure-cvim-pod':
                            err_str = "Can only modify certs and passwords for " \
                                "pods in stack " + backup_stack.get('name') + \
                                " during " + curr_action + " operations"
                            stack_level_diff = self.get_stack_level_diff(curr_stack, backup_stack)
                            if not stack_level_diff:
                                self.set_validation_results(ks_config,
                                                            status=STATUS_FAIL,
                                                            err=err_str)
                                return False
                            curr_stack_targets = \
                                self.get_cvim_mon_targets(curr_stack, curr_action)
                            backup_stack_targets = \
                                self.get_cvim_mon_targets(backup_stack, curr_action)
                            if cmp(curr_stack_targets, backup_stack_targets) != 0:
                                self.set_validation_results(ks_config,
                                                            status=STATUS_FAIL,
                                                            err=err_str)
                                return False
                        else:
                            sorted_curr_stack = self.sort_cvim_mon_stack(curr_stack)
                            sorted_backup_stack = \
                                self.sort_cvim_mon_stack(backup_stack)
                            if 'regions' in sorted_curr_stack:
                                curr_stack_targets = sorted_curr_stack['regions']
                            else:
                                curr_stack_targets = {}
                            if 'regions' in sorted_backup_stack:
                                backup_stack_targets = sorted_backup_stack['regions']
                            else:
                                backup_stack_targets = {}
                            if cmp(curr_stack_targets, backup_stack_targets) != 0:
                                err_str = "Cannot modify cvim target info for " \
                                    "stack " + backup_stack.get('name') + \
                                    " during " + curr_action + " operations"
                                self.set_validation_results(ks_config,
                                                            status=STATUS_FAIL,
                                                            err=err_str)
                                return False

                        break

                else:
                    invalid_stacks.append(curr_stack.get('name'))

            if invalid_stacks:
                err_str = "Cannot add, delete, or modify existing stack " + \
                    ', '.join(invalid_stacks) + \
                    " during " + curr_action + " operations"
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return False

        self.set_validation_results(ks_config)
        return

    def get_stack_level_diff(self, curr_stack, backup_stack):
        """
        Check to see if all stack parameters besides target info remain unchanged
        """
        check_stack = copy.deepcopy(curr_stack)
        if 'regions' in check_stack:
            del check_stack['regions']
        check_backup_stack = copy.deepcopy(backup_stack)
        if 'regions' in check_backup_stack:
            del check_backup_stack['regions']
        if cmp(check_stack, check_backup_stack) != 0:
            return False
        return True

    def get_target_diff(self, curr_values, backup_values):
        '''Return cvim target differences during invalid pod operations'''
        curr_set = set(curr_values.items())
        backup_set = set(backup_values.items())

        diff_targets = backup_set - curr_set
        return [item[0] for item in diff_targets]

    def sort_cvim_mon_stack(self, stacks):
        '''Sorts the cvim-mon target stacks, its regins, metros, and pods by name'''
        sorted_stack = stacks

        for region in sorted_stack.get('regions', []):
                region.get('metros', []).sort(key=lambda i: i.get('name'))
                for metro in region.get('metros', []):
                    metro.get('pods', []).sort(key=lambda i: i.get('name'))

        return sorted_stack

    def get_cvim_mon_targets(self, cvim_mon_stack, operation):
        '''Get cvim-mon-ha pod information per stack'''

        cvim_mon_targets = dict()
        temp_stack = copy.deepcopy(cvim_mon_stack)

        for region in temp_stack.get('regions', []):
            for metro in region.get('metros', []):
                for pod in metro.get('pods', []):
                    pod_key = pod.pop('name')
                    pod['region'] = region.get('name')
                    pod['metro'] = metro.get('name')
                    if re.match(r'reconfigure-cvim-pod', operation):
                        pod.pop('cert', None)
                        pod.pop('cvim_mon_proxy_password', None)
                    cvim_mon_targets[pod_key] = pod

        return cvim_mon_targets

    def check_yaml_schema(self, curr_action, ccp_check=0, curr_vm_list=[]):
        '''Checks YAML schema'''

        err_code_list = []
        ks_config = "Schema Validation of Input File"
        err_str = ""
        found_error = 0

        if self.cvimmonha_setup:
            doc = self.cvimmonha_setup

        else:
            with open(self.setup_file, 'r') as f:
                try:
                    doc = yaml.safe_load(f)
                except yaml.parser.ParserError as e:
                    found_error = 1
                except yaml.scanner.ScannerError as e:
                    found_error = 1

        if found_error:
            err_str = "InCorrect setup_data.yaml syntax; Error Info: " + str(e)
            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False

        testbed_type = self.get_testbed_type()
        podtype = self.ymlhelper.get_pod_type()

        if podtype != 'CVIMMONHA' and podtype != 'MGMT_CENTRAL':
            if re.match(r'InvalidInput', testbed_type):
                err_str = "Can't validate setup_data.yaml;\
                          UCSMCOMMON or CIMC-COMMON Section not defined"

                err_code_list.append(self.validation_error_code['CIMC-COMMON'])
                self.set_validation_results(ks_config,
                                            status=STATUS_FAIL,
                                            err=err_str,
                                            error_code_list=err_code_list)
                return False

        schema_validator = schema_validation.SchemaValidator(self.setup_file, \
                                                             curr_action,
                                                             ccp_check,
                                                             curr_vm_list)
        schema_check_list = schema_validator.validate_schema(doc, testbed_type)

        if schema_check_list:
            err_str = " ::".join(schema_check_list)

            for item in schema_check_list:
                temp_list = []
                temp_list = self.get_validation_error_code(item)

                temp_str = ""
                if len(temp_list) > 1:
                    temp_str = "^".join(temp_list)
                else:
                    temp_str = "".join(temp_list)

                if temp_str not in err_code_list:
                    err_code_list.append(temp_str)

            self.set_validation_results(ks_config,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return False
        else:
            self.set_validation_results(ks_config)

        return True

    def get_validation_error_code(self, err_str):
        ''' gets the validation error code from voluptous output'''

        a_key = []
        ve_anchor = ""
        anchor_key_num = 0
        anchor_key = ""

        if not re.search(r'@ data', err_str):
            return "ERROR"

        overall_key_list = []
        all_keys = re.findall(r"\[(['A-Za-z0-9_-]+')\]", err_str)

        # if 1 Key
        if len(all_keys) == 1:
            try:
                overall_key_list.append(self.\
                    validation_error_code[all_keys[0].strip("'")])
            except KeyError:
                overall_key_list.append(self.\
                                        validation_error_code['UNSUPPORTED_KEY'])
            return overall_key_list

        # get the anchor key
        if len(all_keys) > 1:
            a_key = re.findall(r"for dictionary value @ data\[(['A-Za-z0-9_-]+')\]$",
                               err_str)
            anchor_key_num = len(a_key)
            if anchor_key_num:
                anchor_key = a_key[anchor_key_num - 1].strip("'")
                try:
                    ve_anchor = self.validation_error_code[anchor_key]
                except KeyError:
                    ve_anchor = self.validation_error_code['UNSUPPORTED_KEY']

        only_anchor_found = 1
        err_list = err_str.split("@ data")
        for item in err_list:
            if item:
                temp_list = []
                my_keys = re.findall(r"\[(['A-Za-z0-9_-]+')\]", item)
                for keys in my_keys:
                    if keys.strip("'") != anchor_key:

                        try:
                            temp_list.append(
                                self.validation_error_code[keys.strip("'")])
                        except KeyError:
                            print "MISSING KEYS", keys
                            temp_list.append(
                                self.validation_error_code['UNSUPPORTED_KEY'])
                temp_str = ""
                if len(temp_list) >= 1:
                    only_anchor_found = 0
                    temp_str = ":".join(temp_list)
                    if ve_anchor:
                        temp_str = ve_anchor + ":" + temp_str
                    overall_key_list.append(temp_str)
        if only_anchor_found:
            temp_str = ve_anchor
            overall_key_list.append(temp_str)

        return overall_key_list

    def is_ucsm_info_valid(self):
        ''' Check if UCSM IP is accessible '''

        err_code_list = []
        err_code_list.append(self.validation_error_code['UCSMCOMMON'])
        chk_config = "Check UCSM L3 & FW Validity"
        found_error = 0

        ucsm_ip = self.ymlhelper.get_common_ucsm_ip()
        ucsm_uname = self.ymlhelper.get_common_ucsm_username()
        ucsm_pwd = self.ymlhelper.get_common_ucsm_password()
        ucsm_prefix = self.ymlhelper.get_common_ucsm_prefix()

        ucsm_hdl = ucsmutils.UCSM(ucsm_ip, ucsm_uname, ucsm_pwd, ucsm_prefix)
        if ucsm_hdl is None:
            self.log.info("Can't Get UCSM object for %s", ucsm_ip)
            return 0

        try:
            _ = ucsm_hdl.get_fi_mode()
        except urllib2.HTTPError, e:
            found_error = 1
        except Exception as e:
            found_error = 1

        fw_version_check = 1
        if not found_error:
            ucsm_fw_version = ucsm_hdl.ucsm_check_firmware_version()
            if re.search(r'APIFAILED', str(ucsm_fw_version)):
                self.log.info("API failed for %s", ucsm_ip)
                fw_version_check = 0
            elif ucsm_fw_version is False:
                self.log.info("Incorrect UCSM FW Version %s", ucsm_ip)
                fw_version_check = 0

        ucsm_hdl.handle_logout()
        if found_error:
            err_segment = "UCSM Connectivity Check failed for ucsm_ip:" + \
                str(ucsm_ip) + " :check for validity of UCSM IP, username, \
                password and/or prefix: Fail Reason: " + str(e)

            self.ucsm_access = 0
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        elif not fw_version_check:
            found_error = 1
            err_segment = "UCSM FW Version Check failed for :" + \
                str(ucsm_ip) + "Expected Version >= 2.2(5a)"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if not found_error:
            self.set_validation_results(chk_config)

        return

    def check_registry_connectivity(self, action):
        '''Check for registry connectivity'''

        found_error = 0
        proxy_info_exists = 0
        proxy_info = ""
        err_code_list = []
        err_code_list.append(self.validation_error_code['REGISTRY_PASSWORD'])
        chk_config = "Check Registry Connectivity"

        install_mode = self.ymlhelper.check_section_exists('INSTALL_MODE')

        if install_mode is not None and re.search(r'disconnected', install_mode):
            self.log.info("Skipping registry check for disconnected install")
            return

        if not os.path.exists(self.defaults_file):
            msg = "Provide user input files %s, %s " % (self.defaults_file)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=msg,
                                        error_code_list=err_code_list)
            self.log.info(msg)
            return

        image_tag = common.get_image_tag(self.defaults_file)

        if re.search(r'ERROR', str(image_tag)):
            msg = "ERROR: can't process, as the image_tag info is " \
                "unknown in defaults.yaml"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=msg,
                                        error_code_list=err_code_list)
            self.log.info(msg)
            return
        else:
            pass

        reg_uname = self.ymlhelper.check_section_exists('REGISTRY_USERNAME')
        reg_pwd = self.ymlhelper.check_section_exists('REGISTRY_PASSWORD')
        https_proxy_info_exists = 0

        networking_info = self.ymlhelper.get_data_from_userinput_file(['NETWORKING'])
        if networking_info is not None:
            https_proxy_server = networking_info.get('https_proxy_server')
            http_proxy_server = networking_info.get('http_proxy_server')
            if https_proxy_server is not None:
                proxy_info_exists = 1
                proxy_info = https_proxy_server
                https_proxy_info_exists = 1
            elif http_proxy_server is not None:
                proxy_info_exists = 1
                proxy_info = http_proxy_server

        err_msg = []
        if reg_uname is None:
            msg = "REGISTRY_USERNAME is missing"
            found_error = 1
            err_msg.append(msg)

        if reg_pwd is None:
            msg = "REGISTRY_PASSWORD is missing"
            found_error = 1
            err_msg.append(msg)

        if found_error:
            curr_msg = ','.join(err_msg)
            self.log.info(curr_msg)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=curr_msg,
                                        error_code_list=err_code_list)
            return

        curr_install_link = common.get_current_install_link()
        if re.search(r'ERROR', curr_install_link):
            msg = "ERROR: can't process, as the install link is unknown"
            self.log.info(msg)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=msg,
                                        error_code_list=err_code_list)

            return

        registry_info = common.get_registry_info(\
            abs_path_defaults_yaml=self.defaults_file)
        setup_yaml = common.get_contents_of_file(self.setup_file)
        if setup_yaml:
            registry_name = setup_yaml.get('REGISTRY_NAME')
            if registry_name is not None:
                registry_info = registry_name

        if re.search(r'ERROR', registry_info):
            msg = "ERROR: can't process, as the Registry Information is unknown"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=msg,
                                        error_code_list=err_code_list)

            self.log.info(msg)
            return

        error_found = 0

        if proxy_info_exists:
            if https_proxy_info_exists:
                os.environ["https_proxy"] = "https://" + proxy_info
            else:
                os.environ["http_proxy"] = "http://" + proxy_info

        conn_url = "https://%s/v2/_catalog" % (registry_info)
        try:
            conn_status = requests.get(conn_url, auth=(reg_uname, reg_pwd))

            if os.environ.get('https_proxy'):
                os.environ.pop("https_proxy")

            if os.environ.get('http_proxy'):
                os.environ.pop("http_proxy")

        except Exception as e:
            self.log.info("Validation Failed: Connection to registry failed")
            self.log.info(str(e))
            error_found = 1

        if error_found:

            if os.environ.get('https_proxy'):
                os.environ.pop("https_proxy")

            if os.environ.get('http_proxy'):
                os.environ.pop("http_proxy")

            err_msg = "ERROR: Registry %s not reachable, can't proceed, " \
                "check the registry credential" % (registry_info)
            self.log.info(err_msg)

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_msg,
                                        error_code_list=err_code_list)

            return

        if conn_status.status_code != 200:
            err_msg = "ERROR: Registry %s not reachable getting response " \
                "code of %s can't proceed. Please check the registry " \
                "credential" % (registry_info, conn_status.status_code)
            self.log.info(err_msg)

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_msg,
                                        error_code_list=err_code_list)

            try_msg = "Please try %s via requests to debug" % (conn_url)
            self.log.info(try_msg)
            return

        found_image_info = 0
        search_pattern = "rhel7"

        output = conn_status.json()
        if not error_found:
            for key, value in output.iteritems():
                if found_image_info:
                    break

                for item in value:
                    if re.search(search_pattern, item.strip()):
                        found_image_info = 1
                        break

        if not found_image_info:
            err_msg = "Registry output via:%s didnt find %s, in *** %s" \
                % (conn_url, search_pattern, output)
            self.log.info(err_msg)

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_msg,
                                        error_code_list=err_code_list)

            self.log.info(err_msg)
            return

        else:
            msg = "Registry %s reachable!!!" % (registry_info)
            self.log.info(msg)

        if not found_error:
            self.set_validation_results(chk_config)

        return

    def is_cimc_info_valid(self, cimc_info_dict={}, argus=0):
        ''' Checks that the CIMC Info is valid or not'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['SERVERS'])
        chk_config = "Check CIMC Validity"

        if bool(cimc_info_dict) and \
                not os.path.isfile(self.backup_setup_file):
            err_str = "Fatal Error; Can't proceed; " \
                      "As backup_setup_data.yaml does not exist"
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False

        try:
            if not argus:
                servers = self.ymlhelper.get_server_list()

            error_found = 0
            cimc_ip_addr_list = []
            cimc_uname_list = []
            cimc_pwd_list = []
            invalid_cimc_ip_addr_list = []
            missing_cimc_uname = []
            missing_cimc_pwd = []
            cimc_xml_chk_fail_list = []
            cimc_xml_chk_sec_list = []
            cimc_xml_chk_black_list = []
            cimc_version_chk_fail_list = []
            cimc_xml_chk_m430Intel_list = []
            cimc_xml_chk_Intel_Warn_list = []
            found_qct = 0

            if argus:
                cimc_ip_addr_list = self.ymlhelper.get_argus_server_list()
                cimc_uname_list = self.ymlhelper.get_argus_oob_username()
                cimc_pwd_list = self.ymlhelper.get_argus_oob_password()

            else:
                for server in servers:

                    ip_addr = \
                        self.ymlhelper.get_server_cimc_ip(server, return_value=1)
                    uname = self.ymlhelper.get_server_cimc_username(server)

                    if not re.match(r'UCSM', self.get_testbed_type()) \
                            and not found_qct:
                        server_type = self.ymlhelper.get_platform_vendor(server)
                        if server_type == 'QCT':
                            found_qct = 1

                    cimc_uname_list.append(uname)
                    if uname is None:
                        missing_cimc_uname.append(server)

                    if bool(cimc_info_dict):
                        found_change_pwd = 0
                        for _, host_info in cimc_info_dict.iteritems():
                            if ip_addr in host_info:
                                pwd = host_info[1]
                                cimc_pwd_list.append(pwd)
                                found_change_pwd = 1
                                break
                        if not found_change_pwd:
                            pwd = self.ymlhelper.get_server_cimc_password(server)
                            cimc_pwd_list.append(pwd)
                    else:
                        pwd = self.ymlhelper.get_server_cimc_password(server)
                        if pwd is None:
                            missing_cimc_pwd.append(server)
                        else:
                            cimc_pwd_list.append(pwd)

                    if self.is_ipv4v6_valid(ip_addr):
                        cimc_ip_addr_list.append(ip_addr)
                    else:
                        invalid_cimc_ip_addr_list.append(server)

        except TypeError:
            err_segment = "Missing Info in setup.yaml file"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)
            return

        if invalid_cimc_ip_addr_list:
            err_segment = "Missing/Invalid IP Addr:" + \
                          str(invalid_cimc_ip_addr_list)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)
            return

        if missing_cimc_uname:
            err_segment = "Missing CIMC Username:" + \
                          str(missing_cimc_uname)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)
            return

        if missing_cimc_pwd:
            err_segment = "Missing CIMC Password:" + str(missing_cimc_pwd)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)
            return

        if not error_found:
            threadlist = []
            for curr_ip, curr_uname, curr_pwd in zip(\
                    cimc_ip_addr_list, cimc_uname_list, cimc_pwd_list):

                kwargs = {}
                kwargs['curr_uname'] = curr_uname
                kwargs['curr_pwd'] = curr_pwd
                newthread = ExecThread(curr_ip, self.check_cimc_fw_version, **kwargs)
                newthread.start()
                threadlist.append(newthread)

            for mythread in threadlist:
                mythread.join()
                if mythread.oper_status == 60:
                    cimc_xml_chk_fail_list.append(mythread.host_ip)
                elif mythread.oper_status == 2:
                    cimc_xml_chk_sec_list.append(mythread.host_ip)
                elif mythread.oper_status == 3:
                    cimc_xml_chk_black_list.append(mythread.host_ip)
                elif mythread.oper_status == 4:
                    cimc_xml_chk_m430Intel_list.append(mythread.host_ip)
                elif mythread.oper_status == 5:
                    cimc_xml_chk_Intel_Warn_list.append(mythread.host_ip)

                if not mythread.oper_status:
                    self.log.info("CIMC FW Version Check %s Failed",
                                  mythread.host_ip)
                    cimc_version_chk_fail_list.append(mythread.host_ip)

        expt_str = " Expected Version >= 2.0(13i); " \
            "Recommend to use 2.0(13n) or 3.0(4d) for M4/M5 based servers"
        if self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT']):
            expt_str = " Expected Version >= 2.0(13n); " \
                "Recommend to use 3.0(4d) for M4/M5 based servers"

        if cimc_version_chk_fail_list:
            error_found = 1
            err_segment = "CIMC FW Version Check failed for :" + \
                str(cimc_version_chk_fail_list) + expt_str

            if found_qct:
                # NOTE: Assume all servers are same chassis type and there is
                #       no check for correct type of Quanta chassis used for
                #       particular POD type (i.e. CDC is for fullon or ceph
                #       POD type only but being used as GC for edge POD type).
                chassis_type = "UNKNOWN"
                for mythread in threadlist:
                    try:
                        cimc = cimcutils.CIMC(mythread.host_ip,
                                              mythread.kwargs['curr_uname'],
                                              mythread.kwargs['curr_pwd'])
                        chassis_type = cimc.cimc_check_chassis_type()
                        if chassis_type.startswith("Quanta_"):
                            break
                    except Exception:
                        self.log.warning("[%s] Error checking chassis type",
                                         mythread.host_ip)
                err_segment = "FW Version Check failed for: "
                err_segment += str(cimc_version_chk_fail_list)
                if chassis_type == "Quanta_CDC":
                    err_segment += (" Quanta CDC hardware require BMC >= "
                                    "%s.%s and BIOS >= %s.%s" % (
                                        bmconstants.QUANTA_BMC_CDC_MAJOR,
                                        bmconstants.QUANTA_BMC_CDC_MINOR,
                                        bmconstants.QUANTA_BIOS_CDC_MAJOR,
                                        bmconstants.QUANTA_BIOS_CDC_MINOR))
                elif chassis_type == "Quanta_GC":
                    err_segment += (" Quanta GC hardware require BMC >= "
                                    "%s.%s and BIOS >= %s.%s" % (
                                        bmconstants.QUANTA_BMC_GC_MAJOR,
                                        bmconstants.QUANTA_BMC_GC_MINOR,
                                        bmconstants.QUANTA_BIOS_GC_MAJOR,
                                        bmconstants.QUANTA_BIOS_GC_MINOR))
                elif chassis_type == "Quanta_5GSA":
                    err_segment += (" Quanta 5GSA hardware require BMC >= "
                                    "%s.%s and BIOS >= %s.%s" % (
                                        bmconstants.QUANTA_BMC_5GSA_MAJOR,
                                        bmconstants.QUANTA_BMC_5GSA_MINOR,
                                        bmconstants.QUANTA_BIOS_5GSA_MAJOR,
                                        bmconstants.QUANTA_BIOS_5GSA_MINOR))
                else:
                    err_segment += " Unknown/unsupported Quanta hardware"

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)
            return

        cimc_mod_black_tmp_str = ' or '.join(cimc_black_list)
        cimc_mod_black_str = "but not %s for UCS-M4/M5" % (cimc_mod_black_tmp_str)

        if cimc_xml_chk_fail_list:
            cimc_xml_chk_fail_str = ', '.join(cimc_xml_chk_fail_list)

            if found_qct:
                err_segment = "CIMC API Check failed for: " + \
                    cimc_xml_chk_fail_str + \
                    " : check for validity of " \
                    "IP, username and/or password"

            else:
                err_segment = "CIMC API Check failed for: " + \
                    cimc_xml_chk_fail_str + \
                    " : check for validity of CIMC version " \
                    "(>= 2.0(13i) " + cimc_mod_black_str + " is supported. " \
                    "Recommend to use 2.0(13n) or 3.0(4d) for " \
                    "M4/M5 based servers), IP, username and/or password " \
                    "or number of active CIMC sessions > 4"

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)
            return

        if cimc_xml_chk_sec_list:
            expt_str = "; Please upgrade to CIMC Version >= 2.0(13n), " \
                "%s; Recommend to use 2.0(13n) or 3.0(4d) " \
                "for M4/M5 based servers" % (cimc_mod_black_str)
            error_found = 1
            err_segment = "WARNING: CIMC FW Version has security " \
                "vulnerability: " + str(cimc_xml_chk_sec_list) + expt_str
            self.set_validation_results(chk_config, status=STATUS_PASS,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        # if cimc_xml_chk_black_list:
        #     expt_str = "; Please upgrade to CIMC Version >= 2.0(13n), " \
        #         "%s; Recommend to use 2.0(13n) or 3.0(4d) " \
        #         "for M4/M5 based servers" % (cimc_mod_black_str)
        #     err_segment = "Blacklisted CIMC FW Version used in %s %s" \
        #         % (cimc_xml_chk_black_list, expt_str)
        #     self.set_validation_results(chk_config, status=STATUS_FAIL,
        #                                 err=err_segment,
        #                                 error_code_list=err_code_list)
        #     return

        if cimc_xml_chk_m430Intel_list:
            expt_str = "Please run with CIMC Version >= 2.0(13n), " \
                "but not with CIMC 3.0(4a); It is " \
                "recommended to use 3.0(4d) for M4/M5 servers."
            error_found = 1
            err_segment = "WARNING: CIMC FW Version with M4/M5 and Intel NIC " \
                "has PXE issues %s. %s" \
                % (', '.join(cimc_xml_chk_m430Intel_list), expt_str)
            self.set_validation_results(chk_config, status=STATUS_PASS,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if not error_found:
            if cimc_xml_chk_Intel_Warn_list:
                err_segment = "WARNING: CIMC FW Version Check :" + \
                    str(cimc_xml_chk_Intel_Warn_list) + expt_str
                self.set_validation_results(chk_config, status=STATUS_PASS,
                                            err=err_segment)

            else:
                self.set_validation_results(chk_config)

        return

    def is_card_info_for_real(self, chassis_id=None, blade_id=None, rack_id=None):
        ''' Check if blade/rack info is real or not '''

        ucsm_ip = self.ymlhelper.get_common_ucsm_ip()
        ucsm_uname = self.ymlhelper.get_common_ucsm_username()
        ucsm_pwd = self.ymlhelper.get_common_ucsm_password()
        ucsm_prefix = self.ymlhelper.get_common_ucsm_prefix()

        ucsm_hdl = ucsmutils.UCSM(ucsm_ip, ucsm_uname, ucsm_pwd, ucsm_prefix)
        if ucsm_hdl is None:
            self.log.info("Can't Get UCSM object for %s", ucsm_ip)
            return 0

        check_value = 1
        try:
            check_value = ucsm_hdl.check_if_card_present(chassis_id, \
                                                         blade_id, \
                                                         rack_id)
        except urllib2.HTTPError:
            check_value = 0
        except Exception:
            check_value = 0

        ucsm_hdl.handle_logout()
        return check_value

    def is_card_fw_version_supported(self,
                                     chassis_id=None,
                                     blade_id=None,
                                     rack_id=None):
        ''' Check if blade/rack FW version is supported '''

        ucsm_ip = self.ymlhelper.get_common_ucsm_ip()
        ucsm_uname = self.ymlhelper.get_common_ucsm_username()
        ucsm_pwd = self.ymlhelper.get_common_ucsm_password()
        ucsm_prefix = self.ymlhelper.get_common_ucsm_prefix()

        found_error = 0
        ucsm_hdl = ucsmutils.UCSM(ucsm_ip, ucsm_uname, ucsm_pwd, ucsm_prefix)
        if ucsm_hdl is None:
            self.log.info("Can't Get UCSM object for %s", ucsm_ip)
            return 0

        if blade_id is not None:
            node_name = "chassis-%s/blade-%s" % (chassis_id, blade_id)
        else:
            node_name = "rack-unit-%s" % (rack_id)

        fw_version_check = 1
        if not found_error:
            node_fw_version = ucsm_hdl.check_card_fw_version(chassis_id, \
                                                             blade_id, \
                                                             rack_id)

            if re.search(r'APIFAILED', str(node_fw_version)):
                self.log.info("API failed on for %s:%s", ucsm_ip, node_name)
                fw_version_check = 0
            elif node_fw_version is False:
                self.log.info("Incorrect FW Version on %s:%s", ucsm_ip, node_name)
                fw_version_check = 0

        ucsm_hdl.handle_logout()

        return fw_version_check

    def is_blade_info_valid(self):
        ''' Checks that the Blade Info is valid or not'''

        chk_config = "Check Blade Info Validity"
        err_code_list = []
        err_code_list.append(self.validation_error_code['SERVERS'])

        if not self.ucsm_access:
            return

        try:
            servers = self.ymlhelper.get_server_list()
        except TypeError:
            err_segment = "Missing Info in setup.yaml file"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment)
            return

        error_found = 0
        missing_ucsm_info = []
        incorrect_server_type = []
        undefined_server_type = []
        incorrect_chassis_id = []
        undefined_chassis_id = []
        incorrect_blade_id = []
        undefined_blade_id = []
        undefined_rack_unit_id = []
        incorrect_rack_unit_id = []
        incorrect_value_format = []
        unique_rack_id_list = []
        dup_rack_id_list = []
        invalid_role_list = []
        chassis_blade_mapping = {}
        overlapping_blade_info = []
        invalid_card_check = []
        invalid_blade_fw_ver_check = []
        invalid_rack_fw_ver_check = []

        contoller_svr_list = self.ymlhelper.get_server_list(role='control')
        compute_svr_list = self.ymlhelper.get_server_list(role='compute')
        ceph_svr_list = self.ymlhelper.get_server_list(role='block_storage')
        compute_controller_list = contoller_svr_list + compute_svr_list

        for server in servers:
            server_type = "UNKNOWN"
            found_chassis_id = 0
            found_blade_id = 0

            try:
                ucsm_info = self.ymlhelper.get_server_ucsm_info(server)
            except KeyError:
                missing_ucsm_info.append(server)
                continue

            try:
                if ucsm_info['server_type'] is None:
                    undefined_server_type.append(server)
                elif not self.is_input_in_ascii(ucsm_info['server_type']):
                    incorrect_value_format.append(server)
                elif not re.match(r'blade|rack', ucsm_info['server_type']):
                    incorrect_server_type.append(server)
                elif re.match(r'blade', ucsm_info['server_type']):
                    server_type = "blade"
                elif re.match(r'rack', ucsm_info['server_type']):
                    server_type = "rack"
            except KeyError:
                undefined_server_type.append(server)

            if re.match(r'blade', server_type):
                if server not in compute_controller_list:
                    invalid_role_list.append(server)

                try:
                    if ucsm_info['chassis_id'] is None:
                        undefined_chassis_id.append(server)
                    elif not self.is_input_in_ascii(ucsm_info['chassis_id']):
                        incorrect_value_format.append(server)
                    elif not self.is_input_range_valid(
                            ucsm_info['chassis_id'], 1, 24):
                        incorrect_str = str(server) + ": Chassis id: " + \
                            str(ucsm_info['chassis_id'])
                        incorrect_chassis_id.append(incorrect_str)
                    else:
                        found_chassis_id = 1
                except KeyError:
                    undefined_chassis_id.append(server)

                try:
                    if ucsm_info['blade_id'] is None:
                        undefined_blade_id.append(server)
                    elif not self.is_input_in_ascii(ucsm_info['blade_id']):
                        incorrect_value_format.append(server)
                    elif not self.is_input_range_valid(ucsm_info['blade_id'], 1, 8):
                        incorrect_str = str(server) + ": Blade id: " + \
                            str(ucsm_info['blade_id'])
                        incorrect_blade_id.append(incorrect_str)
                    else:
                        found_blade_id = 1
                except KeyError:
                    undefined_blade_id.append(server)

                if found_blade_id and found_chassis_id:
                    # create key which includes chassis_id and blade_id
                    check_key = str(ucsm_info['chassis_id']) + ":" +\
                        str(ucsm_info['blade_id'])
                    if check_key in chassis_blade_mapping.keys() and \
                            chassis_blade_mapping[check_key]:
                        conflicting_servers = str(server) + ":" +\
                            str(chassis_blade_mapping[check_key])
                        overlapping_blade_info.append(conflicting_servers)
                    else:
                        chassis_blade_mapping[check_key] = str(server)
                        card_info_chk = self.is_card_info_for_real( \
                            str(ucsm_info['chassis_id']), \
                            str(ucsm_info['blade_id']))

                        incorrect_str = str(server) + ": Blade id: " + \
                            str(ucsm_info['blade_id'])
                        if not(card_info_chk):
                            invalid_card_check.append(incorrect_str)

                        else:
                            card_fw_version = self.is_card_fw_version_supported( \
                                str(ucsm_info['chassis_id']), \
                                str(ucsm_info['blade_id']))
                            if not card_fw_version:
                                invalid_blade_fw_ver_check.append(incorrect_str)

            elif re.match(r'rack', server_type):

                if server not in ceph_svr_list:
                    invalid_role_list.append(server)

                try:
                    if ucsm_info['rack-unit_id'] is None:
                        undefined_rack_unit_id.append(server)
                    elif not self.is_input_in_ascii(ucsm_info['rack-unit_id']):
                        incorrect_value_format.append(server)
                    elif not self.is_input_range_valid(
                            ucsm_info['rack-unit_id'], 1, 96):
                        incorrect_str = str(server) + ": Rack Unit id: " + \
                            str(ucsm_info['rack-unit_id'])
                        incorrect_rack_unit_id.append(incorrect_str)
                    elif ucsm_info['rack-unit_id'] not in unique_rack_id_list:
                        unique_rack_id_list.append(ucsm_info['rack-unit_id'])

                        card_info_chk = self.is_card_info_for_real(None, None, \
                            str(ucsm_info['rack-unit_id']))

                        incorrect_str = str(server) + ": Rack Unit id: " + \
                            str(ucsm_info['rack-unit_id'])
                        if not(card_info_chk):
                            invalid_card_check.append(incorrect_str)
                        else:
                            card_fw_version = self.is_card_fw_version_supported( \
                                None, None, str(ucsm_info['rack-unit_id']))
                            if not card_fw_version:
                                invalid_rack_fw_ver_check.append(incorrect_str)

                    else:
                        dup_rack_id_list.append(server)
                except KeyError:
                    undefined_rack_unit_id.append(server)

        if invalid_blade_fw_ver_check:
            error_found = 1
            err_segment = "UCSM FW Version Check failed for %s; " \
                "Expected Version >= 2.2(5a)" \
                % (','.join(invalid_blade_fw_ver_check))

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if invalid_rack_fw_ver_check:
            error_found = 1
            err_segment = "UCSM FW Version Check failed for %s; " \
                "Expected Version >= 2.0(3i)" \
                % (','.join(invalid_rack_fw_ver_check))

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if invalid_card_check:
            error_found = 1
            err_segment = "Invalid Card in Chassis: " + \
                str(invalid_card_check)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if missing_ucsm_info:
            error_found = 1
            err_segment = "Missing UCSM Info: " + \
                          str(missing_ucsm_info)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if overlapping_blade_info:
            error_found = 1
            err_segment = "Servers with conflicting blade +\
                slots for the same chassis: " + str(overlapping_blade_info)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if invalid_role_list:
            error_found = 1
            err_segment = "Incorrect ROLES to SERVERS (server_type) \
                          mapping for: " + str(invalid_role_list)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if dup_rack_id_list:
            error_found = 1
            err_segment = "Duplicate rack-unit_id for: " + \
                          str(dup_rack_id_list)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if incorrect_value_format:
            error_found = 1
            err_segment = "Invalid Input Format: " + \
                          str(incorrect_value_format)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if undefined_server_type:
            error_found = 1
            err_segment = "Missing Server of Type Blade/Rack: " + \
                          str(undefined_server_type)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if incorrect_server_type:
            error_found = 1
            err_segment = "Server of Type other than Blade set for : " + \
                          str(incorrect_server_type)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if undefined_chassis_id:
            error_found = 1
            err_segment = "Missing Chassis id: " + \
                str(undefined_chassis_id) + \
                " Expected Value: 1-7"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if incorrect_chassis_id:
            error_found = 1
            err_segment = "Incorrect Chassis id: " + \
                str(incorrect_chassis_id) + \
                " Expected Value: 1-7"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if undefined_blade_id:
            error_found = 1
            err_segment = "Missing Blade id: " + \
                str(undefined_blade_id) + \
                " Expected Value: 1-8"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment)

        if incorrect_blade_id:
            error_found = 1
            err_segment = "Incorrect Blade id: " + \
                str(incorrect_blade_id) + \
                " Expected Value: 1-8"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if undefined_rack_unit_id:
            error_found = 1
            err_segment = "Missing Rack Unit id for Ceph: " + \
                str(undefined_rack_unit_id) + \
                " Expected Value: 1-3"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if incorrect_rack_unit_id:
            error_found = 1
            err_segment = "Incorrect Unit id for Ceph: " + \
                str(incorrect_rack_unit_id) + \
                " Expected Value: 1-3"
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if not error_found:
            self.set_validation_results(chk_config)

        return

    def check_cimc_fw_version(self, cimc_ip, **kwargs):
        ''' executes show version to check if CIMC is alive'''

        cimc_uname = kwargs['curr_uname']
        cimc_password = kwargs['curr_pwd']
        cimc = cimcutils.CIMC(cimc_ip, cimc_uname, cimc_password, \
                              user_input_file=self.setup_file)
        if cimc is None:
            self.log.info("Can't Get CIMC object for %s", cimc_ip)
            return 0

        if self.ymlhelper.get_data_from_userinput_file(['INTEL_NIC_SUPPORT']):
            cimc_fw_version = \
                cimc.cimc_check_firmware_version(intel_nic_support=True)
        else:
            cimc_fw_version = \
                cimc.cimc_check_firmware_version(intel_nic_support=False)

        if re.search(r'APIFAILED', str(cimc_fw_version)):
            self.log.info("API failed for %s", cimc_ip)
            cimc.cimc_logout()
            return 60
        elif re.search(r'BLACKLISTEDCIMC', str(cimc_fw_version)):
            self.log.info("Blacklisted CIMC for %s", cimc_ip)
            cimc.cimc_logout()
            return 3
        elif re.search(r'UCSM4-CIMC30', str(cimc_fw_version)):
            self.log.info("Unsupported CIMC Major version with M4/M5 " \
                "on Intel NIC for %s", cimc_ip)
            cimc.cimc_logout()
            return 4
        elif re.search(r'SECVULNERABILITY', str(cimc_fw_version)):
            self.log.info("Security Vulnerability for %s", cimc_ip)
            cimc.cimc_logout()
            return 2
        elif re.search(r'INTELCIMCWARNING', str(cimc_fw_version)):
            self.log.info("Intel CIMC Warning for %s", cimc_ip)
            cimc.cimc_logout()
            return 5
        elif cimc_fw_version is False:
            self.log.info("Incorrect CIMC FW Version %s", cimc_ip)
            cimc.cimc_logout()
            return 0
        cimc.cimc_logout()
        return 1


    def report_invalid_input(self):
        ''' reports input is invalid'''

        chk_config = "Input Validation Check"
        err_segment = "Invalid Syntax for setup_data.yaml; \
                      Can't Verify the contents of setup_data.yaml"
        self.set_validation_results(chk_config, status=STATUS_FAIL,
                                    err=err_segment + \
                                    ". Please use a yaml \
                                    editor to inspect your file.")
        return

    def check_bn_ip_validity(self):
        ''' checks if build node ip belongs in provision network'''

        err_code_list = []

        # Get the management network type
        curr_mgmt_network = self.ymlhelper.get_management_network_type()

        err_code_list.append(self.validation_error_code['NETWORKING'])
        chk_config = "Check Management Node IP Validity"

        bn_ip = self.cfgmgr.get_build_node_ip('management', from_build_node="yes")
        error_found = 0
        if bn_ip is None and curr_mgmt_network == 'layer2':
            error_found = 1
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err="Management Node not configured \
                                            with IP from Provision Network", \
                                            error_code_list=err_code_list)
        else:
            subnet_family = "ipv6_subnet" if ipaddr.IPAddress(
                bn_ip).version == 6 else "subnet"
            mgmt_network_info = self.ymlhelper.nw_get_specific_vnic_info(\
                'management', subnet_family)

            if not self.validate_ip_for_a_given_network(\
                    bn_ip, mgmt_network_info) and curr_mgmt_network == 'layer2':
                error_found = 1
                self.set_validation_results(chk_config, status=STATUS_FAIL,
                                            err="Management Node not configured \
                                                with IP from Provision Network", \
                                                error_code_list=err_code_list)

            elif self.validate_ip_for_a_given_network(\
                    bn_ip, mgmt_network_info) and curr_mgmt_network == 'layer3':
                error_found = 1
                self.set_validation_results(chk_config, status=STATUS_FAIL,
                                            err="Management Node configured \
                                                with IP from Provision Network in a "
                                                "layer3 environment", \
                                                error_code_list=err_code_list)

            mgmt_pool_info = self.ymlhelper.nw_get_specific_vnic_info(\
                'management', 'pool')

            if mgmt_pool_info is not None and \
                    (self.check_ip_exists_in_a_pool(bn_ip, mgmt_pool_info) == 1):
                error_found = 1
                self.set_validation_results(chk_config, status=STATUS_FAIL,
                                            err="Management Node IP is part of the \
                                                management/provision pool", \
                                                error_code_list=err_code_list)

        if error_found:
            return

        self.set_validation_results(chk_config)
        return

    def check_cloud_auth_status(self, curr_action):
        '''Check the cloud auth status'''

        chk_config = "Check Cloud Auth Status"

        if self.ymlhelper.get_pod_type() == 'ceph':
            return

        if self.ymlhelper.get_pod_type() == 'CVIMMONHA':
            return

        os_cfg_loc = self.get_openstack_configs_loc()

        if not os_cfg_loc:
            self.log.info("Couldnt find openstack-configs dir")
            return

        openrc_loc = os_cfg_loc + "/openstack-configs/openrc"
        if not os.path.isfile(openrc_loc):
            return
        openrc_admin_pwd = common.fetch_rhs_from_openrc('OS_PASSWORD')

        secrets_file_loc = os_cfg_loc + "/openstack-configs/secrets.yaml"
        with open(self.backup_setup_file) as f:
            backup_setup_data = yaml.safe_load(f)

        if self.vault_config is not None and self.vault_config['enabled'] \
                and not self.skip_vault:
            try:
                secrets_admin_pwd = self.hvac_client.read(VAULT_SECRETS_PATH + \
                    '/ADMIN_USER_PASSWORD')['data']['data']['value']
            except Exception:

                # Check if vault value is False
                vault_backup_info = backup_setup_data.get('VAULT', None)
                if not vault_backup_info or not vault_backup_info['enabled']:
                    secrets_data_yaml = common.get_contents_of_file(secrets_file_loc)
                    secrets_admin_pwd = secrets_data_yaml.get(\
                        'ADMIN_USER_PASSWORD', None)
                else:
                    err_str = "Cannot read ADMIN_USER_PASSWORD from Vault"
                    self.set_validation_results(chk_config, status=STATUS_FAIL,
                                                err=err_str)
                    return
        else:
            secrets_data_yaml = common.get_contents_of_file(secrets_file_loc)
            secrets_admin_pwd = secrets_data_yaml.get('ADMIN_USER_PASSWORD')

        if secrets_admin_pwd != openrc_admin_pwd:
            err_str = "ADMIN_PASSWORD mismatch found in openrc " \
                "and vault/secrets.yaml"
            if curr_action == 'reconfigure':
                err_seg = "WARNING: %s during %s operation" % (err_str, curr_action)
                self.set_validation_results(chk_config, status=STATUS_PASS,
                                            err=err_seg)
                return
            else:
                self.set_validation_results(chk_config, status=STATUS_FAIL,
                                            err=err_str)
            return

        int_lb_info = self.ymlhelper.get_data_from_userinput_file(\
            ['internal_lb_vip_ipv6_address'])
        via_v6 = 1
        if int_lb_info is None:
            int_lb_info = self.ymlhelper.get_data_from_userinput_file(\
                ['internal_lb_vip_address'])
            via_v6 = 0
        fetch_token = common.execute_openstack_command('openstack',
                                                       'token issue',
                                                       'project_id',
                                                       int_lb_info,
                                                       via_v6)

        if re.search('ERROR', fetch_token):
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=fetch_token)
            return
        else:
            info_str = "%s: %s" % (chk_config, fetch_token)
            self.log.info(info_str)

        self.set_validation_results(chk_config)
        return

    def get_openstack_configs_loc(self):
        '''Gets the path to openstack-configs'''

        error_found = 0
        curr_command = ['/usr/bin/readlink', '/root/openstack-configs']
        output = ""
        try:
            output = subprocess.check_output(curr_command)
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found or not output:
            return ""

        dir_name = os.path.dirname(output)
        return dir_name

    def generate_cloud_env(self):
        '''Generates the cloud env file'''

        openrc_err = 0
        my_env = {}
        os_cfg_loc = self.get_openstack_configs_loc()

        if not os_cfg_loc:
            self.log.info("Couldnt find openstack-configs dir")
            return my_env, 0

        openrc_loc = os_cfg_loc + "/openstack-configs/openrc"
        if not os.path.isfile(openrc_loc):
            self.log.info("openrc file not found, can't proceed to \
                          determine cloud health")
            return my_env, 0
        else:
            try:
                show_command = ['/usr/bin/grep', '^export', openrc_loc]
                env_info = subprocess.check_output(show_command)
                for item in env_info.splitlines():
                    tmp = item.lstrip('export ')
                    curr_item = tmp.split("=")
                    if len(curr_item) > 1:
                        my_env[curr_item[0]] = curr_item[1]
            except subprocess.CalledProcessError:
                openrc_err = 1
            except OSError:
                openrc_err = 1

        if openrc_err:
            self.log.info("Can't read the openrc file to determine \
                          the cloud health")
            return my_env, 0

        return my_env, 1

    def check_currentcloud_status(\
            self, srv_list, role_list=[], vault_reconfigure=False):
        '''Run Ansible playbook and check cloud status'''

        runargs = {}
        runargs['playbook'] = "cloud-sanity.yaml"
        runargs['vault_reconfigure'] = vault_reconfigure

        if srv_list:
            runargs['replace_controller'] = srv_list

        ceph_server_list = self.ymlhelper.get_server_list(role="block_storage")

        exec_list = []
        err_return_str = ""
        for role in role_list:
            if re.search(r'compute', role):
                if "compute_check" not in exec_list:
                    exec_list.append("compute_check")

            elif re.search(r'block_storage', role):
                if "cephmon_check" not in exec_list:
                    exec_list.append("cephmon_check")

                if "cephosd_check" not in exec_list:
                    exec_list.append("cephosd_check")

            elif re.search(r'control', role):
                if "cntrl_check" not in exec_list:
                    exec_list.append("cntrl_check")

            elif re.search(r'cephosd', role):
                if "cephmon_check" not in exec_list:
                    exec_list.append("cephmon_check")

                if "cephosd_check" not in exec_list:
                    exec_list.append("cephosd_check")

            else:
                if "cntrl_check" not in exec_list:
                    exec_list.append("cntrl_check")

                if "compute_check" not in exec_list:
                    exec_list.append("compute_check")

                if ceph_server_list:
                    if "cephmon_check" not in exec_list:
                        exec_list.append("cephmon_check")

                    if "cephosd_check" not in exec_list:
                        exec_list.append("cephosd_check")

        err_list = []

        for check_type in exec_list:
            runargs['execute'] = check_type
            # Set Execution Context to Validation
            # Because clouddeploy/orchestrator.py needs to check whether
            # it's called from Step 1 or Step 7.
            # It'll be used to Decide to use secrets.yaml or
            # staging_secrets.yaml
            runargs['exec_context'] = "validation"
            retobj = orchestrator.run(run_args=runargs)
            if re.search(r'FAIL', retobj['status']):
                err_list.append(check_type)

        if err_list:
            err_return_str = ', '.join(err_list)
            err_return_str = "Check of type " + err_return_str + " :FAILED"

        return err_return_str

    def check_ready_for_node_add(self, srv_list, role):
        '''Check if the pod is ready for replace controller'''

        err_str = ""
        final_err_str = ""
        env_stat = 0
        my_env = {}
        missing_nodes = []
        invalid_nodes = []
        role_list = []

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        if podtype is not None and podtype == 'ceph':
            ceph_server_list = self.ymlhelper.get_server_list(role="cephosd")
        else:
            ceph_server_list = self.ymlhelper.get_server_list(role="block_storage")

        curr_svr_list = self.ymlhelper.get_server_list(role=role)
        for serv in srv_list:
            if serv not in curr_svr_list:
                missing_nodes.append(serv)

        if missing_nodes:
            missing_nodes_str = ' '.join(missing_nodes)
            err_str = "Missing nodes in setup_data.yaml " + str(missing_nodes_str)
            return missing_nodes_str

        if re.search(r'compute', role):
            my_env, env_stat = self.generate_cloud_env()

            if not env_stat:
                err_str = "Can't read the openrc file to determine \
                          the number of active computes"
                return err_str

            output = ""
            show_command = ['nova', 'hypervisor-list']

            error_found = 0

            try:
                output = subprocess.check_output(show_command, \
                                                 env=dict(os.environ, **my_env))
            except subprocess.CalledProcessError:
                error_found = 1
            except OSError:
                error_found = 1

            if error_found:
                err_str = "Can't execute the nova hypervisor-list command to \
                    determine the number of active compute"
            elif not error_found:
                for item in output.splitlines():
                    for serv in srv_list:
                        if re.search('{}$'.format(serv), item):
                            invalid_nodes.append(serv)

            if invalid_nodes:
                invalid_nodes_str = ' '.join(invalid_nodes)
                err_str = "Computes planned for addition are in the \
                    hypervisor list: " + str(invalid_nodes_str)

                return err_str

            role_list.append("control")
            if ceph_server_list:
                role_list.append("block_storage")

        elif re.search(r'block_storage|cephosd', role):
            if len(srv_list) != 1:
                invalid_nodes_str = ' '.join(srv_list)
                err_str = "Add of 1 Ceph node is allowed at a time: "\
                          + str(invalid_nodes_str)

                return err_str

            srv_str = ''.join(srv_list)

            runargs = {}
            runargs['playbook'] = "cloud-sanity.yaml"
            runargs['execute'] = "cephosd_check"
            runargs['osdinfo'] = srv_str
            retobj = orchestrator.run(run_args=runargs)

            if retobj['status'] == STATUS_FAIL:
                err_str = " OSD Check of type FAILED for role " + str(role)
                return err_str

            # by passing cloud sanity for ceph pod
            if re.search(r'cephosd', role):
                return final_err_str

            role_list.append("control")
            role_list.append("compute")

        tmp_srv_list = []
        curr_cloud_status = self.check_currentcloud_status(tmp_srv_list, \
                                                           role_list=role_list)
        if curr_cloud_status:
            if err_str:
                final_err_str = str(err_str) + " : " + str(curr_cloud_status)
            else:
                final_err_str = str(curr_cloud_status)

        elif err_str:
            final_err_str = str(err_str)

        return final_err_str

    def check_ready_for_replace_controller(self, srv_list):
        '''Check if the pod is ready for replace controller'''

        err_str = ""
        final_err_str = ""
        env_stat = 0
        my_env = {}
        my_env, env_stat = self.generate_cloud_env()

        if not env_stat:
            err_str = "Can't read the openrc file to determine \
                      the number of active controllers"
            return err_str

        output = ""
        show_command = ['nova', 'service-list']

        error_found = 0
        num_active_controllers = 0
        try:
            output = subprocess.check_output(show_command, \
                                             env=dict(os.environ, **my_env))
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found:
            err_str = "Can't execute the nova service-list command to \
                      determine the number of active controllers"
        elif not error_found:
            cntl_svr_list = self.ymlhelper.get_server_list(role='control')
            for serv in srv_list:
                for cntl_server in cntl_svr_list:
                    for item in output.splitlines():
                        parsed_op = ""
                        if "|" in item:
                            parsed_op = [i.strip() for i in item.split("|")]
                        if re.search(r'nova-scheduler', item) and \
                                re.search(r'up', item) \
                                and cntl_server in parsed_op \
                                and serv not in parsed_op:
                            num_active_controllers += 1

        if num_active_controllers < 2:
            err_str = "Num of active controllers needed to execute replace \
                      controllers is 2; Found: " + str(num_active_controllers)

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        if podtype is not None and re.match(r'micro|edge', podtype):
            return err_str

        ceph_server_list = self.ymlhelper.get_server_list(role="block_storage")
        role_list = []
        role_list.append("compute")
        if ceph_server_list is not None:
            role_list.append("block_storage")

        curr_cloud_status = self.check_currentcloud_status(srv_list, \
                                                           role_list=role_list)
        if curr_cloud_status:
            if err_str:
                final_err_str = str(err_str) + " : " + str(curr_cloud_status)
        elif err_str:
            final_err_str = str(err_str)

        return final_err_str

    def execute_cloud_sanity(self):
        """Execute Cloud_sanity"""

        pod_type = self.ymlhelper.get_pod_type()
        ceph_server_list = self.ymlhelper.get_server_list(role="block_storage")

        role_list = []
        if pod_type != 'ceph':
            role_list.append("control")
            role_list.append("compute")

            if ceph_server_list is not None:
                role_list.append("block_storage")

        else:
            role_list.append("cephcontrol")
            role_list.append("cephosd")

        vault_reconfigure = False
        if self.vault_config is not None and self.vault_config['enabled']:
            with open(self.backup_setup_file) as f:
                backup_setup_data = yaml.safe_load(f)
            if 'VAULT' not in backup_setup_data:
                vault_reconfigure = True
            else:
                # Check if vault value is False
                vault_backup_info = backup_setup_data.get('VAULT', None)
                vault_backup_value = vault_backup_info.get('enabled', None)
                if vault_backup_value is not None and vault_backup_value is False:
                    vault_reconfigure = True

        srv_list = []
        curr_cloud_status = self.check_currentcloud_status(\
            srv_list, role_list=role_list, vault_reconfigure=vault_reconfigure)

        final_err_str = STATUS_PASS
        if curr_cloud_status:
            final_err_str = "ERROR: " + str(curr_cloud_status)

        return final_err_str

    def get_server_info_from_backup(self, role=None):
        '''gets the server info from Backup setup_data'''

        ret_list = []
        found_error = 0
        with open(self.backup_setup_file, 'r') as f:
            try:
                doc_backup = yaml.safe_load(f)
            except yaml.parser.ParserError:
                found_error = 1
            except yaml.scanner.ScannerError:
                found_error = 1

        if found_error:
            return ret_list

        if 'ROLES' in doc_backup.keys():
            role_info = doc_backup['ROLES']
            if role == 'block_storage':
                if 'block_storage' in role_info.keys():
                    return doc_backup['ROLES']['block_storage']
                else:
                    ret_list.append('UNDEFINED')
                    return ret_list

            if role == 'compute':
                if 'control' in role_info.keys():
                    return doc_backup['ROLES']['compute']
                else:
                    ret_list.append('UNDEFINED')
                    return ret_list

            if role == 'control':
                if 'control' in role_info.keys():
                    return doc_backup['ROLES']['control']
                else:
                    ret_list.append('UNDEFINED')
                    return ret_list

            if role == 'cephcontrol':
                if 'cephcontrol' in role_info.keys():
                    return doc_backup['ROLES']['cephcontrol']
                else:
                    ret_list.append('UNDEFINED')
                    return ret_list

            if role == 'cephosd':
                if 'cephcontrol' in role_info.keys():
                    return doc_backup['ROLES']['cephosd']
                else:
                    ret_list.append('UNDEFINED')
                    return ret_list

        return ret_list

    def get_storage_deployment_info(self):
        '''look at the input file and get storage deployment info'''

        target_storage_deployment = ""
        volume_driver = self.ymlhelper.get_setup_data_property("VOLUME_DRIVER")

        if volume_driver is None:
            target_storage_deployment = "UNKNOWN"
        elif re.match(r'lvm|ceph', volume_driver):
            target_storage_deployment = volume_driver

        if re.match(r'UNKNOWN', target_storage_deployment):
            return target_storage_deployment

        svr_list = self.ymlhelper.get_server_list(role="block_storage")

        if not svr_list and re.match(r'ceph', volume_driver):
            return "CENTRAL_CEPH"
        elif not svr_list and re.match(r'lvm', volume_driver):
            return "LVM"
        elif svr_list and re.match(r'lvm', volume_driver):
            return "LVM_DEDICATED_CEPH"
        elif svr_list and re.match(r'ceph', volume_driver):
            return "DEDICATED_CEPH"
        else:
            return "STORAGE_TYPE_UNKNOWN"

    def check_valid_cm_action(self, action, new_vms):
        """Check if the Action on Central Mgmt servers are valid"""

        err_code_list = []
        err_code_list.append(self.validation_error_code['SERVERS_IN_VMS'])
        chk_config = "Action Validity Check for Central Mgmt"

        if 'all' in new_vms:
            return

        curr_servers_in_vm_list = []
        missing_vm_list = []
        present_vm_list = []
        curr_servers_in_vm = \
            self.ymlhelper.get_data_from_userinput_file(["SERVERS_IN_VMS"])
        for item in curr_servers_in_vm:
            server_name = item.get('name', None)
            curr_servers_in_vm_list.append(server_name)

        for item in new_vms:
            if action == 'add_vms' and \
                    item not in curr_servers_in_vm_list:
                missing_vm_list.append(item)
            if action == 'delete_vms' and \
                    item in curr_servers_in_vm_list:
                present_vm_list.append(item)

        if missing_vm_list:
            err_msg = "Target Central VMs %s not listed in the " \
                "intent file" % (','.join(missing_vm_list))
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=err_msg,
                                        error_code_list=err_code_list)
            return
        if present_vm_list:
            err_msg = "Central VMs targeted for removal %s listed in " \
                "the intent file" % (','.join(present_vm_list))
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=err_msg,
                                        error_code_list=err_code_list)
            return

        if action == 'add_vms' and \
                not os.path.isfile(self.backup_cm_setup_file):
            err_msg = "Add VMs only allowed on Day 2, for day 1 please use" \
                " --launch_all/-l option; Aborting launch of target VMs:%s" \
                      % (','.join(new_vms))
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=err_msg,
                                        error_code_list=err_code_list)
            return

        backup_servers_in_vm_list = []
        existing_vm_list = []
        absent_vm_list = []

        if os.path.isfile(self.backup_cm_setup_file):
            backup_cm_setup_file = config_parser.YamlHelper(\
                user_input_file=self.backup_cm_setup_file)
            backup_servers_in_vm = \
                backup_cm_setup_file.get_data_from_userinput_file(['SERVERS_IN_VMS'])

            for item in backup_servers_in_vm:
                server_name = item.get('name', None)
                backup_servers_in_vm_list.append(server_name)

        if action == 'add_vms':
            curr_new_servers = \
                list(set(curr_servers_in_vm_list) - set(backup_servers_in_vm_list))

            missing_launch_vms = list(set(curr_new_servers) - set(new_vms))

            if missing_launch_vms:
                err_msg = "Target Central VMs %s listed in the intent " \
                    "file but not targeted for launch" \
                    % (','.join(missing_launch_vms))
                self.set_validation_results(chk_config,
                                            status=STATUS_FAIL,
                                            err=err_msg,
                                            error_code_list=err_code_list)
                return

        if action == 'delete_vms':
            curr_new_servers = \
                list(set(backup_servers_in_vm_list) - set(curr_servers_in_vm_list))

            missing_launch_vms = list(set(curr_new_servers) - set(new_vms))

            if missing_launch_vms:
                err_msg = "Target Central VMs %s removed from the intet file " \
                    "but not targeted for delete" \
                    % (','.join(missing_launch_vms))
                self.set_validation_results(chk_config,
                                            status=STATUS_FAIL,
                                            err=err_msg,
                                            error_code_list=err_code_list)
                return

        for item in new_vms:
            if action == 'add_vms' and \
                    item in backup_servers_in_vm_list:
                existing_vm_list.append(item)

            if action == 'delete_vms' and \
                    item not in backup_servers_in_vm_list:
                absent_vm_list.append(item)

        if existing_vm_list:
            err_msg = "Central VMs %s already exists" \
                % (','.join(existing_vm_list))
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=err_msg,
                                        error_code_list=err_code_list)
            return

        if absent_vm_list:
            err_msg = "Central VMs %s targeted for removal missing in backup" \
                % (','.join(absent_vm_list))
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=err_msg,
                                        error_code_list=err_code_list)
            return

        self.set_validation_results(chk_config)

    def check_servers_exist(self, new_servers, role=None):
        ''' Check user provided servers on cli exist in userinput file'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['SERVERS'])
        chk_config = "Check validation of new servers"

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        invalid_servers = []
        storage_type = self.get_storage_deployment_info()

        backup_ceph_list = []
        # Get the server info from backup_setup_data
        if podtype is not None and podtype == 'ceph':
            backup_cntl_list = self.get_server_info_from_backup(role='cephcontrol')
        else:
            backup_cntl_list = self.get_server_info_from_backup(role='control')

        if podtype is not None and podtype == 'ceph':
            pass
        else:
            backup_compute_list = self.get_server_info_from_backup(role='compute')

        if podtype is not None and podtype == 'ceph':
            backup_ceph_list = \
                self.get_server_info_from_backup(role='cephosd')
        elif re.search(r'DEDICATED', storage_type):
            backup_ceph_list = \
                self.get_server_info_from_backup(role='block_storage')

        error_found_nano = 0
        error_found = 0
        backup_err_list = []

        if podtype is not None and podtype == 'nano':
            error_found = 1
            error_found_nano = 0
        elif (podtype is not None and podtype != 'ceph') \
                and (not backup_compute_list or \
                'UNDEFINED' in backup_compute_list):
            backup_err_list.append('compute')
            error_found = 1

        if not backup_cntl_list or \
                'UNDEFINED' in backup_cntl_list:
            backup_err_list.append('control')
            error_found = 1

        if re.search(r'DEDICATED', storage_type) and \
                (not backup_ceph_list or \
                'UNDEFINED' in backup_ceph_list):
            backup_err_list.append('ceph')
            error_found = 1
        elif (podtype is not None and podtype == 'ceph') and \
                (not backup_ceph_list or \
                'UNDEFINED' in backup_ceph_list):
            backup_err_list.append('ceph')
            error_found = 1

        if error_found:
            if error_found_nano:
                err_str = "Pod management operation of %s " \
                    "on pod type %s is not supported" % (role, podtype)
            else:
                err_str = "InCorrect baseline setup_data.yaml syntax for %s" \
                    % (','.join(backup_err_list))
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        # Get the server info from setup_data
        if podtype is not None and podtype == 'ceph':
            contoller_svr_list = self.ymlhelper.get_server_list(role='cephcontrol')
        else:
            contoller_svr_list = self.ymlhelper.get_server_list(role='control')

        tmp_compute_svr_list = []
        if podtype is not None and podtype == 'ceph':
            pass
        else:
            compute_svr_list = self.ymlhelper.get_server_list(role='compute')
            tmp_compute_svr_list = copy.deepcopy(compute_svr_list)

        tmp_ceph_svr_list = []
        if podtype is not None and podtype == 'ceph':
            ceph_svr_list = self.ymlhelper.get_server_list(role='cephosd')
            tmp_ceph_svr_list = copy.deepcopy(ceph_svr_list)

        elif re.search(r'DEDICATED', storage_type):
            ceph_svr_list = self.ymlhelper.get_server_list(role='block_storage')
            tmp_ceph_svr_list = copy.deepcopy(ceph_svr_list)

        incorrect_mod_list = []
        invalid_tgt_list = []
        existing_node_list = []

        # make sure servers for other roles are not modified
        if role == 'compute':
            if set(contoller_svr_list) != set(backup_cntl_list):
                tmp = list(set(contoller_svr_list). \
                           symmetric_difference(set(backup_cntl_list)))
                tmp_str = ':'.join(tmp)
                tmp_str2 = 'control::' + tmp_str
                incorrect_mod_list.append(tmp_str2)

            if re.search(r'DEDICATED', storage_type):
                # handle multi role scenario
                if podtype is not None and re.match(r'UMHC|NGENAHC', podtype):
                    for serv in new_servers:
                        if serv in ceph_svr_list and \
                                serv in compute_svr_list and \
                                serv not in backup_ceph_list:
                            tmp_ceph_svr_list.remove(serv)

                if set(tmp_ceph_svr_list) != set(backup_ceph_list):
                    tmp = list(set(tmp_ceph_svr_list). \
                               symmetric_difference(set(backup_ceph_list)))
                    tmp_str = ':'.join(tmp)
                    tmp_str2 = 'block_storage::' + tmp_str
                    incorrect_mod_list.append(tmp_str2)

            # make sure that only the right compute is changed
            for serv in new_servers:
                if serv in tmp_compute_svr_list and \
                        serv not in backup_compute_list:
                    tmp_compute_svr_list.remove(serv)

                # check if node exists, then no need to add
                if serv in backup_compute_list:
                    existing_node_list.append(serv)

            if set(tmp_compute_svr_list) != set(backup_compute_list):
                tmp = list(set(tmp_compute_svr_list).\
                           symmetric_difference(set(backup_compute_list)))
                invalid_tgt_list.extend(tmp)

        if role == 'block_storage' or role == 'cephosd':
            # make sure control and compute is not changed
            if set(contoller_svr_list) != set(backup_cntl_list):
                tmp = list(set(contoller_svr_list). \
                           symmetric_difference(set(backup_cntl_list)))
                tmp_str = ':'.join(tmp)
                tmp_str2 = 'control::' + tmp_str
                incorrect_mod_list.append(tmp_str2)

            if podtype is not None and re.match(r'UMHC|NGENAHC', podtype):
                for serv in new_servers:
                    if serv in ceph_svr_list and \
                            serv in compute_svr_list and \
                            serv not in backup_compute_list:
                        tmp_compute_svr_list.remove(serv)

            if podtype is not None and podtype == 'ceph':
                pass
            elif set(tmp_compute_svr_list) != set(backup_compute_list):
                tmp = list(set(tmp_compute_svr_list). \
                           symmetric_difference(set(backup_compute_list)))
                tmp_str = ':'.join(tmp)
                tmp_str2 = 'compute::' + tmp_str
                incorrect_mod_list.append(tmp_str2)

            for serv in new_servers:
                if serv in tmp_ceph_svr_list and serv not in backup_ceph_list:
                    tmp_ceph_svr_list.remove(serv)

                # check if node exists, then no need to add
                if serv in backup_ceph_list:
                    existing_node_list.append(serv)

            if set(tmp_ceph_svr_list) != set(backup_ceph_list):
                tmp = list(set(tmp_ceph_svr_list). \
                           symmetric_difference(set(backup_ceph_list)))
                invalid_tgt_list.extend(tmp)

        if role == 'control' or role == 'cephcontrol':
            # make sure ceph and compute is not changed
            if re.search(r'DEDICATED', storage_type):
                if set(ceph_svr_list) != set(backup_ceph_list):
                    tmp = list(set(ceph_svr_list). \
                               symmetric_difference(set(backup_ceph_list)))
                    tmp_str = ':'.join(tmp)
                    tmp_str2 = 'block_storage::' + tmp_str
                    incorrect_mod_list.append(tmp_str2)
            if set(contoller_svr_list) != set(backup_cntl_list):
                tmp = list(set(contoller_svr_list). \
                           symmetric_difference(set(backup_cntl_list)))
                tmp_str = ':'.join(tmp)
                tmp_str2 = 'control::' + tmp_str
                incorrect_mod_list.append(tmp_str2)

            if podtype is not None and re.match(r'ceph', podtype):
                pass
            elif set(compute_svr_list) != set(backup_compute_list):
                tmp = list(set(compute_svr_list). \
                           symmetric_difference(set(backup_compute_list)))
                tmp_str = ':'.join(tmp)
                tmp_str2 = 'compute::' + tmp_str
                incorrect_mod_list.append(tmp_str2)

        if incorrect_mod_list:
            err_str = "Servers in different role(s) %s modified during pod " \
                "management of %s" % (','.join(incorrect_mod_list), role)
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        if existing_node_list:
            err_str = "Servers %s targeted for pod management" \
                " already exists in the pod" % (','.join(existing_node_list))
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        if invalid_tgt_list:
            err_str = "New server(s) %s detected in setup_data, " \
                "but not included for pod management" \
                % (','.join(invalid_tgt_list))
            self.set_validation_results(chk_config,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        # checks if the node is in the setup_data.yaml file
        svr_list = self.ymlhelper.get_server_list(role=role)
        for serv in new_servers:
            if serv not in svr_list:
                invalid_servers.append(serv)

        # Check if # of OSDs to be added is != 1
        if role == 'block_storage' and len(new_servers) != 1:
            self.set_validation_results(chk_config, status=STATUS_FAIL, \
                                        err="Only add of 1 OSD is allowed at " + \
                                            " a time. Found to be " + \
                                            str(len(new_servers)) + \
                                            " in: " + ",".join(new_servers),
                                        error_code_list=err_code_list)
            return

        if role == 'cephosd' and len(new_servers) != 1:
            self.set_validation_results(chk_config, status=STATUS_FAIL, \
                                        err="Only add of 1 OSD is allowed at " + \
                                            " a time. Found to be " + \
                                            str(len(new_servers)) + \
                                            " in: " + ",".join(new_servers),
                                        error_code_list=err_code_list)
            return

        # Check # of controllers allowed to swap is == 1
        if (role == 'cephcontrol' or role == 'control') \
                and len(new_servers) != 1:
            self.set_validation_results(chk_config, status=STATUS_FAIL, \
                                        err="Only replace of 1 controller is "
                                            "allowed at a time. Found to be " + \
                                            str(len(new_servers)) + \
                                            " in: " + ",".join(new_servers),
                                        error_code_list=err_code_list)
            return

        if invalid_servers:
            err_msg = "%s servers %s not found in setup_data.yaml"  \
                % (role, ','.join(invalid_servers))
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_msg,
                                        error_code_list=err_code_list)
            return

        # checks if the node is in the setup_data.yaml file in the right role
        invalid_servers = []
        svr_list = self.ymlhelper.get_server_list(role=role)
        for serv in new_servers:
            if svr_list is None or serv not in svr_list:
                invalid_servers.append(serv)

        if invalid_servers:
            self.set_validation_results(chk_config, status=STATUS_FAIL, \
                                        err="Server(s) " + \
                                        ",".join(invalid_servers) + \
                                        " not valid " + role + " nodes", \
                                        error_code_list=err_code_list)
            return

        if self.test_type == 'nonblocking':
            return

        if role == 'control':
            try:
                ready_for_controller_swap = \
                    self.check_ready_for_replace_controller(new_servers)
            except (KeyError, TypeError):
                self.set_validation_results(chk_config, status=STATUS_FAIL, \
                                            err="Can't perform cloud \
                                            sanity check with " + \
                                            ",".join(new_servers) + " controller", \
                                            error_code_list=err_code_list)
                return

            if ready_for_controller_swap:
                self.set_validation_results(chk_config, status=STATUS_FAIL, \
                                            err=str(ready_for_controller_swap), \
                                            error_code_list=err_code_list)
                return

        elif re.search(r'compute|block_storage|cephosd', role):
            ready_for_node_add = \
                self.check_ready_for_node_add(new_servers, role)
            if ready_for_node_add:
                self.set_validation_results(chk_config, status=STATUS_FAIL, \
                                            err=str(ready_for_node_add), \
                                            error_code_list=err_code_list)
                return

        self.set_validation_results(chk_config)
        return

    def get_hypervisors_list(self):
        """ Method to return the list of hypervisors in the cloud
        """
        openrc_loc = '/opt/cisco/openrc'
        my_env = {}
        output = None
        openrc_err = "Can't read the openrc file to find the hypervisors"
        err_str = "Can't execute the nova hypervisor-list command"
        if not os.path.isfile(openrc_loc):
            return "openrc file not found, can't proceed to \
                      determine nova hypervisors"
        else:
            try:
                show_command = ['/usr/bin/grep', '^export', openrc_loc]
                env_info = subprocess.check_output(show_command)
                for item in env_info.splitlines():
                    curr_item = item.lstrip('export ').split("=")
                    if len(curr_item) > 1:
                        my_env[curr_item[0]] = curr_item[1]
            except (subprocess.CalledProcessError, OSError):
                return openrc_err

        show_command = ['nova', 'hypervisor-list']
        try:
            output = subprocess.check_output(show_command,
                                             env=dict(os.environ, **my_env))
        except (subprocess.CalledProcessError, OSError):
            return err_str

        return output

    def get_vms_per_hypervisor(self, hypervisor):
        """
        Method to find VM count on a given hypervisor
        """
        openrc_loc = '/opt/cisco/openrc'
        output = None
        openrc_err = "Can't read the openrc file to find the vm per " \
            "hypervisors"
        my_env = {}
        err_str = "Can't find VM count on a given hypervisor"
        if not os.path.isfile(openrc_loc):
            return "openrc file not found, can't proceed to \
                      determine vm count on a hypervisor"
        else:
            try:
                show_command = ['/usr/bin/grep', '^export', openrc_loc]
                env_info = subprocess.check_output(show_command)
                for item in env_info.splitlines():
                    curr_item = item.lstrip('export ').split("=")
                    if len(curr_item) > 1:
                        my_env[curr_item[0]] = curr_item[1]
            except (subprocess.CalledProcessError, OSError):
                return openrc_err

        try:
            args1 = "/usr/bin/openstack server list --host " \
                    + hypervisor + " --all-projects -f value -c ID"
            output1 = subprocess.Popen(args1.split(),
                                       stdout=subprocess.PIPE,
                                       env=dict(os.environ, **my_env))
            args2 = "wc -l"
            output2 = \
                subprocess.Popen(args2.split(),
                                 stdin=output1.stdout,
                                 stdout=subprocess.PIPE)
            output, stderr = output2.communicate()
            if stderr:
                return err_str
        except (subprocess.CalledProcessError, OSError):
            return err_str

        return output

    def check_server_preconfigured(self, servers):
        ''' Check if server was already configured
         during initial Openstack install '''

        section_name = "Check if server is preconfigured"
        found_error = False

        cobbler_ip = self.cfgmgr.get_build_node_ip('management')

        if (self.ymlhelper.get_pod_type() == 'ceph') or \
                (self.ymlhelper.get_pod_type() == 'nano'):
            hypervisor_list = []
        else:
            hypervisor_list = self.get_hypervisors_list()

        invalid_servers = []

        try:
            parsed_cobbler_file = config_parser.YamlHelper(
                user_input_file=self.cobbler_file)
            cobbler_file_dict = parsed_cobbler_file.\
                create_parsed_yaml(self.cobbler_file)
            for svr in servers:
                if svr in cobbler_file_dict and \
                        re.search(svr, hypervisor_list):
                    invalid_servers.append(svr)

        except ValueError:
            found_error = True
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err="Cobbler IP not Accessible " + \
                                            (cobbler_ip))
        except yaml.parser.ParserError as e:
            found_error = True
        except yaml.scanner.ScannerError as e:
            found_error = True

        if found_error:
            err_str = "InCorrect %s syntax; Error Info: %s" \
                % (self.cobbler_file, str(e))
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False


        if invalid_servers:
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err="Servers " + \
                                            ",".join(invalid_servers) + \
                                            " already part of OpenStack cloud")
            return False


        if not found_error:
            self.set_validation_results(section_name)

        return

    def check_valid_openstack_node(self, servers, role=None):
        '''Check user provided server is a valid compute node in cloud'''

        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])

        err_code_list = []
        err_code_list.append(self.validation_error_code['SERVERS'])
        section_name = "Check %s node marked for removal is valid" % (role)
        found_error = 0
        svr_list = self.ymlhelper.get_server_list()
        invalid_servers = []

        storage_type = self.get_storage_deployment_info()
        for server in servers:
            if server in svr_list:
                invalid_servers.append(server)

        backup_ceph_list = []
        tmp_compute_svr_list = []

        # Get the server info from backup_setup_data
        if podtype is not None and podtype == 'ceph':
            backup_cntl_list = self.get_server_info_from_backup(role='cephcontrol')
        else:
            backup_cntl_list = self.get_server_info_from_backup(role='control')
            backup_compute_list = self.get_server_info_from_backup(role='compute')
            tmp_compute_svr_list = copy.deepcopy(backup_compute_list)

        tmp_ceph_svr_list = []
        if podtype is not None and podtype == 'ceph':
            backup_ceph_list = \
                self.get_server_info_from_backup(role='cephosd')
            tmp_ceph_svr_list = copy.deepcopy(backup_ceph_list)

        elif re.search(r'DEDICATED', storage_type):
            backup_ceph_list = \
                self.get_server_info_from_backup(role='block_storage')
            tmp_ceph_svr_list = copy.deepcopy(backup_ceph_list)

        error_found = 0
        nano_error_found = 0
        backup_err_list = []
        if (podtype is not None and podtype != 'ceph') and \
                (not backup_compute_list or \
                'UNDEFINED' in backup_compute_list):
            backup_err_list.append('compute')
            error_found = 1

        if not backup_cntl_list or \
                'UNDEFINED' in backup_cntl_list:
            backup_err_list.append('control')
            error_found = 1

        if podtype is not None and podtype == 'nano':
            error_found = 1
            nano_error_found = 1
        elif podtype is not None and podtype == 'ceph':
            if (not backup_ceph_list or \
                    'UNDEFINED' in backup_ceph_list):
                backup_err_list.append('ceph')
                error_found = 1
        elif re.search(r'DEDICATED', storage_type) and \
                (not backup_ceph_list or \
                'UNDEFINED' in backup_ceph_list):
            backup_err_list.append('ceph')
            error_found = 1

        if error_found:
            if nano_error_found:
                err_str = "Pod operation for %s not allowed " \
                    "for %s pod" % (role, podtype)
            else:
                err_str = "InCorrect baseline setup_data.yaml syntax for %s" \
                    % (','.join(backup_err_list))
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        # Get the server info from setup_data
        if podtype is not None and podtype == 'ceph':
            contoller_svr_list = self.ymlhelper.get_server_list(role='cephcontrol')
        else:
            contoller_svr_list = self.ymlhelper.get_server_list(role='control')
            compute_svr_list = self.ymlhelper.get_server_list(role='compute')

        if podtype is not None and podtype == 'ceph':
            ceph_svr_list = self.ymlhelper.get_server_list(role='cephosd')
        elif re.search(r'DEDICATED', storage_type):
            ceph_svr_list = self.ymlhelper.get_server_list(role='block_storage')

        incorrect_mod_list = []
        invalid_tgt_list = []
        existing_node_list = []
        non_existing_node_list = []

        ignore_node_list = []

        # make sure servers for other roles are not modified
        if role == 'compute':
            if set(contoller_svr_list) != set(backup_cntl_list):
                tmp = list(set(contoller_svr_list). \
                           symmetric_difference(set(backup_cntl_list)))
                tmp_str = ':'.join(tmp)
                tmp_str2 = 'control::' + tmp_str
                incorrect_mod_list.append(tmp_str2)

            if re.search(r'DEDICATED', storage_type):
                #handle the multi role node
                if podtype is not None and re.match(r'UMHC|NGENAHC', podtype):
                    for serv in servers:
                        if serv in backup_ceph_list and \
                                serv in backup_compute_list and \
                                serv not in ceph_svr_list:
                            tmp_ceph_svr_list.remove(serv)

                if set(ceph_svr_list) != set(tmp_ceph_svr_list):
                    tmp = list(set(ceph_svr_list). \
                               symmetric_difference(set(tmp_ceph_svr_list)))
                    tmp_str = ':'.join(tmp)
                    tmp_str2 = 'block_storage::' + tmp_str
                    incorrect_mod_list.append(tmp_str2)

            # make sure that only the right compute is changed
            for serv in servers:
                if serv in tmp_compute_svr_list and \
                        serv not in compute_svr_list:
                    tmp_compute_svr_list.remove(serv)

                if serv in compute_svr_list:
                    existing_node_list.append(serv)

                if serv not in ignore_node_list and \
                        serv not in backup_compute_list:
                    non_existing_node_list.append(serv)

            if set(tmp_compute_svr_list) != set(compute_svr_list):
                tmp = list(set(tmp_compute_svr_list). \
                           symmetric_difference(set(compute_svr_list)))
                invalid_tgt_list.extend(tmp)

        if role == 'block_storage' or role == 'cephosd':
            # make sure control and compute is not changed
            if set(contoller_svr_list) != set(backup_cntl_list):
                tmp = list(set(contoller_svr_list). \
                           symmetric_difference(set(backup_cntl_list)))
                tmp_str = ':'.join(tmp)
                tmp_str2 = 'control::' + tmp_str
                incorrect_mod_list.append(tmp_str2)

            if podtype is not None and re.match(r'UMHC|NGENAHC', podtype):
                for serv in servers:
                    if serv in backup_ceph_list and \
                            serv in backup_compute_list and \
                            serv not in compute_svr_list:
                        tmp_compute_svr_list.remove(serv)

            if podtype is not None and podtype == 'ceph':
                pass
            elif set(compute_svr_list) != set(tmp_compute_svr_list):
                tmp = list(set(compute_svr_list). \
                           symmetric_difference(set(tmp_compute_svr_list)))
                tmp_str = ':'.join(tmp)
                tmp_str2 = 'compute::' + tmp_str
                incorrect_mod_list.append(tmp_str2)

            # make sure that only the right storage is changed
            for serv in servers:
                if serv in tmp_ceph_svr_list and serv not in ceph_svr_list:
                    tmp_ceph_svr_list.remove(serv)

                if serv in ceph_svr_list:
                    existing_node_list.append(serv)

                if serv not in ignore_node_list and \
                        serv not in backup_ceph_list:
                    non_existing_node_list.append(serv)

            if set(tmp_ceph_svr_list) != set(ceph_svr_list):
                tmp = list(set(tmp_ceph_svr_list). \
                           symmetric_difference(set(ceph_svr_list)))
                invalid_tgt_list.extend(tmp)

        if incorrect_mod_list:
            err_str = "Servers in different role(s) %s modified during pod " \
                      "management of %s" % (','.join(incorrect_mod_list), role)
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        if existing_node_list:
            err_str = "Servers %s targeted for %s removal" \
                " exists in setup_data" \
                % (role, ','.join(existing_node_list))
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        if invalid_tgt_list:
            err_str = "New server(s) %s deleted from setup_data, " \
                      "but not included for pod management" \
                      % (','.join(invalid_tgt_list))
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        if non_existing_node_list:
            err_str = "Servers %s targeted for %s removal" \
                " does not exist in backup_setup_data" \
                % (role, ','.join(non_existing_node_list))
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str,
                                        error_code_list=err_code_list)
            return

        # Check if # of OSDs to be removed is != 1
        if (role == 'block_storage' or role == 'cephosd') and len(servers) != 1:
            found_error = 1
            self.set_validation_results(section_name, status=STATUS_FAIL, \
                                    err="Only removal of 1 OSD is allowed " + \
                                        "at a time. Found to be " + \
                                        str(len(servers)) + \
                                        " in: " + ",".join(servers),
                                        error_code_list=err_code_list)
            return

        if invalid_servers:
            found_error = 1
            self.set_validation_results(section_name, status=STATUS_FAIL, \
                                        err="Server(s) " + \
                                        ",".join(invalid_servers) + \
                                        " still exist in setup_data.yaml. \
                                        If you intend to remove, \
                                        please remove from setup_data.yaml",
                                        error_code_list=err_code_list)

        if found_error:
            return

        err_msg = ""
        try:
            parsed_cobbler_file = config_parser.YamlHelper(
                user_input_file=self.cobbler_file)
            cobbler_file_dict = \
                parsed_cobbler_file.create_parsed_yaml(self.cobbler_file)

        except yaml.parser.ParserError as e:
            found_error = 1
            err_msg = str(e)
        except yaml.scanner.ScannerError as e:
            found_error = 1
            err_msg = str(e)

        if found_error:
            err_str = "InCorrect %s syntax; Error Info: %s" \
                % (self.cobbler_file, err_msg)
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return False

        invalid_servers = []
        for server in servers:
            if server in cobbler_file_dict:
                if 'role' in cobbler_file_dict[server]:
                    server_role = cobbler_file_dict[server]['role'].split()
                    if server not in cobbler_file_dict or role not in server_role:
                        invalid_servers.append(server)
                else:
                    invalid_servers.append(server)
            else:
                invalid_servers.append(server)

        if invalid_servers:
            self.log.info("Server(s) " + ",".join(invalid_servers) + \
                " not a valid " + role + " in cobbler server")

        if not found_error:
            self.set_validation_results(section_name)

        return

    def check_valid_controller_given(self, server):
        '''Check controller hostname is same as initial install'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['SERVERS'])
        section_name = "Check controller/cephcontrol hostname is " \
            "same as initial install"
        found_error = 0

        server = server[0]
        parsed_cobbler_file = config_parser.YamlHelper(
            user_input_file=self.cobbler_file)
        cobbler_file_dict = parsed_cobbler_file.create_parsed_yaml(self.cobbler_file)

        invalid_server = None
        if server in cobbler_file_dict:
            if 'role' in cobbler_file_dict[server]:
                server_role = cobbler_file_dict[server]['role'].split()

                if server not in cobbler_file_dict or \
                        ("control" not in server_role and \
                        "cephcontrol" not in server_role):
                    invalid_server = server
            else:
                invalid_server = server
        else:
            invalid_server = server

        if invalid_server:
            found_error = 1
            self.set_validation_results(section_name, status=STATUS_FAIL, \
                                        err="Controller with " + \
                                        invalid_server + " hostname not "
                                        "found in your cloud")

        if not found_error:
            self.set_validation_results(section_name)

    def check_ucsm_plugin_presence(self):
        '''Check if UCSM plugin is present in setup_data.yaml file'''

        if re.match(r'UCSM', self.get_testbed_type()):
            ucsm_common = self.ymlhelper.get_data_from_userinput_file(['UCSMCOMMON'])
            if 'ENABLE_UCSM_PLUGIN' in ucsm_common.keys():
                ucsm_plugin_info = ucsm_common['ENABLE_UCSM_PLUGIN']
                if ucsm_plugin_info:
                    return 1

        return 0

    def check_deployment_type_with_ucsm_plugin(self):
        '''Check that only OVS/VLAN is supported for B-series with UCSM Plugin'''

        mechanism_driver = \
            self.ymlhelper.get_data_from_userinput_file(["MECHANISM_DRIVERS"])

        network_type = self.get_network_type()

        if network_type is None:
            return "Invalid; network_type not defined"

        if network_type.lower() == "vlan":
            if re.match(r'openvswitch', mechanism_driver) \
                    or re.match(r'vpp', mechanism_driver):
                return ""

        return ("Invalid: UCSM Plugin is only supported for B-series "
                "with mechanism_driver of openvswitch or VPP and "
                "TENANT_NETWORK_TYPE as VLAN")

    def _get_vtc_api_client(self):
        ncs_ip = self.ymlhelper.parsed_config['VTS_PARAMETERS']['VTS_NCS_IP']
        username = self.ymlhelper.parsed_config['VTS_PARAMETERS']['VTS_USERNAME']
        password = self.ymlhelper.parsed_config['VTS_PARAMETERS']['VTS_PASSWORD']
        site_uuid = self.ymlhelper.parsed_config['VTS_PARAMETERS']['VTS_SITE_UUID']

        return VtcClient(ncs_ip, username, password, site_uuid)

    def _get_vtc_ssh_client(self):
        ncs_ip = self.ymlhelper.parsed_config['VTS_PARAMETERS']['VTS_NCS_IP']
        username = self.ymlhelper.parsed_config['VTS_PARAMETERS']['VTC_SSH_USERNAME']
        password = self.ymlhelper.parsed_config['VTS_PARAMETERS']['VTC_SSH_PASSWORD']

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ncs_ip, username=username, password=password, timeout=10)
        client.get_host_keys()
        return client

    def check_vtc(self):
        '''Check vtc enablement and day0'''
        vts_enabled = self.ymlhelper.get_mechanism_driver() == 'vts'
        vts_parameters = self.ymlhelper.parsed_config.get('VTS_PARAMETERS', {})
        vts_day0_enabled = vts_parameters.get('VTS_DAY0')

        if not vts_enabled:
            return

        if vts_day0_enabled:
            if self.check_vtc_reachable() == STATUS_FAIL:
                return
            if self.check_vtc_ssh_credentials() == STATUS_FAIL:
                return
            if self.check_vtc_version() == STATUS_FAIL:
                return
            if self.check_vtc_api_credentials() == STATUS_FAIL:
                return
            if self.check_vtc_xrvr_list() == STATUS_PASS:
                self.check_vtc_xrvr_loopback0()
                self.check_vtc_vtsr_ospf()

        self.check_vtc_vtsr_underlay_ips(vts_parameters)

    def check_vtc_reachable(self):
        '''Check vtc reachability'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['VTS_PARAMETERS'])
        status = STATUS_PASS
        err_msg = None
        ping_count = 4
        try:
            ncs_ip = self.ymlhelper.parsed_config['VTS_PARAMETERS']['VTS_NCS_IP']
            command = ['/usr/bin/ping', '-c', str(ping_count), '-w', '30', ncs_ip]
            subprocess.check_output(command, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as ex:
            status = STATUS_FAIL
            err_msg = 'VTS_PARAMETERS.VTS_NCS_IP IP address is not reachable'
        except KeyError as ex:
            status = STATUS_FAIL
            err_msg = 'Cannot find {msg} in setup_data.yaml'.format(msg=ex.message)
        except Exception as ex:
            status = STATUS_FAIL
            err_msg = ex.message

        if status == STATUS_FAIL:
            self.set_validation_results('VTC Virtual IP Check',
                                        status, err=err_msg,
                                        error_code_list=err_code_list)
        else:
            self.set_validation_results('VTC Virtual IP Check', status, err=err_msg)

        return status

    def check_vtc_api_credentials(self):
        '''Check vtc api credentials'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['VTS_PARAMETERS'])
        status = STATUS_PASS
        err_msg = None
        try:
            self._get_vtc_api_client()
        except KeyError as ex:
            status = STATUS_FAIL
            err_msg = 'Cannot find {msg} in setup_data.yaml'.format(msg=ex.message)
        except Exception as ex:
            status = STATUS_FAIL
            err_msg = 'Cannot connect to VTC API: {msg}'.format(msg=ex.message)

        if status == STATUS_FAIL:
            self.set_validation_results('VTC API Credentials Check',
                                        status, err=err_msg,
                                        error_code_list=err_code_list)
        else:
            self.set_validation_results('VTC API Credentials Check',
                                        status, err=err_msg)

        return status

    def check_vtc_xrvr_list(self):
        '''Check xrvr info'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['VTS_PARAMETERS'])
        status = STATUS_PASS
        err_msg = None
        try:
            client = self._get_vtc_api_client()
            xrvr_list = client.get_xrvr_device_list()
            if not xrvr_list:
                status = STATUS_FAIL
                err_msg = 'There are no VTSRs'
        except Exception as ex:
            status = STATUS_FAIL
            err_msg = 'Cannot get VTSRs list: {msg}'.format(msg=ex.message)

        section_name = 'VTC VTSRs Check'

        if status == STATUS_FAIL:
            self.set_validation_results(section_name, status,
                                        err=err_msg,
                                        error_code_list=err_code_list)
        else:
            self.set_validation_results(section_name, status, err=err_msg)

        return status

    def check_vtc_xrvr_loopback0(self):
        '''Checks the VTSR intf'''

        status = STATUS_PASS
        err_msg_list = []
        expected_interface = 'loopback0'
        try:
            client = self._get_vtc_api_client()
            vtsr_list = client.get_xrvr_device_list()
            for vtsr in vtsr_list:
                config = client.get_device_config(vtsr)
                config = \
                    config.get('Cisco-IOS-XR-ifmgr-cfg:interface-configurations', {})
                config = config.get('interface-configuration', {})
                for interface in config:
                    if expected_interface in interface['interface-name'].lower():
                        break
                else:
                    status = STATUS_FAIL
                    err_msg_list.append(
                        'Cannot find intf {i} on VTSR '
                        '{v}.'.format(i=expected_interface, v=vtsr))
        except Exception as ex:
            status = STATUS_FAIL
            err_msg_list.append('Cannot check intf on VTSRs: '
                                '{msg}'.format(msg=ex.message))

        self.set_validation_results('VTC VTSRs Intf Check',
                                    status, err='\n'.join(err_msg_list))
        return status

    def check_vtc_vtsr_ospf(self):
        '''Checks the VTSR OSPF Configuration'''

        status = STATUS_PASS
        err_msg_list = []
        try:
            client = self._get_vtc_api_client()
            vtsr_list = client.get_xrvr_device_list()
            for vtsr in vtsr_list:
                config = client.get_device_config(vtsr)
                config = \
                    config.get('Cisco-IOS-XR-ipv4-ospf-cfg:ospf', {})
                if not config.get('processes', []):
                    status = STATUS_FAIL
                    err_msg_list.append('Cannot find OSPF routers configured '
                                        'on VTSR {v}.'.format(v=vtsr))
        except Exception as ex:
            status = STATUS_FAIL
            err_msg_list.append('Cannot check OSPF configuration on VTSRs: '
                                '{msg}'.format(msg=ex.message))

        self.set_validation_results('VTC VTSRs OSPF Configuration Check',
                                    status, err='\n'.join(err_msg_list))
        return status

    def check_vtc_vtsr_underlay_ips(self, vts_parameters):
        '''Fetch and validate VTS_XRNC_TENANT_IPS'''

        status = STATUS_PASS
        err_msg_list = []
        defined_vtsr_ips = sorted(vts_parameters['VTS_XRNC_TENANT_IPS']) \
            if 'VTS_XRNC_TENANT_IPS' in vts_parameters else None
        try:
            client = self._get_vtc_api_client()
            vtsr_ips = sorted(client.get_xrvr_underlay_ips())
        except Exception:
            if not defined_vtsr_ips:
                status = STATUS_FAIL
                err_msg_list.append('VTS_XRNC_TENANT_IPS is neither defined '
                                    'in setup_data.yaml, nor able to be '
                                    'discovered from VTC.')
            else:
                err_msg_list.append('Warning: Cannot get VTS_XRNC_TENANT_IPS '
                                    'from VTC, fallback to use pre-defined '
                                    'VTS_XRNC_TENANT_IPS from setup_data.yaml.')
                vtsr_ips = defined_vtsr_ips

        if defined_vtsr_ips and vtsr_ips != defined_vtsr_ips:
            # Cross check the VTSR IP defined in setup_data.yaml is the same
            # as discovered
            status = STATUS_FAIL
            err_msg_list.append('VTS_XRNC_TENANT_IPS is defined in '
                                'setup_data.yaml (%s), but doesn\'t match '
                                'with the IPs discovered from VTC (%s).' %
                                (defined_vtsr_ips, vtsr_ips))

        self.set_validation_results('VTS_XRNC_TENANT_IPS Configuration Check',
                                    status, err='\n'.join(err_msg_list))

        return status

    def check_vtc_ssh_credentials(self):
        '''Check vtc ssh credantials'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['VTS_PARAMETERS'])
        status = STATUS_PASS
        err_msg = None
        try:
            self._get_vtc_ssh_client()
        except KeyError as ex:
            status = STATUS_FAIL
            err_msg = 'Cannot find {msg} in setup_data.yaml'.format(msg=ex.message)
        except Exception as ex:
            status = STATUS_FAIL
            err_msg = 'Cannot connect to VTC via ssh: {msg}'.format(msg=ex.message)

        if status == STATUS_FAIL:
            self.set_validation_results('VTC SSH Credentials Check', status,
                                        err=err_msg, error_code_list=err_code_list)
        else:
            self.set_validation_results('VTC SSH Credentials Check',
                                        status, err=err_msg)

        return status

    def check_vtc_version(self):
        '''checks the vts version'''
        status = STATUS_PASS
        err_msg = None
        exp_min_version = '2.5'
        exp_max_version = '2.6'
        try:
            client = self._get_vtc_ssh_client()
            _, stdout, _ = client.exec_command('/opt/vts/bin/version_info')  # nosec
            # Convert string to valid yaml. Replace '=' with ':'
            version_info = re.sub(r'(^|\n)(\w+)=', r'\1\2: ', stdout.read())
            version_info = yaml.safe_load(version_info)
            if version_info.get('vts_version') is None:
                status = STATUS_FAIL
                err_msg = 'VTC version not found in /opt/vts/bin/version_info' \
                          'Need {s} or later.'.format(s=exp_min_version)

            elif (re.match(str(exp_min_version), \
                           str(version_info['vts_version']))) or \
                    (re.match(str(exp_max_version), \
                              str(version_info['vts_version']))):
                pass
            elif (not re.match(str(exp_min_version), \
                               str(version_info['vts_version']))) \
                    and (not re.match(str(exp_max_version), \
                                      str(version_info['vts_version']))):
                status = STATUS_FAIL
                err_msg = 'VTC version {n} is not supported. Needs to be between ' \
                          '{m} and {x}.'.format(n=version_info['vts_version'],
                                                m=exp_min_version,
                                                x=exp_max_version)
        except Exception as ex:
            status = STATUS_FAIL
            err_msg = 'Cannot check VTC version: {msg}'.format(msg=ex.message)

        self.set_validation_results('VTC Version Check', status, err=err_msg)
        return status

    def check_section_input_info(self):
        ''' check if sections have the info in string format'''

        expected_section_other_info = ['TENANT_NETWORK_TYPES',
                                       'MECHANISM_DRIVERS']

        optional_section = ['MON_HOSTS', 'VNI_RANGE']

        missing_section_info = []
        invalid_info_list = []
        invalid_optional_item_entry = []
        invalid_value_format = []
        err_code_list = []
        curr_code_list = []
        warning_found = 0
        warning_msg = ""

        if self.ymlhelper.get_pod_type() == 'ceph':
            return

        if self.ymlhelper.get_pod_type() == 'CVIMMONHA':
            return

        mismatch_ucsm_plugin_found = 0
        for item in expected_section_other_info:
            ret_value = self.ymlhelper.check_section_exists(item)

            if ret_value is None:
                missing_section_info.append(item)
            elif not self.is_input_in_ascii(ret_value):
                invalid_value_format.append(item)
            else:

                if re.search(r'MECHANISM_DRIVERS', item) and \
                        fnmatch(r'linuxbridge', ret_value) and \
                        re.search('vlan', self.get_network_type(), re.IGNORECASE):
                    ex_input = item + " " + ret_value + \
                        "; Expected: TENANT_NETWORK_TYPES to be VXLAN"
                    invalid_info_list.append(ex_input)
                    curr_code_list.append(
                        self.validation_error_code['TENANT_NETWORK_TYPES'])

                elif re.search(r'MECHANISM_DRIVERS', item) and \
                        fnmatch(r'vts', ret_value) and \
                        re.search('vxlan', self.get_network_type(), \
                            re.IGNORECASE):
                    ex_input = item + " " + ret_value + \
                        "; Expected: TENANT_NETWORK_TYPES to be VLAN"
                    invalid_info_list.append(ex_input)
                    curr_code_list.append(
                        self.validation_error_code['TENANT_NETWORK_TYPES'])

                elif re.search(r'MECHANISM_DRIVERS', item) and \
                        fnmatch(r'vpp', ret_value) and \
                        re.search('vxlan', self.get_network_type(), \
                            re.IGNORECASE):
                    ex_input = item + " " + ret_value + \
                        "; Expected: TENANT_NETWORK_TYPES to be VLAN"
                    invalid_info_list.append(ex_input)
                    curr_code_list.append(
                        self.validation_error_code['TENANT_NETWORK_TYPES'])

                elif re.search(r'MECHANISM_DRIVERS', item) and \
                        fnmatch(r'aci', ret_value) and \
                        re.search('vxlan', self.get_network_type(), \
                            re.IGNORECASE):
                    ex_input = item + " " + ret_value + \
                        "; Expected: TENANT_NETWORK_TYPES to be VLAN"
                    invalid_info_list.append(ex_input)
                    curr_code_list.append(
                        self.validation_error_code['TENANT_NETWORK_TYPES'])

                elif re.search(r'MECHANISM_DRIVERS', item) and \
                        fnmatch(r'vpp', ret_value) and \
                        re.search('vlan', self.get_network_type(), \
                            re.IGNORECASE):

                    intel_nic_pod = \
                        self.ymlhelper.get_data_from_userinput_file(\
                            ['INTEL_NIC_SUPPORT'])
                    if intel_nic_pod is None or intel_nic_pod is False:
                        warning_msg = "WARNING: Support for VPP is deprecated " \
                                      "on Cisco VIC configuration"
                        warning_found = 1

        #Check if USCM only is deployed for B-series with OVS/VLAN
                if not mismatch_ucsm_plugin_found and \
                        self.check_ucsm_plugin_presence():
                    check_dep_with_ucsm_plugn = \
                        self.check_deployment_type_with_ucsm_plugin()
                    if check_dep_with_ucsm_plugn:
                        mismatch_ucsm_plugin_found = 1
                        ex_input = item + " " + ret_value + " " + \
                            check_dep_with_ucsm_plugn
                        invalid_info_list.append(ex_input)
                        curr_code_list.append(\
                            self.validation_error_code['MECHANISM_DRIVERS'])

        if curr_code_list:
            ve_str = "^".join(curr_code_list)
            err_code_list.append(ve_str)

        for item in optional_section:
            ret_value = self.ymlhelper.check_section_exists(item)

            if ret_value is None:
                continue
            elif not self.is_input_in_ascii(ret_value):
                invalid_value_format.append(item)

            if re.search(r'VNI_RANGE', item):
                try:
                    vni_items = ret_value.split(":")
                    if len(vni_items) != 2:
                        ex_input = item + " Expected Format: min_vni_id:max_vni_id"
                        invalid_optional_item_entry.append(ex_input)
                    elif not vni_items[0].isdigit or not vni_items[1].isdigit:
                        ex_input = item + " Expected Format: min_vni_id:max_vni_id"
                        invalid_optional_item_entry.append(ex_input)
                    elif int(vni_items[0]) < 1 or int(vni_items[0]) > 16777216:
                        ex_input = item + " Expected Range: min_vni_id 1 to 2^24"
                        invalid_optional_item_entry.append(ex_input)
                    elif int(vni_items[1]) < 1 or int(vni_items[1]) > 16777216:
                        ex_input = item + " Expected Range: max_vni_id 1 to 2^24"
                        invalid_optional_item_entry.append(ex_input)
                    elif int(vni_items[0]) > int(vni_items[1]):
                        ex_input = item + " Expected min_vni_id < max_vni_id"
                        invalid_optional_item_entry.append(ex_input)
                except ValueError:
                    continue

            elif re.search(r'MON_HOSTS', item):
                check_flag = 0
                if ret_value is None:
                    continue
                else:
                    try:
                        _ = ret_value
                        check_flag = 1
                    except ValueError:
                        continue

                if check_flag:
                    try:
                        ip_list = ret_value.split(",")
                    except ValueError:
                        ip_list = ret_value.split("")
                    for ip in ip_list:
                        if not self.is_ipv4v6_valid(ip):
                            my_str = item + ":" + ip
                            if my_str not in invalid_optional_item_entry:
                                invalid_optional_item_entry.append(my_str)

        chk_config = "Check Section Info"
        error_found = 0
        if invalid_value_format:
            error_found = 1
            err_segment = "Invalid Input Format: " + str(invalid_value_format)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment)

        if missing_section_info \
                or invalid_info_list \
                or invalid_optional_item_entry \
                or invalid_value_format:

            error_found = 1
            err_segment = ""
            if missing_section_info:
                err_segment = "Missing Section Entry:" + \
                              str(missing_section_info) + ";"

            if invalid_info_list:
                err_segment += "Invalid Info:" + str(invalid_info_list)

            if invalid_optional_item_entry:
                err_segment += "Invalid Info:" + str(invalid_optional_item_entry)

            if invalid_value_format:
                err_segment += "Invalid Value Format:" + str(invalid_value_format)

            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment + " incorrect/not provided",
                                        error_code_list=err_code_list)
            return

        if not error_found:
            if warning_found:
                self.set_validation_results(chk_config,
                                            status=STATUS_PASS,
                                            err=warning_msg)
            else:
                self.set_validation_results(chk_config)

        return

    def get_installer_path(self):
        ''' Get installer path if present '''
        app_conf_path = "/opt/cisco/mercury_restapi/app.conf"
        try:
            with open(app_conf_path, 'r') as f:
                for line in f:
                    if "installer_dir =" in line:
                        return line.split("installer_dir = ")[1].strip('\n')
        except IOError:
            return None

    def check_insight_workspace(self):
        '''Checks to see if Insight workspace is different
        from installer workspace'''

        ks_config = "CVIM/Insight Workspace Conflict Check"
        error_found = 0

        err_msg = ""
        vim_dir = self.get_installer_path()
        if vim_dir is None:
            err_msg = "Unable to fetch VIM Installer dir path"
            self.log.info("Unable to read app.conf from /opt/cisco/mercury_restapi")
            error_found = 1
        else:
            if re.search(r'/root/Insight-', vim_dir, re.IGNORECASE):
                error_found = 1
                err_msg = "VIM Install can't proceed " \
                          "from Insight reserved workspace" \
                          " i.e. it should not have " \
                          "/root/<I|i>nsight-<tag-id> as prefix.\n" \
                          "E.g. workspace: /root/installer-<tag-id>."\
                          " Current VIM Install dir %s" % (vim_dir)
        if error_found:
            err_segment = "%s" % (err_msg)
            self.set_validation_results(ks_config, status=STATUS_FAIL,
                                        err=err_segment)

        if not error_found:
            self.set_validation_results(ks_config)

        return

    def check_solidfire_svip(self):
        '''Checks if the solidfire SVIP is in storage network'''

        ks_config = "SolidFire SVIP Network Check"
        solidfire_present = \
            self.ymlhelper.get_data_from_userinput_file(['SOLIDFIRE'])

        if solidfire_present is None:
            return 0

        cluster_svip_info = solidfire_present.get('cluster_svip')

        storage_network_check = 0

        # check if solid fire is in storage network
        storage_network = \
            self.ymlhelper.nw_get_specific_vnic_info( \
                'storage', 'subnet')

        mgmt_network = \
            self.ymlhelper.nw_get_specific_vnic_info( \
                'management', 'subnet')

        if self.validate_ip_for_a_given_network( \
                cluster_svip_info, storage_network):
            storage_network_check = 1

        if not storage_network_check:
            err_segment = "WARNING: Solidfire SVIP:%s is in " \
                "management network:%s; Please have it in " \
                "Storage Network:%s to get better performance" \
                % (cluster_svip_info, mgmt_network, storage_network)
            self.set_validation_results(ks_config, status=STATUS_PASS,
                                        err=err_segment)

        else:
            self.set_validation_results(ks_config)

        return

    def check_ssh_access_permit_root_login_comp(self):
        """Warn if SSH_ACCESS_OPTIONS/enforce_single_session is 1 with
        permit root login"""

        section_name = "SSH_ACCESS_OPTIONS and perrmit_root_login Compatbility Check"
        ssh_access_option = \
            self.ymlhelper.get_data_from_userinput_file(['SSH_ACCESS_OPTIONS'])

        if ssh_access_option is None:
            return

        permit_root_check = \
            self.ymlhelper.get_data_from_userinput_file(['permit_root_login'])

        if permit_root_check is None:
            return

        if permit_root_check is True:
            return

        enforce_single_session = ['SSH_ACCESS_OPTIONS', 'enforce_single_session']
        is_enforce_single_session = \
            self.ymlhelper.get_deepdata_from_userinput_file(enforce_single_session)

        if is_enforce_single_session is None:
            return

        if is_enforce_single_session is not None and not is_enforce_single_session:
            return

        err_segment = "WARNING: Setting SSH_ACCESS_OPTIONS/enforce_single_session " \
            "with permit_root_login as false while more secure, " \
            "can have negative impact to operation"
        self.set_validation_results(section_name, status=STATUS_PASS,
                                    err=err_segment)

    def check_nova_boot_from_option(self):
        """Check NOVA boot from option"""

        ks_config = "Check NOVA Boot From Option"
        nova_boot_from_value = \
            self.ymlhelper.get_data_from_userinput_file(['NOVA_BOOT_FROM'])

        if nova_boot_from_value is None:
            return

        if nova_boot_from_value == 'ceph':
            err_segment = "WARNING: In an NFVI environment it is " \
                "recommended that NOVA_BOOT_FROM be set to local, not Ceph"
            self.set_validation_results(ks_config, status=STATUS_PASS,
                                        err=err_segment)

        else:
            self.set_validation_results(ks_config)

        return

    def pre_tor_config_validation(self, section_name, curr_action):
        '''TOR Config check pre-configuration'''

        tor_config = self.ymlhelper.get_tor_config()
        if tor_config is None or \
                ('CONFIGURE_TORS' in tor_config.keys() and \
                not tor_config['CONFIGURE_TORS']):
            return

        tor_type = self.ymlhelper.get_tor_type() or NEXUS_TOR_TYPE
        runargs = {}
        runargs['playbook'] = "pre-tor-validation.yaml"
        if tor_type == NEXUS_TOR_TYPE:
            runargs['action'] = "validate-tors"
        if tor_type == NCS_TOR_TYPE:
            runargs['action'] = "ncs-pre-validation"

        os.environ['AUTO_TOR_SETUP_DATA'] = self.setup_file
        os.environ['AUTO_TOR_OP'] = curr_action

        runargs['setup_file'] = self.setup_file
        retobj = build_orchestration.run(runargs)

        if retobj['status'] == STATUS_FAIL:
            self.set_validation_results(section_name, status=STATUS_FAIL,
                                        err="ToR/NCS Platform Validation failure")
        if retobj['status'] == STATUS_PASS:
            self.set_validation_results(section_name)

    def post_tor_config_validation(self, section_name):
        '''TOR Config check post configuration'''

        tor_config = self.ymlhelper.get_tor_config()
        if tor_config is None or \
                ('CONFIGURE_TORS' in tor_config.keys() and \
                not tor_config['CONFIGURE_TORS']):
            return

        tor_type = self.ymlhelper.get_tor_type() or NEXUS_TOR_TYPE
        runargs = {}
        runargs['playbook'] = "post-tor-validation.yaml"
        if tor_type == NEXUS_TOR_TYPE:
            runargs['action'] = "verify-tors"
        if tor_type == NCS_TOR_TYPE:
            runargs['action'] = "ncs-post-validation"

        runargs['setup_file'] = self.setup_file
        retobj = build_orchestration.run(runargs)

        if retobj['status'] == STATUS_FAIL:
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err="ToR/NCS provisioning failed. "
                                            "Check your ToR configs.")
        if retobj['status'] == STATUS_PASS:
            self.set_validation_results(section_name)

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

    def check_link_agg_for_tor(self, section_name):
        '''Check link agg for TOR'''

        mgmt_node_type = common.fetch_mgmt_node_type()
        if mgmt_node_type == "vm":
            return

        error_found = 0
        show_command = ['/usr/sbin/ip', '-d', '-o', 'link']

        try:
            output = subprocess.check_output(show_command)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found:
            err_str = "Execution of %s Failed" \
                % (' '.join(show_command))
            self.set_validation_results(section_name,
                                        status=STATUS_FAIL,
                                        err=err_str)
            return

        for item in output.splitlines():
            if self.is_tor_type_ncs5500() and \
                    re.search(r'team_slave', item.strip()):
                err_str = "L2 Agg of teaming found on mgmt node " \
                    "when TOR is NCS-5500"
                self.set_validation_results(section_name,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return
            elif common.is_pod_upgraded():
                self.set_validation_results(section_name)
                return
            elif not self.is_tor_type_ncs5500() and \
                    re.search(r'bond_slave', item.strip()):
                err_str = "L2 Agg of bonding found on mgmt node " \
                    "when TOR is not NCS-5500"
                self.set_validation_results(section_name,
                                            status=STATUS_FAIL,
                                            err=err_str)
                return

        self.set_validation_results(section_name)
        return

    def check_snmp_status(self):
        '''
        Verify if SNMP is up and listening to 1161 port
        '''
        section_name = "Verify SNMP service is up"
        status = STATUS_FAIL
        try:
            output = subprocess.check_output(['/usr/sbin/ss', '-panl'])
        except subprocess.CalledProcessError:
            self.set_validation_results(section_name, status, \
                err="Couldn't check for SNMP port")
            return
        snmp_found = False
        for item in output.splitlines():
            if (re.search(r'127.0.0.1:1161', item) and re.search(r'httpd', item)):
                snmp_found = True
                break
        if not snmp_found:
            self.set_validation_results(section_name, status, \
                err="Port for SNMP service not opened")
            return
        try:
            url = ('http://localhost:1161')
            r = requests.get(url)
        except (requests.exceptions.ConnectionError, \
                requests.exceptions.ConnectTimeout) as e:
            self.set_validation_results(section_name, status, \
                err="SNMP rest-api got exception: %s" % e)
            return
        if r.status_code != 200:
            self.set_validation_results(section_name, status, \
                err="SNMP rest-api got error %s" % r.status_code)
            return
        # Success case
        self.set_validation_results(section_name)
        return

    def check_server_mon_status(self):
        '''
        Verify if SERVER_MON is up and listening to udp port 5140 and
        it has port 7081 open
        '''
        section_name = "Verify SERVER_MON service is up"
        status = STATUS_FAIL
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            _ = sock.connect_ex(('127.0.0.1', 7081))
        except socket.error:
            self.set_validation_results(
                section_name, status, err="Port for ucs-monitor is not open")
            return
        try:
            output = subprocess.check_output(['/usr/sbin/ss', '-panl'])
        except subprocess.CalledProcessError:
            self.set_validation_results(
                section_name, status, err="Couldn't check for RSYSLOG UCS port")
            return
        key = ["SERVER_MON", "rsyslog_severity"]
        server_mon_sev = self.ymlhelper.get_data_from_userinput_file(key)
        if not server_mon_sev:
            self.set_validation_results(section_name)
            return
        # Validate SYSLOG part of SERVER_MON
        server_mon_rsyslog_found = False
        api_ip = self.get_mgmt_node_info('br_api')

        ucs_rsyslog = "5140"
        if not api_ip:
            self.log.error("Couldn't not get br_api ip address %s" % str(api_ip))
            self.set_validation_results(section_name, status,
                                        err="br_api value not found")
            return

        ip_and_port = re.escape(api_ip) + ":" + re.escape(ucs_rsyslog)
        for line in output.splitlines():
            if (re.search(ip_and_port, line) and re.search(r'td-agent', line)):
                server_mon_rsyslog_found = True
                break

        if not server_mon_rsyslog_found:
            self.set_validation_results(section_name, status, \
                err="Port for RSYSLOG SERVER_MON service not opened")
            return

        # Success case
        self.set_validation_results(section_name)
        return

    def check_intf_policy_preprovisioning(self):
        '''Check if interface policies are pre-provisioned'''


        configure_fabric = ['APICINFO', 'configure_fabric']

        cfg_fabric_chk = \
            self.ymlhelper.get_deepdata_from_userinput_file(configure_fabric)

        if cfg_fabric_chk is None:
            return
        elif cfg_fabric_chk is not None and cfg_fabric_chk:
            return

        section_name = "Check Fabric Access Config"

        fab_cfg_status = apic_orchestration.discover_fabric_access_config()

        err_msg = fab_cfg_status.get('message')
        status = fab_cfg_status.get('status')

        if status == STATUS_PASS:
            self.set_validation_results(section_name)
            return

        err_msg += str(fab_cfg_status.get('unconfig_pprofiles_ppolicies', ''))
        err_msg += '\n' + str(fab_cfg_status.get('unconfig_sriov_policies', ''))
        err_msg_details = " %s Failure details Info: \n %s" \
                          % (section_name, fab_cfg_status)
        self.log.info(err_msg_details)

        self.set_validation_results(section_name, status, err_msg)
        return


    def check_server_fabric_connectivity(self, curr_action):
        '''Check Sever ToR Connectivity'''

        auto_tor_via_aci = self.cfgmgr.extend_auto_tor_to_aci_fabric()
        curr_mech_driver = self.ymlhelper.check_section_exists('MECHANISM_DRIVERS')

        if curr_mech_driver != 'aci' and not auto_tor_via_aci:
            return

        section_name = "Check Server/Fabric Connectivity"
        invalid_switch_port_list = []
        error_found = 0

        api_orch_handle = apic_orchestration.Orchestrator(self.setup_file)

        leaf_inft_dict = api_orch_handle.check_phys_interface_state()

        rogue_switch_list = []
        if leaf_inft_dict.get('status', None) == STATUS_FAIL:
            err_msg = leaf_inft_dict.get('err_msg')

            if err_msg is None:
                err_msg = "ERROR: Unmapped ACI Leaf switche(s) found"

            error_found = 1
            if self.pod_pv_count_per_switch:
                for key, value in self.pod_pv_count_per_switch.iteritems():
                    if value == 0:
                        rogue_switch_list.append(key)

            if rogue_switch_list:
                err_msg = "ERROR: Unmapped ACI Leaf switche(s) found: %s" \
                    % (', '.join(rogue_switch_list))

        else:
            for switch, entry in leaf_inft_dict.iteritems():
                if entry:
                    error_found = 1
                    for item in entry:
                        tmp = "%s:%s" % (switch, item)
                        invalid_switch_port_list.append(tmp)

            if error_found:
                err_msg = "Servers with in-correct mapping found" \
                    + str(invalid_switch_port_list)

                if curr_action != 'install':
                    err_msg = "WARNING:" + str(err_msg)

        if error_found:
            if curr_action == 'install':
                self.set_validation_results(section_name, STATUS_FAIL, err=err_msg)
            else:
                self.set_validation_results(section_name, STATUS_PASS, err=err_msg)

            return

        self.set_validation_results(section_name)
        return

    def check_nfvbench_card_for_vxlan(self):
        '''Check NFVBench Card for VXLAN is X710 based'''

        section_name = "Management Node check for NFVBench with VXLAN"
        if not self.cfgmgr.check_nfvbench_presence():
            return

        if not self.cfgmgr.is_vxlan_enabled():
            return

        chk_nfvbench_for_vxlan = \
            common.is_bom_valid_for_nfvbench(check_vxlan_support=1)

        if re.search(r'ERROR', chk_nfvbench_for_vxlan):
            self.set_validation_results(section_name, status=STATUS_PASS, \
                err="WARNING: Management node has X520 card which is not "
                    "compatible for NFVBench with VXLAN")

        else:
            self.set_validation_results(section_name, status=STATUS_PASS)

        return

    def check_port_vlan_count(self):
        '''Check PV count in aci fabric'''

        auto_tor_via_aci = self.cfgmgr.extend_auto_tor_to_aci_fabric()
        if not auto_tor_via_aci:
            return

        is_cpdp_one = self.cfgmgr.is_cp_dp_collapsed()

        num_tenant_vlan = 0
        tenant_vlan_info = self.ymlhelper.check_section_exists(
            'TENANT_VLAN_RANGES')

        podtype = self.ymlhelper.get_pod_type()

        if tenant_vlan_info is not None:
            tenant_vlan_list = common.expand_vlan_range(tenant_vlan_info)
            num_tenant_vlan = len(tenant_vlan_list)

        prov_vlan_info = self.ymlhelper.check_section_exists(
            'PROVIDER_VLAN_RANGES')

        num_prov_vlan = 0
        if prov_vlan_info is not None:
            prov_vlan_list = common.expand_vlan_range(prov_vlan_info)
            num_prov_vlan = len(prov_vlan_list)

        server_info_list = self.ymlhelper.get_data_from_userinput_file(['SERVERS'])

        section_name = "Check Port:VLAN Count in Pod"
        role_profiles = self.ymlhelper.rp_get_all_roles()

        total_pv_count_per_switch = {}
        total_pv_count_on_control = {}
        total_pv_count_on_compute = {}
        total_pv_count_on_ceph = {}
        total_pv_count = 0

        torswitchinfo = \
            self.ymlhelper.get_data_from_userinput_file(['TORSWITCHINFO'])

        switch_list = []
        if torswitchinfo is not None:
            switchdetails = torswitchinfo.get('SWITCHDETAILS', None)
            if switchdetails is not None:
                for item in switchdetails:
                    curr_hostname = item.get('hostname')
                    if curr_hostname is not None and \
                            curr_hostname not in switch_list:
                        switch_list.append(curr_hostname)

        for switch in switch_list:
            total_pv_count_on_control[switch] = 0
            total_pv_count_on_compute[switch] = 0
            total_pv_count_on_ceph[switch] = 0
            total_pv_count_per_switch[switch] = 0

        if podtype == 'ceph':
            contoller_svr_list = self.ymlhelper.get_server_list(role='cephcontrol')
            ceph_svr_list = self.ymlhelper.get_server_list(role='cephosd')

        else:
            contoller_svr_list = self.ymlhelper.get_server_list(role='control')
            compute_svr_list = self.ymlhelper.get_server_list(role='compute')
            ceph_svr_list = self.ymlhelper.get_server_list(role='block_storage')

        nfvbench_tor_list = []
        is_nfvbench_present = self.cfgmgr.check_nfvbench_presence()
        if is_nfvbench_present:
            key = ["NFVBENCH", "tor_info"]
            nfvbench_tor_mappings = self.ymlhelper.get_data_from_userinput_file(key)

            for key in nfvbench_tor_mappings.keys():
                if key not in nfvbench_tor_list:
                    nfvbench_tor_list.append(key)

        tor_port_map = {}
        dp_port_map = {}
        sriov_port_map = {}

        for role in role_profiles:

            svr_list = self.ymlhelper.get_server_list(role=role)
            if svr_list is None:
                continue
            elif not svr_list:
                continue
            else:
                if role == 'control':
                    svr_list = copy.deepcopy(contoller_svr_list)

                elif role == 'compute':
                    svr_list = copy.deepcopy(compute_svr_list)

                elif role == 'block_storage':
                    svr_list = copy.deepcopy(ceph_svr_list)

                elif role == 'cephosd':
                    svr_list = copy.deepcopy(ceph_svr_list)

                for server in svr_list:

                    curr_server_info = server_info_list.get(server)

                    access_vlan_info = curr_server_info.get('sriov_access_vlan')
                    if access_vlan_info is not None:
                        num_prov_vlan = 1

                    tor_info = curr_server_info.get('tor_info')
                    if tor_info is not None:
                        tor_port_map = common.fetch_switch_port_num(tor_info)

                    dp_tor_info = curr_server_info.get('dp_tor_info')
                    if dp_tor_info is not None:
                        dp_port_map = common.fetch_switch_port_num(dp_tor_info)

                    sriov_tor_info = curr_server_info.get('sriov_tor_info')
                    if sriov_tor_info is not None:
                        sriov_port_map = common.fetch_switch_port_num(sriov_tor_info)

                    if role == 'control':
                        if is_cpdp_one:
                            for key, value in tor_port_map.iteritems():
                                total_pv_count_on_control[key] +=  \
                                    int(value) * (4 + num_prov_vlan +
                                                  num_tenant_vlan)

                        else:
                            for key, value in tor_port_map.iteritems():
                                total_pv_count_on_control[key] += (int(value) * 4)

                            for key, value in dp_port_map.iteritems():
                                total_pv_count_on_control[key] += \
                                    (int(value) * (num_prov_vlan + num_tenant_vlan))

                    if role == 'compute':
                        if re.match(r'micro|edge', podtype) \
                                and server in contoller_svr_list:
                            pass
                        else:
                            if is_cpdp_one:
                                for key, value in tor_port_map.iteritems():
                                    total_pv_count_on_compute[key] +=  \
                                        int(value) * (2 + num_prov_vlan + \
                                                      num_tenant_vlan)

                            else:
                                for key, value in tor_port_map.iteritems():
                                    total_pv_count_on_compute[key] +=  \
                                        int(value) * (2)

                                for key, value in dp_port_map.iteritems():
                                    total_pv_count_on_compute[key] +=  \
                                        int(value) * (num_prov_vlan +
                                                      num_tenant_vlan)

                        for key, value in sriov_port_map.iteritems():
                            total_pv_count_on_compute[key] += \
                                (int(value)) * (num_prov_vlan)

                    if role == 'cephosd':
                        for key, value in tor_port_map.iteritems():
                            total_pv_count_on_compute[key] += \
                                int(value) * (2)

                    elif role == 'block_storage' and \
                            not re.match(r'micro|UMHC|NGENAHC', podtype):
                        for key, value in tor_port_map.iteritems():
                            total_pv_count_on_ceph[key] += \
                                int(value) * (2)

        for key, value in total_pv_count_on_control.iteritems():
            total_pv_count_per_switch[key] += value
            total_pv_count += value

        for key, value in total_pv_count_on_compute.iteritems():
            total_pv_count_per_switch[key] += value
            total_pv_count += value

        for key, value in total_pv_count_on_ceph.iteritems():
            total_pv_count_per_switch[key] += value
            total_pv_count += value

        for key, value in total_pv_count_per_switch.iteritems():
            if key in nfvbench_tor_list:
                total_pv_count_per_switch[key] += int(num_tenant_vlan)
                total_pv_count += value

        podname = self.ymlhelper.check_section_exists('PODNAME')
        if podname is None:
            podname = "CurrentPod"

        self.pod_pv_count_per_switch = copy.deepcopy(total_pv_count_per_switch)
        det_str = "Total PV (port-vlan) count for %s: %s: " \
            "\nDetails: ControlPVCount: %s ComputePVCount:%s CephPVCount:%s" \
            % (podname, total_pv_count, total_pv_count_on_control, \
               total_pv_count_on_compute, total_pv_count_on_ceph)
        self.log.info(det_str)

        info_str = "Total PV (port-vlan) count for %s is %s and that " \
            "at switch level %s" \
            % (podname, total_pv_count, total_pv_count_per_switch)
        self.log.info(info_str)
        self.set_validation_results(section_name, status=STATUS_PASS,
                                    err=info_str)

        return

    def _repo_mirror_rpm_download_check(self, cobbler_ip, repo_dir, rpm_dict):
        '''Check if RPM is downloaded'''

        err_msg = None
        failed_list = []
        for filename, (sha1sum, _) in rpm_dict.iteritems():
            url = "http://%s/repo/%s/%s" % (cobbler_ip, repo_dir, filename)
            try:
                sha1 = hashlib.sha1()
                response = requests.get(url, stream=True)
                if response.status_code != 200:
                    failed_list.append(filename)
                    continue
                for chunk in response.iter_content(chunk_size=4096):
                    if chunk:
                        sha1.update(chunk)
                if sha1.hexdigest() != sha1sum:
                    failed_list.append(filename)
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.ConnectTimeout) as e:
                err_msg = "Cobbler Web connection error: %s" % e
                break
        return (err_msg, failed_list)

    def _copy_rpm_to_repo_mirror(self, src_rpm_dir, repo_dir, rpm_dict,
                                 copy_rpm_list):
        '''Copies rmp to repo mirror'''
        try:
            output = subprocess.check_output(["/usr/bin/systemctl", "cat",
                                              "docker-cobbler-web"])
            #ExecStart=/usr/bin/docker start -a repo_mirror_11413
            match = re.search(r"ExecStart=.*docker start.* (\w+)$", output,
                              re.MULTILINE)
            repo_mirror = match.group(1)
        except (subprocess.CalledProcessError, AttributeError):
            return "Failed to find active 'repo_mirror' container"

        hash_sha1_dict = {}
        for filename in os.listdir(src_rpm_dir):
            if ".rpm" in filename:
                sha1 = hashlib.sha1()
                src_rpm_file = os.path.join(src_rpm_dir, filename)
                with open(src_rpm_file, "rb") as rf:
                    for chunk in iter(lambda: rf.read(4096), b""):
                        sha1.update(chunk)
                hash_sha1_dict[sha1.hexdigest()] = src_rpm_file

        if hash_sha1_dict:
            for copy_rpm in copy_rpm_list:
                src_rpm_file = hash_sha1_dict[rpm_dict[copy_rpm][0]]
                dst_location = "%s:/var/www/html/repo/%s/%s" % (
                    repo_mirror, repo_dir, copy_rpm)
                try:
                    subprocess.check_output(["/usr/bin/docker", "cp", src_rpm_file,
                                             dst_location])
                except subprocess.CalledProcessError:
                    return "Copy '%s' to repo_mirror failed" % copy_rpm

    def verify_thirdparty_hw_binary_utilities_rpms(self):
        '''verify the existence of hirdparty_hw_binary_utilities_rpms'''

        # static values correspond to values used in defaults.yaml
        repo_name = "thirdparty-hw-binary-utilities"
        rpm_list_tag = "thirdparty_hw_binary_utilities"
        cobbler_ip = self.cfgmgr.get_build_node_ip("management")
        # get repo full name
        repo_dir = None
        if self.cfgmgr.parsed_defaults.parsed_config.get("REDHAT_REPOS"):
            for repo in self.cfgmgr.parsed_defaults.parsed_config[
                    "REDHAT_REPOS"].get("repos", []):
                if repo_name in repo:
                    repo_dir = str(repo) + "--x86_64"
                    break
        # get expected rpm file's info
        rpm_dict = {}
        if self.cfgmgr.parsed_defaults.parsed_config.get(rpm_list_tag):
            for rpm in self.cfgmgr.parsed_defaults.parsed_config[rpm_list_tag]:
                rpm_dict[rpm["filename"]] = (rpm["sha1sum"], rpm["url"])

        err_msg = None
        failed_list = []
        if cobbler_ip and repo_dir and rpm_dict:
            err_msg, failed_list = self._repo_mirror_rpm_download_check(
                cobbler_ip, repo_dir, rpm_dict)
        if not err_msg and failed_list:
            err_msg = self._copy_rpm_to_repo_mirror(self.cfg_dir, repo_dir,
                                                    rpm_dict, failed_list)
            # recheck repo again after successful copy
            if not err_msg:
                err_msg, failed_list = self._repo_mirror_rpm_download_check(
                    cobbler_ip, repo_dir, rpm_dict)
        if not err_msg and failed_list:
            err_msg = ("RPM not found, please download following and copy it "
                       "to '%s' directory:" % self.cfg_dir)
            for failed in failed_list:
                err_msg += "\n%s" % rpm_dict[failed][1]
        self.set_validation_results(
            "Verify thirdparty hardware binary utilities exist in Cobbler "
            "Web Repo", status=STATUS_FAIL if err_msg else STATUS_PASS, err=err_msg)

    def is_argus_ip_in_use(self):
        """Validate that the cvim_mon target ips are pingable and ports are up"""

        argus_info = \
            self.ymlhelper.get_data_from_userinput_file(['ARGUS_BAREMETAL'])
        cluster_info = argus_info.get('SITE_CONFIG').get('clusters')

        v6 = argus_info.get('DHCP_MODE')
        argus_ip_list = []

        err_code_list = []
        err_code_list.append(self.validation_error_code['ip_address'])
        cvim_mon_target_fail_list = []
        threadlist = []
        error_found = 0

        for cluster in cluster_info:
            servers = cluster.get('servers')
            for server in servers:
                if v6 and v6 == 'v6':
                    argus_ip_list.append(server.get('ip_address').get(\
                        'management_1_v6').split('/')[0])
                    argus_ip_list.append(server.get('ip_address').get(\
                        'api_1_v6').split('/')[0])
                else:
                    argus_ip_list.append(server.get('ip_address').get(\
                        'management_1_v4').split('/')[0])
                    argus_ip_list.append(server.get('ip_address').get(\
                        'api_1_v4').split('/')[0])

        for ip in argus_ip_list:
            kwargs = {}
            newthread = ExecThread(ip, \
                                   self.is_ip_reachable, **kwargs)
            newthread.start()
            threadlist.append(newthread)

        for mythread in threadlist:
            mythread.join()
            if mythread.oper_status == 2:
                cvim_mon_target_fail_list.append(mythread.host_ip)

        chk_config = "Check Argus network ips in use"
        if cvim_mon_target_fail_list:
            error_found = 1
            err_segment = "CVIM MGMT node ping check failed for :" + \
                str(cvim_mon_target_fail_list)
            self.set_validation_results(chk_config, status=STATUS_FAIL,
                                        err=err_segment,
                                        error_code_list=err_code_list)

        if not error_found:
            self.set_validation_results(chk_config)

        return

    def is_ip_reachable(self, ip_addr):
        """Validate if ipv4v6 is pingable"""

        ip_check = False

        if re.search('[:]+', ip_addr):
            v6 = 1
        else:
            v6 = 0

        try:
            if v6:
                ping = subprocess.Popen(['/usr/bin/ping6', '-c5', ip_addr], \
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                ping = subprocess.Popen(['/usr/bin/ping', '-c5', '-W2', ip_addr], \
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out = ping.communicate()[0]

            if not out:
                ip_check = True

            for item in out.splitlines():
                if re.search(r'100% packet loss|Network is unreachable', item):
                    ip_check = True

        except subprocess.CalledProcessError:
            ip_check = True

        if not ip_check:
            return 1

        return 2

    def report_duplicates(self, check_list):
        '''Return list of duplicate values found'''
        c = Counter(check_list)
        duplicate_list = []
        for key, item in c.iteritems():
            if item > 1:
                duplicate_list.append(key)
        return duplicate_list

    def get_data_from_cvimmonha_setup(self, key, search_dict):
        """
        Generic method to get data from userinput file
        """
        try:
            data = search_dict[key]
        except (KeyError, TypeError) as e:
            chk_config = "Get data from cvimmonha setup file"
            err_segment = "Unable to find key : {} in setup file".format(key)
            self.set_validation_results(chk_config, status=STATUS_FAIL, \
                err=err_segment)
            return []
        return data

    def check_dhcp_ipv6(self):
        '''Check if ipv6 is configured if user selects dhcp option as ipv6'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['DHCP_MODE'])

        argus_info = \
            self.get_data_from_cvimmonha_setup("ARGUS_BAREMETAL", self.cvimmonha_setup)

        if argus_info:
            dhcp_mode = argus_info.get('DHCP_MODE', None)

            if dhcp_mode == "v6":
                networks_dir = '/etc/sysconfig/network-scripts/'
                network_path = networks_dir + 'ifcfg-br_api'

                with open(network_path) as f:
                    network_details = f.read()

                if not re.search(r'IPV6ADDR', network_details):
                    chk_config = "Check Provided IPv6 interface"
                    err_segment = "No IPv6 address found in interface: 'br_api'"
                    self.set_validation_results(chk_config, status=STATUS_FAIL, \
                        err=err_segment, error_code_list=err_code_list)
                    return

        return

    def check_ipv6_network_input(self, mgmt_ip_gateway, mgmt_ip_subnet):
        '''check if ipv6 ips are in the correct subnets'''

        test = \
            ipaddr.IPv6Address(mgmt_ip_gateway) in ipaddr.IPv6Network(mgmt_ip_subnet)
        return test

    def check_cvim_mon_ha_info(self):
        """Checks for Info with Quanta"""
        err_code_list = []

        chk_config = "CVIM MON HA Check"
        err_code_list.append(self.validation_error_code['SITE_CONFIG'])

        site_config_details = ['ARGUS_BAREMETAL', 'SITE_CONFIG']
        site_info = \
            self.ymlhelper.get_deepdata_from_userinput_file(site_config_details)

        err_list = []
        err_found = 0
        cluster_info = site_info.get('clusters', None)
        curr_quanta_platform = False
        for item in cluster_info:

            curr_server_name = item.get('name')
            curr_server_info = item.get('servers')

            for curr_item in curr_server_info:
                curr_oob_ip = curr_item.get('oob_ip', None)
                ip_address = curr_item.get('ip_address', None)
                api_1_vlan_id = ip_address.get('api_1_vlan_id', None)

                if config_parser.PlatformDiscovery(\
                        self.setup_file).is_quanta(curr_oob_ip):
                    curr_quanta_platform = True

                if curr_quanta_platform and api_1_vlan_id is None:
                    err_found = 1
                    err_str = "api_1_vlan_id is not defined for Qunata server: %s" \
                        % (curr_server_name)
                    err_list.append(err_str)

        if err_found:
            err_info = ','.join(err_list)
            self.set_validation_results(chk_config, status=STATUS_FAIL, \
                err=err_info, error_code_list=err_code_list)
        else:
            self.set_validation_results(chk_config)

        return

    def check_cvim_mon_ha_target_names(self):
        '''Check if stack names of cvim-mon-ha targets are unique'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['cvim-mon-stacks'])
        error = 0

        target_names = []

        cvim_mon_stacks = \
            self.get_data_from_cvimmonha_setup('cvim-mon-stacks', self.cvimmonha_setup)

        for stack in cvim_mon_stacks:
            target_names.append(stack.get('name'))

        if len(target_names) != len(set(target_names)):
            duplicate_target_names = self.report_duplicates(target_names)

            chk_config = "Check Duplicate cvim-mon target names provided"
            error = 1
            err_segment = "Duplicate cvim-mon stack target names found: " + \
                str(duplicate_target_names)
            self.set_validation_results(chk_config, status=STATUS_FAIL, \
                err=err_segment, error_code_list=err_code_list)
            return

        chk_config = "Check Cvim-Mon Target Nomenclature"

        if not error:
            self.set_validation_results(chk_config)

        return

    def check_cvim_mon_stack_info(self):
        '''Check to see if all pods in a cvim-mon stack have unique ips'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['cvim-mon-stacks'])
        error = 0

        cvim_mon_stacks = self.get_data_from_cvimmonha_setup('cvim-mon-stacks', self.cvimmonha_setup)
        for stack in cvim_mon_stacks:
            stack_ip_list = []
            stack_region_names = []
            stack_metro_names = []
            stack_pod_names = []
            for region in stack.get('regions', []):
                stack_region_names.append(region.get('name'))
                for metro in region.get('metros', []):
                    stack_metro_names.append(metro.get('name'))
                    for pod in metro.get('pods', []):
                        stack_ip_list.append(pod.get('ip'))
                        stack_pod_names.append(pod.get('name'))

            self.check_duplicates(stack_region_names, "region names", stack)
            self.check_duplicates(stack_metro_names, "metro names", stack)
            # self.check_duplicates(stack_ip_list, "IPs", stack)
            self.check_duplicates(stack_pod_names, "pod names", stack)

        chk_config = "Check duplicate Cvim-Mon target Information"
        if not error:
            self.set_validation_results(chk_config)

        return

    def check_duplicates(self, duplicate_check_list, name, stack):
        '''Report any errors with duplicate information found in cvim-mon stacks'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['cvim-mon-stacks'])

        duplicates_list = \
            self.report_duplicates(duplicate_check_list)

        if duplicates_list:
            chk_config = "Check Duplicate " + name + " per cvim-mon stack"
            err_segment = "Duplicate " + name + " in cvim-mon stack found: " + \
                str(duplicates_list) + " for stack " + \
                str(stack.get('name'))
            self.set_validation_results(chk_config, status=STATUS_FAIL, \
                err=err_segment, error_code_list=err_code_list)
        return

    def is_cvim_mon_target_reachable(self):
        '''Check if cvim-mon targets can all be authenticated'''

        err_code_list = []
        err_code_list.append(self.validation_error_code['cvim-mon-stacks'])
        error = 0
        threadlist = []

        cvim_mon_stacks = \
            self.get_data_from_cvimmonha_setup('cvim-mon-stacks', self.cvimmonha_setup)
        args_map = []
        pool = ThreadPool(processes=THREAD_POOL_SIZE)
        for stack in cvim_mon_stacks:
            for region in stack.get('regions', []):
                for metro in region.get('metros', []):
                    for pod in metro.get('pods', []):
                        if pod.get('username', None) is None:
                            # http target (non-cvim pod), need not validate
                            continue
                        target_external_vip = pod.get('ip')
                        kwargs = {}
                        kwargs['curr_uname'] = pod.get('username')
                        kwargs['curr_pwd'] = pod.get('cvim_mon_proxy_password')
                        kwargs['cert'] = pod.get('cert')
                        target_key = target_external_vip + "/" + \
                            pod.get('name', '')
                        args_map.append((target_key, deepcopy(kwargs)))

        if args_map:
            pool.map(partial(self.worker_wrapper,
                             self.check_cvim_mon_target_authentication),
                     args_map)
            pool.close()
            pool.join()

        chk_config = "Check CVIM target authentication"
        if self.cvim_mon_target_connection_fail_list:
            error = 1
            err_segment = "WARNING: CVIM External VIP " \
                "url connection check failed for:" + \
                str(self.cvim_mon_target_connection_fail_list)
            self.set_validation_results(chk_config, status=STATUS_PASS,
                                        err=err_segment)

        if self.cvim_mon_target_fail_list:
            error = 1
            err_segment = "WARNING: CVIM External VIP " \
                "username and password authentication check failed for:" + \
                str(self.cvim_mon_target_fail_list)
            self.set_validation_results(chk_config, status=STATUS_PASS,
                                        err=err_segment)

        if self.cvim_mon_target_cert_fail_list:
            error = 1
            err_segment = "WARNING: CVIM External VIP " \
                "cert authentication check failed for:" + \
                str(self.cvim_mon_target_cert_fail_list)
            self.set_validation_results(chk_config, status=STATUS_PASS,
                                        err=err_segment)

        if not error:
            self.set_validation_results(chk_config)

        return

    def worker_wrapper(self, function, args):
        """
        Worker wrapper function to provide the required arguments
        to the multithreaded job
        """
        # FORMAT: external_vip_details = target_external_vip +"/"+ pod_name
        external_vip_details = ""
        try:
            external_vip_details, kwargs = args
            return function(external_vip_details, **kwargs)
        except Exception as e:
            self.log.error("Exception on %s with : %s", external_vip_details, e)

    def check_cvim_mon_target_authentication(self, external_vip_details, **kwargs):
        '''Check if we get a valid response from cvim target given
        credentials in setup data'''

        ip, target_name = external_vip_details.split("/")
        url = "https://" + ip + "/metrics"

        try:
            response = requests.get(url, auth=(kwargs['curr_uname'], \
                        kwargs['curr_pwd']), verify=kwargs['cert'], timeout=10)
            if response.status_code != 200:
                self.cvim_mon_target_fail_list.append(target_name + ": " + ip)
        except requests.exceptions.Timeout as e:
            err_msg = ip + str(e)
            self.log.error(err_msg)
            self.cvim_mon_target_connection_fail_list.append(target_name + ": " + ip)
        except requests.exceptions.SSLError as e:
            err_msg = ip + str(e)
            self.log.error(err_msg)
            self.cvim_mon_target_cert_fail_list.append(target_name + ": " + ip)

        return

    def check_argus_network_parameters(self):
        """Determine what argus network checks to run based on dhcp mode"""
        err_code_list = list()
        err_code_list.append(self.validation_error_code['ip_address'])

        argus_info = \
            self.get_data_from_cvimmonha_setup('ARGUS_BAREMETAL', self.cvimmonha_setup)

        if argus_info:
            dhcp_mode = argus_info.get('DHCP_MODE', None)
            if dhcp_mode:
                v6 = True if re.search(r'v6', dhcp_mode) else False
            else:
                v6 = False

            if v6:
                self.check_argus_network_input("api", v6)
                self.check_argus_network_input("management", v6)

            self.check_argus_network_input("api")
            self.check_argus_network_input("management")

        return

    def check_argus_network_input(self, network, v6=False):
        """Check if content for argus network section is valid or not"""

        err_code_list = list()
        err_code_list.append(self.validation_error_code['ip_address'])

        argus_info = self.get_data_from_cvimmonha_setup('ARGUS_BAREMETAL', self.cvimmonha_setup)
        if argus_info:
            argus_site_info = self.get_data_from_cvimmonha_setup('SITE_CONFIG', argus_info)
            if argus_site_info:
                argus_clusters_info = self.get_data_from_cvimmonha_setup('clusters', argus_site_info)

        if not argus_clusters_info:
            return

        br_mgmt = common.get_ip_info('br_mgmt')
        if re.search(r'ERROR', br_mgmt):
            chk_config = "Check for valid pxe interface name"
            error = 1
            self.set_validation_results(
                chk_config,
                status=STATUS_FAIL,
                err="PXE Interface: 'br_mgmt' not found for ip address lists",
                error_code_list=err_code_list)
            return

        cluster_names = []
        server_names = []
        oob_ips = []
        error = 0
        br_network = network

        for servers in argus_clusters_info:
            gateway_check = []
            diff_subnet_check = []
            duplicate_ip_check = []

            cluster_names.append(servers['name'])

            for server in servers['servers']:

                oob_ips.append(server['oob_ip'])
                server_names.append(server['name'])

                if v6:
                    server_ip = server['ip_address'][br_network + '_1_v6']
                    server_gateway = \
                        server['ip_address'][br_network + '_1_gateway_v6']
                else:
                    server_ip = server['ip_address'][br_network + '_1_v4']
                    server_gateway = \
                        server['ip_address'][br_network + '_1_gateway_v4']

                server_ip_subnet = str(netaddr.IPNetwork(server_ip).cidr)

                if v6:
                    mgmt_ip = server['ip_address']['management_1_v6']
                    api_ip = server['ip_address']['api_1_v6']

                    mgmt_ip_subnet = str(netaddr.IPNetwork(mgmt_ip).cidr)
                    api_ip_subnet = str(netaddr.IPNetwork(api_ip).cidr)

                    if ipaddr.IPNetwork(mgmt_ip_subnet).overlaps(\
                            ipaddr.IPNetwork(api_ip_subnet)):
                        chk_config = "Check for mgmt and api subnet overlap"
                        error = 1
                        self.set_validation_results(
                            chk_config, status=STATUS_FAIL, err="Mgmt subnet " +
                            str(mgmt_ip_subnet) + " and api subnet " +
                            str(api_ip_subnet) + " should not overlap for " +
                            str(server['name']),
                            error_code_list=err_code_list)

                mgmt_ip = server['ip_address']['management_1_v4']
                api_ip = server['ip_address']['api_1_v4']

                mgmt_ip_subnet = str(netaddr.IPNetwork(mgmt_ip).cidr)
                api_ip_subnet = str(netaddr.IPNetwork(api_ip).cidr)

                if ipaddr.IPNetwork(mgmt_ip_subnet).overlaps(\
                        ipaddr.IPNetwork(api_ip_subnet)):
                    chk_config = "Check for mgmt and api subnet overlap"
                    error = 1
                    self.set_validation_results(
                        chk_config, status=STATUS_FAIL, err="Mgmt subnet " +
                        str(mgmt_ip_subnet) + " and api subnet " +
                        str(api_ip_subnet) + " should not overlap for " +
                        str(server['name']),
                        error_code_list=err_code_list)

                # CHECK TO SEE IF MANAGEMENT GATEWAY IS PART OF MANAGEMENT
                # IP SUBNET
                v4_check = not v6 and \
                    (True if self.validate_ip_for_a_given_network(\
                        server_gateway, server_ip_subnet) == 1 else False)
                v6_check = v6 and self.check_ipv6_network_input(
                    server_gateway, server_ip_subnet)
                if not v4_check and not v6_check:

                    chk_config = "Check for " + \
                        br_network + " gateway in " + br_network + " subnet"
                    error = 1
                    self.set_validation_results(
                        chk_config, status=STATUS_FAIL, err="Incorrect Gateway IP " +
                        str(server_gateway) + " for subnet " +
                        str(server_ip_subnet) + " in server " +
                        str(server['name']),
                        error_code_list=err_code_list)

                # CHECK IF MGMT GATEWAY IP FOR SERVER IS THE SAME AS MGMT IP
                if server_gateway == server_ip.split('/')[0]:
                    chk_config = "Check for " + br_network + \
                        " gateway to not match " + br_network + " ip"
                    error = 1
                    self.set_validation_results(
                        chk_config, status=STATUS_FAIL, err="Gateway IP " +
                        str(server_gateway) + " can't be same as " +
                        br_network + " ip " +
                        str(server_ip) + " in server " +
                        str(server['name']),
                        error_code_list=err_code_list)

                gateway_check.append(server_gateway)
                diff_subnet_check.append(server_ip_subnet)
                duplicate_ip_check.append(server_ip.split('/')[0])

            # CHECK TO SEE IF MGMT IPS FOR EACH CLUSTER BELONG TO SAME SUBNET
            if len(set(diff_subnet_check)) > 1:
                chk_config = "Check if cluster " + \
                    br_network + " ips are part of same cidr"
                error = 1
                err_segment = br_network + " ips are part of different " \
                                           "subnets: " + str(diff_subnet_check)
                self.set_validation_results(
                    chk_config, status=STATUS_FAIL, err=err_segment,
                    error_code_list=err_code_list)

            if br_network == 'api':
                if v6:
                    mgmt_node_ip = self.get_ipv6_addr('br_api')
                else:
                    mgmt_node_ip = self.get_mgmt_node_info('br_api')
                loadbalancer_ip = self.ymlhelper.get_data_from_userinput_file(
                    ['external_loadbalancer_ip'])
            else:
                if v6:
                    mgmt_node_ip = self.get_ipv6_addr('br_mgmt')
                else:
                    mgmt_node_ip = self.get_mgmt_node_info('br_mgmt')
                loadbalancer_ip = self.ymlhelper.get_data_from_userinput_file(
                    ['internal_loadbalancer_ip'])

            # Check if mgmt node private ip is in same subnet as argus servers
            if br_network == 'management' and not v6_check:
                if not self.validate_ip_for_a_given_network(
                        mgmt_node_ip, diff_subnet_check[0]):
                    chk_config = "Check if " + br_network + \
                        " node ip and argus server " + br_network + \
                        " ips are part of same subnet"
                    error = 1
                    err_segment = "Management node ip: " + \
                        str(mgmt_node_ip) + " is not part of subnet " + \
                        str(diff_subnet_check[0])
                    self.set_validation_results(
                        chk_config, status=STATUS_FAIL, err=err_segment,
                        error_code_list=err_code_list)

            elif br_network == 'management':
                if not self.check_ipv6_network_input(
                        mgmt_node_ip, diff_subnet_check[0]):
                    chk_config = "Check if " + br_network + \
                        " node ip and argus server " + br_network + \
                        " ips are part of same subnet"
                    error = 1
                    err_segment = "Management node ip: " + \
                        str(mgmt_node_ip) + " is not part of subnet " + \
                        str(diff_subnet_check[0])
                    self.set_validation_results(
                        chk_config, status=STATUS_FAIL, err=err_segment,
                        error_code_list=err_code_list)

            # Check if internal load balancer ip is in same subnet as argus
            # servers
            subnet_error = 0
            if v6:
                if not self.check_ipv6_network_input(
                        loadbalancer_ip, diff_subnet_check[0]):
                    subnet_error = 1
            else:
                if not common.is_valid_ipv6_address(loadbalancer_ip):
                    if not self.validate_ip_for_a_given_network(
                            loadbalancer_ip, diff_subnet_check[0]):
                        subnet_error = 1

            if subnet_error == 1:
                chk_config = "Check if loadbalancer ip and argus " \
                             "server " + br_network + " ips are part of same subnet"
                error = 1
                err_segment = "Loadbalancer ip: " + \
                    str(loadbalancer_ip) + " is not part of subnet " + \
                    str(diff_subnet_check[0])
                self.set_validation_results(
                    chk_config, status=STATUS_FAIL, err=err_segment,
                    error_code_list=err_code_list)

            duplicate_ip_check.append(mgmt_node_ip)
            duplicate_ip_check.append(loadbalancer_ip)

            # CHECK IF CLUSTER MGMT IPS ARE THE SAME
            if len(duplicate_ip_check) != len(set(duplicate_ip_check)):
                duplicate_ip_addr_list = \
                    self.report_duplicates(duplicate_ip_check)

                chk_config = "Check Duplicate MGMT IPs per server"
                error = 1
                err_segment = "Duplicate MGMT IPs found: " + \
                    str(duplicate_ip_addr_list)
                self.set_validation_results(
                    chk_config, status=STATUS_FAIL, err=err_segment,
                    error_code_list=err_code_list)

            # CHECK TO SEE IF ALL SERVERS IN A CLUSTER HAVE THE SAME MGMT
            # GATEWAY IP
            if len(set(gateway_check)) > 1:
                chk_config = "Check " + br_network + " Gateway IPs per cluster"
                error = 1
                err_segment = "Different " + br_network + " gateway ips found: " + \
                    str(gateway_check) + " for cluster " + \
                    str(servers['name'])
                self.set_validation_results(
                    chk_config, status=STATUS_FAIL, err=err_segment,
                    error_code_list=err_code_list)

            # CHECK TO SEE IF ALL SERVER NAMES IN A CLUSTER ARE UNIQUE
            if len(server_names) != len(set(server_names)):
                duplicate_server_name_list = self.report_duplicates(server_names)

                chk_config = "Check Duplicate server names provided"
                error = 1
                err_segment = "Duplicate server names found: " + \
                    str(duplicate_server_name_list)
                self.set_validation_results(
                    chk_config, status=STATUS_FAIL, err=err_segment,
                    error_code_list=err_code_list)
                return

        # CHECK TO SEE IF ALL OOB IPS ARE UNIQUE IPS
        if len(oob_ips) != len(set(oob_ips)):
            duplicate_oob_ip_list = self.report_duplicates(oob_ips)

            chk_config = "Check Duplicate oob ips provided"
            error = 1
            err_segment = "Duplicate oob ips found: " + \
                str(duplicate_oob_ip_list)
            self.set_validation_results(
                chk_config, status=STATUS_FAIL, err=err_segment,
                error_code_list=err_code_list)
            return

        chk_config = "Check Argus " + br_network + " network information"

        if not error:
            self.set_validation_results(chk_config)

        return


def is_cloud_deploy_set(setup_file):
    '''Checks if Cloud deploy is true in setup_data'''

    found_cloud_deploy_flag = 0
    if setup_file is None:
        homedir = os.path.expanduser("~")
        cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)
        setup_file = os.path.join(cfg_dir, DEFAULT_SETUP_FILE)

    with open(setup_file) as f:
        data = f.readlines()

        for line in data:
            if re.search(r'CLOUD_DEPLOY: True', line, re.IGNORECASE):
                found_cloud_deploy_flag = 1
                break

    mgmt_node_type = common.fetch_mgmt_node_type()
    if mgmt_node_type == "vm":
        found_cloud_deploy_flag = 1

    return found_cloud_deploy_flag


def check_absence_in_backup(feature_name):
    '''Check if option is being brought as reconfiure'''

    homedir = os.path.expanduser("~")
    cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)
    backup_setup_file = os.path.join(cfg_dir, BACKUP_SETUP_FILE)

    found_error = 0
    if not os.path.isfile(backup_setup_file):
        return 1

    with open(backup_setup_file, 'r') as f:
        try:
            doc_backup = yaml.safe_load(f)
        except yaml.parser.ParserError:
            found_error = 1
        except yaml.scanner.ScannerError:
            found_error = 1

    if found_error:
        return 1

    if doc_backup.get(feature_name) is None:
        return 1

    return 0


def br_mgmt_check_todo_or_notto(setup_file):
    """Check to see if br_mgmt_check needs to be skipped"""

    do_br_mgmt_check = 1
    if setup_file is None:
        homedir = os.path.expanduser("~")
        cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)
        setup_file = os.path.join(cfg_dir, DEFAULT_SETUP_FILE)

    validator = Validator(setup_file)
    torswitch_check = \
        validator.ymlhelper.get_setup_data_property('TORSWITCHINFO')
    if torswitch_check is not None:
        configure_tor = ['TORSWITCHINFO', 'CONFIGURE_TORS']
        configure_tor_flag = \
            validator.ymlhelper.get_deepdata_from_userinput_file(configure_tor)
        if configure_tor_flag is not None and configure_tor_flag:
            return 0

    mech_driver = \
        validator.ymlhelper.get_setup_data_property('MECHANISM_DRIVERS')
    if mech_driver == 'aci':
        return 0

    apic_info = \
        validator.ymlhelper.get_setup_data_property('APICINFO')
    if apic_info is not None:
        configure_fabric = ['APICINFO', 'configure_fabric']
        cfg_fabric_chk = \
            validator.ymlhelper.get_deepdata_from_userinput_file(configure_fabric)
        if cfg_fabric_chk is not None and cfg_fabric_chk:
            return 0
    return do_br_mgmt_check


def run(run_args={}):
    '''
    Run method. Invoked from common runner.
    '''

    curr_setupfileloc = None
    try:
        if not re.match(r'NotDefined', run_args['SetupFileLocation']):
            err_str = ""
            input_file_chk = {}
            input_file_chk = {}
            curr_setupfileloc = run_args['SetupFileLocation']
            if not os.path.isfile(curr_setupfileloc):
                err_str = "Input file: " + curr_setupfileloc + " does not exist"

            elif not os.access(curr_setupfileloc, os.R_OK):
                err_str = "Input file: " + curr_setupfileloc + " is not readable"

            if err_str:
                print err_str
                input_file_chk['status'] = STATUS_FAIL
                return input_file_chk

    except KeyError:
        curr_setupfileloc = None

    except TypeError:
        curr_setupfileloc = None

    if 'testType' in run_args.keys():
        test_type = run_args['testType']
    else:
        test_type = 'all'

    if run_args.get('viaCLI') is None:
        run_args['viaCLI'] = False
    viaCLI = run_args['viaCLI']

    cvimmonha_setup = run_args.get('cvimmonha_setup', None)
    bkp_cvimmonha_setup = run_args.get('backup_cvimmonha_setup', None)

    validator = Validator(curr_setupfileloc,
                          test_type, viaCLI, cvimmonha_setup,
                          bkp_cvimmonha_setup)
    optional_services = \
        validator.ymlhelper.get_setup_data_property('OPTIONAL_SERVICE_LIST')

    bn_status = {}
    podtype = validator.ymlhelper.get_pod_type()

    cloud_deploy_flag = is_cloud_deploy_set(validator.setup_file)

    br_mgmt_check = br_mgmt_check_todo_or_notto(curr_setupfileloc)

    if re.search(r'all|static', run_args['checkType']):
        # TODO: Temporary allow backward compatible for management node with
        #       FlexFlash setup.  This section and the flexflash module should
        #       be remove when all the setup have migrate to hard disk only.
        flexflash = False
        try:
            for disk in os.listdir('/dev/disk/by-id/'):
                if re.search('usb-(CiscoVD|HV)_Hypervisor.*-part[12]{1}$', disk):
                    flexflash = True
                    break
        except OSError:
            flexflash = True

        flexflash = False
        bn_validator = None

        supressOutputFlag = 0
        skip_version_check = 0

        if 'supressOutput' in run_args.keys() and run_args['supressOutput']:
            supressOutputFlag = 1

        if 'InstallType' in run_args.keys() and \
                run_args['InstallType'] == 'upgrade':
            skip_version_check = 1
        elif 'action' in run_args.keys() and \
                run_args['action'] == 'upgrade':
            skip_version_check = 1

        if podtype == 'CVIMMONHA':
            skip_restapi_check = 1
        else:
            skip_restapi_check = 0

        if test_type == 'nonblocking' or test_type == 'blocking':
            pass
        else:
            bn_validator = bn_validations.BNValidator(flexflash)
            bn_status = bn_validator.validate_buildnode(checkType="all", \
                supressOutput=supressOutputFlag, \
                skip_version_check=skip_version_check, \
                cloud_deploy=cloud_deploy_flag, \
                podtype=podtype, \
                skip_restapi_check=skip_restapi_check, \
                br_mgmt_check=br_mgmt_check)

    time.sleep(1)
    schema_check_status = True
    valid_key_check = True
    valid_operation_check = True

    cimc_info_dict = {}
    try:
        _ = run_args['checkType']
        testbed_type = validator.get_testbed_type()

        if 'add_osds' in run_args.keys():
            curr_action = "add_osds"
        elif 'remove_osd' in run_args.keys():
            curr_action = "remove_osd"
        elif 'add_computes' in run_args.keys():
            curr_action = "add_computes"
        elif 'remove_computes' in run_args.keys():
            curr_action = "remove_computes"
        elif 'replace_controller' in run_args.keys():
            curr_action = "replace_controller"
        elif 'expand_osd' in run_args.keys():
            curr_action = "expand_osd"
        elif 'add_vms' in run_args.keys():
            curr_action = "add_vms"
        elif 'delete_vms' in run_args.keys():
            curr_action = "delete_vms"
        elif 'nodelist' in run_args.keys():
            curr_action = "nodelist"
        else:
            curr_action = "install"

        if 'action' in run_args.keys() and \
                run_args['action'] == 'reconfigure_cimc_password':
            curr_action = "reconfigure_cimc_password"
        elif 'action' in run_args.keys() and \
                re.match(r'reconfigure', run_args['action']) and \
                'add_leaf_switches' in run_args.keys():
            curr_action = "reconfigure"

        # in the case of reconfigure, we do static validation only;
        # skipping HW validation to save time and backing up setup_data
        if 'action' in run_args.keys() and \
                run_args['action'] == 'reconfigure' and \
                re.match('static_hw_validation', run_args['checkType']):
            run_args['checkType'] = 'static'

            if os.path.exists(SETUP_FILE_DIR):
                with open(SETUP_FILE_DIR, 'r') as setupfile:
                    setup_data = yaml.safe_load(setupfile.read())
                    if "cvim-mon-stacks" in setup_data:
                        for stack in setup_data["cvim-mon-stacks"]:
                            validator.check_user_custom_config_file(\
                                "alertmanager_custom_config.yml",
                                "alertmanager", "NONE", stack["name"])
                            validator.check_user_custom_config_file(\
                                "alerting_custom_rules.yml",
                                "prometheus", "NONE", stack["name"])

        elif 'action' in run_args.keys() and \
                run_args['action'] == 'reconfigure_cimc_password' and \
                re.match('static_hw_validation', run_args['checkType']):
            run_args['checkType'] = 'static'

        if re.search(\
                r'all|static|runtime|ccp_orchestration|ccp_deletion|ccp_upgrade', \
                run_args['checkType']):

            if run_args['checkType'] == 'ccp_orchestration':
                validator.set_oper_stage("Check Yaml Schema")
                schema_check_status = validator.check_yaml_schema(\
                    curr_action, ccp_check=1)
            else:
                validator.set_oper_stage("Check Yaml Schema")
                curr_vm_list = []
                if curr_action == 'add_vms':
                    curr_vm_list = run_args['add_vms']
                if curr_action == 'delete_vms':
                    curr_vm_list = run_args['delete_vms']

                schema_check_status = \
                    validator.check_yaml_schema(\
                        curr_action, curr_vm_list=curr_vm_list)

            validator.set_oper_stage("Check For Valid Keys")
            valid_key_check = validator.check_for_valid_keys()

            if 'add_computes' in run_args.keys():
                valid_operation_check = \
                    validator.check_allowed_operations(curr_action, \
                                                       run_args['add_computes'])
            elif 'remove_computes' in run_args.keys():
                valid_operation_check = \
                    validator.check_allowed_operations(curr_action, \
                                                       run_args['remove_computes'])
            else:
                valid_operation_check = \
                    validator.check_allowed_operations(curr_action)

            check_cimc_pwd_syntax = True
            if 'action' in run_args.keys() and \
                    run_args['action'] == 'reconfigure_cimc_password':
                if 'reconfig_info' in run_args.keys():
                    cimc_info_dict = run_args['reconfig_info']
                    if bool(cimc_info_dict):
                        validator.set_oper_stage("Reset CIMC Password")
                        check_cimc_pwd_syntax = \
                            validator.check_cimc_pwd_validity(cimc_info_dict)

        if re.search(r'all|static|ccp_orchestration|ccp_deletion|ccp_upgrade', \
                run_args['checkType']) and \
                schema_check_status and valid_key_check and \
                valid_operation_check and check_cimc_pwd_syntax:

            if cloud_deploy_flag:
                validator.set_oper_stage("Check ES SNAPSHOT Settings")
                validator.check_es_snapshot_settings_for_vm()

            if podtype == 'MGMT_CENTRAL':
                validator.set_oper_stage("Check For Duplicate Info List")
                validator.check_for_duplicate_info()

                validator.set_oper_stage("Check Hosted Cloud Pod Status")
                validator.check_hosted_cloud_pod_status()

                validator.set_oper_stage("Check Hosted Cloud RAM Status")
                validator.check_hosted_cloud_ram_status()

                validator.set_oper_stage("Check Valid Openrc and Project")
                validator.check_openrc_project_status()

                # this condition is only for Central Management Servers in VMs
                # add_computes and remove_computes refer to add/remove of VMs
                if curr_action == 'add_vms':

                    validator.set_oper_stage("Check Servers exist in Userinput File")
                    validator.check_valid_cm_action(\
                        curr_action, run_args['add_vms'])

                    validator.set_oper_stage("Config Setup Data Change Allowed")
                    validator.check_cm_config_change(\
                        curr_action, run_args['add_vms'])

                if curr_action == 'delete_vms':
                    validator.set_oper_stage("Check Servers exist in Userinput File")
                    validator.check_valid_cm_action(\
                        curr_action, run_args['delete_vms'])

                    validator.set_oper_stage("Config Setup Data Change Allowed")
                    validator.check_cm_config_change(\
                        curr_action, run_args['delete_vms'])

                if test_type == 'nonblocking':
                    pass
                else:
                    validator.set_oper_stage("Check DNS servers")
                    validator.check_mgmt_central_dns_servers_provided()

#                    validator.set_oper_stage("Run Cloud Sanity")
#                    validator.run_cloud_sanity()

            elif podtype == 'CVIMMONHA':

                if 'cvim_mon_action' in run_args.keys():
                    validator.set_oper_stage("config location check")
                    validator.check_cvim_mon_ha_config_change(\
                        run_args['cvim_mon_action'],
                        stack_name=run_args.get('stack-name'))

                    validator.set_oper_stage("Check For Duplicate Info List")
                    validator.check_for_duplicate_info()

                    validator.set_oper_stage("Check Cvim-Mon stack nomenclature")
                    validator.check_cvim_mon_ha_target_names()

                    validator.set_oper_stage("Check Cvim-Mon stack ips")
                    validator.check_cvim_mon_stack_info()

                elif 'cvim_mon_pod_oper' in run_args.keys():
                    validator.set_oper_stage("Check For Duplicate Info List")
                    validator.check_for_duplicate_info()
                    validator.set_oper_stage("Check Cvim-Mon stack nomenclature")
                    validator.check_cvim_mon_ha_target_names()

                    validator.set_oper_stage("Check Cvim-Mon stack ips")
                    validator.check_cvim_mon_stack_info()

                    validator.set_oper_stage("Check DHCP IPv6 validity")
                    validator.check_dhcp_ipv6()

                    validator.set_oper_stage("Check Argus network input info")
                    validator.check_argus_network_parameters()

                    validator.set_oper_stage("Check for cvim-mon-ha pod operations")
                    validator.check_cvim_mon_ha_config_change(\
                        pod_oper=run_args['cvim_mon_pod_oper'],
                        stack_name=run_args.get('stack-name'))

                else:
                    validator.set_oper_stage("config location check")
                    validator.check_user_config_location()

                    validator.set_oper_stage("Check For Duplicate Info List")
                    validator.check_for_duplicate_info()

                    validator.set_oper_stage("Check DHCP IPv6 validity")
                    validator.check_dhcp_ipv6()

                    validator.set_oper_stage("Check Argus network input info")
                    validator.check_argus_network_parameters()

                    validator.set_oper_stage("Check Cvim-Mon stack nomenclature")
                    validator.check_cvim_mon_ha_target_names()

                    validator.set_oper_stage("Check Cvim-Mon stack ips")
                    validator.check_cvim_mon_stack_info()

                    if test_type == 'nonblocking':
                        pass
                    else:
                        validator.set_oper_stage("Check NTP servers")
                        validator.check_ntp_servers_provided()

                if test_type == 'nonblocking':
                    pass
                else:

                    validator.set_oper_stage(\
                        "Check CVIM target authentication")
                    validator.is_cvim_mon_target_reachable()

                    validator.set_oper_stage("Check Argus cimc details")
                    validator.is_cimc_info_valid(argus=1)

                    validator.set_oper_stage("Check api_1_vlan_id Presence")
                    validator.check_cvim_mon_ha_info()
            else:

                validator.set_oper_stage("Check Controller Placement")
                validator.check_controller_placement()

                validator.set_oper_stage("Section with String Input Check")
                validator.check_section_input_info()

                validator.set_oper_stage("config location check")
                validator.check_user_config_location()

                validator.set_oper_stage("check server config")
                validator.check_server_list()

                validator.set_oper_stage("Check Nova Boot From Option")
                validator.check_nova_boot_from_option()

                validator.set_oper_stage("Check SSH_ACCESS and permit_root_login")
                validator.check_ssh_access_permit_root_login_comp()

                time.sleep(1)

                validator.set_oper_stage("Check Management Node IP")
                validator.check_bn_ip_validity()

                validator.set_oper_stage(\
                    "Check Servers Name Compatibility for IPA")
                validator.check_ipa_server_name_compatibility()

                validator.set_oper_stage("Check GPU RPM Presence")
                validator.check_gpu_rpm()

                if test_type == 'nonblocking':
                    pass
                else:

                    validator.set_oper_stage("Check User Cert Trust Chain")
                    validator.check_cert_trust_chain()

                    validator.set_oper_stage("Check User SSL Certs")
                    validator.check_user_tls_certificate()

                    validator.set_oper_stage("Check PV count in ACI Fabric")
                    validator.check_port_vlan_count()

                    # Ensure check_port_vlan_count is called before
                    # check_server_fabric_connectivity as a dependent global variable
                    # gets set in it
                    validator.set_oper_stage("Check Server/Fabric Connectivity")
                    validator.check_server_fabric_connectivity(curr_action)

                    validator.set_oper_stage(\
                        "Check Intf Policies are pre_provisioned")
                    validator.check_intf_policy_preprovisioning()

                    curr_section_name = "Check Link Aggregation Setting For TOR"
                    validator.set_oper_stage(curr_section_name)
                    validator.check_link_agg_for_tor(curr_section_name)

                    if 'action' in run_args.keys():
                        action = run_args['action']
                    else:
                        action = None

                    validator.set_oper_stage("Check Registry Connectivity")
                    if action is not None and \
                            (action == 'reconfigure_cimc_password' \
                             or action == 'reconfigure'):
                        pass
                    else:
                        validator.check_registry_connectivity(action)

                    validator.set_oper_stage("Check NTP servers")
                    validator.check_ntp_servers_provided()

                    validator.set_oper_stage("Check DNS servers")
                    validator.check_dns_servers_provided()

                    validator.set_oper_stage("Check Solidfire SVIP")
                    validator.check_solidfire_svip()

                    validator.set_oper_stage("Check VTC Details")
                    validator.check_vtc()

                    validator.set_oper_stage("Check SERVER_MON Validity")
                    validator.check_server_mon_validity()

                    validator.set_oper_stage("Check Zadara VPSA NS Validity")
                    validator.check_zadara_vpsa_nslookup_validity()

                    validator.set_oper_stage("Check Zadara VPSA Endpoint")
                    validator.check_zadara_vpsa_endpoint()

                    validator.set_oper_stage("Check Zadara VPSA PoolName")
                    validator.check_zadara_vpsa_poolname()

                    validator.set_oper_stage("Check Zadara Glance NFS Name")
                    validator.check_zadara_glance_nfs_name()

                    validator.set_oper_stage("Check IPA Servers Status")
                    validator.check_ipa_server_status()

                    validator.set_oper_stage("Check LDAP for VIM ADMIN")
                    validator.check_ldap_for_vim_admins()

                    validator.set_oper_stage("Check Layer3 deployment")
                    validator.check_local_management_network_gw_reachability()

                    section_name = "Check ToR Platform Software compatibility"
                    validator.set_oper_stage(section_name)
                    validator.pre_tor_config_validation(section_name, curr_action)

                    validator.set_oper_stage("Check Cloud Auth Status")
                    validator.check_cloud_auth_status(run_args.get('action'))

                    validator.set_oper_stage("Check the IP pool range")
                    validator.check_pool_range()

                    validator.set_oper_stage(\
                        "Check External Server Connectivity CVIMMON")
                    validator.check_ext_server_for_cvim_mon()

                    time.sleep(1)

                    if optional_services is not None \
                            and 'ironic' in optional_services:
                        if curr_action == 'install' and \
                                check_absence_in_backup('IRONIC'):
                            validator.set_oper_stage(\
                                "Validate ironic_inventory.yaml")
                            validator.check_ironic_inventory_yaml()

                validator.set_oper_stage("Check servers in ROLES and SERVERS match")
                validator.verify_servers_in_roles_and_servers(curr_action)

                validator.set_oper_stage("Check Network Input")
                validator.check_network_input()

                validator.set_oper_stage("Check For Duplicate Info List")
                validator.check_for_duplicate_info()

                validator.set_oper_stage("Check Insight Workspace")
                validator.check_insight_workspace()

                validator.set_oper_stage("Check for NVFBench Supported Card")
                validator.check_nfvbench_card_for_vxlan()

                if curr_action == 'reconfigure_cimc_password':
                    validator.check_config_change('reconfigure_cimc_password')

                elif 'action' in run_args.keys() and \
                        re.match(r'reconfigure', run_args['action']) and \
                        'add_leaf_switches' in run_args.keys():
                    curr_rma_tor_list = copy.deepcopy(run_args['add_leaf_switches'])
                    validator.check_config_change('reconfigure', \
                                                  rma_tor_list=curr_rma_tor_list)
                elif 'action' in run_args.keys() and \
                        re.match(r'reconfigure', run_args['action']):

                    if test_type == 'nonblocking':
                        skip_cloud_sanity = 1
                    else:
                        skip_cloud_sanity = 0

                    validator.check_config_change(\
                        'install', skip_cloud_sanity=skip_cloud_sanity)

                if 'add_computes' in run_args.keys():
                    validator.set_oper_stage("Config Setup Data Change Allowed")
                    schema_check_status = validator.check_config_change(curr_action)

                    validator.set_oper_stage("Check Servers exist in Userinput File")
                    validator.check_servers_exist(run_args['add_computes'],
                                                  role="compute")

                    validator.set_oper_stage("Check if server is already configured")
                    validator.check_server_preconfigured(run_args['add_computes'])

                    validator.set_oper_stage(\
                        "Check Servers Name Compatibility for IPA")
                    validator.check_ipa_server_name_compatibility(\
                        run_args['add_computes'])

                if 'add_osds' in run_args.keys():
                    validator.set_oper_stage("Config Setup Data Change Allowed")
                    schema_check_status = validator.check_config_change(curr_action)

                    validator.set_oper_stage("Check Servers exist in Userinput File")
                    if validator.ymlhelper.get_pod_type() == 'ceph':
                        validator.check_servers_exist(run_args['add_osds'],
                                                      role="cephosd")
                    else:
                        validator.check_servers_exist(run_args['add_osds'],
                                                      role="block_storage")

                    validator.set_oper_stage("Check if server is already configured")
                    validator.check_server_preconfigured(run_args['add_osds'])

                    validator.set_oper_stage(\
                        "Check Hostname Name Compatibility for IPA")
                    validator.check_ipa_server_name_compatibility(\
                        run_args['add_osds'])

                if 'remove_computes' in run_args.keys():
                    validator.set_oper_stage("Config Setup Data Change Allowed")
                    schema_check_status = validator.check_config_change(curr_action)
                    validator.set_oper_stage("Check Servers exist in Userinput File")
                    validator.check_valid_openstack_node(run_args['remove_computes'],
                                                         role="compute")

                if 'remove_osd' in run_args.keys():
                    validator.set_oper_stage("Config Setup Data Change Allowed")
                    schema_check_status = validator.check_config_change(curr_action)

                    validator.set_oper_stage("Check Servers exist in Userinput File")
                    try:
                        if validator.ymlhelper.get_pod_type() == 'ceph':
                            validator.check_valid_openstack_node(
                                run_args['remove_osd'].split(),
                                role="cephosd")
                        else:
                            validator.check_valid_openstack_node(
                                run_args['remove_osd'].split(),
                                role="block_storage")
                    except AttributeError:
                        if validator.ymlhelper.get_pod_type() == 'ceph':
                            validator.check_valid_openstack_node(
                                run_args['remove_osd'], role="cephosd")
                        else:
                            validator.check_valid_openstack_node(
                                run_args['remove_osd'], role="block_storage")

                if 'replace_controller' in run_args.keys():
                    validator.set_oper_stage("Config Setup Data Change Allowed")
                    schema_check_status = validator.check_config_change(\
                        curr_action, run_args['replace_controller'])

                    validator.set_oper_stage("Check Servers exist in Userinput File")
                    if validator.ymlhelper.get_pod_type() == 'ceph':
                        validator.check_servers_exist(\
                            run_args['replace_controller'], role="cephcontrol")
                    else:
                        validator.check_servers_exist(\
                            run_args['replace_controller'], role='control')

                    validator.set_oper_stage(\
                        "Check host provided is a valid controller")
                    validator.check_valid_controller_given( \
                        run_args['replace_controller'])

                if re.match(r'StandAlone', testbed_type):

                    if test_type == 'nonblocking':
                        pass
                    else:
                        if curr_action == 'reconfigure_cimc_password' \
                                and bool(cimc_info_dict):
                            validator.set_oper_stage("Check Validity of CIMC info")
                            validator.is_cimc_info_valid(\
                                cimc_info_dict=cimc_info_dict)
                        else:
                            validator.set_oper_stage("Check Validity of CIMC info")
                            validator.is_cimc_info_valid()

                        validator.set_oper_stage("Check APIC Connectivity Status")
                        validator.check_apic_hosts_connectivity()

                        validator.set_oper_stage("Check VMTP GATEWAY Connectivity")
                        validator.check_vmtp_gw_connectivity()

                    validator.set_oper_stage("Check For Duplicate CIMC IP")
                    validator.check_for_duplicate_cimc_ip()

                    if (validator.ymlhelper.get_pod_type() == 'edge' and
                            config_parser.PlatformDiscovery(
                                curr_setupfileloc).contain_quanta_platform()):
                        validator.set_oper_stage("Check for thirdparty BIOS \
                            configuration utilities")
                        validator.check_thirdparty_bios_configuration_utility()

                elif re.match(r'UCSM', testbed_type):
                    if test_type == 'nonblocking':
                        pass
                    else:
                        validator.set_oper_stage("Check UCSM Accessibility")
                        validator.is_ucsm_info_valid()

                    validator.set_oper_stage("Check Validity of Blade Info")
                    validator.is_blade_info_valid()

        # does run time check if Cobbler WebServer is up
        if re.search(r'all|runtime|ccp_orchestration|ccp_deletion|ccp_upgrade', \
                run_args['checkType']) and \
                schema_check_status and valid_operation_check:

            if test_type == 'nonblocking':
                skip_cloud_sanity = 1
            else:
                skip_cloud_sanity = 0

            if validator.vault_config is None \
                    or not validator.vault_config['enabled']:
                validator.set_oper_stage("Check Secrets Yaml Syntax")
                validator.check_reconfigure_options("secrets", curr_action)

            validator.set_oper_stage("Check Openstack Configs Yaml Syntax")
            validator.check_reconfigure_options(\
                "new_cfg", curr_action=curr_action,
                skip_cloud_check=skip_cloud_sanity)

            validator.set_oper_stage("Config Setup Data Change Allowed")
            if 'replace_controller' in run_args.keys():
                validator.check_config_change(curr_action,
                                              run_args['replace_controller'])
            elif 'action' in run_args.keys() and \
                    re.match(r'reconfigure', run_args['action']) and \
                    'add_leaf_switches' in run_args.keys():
                curr_rma_tor_list = copy.deepcopy(run_args['add_leaf_switches'])
                validator.check_config_change('reconfigure', \
                                              rma_tor_list=curr_rma_tor_list,
                                              skip_cloud_sanity=1)
            elif run_args['checkType'] == 'ccp_orchestration':
                validator.check_config_change(\
                    curr_action, ccp_check=1, skip_cloud_sanity=skip_cloud_sanity)
            elif run_args['checkType'] == 'ccp_deletion':
                validator.check_config_change(\
                    curr_action, ccp_check=1, delete_ccp=1,
                    skip_cloud_sanity=skip_cloud_sanity)
            elif run_args['checkType'] == 'ccp_upgrade':
                validator.check_config_change(\
                    curr_action, ccp_check=1, upgrade_ccp=1,
                    skip_cloud_sanity=skip_cloud_sanity)
            elif curr_setupfileloc is None:
                validator.check_config_change(curr_action, skip_cloud_sanity=1)

            validator.set_oper_stage("Dump Setup Data contents")
            validator.dump_setup_data_contents()

            if test_type == 'nonblocking':
                pass
            else:
                validator.set_oper_stage("Check Pod Layer3 deployment")
                validator.check_pod_management_network_gw_reachability()

                validator.set_oper_stage("Check Swiftstack Connectivity Status")
                validator.check_swiftstack_server_status()

                validator.set_oper_stage("Cobbler API Server Status")
                validator.check_api_server_status()

                validator.set_oper_stage("Verify tftp Server Status")
                validator.check_tftp_server_status()

                validator.set_oper_stage("Verify Kickstart Files exist in Cobbler")
                validator.verify_kickstart_files_and_host_profile()

                validator.set_oper_stage("Cobbler Web Server Status")
                validator.check_web_server_status(target_type="Cobbler",
                                                  port_no=80)

                if config_parser.PlatformDiscovery(
                        curr_setupfileloc).contain_ilo_platform():
                    validator.set_oper_stage("Verify thirdparty hardware binary \
                        utilities exist in Cobbler Web Repo")
                    validator.verify_thirdparty_hw_binary_utilities_rpms()

                validator.set_oper_stage("Elasticsearch Remote")
                validator.check_es_remote_snapshot_status()

                validator.set_oper_stage("Kibana Web Server Status")
                validator.check_web_server_status(target_type="Kibana", port_no=5601)

                validator.set_oper_stage("ElasticSearch Web Server Status")
                validator.check_web_server_status(target_type="ElasticSearch",
                                                  port_no=9200)

                validator.set_oper_stage("Fluentd Aggregator Status")
                validator.check_fluentd_aggr_status()

                snmp_cfg = validator.ymlhelper.get_data_from_userinput_file(["SNMP"])
                if snmp_cfg and snmp_cfg.get('enabled', True):
                    validator.set_oper_stage("SNMP Status")
                    validator.check_snmp_status()

                smon_cfg = \
                    validator.ymlhelper.get_data_from_userinput_file(["SERVER_MON"])
                if smon_cfg and smon_cfg.get('enabled', True):
                    validator.set_oper_stage("SERVER_MON Status")
                    validator.check_server_mon_status()

                validator.set_oper_stage("Docker Registry Container Status")
                validator.check_web_server_status(target_type="Docker",
                                                  port_no=5000)

                cvim_mon = \
                    validator.ymlhelper.get_data_from_userinput_file(["CVIM_MON"])
                if cvim_mon and cvim_mon.get('enabled', False) and \
                        not cvim_mon.get('central', False):
                    validator.set_oper_stage("Grafana Web Server Status")
                    validator.check_web_server_status(target_type="Grafana",
                                                      port_no=3000)

                    validator.set_oper_stage("Prometheus Web Server Status")
                    validator.check_web_server_status(target_type="Prometheus",
                                                      port_no=9090)

                    validator.set_oper_stage("Alertmanager Web Server Status")
                    validator.check_web_server_status(target_type="Alertmanager",
                                                      port_no=9093)

                    validator.set_oper_stage("Check LDAP for CVIMMON")
                    validator.check_ldap_for_cvim_mon()


            if curr_action == 'install':
                if test_type == 'nonblocking':
                    pass
                else:
                    section_name = "Verify ToR/NCS status"
                    validator.set_oper_stage(section_name)
                    #validator.post_tor_config_validation(section_name)

    except (KeyError, TypeError) as e:
        print "\n\n"
        print e
        print "\n\n"
        chk_config = "Input Validation Check"
        validator.set_oper_stage(chk_config)
        validator.report_invalid_input()

    if 'supressOutput' in run_args.keys() and run_args['supressOutput']:
        validator.set_oper_stage("Suppressing output")
    else:
        validator.display_validation_results(run_args['checkType'])
    time.sleep(1)

    sw_result = validator.check_validation_results()

    hw_status = {}

    # With reconfigure option in case of VIC/NIC combo with,
    # online validation for the nw_adapter checks if the there
    # is a change in the SRIOV nic card type detected
    if 'action' in run_args.keys() and run_args['action'] == 'reconfigure' \
            and validator.ymlhelper.eval_sriov_card_delta():
        run_args['checkType'] = 'all'

    if 'remove_computes' in run_args.keys():
        print "Skipping HW Validation for remove computes"
    elif 'remove_osd' in run_args.keys():
        print "Skipping HW Validation for remove OSD"

    elif podtype == 'MGMT_CENTRAL':
        print "Skipping HW Validation for " \
            "add computes during Central Management VMs"

    elif 'add_computes' in run_args.keys() and \
            re.search(r'UCSM|StandAlone', testbed_type) and \
            re.match(r'PASS', sw_result['status']) and \
            re.search(r'all|hw_validation', run_args['checkType']):
        validator.set_oper_stage("Starting HW Validation, takes time!!!")
        hw_validator = hw_validations.HWValidator()
        hw_status = hw_validator.validate_hw_details("all", run_args['add_computes'])

    elif 'add_osds' in run_args.keys() and \
            re.search(r'UCSM|StandAlone', testbed_type) and \
            re.match(r'PASS', sw_result['status']) and \
            re.search(r'all|hw_validation', run_args['checkType']):
        validator.set_oper_stage("Starting HW Validation, takes time!!!")
        hw_validator = hw_validations.HWValidator()
        hw_status = hw_validator.validate_hw_details("all", run_args['add_osds'])

    elif 'expand_osd' in run_args.keys() and \
            re.search(r'UCSM|StandAlone', testbed_type) and \
            re.match(r'PASS', sw_result['status']) and \
            re.search(r'all|hw_validation', run_args['checkType']):
        validator.set_oper_stage("Starting HW Validation, takes time!!!")
        hw_validator = hw_validations.HWValidator()
        host_list = [run_args['expand_osd']]
        hw_status = hw_validator.validate_hw_details("all", host_list)

    elif 'replace_controller' in run_args.keys() and \
            re.search(r'UCSM|StandAlone', testbed_type) and \
            re.match(r'PASS', sw_result['status']) and \
            re.search(r'all|hw_validation', run_args['checkType']):
        validator.set_oper_stage("Starting HW Validation, takes time!!!")
        hw_validator = hw_validations.HWValidator()
        hw_status = hw_validator.validate_hw_details("all", \
                                                     run_args['replace_controller'])

    elif re.match(r'PASS', sw_result['status']) and \
            re.search(r'all|hw_validation', run_args['checkType']):
        validator.set_oper_stage("Starting HW Validation, takes time!!!")

        # take a backup of setup data
        if "add_computes" not in run_args and "add_osds" not in run_args and \
            "remove_computes" not in run_args and \
                "remove_osd" not in run_args and \
                "replace_controller" not in run_args and \
                curr_setupfileloc is None:

            cfg_directory = os.environ['HOME'] + "/" + DEFAULT_CFG_DIR
            setup_file = cfg_directory + "/setup_data.yaml"
            backup_file = cfg_directory + "/.backup_setup_data.yaml"
            if os.path.isfile(setup_file):
                try:
                    if os.path.isfile(backup_file):
                        os.remove(backup_file)
                    shutil.copy2(setup_file, backup_file)
                except OSError:
                    pass
        hw_validator = hw_validations.HWValidator(
            setupfileloc=curr_setupfileloc)
        hw_status = hw_validator.validate_hw_details()

    overall_status = validator.get_validation_report_in_array(hw_status, bn_status)

    if not list(hw_status.keys()):
        overall_status['status'] = sw_result['status']
    else:
        hw_result = {}
        hw_result_info = \
            hw_status['Hardware Validation']['Overall_HW_Result']['status']
        hw_result['status'] = hw_result_info
        overall_status['status'] = hw_result['status']

    if list(bn_status.keys()):
        if re.search(r'FAIL', bn_status['status']):
            overall_status['status'] = bn_status['status']

    if os.path.isdir('/root/openstack-configs'):
        install_dir = os.readlink('/root/openstack-configs')
        with open(install_dir + '/.validation.json', 'w') as f:
            json.dump(overall_status, f)

    return overall_status


def check_status():
    '''
    Check Status
    '''
    return (Validator.STAGE_COUNT,
            Validator.OPER_STAGE)


def main(check_type={}):
    '''
    Config Manager main.
    '''
    run(run_args=check_type)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Input/RunTime Validation")
    parser.add_argument("--checkType", dest="CheckType",
                        default="static",
                        choices=["static", "all", "runtime", "ccp_orchestration",
                                 "optional", "static_hw_validation", "ccp_deletion",
                                 "ccp_upgrade"])

    parser.add_argument("--testType", dest="TestType",
                        default="all",
                        choices=["all", "nonblocking", "blocking"])

    parser.add_argument("--setup_file_location", dest="SetupFileLocation",
                        default="NotDefined", help="setup file location")

    parser.add_argument("--via_cli", dest="viaCLI",
                        action='store_true', default=False,
                        help="offline validation")

    input_args = {}
    args = parser.parse_args()
    input_args['checkType'] = args.CheckType
    input_args['testType'] = args.TestType
    input_args['SetupFileLocation'] = args.SetupFileLocation
    input_args['viaCLI'] = args.viaCLI

    main(input_args)
