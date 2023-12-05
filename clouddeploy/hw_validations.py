#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
UCS Hardware Validations:
=========================

UCS Hardware Validations Module:
--------------------------------
C-series checks
 1. Check the following hardware details as per the Cisco VIM requirements
     a) Firmware Version Check
         - Expected Version >= 2.0(3i) or 2.0(13e) for intel NIC
     b) All Onboard LOM Ports Check
        - LOM Port OptionROM should be 'Disable'
     c) PCIe Slot: HBA Status Check
        - HBA OptionROM should be 'Enable'
     d) Slot-HBA: Physical Drive Check
        - SLOT-HBA Physical Drive should be in health status 'Good'
     e) Slot-HBA: Virtual Drive Check
        - Virtual Drive Health status should be 'Good'
     f) Flex Flash: Physical Drive Check
        -  Card mode should be in 'mirror' mode and
           Sync status should be 'auto'
     g) Default CISCO VNICs(eth0 and eth1) PXE Boot check
        - eth0 and eth1 VNICs PXE boot status should be disabled
     f) VIC Adapter Card Vendor Check
        - currently supports only Cisco

B-series checks
  1. Check the following hardware details as per the Cisco VIM requirements
     a) Chassis Servers Model check
        - Expected Model : >= B-200 M4
     b) Rack_mounts servers Model check
        - Expected Model : >= C-240 M4
     c) UCSM Servers Power status
        - Should be Power ON
     d) UCSM Servers Flexflash Status check
        - Expected : should be in mirror mode (primary & secondary) and
                     sync status should be 'Auto'
     e) UCSM servers service profile assignment check
        -  Not part of sub-org service profiles should not be associated.
     f) UCSM Chassis servers Storage disks check
        - Expected : supported only two storage disks
     g) UCSM Chassis servers Memory check
        - Expected :All memory slot should be operable and
          none of them are in inoperable state

"""
import argparse
import json
import logging
import netaddr
import os
import prettytable
import re
import subprocess
import sys
import textwrap
from threading import Thread
import time
import timeit
import multiprocessing
from multiprocessing.pool import ThreadPool
from functools import partial
from copy import deepcopy

try:
    curr_folder_path, curr_folder_name = os.path.split(os.getcwd())
    if re.search(r'installer|cvim', curr_folder_path):
        sys.path.append(curr_folder_path)
    elif re.search(r'installer|cvim', curr_folder_name):
        sys.path.append(os.getcwd())
    else:
        print "Script should be run either from " \
              "<installer_dir> or <installer_dir>/clouddeploy/ directory "
        sys.exit(1)
except Exception as exception:
    print "Error in setting up PYTHONPATH :%s" % (exception)

import baremetal.ucs_c.cimc_utils as cimcutils
import baremetal.ucs_b.ucsm_utils as ucsmutils
import baremetal.common.constants as constants
import utils.common as common_utils
import clouddeploy.schema_validation as schema_validation

import utils.config_parser as config_parser
import utils.logger as logger

DEFAULT_CFG_DIR = "openstack-configs"
DEFAULT_SETUP_FILE = "setup_data.yaml"
DEFAULTS_FILE = "defaults.yaml"
SECRETS_FILE = "secrets.yaml"
DEFAULT_IPMI_FILE = "ironic_inventory.yaml"

FW_VERSION_CHK = "CIMC Firmware Version Check"
LOM_INTF_CHK = "All Onboard LOM Ports Check"
HBA_STATUS_CHK = "PCIe Slot: HBA Status Check"
PHYSICAL_DRIVES_CHK = "Physical Drives Check"
FF_PD_CHK = "FlexFlash Status Check"
CIMC_API_CHK = "CIMC API Check"
USER_ERROR = "User Error"
SERVER_CHK = "UCSC Validation"
PCI_ADAPTERS_CHK = "PCIe Slot(s) OptionROM Check"
VNIC_PXE_BOOT_CHK = "Default VNICs PXE Boot Check"
POWER_STATE_CHK = "Server Power Status Check"
VIC_ADAPTER_CHK = "VIC Adapter Check"
NFV_CONFIG_CHK = "NFV Config Check"
INTEL_NIC_CHK = "Intel Network Adapter Check"
INTEL_BOOT_ORDER_CHK = "Intel NIC Actual Boot Order Check"
INTEL_BOOT_CONFIG_CHK = "Boot Config Check"
REDFISH_CONFIG_CHK = "Redfish Enabled Check"
ARGUS_NIC_CHK = "Argus NIC Adapter Check"
ARGUS_DISK_CHK = "Disk Quantity and Uniformity Check"
VIRT_VT_AND_VTD_CHK = "Virtualization(VT/VT-d) Status Check"
SCHEMA_VALIDATION = "Schema Validation of Input File"
IPMI_STATUS_CHK = "IPMI over LAN Status Check"
IPMI_KEY_CHK = "IPMI Encryption Key Check"
VNIC_VLAN_MODE_CHK = "Default VNICs VLAN Mode Check"
PXE_BOOT_ORDER_CHK = "PXE Boot Order Check"
LLDP_STATUS_CHK = "LLDP Status Check"
IPMI_DEFAULT_EN_KEY = "0000000000000000000000000000000000000000"
P_GPU_CARD_CHK = "Physical GPU Card Check"
FOREIGN_CFG_CHK = "Foreign Config Check"

UCSM_VALIDATION = "UCSM Validation"
UCSM_BLADES_MODEL_CHK = "UCSM Chassis Servers Model Check"
UCSM_RACKS_MODEL_CHK = "UCSM Rack-Mount Servers Model Check"
UCSM_SERVERS_POWER_CHK = "UCSM Servers Power Status Check"
UCSM_SERVERS_FF_CHK = "UCSM Servers Flexflash Status Check"
UCSM_SP_ASSIGN_CHK = "UCSM Servers Service Profile Check "
UCSM_STORAGE_CHK = "UCSM Chassis Servers Storage Disk Check"
UCSM_MEMORY_CHK = "UCSM Chassis Servers Memory Check"
UCSM_ADAPTER_CHK = "UCSM Servers VIC Adapter Check"
UCSM_LUN_CHK = "UCSM Rack Servers Storage LUN Check"
UCSM_NFV_CONFIG_CHK = "UCSM Chassis Servers NFV Config Check"
UCSM_IOM_CHK = "UCSM Chassis Servers IO Module Check"
UCSM_MRAID_CHK = "UCSM Rack-Mount Servers MRAID Check"

RESOLVE_LOM_INTF = "Resolve All Onboard LOM Ports Failures"
RESOLVE_HBA_STATUS = "Resolve PCIe Slot: HBA Status Failures"
RESOLVE_FF_PD = "Resolve FlexFlash Status Failures"
RESOLVE_PCI_ADAPTERS = "Resolve PCIe Slot(s) OptionROM Failures"
RESOLVE_VNIC_PXE_BOOT = "Resolve Default VNICs PXE Boot Failures"
RESOLVE_POWER_STATE = "Resolve Server Power Status Failures"
RESOLVE_VIRT_STATUS = "Resolve BIOS Virtualization Failures"
RESOLVE_VNIC_VLAN_MODE = "Resolve VNICs VLAN Mode Failures"
RESOLVE_IPMI_STATUS = "Resolve IPMI Status Failures"
RESOLVE_PXE_BOOT_ORDER_STATUS = "Resolve PXE Boot Order Failures"
RESOLVE_IPMI_KEY = "Resolve IPMI Encryption Key Failures"
RESOLVE_LLDP_STATUS = "Resolve LLDP Status Failures"
RESOLVE_BOOT_CONFIG = "Resolve Boot Config Failures"
RESOLVE_FOREIGN_CONIG = "Clear Foreign Config"
IRONIC_VALIDATIONS = ["vnic_vlan_mode", "ipmi_key", "ipmi_status",
                      "pxe_boot_order", "lldp_status", "boot_config"]

THREAD_POOL_SIZE = multiprocessing.cpu_count() \
    if multiprocessing.cpu_count() < 40 else 40


class HWValidator(object):
    '''
    Validator class.
    '''
    OPER_STAGE = "INIT"
    STAGE_COUNT = 0

    def __init__(self, standalone=False, setupfileloc=None, target_ospd=False,
                 ironic=False, ironicfileloc=None):
        '''
        Initialize validator
        '''
        # ###############################################
        # Set up logging
        # ###############################################
        if standalone:
            """ Creating a python logger to stdout which helps the standalone
            user to see the validation status and results on the terminal """
            self.log = logging.getLogger(__name__)
            out_hdlr = logging.StreamHandler(sys.stdout)
            out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
            out_hdlr.setLevel(logging.INFO)
            self.log.addHandler(out_hdlr)
            self.log.setLevel(logging.INFO)
        else:
            self.loginst = logger.Logger(name=__name__)
            self.log = self.loginst.get_logger()

        self.ymlhelper = None
        self.ironic_yml_helper = None
        self.ironic_inv_file = None
        self.ironic_validation = False

        self.validation_results = []
        self.resolve_failures_results = []
        self.target_ospd = target_ospd
        homedir = self.get_homedir()
        self.cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)

        if setupfileloc is not None:
            self.setup_file = setupfileloc
        else:
            self.setup_file = os.path.join(self.cfg_dir, DEFAULT_SETUP_FILE)

        if ironicfileloc is not None:
            self.ironic_inv_file = ironicfileloc
            if ironic:
                self.ironic_validation = True
        else:
            self.ironic_inv_file = os.path.join(self.cfg_dir, DEFAULT_IPMI_FILE)
            if ironic:
                self.ironic_validation = True

        self.defaults_file = os.path.join(self.cfg_dir, DEFAULTS_FILE)
        self.secrets_file = os.path.join(self.cfg_dir, SECRETS_FILE)

        self.ymlhelper = config_parser.YamlHelper(
            user_input_file=self.setup_file)
        if ironic and self.ironic_inv_file:
            if os.path.exists(self.ironic_inv_file):
                self.ironic_yml_helper = config_parser.YamlHelper(
                    user_input_file=self.ironic_inv_file)

        """ Added dummy entry in the lists to make sure validation is performed
        which helps in the logic to display the results accordingly"""

        self.cimc_version_chk_fail_list = ['failed']
        self.cimc_lom_chk_fail_list = ['failed']
        self.cimc_hba_chk_fail_list = ['failed']
        self.cimc_physical_drives_chk_fail_list = ['failed']
        self.pchstorage_warn_list = []
        self.cimc_flex_flash_pd_fail_list = ['failed']
        self.cimc_credentials = {}
        self.cimc_ssh_chk_fail_list = []
        self.ff_capacity_warn_list = []
        self.ff_sync_warn_list = []
        self.auth_failure_list = []
        self.vic_slot_mapping = {}
        self.hostname_mapping = {}
        self.pcie_slot_failure_list = ['failed']
        self.nfv_cfg_failure_list = ['failed']
        self.cisco_vnic_pxe_chk_fail_list = ['failed']
        self.unsupported_hw_list = []
        self.offline_hw_list = []
        self.max_sessions_exceed_list = []
        self.common_failures_list = []
        self.power_failure_list = ['failed']
        self.validation_report = {}
        self.resolve_failures_report = {}
        self.vic_unsupported_vendor_list = ['failed']
        self.roles_map = {}
        self.vic_adapter_warn_list = []
        self.nfv_hosts = None
        self.intel_nic_warn_list = []
        self.intel_boot_order_warn_list = []
        self.intel_nic_failures_list = ['failed']
        self.intel_boot_order_failures_list = ['failed']
        self.intel_boot_config_failures_list = ['failed']
        self.redfish_enabled_failures_list = ['failed']
        self.argus_nic_failures_list = ['failed']
        self.argus_disk_failures_list = ['failed']
        self.argus_disk_uniformity = list()
        self.virt_vt_vtd_chk_failures_list = ['failed']
        self.ipmi_status_failure_list = ['failed']
        self.ipmi_key_failure_list = ['failed']
        self.cisco_vnic_vlan_mode_chk_fail_list = ['failed']
        self.pxe_boot_order_chk_fail_list = ['failed']
        self.lldp_status_failure_list = ['failed']
        self.p_gpu_chk_fail_list = ['failed']
        self.cimc_foreign_chk_fail_list = ['failed']
        self.final_result = {}

        self.ucsm_unsupported_blades_list = ['failed']
        self.ucsm_unsupported_racks_list = ['failed']
        self.ucsm_servers_power_failure_list = []
        self.ucsm_ff_status_fail_list = ['failed']
        self.ucsm_sp_assignment_fail_list = ['failed']
        self.ucsm_storage_failures = ['failed']
        self.ucsm_memory_failures = ['failed']
        self.ucsm_adapter_failures = ['failed']
        self.ucsm_lun_failures = ['failed']
        self.ucsm_nfv_config_failures = ['failed']
        self.ucsm_iom_failures = ['failed']
        self.ucsm_mraid_failures = ['failed']

        self.log.debug("Hardware Validator Initialized")

    def set_oper_stage(self, msg):
        '''
        Set Operation stage status.
        '''
        HWValidator.OPER_STAGE = msg
        HWValidator.STAGE_COUNT += 1

    def get_homedir(self):
        '''
        Get the current username
        '''
        homedir = os.path.expanduser("~")
        return homedir

    def set_validation_results(self, name, status='PASS', err=None,
                               reslv_reslt=False):
        '''   Set the validations, for the rules. '''
        result = {}
        result['name'] = name
        result['err'] = err
        if status is 'PASS':
            status = "\033[92mPASS\033[0m"
        else:
            status = "\033[91mFAIL\033[0m"
        result['status'] = status
        if reslv_reslt:
            self.resolve_failures_results.append(result)
        self.validation_results.append(result)

    def is_ipv4v6_valid(self, ip_addr):
        '''Checks if input is of type v4 or v6 address'''
        valid = False
        try:
            if (netaddr.IPNetwork(ip_addr).version == 4 or \
                    netaddr.IPNetwork(ip_addr).version == 6):
                valid = True
        except netaddr.core.AddrFormatError:
            self.log.debug("Invalid IPv4 or IPv6 address format: %s", ip_addr)
        return valid

    def display_validation_results(self, display_reslv_rslts=False):
        '''
        Print the validation results
        '''
        ptable = prettytable.PrettyTable(["UseCase", "Status", "Failure Reason"])
        ptable.align["UseCase"] = "l"
        ptable.align["Failure Reason"] = "l"
        if not display_reslv_rslts:
            for rule in self.validation_results:
                err_str = None
                if rule['err']:
                    err_str = textwrap.fill(rule['err'].strip(), width=40)

                name_str = textwrap.fill(rule['name'].strip(), width=40)

                ptable.add_row([name_str, rule['status'], err_str])

            print "\n"
            if self.ironic_validation:
                print "  Ironic Hardware Validations"
            else:
                print "  UCS Hardware Validations"
            self.log.info("**** UCS Hardware Validations! ****")
            print ptable
        else:
            if self.resolve_failures_results:
                for rule in self.resolve_failures_results:
                    err_str = None
                    if rule['err']:
                        err_str = textwrap.fill(rule['err'].strip(), width=40)

                    name_str = textwrap.fill(rule['name'].strip(), width=40)

                    ptable.add_row([name_str, rule['status'], err_str])

                print "\n"
                print "  Resolve Hardware Validations Failures"
                self.log.info("**** Resolve Hardware Validations Failures ****")
                print ptable


    def check_validation_results(self):
        '''
        Checks the validation info and returns overall Pass/Fail
        '''
        result = {}
        result['status'] = 'PASS'

        for rule in self.validation_results:
            if re.search(r'FAIL', rule['status']):
                result['status'] = 'FAIL'
        return result

    def check_user_config_location(self):
        '''
        Make sure user configs are present
        '''
        result = {}

        self.log.debug("User config directory and file validation")

        if not os.path.exists(self.cfg_dir):
            result['status'] = 'FAIL'
            msg = "%s Directory does not exist." % (self.cfg_dir)
            cmsg = logger.stringc(msg, 'red')
            self.log.error(cmsg)
            return result

        if not os.path.exists(self.setup_file) or \
                not os.path.exists(self.defaults_file) or \
                not os.path.exists(self.secrets_file):
            result['status'] = 'FAIL'
            msg = "Provide user input files %s, %s %s" % (self.setup_file,
                                                          self.defaults_file,
                                                          self.secrets_file)
            cmsg = logger.stringc(msg, 'red')
            self.log.error(cmsg)
            return result

        result['status'] = 'PASS'

        self.log.debug("User Config location validation: Successful")
        return result

    def check_nfv_configs(self, nfv_cfg, cpu_mem):
        """
        Verify whether NFV configs are able to be applied
        Note: This function will be run on a per NFV host fasion.
        """

        def threads_set(csv):
            '''set the thread'''
            return set([int(x) for x in csv.split(',') if x])

        total_pcores = cpu_mem['cores_per_socket'] * cpu_mem['nr_sockets']
        nfv_dict = self.ymlhelper.get_nfv_dict(nfv_cfg, cpu_mem)
        hostcpus = threads_set(nfv_dict['ansible_inventory_dict']['hostcpus'])
        vswitchcpus = threads_set(nfv_dict['ansible_inventory_dict']['vswitchcpus'])
        cephosdcpus = set(self.ymlhelper.break_comma_hyphen_list(
            nfv_dict['ansible_inventory_dict']['ceph_osd_cpuset_cpus']))
        res_hp_2m = int(nfv_dict['ansible_inventory_dict']['res_hp_2m'])
        res_hp_1g = int(nfv_dict['ansible_inventory_dict']['res_hp_1g'])
        if len(hostcpus) > cpu_mem['total_threads']:
            err_str = ('NR_RESERVED_HOST_PCORES: %(cfg_pcores)s exceeds '
                       '%(total_pcores)s physical '
                       'cores available on the system.' % {
                           'cfg_pcores': nfv_cfg['nr_reserved_host_pcores'],
                           'total_pcores': total_pcores})
            return err_str

        if hostcpus.intersection(vswitchcpus).intersection(cephosdcpus):
            err_str = "The cores reserved for system services, vswitches, " \
                "and ceph-osd services are more than the available cores on " \
                "the host. Reduce NR_RESERVED_HOST_PCORES and/or " \
                "NR_RESERVED_ISOL_PCORES and/or CEPH_OSD_RESERVED_PCORES " \
                "and try again."
            return err_str

        if res_hp_2m > 0 and res_hp_1g > 0:
            err_str = "Both 2M and 1G huge pages are configured to be " \
                "reserved, but vswitches will consume only one of the " \
                "sizes. Reserve only one size of huge pages and try " \
                "again."
            return err_str

        # Check if there is minimum memory rserved for system services
        system_memory = nfv_dict['ansible_inventory_dict']['res_sys_mem']
        if system_memory < 16384:
            err_str = 'Minimum of 16GB memory is required for host OS.'
            return err_str

        # Get the *estimated* available memory from CIMC
        #
        # From the known fact, the real available memory for operating system
        # to use is approximately 98% of the installed memeory in DIMM:
        #     (UCS C220)
        #         DIMM Memory: 65536 MB, OS available: 64159 MB
        #         DIMM Memory: 131072 MB, OS available: 128726 MB
        #         DIMM Memory: 262144 MB, OS available: 257582 MB
        #         DIMM Memory: 524288 MB, OS available: 515772 MB
        #
        # However, there is no way to get the precise value during hardware
        # validation phase, so an estimated value (97% of physical installed
        # memory to be safe) will be used to perform the validation.
        avail_mem = int(cpu_mem['total_memory'] * 0.97)
        res_mem_2m = nfv_dict['ansible_inventory_dict']['res_hp_2m'] * 2
        res_mem_1g = nfv_dict['ansible_inventory_dict']['res_hp_1g'] * 1024
        if avail_mem < system_memory + res_mem_2m + res_hp_1g:
            err_str = "There is not enough memory (%s MB estimated total) " \
                "to reserve for the sum of system memory (%s MB), 2M huge " \
                "pages (%s MB), and 1G huge pages (%s MB). Reduce reserved " \
                "memories and try again." % (
                    avail_mem, system_memory, res_mem_2m, res_mem_1g
                )

        return 'PASS'

    def hw_validation_check(self, use_case, host_list, ironic_validation=False):
        """ Checks that the H/W is valid or not as per the
        Cisco VIM Requirements"""

        if ironic_validation:
            err_segment = ""
            invalid_host_list = []
            servers = []

            if not (self.ymlhelper.is_ironic_enabled() and \
                    os.path.exists(self.ironic_inv_file)):
                err_segment = "WARNING: Skipping Hardware Validation as " + \
                              " IRONIC is not enabled and/or " + \
                              "ironic_inventory.yaml file not available under " + \
                              " /root/openstack-configs/ directory."
                self.set_validation_results(USER_ERROR, status='PASS',
                                            err=err_segment)
                return

            if host_list is None:
                servers = self.ironic_yml_helper.get_ipmi_server_list()
            else:
                servers = host_list
            for server in servers:
                if not common_utils.is_valid_hostname(server) or \
                        self.is_ipv4v6_valid(server):
                    invalid_host_list.append(server)

            if len(invalid_host_list) > 0:
                err_segment = "Provide valid host names for " + \
                              str(invalid_host_list)
                self.set_validation_results(USER_ERROR, status='FAIL',
                                            err=err_segment)
                return

            overlap_cimc, unsupported_servers = self.check_overlap_cimc_ip(host_list)
            if len(overlap_cimc) > 0:
                err_segment = "IPMI Address " + str(overlap_cimc) + \
                              " has been already used in setup_data.yaml"
                self.set_validation_results(USER_ERROR, status='FAIL',
                                            err=err_segment)
                return

            if len(unsupported_servers) > 0:
                err_segment = "WARNING: Skipping Hardware Validation as IRONIC" + \
                              " HW Validation not yet supported for Third party" + \
                              " server(Quanta/HP)"
                self.set_validation_results(USER_ERROR, status='PASS',
                                            err=err_segment)
                return

        if host_list:
            for server in host_list:
                if not common_utils.is_valid_hostname(server) or \
                        self.is_ipv4v6_valid(server):
                    err_segment = "Provide Valid Host name(s) as defined in " + \
                                  "'setup_data.yaml' file instead of Ipaddress"
                    self.set_validation_results(USER_ERROR, status='FAIL',
                                                err=err_segment)
                    return

        self.log.info("Hardware Validation is in progress. " \
                      "May take some time....")
        threadlist = []
        hw_type = self.get_hardware_type()
        podtype = self.ymlhelper.get_pod_type()

        if re.match(r'UCSM', hw_type):
            self.validate_ucsm_hardware(host_list)
        elif re.match(r'UCSC|IPMI', hw_type) or podtype == 'CVIMMONHA':
            servers = self.validate_ucsc_hardware(use_case, host_list,
                                                  ironic_validation)
            for server in servers:
                hw_result = self.final_result.get(server)
                if hw_result:
                    self.validate_results(hw_result, server)

        self.display_hw_validation_results()

    def check_overlap_cimc_ip(self, host_list):
        """
        Function to check cimc ip overlaps with
        ironic nodes
        """
        overlap_list = []
        unsupported_platform = []
        ironic_servers = self.populate_ironic_ipmi_details(host_list)
        cvim_servers = self.populate_server_details()
        for i_server in ironic_servers[0]:
            vendor = self.ironic_yml_helper.get_platform_vendor(i_server,
                                                                True)
            if not vendor == "CSCO":
                unsupported_platform.append(i_server)

            for c_server in cvim_servers[0]:
                if i_server == c_server:
                    overlap_list.append(i_server)

        return overlap_list, unsupported_platform

    def validate_ucsc_hardware(self, use_cases, host_list, ironic):
        """
        validate UCSC hardware
        """
        input_data = []
        threadlist = []
        podtype = self.ymlhelper.get_pod_type()
        if ironic:
            err_str = ""
            schema_validator = schema_validation.SchemaValidator(self.setup_file, \
                                                             "install")
            schema_check_list = schema_validator.ironic_schema_validation(\
                self.ironic_yml_helper.get_parsed_config())
            if len(schema_check_list):
                err_str = " ::".join(schema_check_list)
                self.set_validation_results(SCHEMA_VALIDATION,
                                            status='FAIL',
                                            err=err_str)
                return threadlist
            input_data = self.populate_ironic_ipmi_details(host_list)
        elif podtype == 'CVIMMONHA':
            input_data = self.populate_argus_server_details(host_list)
        else:
            input_data = self.populate_server_details(host_list)

        cimc_ip_addr_list = input_data[0]
        cimc_uname_list = input_data[1]
        cimc_pwd_list = input_data[2]
        error_found = input_data[3]
        kwargs = {}
        pool = ThreadPool(processes=THREAD_POOL_SIZE)
        excec_function = ""
        args_map = {}
        if not error_found:
            for curr_ip, curr_uname, curr_pwd in \
                    zip(cimc_ip_addr_list, cimc_uname_list, cimc_pwd_list):
                kwargs['curr_uname'] = curr_uname
                kwargs['curr_pwd'] = curr_pwd
                kwargs['validate_of'] = use_cases
                kwargs['ironic_node'] = ironic
                if not ironic:
                    cimc = cimcutils.CIMC(curr_ip, curr_uname, curr_pwd, \
                           user_input_file=self.setup_file, ipmi_node=ironic)
                    if cimc is None:
                        self.log.info("Can't Get CIMC object for %s", curr_ip)
                        return 0
                    try:
                        # Firmware version check
                        fw_version = cimc.cimc_get_version()
                        if fw_version is None:
                            err_segment = curr_ip + "--" + " CIMC API Check " + \
                                " failed. Check for validity of CIMC IP, " + \
                                "Username and/or Password or number of active" + \
                                "CIMC session > 4 on "
                            self.cimc_ssh_chk_fail_list.append(err_segment)
                            continue

                        if podtype == 'CVIMMONHA':
                            if int(fw_version['major']) < \
                                    int(constants.CIMC_ARGUS_MAJOR):
                                err_segment = curr_ip + "--" + " Unsupported " + \
                                    " Firmware version (" + \
                                    + str(fw_version).replace(":", "=") + ")" + \
                                    " found on the server(s). Supported " + \
                                    " versions are Major = 4.0 and Minor >= 1a on "
                                self.unsupported_hw_list.append(err_segment)
                                continue
                        else:
                            if not cimc.cimc_check_firmware_version():
                                err_segment = curr_ip + "--" + " Unsupported " + \
                                    " Firmware version (" + \
                                    str(fw_version).replace(":", "=") + ")" + \
                                    " found on the server(s). Supported " + \
                                    " versions are Major = 2.0 and Minor >= 3i on "
                                self.unsupported_hw_list.append(err_segment)
                                continue

                        # Server Model check
                        roles = self.roles_map[curr_ip]
                        if "block_storage" in roles and len(roles) == 1:
                            server_model = cimc.get_server_model()
                            if not any(submodel in server_model for submodel \
                                       in constants.STORAGE_SERVER_MODELS):
                                err_segment = curr_ip + "--" + " Unsupported " + \
                                    "Hardware(" + server_model + ") found for " + \
                                    "Storage node(s).Supported is C240-M4 model"
                                self.unsupported_hw_list.append(err_segment)
                                continue
                        else:
                            server_model = cimc.get_server_model()
                            if not any(submodel in server_model for submodel \
                                       in constants.CONTROL_COMPUTE_SERVER_MODELS) \
                                    and ("control" in roles or "compute" in roles):
                                err_segment = curr_ip + "--" + " Unsupported " + \
                                    "Hardware(" + server_model + ") found for " + \
                                    "Control/Compute node(s). Supported is " + \
                                    "C220/C240 - model"
                                self.unsupported_hw_list.append(err_segment)
                                continue
                        args_map[curr_ip] = deepcopy(kwargs)
                    except Exception as e:
                        self.log.error("Exception on  %s with %s", curr_ip, e)
                        error_desc = cimc.cimc_get_error_details(e, True)
                        if re.search(r'Authentication failed', error_desc):
                            self.log.debug("Authentication failed for %s", curr_ip)
                            self.auth_failure_list.append(curr_ip)
                        elif re.search(r'Maximum sessions reached', error_desc):
                            self.log.debug("Maximum sessions reached for  %s",
                                           curr_ip)
                            self.max_sessions_exceed_list.append(curr_ip)
                        elif re.search(r'connection timed', error_desc.lower()):
                            self.log.debug("Server not reachable %s", curr_ip)
                            self.offline_hw_list.append(curr_ip)
                        else:
                            self.log.debug("Unknowm Errors on %s", curr_ip)

                        continue

                    if cimc:
                        cimc.cimc_logout()

                    excec_function = self.check_ucsc_hw_details
                else:
                    args_map[curr_ip] = deepcopy(kwargs)
                    excec_function = self.check_ucsc_ipmi_hw_details

        if excec_function:
            job_args = [(k, v) for k, v in args_map.iteritems()]
            pool.map(partial(self.worker_wrapper, excec_function),
                     job_args)
            pool.close()
            pool.join()

        return cimc_ip_addr_list

    def worker_wrapper(self, function, args):
        """
        Worker wrapper function to provide the required arguments
        to the job
        """
        cimc_ip = ""
        try:
            cimc_ip, kwargs = args
            return function(cimc_ip, **kwargs)
        except Exception as e:
            self.log.error("Exception on %s with : %s", cimc_ip, e)

    def populate_chassis_blade_rack_details(self, host_list):
        """
        Mapping chassisid, bladeid and rackid  based on
        the user inputs from the setup_data.yaml file
        to filter the servers to validate from whole servers
        avaialble in UCSM
        """
        chassis_info = {}
        rack_id_list = []
        if host_list is None:
            '''Default, consider all the servers in setup_data.yaml file
                   for validation '''
            servers = self.ymlhelper.get_server_list()
        else:
            '''Only specific servers for validation '''
            servers = host_list

        if len(servers):
            for server in servers:
                if len(server):

                    blade_id = self.ymlhelper.get_server_ucsm_details(
                        server, "blade_id")
                    chassis_id = self.ymlhelper.get_server_ucsm_details(
                        server, "chassis_id")
                    chassis_id = str(chassis_id)
                    rack_id = self.ymlhelper.get_server_ucsm_details(
                        server, "rack-unit_id")
                    if rack_id:
                        rack_id_list.append(str(rack_id))

                    blade_id_list = chassis_info.get(chassis_id)
                    if not blade_id_list:
                        blade_id_list = []
                        if blade_id:
                            blade_id_list.append(str(blade_id))
                            chassis_info[chassis_id] = blade_id_list
                    else:
                        if blade_id not in blade_id_list:
                            blade_id_list.append(str(blade_id))
                            chassis_info[chassis_id] = blade_id_list

        return chassis_info, rack_id_list

    def populate_server_details(self, host_list=None):
        """
        Populating prerequisities for Hardware Validation
        """
        try:
            error_found = 0
            cimc_ip_addr_list = []
            cimc_uname_list = []
            cimc_pwd_list = []
            invalid_cimc_ip_addr_list = []
            missing_cimc_uname = []
            missing_cimc_pwd = []

            if host_list is None:
                '''Default, consider all the servers in setup_data.yaml file
                   for validation '''
                servers = self.ymlhelper.get_server_list()
            else:
                '''Only specific servers for validation '''
                servers = host_list
            if len(servers):
                for server in servers:
                    if len(server):
                        ip_addr = self.ymlhelper.get_server_cimc_ip(
                            server, return_value=1)
                        if ip_addr is None:
                            if server not in invalid_cimc_ip_addr_list:
                                invalid_cimc_ip_addr_list.append(server)

                        uname = self.ymlhelper.get_server_cimc_username(
                            server)

                        vic_slot = self.ymlhelper.get_server_hw_info(\
                            server, "VIC_slot")

                        if ip_addr is not None:
                            self.vic_slot_mapping[ip_addr] = vic_slot
                            self.hostname_mapping[ip_addr] = server

                        cimc_uname_list.append(uname)
                        if uname is None:
                            missing_cimc_uname.append(server)

                        pwd = self.ymlhelper.get_server_cimc_password(server)
                        cimc_pwd_list.append(pwd)
                        if pwd is None:
                            missing_cimc_pwd.append(server)

                        if (ip_addr is not None and \
                                self.is_ipv4v6_valid(ip_addr)):
                            cimc_ip_addr_list.append(ip_addr)
                        else:
                            if server not in invalid_cimc_ip_addr_list:
                                invalid_cimc_ip_addr_list.append(server)

                        if ip_addr is not None:
                            self.roles_map[ip_addr] = \
                                self.ymlhelper.get_server_cimc_role(server,
                                                                    allroles=True)
            if ip_addr is not None:
                self.nfv_hosts = \
                    [self.ymlhelper.get_server_cimc_ip(x, return_value=1) \
                     for x in self.ymlhelper.get_server_list(role='nfv_host')]

        except TypeError:
            error_found = 1
            err_segment = "Missing Info in setup.yaml file"
            self.set_validation_results(USER_ERROR, status='FAIL',
                                        err=err_segment)
            return

        if len(invalid_cimc_ip_addr_list):
            error_found = 1
            err_segment = "Host not found in 'setup_data.yaml' file:" + \
                          str(invalid_cimc_ip_addr_list)
            self.set_validation_results(USER_ERROR, status='FAIL',
                                        err=err_segment)

        if len(missing_cimc_uname):
            error_found = 1
            err_segment = "Missing CIMC Username:" + \
                          str(missing_cimc_uname)
            self.set_validation_results(USER_ERROR, status='FAIL',
                                        err=err_segment)

        if len(missing_cimc_pwd):
            error_found = 1
            err_segment = "Missing CIMC Password:" + \
                          str(missing_cimc_pwd)
            self.set_validation_results(USER_ERROR, status='FAIL',
                                        err=err_segment)

        return cimc_ip_addr_list, cimc_uname_list, cimc_pwd_list, error_found


    def populate_ironic_ipmi_details(self, host_list):
        """
        Populating prerequisities for Hardware Validation
        """
        try:
            error_found = 0
            cimc_ip_addr_list = []
            cimc_uname_list = []
            cimc_pwd_list = []
            invalid_cimc_ip_addr_list = []
            missing_cimc_uname = []
            missing_cimc_pwd = []
            invalid_host_list = []

            if host_list is None:
                '''Default, consider all the servers in setup_data.yaml file
                   for validation '''
                servers = self.ironic_yml_helper.get_ipmi_server_list()
            else:
                '''Only specific servers for validation '''
                servers = host_list

            if len(servers):
                for server in servers:
                    if len(server):
                        ip_addr = self.ironic_yml_helper.get_ipmi_server_ip(
                            server, return_value=1)
                        if ip_addr is None:
                            if server not in invalid_cimc_ip_addr_list:
                                invalid_cimc_ip_addr_list.append(server)
                        uname = self.ironic_yml_helper.get_ipmi_server_username(
                            server)
                        cimc_uname_list.append(uname)
                        if uname is None:
                            missing_cimc_uname.append(server)

                        pwd = self.ironic_yml_helper.get_ipmi_server_password(server)
                        cimc_pwd_list.append(pwd)

                        if pwd is None:
                            missing_cimc_pwd.append(server)

                        if (ip_addr is not None and \
                                self.is_ipv4v6_valid(ip_addr)):
                            self.hostname_mapping[ip_addr] = server
                            cimc_ip_addr_list.append(ip_addr)
                        else:
                            if server not in invalid_cimc_ip_addr_list:
                                invalid_cimc_ip_addr_list.append(server)
        except TypeError:
            error_found = 1
            err_segment = "Missing Info in ironic_inventory.yaml file"
            self.set_validation_results(USER_ERROR, status='FAIL',
                                        err=err_segment)
            return

        if len(invalid_cimc_ip_addr_list):
            error_found = 1
            err_segment = "Host not found in 'ironic_inventory.yaml' file:" + \
                          str(invalid_cimc_ip_addr_list)
            self.set_validation_results(USER_ERROR, status='FAIL',
                                        err=err_segment)

        if len(missing_cimc_uname):
            error_found = 1
            err_segment = "Missing IPMI Username:" + \
                          str(missing_cimc_uname)
            self.set_validation_results(USER_ERROR, status='FAIL',
                                        err=err_segment)

        if len(missing_cimc_pwd):
            error_found = 1
            err_segment = "Missing IPMI Password:" + \
                          str(missing_cimc_pwd)
            self.set_validation_results(USER_ERROR, status='FAIL',
                                        err=err_segment)


        return cimc_ip_addr_list, cimc_uname_list, cimc_pwd_list, error_found

    def populate_argus_server_details(self, host_list):
        """
        Populating prerequisities for Hardware Validation
        """
        try:
            error_found = 0
            cimc_ip_addr_list = []
            cimc_uname_list = []
            cimc_pwd_list = []

            cimc_ip_addr_list = self.ymlhelper.get_argus_server_list()
            cimc_uname_list = self.ymlhelper.get_argus_oob_username()
            cimc_pwd_list = self.ymlhelper.get_argus_oob_password()

            for ip_addr in cimc_ip_addr_list:
                self.roles_map[ip_addr] = 'cvimmonha'
                self.vic_slot_mapping[ip_addr] = None
                self.hostname_mapping[ip_addr] = None
            self.nfv_hosts = []

        except TypeError:
            error_found = 1
            err_segment = "Missing Info in setup.yaml file"
            self.set_validation_results(USER_ERROR, status='FAIL',
                                        err=err_segment)
            return


        return cimc_ip_addr_list, cimc_uname_list, cimc_pwd_list, error_found

    def validate_ucsm_hardware(self, host_list):
        """
        Validate  UCSM hardware details
        """
        chassis_info, rack_id_list = \
            self.populate_chassis_blade_rack_details(host_list)
        if not (chassis_info or rack_id_list):
            err_segment = "Server(s) Not Found." + \
                          str(host_list) + " . Please check the Inventory"
            self.set_validation_results(UCSM_RACKS_MODEL_CHK, status='FAIL',
                                        err=err_segment)
            self.validation_report[UCSM_RACKS_MODEL_CHK] = "FAIL" \
                + "~" + err_segment
            return
        ucsm_ip = self.ymlhelper.get_common_ucsm_ip()
        ucsm_user = self.ymlhelper.get_common_ucsm_username()
        ucsm_pass = self.ymlhelper.get_common_ucsm_password()
        ucsm_prefix = self.ymlhelper.get_common_ucsm_prefix()
        mraid_mode = self.ymlhelper.enable_mraid_card()

        self.validate_ucsm_user_inputs(ucsm_ip, ucsm_user, ucsm_pass, ucsm_prefix)
        ucsm = ucsmutils.UCSM(ucsm_ip, ucsm_user, ucsm_pass, ucsm_prefix)
        try:
            # UCSM Blades Model Type check
            if chassis_info:
                self.log.info("Verifying Chassis Servers model on %s ", ucsm_ip)
                if "failed" in self.ucsm_unsupported_blades_list:
                    self.ucsm_unsupported_blades_list.remove("failed")
                ucsm_blade_version_chk = ucsm.check_ucsm_chassis_servers_model(
                    chassis_info)
                if re.search(r'APIFAILED', str(ucsm_blade_version_chk)):
                    self.log.info("UCSM Blades Model Type API failed for %s", \
                                  ucsm_ip)
                    api_failures = ucsm_ip + "--" + UCSM_BLADES_MODEL_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif ucsm_blade_version_chk:
                    self.ucsm_unsupported_blades_list.append(ucsm_blade_version_chk)

            # UCSM RackMount server Model type check
            if rack_id_list:
                self.log.info("Verifying Racks_Mounts Servers model on %s ", ucsm_ip)
                if "failed" in self.ucsm_unsupported_racks_list:
                    self.ucsm_unsupported_racks_list.remove("failed")
                ucsm_rack_version_chk_result = \
                    ucsm.check_ucsm_rack_mount_server_model(rack_id_list)
                if re.search(r'APIFAILED', str(ucsm_rack_version_chk_result)):
                    self.log.info("UCSM Racks_Mount Servers Model API" \
                                  "failed for %s", ucsm_ip)
                    api_failures = ucsm_ip + "--" + UCSM_RACKS_MODEL_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif ucsm_rack_version_chk_result:
                    self.ucsm_unsupported_racks_list.append(
                        ucsm_rack_version_chk_result)

            # TODO: Temporary allow backward compatibility, need to remove once
            #       all setup move away from FlexFlash.
            ff_host_list = []
            for svr_role in self.ymlhelper.rp_get_all_roles():
                ks_file = self.ymlhelper.cobbler_get_kickstart_file(svr_role)
                if ks_file and re.search("flexflash.*\.ks", ks_file):
                    srv_list = self.ymlhelper.get_server_list(role=svr_role)
                    if len(srv_list) > 0:
                        ff_host_list.extend(srv_list)
            if len(ff_host_list) > 0:
                ff_chassis_info, ff_rack_id_list = \
                    self.populate_chassis_blade_rack_details(ff_host_list)
                # UCSM Storage Flexflash Status check
                self.log.info("Verifying Servers Flexflash status on %s ",
                              ucsm_ip)
                if "failed" in self.ucsm_ff_status_fail_list:
                    self.ucsm_ff_status_fail_list.remove("failed")
                ff_status_chk_result = ucsm.check_storage_flexflash_status(
                    ff_chassis_info, ff_rack_id_list)
                if re.search(r'APIFAILED', str(ff_status_chk_result)):
                    self.log.info("UCSM Flexflash status API failed for %s",
                                  ucsm_ip)
                    api_failures = ucsm_ip + "--" + UCSM_SERVERS_FF_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif ff_status_chk_result:
                    self.ucsm_ff_status_fail_list.append(ff_status_chk_result)

            # UCSM Service profile assignment check
            self.log.info("Verifying Servers SP assignment status on %s ", ucsm_ip)
            if "failed" in self.ucsm_sp_assignment_fail_list:
                self.ucsm_sp_assignment_fail_list.remove("failed")
            sp_assigment_result = ucsm.check_service_profile_assigment(
                ucsm_prefix, chassis_info, rack_id_list)
            if re.search(r'APIFAILED', str(sp_assigment_result)):
                self.log.info("UCSM Service Profile check API" \
                              "failed for %s", ucsm_ip)
                api_failures = ucsm_ip + "--" + UCSM_SP_ASSIGN_CHK
                self.cimc_ssh_chk_fail_list.append(api_failures)
            elif sp_assigment_result:
                self.ucsm_sp_assignment_fail_list.append(sp_assigment_result)

            # UCSM Chassis servers Storage disk check
            if chassis_info:
                self.log.info("Verifying Chassis Servers Storage disks on %s ",
                              ucsm_ip)
                if "failed" in self.ucsm_storage_failures:
                    self.ucsm_storage_failures.remove("failed")
                storage_disk_chk = ucsm.check_chassis_servers_storage_disks(
                    chassis_info)
                if re.search(r'APIFAILED', str(storage_disk_chk)):
                    self.log.info("UCSM Storage disk check API failed for %s", \
                                  ucsm_ip)
                    api_failures = ucsm_ip + "--" + UCSM_STORAGE_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif storage_disk_chk:
                    failure_report = self.consolidate_failure_msg(storage_disk_chk)
                    self.ucsm_storage_failures.append(failure_report)

            # UCSM Chassis servers Memory status
            if chassis_info:
                self.log.info("Verifying Chassis Servers Memory status on %s ",
                              ucsm_ip)
                if "failed" in self.ucsm_memory_failures:
                    self.ucsm_memory_failures.remove("failed")
                memory_chk = ucsm.check_chassis_servers_memory_status(chassis_info)
                if re.search(r'APIFAILED', str(memory_chk)):
                    self.log.info("UCSM Memory check API failed for %s", \
                                  ucsm_ip)
                    api_failures = ucsm_ip + "--" + UCSM_MEMORY_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif memory_chk:
                    failure_report = self.consolidate_failure_msg(memory_chk)
                    self.ucsm_memory_failures.append(failure_report)

            # UCSM adapter vendor and model check
            self.log.info("Verifying Chassis Servers Adapter details on %s ",
                          ucsm_ip)
            if "failed" in self.ucsm_adapter_failures:
                self.ucsm_adapter_failures.remove("failed")
            adapter_chk = ucsm.check_vic_adapter(chassis_info, rack_id_list)
            if re.search(r'APIFAILED', str(adapter_chk)):
                self.log.info("UCSM Adapter check API failed for %s", \
                              ucsm_ip)
                api_failures = ucsm_ip + "--" + UCSM_ADAPTER_CHK
                self.cimc_ssh_chk_fail_list.append(api_failures)
            elif adapter_chk:
                failure_report = self.consolidate_failure_msg(adapter_chk)
                self.ucsm_adapter_failures.append(failure_report)

            # UCSM storage Storage lun disk check
            self.log.info("Verifying Rack Servrs LUN disks Existency on %s ",
                          ucsm_ip)
            if "failed" in self.ucsm_lun_failures:
                self.ucsm_lun_failures.remove("failed")
            lun_chk = ucsm.check_rack_servers_storage_lun_disks(rack_id_list)
            if re.search(r'APIFAILED', str(lun_chk)):
                self.log.info("UCSM STORAGE LUN CHECK API failed for %s", \
                              ucsm_ip)
                api_failures = ucsm_ip + "--" + UCSM_LUN_CHK
                self.cimc_ssh_chk_fail_list.append(api_failures)
            elif lun_chk:
                failure_report = self.consolidate_failure_msg(lun_chk)
                self.ucsm_lun_failures.append(failure_report)

            # UCSM Chassis servers IOM count check
            if chassis_info:
                self.log.info("Verifying Chassis Servers IOM count on %s ",
                              ucsm_ip)
                if "failed" in self.ucsm_iom_failures:
                    self.ucsm_iom_failures.remove("failed")
                iom_chk = ucsm.check_chassis_iom_count(chassis_info)
                if re.search(r'APIFAILED', str(iom_chk)):
                    self.log.info("UCSM IOM check API failed for %s", \
                                  ucsm_ip)
                    api_failures = ucsm_ip + "--" + UCSM_IOM_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif iom_chk:
                    failure_report = self.consolidate_failure_msg(iom_chk)
                    self.ucsm_iom_failures.append(failure_report)

            # CPU and Memory check for NFV Hosts
            if chassis_info:
                self.log.info("Verifying CPU and Memory for NFV configs on %s ",
                              ucsm_ip)
                if "failed" in self.ucsm_nfv_config_failures:
                    self.ucsm_nfv_config_failures.remove("failed")
                nfv_cfg = {x: self.ymlhelper.get_nfv_configs(x)
                           for x in self.ymlhelper.
                           get_server_list(role='nfv_host')}
                nfv_hosts_dict = {x: self.ymlhelper.get_server_ucsm_info(x)
                                  for x in self.ymlhelper.
                                  get_server_list(role='nfv_host')}
                nfv_chk = ucsm.check_chassis_servers_nfv_configs(
                    nfv_cfg, nfv_hosts_dict, self.check_nfv_configs)
                if re.search(r'APIFAILED', str(nfv_chk)):
                    self.log.info("UCSM CPU/Memory check API failed for %s",
                                  ucsm_ip)
                    self.cimc_ssh_chk_fail_list.append(ucsm_ip)
                elif nfv_chk:
                    failure_report = self.consolidate_failure_msg(nfv_chk)
                    self.ucsm_nfv_config_failures.append(failure_report)

            # UCSM RackMount server MRAID check
            if rack_id_list:
                self.log.info("Verifying Racks_Mounts Servers MRAID mode on %s ",
                              ucsm_ip)
                if "failed" in self.ucsm_mraid_failures:
                    self.ucsm_mraid_failures.remove("failed")
                ucsm_mraid_chk_result = \
                    ucsm.check_rack_server_mraid_type(mraid_mode, rack_id_list)
                if re.search(r'APIFAILED', str(ucsm_mraid_chk_result)):
                    self.log.info("UCSM Racks_Mount Servers MRAID API" \
                                  "failed for %s", ucsm_ip)
                    api_failures = ucsm_ip + "--" + UCSM_MRAID_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif ucsm_mraid_chk_result:
                    failure_report = self.consolidate_failure_msg(
                        ucsm_mraid_chk_result)
                    self.ucsm_mraid_failures.append(failure_report)

        except Exception as e:
            self.log.error("Exception on %s with %s", ucsm_ip, e)
            error_desc = str(e)
            if re.search(r'Authentication failed', error_desc):
                self.log.debug("Authentication failed for %s", ucsm_ip)
                self.auth_failure_list.append(ucsm_ip)
            elif re.search(r'connection timed', error_desc.lower()):
                self.log.debug("Server not reachable %s", ucsm_ip)
                self.offline_hw_list.append(ucsm_ip)
            else:
                self.log.debug("Unknowm Errors on %s", ucsm_ip)
                #self.common_failures_list.append(ucsm_ip)

        ucsm.handle_logout()

    def validate_ucsm_user_inputs(self, ucsm_ip, ucsm_user, ucsm_pass, ucsm_prefix):
        """ validate the uscm credentials """

        if ucsm_ip is None:
            err_segment = "Missing/Invalid UCSM IP Address found:"
            self.set_validation_results(UCSM_VALIDATION, status='FAIL',
                                        err=err_segment)
        if ucsm_user is None:
            err_segment = "Missing/Invalid UCSM User found:"
            self.set_validation_results(UCSM_VALIDATION, status='FAIL',
                                        err=err_segment)
        if ucsm_pass is None:
            err_segment = "Missing/Invalid UCSM Password found:"
            self.set_validation_results(UCSM_VALIDATION, status='FAIL',
                                        err=err_segment)
        if ucsm_prefix is None:
            err_segment = "Missing/Invalid  UCSM Prefix found:"
            self.set_validation_results(UCSM_VALIDATION, status='FAIL',
                                        err=err_segment)

    def check_ucsc_hw_details(self, cimc_ip, **kwargs):
        ''' executes show version to check if CIMC is alive'''

        command = ["/usr/bin/ssh-keygen", "-H", "-R", str(cimc_ip)]
        try:
            with open(os.devnull, 'wb') as DEVNULL:
                subprocess.call(command, stdout=DEVNULL,
                                stderr=subprocess.STDOUT)
        except OSError as e:
            self.log.info("Can't Remove SSH key; Error: %s", e)
            return 0
        final_result = {}
        hw_result = {}
        cimc_uname = kwargs['curr_uname']
        cimc_password = kwargs['curr_pwd']
        validate_of_list = kwargs['validate_of']
        cisco_support = self.ymlhelper.use_cisco_vic(cimc_ip)
        intel_support = self.ymlhelper.use_intel_nic(cimc_ip)
        is_cisco_vic_intel = self.ymlhelper.is_cisco_vic_intel_sriov()
        intel_sriov_support = self.ymlhelper.create_sriov()
        host_name = self.hostname_mapping[cimc_ip]
        gpu_count = self.ymlhelper.get_gpu_count(host_name)
        roles = self.roles_map[cimc_ip]
        self.cimc_credentials[cimc_ip] = cimc_uname.strip() + \
            " : " + cimc_password.strip()
        cimc = cimcutils.CIMC(cimc_ip, cimc_uname, cimc_password, \
                              user_input_file=self.setup_file)
        if cimc is None:
            self.log.info("Can't Get CIMC object for %s", cimc_ip)
            return 0

        # NOTE: Special standalone VIC-NIC setup without any extra vNICs
        #       created, just the default vNIC ports plus Intel NICs:
        #         * control plane: vNIC eth0/eth1
        #         * data plane: first two available NIC ports
        #         * sriov: any available NIC ports leftover
        #       Basically it will mimic pure Intel deployment:
        #         * control plane: samx0/1
        #         * data plane: pet0/1
        #         * sriov: sriov[0-3]
        standalone_vic_nic = False
        if (self.ymlhelper.get_pod_type() == "NGENAHC" or \
                (cisco_support and intel_support)):
            standalone_vic_nic = True

        for validate_of in validate_of_list:
            # CIMC Firmware Version check
            if validate_of in ['firmware', 'all'] and \
               'firmware' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying Firmware Version on %s ", cimc_ip)
                cimc_fw_version = cimc.cimc_check_firmware_version(
                    intel_nic_support=self.ymlhelper.use_intel_nic(cimc_ip))

                if re.search(r'APIFAILED', str(cimc_fw_version)):
                    self.log.info("Firmware version API failed for %s", cimc_ip)
                    hw_result['FWV'] = "CIMC API Check failed"
                elif cimc_fw_version is False:
                    self.log.info("Incorrect CIMC FW Version %s", cimc_ip)
                    hw_result['FWV'] = "CIMC firmware version check failed"
                else:
                    hw_result['FWV'] = "PASS"

            # LOM ports check
            if validate_of in ['lom', 'all'] and \
               'lom' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying LOM Ports Status on  %s ", cimc_ip)
                lom_state = cimc.cimc_check_lom_ports_status()
                if re.search(r'APIFAILED', str(lom_state)):
                    self.log.info("LOM port status API failed for %s", cimc_ip)
                    hw_result['LOM'] = "CIMC API Check failed"
                if not self.target_ospd:
                    if lom_state is False:
                        self.log.info("LOM Port is not disabled on  %s", cimc_ip)
                        hw_result['LOM'] = "LOM ports status check failed"
                    else:
                        hw_result['LOM'] = "PASS"
                else:
                    if lom_state is False:
                        hw_result['LOM'] = "PASS"
                    else:
                        self.log.info("LOM Port is enabled on  %s", cimc_ip)
                        hw_result['LOM'] = "LOM ports status check failed"

            # TODO: Temporary allow backward compatibility, need to remove once
            #       all setup move away from FlexFlash.
            ks_file = self.ymlhelper.cobbler_get_kickstart_file(roles[0])
            svr_uses_flexflash = bool(re.search("flexflash.*\.ks", ks_file))

            # HBA status check
            if validate_of in ['hba', 'all'] and \
               'hba' not in constants.SKIP_VALIDATION_FEATURES:

                self.log.info("Verifying HBA Slot status on %s ", cimc_ip)
                hba_status = cimc.cimc_check_pcie_hba_slot_status(
                    enabled=(not svr_uses_flexflash))
                hw_result['HBA'] = hba_status

            # Physical drive check
            if (not svr_uses_flexflash and \
                    validate_of in ['physical_drives', 'all'] and \
                    'physical_drives' not in
                    constants.SKIP_VALIDATION_FEATURES):
                self.log.info("Verifying physical drive(s) status on %s",
                              cimc_ip)
                host_name = self.hostname_mapping[cimc_ip]
                pd_kwargs = {
                    "root_drive_controller": "SAS",
                    "num_root_drive": self.ymlhelper.get_num_root_drive(
                        host_name),
                    "root_drive_type": self.ymlhelper.get_root_drive_type(
                        host_name),
                    "root_drive_raid_level": \
                        self.ymlhelper.get_root_drive_raid_level(host_name),
                    "root_drive_raid_spare": \
                        self.ymlhelper.get_root_drive_raid_spare(host_name),
                    "roles": roles}
                if "block_storage" in roles:
                    pd_kwargs.update({
                        "num_journal_drive": constants.MIN_NUM_JOURNAL_DRIVE,
                        "num_osd_drive": constants.MIN_NUM_OSD_DRIVE})

                    ceph_type = self.ymlhelper.get_ceph_cluster_info(host_name)
                    if ceph_type != 'UNDEFINED':
                        pd_kwargs.update({
                            "osd_drive_type": ceph_type})

                    if (len(roles) == 1 and \
                            cimc.cimc_check_chassis_type() == "M4"):
                        pd_kwargs["root_drive_controller"] = "PCH"
                hw_result['PHYSICAL-DRIVES'] = cimc.cimc_check_physical_drives(
                    **pd_kwargs)

            if svr_uses_flexflash:
                # SLOT-HBA Physical drive check
                if validate_of in ['physical_drives', 'all'] and \
                   'physical_drives' not in constants.SKIP_VALIDATION_FEATURES:
                    self.log.info("Verifying HBA Controller Physical drive(s) " \
                                  "status on %s ", cimc_ip)
                    pd_status = cimc.cimc_check_hba_controller_info(roles)
                    hw_result['PHYSICAL-DRIVES'] = pd_status

                # Flex flash Physical drive check
                if validate_of in ['flexflash', 'all'] and \
                   'flexflash' not in constants.SKIP_VALIDATION_FEATURES:
                    self.log.info("Verifying Flexflash Card(s) status on %s",
                                  cimc_ip)
                    ff_pd_status = cimc.cimc_check_flex_flash_info()
                    if re.search(r'APIFAILED', str(ff_pd_status)):
                        self.log.info("Flexflash API failed for %s", cimc_ip)
                        hw_result['FF-PD'] = "CIMC API check failed"
                    elif ff_pd_status is False:
                        self.log.info("Flexflash card(s) are not in mirror mode" \
                                      "on %s", cimc_ip)
                        hw_result['FF-PD'] = ("Flexflash card(s) are not in "
                                              "mirror mode")
                    elif re.search(r'Warning', str(ff_pd_status)):
                        hw_result['FF-PD'] = ff_pd_status
                    else:
                        hw_result['FF-PD'] = "PASS"

            # PCIe Adapter slot/MLOM check
            if validate_of in ['pcie_slot', 'all'] and \
               'pcie_slot' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying PCIe Slots/MLOM status on %s ", cimc_ip)
                vic_slot = self.vic_slot_mapping[cimc_ip]
                pcie_slot_status = cimc.cimc_check_pcie_vic_slot_status(
                    vic_slot, intel_support, is_cisco_vic_intel)
                hw_result['PCA'] = pcie_slot_status

            # CPU and Memory check for NFV Hosts
            if validate_of in ['nfv_config', 'all'] and \
               cimc_ip in self.nfv_hosts and \
               'nfv_config' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying CPU and Memory for NFV configs on %s ", \
                              cimc_ip)
                try:
                    cpu_mem = cimc.cimc_get_cpu_memory_info()
                    server = self.hostname_mapping[cimc_ip]
                    nfv_cfg = self.ymlhelper.get_nfv_configs(server)
                    if nfv_cfg:
                        hw_result['NFV'] = self.check_nfv_configs(nfv_cfg, cpu_mem)
                except Exception:
                    self.log.info("computeRackUnit API failed for %s", cimc_ip)
                    hw_result['NFV'] = "CIMC API Check failed"

            #  Server Power status check
            if validate_of in ['power', 'all'] and \
               'power' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying Server Power status on %s ", cimc_ip)
                powered_on = cimc.check_server_power_status()
                if re.search(r'APIFAILED', str(powered_on)):
                    self.log.info("Power status API failed for %s", cimc_ip)
                    hw_result['SPS'] = "CIMC API Check failed"
                elif powered_on is False:
                    self.log.info("Server powered down %s", cimc_ip)
                    hw_result['SPS'] = "Server powered down"
                else:
                    hw_result['SPS'] = "PASS"

            # TODO: Need to restructure/clean up network validation code to
            #       handle different hardware combination.  For now, if both
            #       CISCO_VIC_SUPPORT and INTEL_NIC_SUPPORT flags are True,
            #       only run the following check and skip the remaining.
            if standalone_vic_nic:
                if validate_of not in ["vic_adapter", "nw_adapter", "all"]:
                    continue
                combine_cpdp = self.ymlhelper.get_combine_cpdp(
                    self.hostname_mapping[cimc_ip])
                if not cimc.get_vic_and_nic_combo_mac_addresses(
                        sriov=intel_sriov_support, combine_cpdp=combine_cpdp):
                    err_msg = "FAIL: Error checking for Cisco VIC or Intel NIC"
                    self.log.error("[%s] %s", cimc_ip, err_msg)
                    if validate_of in ["vic_adapter", "all"]:
                        hw_result["APTER_CHK"] = err_msg
                    if validate_of in ["nw_adapter", "all"]:
                        hw_result["INTEL_NIC_CHK"] = err_msg
                    continue
                macs = cimc.cimc_baremetal_info["intel_macs"]["macs"]
                # Check for Cisco VIC
                if validate_of in ["vic_adapter", "all"]:
                    if len(macs["control"]) < 2:
                        err_msg = ("FAIL: No Cisco VIC adapter card found for "
                                   "control plane ports")
                        self.log.error("[%s] %s", cimc_ip, err_msg)
                        hw_result["ADAPTER_CHK"] = err_msg
                        continue
                    hw_result["ADAPTER_CHK"] = "PASS"
                # Check for Intel NIC
                if validate_of in ["nw_adapter", "all"]:
                    if "block_storage" not in roles or len(roles) != 1:
                        if len(macs["data"]) < 2 and not combine_cpdp:
                            err_msg = ("FAIL: Not enough Intel NIC port found "
                                       "for data plane ports")
                            self.log.error("[%s] %s", cimc_ip, err_msg)
                            hw_result["INTEL_NIC_CHK"] = err_msg
                            continue
                        if "compute" in roles and intel_sriov_support:
                            nsriov = self.ymlhelper.get_intel_sriov_phys_ports(
                                self.hostname_mapping[cimc_ip])
                            if len(macs["sriov"]) < nsriov:
                                err_msg = ("FAIL: Not enought Intel NIC port "
                                           "found for sriov ports")
                                self.log.error("[%s] %s", cimc_ip, err_msg)
                                hw_result["INTEL_NIC_CHK"] = err_msg
                                continue
                    hw_result["INTEL_NIC_CHK"] = "PASS"
                self.log.debug("[%s] VIC/NIC adapter(s) check pass, found all "
                               "necessary ports")
                continue

            # Default CISCO Vnic PXE boot status check
            if not intel_support:
                if validate_of == 'vnic_pxe_boot' or \
                   (validate_of == 'all' and 'SPS' in hw_result and \
                        hw_result['SPS'] is "PASS") and \
                   'vnic_pxe_boot' not in constants.SKIP_VALIDATION_FEATURES:
                    self.log.info("Verifying Default vNICs PXE boot " \
                                  "status on %s ", cimc_ip)
                    vnic_pxe_status = cimc.cimc_check_default_vnic_pxe_boot_status()
                    if re.search(r'APIFAILED', str(vnic_pxe_status)):
                        self.log.info(" Default Vnic PXE boot API failed" + \
                                      "for %s", cimc_ip)
                        hw_result['VNIC'] = "CIMC API check failed"
                    elif not self.target_ospd:
                        if vnic_pxe_status is False:
                            self.log.info("Cisco Vnic PXE boot status is not " \
                                          "disabled on %s", cimc_ip)
                            hw_result['VNIC'] = "Cisco VNIC PXE boot status " \
                                "check failed"
                        else:
                            hw_result['VNIC'] = "PASS"
                    else:
                        if vnic_pxe_status is False:
                            hw_result['VNIC'] = "PASS"
                        else:
                            self.log.info("Cisco Vnic PXE boot status is " \
                                          "enabled on %s", cimc_ip)
                            hw_result['VNIC'] = "Cisco VNIC PXE boot status " \
                                "check failed"

            # Adapter Vendor check
            if not intel_support:
                if validate_of == 'vic_adapter' or \
                   (validate_of == 'all' and 'SPS' in hw_result and \
                        hw_result['SPS'] is "PASS") and \
                   'vic_adapter' not in constants.SKIP_VALIDATION_FEATURES:
                    self.log.info("Verifying VIC Adapter Card Vendor on %s ", \
                                  cimc_ip)
                    vic_slot = self.vic_slot_mapping[cimc_ip]
                    vic_vendor_chk = cimc.cimc_check_vic_adapter_card(vic_slot)
                    hw_result['ADAPTER_CHK'] = vic_vendor_chk

            # Intel NIC Check
            skip_intel_check = 0
            if intel_support or (is_cisco_vic_intel and 'compute' in roles):
                num_intel_sriov_phys_ports = \
                    self.ymlhelper.get_intel_sriov_phys_ports(
                        self.hostname_mapping[cimc_ip])
                if validate_of in ['nw_adapter', 'all'] and \
                   'nw_adapter' not in constants.SKIP_VALIDATION_FEATURES:
                    self.log.info("Verifying Intel Network Adapter details on %s ",
                                  cimc_ip)
                    reqd_intel_card_type = None
                    if is_cisco_vic_intel and 'compute' in roles:
                        reqd_intel_card_type = self.ymlhelper.get_intel_card_type(
                            server=self.hostname_mapping[cimc_ip])
                    min_num_reqd_intel_card = None
                    if self.ymlhelper.use_nic_redundancy(
                            server=self.hostname_mapping[cimc_ip]):
                        min_num_reqd_intel_card = 2
                    if 'compute' not in roles:
                        intel_sriov_support = False
                        # TODO: Hack to support thirdparties where CP and DP
                        #       interfaces are combined into one.  The number
                        #       of NICs will be less, so temporary change the
                        #       values.
                        if config_parser.PlatformDiscovery(
                                self.setup_file).is_thirdparties(cimc_ip):
                            is_cisco_vic_intel = False
                            min_num_reqd_intel_card = 0
                            num_intel_sriov_phys_ports = 0
                    hw_status, nw_adapter_chk = cimc.cimc_check_nw_adapter_details(
                        intel_sriov_support, is_cisco_vic_intel,
                        reqd_intel_card_type, min_num_reqd_intel_card,
                        num_intel_sriov_phys_ports,
                        server=self.hostname_mapping[cimc_ip],
                        trusted_vf=self.ymlhelper.check_trusted_vf_mode(
                            self.hostname_mapping[cimc_ip]),
                        combine_cpdp=self.ymlhelper.get_combine_cpdp(
                            self.hostname_mapping[cimc_ip]))
                    hw_result['INTEL_NIC_CHK'] = nw_adapter_chk
                    if not hw_status:
                        skip_intel_check = 1
                    elif hw_status and re.match(r'Skipping', str(nw_adapter_chk)):
                        skip_intel_check = 1

            # Intel Actual Boot Order Check
            if intel_support and not skip_intel_check:
                if validate_of in ['intel_boot_order', 'all'] and \
                   'intel_boot_order' not in constants.SKIP_VALIDATION_FEATURES:
                    self.log.info("Verifying Intel Actual Boot Order on %s ", \
                                  cimc_ip)
                    nlr_enabled = self.ymlhelper.use_nic_redundancy(\
                        server=self.hostname_mapping[cimc_ip])
                    boot_order_chk = cimc.cimc_boot_order_check(\
                        cimc.cimc_check_chassis_type(),
                        nlr_enabled)
                    hw_result['INTEL_BOOT_ORDER_CHK'] = boot_order_chk

            # GPU card check
            if 'compute' in roles:
                if validate_of in ['gpu_card', 'all'] and \
                   'gpu_card' not in constants.SKIP_VALIDATION_FEATURES:
                    self.log.info("Verifying Physical GPU Card details on %s ", \
                                  cimc_ip)
                    gpu_chk = cimc.cimc_check_gpu_card(gpu_count)
                    hw_result['GPU_CHK'] = gpu_chk

            # Foreign config check
            if validate_of in ['foreign_config'] and \
               'foreign_config' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying Foreign config status on %s ", cimc_ip)
                f_cfg_status = cimc.cimc_check_foreign_config()
                if re.search(r'APIFAILED', str(f_cfg_status)):
                    self.log.info("Foreign config check API failed for %s", cimc_ip)
                    hw_result['F_CONFIG'] = "CIMC API Check failed"
                if f_cfg_status is False:
                    self.log.info("Disks with foreign config found on  %s", cimc_ip)
                    hw_result['F_CONFIG'] = "Forign config status check failed"
                else:
                    hw_result['F_CONFIG'] = "PASS"

            podtype = self.ymlhelper.get_pod_type()
            if podtype == 'CVIMMONHA':
                if validate_of in ['argus_nw_adapter', 'all'] and \
                   'argus_nw_adapter' not in constants.SKIP_VALIDATION_FEATURES:
                    self.log.info("Verifying Intel Network Adapter details on %s ",
                                  cimc_ip)
                    nw_adapter_chk = cimc.cimc_check_argus_nw_adapter_details()
                    hw_result['ARGUS_NIC_CHK'] = nw_adapter_chk

                if validate_of in ['argus_disks', all] and \
                   'argus_disks' not in constants.SKIP_VALIDATION_FEATURES:
                    self.log.info("Verifying Number of Disks on %s ",
                                  cimc_ip)
                    disk_chk = cimc.argus_disks_check()
                    hw_result['ARGUS_DISK_CHK'] = disk_chk.get('status', 'FAIL')
                    self.argus_disk_uniformity.append(disk_chk.get('storage_type'))

                if validate_of in ['redfish_config'] and \
                    'redfish_config' not in constants.SKIP_VALIDATION_FEATURES:
                    self.log.info("Verifying Redfish Config on %s ", \
                                  cimc_ip)
                    redfish_check = cimc.redfish_config_check()
                    if redfish_check:
                        hw_result['REDFISH_CONFIG_CHK'] = redfish_check

                if validate_of in ['intel_boot_config' or 'all'] and \
                   'intel_boot_config' not in constants.SKIP_VALIDATION_FEATURES:
                    self.log.info("Verifying Intel Actual Boot Config on %s ", \
                                  cimc_ip)
                    boot_order_chk = cimc.cimc_boot_config_check()
                    hw_result['INTEL_BOOT_CONFIG_CHK'] = boot_order_chk


        cimc.cimc_logout()
        self.final_result[cimc_ip] = hw_result
        return True

    def check_ucsc_ipmi_hw_details(self, cimc_ip, **kwargs):
        ''' executes show version to check if CIMC is alive'''

        command = ["/usr/bin/ssh-keygen", "-H", "-R", str(cimc_ip)]
        try:
            with open(os.devnull, 'wb') as DEVNULL:
                subprocess.call(command, stdout=DEVNULL,
                                stderr=subprocess.STDOUT)
        except OSError as e:
            self.log.info("Can't Remove SSH key; Error: %s", e)
            return 0

        final_result = {}
        hw_result = {}
        cimc_uname = kwargs['curr_uname']
        cimc_password = kwargs['curr_pwd']
        validate_of_list = kwargs['validate_of']
        self.cimc_credentials[cimc_ip] = cimc_uname.strip() + \
            " : " + cimc_password.strip()

        server_name = self.ironic_yml_helper.get_server_name_from_ipmi_ip(cimc_ip)
        adapter_type = self.ironic_yml_helper.get_adapter_type(server_name)
        ipmi_key = self.ironic_yml_helper.get_ipmi_encryption_key(server_name)

        cimc = cimcutils.CIMC(cimc_ip, cimc_uname, cimc_password,
                              user_input_file=self.ironic_inv_file, ipmi_node=True)

        if cimc is None:
            self.log.info("Can't Get CIMC object for %s", cimc_ip)
            return 0

        fw_version = cimc.cimc_get_version()
        if fw_version is None:
            err_segment = cimc_ip + "--" + " CIMC API Check failed." + \
                " Check for validity of CIMC IP, Username" + \
                " and/or Password or number of active" + \
                "CIMC session > 4 on "
            self.cimc_ssh_chk_fail_list.append(err_segment)
            return 0

        for validate_of in validate_of_list:
            #  Server Power status check
            if validate_of in ['power', 'all'] and \
               'power' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying Server Power status on %s ", cimc_ip)
                powered_on = cimc.check_server_power_status()
                if re.search(r'APIFAILED', str(powered_on)):
                    self.log.info("Power status API failed for %s", cimc_ip)
                    hw_result['SPS'] = "CIMC API Check failed"
                elif powered_on is False:
                    self.log.info("Server powered down %s", cimc_ip)
                    hw_result['SPS'] = "Server powered down"
                else:
                    hw_result['SPS'] = "PASS"

            # # Default CISCO Vnic PXE boot status check
            if validate_of == 'vnic_pxe_boot' or \
               (validate_of == 'all' and 'SPS' in hw_result and \
                    hw_result['SPS'] is "PASS") and adapter_type != "NIC" and \
               'vnic_pxe_boot' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying Default vNICs PXE boot " \
                              "status on %s ", cimc_ip)
                vnic_pxe_status = cimc.check_ipmi_default_vnic_pxe_boot_status()
                if re.search(r'APIFAILED', str(vnic_pxe_status)):
                    self.log.info(" Default Vnic PXE boot API failed " + \
                                  "for %s", cimc_ip)
                    hw_result['VNIC'] = "CIMC API check failed"
                elif vnic_pxe_status:
                    hw_result['VNIC'] = "PASS"
                else:

                    self.log.info("Cisco Vnic PXE boot status is " \
                                  "disabled on %s", cimc_ip)
                    hw_result['VNIC'] = vnic_pxe_status

            # # IPMI status check
            if validate_of in ['ipmi_status', 'all'] and \
               'ipmi' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying IPMI status on %s ", cimc_ip)
                ipmi_status = cimc.check_ipmi_status()
                if re.search(r'APIFAILED', str(ipmi_status)):
                    self.log.info("IPMI status check API failed \
                                              for %s", cimc_ip)
                    hw_result['IPMI_STATUS'] = "CIMC API check failed"
                elif ipmi_status:
                    hw_result['IPMI_STATUS'] = "PASS"
                else:
                    self.log.info("IPMI_STATUS status is diaabled on %s", cimc_ip)
                    hw_result['IPMI_STATUS'] = "IPMI status check failed"

            # # IPMI Encryption Key
            if validate_of in ['ipmi_key', 'all'] and \
               'ipmi' not in constants.SKIP_VALIDATION_FEATURES:
                #TODO tenary
                if not ipmi_key:
                    ipmi_key = IPMI_DEFAULT_EN_KEY
                self.log.info("Verifying IPMI Encryption key on %s ", cimc_ip)
                hw_result['IPMI_KEY'] = cimc.check_ipmi_encryption_key(ipmi_key)

            # Physical drive check
            if validate_of in ['physical_drives', 'all'] and \
                    'physical_drives' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying physical drive(s) status on %s",
                              cimc_ip)
                hw_result['PHYSICAL-DRIVES'] = cimc.check_ipmi_pdrives_health()


            # # Default CISCO Vnic PXE boot status check
            if validate_of == 'vnic_vlan_mode' or \
               (validate_of == 'all' and 'SPS' in hw_result and \
                    hw_result['SPS'] is "PASS") and adapter_type != "NIC" and  \
               'vnic_vlan_mode' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying Default vNICs VLAN mode on %s ", cimc_ip)
                vnic_pxe_status = cimc.cimc_check_default_vnic_vlan_mode()
                if re.search(r'APIFAILED', str(vnic_pxe_status)):
                    self.log.info("Default Vnic VLAN Mode failed " + \
                                  "for %s", cimc_ip)
                    hw_result['VNIC_VLAN_MODE'] = "CIMC API check failed"
                elif vnic_pxe_status:
                    hw_result['VNIC_VLAN_MODE'] = "PASS"
                else:
                    self.log.info("VNIC VLAN Mode not in " \
                                  "TRUNK  on %s", cimc_ip)
                    hw_result['VNIC_VLAN_MODE'] = "Cisco VNIC VLAN Mode " \
                        "check failed"

            # # Configure Boot order check
            if validate_of in ['pxe_boot_order', 'all'] and \
                    'pxe_boot_order' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying PXE boot order on %s ", cimc_ip)
                is_intel_nic = True if adapter_type == "NIC" else False
                hw_result['IPMI_BOOT_ORDER'] = cimc.ipmi_boot_order_check(
                    is_intel_nic)

            # LLDP status check
            if validate_of == 'lldp_status' or \
                (validate_of == 'all' and 'SPS' in hw_result and \
                    hw_result['SPS'] is "PASS") and adapter_type != "NIC" \
               and 'lldp_status' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying LLDP status on %s ", cimc_ip)
                lldp_status = cimc.check_lldp_status()
                if re.search(r'APIFAILED', str(lldp_status)):
                    self.log.info("LLDP status check API failed \
                                              for %s", cimc_ip)
                    hw_result['LLDP_STATUS'] = "CIMC API check failed"
                elif lldp_status:
                    hw_result['LLDP_STATUS'] = "PASS"
                else:
                    self.log.info("LLDP_STATUS status is Enabled on %s", cimc_ip)
                    hw_result['LLDP_STATUS'] = "LLDP status check failed"

            if validate_of in ['boot_config', 'all'] and \
                    'boot_config' not in constants.SKIP_VALIDATION_FEATURES:
                self.log.info("Verifying Actual Boot Config on %s ", \
                              cimc_ip)
                boot_order_chk = cimc.cimc_boot_config_check(ironic=True)
                hw_result['INTEL_BOOT_CONFIG_CHK'] = boot_order_chk

        cimc.cimc_logout()
        self.final_result[cimc_ip] = hw_result
        return True


    def report_invalid_input(self):
        ''' reports input is invalid'''

        chk_config = "Input Validation Check"
        err_segment = "Unknown Error found."
        self.set_validation_results(chk_config, status='FAIL',
                                    err=err_segment + ".Please make sure that" + \
                                    "'setup_data.yaml' file to be valid.")
        return

    def validate_hw_details(self, use_case_list="all", host_list=None,
                            ironic_validation=False):
        ''' Validating hardware details. By default this function \
         validates all the servers mentioned in setup_data.yaml file. \
         Also had an option to validate only specific servers as well '''
        try:
            if use_case_list == "all":
                use_case_list = ['all']

            self.set_oper_stage("Check Validity of CIMC info")
            hw_error = self.hw_validation_check(use_case_list, host_list,
                                                ironic_validation)

        except (KeyError, TypeError) as e:
            print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
            print e
            print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
            chk_config = "Input Validation Check"
            self.set_oper_stage(chk_config)
            self.report_invalid_input()

        self.display_validation_results()
        time.sleep(1)

        ''' Returning whole consolidated report as dictionary to the
           Software Validation module to construct JSON output '''
        hw_validation_result = self.get_hw_validation_report()

        return hw_validation_result

    def resolve_hw_failures(self, features="all", force_yes=False,
                            hosts=None):
        ''' Validating hardware details. By default this function \
         validates all the servers mentioned in setup_data.yaml file. \
         Also had an option to validate only specific servers as well '''

        hw_type = self.get_hardware_type()
        if re.match(r'UCSM', hw_type):
            err_str = "Resolve Hardware Failures not supported for B-series."
            self.set_validation_results("Un-Supported Feature", status='FAIL',
                                        err=err_str)
            self.display_validation_results()
            return

        if not self.ironic_validation and features in IRONIC_VALIDATIONS:
            err_str = "Resolve " + features + " applicable for Ironic nodes only."
            self.set_validation_results(USER_ERROR, status='FAIL', err=err_str)
            self.display_validation_results()
            return

        options = {
            'lom': self.resolve_lom_port_failures,
            'hba': self.resolve_hba_port_failures,
            'flexflash': self.resolve_flexflash_failures,
            'all': self.resolve_all_validation_failures,
            'power': self.resolve_power_failures,
            'pcie_slot': self.resolve_pcie_adapter_slots_failures,
            'vnic_pxe_boot': self.resolve_vnic_pxe_boot_failures,
            'vnic_vlan_mode': self.resolve_vnic_vlan_mode_failures,
            'ipmi_key': self.resolve_ipmi_en_key_failures,
            'ipmi_status': self.resolve_ipmi_status_failures,
            'pxe_boot_order': self.resolve_pxe_boot_order_failures,
            'lldp_status': self.resolve_lldp_failures,
            'boot_config': self.resolve_boot_config_failures,
            'foreign_config': self.resolve_foreign_config_failures
        }
        use_cases = [x for x in features.split(',')]
        if len(use_cases) > 1:
            options['all'](force_yes, hosts, use_cases)
        else:
            for use_case in use_cases:
                if re.search(r'lom', use_case):
                    options['lom'](force_yes, hosts)
                elif re.search(r'hba', use_case):
                    options['hba'](force_yes, hosts)
                elif re.search(r'flexflash', use_case):
                    options['flexflash'](force_yes, hosts)
                elif re.search(r'pcie_slot', use_case):
                    options['pcie_slot'](force_yes, hosts)
                elif re.search(r'power', use_case):
                    options['power'](force_yes, hosts)
                elif re.search(r'vnic_pxe_boot', use_case):
                    options['vnic_pxe_boot'](force_yes, hosts)
                elif re.search(r'vnic_vlan_mode', use_case):
                    options['vnic_vlan_mode'](force_yes, hosts)
                elif re.search(r'\bipmi_status\b', use_case):
                    options['ipmi_status'](force_yes, hosts)
                elif re.search(r'\bipmi_key\b', use_case):
                    options['ipmi_key'](force_yes, hosts)
                elif re.search(r'pxe_boot_order', use_case):
                    options['pxe_boot_order'](force_yes, hosts)
                elif re.search(r'lldp_status', use_case):
                    options['lldp_status'](force_yes, hosts)
                elif re.search(r'boot_config', use_case):
                    options['boot_config'](force_yes, hosts)
                elif re.search(r'foreign_config', use_case):
                    options['foreign_config'](force_yes, hosts)
                elif re.search(r'all', use_case):
                    options['all'](force_yes, hosts, use_cases)

        self.display_validation_results(True)
        time.sleep(1)
        ''' Returning whole consolidated report as dictionary to the
           Software Validation module to construct JSON output '''
        resolve_report = self.get_resolve_failures_report()

        return resolve_report

    def enable_user_option_to_proceed(self, msg):
        """ Enable the prompt for user option """
        msg = "Do you want to resolve " + msg + " validation failures [y/N] "
        usr_option = raw_input(msg)
        if usr_option.lower() == 'y' or usr_option.lower() == 'yes':
            return True
        elif usr_option.lower() == 'n' or usr_option.lower() == 'no':
            return False

        return False

    def resolve_lom_port_failures(self, force_yes, input_host_list,
                                  validate_again=True):
        """ Resolve OptionROM LOM port(s) validation failures """

        proceed = True

        if not force_yes:
            proceed = self.enable_user_option_to_proceed("LOM Port(s)")
        if proceed:
            try:
                threadlist = []
                kwargs = {}
                usecase_list = ['lom']
                if validate_again:
                    """ Pre and Post validating only LOM port(s) status instead of
                         all usecases while resolving LOM port(s)failures """
                    hosts_list = self.get_host_lists(input_host_list)

                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if "failed" not in self.cimc_lom_chk_fail_list \
                        and not len(self.cimc_lom_chk_fail_list):
                    hosts = self.get_host_names(input_host_list)
                    self.log.info("LOM Port(s) already Disabled on all server(s)")
                    err_segment = "WARNING : LOM Port(s) already Disabled on " + \
                                  "server(s)" + str(hosts)
                    self.set_validation_results(RESOLVE_LOM_INTF, status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_LOM_INTF] = "PASS" + \
                        "~" + err_segment
                    return False
                kwargs['usecase'] = 'lom'
                if "failed" not in self.cimc_lom_chk_fail_list \
                        and len(self.cimc_lom_chk_fail_list):
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for cimc_ip in self.cimc_lom_chk_fail_list:
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()
                if validate_again:
                    host_list = []
                    if "failed" not in self.cimc_lom_chk_fail_list:
                        for cimc in self.cimc_lom_chk_fail_list:
                            host_name = self.hostname_mapping[cimc]
                            host_list.append(host_name)
                        self.cimc_lom_chk_fail_list = []
                        self.validation_results = []
                        self.unsupported_hw_list = []
                        self.log.info("Validating again after resolving the" + \
                                      "failures")
                        self.validate_hw_details(usecase_list, host_list)
                self.set_validation_results(RESOLVE_LOM_INTF, status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_LOM_INTF] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_LOM_INTF, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_LOM_INTF] = "FAIL" + \
                    "~" + err_seg
                return False
            return True

    def resolve_foreign_config_failures(self, force_yes, input_host_list,
                                  validate_again=True):
        """ Resolve Foreign Config validation failures """

        proceed = True
        if not force_yes:
            proceed = self.enable_user_option_to_proceed("Foreign Config")
        if proceed:
            try:
                threadlist = []
                kwargs = {}
                usecase_list = ['foreign_config']
                if validate_again:
                    """ Pre and Post validating only foreign config status instead of
                         all usecases while resolving Foreign config failures """
                    hosts_list = self.get_host_lists(input_host_list)

                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if "failed" not in self.cimc_foreign_chk_fail_list \
                        and not len(self.cimc_foreign_chk_fail_list):
                    hosts = self.get_host_names(input_host_list)
                    self.log.info("No disks with foreign config found")
                    err_segment = "WARNING : No disks with foreign config " + \
                                  "found on server(s)" + str(hosts)
                    self.set_validation_results(RESOLVE_FOREIGN_CONIG, status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_FOREIGN_CONIG] = "PASS" + \
                        "~" + err_segment
                    return False
                kwargs['usecase'] = 'foreign_config'
                if "failed" not in self.cimc_foreign_chk_fail_list \
                        and len(self.cimc_foreign_chk_fail_list):
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for cimc_ip in self.cimc_foreign_chk_fail_list:
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()
                if validate_again:
                    host_list = []
                    if "failed" not in self.cimc_foreign_chk_fail_list:
                        for cimc in self.cimc_foreign_chk_fail_list:
                            host_name = self.hostname_mapping[cimc]
                            host_list.append(host_name)
                        self.cimc_foreign_chk_fail_list = []
                        self.validation_results = []
                        self.unsupported_hw_list = []
                        self.log.info("Validating again after resolving the" + \
                                      "failures")
                        self.validate_hw_details(usecase_list, host_list)
                self.set_validation_results(RESOLVE_FOREIGN_CONIG, status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_FOREIGN_CONIG] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_FOREIGN_CONIG, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_FOREIGN_CONIG] = "FAIL" + \
                    "~" + err_seg
                return False
            return True

    def perform_task(self, cimc_ip, **kwargs):
        """
        Function to resolve hw_validation failures as per
        the requirements
        """
        cimc = ""
        try:
            use_case = kwargs['usecase']
            intel_nic_support = self.ymlhelper.use_intel_nic(cimc_ip)
            is_cisco_vic_and_intel = self.ymlhelper.is_cisco_vic_intel_sriov()
            credentials = self.cimc_credentials[cimc_ip]
            creds = credentials.split(" : ")
            ipmi_key = kwargs.get('ipmi_key')
            if self.ironic_validation:
                cimc = cimcutils.CIMC(cimc_ip, creds[0].strip(), creds[1].strip(), \
                                  user_input_file=self.ironic_inv_file,
                                  ipmi_node=self.ironic_validation)
            else:
                cimc = cimcutils.CIMC(cimc_ip, creds[0].strip(), creds[1].strip(), \
                                  user_input_file=self.setup_file)
            if use_case == 'lom':
                self.log.info("Resolving LOM Failures on  %s ", cimc_ip)
                if self.target_ospd:
                    cimc.resolve_lom_ports_validation_failures(enable_lom=True)
                else:
                    cimc.resolve_lom_ports_validation_failures()
                self.log.info("Resolved LOM Failures on %s", cimc_ip)
            if use_case == 'hba':
                err_msg = kwargs['err_msg']
                self.log.info("Resolving HBA Failures on  %s", cimc_ip)
                if re.search("'Enable' PCIe HBA OptionROM on", err_msg):
                    cimc.resolve_hba_slot_validation_failures(enable=True)
                else:
                    cimc.resolve_hba_slot_validation_failures(enable=False)
                self.log.info("Resolved HBA Failures on  %s", cimc_ip)
            if use_case == 'power':
                self.log.info("Resolving Power Failures on  %s ", cimc_ip)
                cimc.resolve_power_validation_failures()
                self.log.info("Resolved Power Failures on %s", cimc_ip)
            if use_case == 'pcie_slot':
                vic_slot = kwargs['vic_slot']
                self.log.info("Resolving PCIe Adapter Slot Failures on  %s ",
                              cimc_ip)
                cimc.resolve_pcie_vic_slot_validation_failures(vic_slot, \
                                                             intel_nic_support, \
                                                             is_cisco_vic_and_intel)
                self.log.info("Resolved PCIe Adapter Slot Failures on %s", cimc_ip)
            if use_case == 'vnic':
                self.log.info("Resolving VNIC PXE Boot Failures on  %s", cimc_ip)
                if self.target_ospd or self.ironic_validation:
                    cimc.resolve_vnic_pxeboot_validation_failures(enable_pxe=True,
                                                                  ironic=True)
                else:
                    cimc.resolve_vnic_pxeboot_validation_failures()

                self.log.info("Resolved VNIC PXE Boot Failures on  %s", cimc_ip)
            if use_case == 'flexflash':
                self.log.info("Resolving Flexflash validation failures on %s",
                              cimc_ip)
                cimc.resolve_flex_flash_validation_failures()
                self.log.info("Resolved Flexflash validation failures on %s",
                              cimc_ip)

            if use_case == 'vnic_vlan_mode':
                self.log.info("Resolving vNIC VLAN Mode Failures on  %s", cimc_ip)
                cimc.resolve_vnic_vlan_mode_validation_failures(mode='TRUNK')
                self.log.info("Resolved vNIC VLAN Mode Failures on  %s", cimc_ip)

            if use_case == 'ipmi_status':
                self.log.info("Resolving IPMI status Failures on  %s", cimc_ip)
                cimc.resolve_ipmi_status_validation_failures()
                self.log.info("Resolved IPMI status Failures on  %s", cimc_ip)

            if use_case == 'ipmi_key':
                self.log.info("Resolving IPMI Encryption Key Failures on  %s",
                              cimc_ip)
                cimc.resolve_ipmi_en_key_validation_failures(ipmi_key)
                self.log.info("Resolved IPMI Encryption Key Failures on  %s",
                              cimc_ip)
            if use_case == 'pxe_boot_order':
                self.log.info("Resolving PXE Boot Order Failures on  %s", cimc_ip)
                host_name = self.hostname_mapping[cimc_ip]
                adapter_type = self.ironic_yml_helper.get_adapter_type(host_name)
                intel_nic = True if adapter_type == "NIC" else False
                cimc.resolve_pxe_boot_order_validation_failures(intel_nic)
                self.log.info("Resolved PXE Boot Order Failures on  %s", cimc_ip)

            if use_case == 'lldp_status':
                self.log.info("Resolving LLDP Status Failures on  %s", cimc_ip)
                cimc.disable_lldp(cimc_ip)
                self.log.info("Resolved LLDP Status Failures on  %s", cimc_ip)

            if use_case == 'boot_config':
                self.log.info("Resolving Boot Config Failures on  %s", cimc_ip)
                cimc.cimc_set_boot_mode("Legacy")
                self.log.info("Resolved Boot Config Failures on  %s", cimc_ip)

            if use_case == 'foreign_config':
                self.log.info("Resolving Foreign Config Failures on  %s", cimc_ip)
                cimc.cimc_clear_foreign_config()
                self.log.info("Resolved Foreign Config Failures on  %s", cimc_ip)

            cimc.cimc_logout()
        except Exception as e:
            if cimc:
                cimc.cimc_logout()
            self.log.error("Exception occurred on performing task  %s", e)


    def resolve_hba_port_failures(self, force_yes, input_host_list,
                                  validate_again=True):
        """ resolve_hba_port_failure """

        proceed = True
        kwargs = {}
        threadlist = []
        usecase_list = ['hba']
        if not force_yes:
            proceed = self.enable_user_option_to_proceed("HBA Slot")

        if proceed:
            try:
                if validate_again:
                    """ Pre and Post validating only HBA slot status instead of all
                        usecases while resolving HBA port failures """
                    hosts_list = self.get_host_lists(input_host_list)
                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if not len(self.cimc_hba_chk_fail_list):
                    self.log.info("PCIe HBA OptionROM already configured " + \
                                  "properly on all server(s)")
                    hosts = self.get_host_names(input_host_list)
                    err_segment = "WARNING : PCIe HBA OptionROM already  " + \
                                  "configured properly on all server(s) " + \
                                  str(hosts)
                    self.set_validation_results(RESOLVE_HBA_STATUS, status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_HBA_STATUS] = "PASS" + \
                        "~" + err_segment
                    return False
                kwargs['usecase'] = 'hba'
                if "failed" not in self.cimc_hba_chk_fail_list:
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for failed_hba in self.cimc_hba_chk_fail_list:
                        cimc_ip, err_msg = failed_hba.split('--')
                        kwargs['err_msg'] = err_msg
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()

                if validate_again:
                    host_list = []
                    if "failed" not in self.cimc_hba_chk_fail_list:
                        for failed_hba in self.cimc_hba_chk_fail_list:
                            cimc_ip = failed_hba.split('--')[0]
                            host_name = self.hostname_mapping[cimc_ip]
                            host_list.append(host_name)
                        self.cimc_hba_chk_fail_list = []
                        self.validation_results = []
                        self.unsupported_hw_list = []
                        self.log.info("Validating again after resolving the" + \
                                      "failures")
                        self.validate_hw_details(usecase_list, host_list)
                self.set_validation_results(RESOLVE_HBA_STATUS, status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_HBA_STATUS] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_HBA_STATUS, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_HBA_STATUS] = "FAIL" + \
                    "~" + err_seg
                return False
            return True

    def resolve_power_failures(self, force_yes, input_host_list,
                               validate_again=True):
        """ resolve_hba_port_failure """

        proceed = True
        kwargs = {}
        threadlist = []
        usecase_list = ['power']
        if not force_yes:
            proceed = self.enable_user_option_to_proceed("Power")
        if proceed:
            try:
                if validate_again:
                    """ Pre and Post validating only Power status instead of all
                        usecases while resolving Power failures """
                    hosts_list = self.get_host_lists(input_host_list)
                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list,
                                                 self.ironic_validation)

                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if not len(self.power_failure_list):
                    self.log.info("All server(s) are Powered ON already")
                    hosts = self.get_host_names(input_host_list)
                    err_segment = "WARNING : All server(s) are Powered ON" + \
                                  " already " + str(hosts)
                    self.set_validation_results(RESOLVE_POWER_STATE, status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_POWER_STATE] = "PASS" + \
                        "~" + err_segment
                    return False
                kwargs['usecase'] = 'power'
                if "failed" not in self.power_failure_list:
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for cimc_ip in self.power_failure_list:
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()

                if validate_again:
                    host_list = []
                    if "failed" not in self.power_failure_list:
                        for cimc in self.power_failure_list:
                            host_name = self.hostname_mapping[cimc]
                            host_list.append(host_name)
                        self.power_failure_list = []
                        self.validation_results = []
                        self.log.info("Validating again after resolving " + \
                                      "the failures")
                        self.validate_hw_details(usecase_list, host_list,
                                                 self.ironic_validation)
                self.set_validation_results(RESOLVE_POWER_STATE, status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_POWER_STATE] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_POWER_STATE, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_POWER_STATE] = "FAIL" + \
                    "~" + err_seg
                return False
            return True

    def resolve_pcie_adapter_slots_failures(self, force_yes, input_host_list,
                                            validate_again=True):
        """ resolve_pcie_adapter_slots_failures """

        proceed = True
        kwargs = {}
        threadlist = []
        usecase_list = ['pcie_slot']
        if not force_yes:
            """ Pre and Post validating only PCIe VIC Slot status instead of all
                    usecases while resolving PCIe VIC Slot failures """
            proceed = self.enable_user_option_to_proceed("PCIe Slot")

        if proceed:
            try:
                if validate_again:
                    hosts_list = self.get_host_lists(input_host_list)
                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if not len(self.pcie_slot_failure_list):
                    self.log.info("PCIe Adapter Slots already Enabled on" + \
                                  " all server(s)")
                    hosts = self.get_host_names(input_host_list)
                    err_segment = "WARNING : PCIe Adapter Slots already Enabled" + \
                                  " on all server(s) " + str(hosts)
                    self.set_validation_results(RESOLVE_PCI_ADAPTERS,
                                                status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_PCI_ADAPTERS] = "PASS" + \
                        "~" + err_segment
                    return False
                kwargs['usecase'] = 'pcie_slot'
                if "failed" not in self.pcie_slot_failure_list:
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for failed_pcie in self.pcie_slot_failure_list:
                        cimc_ip, err_msg = failed_pcie.split('--')
                        kwargs['err_msg'] = err_msg
                        vic_slot = self.vic_slot_mapping[cimc_ip]
                        kwargs['vic_slot'] = vic_slot
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()

                if validate_again:
                    host_list = []
                    if "failed" not in self.pcie_slot_failure_list:
                        for failed_pcie in self.pcie_slot_failure_list:
                            cimc = failed_pcie.split('--')[0]
                            host_name = self.hostname_mapping[cimc]
                            host_list.append(host_name)
                        self.pcie_slot_failure_list = []
                        self.validation_results = []
                        self.log.info("Validating again after resolving the " + \
                                      "Failures")
                        self.validate_hw_details(usecase_list, host_list)
                self.set_validation_results(RESOLVE_PCI_ADAPTERS,
                                            status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_PCI_ADAPTERS] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_PCI_ADAPTERS, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_PCI_ADAPTERS] = "FAIL" + \
                                                                     "~" + err_seg
                return False

            return True

    def resolve_flexflash_failures(self, force_yes, input_host_list,
                                   validate_again=True):
        """ resolve_flexflash_failures """

        proceed = True
        kwargs = {}
        threadlist = []
        usecase_list = ['flexflash']
        if not force_yes:
            """ Pre and Post validating only Flexflash status instead of all
                    other usecases while resolving Flexflash failures """
            proceed = self.enable_user_option_to_proceed("Flexflash")

        if proceed:
            try:
                if validate_again:
                    hosts_list = self.get_host_lists(input_host_list)
                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if not len(self.cimc_flex_flash_pd_fail_list):
                    self.log.info("No Flexflash Failures on any server(s)")
                    hosts = self.get_host_names(input_host_list)
                    err_segment = "WARNING : No Flexflash Failures on " + \
                                  "any server(s) " + str(hosts)
                    self.set_validation_results(RESOLVE_FF_PD,
                                                status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_FF_PD] = "PASS" + \
                        "~" + err_segment
                    return False
                # TODO: Temporary allow backward compatibility, need to remove once
                #       all setup move away from FlexFlash.
                elif "failed" in self.cimc_flex_flash_pd_fail_list \
                        and len(self.cimc_flex_flash_pd_fail_list) == 1:
                    self.log.info("Skip resolving Flexflash validation failures")
                    return False
                kwargs['usecase'] = 'flexflash'
                if "failed" not in self.cimc_flex_flash_pd_fail_list:
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for cimc_ip in self.cimc_flex_flash_pd_fail_list:
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()

                if validate_again:
                    host_list = []
                    if "fail" not in self.cimc_flex_flash_pd_fail_list:
                        for cimc in self.cimc_flex_flash_pd_fail_list:
                            host_name = self.hostname_mapping[cimc]
                            host_list.append(host_name)
                        self.cimc_flex_flash_pd_fail_list = []
                        self.validation_results = []
                        self.log.info("Validating again after resolving" + \
                                      "the Failures")
                        self.validate_hw_details(usecase_list, host_list)
                self.set_validation_results(RESOLVE_FF_PD,
                                            status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_FF_PD] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_FF_PD, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_FF_PD] = "FAIL" + "~" + err_seg
                return False

            return True

    def resolve_vnic_pxe_boot_failures(self, force_yes, input_host_list,
                                       validate_again=True):
        """ resolve_vnic_pxe_boot_failures """

        proceed = True
        kwargs = {}
        threadlist = []
        usecase_list = ['vnic_pxe_boot']
        if not force_yes:
            proceed = self.enable_user_option_to_proceed("VNIC PXE Boot")

        if proceed:
            try:
                if validate_again:
                    """ Pre and Post validating only vnic pxe boot status instead
                         of all usecases while resolving vnic pxe boot failures """
                    hosts_list = self.get_host_lists(input_host_list)
                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list,
                                                 self.ironic_validation)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return
                status = "Disabled"
                if self.ironic_validation:
                    status = "Enabled"
                if not len(self.cisco_vnic_pxe_chk_fail_list):
                    self.log.info("VNIC PXE BOOT is already %s on " + \
                                  "all server(s)", status)
                    hosts = self.get_host_names(input_host_list)
                    err_segment = "WARNING : VNIC PXE BOOT is already " + \
                                  str(status) + " on all server(s)" + str(hosts)
                    self.set_validation_results(RESOLVE_VNIC_PXE_BOOT,
                                                status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_VNIC_PXE_BOOT] = "PASS" + \
                        "~" + err_segment
                    return False
                kwargs['usecase'] = 'vnic'
                if "failed" not in self.cisco_vnic_pxe_chk_fail_list:
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for failed_vnic in self.cisco_vnic_pxe_chk_fail_list:
                        cimc_ip = failed_vnic.split('--')[0]
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()

                if validate_again:
                    host_list = []
                    if "failed" not in self.cisco_vnic_pxe_chk_fail_list:
                        for failed_vnic in self.cisco_vnic_pxe_chk_fail_list:
                            cimc = failed_vnic.split('--')[0]
                            host_name = self.hostname_mapping[cimc]
                            host_list.append(host_name)
                        self.cisco_vnic_pxe_chk_fail_list = []
                        self.validation_results = []
                        self.unsupported_hw_list = []
                        self.log.info("Validating again after resolving the " + \
                                      "failures")
                        self.validate_hw_details(usecase_list, host_list,
                                                 self.ironic_validation)
                self.set_validation_results(RESOLVE_VNIC_PXE_BOOT,
                                            status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_VNIC_PXE_BOOT] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_VNIC_PXE_BOOT, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_VNIC_PXE_BOOT] = "FAIL" + \
                    "~" + err_seg
                return False
            return True

    def resolve_vnic_vlan_mode_failures(self, force_yes, input_host_list,
                                       validate_again=True):
        """ resolve_vnic_vlan_mode_failures """

        proceed = True
        kwargs = {}
        threadlist = []
        usecase_list = ['vnic_vlan_mode']
        if not force_yes:
            proceed = self.enable_user_option_to_proceed("vNIC VLAM Mode")

        if proceed:
            try:
                if validate_again:
                    """ Pre and Post validating only vnic vlan mode status instead
                         of all usecases while resolving vnic pxe boot failures """
                    hosts_list = self.get_host_lists(input_host_list)
                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list,
                                                 self.ironic_validation)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if not len(self.cisco_vnic_vlan_mode_chk_fail_list):
                    self.log.info("vNIC VLAN Mode is already in TRUNK mode on " + \
                                  "all server(s)")
                    hosts = self.get_host_names(input_host_list)
                    err_segment = "WARNING : vNIC VLAN Mode is already in " + \
                                  " TRUNK mode on all server(s) " + str(hosts)
                    self.set_validation_results(RESOLVE_VNIC_VLAN_MODE,
                                                status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_VNIC_VLAN_MODE] = "PASS" + \
                        "~" + err_segment
                    return False
                kwargs['usecase'] = 'vnic_vlan_mode'
                if "failed" not in self.cisco_vnic_vlan_mode_chk_fail_list:
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for cimc_ip in self.cisco_vnic_vlan_mode_chk_fail_list:
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()

                if validate_again:
                    host_list = []
                    if "failed" not in self.cisco_vnic_vlan_mode_chk_fail_list:
                        for cimc in self.cisco_vnic_vlan_mode_chk_fail_list:
                            host_name = self.hostname_mapping[cimc]
                            host_list.append(host_name)
                        self.cisco_vnic_vlan_mode_chk_fail_list = []
                        self.validation_results = []
                        self.unsupported_hw_list = []
                        self.log.info("Validating again after resolving the " + \
                                      "failures")
                        self.validate_hw_details(usecase_list, host_list,
                                                 self.ironic_validation)
                self.set_validation_results(RESOLVE_VNIC_VLAN_MODE,
                                            status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_VNIC_VLAN_MODE] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_VNIC_VLAN_MODE, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_VNIC_VLAN_MODE] = "FAIL" + \
                    "~" + err_seg
                return False
            return True

    def resolve_ipmi_status_failures(self, force_yes, input_host_list,
                                     validate_again=True):
        """ resolve_vnic_vlan_mode_failures """
        proceed = True
        kwargs = {}
        threadlist = []
        usecase_list = ['ipmi_status']
        if not force_yes:
            proceed = self.enable_user_option_to_proceed("IPMI Status")

        if proceed:
            try:
                if validate_again:
                    """ Pre and Post validating only ipmi status instead
                         of all usecases while resolving vnic pxe boot failures """
                    hosts_list = self.get_host_lists(input_host_list)
                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list,
                                                 self.ironic_validation)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if not len(self.ipmi_status_failure_list):
                    self.log.info("IPMI is already Enabled on " + \
                                  "all server(s)")
                    hosts = self.get_host_names(input_host_list)
                    err_segment = "WARNING : IPMI is already Enabled on" + \
                                  " on all server(s) " + str(hosts)
                    self.set_validation_results(RESOLVE_IPMI_STATUS,
                                                status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_IPMI_STATUS] = "PASS" + \
                        "~" + err_segment
                    return False
                kwargs['usecase'] = 'ipmi_status'
                if "failed" not in self.ipmi_status_failure_list:
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for cimc_ip in self.ipmi_status_failure_list:
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()

                if validate_again:
                    host_list = []
                    if "failed" not in self.ipmi_status_failure_list:
                        for cimc in self.ipmi_status_failure_list:
                            host_name = self.hostname_mapping[cimc]
                            host_list.append(host_name)
                        self.ipmi_status_failure_list = []
                        self.validation_results = []
                        self.unsupported_hw_list = []
                        self.log.info("Validating again after resolving the " + \
                                      "failures")
                        self.validate_hw_details(usecase_list, host_list,
                                                 self.ironic_validation)
                self.set_validation_results(RESOLVE_IPMI_STATUS,
                                            status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_IPMI_STATUS] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_IPMI_STATUS, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_IPMI_STATUS] = "FAIL" + \
                    "~" + err_seg
                return False
            return True

    def resolve_ipmi_en_key_failures(self, force_yes, input_host_list,
                                     validate_again=True):
        """ resolve_vnic_vlan_mode_failures """

        proceed = True
        kwargs = {}
        threadlist = []
        usecase_list = ['ipmi_key']
        if not force_yes:
            proceed = self.enable_user_option_to_proceed("IPMI Encryption Key")

        if proceed:
            try:
                if validate_again:
                    """ Pre and Post validating only ipmi encryption key instead
                         of all usecases while resolving IPMI Key failures """
                    hosts_list = self.get_host_lists(input_host_list)
                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list,
                                                 self.ironic_validation)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if not len(self.ipmi_key_failure_list):
                    self.log.info("IPMI Encryption Key Matched with User " + \
                                  "Key on all server(s)")
                    hosts = self.get_host_names(input_host_list)
                    err_segment = "WARNING : IPMI Encryption Key Matched " + \
                                  " with User Key on all server(s) " + str(hosts)
                    self.set_validation_results(RESOLVE_IPMI_STATUS,
                                                status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_IPMI_STATUS] = "PASS" + \
                        "~" + err_segment
                    return False
                kwargs['usecase'] = 'ipmi_key'
                if "failed" not in self.ipmi_key_failure_list:
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for failed_ipmi_key in self.ipmi_key_failure_list:
                        cimc_ip = failed_ipmi_key.split('--')[0]
                        host_name = self.hostname_mapping[cimc_ip]
                        ipmi_key = self.ironic_yml_helper.get_ipmi_encryption_key(\
                            host_name)
                        if not ipmi_key:
                            ipmi_key = IPMI_DEFAULT_EN_KEY
                        kwargs['ipmi_key'] = ipmi_key
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()

                if validate_again:
                    host_list = []
                    if "failed" not in self.ipmi_key_failure_list:
                        for failed_ipmi_key in self.ipmi_key_failure_list:
                            cimc_ip = failed_ipmi_key.split('--')[0]
                            host_name = self.hostname_mapping[cimc_ip]
                            host_list.append(host_name)
                        self.ipmi_key_failure_list = []
                        self.validation_results = []
                        self.unsupported_hw_list = []
                        self.log.info("Validating again after resolving the " + \
                                      "failures")
                        self.validate_hw_details(usecase_list, host_list,
                                                 self.ironic_validation)
                self.set_validation_results(RESOLVE_IPMI_KEY,
                                            status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_IPMI_KEY] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_IPMI_KEY, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_IPMI_KEY] = "FAIL" + \
                    "~" + err_seg
                return False
            return True


    def resolve_pxe_boot_order_failures(self, force_yes, input_host_list,
                                        validate_again=True):
        """ resolve_vnic_vlan_mode_failures """

        proceed = True
        kwargs = {}
        threadlist = []
        usecase_list = ['pxe_boot_order']
        if not force_yes:
            proceed = self.enable_user_option_to_proceed("PXE Boot Order")

        if proceed:
            try:
                if validate_again:
                    """ Pre and Post validating only pxe boot order instead
                         of all usecases while resolving vnic pxe boot failures """
                    hosts_list = self.get_host_lists(input_host_list)
                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list,
                                                 self.ironic_validation)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if not len(self.pxe_boot_order_chk_fail_list):
                    self.log.info("PXE Boot Order Configured on " + \
                                  "all server(s)")
                    hosts = self.get_host_names(input_host_list)
                    err_segment = "WARNING : PXE Boot Order Already " + \
                                  " Configured on all server(s) " + str(hosts)
                    self.set_validation_results(RESOLVE_PXE_BOOT_ORDER_STATUS,
                                                status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_PXE_BOOT_ORDER_STATUS] = \
                        "PASS" + "~" + err_segment
                    return False
                kwargs['usecase'] = 'pxe_boot_order'
                if "failed" not in self.pxe_boot_order_chk_fail_list:
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for failures in self.pxe_boot_order_chk_fail_list:
                        cimc_ip, err_msg = failures.split('--')
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()

                if validate_again:
                    host_list = []
                    if "failed" not in self.pxe_boot_order_chk_fail_list:
                        for failures in self.pxe_boot_order_chk_fail_list:
                            cimc_ip, err_msg = failures.split('--')
                            host_name = self.hostname_mapping[cimc_ip]
                            host_list.append(host_name)
                        self.pxe_boot_order_chk_fail_list = []
                        self.validation_results = []
                        self.unsupported_hw_list = []
                        self.log.info("Validating again after resolving the " + \
                                      "failures")
                        self.validate_hw_details(usecase_list, host_list,
                                                 self.ironic_validation)
                self.set_validation_results(RESOLVE_PXE_BOOT_ORDER_STATUS,
                                            status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_PXE_BOOT_ORDER_STATUS] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_VNIC_VLAN_MODE, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_VNIC_VLAN_MODE] = "FAIL" + \
                    "~" + err_seg
                return False
            return True

    def resolve_lldp_failures(self, force_yes, input_host_list,
                              validate_again=True):
        """ resolve_lldp_failures """
        proceed = True
        kwargs = {}
        threadlist = []
        usecase_list = ['lldp_status']
        if not force_yes:
            proceed = self.enable_user_option_to_proceed("LLDP Status")

        if proceed:
            try:
                if validate_again:
                    """ Pre and Post validating only lldp status instead
                         of all usecases while resolving lldp status failures """
                    hosts_list = self.get_host_lists(input_host_list)
                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list,
                                                 self.ironic_validation)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if not len(self.lldp_status_failure_list):
                    self.log.info("LLDP already Disabled on " + \
                                  "all server(s)")
                    hosts = self.get_host_names(input_host_list)
                    err_segment = "WARNING : LLDP already Disabled on" + \
                                  " on all server(s) " + str(hosts)
                    self.set_validation_results(RESOLVE_LLDP_STATUS,
                                                status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_LLDP_STATUS] = "PASS" + \
                        "~" + err_segment
                    return False
                kwargs['usecase'] = 'lldp_status'
                if "failed" not in self.lldp_status_failure_list:
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for cimc_ip in self.lldp_status_failure_list:
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()

                if validate_again:
                    host_list = []
                    if "failed" not in self.lldp_status_failure_list:
                        for cimc in self.lldp_status_failure_list:
                            host_name = self.hostname_mapping[cimc]
                            host_list.append(host_name)
                        self.lldp_status_failure_list = []
                        self.validation_results = []
                        self.unsupported_hw_list = []
                        self.log.info("Validating again after resolving the " + \
                                      "failures")
                        self.validate_hw_details(usecase_list, host_list,
                                                 self.ironic_validation)
                self.set_validation_results(RESOLVE_LLDP_STATUS,
                                            status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_LLDP_STATUS] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_LLDP_STATUS, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_LLDP_STATUS] = "FAIL" + \
                    "~" + err_seg
                return False
            return True

    def resolve_boot_config_failures(self, force_yes, input_host_list,
                                     validate_again=True):
        """ resolve_lldp_failures """
        proceed = True
        kwargs = {}
        threadlist = []
        usecase_list = ['boot_config']
        if not force_yes:
            proceed = self.enable_user_option_to_proceed("Boot Config")

        if proceed:
            try:
                if validate_again:
                    """ Pre and Post validating only boot config instead
                         of all usecases while resolving boot config check
                         failures """
                    hosts_list = self.get_host_lists(input_host_list)
                    hw_info_present = \
                        self.validate_hw_details(usecase_list, hosts_list,
                                                 self.ironic_validation)
                    if not hw_info_present.get('Hardware Validation'):
                        return False

                if len(self.cimc_ssh_chk_fail_list):
                    self.log.debug("CIMC API failures found on servers %s", \
                                  self.cimc_ssh_chk_fail_list)
                    return

                if not len(self.intel_boot_config_failures_list):
                    self.log.info("Boot Config already in Legacy mode on " + \
                                  "all server(s)")
                    hosts = self.get_host_names(input_host_list)
                    err_segment = "WARNING : Boot Config already in Legacy mode " + \
                                  " on all server(s) " + str(hosts)
                    self.set_validation_results(RESOLVE_BOOT_CONFIG,
                                                status='PASS',
                                                err=err_segment, reslv_reslt=True)
                    self.resolve_failures_report[RESOLVE_BOOT_CONFIG] = "PASS" + \
                        "~" + err_segment
                    return False
                kwargs['usecase'] = 'boot_config'
                if "failed" not in self.intel_boot_config_failures_list:
                    pool = ThreadPool(processes=THREAD_POOL_SIZE)
                    args_map = {}
                    for failures in self.intel_boot_config_failures_list:
                        cimc_ip, err_msg = failures.split('--')
                        args_map[cimc_ip] = deepcopy(kwargs)

                    job_args = [(k, v) for k, v in args_map.iteritems()]
                    pool.map(partial(self.worker_wrapper, self.perform_task),
                             job_args)
                    pool.close()
                    pool.join()

                if validate_again:
                    host_list = []
                    if "failed" not in self.intel_boot_config_failures_list:
                        for failures in self.intel_boot_config_failures_list:
                            cimc_ip, err_msg = failures.split('--')
                            host_name = self.hostname_mapping[cimc_ip]
                            host_list.append(host_name)
                        self.intel_boot_config_failures_list = []
                        self.validation_results = []
                        self.unsupported_hw_list = []
                        self.log.info("Validating again after resolving the " + \
                                      "failures")
                        self.validate_hw_details(usecase_list, host_list,
                                                 self.ironic_validation)
                self.set_validation_results(RESOLVE_BOOT_CONFIG,
                                            status='PASS',
                                            err=None, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_BOOT_CONFIG] = "PASS"
            except Exception as e:
                self.log.error("Exception occurred on performing task  %s", e)
                hosts = self.get_host_names(input_host_list)
                err_seg = str(e) + " on " + str(hosts)
                self.set_validation_results(RESOLVE_BOOT_CONFIG, status='FAIL',
                                            err=err_seg, reslv_reslt=True)
                self.resolve_failures_report[RESOLVE_BOOT_CONFIG] = "FAIL" + \
                    "~" + err_seg
                return False
            return True

    def clear_failure_lists(self):
        """ Clearing the old results """
        self.cimc_version_chk_fail_list = ['failed']
        self.cimc_lom_chk_fail_list = ['failed']
        self.cimc_hba_chk_fail_list = ['failed']
        self.cimc_physical_drives_chk_fail_list = ['failed']
        self.pchstorage_warn_list = []
        self.cimc_flex_flash_pd_fail_list = ['failed']
        self.cimc_credentials.clear()
        self.validation_results = []
        self.ff_capacity_warn_list = []
        self.ff_sync_warn_list = []
        self.pcie_slot_failure_list = ['failed']
        self.nfv_cfg_failure_list = ['failed']
        self.cisco_vnic_pxe_chk_fail_list = ['failed']
        self.unsupported_hw_list = []
        self.max_sessions_exceed_list = []
        self.common_failures_list = []
        self.power_failure_list = ['failed']
        self.cimc_ssh_chk_fail_list = []
        self.virt_vt_vtd_chk_failures_list = ['failed']

    def validate_results(self, hw_result, cimc_ip):
        """ Validating the results """

        roles = self.roles_map.get(cimc_ip)
        # Firmware check
        if not hw_result.get("FWV") is None:
            fw_check = hw_result['FWV']
            if "failed" in self.cimc_version_chk_fail_list:
                self.cimc_version_chk_fail_list.remove("failed")
            if not re.search(r'PASS', fw_check):
                if re.search(r'API', fw_check):
                    api_failures = cimc_ip + "--" + FW_VERSION_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                else:
                    self.cimc_version_chk_fail_list.append(cimc_ip)

        # LOM result check
        if not hw_result.get("LOM") is None:
            lom_check = hw_result['LOM']
            if "failed" in self.cimc_lom_chk_fail_list:
                self.cimc_lom_chk_fail_list.remove("failed")
            if not re.search(r'PASS', lom_check):
                if re.search(r'API', lom_check):
                    api_failures = cimc_ip + "--" + LOM_INTF_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                else:
                    self.cimc_lom_chk_fail_list.append(cimc_ip)

        # HBA result check
        if not hw_result.get("HBA") is None:
            hba_check = hw_result['HBA']
            if "failed" in self.cimc_hba_chk_fail_list:
                self.cimc_hba_chk_fail_list.remove("failed")
            if re.search(r'API', str(hba_check)):
                api_failures = cimc_ip + "--" + HBA_STATUS_CHK
                self.cimc_ssh_chk_fail_list.append(api_failures)
            elif re.search(r'FAIL', str(hba_check)):
                failure_msg = cimc_ip + "--" + hba_check.split(":")[1].strip()
                self.cimc_hba_chk_fail_list.append(failure_msg)

        # Physical drive result check
        if hw_result.get("PHYSICAL-DRIVES") is not None \
           and (roles is None or "vts" not in roles):
            pd_check = hw_result["PHYSICAL-DRIVES"]
            if pd_check and pd_check is not None:
                if "failed" in self.cimc_physical_drives_chk_fail_list:
                    self.cimc_physical_drives_chk_fail_list.remove("failed")
                if re.search(r'API', str(pd_check)):
                    api_failures = cimc_ip + "--" + PHYSICAL_DRIVES_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'WARN', str(pd_check)):
                    warn_list = cimc_ip + "--" + pd_check.split(":")[1].strip()
                    self.pchstorage_warn_list.append(warn_list)
                elif re.search(r'FAIL', str(pd_check)):
                    failure_msg = cimc_ip + "--" + pd_check.split(":")[1].strip()
                    self.cimc_physical_drives_chk_fail_list.append(failure_msg)

        # Server power status check
        if not hw_result.get("SPS") is None:
            power_chk = hw_result['SPS']
            if "failed" in self.power_failure_list:
                self.power_failure_list.remove("failed")
            if not re.search(r'PASS', power_chk):
                if re.search(r'API', power_chk):
                    api_failures = cimc_ip + "--" + POWER_STATE_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                else:
                    self.power_failure_list.append(cimc_ip)

        # CPU/Memory check for NFV Hosts
        if not hw_result.get("NFV") is None:
            nfv_chk = hw_result['NFV']
            if "failed" in self.nfv_cfg_failure_list:
                self.nfv_cfg_failure_list.remove("failed")
            if nfv_chk != 'PASS':
                if re.search(r'API', nfv_chk):
                    api_failures = cimc_ip + "--" + NFV_CONFIG_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                else:
                    self.nfv_cfg_failure_list.append(
                        {'Host': cimc_ip, 'Reason': hw_result['NFV']})

        # Cisco VNIC PXE boot status check
        if (hw_result.get("VNIC") is not None and hw_result.get("SPS") is None) \
                or (hw_result.get("VNIC") is not None \
                    and re.search(r'PASS', power_chk)):
            vnic_pxe_chk = hw_result['VNIC']
            if "failed" in self.cisco_vnic_pxe_chk_fail_list and \
                    not re.search(r'API', vnic_pxe_chk):
                self.cisco_vnic_pxe_chk_fail_list.remove("failed")
            if not re.search(r'PASS', vnic_pxe_chk):
                if re.search(r'API', vnic_pxe_chk):
                    api_failures = cimc_ip + "--" + VNIC_PXE_BOOT_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'FAIL', vnic_pxe_chk):
                    failure_msg = cimc_ip + "--" + vnic_pxe_chk.split(":")[1].strip()
                    self.cisco_vnic_pxe_chk_fail_list.append(failure_msg)
                else:
                    self.cisco_vnic_pxe_chk_fail_list.append(cimc_ip)

        #  Flex flash Physical drive result check
        if hw_result.get("FF-PD") is not None and \
           (roles is None or "vts" not in roles):
            ff_pd_Check = hw_result['FF-PD']
            if "failed" in self.cimc_flex_flash_pd_fail_list:
                self.cimc_flex_flash_pd_fail_list.remove("failed")
            if not re.search(r'PASS', ff_pd_Check):
                if re.search(r'API', ff_pd_Check):
                    api_failures = cimc_ip + "--" + FF_PD_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'syncing', ff_pd_Check.lower()):
                    self.ff_sync_warn_list.append(cimc_ip)
                elif re.search(r'capacity', ff_pd_Check.lower()):
                    self.ff_capacity_warn_list.append(cimc_ip)
                else:
                    self.cimc_flex_flash_pd_fail_list.append(cimc_ip)

        # PCIe slot  status check
        if not hw_result.get("PCA") is None:
            pcie_chk = hw_result['PCA']
            if "failed" in self.pcie_slot_failure_list:
                self.pcie_slot_failure_list.remove("failed")
            if re.search(r'API', str(pcie_chk)):
                api_failures = cimc_ip + "--" + PCI_ADAPTERS_CHK
                self.cimc_ssh_chk_fail_list.append(api_failures)
            elif re.search(r'FAIL', str(pcie_chk)):
                failure_msg = cimc_ip + "--" + pcie_chk.split(":")[1].strip()
                self.pcie_slot_failure_list.append(failure_msg)

        # Adapter vendor check
        if not hw_result.get("ADAPTER_CHK") is None:
            adapter_chk = hw_result['ADAPTER_CHK']
            if adapter_chk and adapter_chk is not None:
                if "failed" in self.vic_unsupported_vendor_list:
                    self.vic_unsupported_vendor_list.remove("failed")
                if re.search(r'API', str(adapter_chk)):
                    api_failures = cimc_ip + "--" + VIC_ADAPTER_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'WARN', str(adapter_chk)):
                    warn_list = cimc_ip + "--" + adapter_chk.split(":")[1].strip()
                    self.vic_adapter_warn_list.append(warn_list)
                elif re.search(r'FAIL', str(adapter_chk)):
                    failure_msg = cimc_ip + "--" + adapter_chk.split(":")[1].strip()
                    self.vic_unsupported_vendor_list.append(failure_msg)

        # Virtualization(VT & VT-d) check
        if not hw_result.get("VIRT") is None:
            virt_chk = hw_result['VIRT']
            if "failed" in self.virt_vt_vtd_chk_failures_list:
                self.virt_vt_vtd_chk_failures_list.remove("failed")
            if not re.search(r'PASS', virt_chk):
                if re.search(r'API', virt_chk):
                    api_failures = cimc_ip + "--" + VIRT_VT_AND_VTD_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                else:
                    self.virt_vt_vtd_chk_failures_list.append(cimc_ip)

        # Intel NIC Check
        if not hw_result.get("INTEL_NIC_CHK") is None:
            intel_nic_chk = hw_result['INTEL_NIC_CHK']
            if intel_nic_chk and intel_nic_chk is not None:
                if "failed" in self.intel_nic_failures_list:
                    self.intel_nic_failures_list.remove("failed")
                if re.search(r'API', str(intel_nic_chk)):
                    api_failures = cimc_ip + "--" + INTEL_NIC_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'WARN', str(intel_nic_chk)):
                    warn_list = cimc_ip + "--" + intel_nic_chk.split(":")[1].strip()
                    self.intel_nic_warn_list.append(warn_list)
                elif re.search(r'FAIL', str(intel_nic_chk)):
                    failure_msg = cimc_ip + "--" + \
                        intel_nic_chk.split(":")[1].strip()
                    self.intel_nic_failures_list.append(failure_msg)

        # Intel Actual Boot Order Check
        if not hw_result.get("INTEL_BOOT_ORDER_CHK") is None:
            boot_order_chk = hw_result['INTEL_BOOT_ORDER_CHK']
            if boot_order_chk and boot_order_chk is not None:
                if "failed" in self.intel_boot_order_failures_list:
                    self.intel_boot_order_failures_list.remove("failed")
                if re.search(r'API', str(boot_order_chk)):
                    api_failures = cimc_ip + "--" + INTEL_BOOT_ORDER_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'WARN', str(boot_order_chk)):
                    warn_list = cimc_ip + "--" + boot_order_chk.split(":")[1].strip()
                    self.intel_boot_order_warn_list.append(warn_list)
                elif re.search(r'FAIL', str(boot_order_chk)):
                    failure_msg = cimc_ip + "--" + \
                        boot_order_chk.split(":")[1].strip()
                    self.intel_boot_order_failures_list.append(failure_msg)

        # Intel Actual Boot Config Check
        if not hw_result.get("INTEL_BOOT_CONFIG_CHK") is None:
            boot_order_chk = hw_result['INTEL_BOOT_CONFIG_CHK']
            if boot_order_chk and boot_order_chk is not None:
                if "failed" in self.intel_boot_config_failures_list:
                    self.intel_boot_config_failures_list.remove("failed")
                if re.search(r'API', str(boot_order_chk)):
                    api_failures = cimc_ip + "--" + INTEL_BOOT_CONFIG_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'FAIL', str(boot_order_chk)):
                    failure_msg = cimc_ip + "--" + \
                        boot_order_chk.split(":")[1].strip()
                    self.intel_boot_config_failures_list.append(failure_msg)

        # GPU Check
        if not hw_result.get("GPU_CHK") is None:
            p_gpu_chk = hw_result['GPU_CHK']
            if p_gpu_chk and p_gpu_chk is not None and \
               not re.match(r'Skipping', str(p_gpu_chk)):
                if "failed" in self.p_gpu_chk_fail_list:
                    self.p_gpu_chk_fail_list.remove("failed")
                if re.search(r'API', str(p_gpu_chk)):
                    api_failures = cimc_ip + "--" + P_GPU_CARD_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'FAIL', str(p_gpu_chk)):
                    failure_msg = cimc_ip + "--" + \
                        p_gpu_chk.split(":")[1].strip()
                    self.p_gpu_chk_fail_list.append(failure_msg)

        if not hw_result.get("REDFISH_CONFIG_CHK") is None:
            redfish_enable_check = hw_result['REDFISH_CONFIG_CHK']
            if redfish_enable_check and redfish_enable_check is not None:
                if "failed" in self.redfish_enabled_failures_list:
                    self.redfish_enabled_failures_list.remove("failed")
                if re.search(r'API', str(redfish_enable_check)):
                    api_failures = cimc_ip + "--" + REDFISH_CONFIG_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'FAIL', str(redfish_enable_check)):
                    failure_msg = cimc_ip + "--" + \
                        redfish_enable_check.split(":")[1].strip()
                    self.redfish_enabled_failures_list.append(failure_msg)

        # Intel Actual Boot Config Check
        if not hw_result.get("ARGUS_NIC_CHK") is None:
            argus_nic_chk = hw_result['ARGUS_NIC_CHK']
            if argus_nic_chk and argus_nic_chk is not None:
                if "failed" in self.argus_nic_failures_list:
                    self.argus_nic_failures_list.remove("failed")
                if re.search(r'API', str(argus_nic_chk)):
                    api_failures = cimc_ip + "--" + ARGUS_NIC_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'FAIL', str(argus_nic_chk)):
                    failure_msg = cimc_ip + "--" + \
                        argus_nic_chk.split(":")[1].strip()
                    self.argus_nic_failures_list.append(failure_msg)

        # Argus Num Disk Check
        if not hw_result.get("ARGUS_DISK_CHK") is None:
            argus_disk_chk = hw_result['ARGUS_DISK_CHK']
            if argus_disk_chk and argus_disk_chk is not None:
                if "failed" in self.argus_disk_failures_list:
                    self.argus_disk_failures_list.remove("failed")
                if re.search(r'API', str(argus_disk_chk)):
                    api_failures = cimc_ip + "--" + ARGUS_DISK_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'FAIL', str(argus_disk_chk)):
                    failure_msg = cimc_ip + "--" + \
                        argus_disk_chk.split(":")[1].strip()
                    self.argus_disk_failures_list.append(failure_msg)

        # Server IPMI status check
        if not hw_result.get("IPMI_STATUS") is None:
            ipmi_chk = hw_result['IPMI_STATUS']
            if "failed" in self.ipmi_status_failure_list:
                self.ipmi_status_failure_list.remove("failed")
            if not re.search(r'PASS', ipmi_chk):
                if re.search(r'API', ipmi_chk):
                    api_failures = cimc_ip + "--" + IPMI_STATUS_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                else:
                    self.ipmi_status_failure_list.append(cimc_ip)

        # Server IPMI encryption key check
        if not hw_result.get("IPMI_KEY") is None:
            ipmi_chk = hw_result['IPMI_KEY']
            if "failed" in self.ipmi_key_failure_list:
                self.ipmi_key_failure_list.remove("failed")
            if re.search(r'API', str(ipmi_chk)):
                api_failures = cimc_ip + "--" + IPMI_KEY_CHK
                self.cimc_ssh_chk_fail_list.append(api_failures)
            elif re.search(r'FAIL', str(ipmi_chk)):
                failure_msg = cimc_ip + "--" + ipmi_chk.split(":")[1].strip()
                self.ipmi_key_failure_list.append(failure_msg)


        # Cisco VNIC PXE boot status check
        if (hw_result.get("VNIC_VLAN_MODE") is not None and \
            hw_result.get("SPS") is None) \
                or (hw_result.get("VNIC_VLAN_MODE") is not None \
                    and re.search(r'PASS', power_chk)):
            vnic_vlan_mode_chk = hw_result['VNIC_VLAN_MODE']
            if "failed" in self.cisco_vnic_vlan_mode_chk_fail_list and \
                    not re.search(r'API', vnic_vlan_mode_chk):
                self.cisco_vnic_vlan_mode_chk_fail_list.remove("failed")
            if not re.search(r'PASS', vnic_vlan_mode_chk):
                if re.search(r'API', vnic_vlan_mode_chk):
                    api_failures = cimc_ip + "--" + VNIC_VLAN_MODE_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                else:
                    self.cisco_vnic_vlan_mode_chk_fail_list.append(cimc_ip)

        # boot order check
        if hw_result.get("IPMI_BOOT_ORDER") is not None:
            boot_order_chk = hw_result["IPMI_BOOT_ORDER"]
            if boot_order_chk and boot_order_chk is not None:
                if "failed" in self.pxe_boot_order_chk_fail_list:
                    self.pxe_boot_order_chk_fail_list.remove("failed")
                if re.search(r'API', str(boot_order_chk)):
                    api_failures = cimc_ip + "--" + PXE_BOOT_ORDER_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                elif re.search(r'FAIL', str(boot_order_chk)):
                    failure_msg = cimc_ip + "--" + \
                        boot_order_chk.split(":")[1].strip()
                    self.pxe_boot_order_chk_fail_list.append(failure_msg)

        # LLDP status result check
        if not hw_result.get("LLDP_STATUS") is None:
            lldp_chk = hw_result['LLDP_STATUS']
            if "failed" in self.lldp_status_failure_list:
                self.lldp_status_failure_list.remove("failed")
            if not re.search(r'PASS', lldp_chk):
                if re.search(r'API', lldp_chk):
                    api_failures = cimc_ip + "--" + LLDP_STATUS_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                else:
                    self.lldp_status_failure_list.append(cimc_ip)

        # Forign config check
        if not hw_result.get("F_CONFIG") is None:
            fg_check = hw_result['F_CONFIG']
            if "failed" in self.cimc_foreign_chk_fail_list:
                self.cimc_foreign_chk_fail_list.remove("failed")
            if not re.search(r'PASS', fg_check):
                if re.search(r'API', fg_check):
                    api_failures = cimc_ip + "--" + FOREIGN_CFG_CHK
                    self.cimc_ssh_chk_fail_list.append(api_failures)
                else:
                    self.cimc_foreign_chk_fail_list.append(cimc_ip)

    def display_hw_validation_results(self):
        """ Displaying the hardware validation results """

        if re.match(r'UCSM', self.get_hardware_type()):
            # Display UCSM Blades model type results
            if "failed" not in self.ucsm_unsupported_blades_list:
                if len(self.ucsm_unsupported_blades_list):
                    err_segment = " Unsupported UCSM HW Model found for :" + \
                        str(self.ucsm_unsupported_blades_list) + \
                        ". Expected Model : B200-M3/M4"
                    self.set_validation_results(UCSM_BLADES_MODEL_CHK, status='FAIL',
                                                err=err_segment)
                    self.validation_report[UCSM_BLADES_MODEL_CHK] = "FAIL" \
                        + "~" + err_segment
                else:
                    self.set_validation_results(UCSM_BLADES_MODEL_CHK)
                    self.validation_report[UCSM_BLADES_MODEL_CHK] = "PASS"

            # Display UCSM Racks model type results
            if "failed" not in self.ucsm_unsupported_racks_list:
                if len(self.ucsm_unsupported_racks_list):
                    err_segment = " Unsupported UCSM HW Model found for :" + \
                        str(self.ucsm_unsupported_racks_list) +\
                        ". Expected Model : C240-M4"
                    self.set_validation_results(UCSM_RACKS_MODEL_CHK, status='FAIL',
                                                err=err_segment)
                    self.validation_report[UCSM_RACKS_MODEL_CHK] = "FAIL" \
                        + "~" + err_segment
                else:
                    self.set_validation_results(UCSM_RACKS_MODEL_CHK)
                    self.validation_report[UCSM_RACKS_MODEL_CHK] = "PASS"

            # Display UCSM Flexflash status results
            if "failed" not in self.ucsm_ff_status_fail_list:
                if len(self.ucsm_ff_status_fail_list):
                    err_segment = "Invalid number of FlexFlash cards found on " + \
                                  str(self.ucsm_ff_status_fail_list) + \
                        ". 'TWO' FlexFlash cards should be available."
                    self.set_validation_results(UCSM_SERVERS_FF_CHK, status='FAIL',
                                                err=err_segment)
                    self.validation_report[UCSM_SERVERS_FF_CHK] = "FAIL" \
                        + "~" + err_segment
                else:
                    self.set_validation_results(UCSM_SERVERS_FF_CHK)
                    self.validation_report[UCSM_SERVERS_FF_CHK] = "PASS"

            # Display UCSM Service Profile assignment results
            if "failed" not in self.ucsm_sp_assignment_fail_list:
                if len(self.ucsm_sp_assignment_fail_list):
                    err_segment = "Already Service Profile associated on :" + \
                        str(self.ucsm_sp_assignment_fail_list) + \
                        ". Dissociate the existing Service Profile. "
                    self.set_validation_results(UCSM_SP_ASSIGN_CHK, status='FAIL',
                                                err=err_segment)
                    self.validation_report[UCSM_SP_ASSIGN_CHK] = "FAIL" \
                        + "~" + err_segment
                else:
                    self.set_validation_results(UCSM_SP_ASSIGN_CHK)
                    self.validation_report[UCSM_SP_ASSIGN_CHK] = "PASS"

            # Display UCSM Chassis servers Storage disk results
            if "failed" not in self.ucsm_storage_failures:
                if len(self.ucsm_storage_failures):
                    self.set_validation_results(UCSM_STORAGE_CHK, status='FAIL',
                                                err=str(self.ucsm_storage_failures))
                    self.validation_report[UCSM_STORAGE_CHK] = "FAIL" \
                        + "~" + str(self.ucsm_storage_failures)
                else:
                    self.set_validation_results(UCSM_STORAGE_CHK)
                    self.validation_report[UCSM_STORAGE_CHK] = "PASS"

            # Display UCSM Chassis servers Memory check results
            if "failed" not in self.ucsm_memory_failures:
                if len(self.ucsm_memory_failures):
                    self.set_validation_results(UCSM_MEMORY_CHK, status='FAIL',
                                                err=str(self.ucsm_memory_failures))
                    self.validation_report[UCSM_MEMORY_CHK] = "FAIL" \
                        + "~" + str(self.ucsm_memory_failures)
                else:
                    self.set_validation_results(UCSM_MEMORY_CHK)
                    self.validation_report[UCSM_MEMORY_CHK] = "PASS"

            # Display UCSM Chassis servers Adapter check results
            if "failed" not in self.ucsm_adapter_failures:
                if len(self.ucsm_adapter_failures):
                    self.set_validation_results(UCSM_ADAPTER_CHK, status='FAIL',
                                                err=str(self.ucsm_adapter_failures))
                    self.validation_report[UCSM_ADAPTER_CHK] = "FAIL" \
                        + "~" + str(self.ucsm_adapter_failures)
                else:
                    self.set_validation_results(UCSM_ADAPTER_CHK)
                    self.validation_report[UCSM_ADAPTER_CHK] = "PASS"

            # Display UCSM Storage LUN disk check results
            if "failed" not in self.ucsm_lun_failures:
                if len(self.ucsm_lun_failures):
                    self.set_validation_results(UCSM_LUN_CHK, status='FAIL',
                                                err=str(self.ucsm_lun_failures))
                    self.validation_report[UCSM_LUN_CHK] = "FAIL" \
                        + "~" + str(self.ucsm_lun_failures)
                else:
                    self.set_validation_results(UCSM_LUN_CHK)
                    self.validation_report[UCSM_LUN_CHK] = "PASS"

            # Display UCSM Chassis servers IOM count check results
            if "failed" not in self.ucsm_iom_failures:
                if len(self.ucsm_iom_failures):
                    self.set_validation_results(UCSM_IOM_CHK, status='FAIL',
                                                err=str(self.ucsm_iom_failures))
                    self.validation_report[UCSM_IOM_CHK] = "FAIL" \
                        + "~" + str(self.ucsm_iom_failures)
                else:
                    self.set_validation_results(UCSM_IOM_CHK)
                    self.validation_report[UCSM_IOM_CHK] = "PASS"

            # Display UCSM Rack servers MRAID check results
            if "failed" not in self.ucsm_mraid_failures:
                if len(self.ucsm_mraid_failures):
                    self.set_validation_results(UCSM_MRAID_CHK, status='FAIL',
                                                err=str(self.ucsm_mraid_failures))
                    self.validation_report[UCSM_MRAID_CHK] = "FAIL" \
                        + "~" + str(self.ucsm_mraid_failures)
                else:
                    self.set_validation_results(UCSM_MRAID_CHK)
                    self.validation_report[UCSM_MRAID_CHK] = "PASS"

            # Display NFV Config Check Stauts
            if "failed" not in self.ucsm_nfv_config_failures:
                if len(self.ucsm_nfv_config_failures):
                    err_segment = "NFV configs cannot be applied on: %s." % \
                        str(self.ucsm_nfv_config_failures)
                    self.set_validation_results(UCSM_NFV_CONFIG_CHK, status='FAIL',
                                                err=err_segment)
                    self.validation_report[UCSM_NFV_CONFIG_CHK] = "FAIL" + \
                        "~" + err_segment
                else:
                    self.set_validation_results(UCSM_NFV_CONFIG_CHK)
                    self.validation_report[UCSM_NFV_CONFIG_CHK] = "PASS"

        else:
            intel_support = self.ymlhelper.use_intel_nic()
            expt_str = " Expected Version >= 2.0(13i)"
            if intel_support:
                expt_str = " Expected Version >= 2.0(13i)"

            # Display Firmware results
            if "failed" not in self.cimc_version_chk_fail_list and \
                    len(self.cimc_version_chk_fail_list):
                err_segment = " CIMC Firmware version check failed for :" + \
                    str(self.cimc_version_chk_fail_list) + expt_str

                # TODO: Need to better handle the error message for different
                #       platform.  For now, still sticking with the hardcoding
                #       and provide a generic output when it's a thirdparties.
                if config_parser.PlatformDiscovery(
                        self.setup_file).contain_thirdparties_platform():
                    err_segment = " Firmware version check failed for: " + \
                        str(self.cimc_version_chk_fail_list)

                self.set_validation_results(FW_VERSION_CHK, status='FAIL',
                                            err=err_segment)
                self.validation_report[FW_VERSION_CHK] = "FAIL" + "~" + err_segment
            elif not self.cimc_version_chk_fail_list:
                self.set_validation_results(FW_VERSION_CHK)
                self.validation_report[FW_VERSION_CHK] = "PASS"

            # Display LOM status results
            if "failed" not in self.cimc_lom_chk_fail_list \
                    and len(self.cimc_lom_chk_fail_list):
                if self.target_ospd:
                    err_segment = "LOM Port(s) OptionROM is 'Disabled' on :" + \
                                  str(self.cimc_lom_chk_fail_list) + \
                                  " for OSPD option. 'Enable' all LOM Port(s)"
                else:
                    err_segment = "LOM Port(s) OptionROM is 'Enabled' on :" + \
                                  str(self.cimc_lom_chk_fail_list) + \
                                  ". 'Disable' all LOM Port(s)"

                self.set_validation_results(LOM_INTF_CHK, status='FAIL',
                                            err=err_segment)
                self.validation_report[LOM_INTF_CHK] = "FAIL" + "~" + err_segment
            elif not self.cimc_lom_chk_fail_list:
                self.set_validation_results(LOM_INTF_CHK)
                self.validation_report[LOM_INTF_CHK] = "PASS"

            # Display HBA status results
            if "failed" not in self.cimc_hba_chk_fail_list \
                    and len(self.cimc_hba_chk_fail_list):
                failure_report = self.consolidate_failure_msg(
                    self.cimc_hba_chk_fail_list)
                self.set_validation_results(HBA_STATUS_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[HBA_STATUS_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif not self.cimc_hba_chk_fail_list:
                self.set_validation_results(HBA_STATUS_CHK)
                self.validation_report[HBA_STATUS_CHK] = "PASS"

            # Display Server Power status results
            if "failed" not in self.power_failure_list \
                    and len(self.power_failure_list):
                err_segment = "Server(s) are Powered Off: " +  \
                    str(self.power_failure_list) + ". Power ON the Server(s)"
                self.set_validation_results(POWER_STATE_CHK, status='FAIL',
                                            err=err_segment)
                self.validation_report[POWER_STATE_CHK] = "FAIL" + "~" + err_segment
            elif not self.power_failure_list:
                self.set_validation_results(POWER_STATE_CHK)
                self.validation_report[POWER_STATE_CHK] = "PASS"

            # Display NFV Config Check Stauts
            if "failed" not in self.nfv_cfg_failure_list \
                    and len(self.nfv_cfg_failure_list):
                err_segment = "NFV configs cannot be applied on: %s." % \
                    str(self.nfv_cfg_failure_list)
                self.set_validation_results(NFV_CONFIG_CHK, status='FAIL',
                                            err=err_segment)
                self.validation_report[NFV_CONFIG_CHK] = "FAIL" + \
                    "~" + err_segment
            elif not self.nfv_cfg_failure_list:
                self.set_validation_results(NFV_CONFIG_CHK)
                self.validation_report[NFV_CONFIG_CHK] = "PASS"

            # Display CISCO VNIC PXE Boot Stauts
            if "failed" not in self.cisco_vnic_pxe_chk_fail_list \
                    and len(self.cisco_vnic_pxe_chk_fail_list):
                if self.target_ospd:
                    err_segment = " VNIC PXE Boot is 'Disabled' on :" + \
                        str(self.cisco_vnic_pxe_chk_fail_list) + \
                        "for OSPD option. 'Enable' PXE Boot"
                elif self.ironic_validation:
                    err_segment = self.consolidate_failure_msg(
                        self.cisco_vnic_pxe_chk_fail_list)
                else:
                    err_segment = " VNIC PXE Boot is 'Enabled' on :" + \
                        str(self.cisco_vnic_pxe_chk_fail_list) + \
                        ". 'Disable' PXE Boot"

                self.set_validation_results(VNIC_PXE_BOOT_CHK, status='FAIL',
                                            err=str(err_segment))
                self.validation_report[VNIC_PXE_BOOT_CHK] = "FAIL" + \
                    "~" + str(err_segment)
            elif not self.cisco_vnic_pxe_chk_fail_list:
                self.set_validation_results(VNIC_PXE_BOOT_CHK)
                self.validation_report[VNIC_PXE_BOOT_CHK] = "PASS"

            # Display pysical drive results
            if "failed" not in self.cimc_physical_drives_chk_fail_list \
                    and len(self.cimc_physical_drives_chk_fail_list):
                failure_report = self.consolidate_failure_msg(
                    self.cimc_physical_drives_chk_fail_list)
                self.set_validation_results(PHYSICAL_DRIVES_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[PHYSICAL_DRIVES_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif len(self.pchstorage_warn_list):
                warn_msg = "Warning: " + str(self.consolidate_failure_msg(
                    self.pchstorage_warn_list))
                self.set_validation_results(PHYSICAL_DRIVES_CHK, status='PASS',
                                            err=warn_msg)
                self.validation_report[PHYSICAL_DRIVES_CHK] = (
                    "PASS" + "~" + str(warn_msg))
            elif not self.cimc_physical_drives_chk_fail_list:
                self.set_validation_results(PHYSICAL_DRIVES_CHK)
                self.validation_report[PHYSICAL_DRIVES_CHK] = "PASS"

            # Display Flex flash Physical drive results
            if "failed" not in self.cimc_flex_flash_pd_fail_list \
                    and len(self.cimc_flex_flash_pd_fail_list):
                err_segment = "Either FlexFlash Physical Drive(s) are not in" + \
                    " mirror mode or Sync mode is not in 'Auto' on :" + \
                    str(self.cimc_flex_flash_pd_fail_list) + \
                    ". Enable mirror/auto mode for FlexFlash Physical Drive(s)"
                self.set_validation_results(FF_PD_CHK, status='FAIL',
                                            err=err_segment)
                self.validation_report[FF_PD_CHK] = "FAIL" + "~" + err_segment
            elif len(self.ff_sync_warn_list):
                warn_msg = "Flexflash Virtual drive Syncing(Auto) Operation is" + \
                           " in progress. Revalidate after the sync " + \
                           "operation completion on " + str(self.ff_sync_warn_list)
                self.set_validation_results(FF_PD_CHK, status='FAIL', err=warn_msg)
                self.validation_report[FF_PD_CHK] = "FAIL" + "~" + warn_msg
            elif len(self.ff_capacity_warn_list):
                warn_msg = "Warning: Minimum capacity for Flexflash" + \
                    "physical drive(s) should be 32 GB on " + \
                           + str(self.ff_capacity_warn_list)
                self.set_validation_results(FF_PD_CHK, status='PASS', err=warn_msg)
                self.validation_report[FF_PD_CHK] = "PASS" + "~" + warn_msg
            elif not self.cimc_flex_flash_pd_fail_list:
                self.set_validation_results(FF_PD_CHK)
                self.validation_report[FF_PD_CHK] = "PASS"

            # Display PCIe slots/MLOM validation results
            if "failed" not in self.pcie_slot_failure_list \
                    and len(self.pcie_slot_failure_list):
                failure_report = \
                    self.consolidate_failure_msg(self.pcie_slot_failure_list)
                self.set_validation_results(PCI_ADAPTERS_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[PCI_ADAPTERS_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif not self.pcie_slot_failure_list:
                self.set_validation_results(PCI_ADAPTERS_CHK)
                self.validation_report[PCI_ADAPTERS_CHK] = "PASS"

            # Display Virtualization(VT/VT-d) status results
            if "failed" not in self.virt_vt_vtd_chk_failures_list \
                    and len(self.virt_vt_vtd_chk_failures_list):
                err_segment = " BIOS Virtualization(VT/VT-d) Option(s) are " + \
                              "'Disabled' on" + \
                              str(self.virt_vt_vtd_chk_failures_list) + \
                              ". 'Enable' Virtualization(VT/VT-d) option(s)."
                self.set_validation_results(VIRT_VT_AND_VTD_CHK, status='FAIL',
                                            err=err_segment)
                self.validation_report[VIRT_VT_AND_VTD_CHK] = "FAIL" + \
                    "~" + err_segment
            elif not self.virt_vt_vtd_chk_failures_list:
                self.set_validation_results(VIRT_VT_AND_VTD_CHK)
                self.validation_report[VIRT_VT_AND_VTD_CHK] = "PASS"

            # Display Max Sessions Exceeded Failures
            if len(self.max_sessions_exceed_list):
                err_segment = "Maximum sessions reached for: " \
                              + str(self.max_sessions_exceed_list) + \
                    ". Clear the sessions ( Admin -> User Management)" + \
                    "and retry the Hardware Validation"
                self.set_validation_results(SERVER_CHK, status='FAIL',
                                            err=err_segment)
                self.validation_report[SERVER_CHK] = "FAIL" + "~" + err_segment

            # Display unsupported hw failures
            if len(self.unsupported_hw_list):
                failure_report = self.consolidate_failure_msg(
                    self.unsupported_hw_list)
                self.set_validation_results(SERVER_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[SERVER_CHK] = "FAIL" + \
                    "~" + str(failure_report)

            # Display VIC Adapter check results
            if "failed" not in self.vic_unsupported_vendor_list \
                    and len(self.vic_unsupported_vendor_list):
                failure_report = self.consolidate_failure_msg(
                    self.vic_unsupported_vendor_list)
                self.set_validation_results(VIC_ADAPTER_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[VIC_ADAPTER_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif len(self.vic_adapter_warn_list):
                warn_report = self.consolidate_failure_msg(
                    self.vic_adapter_warn_list)
                warn_report = "WARNING : " + str(warn_report)
                self.set_validation_results(VIC_ADAPTER_CHK, status="PASS",
                                            err=str(warn_report))
                self.validation_report[VIC_ADAPTER_CHK] = "PASS" + \
                    "~" + str(warn_report)
            elif not self.vic_unsupported_vendor_list:
                self.set_validation_results(VIC_ADAPTER_CHK)
                self.validation_report[VIC_ADAPTER_CHK] = "PASS"

            # Display Intel NIC check results
            if "failed" not in self.intel_nic_failures_list \
                    and len(self.intel_nic_failures_list):
                failure_report = self.consolidate_failure_msg(
                    self.intel_nic_failures_list)
                self.set_validation_results(INTEL_NIC_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[INTEL_NIC_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif len(self.intel_nic_warn_list):
                warn_report = self.consolidate_failure_msg(
                    self.intel_nic_warn_list)
                warn_report = "WARNING : " + str(warn_report)
                self.set_validation_results(INTEL_NIC_CHK, status="PASS",
                                            err=str(warn_report))
                self.validation_report[INTEL_NIC_CHK] = "PASS" + \
                    "~" + str(warn_report)
            elif not self.intel_nic_failures_list:
                self.set_validation_results(INTEL_NIC_CHK)
                self.validation_report[INTEL_NIC_CHK] = "PASS"

            # Display Actual Boot Order check results
            if "failed" not in self.intel_boot_order_failures_list \
                    and len(self.intel_boot_order_failures_list):
                failure_report = self.consolidate_failure_msg(
                    self.intel_boot_order_failures_list)
                self.set_validation_results(INTEL_BOOT_ORDER_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[INTEL_BOOT_ORDER_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif len(self.intel_boot_order_warn_list):
                warn_report = self.consolidate_failure_msg(
                    self.intel_boot_order_warn_list)
                warn_report = "WARNING : " + str(warn_report)
                self.set_validation_results(INTEL_BOOT_ORDER_CHK,
                                            status="PASS",
                                            err=str(warn_report))
                self.validation_report[INTEL_NIC_CHK] = "PASS" + \
                    "~" + str(warn_report)
            elif not self.intel_boot_order_failures_list:
                self.set_validation_results(INTEL_BOOT_ORDER_CHK)
                self.validation_report[INTEL_BOOT_ORDER_CHK] = "PASS"

            if "failed" not in self.intel_boot_config_failures_list \
                    and len(self.intel_boot_config_failures_list):
                failure_report = self.consolidate_failure_msg(
                    self.intel_boot_config_failures_list)
                self.set_validation_results(INTEL_BOOT_CONFIG_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[INTEL_BOOT_CONFIG_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif not self.intel_boot_config_failures_list:
                self.set_validation_results(INTEL_BOOT_CONFIG_CHK)
                self.validation_report[INTEL_BOOT_CONFIG_CHK] = "PASS"

            if "failed" not in self.redfish_enabled_failures_list \
                    and len(self.redfish_enabled_failures_list):
                failure_report = self.consolidate_failure_msg(
                    self.redfish_enabled_failures_list)
                self.set_validation_results(REDFISH_CONFIG_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[REDFISH_CONFIG_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif not self.redfish_enabled_failures_list:
                self.set_validation_results(REDFISH_CONFIG_CHK)
                self.validation_report[REDFISH_CONFIG_CHK] = "PASS"

            if "failed" not in self.argus_nic_failures_list \
                    and len(self.argus_nic_failures_list):
                failure_report = self.consolidate_failure_msg(
                    self.argus_nic_failures_list)
                self.set_validation_results(ARGUS_NIC_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[ARGUS_NIC_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif not self.argus_nic_failures_list:
                self.set_validation_results(ARGUS_NIC_CHK)
                self.validation_report[ARGUS_NIC_CHK] = "PASS"

            if "failed" not in self.argus_disk_failures_list \
                    and len(self.argus_disk_failures_list):
                failure_report = self.consolidate_failure_msg(
                    self.argus_disk_failures_list)
                self.set_validation_results(ARGUS_DISK_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[ARGUS_DISK_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif self.argus_disk_uniformity and len(set(self.argus_disk_uniformity)) > 1:
                failure_report = "All Cvim-mon HA cluster nodes must have only all SSD or all HDD drives"
                self.set_validation_results(ARGUS_DISK_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[ARGUS_DISK_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif not self.argus_disk_failures_list:
                self.set_validation_results(ARGUS_DISK_CHK)
                self.validation_report[ARGUS_DISK_CHK] = "PASS"

            # Display Server IPMI status results
            if "failed" not in self.ipmi_status_failure_list \
                    and len(self.ipmi_status_failure_list):
                err_segment = "IPMI status Disabled on Server(s): " +  \
                    str(self.ipmi_status_failure_list) + ". Enable IPMI."
                self.set_validation_results(IPMI_STATUS_CHK, status='FAIL',
                                            err=err_segment)
                self.validation_report[IPMI_STATUS_CHK] = "FAIL" + "~" + err_segment
            elif not self.ipmi_status_failure_list:
                self.set_validation_results(IPMI_STATUS_CHK)
                self.validation_report[IPMI_STATUS_CHK] = "PASS"

            # Display Server IPMI encryption key results
            if "failed" not in self.ipmi_key_failure_list \
                    and len(self.ipmi_key_failure_list):
                failure_report = self.consolidate_failure_msg(
                    self.ipmi_key_failure_list)
                self.set_validation_results(IPMI_KEY_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[IPMI_KEY_CHK] = \
                    "FAIL" + "~" + str(failure_report)
            elif not self.ipmi_key_failure_list:
                self.set_validation_results(IPMI_KEY_CHK)
                self.validation_report[IPMI_KEY_CHK] = "PASS"

            # Display CISCO VNIC VLAN mode
            if "failed" not in self.cisco_vnic_vlan_mode_chk_fail_list \
                    and len(self.cisco_vnic_vlan_mode_chk_fail_list):
                err_segment = " VNIC VLAN Mode not in TRUNK on :" + \
                    str(self.cisco_vnic_vlan_mode_chk_fail_list)
                self.set_validation_results(VNIC_VLAN_MODE_CHK, status='FAIL',
                                            err=err_segment)
                self.validation_report[VNIC_VLAN_MODE_CHK] = "FAIL" + \
                    "~" + err_segment
            elif not self.cisco_vnic_vlan_mode_chk_fail_list:
                self.set_validation_results(VNIC_VLAN_MODE_CHK)
                self.validation_report[VNIC_VLAN_MODE_CHK] = "PASS"

            # Display boot order check results
            if "failed" not in self.pxe_boot_order_chk_fail_list \
                    and len(self.pxe_boot_order_chk_fail_list):
                failure_report = self.consolidate_failure_msg(
                    self.pxe_boot_order_chk_fail_list)
                self.set_validation_results(PXE_BOOT_ORDER_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[PXE_BOOT_ORDER_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif not self.pxe_boot_order_chk_fail_list:
                self.set_validation_results(PXE_BOOT_ORDER_CHK)
                self.validation_report[PXE_BOOT_ORDER_CHK] = "PASS"

            # Display LLDP status results
            if "failed" not in self.lldp_status_failure_list \
                    and len(self.lldp_status_failure_list):
                err_segment = "LLDP status 'Enabled' on Server(s): " + \
                    str(self.lldp_status_failure_list) + \
                    ". Enabled LLDP may prevent " + \
                    "inspector from getting correct information about " +\
                    "server to switch connection. 'Disable' LLDP."
                self.set_validation_results(LLDP_STATUS_CHK, status='FAIL',
                                            err=err_segment)
                self.validation_report[LLDP_STATUS_CHK] = "FAIL" + "~" + err_segment
            elif not self.lldp_status_failure_list:
                self.set_validation_results(LLDP_STATUS_CHK)
                self.validation_report[LLDP_STATUS_CHK] = "PASS"

            # Display GPU card check results
            if "failed" not in self.p_gpu_chk_fail_list \
                    and len(self.p_gpu_chk_fail_list):
                failure_report = self.consolidate_failure_msg(
                    self.p_gpu_chk_fail_list)
                self.set_validation_results(P_GPU_CARD_CHK, status='FAIL',
                                            err=str(failure_report))
                self.validation_report[P_GPU_CARD_CHK] = "FAIL" + \
                    "~" + str(failure_report)
            elif not self.p_gpu_chk_fail_list:
                self.set_validation_results(P_GPU_CARD_CHK)
                self.validation_report[P_GPU_CARD_CHK] = "PASS"

            # Display Foreign config results
            if "failed" not in self.cimc_foreign_chk_fail_list \
                    and len(self.cimc_foreign_chk_fail_list):
                err_segment = "Disk(s) with foreign config found on :" + \
                              str(self.cimc_foreign_chk_fail_list) + \
                              ". Clear the Foreign Config."
                self.set_validation_results(FOREIGN_CFG_CHK, status='FAIL',
                                            err=err_segment)
                self.validation_report[FOREIGN_CFG_CHK] = "FAIL" + "~" + err_segment
            elif not self.cimc_foreign_chk_fail_list:
                self.set_validation_results(FOREIGN_CFG_CHK)
                self.validation_report[FOREIGN_CFG_CHK] = "PASS"

        # Display CIMC API failure results
        if len(self.cimc_ssh_chk_fail_list):
            cons_report = self.consolidate_failure_msg(self.cimc_ssh_chk_fail_list)
            err_segment = "API Failures : " + \
                          str(cons_report)
            self.set_validation_results(CIMC_API_CHK, status='FAIL',
                                        err=err_segment)
            self.validation_report[CIMC_API_CHK] = "FAIL" + "~" + err_segment

        # Display Authentication Failures
        if len(self.auth_failure_list):
            err_segment = "Authentication Failed for: " + \
                          str(self.auth_failure_list) + \
                ". Provide Valid Credentials and retry the Hardware Validation"
            self.set_validation_results(SERVER_CHK, status='FAIL',
                                        err=err_segment)
            self.validation_report[SERVER_CHK] = "FAIL" + "~" + err_segment

        # Display unsupported hw failures
        if len(self.offline_hw_list):
            err_segment = "Offline Hardware found for " + \
                str(self.offline_hw_list) + "."
            self.set_validation_results(SERVER_CHK, status='FAIL',
                                        err=err_segment)
            self.validation_report[SERVER_CHK] = "FAIL" + "~" + err_segment

        # Common failures
        if len(self.common_failures_list):
            err_segment = "Unknown errors on " + \
                str(self.common_failures_list)
            self.set_validation_results(SERVER_CHK, status='FAIL',
                                        err=err_segment)
            self.validation_report[SERVER_CHK] = "FAIL" + "~" + err_segment

    def consolidate_failure_msg(self, failure_list):
        """
        Function to consolidate the failure messages
        """
        failure_msg = {}
        try:
            for f_msg in failure_list:
                hw_info = f_msg.split("--")[0]
                failure_reason = f_msg.split("--")[1]
                ip_list = failure_msg.get(failure_reason, None)
                if ip_list is None:
                    ip_list = []
                    ip_list.append(str(hw_info))
                    failure_msg[failure_reason] = ip_list
                else:
                    if str(hw_info) not in ip_list:
                        ip_list.append(str(hw_info))
                        failure_msg[failure_reason] = ip_list

        except Exception as e:
            self.log.error("Exception occurred at %s", e)

        return failure_msg

    def resolve_all_validation_failures(self, force_yes, input_host_list,
                                        feature_list, initial_check=True):
        """ Reoslve All Hardware Failures """

        proceed = True
        validate_again = False

        if not force_yes:
            proceed = self.enable_user_option_to_proceed("All")

        if proceed:
            hosts_list = self.get_host_lists(input_host_list)

            if initial_check:
                self.validate_hw_details(feature_list, hosts_list,
                                         self.ironic_validation)

            if len(self.cimc_ssh_chk_fail_list):
                self.log.debug("CIMC API failures found on servers %s", \
                               self.cimc_ssh_chk_fail_list)
                return

            if not self.ironic_validation and \
               any(x in feature_list for x in ['lom', 'all']):
                is_resolved = self.resolve_lom_port_failures(force_yes, hosts_list,
                                                             False)
                if is_resolved:
                    validate_again = True
                time.sleep(1)

            if not self.ironic_validation and \
               any(x in feature_list for x in ['hba', 'all']):
                is_resolved = self.resolve_hba_port_failures(force_yes, hosts_list,
                                                             False)
                if is_resolved and not validate_again:
                    validate_again = True
                time.sleep(1)
            if not self.ironic_validation and \
               any(x in feature_list for x in ['flexflash', 'all']):
                is_resolved = self.resolve_flexflash_failures(force_yes, hosts_list,
                                                              False)
                if is_resolved and not validate_again:
                    validate_again = True
                time.sleep(1)
            if not self.ironic_validation and \
               any(x in feature_list for x in ['pcie_slot', 'all']):
                is_resolved = self.resolve_pcie_adapter_slots_failures(force_yes,
                                                                       hosts_list,
                                                                       False)
                if is_resolved and not validate_again:
                    validate_again = True
                time.sleep(1)

            if any(x in feature_list for x in ['vnic_pxe_boot', 'all']):
                is_resolved = self.resolve_vnic_pxe_boot_failures(force_yes,
                                                                  hosts_list, False)
                if is_resolved and not validate_again:
                    validate_again = True
                time.sleep(1)

            if any(x in feature_list for x in ['power', 'all']):
                is_resolved = self.resolve_power_failures(force_yes, hosts_list,
                                                          False)
                if is_resolved and not validate_again:
                    validate_again = True
                time.sleep(1)

            if self.ironic_validation and \
               any(x in feature_list for x in ['vnic_vlan_mode', 'all']):
                is_resolved = self.resolve_vnic_vlan_mode_failures(force_yes,
                                                                   hosts_list,
                                                                   False)
                if is_resolved and not validate_again:
                    validate_again = True
                time.sleep(1)

            if self.ironic_validation and \
               any(x in feature_list for x in ['ipmi_key', 'all']):
                is_resolved = self.resolve_ipmi_en_key_failures(force_yes,
                                                                hosts_list,
                                                                False)
                if is_resolved and not validate_again:
                    validate_again = True
                time.sleep(1)

            if self.ironic_validation and \
               any(x in feature_list for x in ['ipmi_status', 'all']):
                is_resolved = self.resolve_ipmi_status_failures(force_yes,
                                                                hosts_list,
                                                                False)
                if is_resolved and not validate_again:
                    validate_again = True
                time.sleep(1)

            if self.ironic_validation and \
               any(x in feature_list for x in ['pxe_boot_order', 'all']):
                is_resolved = self.resolve_pxe_boot_order_failures(force_yes,
                                                                   hosts_list,
                                                                   False)
                if is_resolved and not validate_again:
                    validate_again = True
                time.sleep(1)

            if self.ironic_validation and \
               any(x in feature_list for x in ['lldp_status', 'all']):
                is_resolved = self.resolve_lldp_failures(force_yes,
                                                        hosts_list,
                                                        False)
                if is_resolved and not validate_again:
                    validate_again = True
                time.sleep(1)

            if self.ironic_validation and \
               any(x in feature_list for x in ['boot_config', 'all']):
                is_resolved = self.resolve_boot_config_failures(force_yes,
                                                                hosts_list,
                                                                False)
                if is_resolved and not validate_again:
                    validate_again = True
                time.sleep(1)


            # Verifying the actions
            if validate_again:
                self.log.info("Validating again after resolving the failures")
                self.clear_failure_lists()
                self.validate_hw_details(feature_list, hosts_list,
                                         self.ironic_validation)
            else:
                self.log.info("All configurations are already as expected " + \
                              "or resolve action might not be triggered due to " + \
                              "CIMC API failures.")
                return False

        return True

    def get_hw_validation_report(self):
        "Display final validation report in  JSON format"

        validation_types = ['Hardware Validation']
        val_results = {}
        ucase_results = {}
        json_dict = {}
        for key, value in self.validation_report.iteritems():
            """ Iterating over  consolidated dictionary to construct
             the sub dictionaries to form the nested JSON format """
            if not re.search(r'PASS', value):
                ucase_results['status'] = value.split("~")[0]
                ucase_results['reason'] = value.split("~")[1]
            else:
                ucase_results['status'] = value
                ucase_results['reason'] = 'None'
            val_results[key] = ucase_results
            ucase_results = {}

            overall_hw_result = self.check_validation_results()
            ucase_results['reason'] = 'None'
            if re.match(r'PASS', overall_hw_result['status']):
                ucase_results['status'] = "PASS"
            else:
                ucase_results['status'] = "FAIL"

            val_results['Overall_HW_Result'] = ucase_results

        """ Constructing dictionary as per nested json format """
        for v_type in validation_types:
            json_dict[v_type] = {}

        # Populating Hardware Validation results into json_dict
        for key, value in val_results.iteritems():
            json_dict['Hardware Validation'][key] = value

        return json_dict

    def get_resolve_failures_report(self):
        "Display final resolve failures report in  JSON format"

        validation_types = ['Resolve H/W Validation Failures']
        val_results = {}
        ucase_results = {}
        json_dict = {}
        for key, value in self.resolve_failures_report.iteritems():
            """ Iterating over  consolidated dictionary to construct
             the sub dictionaries to form the nested JSON format """
            if not re.search(r'PASS', value):
                ucase_results['status'] = value.split("~")[0]
                ucase_results['reason'] = value.split("~")[1]
            else:
                if len(value.split("~")) > 1:
                    ucase_results['status'] = value.split("~")[0]
                    ucase_results['reason'] = value.split("~")[1]
                else:
                    ucase_results['status'] = value
                    ucase_results['reason'] = 'None'

            val_results[key] = ucase_results

        """ Constructing dictionary as per nested json format """
        for v_type in validation_types:
            json_dict[v_type] = {}

        # Populating Hardware Validation results into json_dict
        for key, value in val_results.iteritems():
            json_dict['Resolve H/W Validation Failures'][key] = value


        return json_dict


    def get_host_lists(self, input_host_list):
        """
        Get the given input hosts list
        """
        hosts_list = []
        if input_host_list in ["None", None]:
            return None
        hosts = input_host_list.split(",")
        for host in hosts:
            if len(host) > 1:
                hosts_list.append(host)
        return hosts_list


    def get_host_names(self, input_host_list):
        """
        Get the given input hosts names
        """
        host_names = []
        if input_host_list in ["None", None]:
            if self.ironic_validation:
                host_names = self.ironic_yml_helper.get_server_list()
            else:
                host_names = self.ymlhelper.get_server_list()
            return host_names
        if type(input_host_list) is not list:
            hosts = input_host_list.split(",")
            for host in hosts:
                if len(host) > 1:
                    host_names.append(host)
            return host_names

        return input_host_list


    def get_hardware_type(self):
        '''
        Determine the Hardware type being validated against
        '''
        ipmi_check = None
        ucsc_check = self.ymlhelper.check_section_exists('CIMC-COMMON')
        ucsm_check = self.ymlhelper.check_section_exists('UCSMCOMMON')
        podtype = \
            self.ymlhelper.get_data_from_userinput_file(["PODTYPE"])
        if self.ironic_yml_helper:
            ipmi_check = self.ironic_yml_helper.check_section_exists('IPMI-COMMON')

        if ucsc_check and ucsm_check:
            self.log.error("Both CIMC-COMMON (for C-series) and " +\
                           "UCSMCOMMON for B series defined, Can't proceed")
            return "IncorrectInput"
        elif ucsc_check is not None:
            return "UCSC"
        elif ucsm_check is not None:
            return "UCSM"
        elif ipmi_check is not None:
            return "IPMI"
        elif podtype is not None and podtype == 'CVIMMONHA':
            return "CVIMMONHA"
        else:
            self.log.error("Neither CIMC-COMMON (for C-series) or " + \
                           "UCSMCOMMON for B series defined, Can't proceed")
            return "InvalidInput"

def run(run_args={}):
    '''
    Run method. Invoked from common runner.
    '''
    input_setupfileloc = None
    input_ironicfileloc = None
    try:
        err_str = ""
        if not re.match(r'None', run_args['setup_file_location']):
            input_setupfileloc = run_args['setup_file_location']
            if not os.path.isfile(input_setupfileloc):
                err_str = "Input file: " + input_setupfileloc + " doesn't exist"
            elif not os.access(input_setupfileloc, os.R_OK):
                err_str = "Input file: " + input_setupfileloc + " is not readable"

        if not re.match(r'None', run_args['ironic_file_location']):
            input_ironicfileloc = run_args['ironic_file_location']
            if not os.path.isfile(input_ironicfileloc):
                err_str = "Input file: " + input_ironicfileloc + " doesn't exist"
            elif not os.access(input_ironicfileloc, os.R_OK):
                err_str = "Input file: " + input_ironicfileloc + " is not readable"

        if len(err_str):
            validator = HWValidator()
            validator.set_validation_results(USER_ERROR, status='FAIL', \
                                             err=err_str)
            validator.display_validation_results()
            return
    except KeyError:
        input_setupfileloc = None

    standalone = True if run_args.get('standalone', None) else False
    validator = HWValidator(standalone, input_setupfileloc, run_args['target_ospd'],
                            run_args['ironic'], input_ironicfileloc)

    use_case_list = ['all']
    params = "all" if run_args.get('validate_of') is "None" else \
        run_args.get('validate_of')
    if not params == "all":
        use_case_list = params.split(",")

    if run_args['resolve_failures'] is "None":
        if run_args['hosts'] is "None":
            validator.validate_hw_details(use_case_list, None, run_args['ironic'])
        else:
            input_host_list = run_args['hosts']
            hosts_list = validator.get_host_lists(input_host_list)
            validator.validate_hw_details(use_case_list, hosts_list,
                                          run_args['ironic'])
    else:
        validator.resolve_hw_failures(run_args['resolve_failures'],
                                      run_args['force_yes'], run_args['hosts'])


    final_result = validator.check_validation_results()
    return final_result


def main(resolve_failures={}):
    '''
    Main.
    '''
    status = run(run_args=resolve_failures)
    return status


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="UCS Hardware Validations",
                                     formatter_class=argparse.RawTextHelpFormatter)
    reslv_help_string = "\n".join(["all - Fix all the failures. ",
                                   "lom - Fix LOM port(s) status failures. ", \
                                   "hba - Fix HBA port status failures. ", \
                                   "flexflash - Fix Flexflash failures. ", \
                                   "pcie_slot - Fix PCIe slot status failures. ", \
                                   "power - Fix Power failures.", \
                                   "vnic_pxe_boot - Fix Vnic PXE_Boot status" + \
                                   "failures",
                                   "vnic_vlan_mode - Fix VNIC Vlan mode " + \
                                   " failures [Applicable for Ironic Nodes]",
                                   "ipmi_key - Fix IPMI Key failures " + \
                                   "[Applicable for Ironic Nodes]",
                                   "ipmi_status - Fix IPMI status failures " + \
                                   "[Applicable for Ironic Nodes]",
                                   "pxe_boot_order - Fix PXE Boot order " + \
                                   " failures [Applicable for Ironic Nodes]",
                                   "lldp_status - Fix LLDP status failures " + \
                                   "[Applicable for Ironic Nodes]",
                                   "boot_config - Fix Boot Config failures " + \
                                   "[Applicable for Ironic Nodes]",
                                   "foreign_config - Clear Foreign config"])
    validate_help_string = "\n".join(["all - Validate all the features." + \
                                      " [default action]", \
                                      "firmware - Validate Firmware version", \
                                      "lom - Validate LOM port(s) status. ", \
                                      "hba - Validate HBA port status. ", \
                                      "flexflash - Validate Flexflash status. ", \
                                      "pcie_slot - Validate PCIe slot status. ", \
                                      "power - Validate Power status.", \
                                      "vnic_pxe_boot - Validate Vnic PXE_Boot" + \
                                      " status. ", \
                                      "physical_drives - Validate " + \
                                      " Physical drives status. ", \
                                      "nfv_config - Validate NFV configurations. ",
                                      "vic_adapter - Validate VIC Adapter details. ",
                                      "nw_adapter - Validate Intel NIC details. ",
                                      "intel_boot_order - Validate Intel NIC" + \
                                      " Boot-order. ",
                                      "gpu_card - Validate P-GPU Card details",
                                      "vnic_vlan_mode - Validate VNIC VLAN " + \
                                      "Mode [Applicable for Ironic nodes]",
                                      "ipmi_key - Validate IPMI Key " + \
                                      "[Applicable for Ironic nodes]",
                                      "ipmi_status - Validate IPMI Staus " + \
                                      "[Applicable for Ironic nodes]",
                                      "pxe_boot_order - Validate PXE Boot " + \
                                      "Order [Applicable for Ironic nodes]",
                                      "lldp_status - Validate LLDP Status " + \
                                      "[Applicable for Ironic nodes]",
                                      "boot_config - Validate Boot Config " + \
                                      "[Applicable for Ironic and CVIMMONHA nodes]"])
    feature_choices = ["lom", "hba", "flexflash", "pcie_slot",
                       "power", "vnic_pxe_boot", "all"]
    parser.add_argument("--resolve-failures", "-rf",
                        default="None",
                        dest="resolve_failures", help=reslv_help_string)
    parser.add_argument("--ospd", "-ospd",
                        action='store_true', default=False,
                        dest="target_ospd", help=argparse.SUPPRESS)

    parser.add_argument("--validate", "-v",
                        default="None",
                        dest="validate_of", help=validate_help_string)
    parser.add_argument("-y", "-yes", default=False, dest="force_yes",
                        action="store_true")
    parser.add_argument("--ironic-inventory", "-i",
                        action='store_true', default=False,
                        dest="ironic", help="validate ironic requiremnts")

    ''' Option to validate only specific servers '''
    parser.add_argument("--host", default="None", dest="hosts",
                        help="Comma separated list of hostnames")
    parser.add_argument("--file", "-f", dest="setup_file_location",
                        default="None", action='store',
                        help="Provide a valid 'setup_data.yaml' file")
    parser.add_argument("--ironic-inv-file", "-if", dest="ironic_file_location",
                        default="None", action='store',
                        help="Provide a valid 'ironic_inventory.yaml' file")

    input_args = {}
    args = parser.parse_args()
    input_args['resolve_failures'] = args.resolve_failures
    input_args['force_yes'] = args.force_yes
    input_args['standalone'] = "true"
    input_args['hosts'] = args.hosts
    input_args['setup_file_location'] = args.setup_file_location
    input_args['validate_of'] = args.validate_of
    input_args['target_ospd'] = args.target_ospd
    input_args['ironic'] = args.ironic
    input_args['ironic_file_location'] = args.ironic_file_location
    start = timeit.default_timer()
    main(input_args)
    end = timeit.default_timer()
    print "Total time taken (in sec): " + str((end - start))
