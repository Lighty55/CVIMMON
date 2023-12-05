#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
 Validations:
==============

Validations Module:
---------------------------------------
The First step to the to perform a validation on the user input
file. Will be used by runner, rest API and CiscoVIM

"""

import argparse
import os
import re
import sys
import yaml

sys.path.insert(1, os.path.dirname(\
    os.path.dirname(os.path.realpath(__file__))))

import clouddeploy.validations as validations
import clouddeploy.config_manager as config_manager
import utils.logger as logger
import utils.config_parser as config_parser
import utils.common as common

DEFAULT_CFG_DIR = "openstack-configs"
DEFAULT_SETUP_FILE = "setup_data.yaml"
BACKUP_SETUP_FILE = ".backup_setup_data.yaml"
COBBLER_DATA_YAML = ".cobbler_data.yaml"
SYSTEM_CFG_DIR = "system_configs"


class ValidationStatus(object):
    '''Class to return results'''

    def __init__(self, status, message):
        self.status = status
        self.message = message

class ValidatorUtils(object):
    '''
    Validator Utils class.
    '''

    def __init__(self, setupfileloc, loghandle=None):
        '''
        Initialize validator
        '''
        # ###############################################
        # Set up logging
        # ###############################################

        if loghandle is None:
            self.loginst = logger.Logger(name=__name__)
            self.log = self.loginst.get_logger()
        else:
            self.log = loghandle

        homedir = self.get_homedir()
        self.cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)
        cfgd = os.path.join("/bootstrap/", DEFAULT_CFG_DIR)
        if not os.path.exists(self.cfg_dir):
            os.symlink(os.getcwd() + cfgd, self.cfg_dir)
        if setupfileloc is not None:
            self.setup_file = setupfileloc
        else:
            self.setup_file = os.path.join(self.cfg_dir, DEFAULT_SETUP_FILE)

        self.backup_setup_file = os.path.join(self.cfg_dir, BACKUP_SETUP_FILE)
        self.cobbler_data_file = os.path.join(self.cfg_dir, COBBLER_DATA_YAML)

        if self.log is not None:
            self.log.debug("Utils Validator Initialized")

        self.cfgmgr = config_manager.ConfigManager(userinput=self.setup_file)
        self.ymlhelper = config_parser.YamlHelper(
            user_input_file=self.setup_file)

        self.podtype = self.ymlhelper.get_pod_type()

    def get_homedir(self):
        '''
        Get the current username
        '''
        homedir = os.path.expanduser("~")
        return homedir

    def get_installer_dir(self):
        """
        Get the Current Installer DIR PATH
        """
        return os.path.dirname(os.readlink("/root/openstack-configs"))

    def check_storage_multirole(self, server_string):
        ''' This method will return 1 if the storage node
        is part of compute node '''
        status = 0
        compute_info = self.ymlhelper.get_server_list(role='compute')
        server = server_string.split()
        for node in server:
            if node in compute_info:
                status = 1
        return status

    def remove_node_precheck(self, action, server_string, setup_data):
        '''
        Checks the failure scenarios for the remove compute or
        remove storage operations
        '''

        supported = ['compute', 'block_storage', 'cephosd']
        self.ymlhelper = config_parser.YamlHelper(\
            user_input_file=self.backup_setup_file)
        roles = self.ymlhelper.get_setup_data_property('ROLES')

        self.ymlhelper = config_parser.YamlHelper(\
            user_input_file=setup_data)
        servers = self.ymlhelper.get_setup_data_property('SERVERS')

        server_list = server_string.strip().split(",")

        # Check if the Servers to be removed still present in Setupdata
        remove_servers = server_string.strip().split(",")
        extra_servers = set(remove_servers) - set(servers.keys())
        existing_servers = set(remove_servers) - set(extra_servers)
        if existing_servers:
            msg = "Remove the server info from setupdata before deleting"
            return "ERROR : in %s for server(s) : %s : " \
                "%s" % (action, ','.join(existing_servers), msg)

        # Node not in backup_setup_data
        non_existing_node_list = []

        # Node in invalid_role
        invalid_role_node_list = []

        # Node not in backup_setup_data
        node_list_in_setup_data = []

        # Node in controller_list
        target_aio_node_list = []

        target_control_node_list = []
        target_control_compute_node_list = []
        target_cephcontrol_cephosd_node_list = []
        target_block_storage_node_list = []
        target_cdphosd_node_list = []
        target_hc_node_list = []

        for server in server_list:
            node = {}
            node_mtype_list = [role for role in roles.keys()
                               if roles[role] and server in roles[role]]
            if len(node_mtype_list) == 0:
                non_existing_node_list.append(server)

            if not set(node_mtype_list).intersection(set(supported)):
                invalid_role_node_list.append(server)

            node['mtype'] = ' '.join(node_mtype_list)
            if re.search(r'compute', node['mtype']) and \
                    re.search(r'control', node['mtype']) and \
                    re.search(r'block_storage', node['mtype']):
                target_aio_node_list.append(server)

            if re.search(r'compute', node['mtype']) and \
                    re.search(r'control', node['mtype']) and \
                    self.podtype == 'edge':
                target_control_compute_node_list.append(server)

            if re.search(r'cephcontrol', node['mtype']) and \
                    re.search(r'cephosd', node['mtype']) and \
                    self.podtype == 'ceph':
                target_cephcontrol_cephosd_node_list.append(server)

            if re.search(r'control', node['mtype']):
                target_control_node_list.append(server)

            if re.search(r'block_storage', node['mtype']) \
                    and (action == 'remove_computes'):
                target_block_storage_node_list.append(server)

            if re.search(r'cephosd', node['mtype']) \
                    and (action == 'remove_computes'):
                target_cdphosd_node_list.append(server)

            if re.search(r'compute', node['mtype']) and \
                    not re.search(r'block_storage', node['mtype']) and \
                    action == "remove_osd":
                target_hc_node_list.append(server)

            if server in servers.keys():
                node_list_in_setup_data.append(server)

            node_mtype_list = node['mtype'].split()
            if not set(node_mtype_list).intersection(set(supported)):
                if server not in invalid_role_node_list:
                    invalid_role_node_list.append(server)

        if node_list_in_setup_data:
            msg = "Remove the info from setupdata before deleting"
            return "ERROR : in %s for server(s) : %s : %s" \
                   % (action, ','.join(node_list_in_setup_data), msg)

        if non_existing_node_list:
            msg = "The Node is not existing in the pod."
            return "ERROR : in %s for server(s) : %s : %s " \
                   % (action, ','.join(non_existing_node_list), msg)

        if invalid_role_node_list:
            msg = "Only compute and block_storage " \
                "can be added/deleted presently"
            return "ERROR : in %s for server(s) : %s : %s " \
                   % (action, ','.join(invalid_role_node_list), msg)

        if target_aio_node_list:
            msg = "Node with AIO-role only supports replace of controller"
            return "ERROR : in %s for server(s) : %s : %s " \
                   % (action, ','.join(target_aio_node_list), msg)

        if target_control_compute_node_list:
            msg = "Node with control&compute-role only supports " \
                  "replace of controller"
            return "ERROR : in %s for server(s) : %s : %s " \
                   % (action, ','.join(target_control_compute_node_list), msg)

        if target_control_node_list:
            msg = "Remove Node Action with Node Type control is not allowed"
            return "ERROR : in %s for server(s) : %s : %s" \
                   % (action, ','.join(target_control_node_list), msg)

        if target_cephcontrol_cephosd_node_list:
            msg = "Node with cephcontrol&ccephosd-role only supports " \
                  "replace of controller"
            return "ERROR : in %s for server(s) : %s : %s " \
                   % (action, ','.join(server_list), msg)

        if target_block_storage_node_list:
            msg = "Remove Compute Node Action with Node Type block_storage " \
                  "is not allowed"
            return "ERROR : in %s for server(s) : %s : %s " \
                   % (action, ','.join(server_list), msg)

        if target_cdphosd_node_list:
            msg = "Remove Compute Node Action with Node Type ceph_osd " \
                  "is not allowed"
            return "ERROR : in %s for server(s) : %s : %s " \
                   % (action, ','.join(server_list), msg)

        if target_hc_node_list:
            msg = "Remove Storage Node Action with Node Type " \
                  "compute is not allowed"
            return "ERROR : in %s for server(s) : %s : %s" \
                   % (action, ','.join(server_list), msg)

        return "PASS: %s for server(s) : %s" % (action, server_string)

    def add_node_precheck(self, action, server_string, setup_data):
        '''
        Checks the failure scenarios for add computes or add storage operation
        '''

        supported = ['compute', 'block_storage', 'cephosd']
        self.ymlhelper = config_parser.YamlHelper(\
            user_input_file=setup_data)
        roles = self.ymlhelper.get_setup_data_property('ROLES')
        server_list = server_string.strip().split(",")
        self.ymlhelper = config_parser.YamlHelper(\
            user_input_file=self.backup_setup_file)

        servers = self.ymlhelper.get_setup_data_property('SERVERS')

        # Node not in setup_data
        non_existing_node_list = []

        # Node in invalid_role
        invalid_role_node_list = []

        # Node not in setup_data
        node_list_in_setup_data = []

        # Node in controller_list
        target_aio_node_list = []

        target_control_node_list = []
        target_control_compute_node_list = []
        target_cephcontrol_cephosd_node_list = []
        target_block_storage_node_list = []
        target_cdphosd_node_list = []
        target_hc_node_list = []
        target_add_osd_list = []

        # Check if the Servers to be added are present in Setupdata or not
        add_servers = server_string.strip().split(",")
        extra_servers = set(add_servers) - set(servers.keys())
        existing_servers = set(add_servers) - set(extra_servers)
        if existing_servers:
            msg = "The server already existing in the pod"
            return "ERROR : %s for server(s) : %s : " \
                "%s" % (action, ','.join(existing_servers), msg)

        for server in server_list:
            node = {}
            node_mtype_list = [role for role in roles.keys()
                               if roles[role] and server in roles[role]]
            if len(node_mtype_list) == 0:
                non_existing_node_list.append(server)

            if not set(node_mtype_list).intersection(set(supported)):
                invalid_role_node_list.append(server)

            node['mtype'] = ' '.join(node_mtype_list)
            if re.search(r'compute', node['mtype']) and \
                    re.search(r'control', node['mtype']) and \
                    re.search(r'block_storage', node['mtype']):
                target_aio_node_list.append(server)

            if re.search(r'compute', node['mtype']) and \
                    re.search(r'control', node['mtype']) and \
                    self.podtype == 'edge':
                target_control_compute_node_list.append(server)

            if re.search(r'cephcontrol', node['mtype']) and \
                    re.search(r'cephosd', node['mtype']) and \
                    self.podtype == 'ceph':
                target_cephcontrol_cephosd_node_list.append(server)

            if re.search(r'control', node['mtype']):
                target_control_node_list.append(server)

            if re.search(r'block_storage', node['mtype']) and \
                    action == "add_compute":
                target_block_storage_node_list.append(server)

            if re.search(r'cephosd', node['mtype']) and \
                    action == "add_compute":
                target_cdphosd_node_list.append(server)

            if re.search(r'compute', node['mtype']) and \
                    re.search(r'block_storage', node['mtype']) and \
                    action == "add_compute":
                target_hc_node_list.append(server)

            if re.search(r'compute', node['mtype']) and \
                    not re.search(r'block_storage', node['mtype']) and \
                    action == "add_osd":
                target_add_osd_list.append(server)

            if server in servers.keys():
                node_list_in_setup_data.append(server)

        if non_existing_node_list:
            msg = "The setupdata does not have the role for the server defined"
            return "ERROR : %s for server(s) : %s : %s" \
                   % (action, ','.join(non_existing_node_list), msg)

        if len(invalid_role_node_list):
            msg = "ERROR: Only compute, block_storage or cephosd can be added"
            return "ERROR : in %s for server(s) : %s : %s " \
                % (action, ','.join(invalid_role_node_list), msg)

        if len(target_aio_node_list):
            msg = "Node with AIO-role only supports replace of controller"
            return "ERROR : in %s for server(s) : %s : %s " \
                   % (action, ','.join(target_aio_node_list), msg)

        if len(target_control_compute_node_list):
            msg = "Node with control&compute-role only supports " \
                  "replace of controller"
            return "ERROR : in %s for server(s) : %s : %s " \
                   % (action, ','.join(target_control_compute_node_list), msg)

        if target_cephcontrol_cephosd_node_list:
            msg = "Node with cephcontrol&ccephosd-role only supports " \
                  "replace of controller"
            return "ERROR : %s for server(s) : %s : %s " \
                   % (action, ','.join(target_cephcontrol_cephosd_node_list), msg)

        if target_control_node_list:
            msg = "Add Node Action with Node Type control is not allowed"
            return "ERROR : Pre-check for %s on %s : %s " \
                   % (action, ','.join(target_control_node_list), msg)

        if target_block_storage_node_list:
            msg = "Add Compute Node Action with Node Type block_storage " \
                  "is not allowed"
            return "ERROR : %s for server(s) : %s : %s" \
                   % (action, ','.join(target_block_storage_node_list), msg)

        if target_cdphosd_node_list:
            msg = "Add Compute Node Action with Node Type ceph_osd " \
                  "is not allowed"
            return "ERROR : %s for server(s) : %s : %s" \
                % (action, ','.join(target_cdphosd_node_list), msg)

        if target_hc_node_list:
            msg = "Add Compute Node Action with Node Type block_storage " \
                  "is not allowed"
            return "ERROR : %s for server(s) : %s : %s" \
                   % (action, ','.join(target_hc_node_list), msg)

        if node_list_in_setup_data:
            msg = "The server already existing in the pod"
            return "ERROR : %s for server(s) : %s : %s" \
                   % (action, ','.join(node_list_in_setup_data), msg)

        if target_add_osd_list:
            msg = "Add Storage Node Action with Node Type " \
                "compute is not allowed"
            return "ERROR : %s for server(s) : %s : %s" \
                   % (action, ','.join(target_add_osd_list), msg)

        return "PASS: %s for server(s) : %s" % (action, server_string)

    def execute_action_precheck(self, action, server_string,
                                setup_data_info=None,
                                forceyes=False):
        '''Executes a particular function, against a server string'''

        status = 0

        ccp_action_list = ['ccp_orchestration', 'ccp_deletion', 'ccp_upgrade']

        if action in ccp_action_list:
            ret_info = self.ccp_validation_precheck(action, setup_data_info)
            if re.search(r'ERROR', ret_info):
                return ValidationStatus(status, ret_info)

        if re.search(r'add', action) and self.podtype != 'MGMT_CENTRAL':
            ret_info = self.add_node_precheck(action, server_string, setup_data_info)
            if re.search(r'ERROR', ret_info):
                return ValidationStatus(status, ret_info)

        if re.search(r'remove', action) and self.podtype != 'MGMT_CENTRAL':
            ret_info = self.remove_node_precheck(action,
                                                 server_string,
                                                 setup_data_info)
            if re.search(r'ERROR', ret_info):
                return ValidationStatus(status, ret_info)

        if re.search(r'power_on|power_off|reboot|power_status', action):
            ret_info = self.power_mgmt_pre_check(action, server_string, forceyes)

        if action == 'update':
            ret_info = self.power_compute_pre_check(action)

        if re.search(r'regenerate_secrets|setpassword|setopenstackconfigs'
                     r'|reconfigure', action):
            ret_info = self.power_compute_pre_check(action)
            if re.search(r'PASS', ret_info) and (action == "reconfigure"):
                ret_info = self.validate_reconfigure_tls(setup_data_info)
                if re.search(r'PASS', ret_info):
                    ret_info = self.reconfigure_pre_check(action, setup_data_info)

        if re.search(r'add|remove|replace|delete|nodelist', action):

            if action == 'remove_computes' and self.podtype != 'MGMT_CENTRAL':
                compute_info = self.ymlhelper.get_server_list(role='compute')
                tgt_compute_list = server_string.strip().split(",")
                powered_on_lo_compute = \
                    self.fetch_lo_power_on_status(compute_info, tgt_compute_list)
                if len(powered_on_lo_compute) == 0:
                    ret_info = "ERROR: %s of all compute server(s):%s " \
                        "not allowed, as that will leave the cloud inoperable" \
                        % (action, ','.join(tgt_compute_list))
                else:
                    ret_info = self.addreplace_node_pre_check(action,
                                                              server_string,
                                                              setup_data_info)

            elif action == 'remove_osd' and \
                    self.check_storage_multirole(server_string):
                compute_info = self.ymlhelper.get_server_list(role='compute')
                tgt_compute_list = server_string.strip().split(",")
                powered_on_lo_compute = \
                    self.fetch_lo_power_on_status(compute_info, tgt_compute_list)
                if len(powered_on_lo_compute) == 0:
                    ret_info = "ERROR: %s of all compute server(s):%s " \
                        "not allowed, as that will leave the cloud inoperable" \
                        % (action, ','.join(tgt_compute_list))
                else:
                    ret_info = \
                        self.addreplace_node_pre_check(action,
                                                       server_string,
                                                       setup_data_info)
            else:
                ret_info = self.addreplace_node_pre_check(action,
                                                          server_string,
                                                          setup_data_info)

        if re.search(r'reconfigure_cimc_password', action):
            ret_info = self.power_compute_pre_check(action)
            if re.search(r'PASS', ret_info):
                ret_info = self.reconfigure_cimc_password_pre_check(action,
                                                                    setup_data_info)

        if re.search(r'ERROR\(s\)\:', ret_info):
            status = 0
        else:
            status = 1

        return ValidationStatus(status, ret_info)

    def validate_reconfigure_tls(self, setup_data_info=None):
        '''
        Checks certificates are available if tls enabled true for reconfigure
        '''
        backup_tls_status = None
        setup_tls_status = None
        if not setup_data_info:
            setup_data_info = self.setup_file
        setup_yaml = config_parser.YamlHelper(\
            user_input_file=setup_data_info)
        setup_dict = setup_yaml.create_parsed_yaml(setup_data_info)
        if "external_lb_vip_tls" in setup_dict:
            setup_tls_status = \
                setup_yaml.get_data_from_userinput_file(["external_lb_vip_tls"])
            setup_tls_status = str(setup_tls_status).upper()
        ymlhelper = config_parser.YamlHelper(
            user_input_file=self.backup_setup_file)
        backup_dict = ymlhelper.create_parsed_yaml(self.backup_setup_file)
        if "external_lb_vip_tls" in backup_dict:
            backup_tls_status = \
                ymlhelper.get_data_from_userinput_file(["external_lb_vip_tls"])
            backup_tls_status = str(backup_tls_status).upper()

        if not backup_tls_status and not setup_tls_status:
            ret_info = "PASS : Reconfigure Validation"
        elif not backup_tls_status and setup_tls_status == "TRUE":
            ret_info = self.validate_tls_cert_check()
        elif backup_tls_status == "FALSE" and setup_tls_status == "TRUE":
            ret_info = self.validate_tls_cert_check()
        else:
            ret_info = "PASS : Reconfigure TLS Validation"

        return ret_info

    def validate_tls_cert_check(self):
        ''' Validates certs existence  '''
        try:
            missed_file = []
            openstack_conf = "/root/openstack-configs/openstack_config.yaml"
            openstack_yaml = config_parser.YamlHelper(\
                user_input_file=openstack_conf)
            openstack_dict = openstack_yaml.create_parsed_yaml(openstack_conf)
            if (("external_lb_vip_cacert" in openstack_dict) and \
                    ("external_lb_vip_cert" in openstack_dict)):
                cert_file = openstack_dict['external_lb_vip_cacert']
                pem_file = openstack_dict['external_lb_vip_cert']
                if not (os.path.exists(cert_file)):
                    missed_file.append(cert_file)
                if not (os.path.exists(pem_file)):
                    missed_file.append(pem_file)
                if len(missed_file):
                    msg = "ERROR: File(s) %s not found." % (' ,'.join(missed_file))
                    return msg
                else:
                    msg = "PASS : Pre-check of certs existence passed "
                    return msg
            else:
                msg = "ERROR: external_lb_vip_cacert and external_lb_vip_cert " \
                      "not found in the file %s " % (openstack_conf)
                return msg
        except:
            msg = "ERROR: Pre-check of Validation Failed"
            return msg

    def ccp_validation_precheck(self, action, setup_data_loc):
        """CCP Orchestration pre_check"""

        runargs = {}

        runargs['checkType'] = action
        runargs['testType'] = 'nonblocking'
        runargs['SetupFileLocation'] = setup_data_loc
        runargs['supressOutput'] = True

        retobj = validations.run(run_args=runargs)

        if retobj.get('status') == 'FAIL':
            return common.get_failinfo_from_json_output(retobj)

        return "PASS: Precheck for %s" % (action)

    def reconfigure_cimc_password_pre_check(self,
                                            action,
                                            setup_data_loc):
        '''reconfigure_cimc_password_pre_check'''

        runargs = {}

        runargs['checkType'] = 'static'
        runargs['testType'] = 'nonblocking'
        runargs['SetupFileLocation'] = setup_data_loc
        runargs['supressOutput'] = True

        runargs['action'] = 'reconfigure_cimc_password'

        retobj = validations.run(run_args=runargs)

        if retobj.get('status') == 'FAIL':
            return common.get_failinfo_from_json_output(retobj)

        return "PASS: Precheck for %s" % (action)

    def reconfigure_pre_check(self, action, setup_data_loc):
        """reconfigure_pre_check"""

        runargs = {}

        runargs['checkType'] = 'static'
        runargs['testType'] = 'nonblocking'
        runargs['SetupFileLocation'] = setup_data_loc
        runargs['supressOutput'] = True

        runargs['action'] = 'reconfigure'

        retobj = validations.run(run_args=runargs)

        if retobj.get('status') == 'FAIL':
            return common.get_failinfo_from_json_output(retobj)

        return "PASS: Precheck for %s" % (action)

    def addreplace_node_pre_check(self, action, server_string, setup_data_loc):
        '''Add/Replace check'''

        try:
            server_list = server_string.split(",")
        except AttributeError:
            server_list = []
        runargs = {}

        runargs['checkType'] = 'static'
        runargs['testType'] = 'nonblocking'
        runargs['SetupFileLocation'] = setup_data_loc
        runargs['supressOutput'] = True

        if action == 'add_compute':
            runargs['add_computes'] = server_list
        elif action == 'add_osds':
            runargs['add_osds'] = server_list
        elif action == 'replace_controller':
            runargs['replace_controller'] = server_list
        elif action == 'remove_computes':
            runargs['remove_computes'] = server_list
        elif action == 'remove_osd':
            runargs['remove_osd'] = server_list
        elif action == 'add_vms':
            runargs['add_vms'] = server_list
        elif action == 'delete_vms':
            runargs['delete_vms'] = server_list
        elif action == 'nodelist':
            runargs['nodelist'] = 'nodelist'

        retobj = validations.run(run_args=runargs)

        if retobj.get('status') == 'FAIL':
            return common.get_failinfo_from_json_output(retobj)

        return "PASS: Precheck for %s on %s" % (action, server_string)

    def power_compute_pre_check(self, action):
        '''Execute the power on precheck for all the compute servers
        If error will return string with ERROR'''

        ymlhelper = config_parser.YamlHelper(
            user_input_file=self.backup_setup_file)
        compute_info = ymlhelper.get_server_list(role='compute')
        cobbler_file = \
            config_parser.YamlHelper(user_input_file=self.cobbler_data_file)
        cobbler_file_dict = cobbler_file.create_parsed_yaml(self.cobbler_data_file)
        powered_cobbler_data = dict(cobbler_file_dict)
        powered_off_compute_list = []

        for server in compute_info:
            power_status = powered_cobbler_data[server].get('power_status')
            if power_status != 'on':
                powered_off_compute_list.append(server)

        if len(powered_off_compute_list):
            err_msg = "FAIL: pre-check of %s ," \
                " the servers %s in powered-off state " \
                % (action, ','.join(powered_off_compute_list))
            return err_msg

        msg = "PASS: pre-check of %s " % (action)
        return msg


    def fetch_lo_power_on_status(self, compute_info, tgt_compute_list):
        '''Fetch the list of leftover powered oncomputes'''
        lo_powered_on_compute_list = []
        cobbler_file = \
            config_parser.YamlHelper(user_input_file=self.cobbler_data_file)
        cobbler_file_dict = cobbler_file.create_parsed_yaml(self.cobbler_data_file)
        powered_cobbler_data = dict(cobbler_file_dict)

        for server in compute_info:
            if server not in tgt_compute_list and \
                    powered_cobbler_data[server].get('power_status') == "on":
                lo_powered_on_compute_list.append(server)

        return lo_powered_on_compute_list

    def fetch_pod_info(self, role, setup_data_file):
        ''' This function returns the pod info for the requested role '''
        node_info = []
        cfgmgr = config_manager.ConfigManager(userinput=setup_data_file)
        ymlhelper = config_parser.YamlHelper(\
            user_input_file=setup_data_file)

        node_info = ymlhelper.get_server_list(role=role)
        return node_info

    def power_mgmt_pre_check(self, action, server_string, force):
        """Execute the power on precheck for servers
        If error will return string with ERROR"""

        compute_info = self.fetch_pod_info('compute', self.backup_setup_file)
        controller_info = self.fetch_pod_info('control', self.backup_setup_file)
        ceph_info = self.fetch_pod_info('block_storage', self.backup_setup_file)

        compute_info_setup = self.fetch_pod_info('compute', self.setup_file)

        tgt_compute_list = server_string.strip().split(",")

        with open(self.backup_setup_file, 'r') as c:
            current_data = yaml.safe_load(c)

        if 'CIMC-COMMON' not in current_data:
            err_msg = "ERROR: Power Management or Reboot of Compute is allowed " \
                "only for C series."
            return err_msg

        if not compute_info and not compute_info_setup:
            return "ERROR: Compute info is missing from the pod data"

        for node in tgt_compute_list:
            if node not in compute_info_setup:
                err_msg = "ERROR: The Node %s is not part of the cloud. " \
                    % (node)
                return err_msg
            if node not in compute_info:
                err_msg = "ERROR: The Node %s is not part of the cloud. " \
                    % (node)
                return err_msg

        error_found = 0
        err_list = []
        invalid_compute_list = []
        unsupported_compute_list = []
        for item in tgt_compute_list:
            if item not in compute_info:
                invalid_compute_list.append(item)
            elif item in compute_info and \
                    (item in controller_info or item in ceph_info):
                unsupported_compute_list.append(item)

        if len(invalid_compute_list):
            error_found = 1
            err_msg = "ERROR: %s of server(s):%s not allowed," \
                " as it is not a valid compute node in the pod" \
                % (action, ','.join(invalid_compute_list))
            err_list.append(err_msg)

        if len(unsupported_compute_list) and action != "reboot":
            error_found = 1
            err_msg = "ERROR: %s of server(s):%s not allowed," \
                " as it is involved in multiple roles in the pod" \
                % (action, ','.join(unsupported_compute_list))
            err_list.append(err_msg)

        if len(unsupported_compute_list) > 1 and action == "reboot":
            error_found = 1
            err_msg = "ERROR: Simultaneous reboot of server(s):%s not allowed," \
                      " as they have multiple roles in cloud" \
                      % (','.join(unsupported_compute_list))
            err_list.append(err_msg)

        if action == "reboot" and sorted(compute_info) == sorted(tgt_compute_list)\
                and not force:
            error_found = 1
            err_msg = "ERROR: %s of all compute server(s):%s " \
                "not allowed, as that will leave the cloud inoperable" \
                % (action, ','.join(tgt_compute_list))
            err_list.append(err_msg)

        elif action == "power_off" and \
                sorted(compute_info) == sorted(tgt_compute_list):
            error_found = 1
            err_msg = "ERROR: %s of all compute server(s):%s " \
                "not allowed, as that will leave the cloud inoperable" \
                % (action, ','.join(tgt_compute_list))
            err_list.append(err_msg)

        elif action == "power_off" or action == "reboot":
            powered_on_lo_compute = \
                self.fetch_lo_power_on_status(compute_info, tgt_compute_list)

            if len(powered_on_lo_compute) == 0:
                error_found = 1
                err_msg = "ERROR: %s of all compute server(s):%s " \
                          "not allowed, as that will leave the cloud inoperable" \
                          % (action, ','.join(tgt_compute_list))
                err_list.append(err_msg)

        if error_found:
            err_info = '\n'.join(err_list)
            return err_info

        msg = "PASS: pre-check of %s for %s" \
              % (action, ','.join(tgt_compute_list))
        return msg


def run(run_args={}):
    '''
    Run method. Invoked from common runner.
    '''

    curr_setupfileloc = None
    try:
        if not re.match(r'NotDefined', run_args['SetupFileLocation']):
            err_str = ""
            input_file_chk = {}
            curr_setupfileloc = run_args['SetupFileLocation']
            if not os.path.isfile(curr_setupfileloc):
                err_str = "Input file: " + curr_setupfileloc + " does not exist"

            elif not os.access(curr_setupfileloc, os.R_OK):
                err_str = "Input file: " + curr_setupfileloc + \
                    " is not readable"

            if len(err_str):
                print err_str
                input_file_chk['status'] = "FAIL"
                return input_file_chk

    except KeyError:
        curr_setupfileloc = None

    except TypeError:
        curr_setupfileloc = None

    validator = ValidatorUtils(curr_setupfileloc)

    forceyes = False
    if run_args.get('force'):
        forceyes = True

    if not re.match(r'NotDefined', run_args['SetupFileLocation']):
        retStatus = \
            validator.execute_action_precheck(run_args['Action'],
                                              run_args['ServerInfo'],
                                              run_args['SetupFileLocation'],
                                              forceyes=forceyes)

    else:
        retStatus = \
            validator.execute_action_precheck(run_args['Action'],
                                              run_args['ServerInfo'],
                                              forceyes=forceyes)

    if 'EnableDebug' in run_args and run_args['EnableDebug']:
        print retStatus.status, retStatus.message
    return retStatus.status, retStatus.message


def main(check_type={}):
    '''
    Config Manager main.
    '''
    print "Validation Utils for setup_data"
    run(run_args=check_type)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Runner/RestAPI Validation")

    parser.add_argument("--setup_file_location", dest="SetupFileLocation",
                        default="NotDefined", help="setup file location")

    parser.add_argument("--action", dest="Action",
                        choices=["power_off", "power_on", "add_compute",
                                 "add_osds", "replace_controller",
                                 "remove_computes", "remove_osd",
                                 "reconfigure_cimc_password", "setpassword",
                                 "regenerate_secrets", "update",
                                 "power_status", "ccp_orchestration",
                                 "ccp_deletion", "ccp_upgrade", "reconfigure",
                                 "add_vms", "delete_vms", "nodelist"])

    parser.add_argument("--enable_debug", dest="EnableDebug",
                        action="store_true", default=False,
                        help="Enable Debug Flag")

    parser.add_argument("--server_info", dest="ServerInfo",
                        default=[],
                        help=", separated server string to act on")

    input_args = {}
    args = parser.parse_args()
    input_args['SetupFileLocation'] = args.SetupFileLocation
    input_args['Action'] = args.Action
    input_args['ServerInfo'] = args.ServerInfo
    input_args['EnableDebug'] = args.EnableDebug

    main(input_args)
