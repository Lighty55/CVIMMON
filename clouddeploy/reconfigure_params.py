#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""

Reconfigure Param Module:
---------------------------------------
Validates the basic sanity of secrets.yaml and openstack_config.yaml

"""
import argparse
import copy
import datetime
import json
import os
import re
import random
import string
import textwrap
import shutil
import subprocess
import prettytable
import yaml

from voluptuous import Schema, MultipleInvalid, Invalid
from voluptuous import All, In, Required, Optional, Boolean, Range
from Crypto.PublicKey import RSA
import OpenSSL.crypto as crypto
import utils.common as common
import utils.config_parser as config_parser
import utils.logger as logger

INSTALLER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CFG_DIR = "openstack-configs"
DEBUG_FILE = "openstack_config.yaml"
SECRETS_FILE = "secrets.yaml"
STAGING_SECRETS_FILE = "staging_secrets.yaml"
OPENSTACK_CFG_FILE = "openstack_config.yaml"
DEFAULT_SETUP_FILE = "setup_data.yaml"
BACKUP_SETUP_FILE = ".backup_setup_data.yaml"
OPENRC = "openrc"
NOVA_PUBLIC_KEY = DEFAULT_CFG_DIR + "/nova_public_key"
NOVA_PRIVATE_KEY = DEFAULT_CFG_DIR + "/nova_private_key"
VAULT_FILE = "/opt/cisco/vault/key.yaml"
RSA_KEY_SIZE = 4096

class ReconfigParams(object):
    '''
    ReconfigParams class.
    '''
    OPER_STAGE = "INIT"
    STAGE_COUNT = 0

    def __init__(self, userdefined_mem_ratio="Undefined",
                 userdefined_cpu_ratio="Undefined",
                 curr_action="install", skip_cloud_check=0):
        '''
        Initialize validator
        '''
        self.loginst = logger.Logger(name=__name__)
        self.log = self.loginst.get_logger()
        self.ymlhelper = None
        self.validation_results = []

        self.homedir = self.get_homedir()
        self.cfg_dir = os.path.join(self.homedir, DEFAULT_CFG_DIR)
        self.secrets_file = os.path.join(self.cfg_dir, SECRETS_FILE)
        self.staging_secrets_file = os.path.join(self.cfg_dir, STAGING_SECRETS_FILE)
        self.os_cfg_file = os.path.join(self.cfg_dir, OPENSTACK_CFG_FILE)
        self.setup_file = os.path.join(self.cfg_dir, DEFAULT_SETUP_FILE)
        self.backup_setup_file = os.path.join(self.cfg_dir, BACKUP_SETUP_FILE)
        self.openrc_file = os.path.join(self.cfg_dir, OPENRC)

        self.userdefined_mem_ratio = userdefined_mem_ratio
        self.userdefined_cpu_ratio = userdefined_cpu_ratio

        self.secrets_yaml = config_parser.YamlHelper(
            user_input_file=self.secrets_file)

        self.os_cfg_yaml = config_parser.YamlHelper(
            user_input_file=self.os_cfg_file)

        self.ymlhelper = config_parser.YamlHelper(
            user_input_file=self.setup_file)

        self.curr_action = curr_action
        self.skip_cloud_check = skip_cloud_check
        self.validation_results = []

    def get_homedir(self):
        '''
        Get the current username
        '''
        homedir = os.path.expanduser("~")
        return homedir

    def set_validation_results(self, name, status='PASS', err=None):
        '''
        Set the validations, for the rules.
        '''
        result = {}
        result['name'] = name
        result['err'] = err
        if status is 'PASS':
            status = "\033[92mPASS\033[0m"
        else:
            status = "\033[91mFAIL\033[0m"
        result['status'] = status
        self.validation_results.append(result)

    def display_validation_results(self):
        '''
        Print the validation results
        '''
        ptable = prettytable.PrettyTable(["Rule", "Status", "Error"])
        ptable.align["Rule"] = "l"
        ptable.align["Error"] = "l"

        for rule in self.validation_results:
            err_str = None
            if rule['err']:
                err_str = textwrap.fill(rule['err'].strip(), width=40)

            name_str = textwrap.fill(rule['name'].strip(), width=40)

            ptable.add_row([name_str, rule['status'], err_str])

        print "\n"
        print "  Management Node Validations!"
        print ptable


    def generate_validation_array(self):
        '''Generates the array for validation'''
        val_results = {}
        ucase_results = {}

        #Iterating over  consolidated dictionary to construct
        #the sub dictionaries to form the nested JSON format
        for rule in self.validation_results:
            ucase_results['reason'] = 'None'
            if rule['err']:
                ucase_results['status'] = "Fail"
                ucase_results['reason'] = rule['err']
            else:
                ucase_results['status'] = "Pass"
            key = rule['name']
            val_results[key] = ucase_results
            ucase_results = {}

        overall_sw_result = self.check_validation_results()
        ucase_results['reason'] = 'None'
        if re.match(r'PASS', overall_sw_result['status']):
            ucase_results['status'] = "PASS"
        else:
            ucase_results['status'] = "FAIL"
        val_results['Overall_BN_Result'] = ucase_results
        return val_results


    def get_validation_report_in_array(self):
        "Display final validation report in array format"

        validation_types = ['Management Node Validation']

        val_results = self.generate_validation_array()
        overall_dict = {}

        #Constructing JSON dictionary as per nested json format
        for v_type in validation_types:
            overall_dict[v_type] = {}

        #generate the sw validation array
        for key, value in val_results.iteritems():
            overall_dict['Management Node Validation'][key] = value

        return overall_dict

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

    def check_elk_rotation_size(self, input_str):
        '''Check the Log Size for Elk rotation'''

        err_str = ""
        if isinstance(input_str, int) or \
                isinstance(input_str, float):

            if input_str <= 0:
                err_str = "Input has to >= 0"
                raise Invalid(err_str)

            return err_str
        else:
            err_str = "Only input type of float/int is allowed"
            raise Invalid(err_str)

    def check_elk_rotation_del_older(self, input_str):
        '''
        Check the parameter which indicates the older logs to be deleted
        for Elk rotation
        '''

        err_str = ""
        if isinstance(input_str, int):
            if input_str <= 0:
                err_str = "Input has to be a non-zero positive number"
                raise Invalid(err_str)
        else:
            err_str = "Only input type of int is allowed"
            raise Invalid(err_str)
        return err_str

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
        return err_str

    def check_es_snapshot_autodelete_list(self, input_str):
        '''Check the parameters for the es_snapshot_autodelete feature'''
        es_ss_autodelete = Schema({
            Required('enabled'): All(Boolean(str),
                                     msg="Only Boolean (True/False) value allowed"),
            Required('period'):
                In(frozenset(["hourly", "daily", "weekly", "monthly"]), \
                msg="Frequency for checking space for ES snapshots"),
            Required('threshold_warning'): All(int, Range(min=1, max=99), \
                msg="Threshold to print warning message for ES snapshots"),
            Required('threshold_low'): All(int, Range(min=1, max=99), \
                msg="Threshold of disk space after deleting ES snapshots"),
            Required('threshold_high'): All(int, Range(min=1, max=99), \
                msg="Threshold of disk space to start deleting ES snapshots"),
        })

        err_list = []
        err_str = ""
        try:
            es_ss_autodelete(input_str)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))
        if err_list:
            err_str = ' '.join(err_list)
            raise Invalid(err_str)
        return err_str

    def is_tls_on(self):
        '''Check if tls is on in setup_data.yaml'''

        tls_status = \
            self.ymlhelper.get_data_from_userinput_file(["external_lb_vip_tls"])
        return tls_status


    def is_certificate_file(self, msg="not a valid certificate file"):
        """Verify the file is PEM format certificate."""
        def f(v):
            """validator to return"""

            tls_status = self.is_tls_on()
            if tls_status is None:
                return
            elif tls_status is False:
                return

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

    def is_ca_certificate_file(self, msg="not a valid CA certificate file"):
        """Verify the file is a CA certificate."""
        def f(v):
            """validator to return"""

            tls_status = self.is_tls_on()
            if tls_status is None:
                return
            elif tls_status is False:
                return

            if not os.path.isfile(v):
                raise Invalid(msg)
            try:
                pem = open(v, 'rt').read()
                crypto.load_certificate(crypto.FILETYPE_PEM, pem)
            except:
                raise Invalid(msg)
            return v
        return f


    def get_contents_of_file(self, file_path):
        '''Gets the contents of the file'''

        found_error = 0
        doc = {}
        with open(file_path, 'r') as f:
            try:
                doc = yaml.safe_load(f)
            except yaml.parser.ParserError as e:
                found_error = 1
            except yaml.scanner.ScannerError as e:
                found_error = 1
        f.close()

        if found_error:
            err_str = "Incorrect " + file_path + \
                      " syntax; Error Info: " + str(e)
            self.log.info(err_str)
            return "Invalid File Path"

        return doc

    @classmethod
    def _check_digit_char(cls, input_str):
        """
        This function checks that both Alphabets and Numeric Characters are
        present in Input String
        """
        return re.search(r'[a-zA-Z]', input_str) and \
            re.search(r'[0-9]', input_str)

    def check_secrets_validity(self, input_str):
        '''Check if the secret is valid'''

        input_str = str(input_str)

        err_str = "Only Alpha Numeric Characters for secrets allowed, " \
                  "and passwords must contain at least 1 letter, 1 digit, " \
                  "without whitespaces and length should be >=8 and <= 32"

        err_str_up = "Alpha Numeric Characters for secrets allowed, " \
            "and passwords must contain at least 1 letter, " \
            "without whitespaces and length should be >=8 and <= 32"

        if self.curr_action == 'regenerate_secrets':
            if not self._check_digit_char(input_str):
                raise Invalid(err_str)

            if not re.match(r'[a-zA-Z0-9]{8,32}$', input_str):
                raise Invalid(err_str)

        elif common.is_pod_upgraded():
            if not re.match('(?=.*[a-zA-Z]).{8,32}$', input_str):
                raise Invalid(err_str_up)

        else:
            if not self._check_digit_char(input_str):
                raise Invalid(err_str)

            if not re.match('[a-zA-Z0-9]{8,32}$', input_str):
                raise Invalid(err_str)

        return ""

    def check_horizon_secret_key_validity(self, input_str):
        '''Check if the horizon secret key is valid'''

        input_str = str(input_str)

        err_str = "Only Alpha Numeric Characters for secrets allowed, " \
                  "and passwords must contain at least 1 letter, " \
                  "1 digit, without whitespace and length should be 64 "

        if not self._check_digit_char(input_str):
            raise Invalid(err_str)

        if not re.match(r'[a-zA-Z0-9]{64}$', str(input_str)):
            raise Invalid(err_str)

        return ""

    def check_rabbitmq_erlang_secret_key_validity(self, input_str):
        '''Check if the horizon secret key is valid'''

        if not re.match(r'[A-Z]{20}$', str(input_str)):
            err_str = "RABBITMQ_ERLANG_COOKIE secret length should be 20, " \
                      "without whitespaces and Only UpperCase Characters for " \
                      "secrets allowed."
            raise Invalid(err_str)

        return ""

    def check_encryption_key_validity(self, input_str):
        '''Check if the AES encryption key is valid'''

        if not re.match(r'^[a-fA-F0-9]+$', str(input_str)):
            err_str = "Only hexidecimal Characters for secrets allowed"
            raise Invalid(err_str)
        elif len(str(input_str)) != 64:
            err_str = "Key length need to be 64 characters long"
            raise Invalid(err_str)

        return ""

    def check_mem_subs_ratio(self, target_info, target_ratio, server_name):
        '''Checks the Current Mem Subs Ratio against the proposed one'''

        over_subs_compute = {}
        int_lb_info = self.ymlhelper.get_data_from_userinput_file(\
            ['internal_lb_vip_ipv6_address'])
        via_v6 = 1
        if int_lb_info is None:
            int_lb_info = self.ymlhelper.get_data_from_userinput_file(
                ['internal_lb_vip_address'])
            via_v6 = 0
        server_target_info = \
            common.get_hypervisor_specific_info(server_name,
                                                target_info,
                                                int_lb_info,
                                                via_v6)

        if 'error' in server_target_info.keys():
            err_str = server_target_info['error']
            raise Invalid(err_str)

        curr_lhs_used = target_info + "_used"
        if curr_lhs_used in server_target_info.keys() and \
                server_target_info[curr_lhs_used] == "NotFound":
            err_str = "ERROR: %s not found for %s" % (curr_lhs_used, server_name)
            raise Invalid(err_str)

        elif target_info in server_target_info.keys() and \
                server_target_info[target_info] == "NotFound":
            err_str = "ERROR: %s not found for %s" % (target_info, server_name)
            raise Invalid(err_str)

        elif curr_lhs_used not in server_target_info.keys():
            err_str = "ERROR: %s not found for %s" % (curr_lhs_used, server_name)
            raise Invalid(err_str)

        elif target_info not in server_target_info.keys():
            err_str = "ERROR: %s not found for %s" % (target_info, server_name)
            raise Invalid(err_str)

        actual_target_usage_ratio = \
            float(server_target_info[curr_lhs_used]) \
            / float(server_target_info[target_info])

        if float(actual_target_usage_ratio) > float(target_ratio):
            over_subs_compute[server_name] = float(actual_target_usage_ratio)

        return over_subs_compute

    def nova_cpu_oversubs_ratio_check(self, input_str):
        '''Check if CPU Oversubscription ratio can be changed'''

        if str(self.userdefined_cpu_ratio) != "Undefined":
            input_str = self.userdefined_cpu_ratio
            if re.search(r'.', input_str):
                input_str = float(input_str)
            else:
                input_str = int(input_str)

        if type(input_str) == int or type(input_str) == float:
            pass
        else:
            err_str = "Input %s has to be of type int/float" % (input_str)
            raise Invalid(err_str)

        if float(input_str) < 0.958 or float(input_str) > 16.0:
            err_str = "Input can range from 0.958 to 16.0, " \
                      "found to be %s" % (input_str)
            raise Invalid(err_str)

    def nova_ram_subs_ratio_check(self, input_str):
        '''Check if the Nova mem subs ratio can be changed'''

        if str(self.userdefined_mem_ratio) != "Undefined":
            input_str = self.userdefined_mem_ratio
            if re.search(r'.', input_str):
                input_str = float(input_str)
            else:
                input_str = int(input_str)

        if type(input_str) == int or type(input_str) == float:
            pass
        else:
            err_str = "Input %s has to be of type int/float" % (input_str)
            raise Invalid(err_str)

        if float(input_str) < 1.0 or float(input_str) > 4.0:
            err_str = "Input can range from 1.0 to 4.0, " \
                "found to be %s" % (input_str)
            raise Invalid(err_str)

    def validate_schema(self, schema_type, validate_new_secrets={}, \
                        validate_new_cfg={}, return_type="status"):
        '''Validates yaml content'''

        get_secrets = {}
        if re.search(r'secrets', schema_type) and not len(validate_new_secrets):
            get_secrets = self.get_contents_of_file(self.secrets_file)

        elif re.search(r'new_cfg', schema_type) and not len(validate_new_cfg):
            get_cur_os_cfg = self.get_contents_of_file(self.os_cfg_file)

        if self.ymlhelper.get_pod_type() == 'ceph':
            secrets_schema = Schema({
                Required('COBBLER_PASSWORD'): self.check_secrets_validity,
                Required('CPULSE_DB_PASSWORD'): self.check_secrets_validity,
                Required('KIBANA_PASSWORD'): self.check_secrets_validity,
                Optional('CVIM_MON_PASSWORD'): self.check_secrets_validity,
                Optional('CVIM_MON_SERVER_PASSWORD'): self.check_secrets_validity,
                Optional('CVIM_MON_PROXY_PASSWORD'): self.check_secrets_validity,
                Optional('CVIM_MON_READ_ONLY_PASSWORD'): self.check_secrets_validity,
                Optional('CALIPSO_MONGO_SERVICE_PWD'): self.check_secrets_validity,
                Optional('CALIPSO_API_SERVICE_PWD'): self.check_secrets_validity,
            })
        else:
            secrets_schema = Schema({
                Required('CINDER_DB_PASSWORD'): self.check_secrets_validity,
                Required('CINDER_KEYSTONE_PASSWORD'): self.check_secrets_validity,
                Required('CLOUDPULSE_KEYSTONE_PASSWORD'):
                    self.check_secrets_validity,
                Required('COBBLER_PASSWORD'): self.check_secrets_validity,
                Required('CPULSE_DB_PASSWORD'): self.check_secrets_validity,
                Required('DB_ROOT_PASSWORD'): self.check_secrets_validity,
                Required('KIBANA_PASSWORD'): self.check_secrets_validity,
                Required('GLANCE_DB_PASSWORD'): self.check_secrets_validity,
                Required('GLANCE_KEYSTONE_PASSWORD'): self.check_secrets_validity,
                Required('HAPROXY_PASSWORD'): self.check_secrets_validity,
                Optional('HEAT_DB_PASSWORD'): self.check_secrets_validity,
                Optional('HEAT_KEYSTONE_PASSWORD'): self.check_secrets_validity,
                Optional('HEAT_STACK_DOMAIN_ADMIN_PASSWORD'): \
                self.check_secrets_validity,
                Optional('MAGNUM_DB_PASSWORD'): self.check_secrets_validity,
                Optional('MAGNUM_KEYSTONE_PASSWORD'): self.check_secrets_validity,
                Optional('MAGNUM_DOMAIN_ADMIN_PASSWORD'):
                    self.check_secrets_validity,
                Optional('KEYSTONE_ADMIN_TOKEN'): self.check_secrets_validity,
                Required('KEYSTONE_DB_PASSWORD'): self.check_secrets_validity,
                Required('METADATA_PROXY_SHARED_SECRET'):
                    self.check_secrets_validity,
                Required('NEUTRON_DB_PASSWORD'): self.check_secrets_validity,
                Required('NEUTRON_KEYSTONE_PASSWORD'): self.check_secrets_validity,
                Required('NOVA_DB_PASSWORD'): self.check_secrets_validity,
                Optional('IRONIC_DB_PASSWORD'): self.check_secrets_validity,
                Optional('IRONIC_INSPECTOR_DB_PASSWORD'):
                    self.check_secrets_validity,
                Required('NOVA_KEYSTONE_PASSWORD'): self.check_secrets_validity,
                Optional('IRONIC_KEYSTONE_PASSWORD'): self.check_secrets_validity,
                Required('RABBITMQ_ERLANG_COOKIE'):
                    self.check_rabbitmq_erlang_secret_key_validity,
                Optional('IRONIC_INSPECTOR_KEYSTONE_PASSWORD'): \
                    self.check_secrets_validity,
                Required('RABBITMQ_PASSWORD'): self.check_secrets_validity,
                Required('WSREP_PASSWORD'): self.check_secrets_validity,
                Optional('ETCD_ROOT_PASSWORD'): self.check_secrets_validity,
                Optional('VPP_ETCD_PASSWORD'): self.check_secrets_validity,
                Required('ADMIN_USER_PASSWORD'): self.check_secrets_validity,
                Required('HORIZON_SECRET_KEY'):
                    self.check_horizon_secret_key_validity,
                Optional('CEILOMETER_DB_PASSWORD'): self.check_secrets_validity,
                Optional('CEILOMETER_KEYSTONE_PASSWORD'):
                    self.check_secrets_validity,
                Optional('CVIM_MON_PASSWORD'): self.check_secrets_validity,
                Optional('CVIM_MON_SERVER_PASSWORD'): self.check_secrets_validity,
                Optional('CVIM_MON_PROXY_PASSWORD'): self.check_secrets_validity,
                Optional('CVIM_MON_READ_ONLY_PASSWORD'): self.check_secrets_validity,
                Optional('CALIPSO_MONGO_SERVICE_PWD'): self.check_secrets_validity,
                Optional('CALIPSO_API_SERVICE_PWD'): self.check_secrets_validity,
                Optional('GNOCCHI_DB_PASSWORD'): self.check_secrets_validity,
                Optional('GNOCCHI_KEYSTONE_PASSWORD'): self.check_secrets_validity,
                Required('VOLUME_ENCRYPTION_KEY'):
                    self.check_encryption_key_validity,
            })

        os_cfg_schema = Schema({
            Optional('HEAT_VERBOSE_LOGGING'): All(Boolean(str),
                                                  msg="Only Boolean value \
                                                  True/False allowed"),
            Optional('OCTAVIA_DEBUG_LOGGING'): All(Boolean(str), \
                                                msg="Only Boolean value \
                                            True/False allowed"),
            Optional('OCTAVIA_VERBOSE_LOGGING'): All(Boolean(str),
                                                  msg="Only Boolean value \
                                                      True/False allowed"),
            Optional('HEAT_DEBUG_LOGGING'): All(Boolean(str), \
                                                msg="Only Boolean value \
                                                True/False allowed"),
            Optional('MAGNUM_VERBOSE_LOGGING'): All(Boolean(str),
                                                    msg="Only Boolean value \
                                                    True/False allowed"),
            Optional('MAGNUM_DEBUG_LOGGING'): All(Boolean(str), \
                                                  msg="Only Boolean value \
                                                  True/False allowed"),
            Required('GLANCE_VERBOSE_LOGGING'): All(Boolean(str), \
                                                    msg="Only Boolean value \
                                                    True/False allowed"),
            Required('GLANCE_DEBUG_LOGGING'): All(Boolean(str), \
                                                  msg="Only Boolean value \
                                                  True/False allowed"),
            Required('CINDER_VERBOSE_LOGGING'): All(Boolean(str), \
                                                    msg="Only Boolean value \
                                                    True/False allowed"),
            Required('CINDER_DEBUG_LOGGING'): All(Boolean(str), \
                                                  msg="Only Boolean value \
                                                  True/False allowed"),
            Required('NOVA_VERBOSE_LOGGING'): All(Boolean(str), \
                                                  msg="Only Boolean value \
                                                  True/False allowed"),
            Required('NOVA_DEBUG_LOGGING'): All(Boolean(str), \
                                                msg="Only Boolean value \
                                                True/False allowed"),
            Required('NEUTRON_VERBOSE_LOGGING'): All(Boolean(str), \
                                                     msg="Only Boolean value \
                                                     True/False allowed"),
            Required('NEUTRON_DEBUG_LOGGING'): All(Boolean(str), \
                                                   msg="Only Boolean value \
                                                   True/False allowed"),
            Required('KEYSTONE_VERBOSE_LOGGING'): All(Boolean(str), \
                                                      msg="Only Boolean value \
                                                      True/False allowed"),
            Required('KEYSTONE_DEBUG_LOGGING'): All(Boolean(str), \
                                                    msg="Only Boolean value \
                                                    True/False allowed"),
            Required('CLOUDPULSE_VERBOSE_LOGGING'): All(Boolean(str), \
                                                        msg="Only Boolean value \
                                                        True/False allowed"),
            Required('CLOUDPULSE_DEBUG_LOGGING'): All(Boolean(str), \
                                                      msg="Only Boolean value \
                                                      True/False allowed"),
            Required('IRONIC_VERBOSE_LOGGING'): All(Boolean(str), \
                                                  msg="Only Boolean value \
                                                  True/False allowed"),
            Required('IRONIC_DEBUG_LOGGING'): All(Boolean(str), \
                                                msg="Only Boolean value \
                                                True/False allowed"),
            Optional('OPFLEX_DEBUG_LOGGING'):
                All(Boolean(str), msg="Only Boolean value True/False allowed"),
            Optional('AIM_DEBUG_LOGGING'):
                All(Boolean(str), msg="Only Boolean value True/False allowed"),
            Optional('CEILOMETER_VERBOSE_LOGGING'): All(Boolean(str), \
                                                        msg="Only Boolean value \
                                                        True/False allowed"),
            Optional('CEILOMETER_DEBUG_LOGGING'): All(Boolean(str), \
                                                      msg="Only Boolean value \
                                                      True/False allowed"),
            Optional('LOGGING_FORMAT_PLAIN'): All(Boolean(str), \
                   msg="Only Boolean value True/False allowed"),
            Optional('LOGGING_FORMAT_JSON'): All(Boolean(str), \
                   msg="Only Boolean value True/False allowed"),
            Required('elk_rotation_frequency'):
                In(frozenset(["daily", "weekly", "fortnightly", "monthly"]),
                   msg='only daily, weekly, fortnightly, or monthly allowed'),
            Required('elk_rotation_size'): self.check_elk_rotation_size,
            Required('elk_rotation_del_older'): self.check_elk_rotation_del_older,
            Required('log_rotation_frequency'):
                In(frozenset(["daily", "weekly", "monthly", "yearly"]),
                   msg='only daily, weekly, monthly or yearly allowed'),
            Required('log_rotation_size'): self.check_log_rotation_size,
            Required('log_rotation_del_older'): self.check_log_rotation_del_older,
            Required('ES_SNAPSHOT_AUTODELETE'): \
                self.check_es_snapshot_autodelete_list,
            Required('external_lb_vip_cert'): All(str, self.is_certificate_file()),
            Required('external_lb_vip_cacert'): \
                All(str, self.is_ca_certificate_file()),
            Required('NOVA_RAM_ALLOCATION_RATIO'): self.nova_ram_subs_ratio_check,
            Required('NOVA_CPU_ALLOCATION_RATIO'): \
                self.nova_cpu_oversubs_ratio_check,
            Optional('GNOCCHI_VERBOSE_LOGGING'): All(Boolean(str), \
                   msg="Only Boolean value True/False allowed"),
            Optional('GNOCCHI_DEBUG_LOGGING'): All(Boolean(str), \
                   msg="Only Boolean value True/False allowed"),
        })

        err_list = []
        ks_config = ""

        my_tag = ""
        # common validation
        try:
            if re.search(r'secrets', schema_type):
                ks_config = "Reconfigure Password"
                my_tag = self.secrets_file
                if not validate_new_secrets:
                    info_str = "Validating " + schema_type + " for " + \
                               str(get_secrets)
                    secrets_schema(get_secrets)
                else:
                    info_str = "Validating " + schema_type + " for " + \
                               str(validate_new_secrets)
                    secrets_schema(validate_new_secrets)

            elif re.search(r'new_cfg', schema_type):
                ks_config = "Set OS Config Option"
                my_tag = self.os_cfg_file
                if not validate_new_cfg:
                    info_str = "Validating " + schema_type + " for " + \
                               str(get_cur_os_cfg)
                    self.log.info(info_str)
                    os_cfg_schema(get_cur_os_cfg)
                else:
                    info_str = "Validating " + schema_type + " for " + \
                               str(validate_new_cfg)
                    self.log.info(info_str)
                    os_cfg_schema(validate_new_cfg)
        except MultipleInvalid as e:
            for x in e.errors:
                err_list.append(str(x))

        if re.match(r'list', return_type):
            if validate_new_cfg or validate_new_secrets:
                return err_list
            elif err_list:
                msg_str = " Error in file " + my_tag
                err_list.append(msg_str)
            return err_list

        if err_list:
            err_str = " ::".join(err_list)
            self.set_validation_results(ks_config,
                                        status='FAIL',
                                        err=err_str)
            self.log.info(err_str)
            return False
        else:
            self.set_validation_results(ks_config)
            return True

    def allow_reconfigure(self):
        '''check to allow reconfigure post update'''
        cfgd = INSTALLER_DIR + '/' + DEFAULT_CFG_DIR
        update_file = cfgd + '/' + "update.yaml"
        if os.path.isfile(update_file):
            print ""
            print "ERROR: Update has been performed from this workspace."
            print "You can only perform this operation after commit or rollback"
            print ""
            return False

        return True

    def reconfigure_selected_items(self, schema_type, secret_entry={}, \
                                   new_cfg_entry={}):
        '''Reconfigure selected secrets or debug configs'''

        error_found = 0
        err_str = ""

        get_curr_content = {}

        if not self.allow_reconfigure():
            return False

        # check if is one of the 2 categories
        if not re.search(r'.*secrets.*|.*new_cfg.*', schema_type):
            err_str = "Schema Type of secrets or new_cfg only support"
            error_found = 1
        elif re.search(r'secrets', schema_type) and not secret_entry:
            err_str = "Info associated to new secrets to change not available"
            error_found = 1
        elif re.search(r'new_cfg', schema_type) and not new_cfg_entry:
            err_str = "Info associated to new_cfg change not available"
            error_found = 1

        if error_found:
            self.log.info(err_str)
            return False

        now = datetime.datetime.now()
        curr_time = now.strftime("%Y-%m-%d-%H-%M-%S")

        # back up the old files
        change_request_info = {}
        if re.search(r'secrets', schema_type):
            curr_file_name = self.secrets_file
            target_file_name = self.staging_secrets_file
            backup_sec_file = "/backup_secrets.yaml" + "-" + str(curr_time)
            backup_file_path = self.cfg_dir + backup_sec_file
            change_request_info = copy.deepcopy(secret_entry)
        elif re.search(r'new_cfg', schema_type):
            curr_file_name = self.os_cfg_file
            backup_file_path = self.cfg_dir + "/.backup_os_cfg.yaml"
            change_request_info = copy.deepcopy(new_cfg_entry)

        # get the current info
        get_curr_content = self.get_contents_of_file(curr_file_name)

        # Delete old files
        if re.search(r'secrets', schema_type):
            pattern = "backup_secrets.yaml"
            num_files_to_keep = 3
            self.del_old_files(self.cfg_dir, pattern, num_files_to_keep)
        else:
            if os.path.isfile(backup_file_path):
                rm_cmd = subprocess.Popen(['/usr/bin/rm', '-rf', backup_file_path], \
                                          stdout=subprocess.PIPE, \
                                          stderr=subprocess.PIPE)
                rm_cmd.communicate()

        # backup the original file
        umask_orig = os.umask(0077)
        shutil.copyfile(curr_file_name, backup_file_path)
        os.umask(umask_orig)

        # generate the new info
        for key_to_find, value_to_replace in change_request_info.iteritems():
            if isinstance(value_to_replace, dict):
                value_to_replace = json.dumps(value_to_replace)
            for key in get_curr_content.keys():
                if re.search(r'secrets', schema_type):
                    if not re.search('VTS', key) and key == key_to_find \
                            and len(value_to_replace) > 2:
                        get_curr_content[key] = value_to_replace
                else:
                    if key == key_to_find:
                        get_curr_content[key] = value_to_replace

        # validate the schema and dump it to a file
        gen_schema_status = self.validate_schema(schema_type, get_curr_content)
        if gen_schema_status:
            if re.search(r'secrets', schema_type):
                curr_file_name = target_file_name

            with open(curr_file_name, 'w') as outfile:
                for key in sorted(get_curr_content):
                    outfile.write(str(key) + ": " + \
                                  str(get_curr_content[key]) + "\n")
#                outfile.write(yaml.dump(get_curr_content, default_flow_style=False))
            return True
        else:
            log_str = "schema validation failed for " + schema_type
            self.log.info(log_str)
            return False

    def generate_nova_ssh_keys(self):
        '''
        Generates RSA key-pair
        '''
        new_key = RSA.generate(RSA_KEY_SIZE, os.urandom)
        private_key = new_key.exportKey("PEM")
        public_key = new_key.publickey().exportKey("OpenSSH")
        with open(os.path.join(self.homedir, NOVA_PUBLIC_KEY), "w") as f:
            f.write(public_key)
        with open(os.path.join(self.homedir, NOVA_PRIVATE_KEY), "w") as f:
            f.write(private_key)

    def generate_secrets(self, size):
        '''
        Generate secrets
        '''

        chars = string.digits + string.ascii_letters

        for _ in range(100):
            secret = ''.join(random.choice(chars) for _ in range(size))   # nosec
            if re.match('^(?=.*\d)(?=.*[a-zA-Z]).{8,}$', secret):
                break

        return secret

    def generate_erlang_cookie(self, size):
        '''
        Generates Random erlang cookie for Rabbitmq
        '''
        chars = string.ascii_letters
        return ''.join(random.choice(chars).upper() for _ in range(size))   # nosec

    def del_old_files(self, path, pattern, num_files_to_keep):
        '''Delete old file from a dir, takes in a pattern and path
        Deletes a specific # of files'''

        self.log.info("Keeping last %s secret backup files @ %s",
                      num_files_to_keep, path)
        file_list = []
        for i in os.listdir(path):
            if os.path.isfile(os.path.join(path, i)) and pattern in i:
                file_list.append(i)

        if len(file_list) <= num_files_to_keep:
            return

        num_files_to_del = len(file_list) - num_files_to_keep
        self.log.info("Found %s secret backup files, will delete %s",
                      len(file_list), num_files_to_del)

        curr_count = 0
        for item in file_list:
            if curr_count < num_files_to_del:
                name_with_path = path + "/" + item
                self.log.info("Deleting %s; %s/%s",
                              name_with_path,
                              str((curr_count + 1)),
                              num_files_to_del)
                os.remove(name_with_path)
                curr_count += 1

        return

    def regenerate_all_secrets(self):
        '''Reconfigure all secrets'''

        if not self.allow_reconfigure():
            return False

        vault_config = self.ymlhelper.get_vault_info()

        if vault_config and vault_config['enabled']:
            with open(self.backup_setup_file, 'r') as f:
                backup_setup_data = yaml.safe_load(f)
            vault_backup_info = backup_setup_data.get('VAULT', None)
            if not vault_backup_info or not vault_backup_info['enabled']:
                self.log.error("Enabling Vault and Reconfigure regenerate "
                               "secrets cannot be perform together")
                return False

        if not vault_config or not vault_config['enabled']:
            now = datetime.datetime.now()
            curr_time = now.strftime("%Y-%m-%d-%H-%M-%S")

            # Delete old files
            pattern = "backup_secrets.yaml"
            num_files_to_keep = 3
            self.del_old_files(self.cfg_dir, pattern, num_files_to_keep)

            # backup the original file
            curr_file_name = self.secrets_file
            backup_sec_file = "/backup_secrets.yaml" + "-" + str(curr_time)
            backup_file_path = self.cfg_dir + backup_sec_file
            shutil.copyfile(curr_file_name, backup_file_path)

        gen_secrets_file = "/opt/cisco/scripts/generate_secrets.py"
        if not os.path.isfile(gen_secrets_file):
            return False
        cmd = ["python", gen_secrets_file, "--regen_secrets"]
        sproc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
        try:
            _ = sproc.stdout.read()
        except subprocess.CalledProcessError:
            self.log.error("Generate secrets script failed")
            return False
        return True

    def generate_optional_svcs_secret(self):
        """
        Generate secrets if optional services are enabled
        """
        if not self.allow_reconfigure():
            return False

        vault_config = self.ymlhelper.get_vault_info()
        if vault_config and vault_config['enabled']:
            with open(self.backup_setup_file, 'r') as f:
                backup_setup_data = yaml.safe_load(f)
            vault_backup_info = backup_setup_data.get('VAULT', None)
            if not vault_backup_info or not vault_backup_info['enabled']:
                # Uninstall Vault for update/upgraded setup on dual stack
                playbook = "mercury-restapi-uninstall.yaml"
                cmd = ["ansible-playbook", playbook, "--tags=vault"]
                cwd = os.path.join(INSTALLER_DIR, "mercury_restapi/playbooks/")
                sproc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, cwd=cwd)
                try:
                    _ = sproc.stdout.read()
                except subprocess.CalledProcessError:
                    self.log.error("Playbook to uninstall Vault failed")
                    return False

                # Install Vault
                playbook = "mercury-restapi-install.yaml"
                cmd = ["ansible-playbook", playbook, "--tags=vault"]
                cwd = os.path.join(INSTALLER_DIR, "mercury_restapi/playbooks/")
                sproc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, cwd=cwd)
                try:
                    _ = sproc.stdout.read()
                except subprocess.CalledProcessError:
                    self.log.error("Playbook to install Vault failed")
                    return False

        gen_secrets_file = "/opt/cisco/scripts/generate_secrets.py"
        if not os.path.isfile(gen_secrets_file):
            return False
        cmd = ["python", gen_secrets_file, "--opt_svc_reconfig"]
        sproc = subprocess.Popen(cmd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
        try:
            _ = sproc.stdout.read()
        except subprocess.CalledProcessError:
            self.log.error("Generate secrets script failed")
            return False

        return True


def run(run_args={}):
    '''
    Run method. Invoked from common runner.
    '''

    validator = ReconfigParams(userdefined_mem_ratio=run_args['memSubRatio'], \
                               userdefined_cpu_ratio=run_args['CPUOSubRatio'])

    # validator = ReconfigParams()
    validator.validate_schema("new_cfg")
    # validator.validate_schema("secrets")
    validator.display_validation_results()
    pwd_result = validator.check_validation_results()

    overall_status = {}
    overall_status = validator.get_validation_report_in_array()
    overall_status['status'] = pwd_result['status']
    return overall_status

#    overall_status = validator.validate_buildnode(run_args['checkType'])
#    return overall_status


def main(check_type={}):
    '''
    Config Manager main.
    '''
    run(run_args=check_type)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Management Node Validation")
    parser.add_argument("--checkType", dest="CheckType",
                        default="all",
                        choices=["static", "all", "runtime"])

    parser.add_argument("--mem_subs_ratio", dest="MemSubRatio",
                        default="Undefined",)

    parser.add_argument("--cpu_osubs_ratio", dest="CPUOSubRatio",
                        default="Undefined",)

    input_args = {}
    args = parser.parse_args()
    input_args['checkType'] = args.CheckType
    input_args['memSubRatio'] = args.MemSubRatio
    input_args['CPUOSubRatio'] = args.CPUOSubRatio

    main(input_args)
