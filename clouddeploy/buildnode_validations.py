#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Validations:
==============

Validations Module:
---------------------------------------
Validates the basic sanity of a Management Node.

Running a validation on the user input file will help avoid such issues and in
turn improve customer satisfaction.

Validations:
------------------
Here are the checks to perform that a build node was installed via an official
ISO and not custom build:
1) The root password entry in /etc/shadow starts with $6
2) All the packages in installer/redhat_packages.txt are installed
3) The installer code is unpacked in root with gerritid+patchid suffix
4) vNICs are bonded with 802.3ad and interface is named bond0
5) The boot partition is 4Gb in size and mounted as /boot
6) The second partition is a LVM PV, assigned to VG <hostname>_vg_root
7) /home is 2Gb in size is a LV in VG <hostname>_vg_root
8) / is at least 20Gb in size and is a LV in VG <hostname>_vg_root
9) A 32Gb swap partition should be one of the LV in VG <hostname>_vg_root
12) A /var partition should be one of the LV in VG <hostname>_vg_root
13) Add RHEL7.5 and Kernel Check
14) Docker version check

"""
import argparse
import copy
import os
import re
import subprocess   # nosec
import textwrap
import sys
import prettytable

sys.path.insert(1, os.path.dirname(\
    os.path.dirname(os.path.realpath(__file__))))
import utils.logger as logger
import utils.config_parser as config_parser
import utils.common as common_utils

INSTALLER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class BNValidator(object):
    '''
    Validator class.
    '''
    OPER_STAGE = "INIT"
    STAGE_COUNT = 0

    def __init__(self, flexflash_flag=True, vlog=None, via_softlink=1):
        '''
        Initialize validator
        '''
        self.validation_results = []

        if not vlog:
            self.loginst = logger.Logger(name=__name__)
            self.log = self.loginst.get_logger()
        else:
            self.log = vlog

        # CSCvc26140, change to allow hostname change post management install
        #             instead of os.uname()[1].split('.')[0] to any string
        self.vg_name = "\w+_vg_root"
        self.df_name = self.vg_name.replace('-', '--')

        self.reimage_str = " Please re-image with buildnode.iso"
        curr_dir = os.path.dirname(os.path.realpath(__file__))
        self.cur_install_dir = curr_dir + "/../"

        self.flexflash_flag = flexflash_flag

        if via_softlink:
            defaults_file = os.path.join(self.cur_install_dir, "openstack-configs",
                                         common_utils.DEFAULTS_FILE)
        else:

            file_name_list = common_utils.find_file_path(INSTALLER_ROOT, \
                                                         "defaults.yaml")
            default_file_abs_path = ""

            for item in file_name_list:
                if os.path.basename(item) == 'defaults.yaml':
                    default_file_abs_path = item
                    break
            defaults_file = default_file_abs_path

        self.parsed_defaults_file = config_parser.YamlHelper(
            user_input_file=defaults_file)
        self.sw_version_info = self.parsed_defaults_file.get_sw_supported_dict()

    def _strip_version_str(self, version_str):
        '''
        Strip the minor version in Version String.
        E.g. 1) '1.7.10' -> '1.7'
             2) '7.4' -> '7.4'
        '''
        match = re.match(r'(\d).(\d+)', str(version_str))
        if match:
            return str(match.group())

        return "Invalid_Version_String"

    def set_validation_results(self, name, status='PASS', err=None):
        '''
        Set the validations, for the rules.
        '''
        result = {}
        result['name'] = name
        result['err'] = err
        if status == 'PASS':
            status = "\033[92mPASS\033[0m"
        else:
            status = "\033[91mFAIL\033[0m"
        result['status'] = status
        self.validation_results.append(result)

    def display_validation_results(self, debugMode):
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

        if not debugMode:
            print "\n"
            print "  Management Node Validations!"
            print ptable

        self.log.info("**** Management Node Validation! ****")
        self.log.info("Result table: \n{0}".format(ptable))
        self.log.info("**** Done Dumping Management Node Validation ! ****")

    def generate_validation_array(self):
        '''Generates the array for validation'''
        val_results = {}
        ucase_results = {}

        # Iterating over  consolidated dictionary to construct
        # the sub dictionaries to form the nested JSON format
        for rule in self.validation_results:
            ucase_results['reason'] = 'None'
            if rule['err']:
                ucase_results['status'] = "Fail"
                tmp_err = re.sub(' +', ' ', rule['err'])
                ucase_results['reason'] = tmp_err
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

        # Constructing JSON dictionary as per nested json format
        for v_type in validation_types:
            overall_dict[v_type] = {}

        # generate the sw validation array
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

    def check_restapi_server_status(self):
        '''Checks if Rest API server is up'''

        check_info = "REST API Server Status"
        restapi_status = common_utils.get_curr_installer_dir(send_info=1)

        if re.match('ERROR:', restapi_status):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=restapi_status)
            return

        self.set_validation_results(check_info)

    def check_root_pwd_entry(self):
        '''Checks if the root password entry in /etc/shadow starts with $6'''
        # grep "^root" /etc/shadow | awk -F":" '{ print $2 }'

        found_pwd = 0
        error_found = 0
        check_info = "Root Password Check"
        show_command = ['/usr/bin/grep', '^root', '/etc/shadow']
        try:
            output = subprocess.check_output(show_command)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1

        if error_found:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="Root password not set on build node \
                                            @ /etc/shadow;" + self.reimage_str)
            return

        for item in output.splitlines():
            if re.search(r'root\:\$6', item.strip()):
                found_pwd = 1
                break

        if not found_pwd:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="Root password on build node doesn't \
                                            start with $6 @ /etc/shadow;" + \
                                            self.reimage_str)
        else:
            self.set_validation_results(check_info)

    def check_rhel_pkg_install_state(self, podtype, sds_check=0,
                                     insight_check=0, argus_check=0):
        '''Check if all RHEL packages are installed'''

        if sds_check or insight_check or argus_check:
            return

        error_found = 0
        check_info = "Check RHEL Pkgs Install State"
        base_dir = self.cur_install_dir
        if not base_dir:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="Dir for openstack-configs \
                                        not Found")
            return

        rh_pkg_info = base_dir + "/redhat_packages.txt"

        if not os.path.exists(rh_pkg_info):
            err_str = "Path of " + rh_pkg_info + "doesnot exist"
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=err_str)
            return

        curr_command = ['/usr/bin/cat', rh_pkg_info]
        output = ""
        try:
            output = subprocess.check_output(curr_command)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found or not output:
            curr_command_str = ' '.join(curr_command)
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="Check output of " + \
                                            ' '.join(curr_command_str) + \
                                        self.reimage_str)
            return

        uninstalled_pkg_list = []
        incorrect_pkg_output = []
        recheck_incorrect_pkg_output = []

        for item in output.splitlines():
            if item == 'python-cloudpulseclient' and podtype == 'ceph':
                continue
            curr_command = ['/usr/bin/rpm', '-q', item]
            try:
                output = subprocess.check_output(curr_command)  # nosec
                if re.search(r'package .* is not installed', output):
                    uninstalled_pkg_list.append(item)
            except subprocess.CalledProcessError:
                incorrect_pkg_output.append(item)
            except OSError:
                incorrect_pkg_output.append(item)

        if incorrect_pkg_output:
            recheck_incorrect_pkg_output = copy.deepcopy(incorrect_pkg_output)
            for item in incorrect_pkg_output:
                if re.match(r'python-|pexpect', item):
                    if re.match(r'python-', item):
                        tmp = re.sub(r'python-', 'python2-', item)
                    elif re.match(r'pexpect', item):
                        tmp = "python2-pexpect"
                    curr_command = ['/usr/bin/rpm', '-q', tmp]

                    try:
                        output = subprocess.check_output(curr_command)  # nosec
                        if re.search(r'package .* is not installed', output):
                            pass
                        else:
                            try:
                                recheck_incorrect_pkg_output.remove(item)
                            except ValueError:
                                pass
                    except subprocess.CalledProcessError:
                        incorrect_pkg_output.append(tmp)
                    except OSError:
                        incorrect_pkg_output.append(tmp)

        if recheck_incorrect_pkg_output:
            incorrect_pkg_str = ', '.join(incorrect_pkg_output)
            err_str = "Check output of rpm -q of %s; %s" \
                % (incorrect_pkg_str, self.reimage_str)
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=err_str)
            return

        if uninstalled_pkg_list:
            uninstalled_pkg_str = ' '.join(uninstalled_pkg_list)
            err_str = "Pkgs %s are not installed; %s" \
                % (uninstalled_pkg_str, self.reimage_str)
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=err_str)
            return

        self.set_validation_results(check_info)
        return

    def check_ansible_version(self):
        '''checks the ansible version'''

        error_found = 0
        check_info = "Check Ansible Version"
        show_command = ['/usr/bin/rpm', '-qa', 'ansible']
        expected_ansible_version = \
            self._strip_version_str(self.sw_version_info['ansible_version'])
        output = ""

        try:
            output = subprocess.check_output(show_command)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="rpm -qa ansible execution Failed;" + \
                                        self.reimage_str)
            return

        for item in output.splitlines():
            if re.search(expected_ansible_version, item):
                self.set_validation_results(check_info)
                break
        else:
            err_str = "Expected ansible version {}. But found {}".format(
                expected_ansible_version, output.strip())
            self.set_validation_results(check_info, status='FAIL', err=err_str)

        return

    def check_docker_version(self, sds_check=0):
        '''check docker version'''

        check_info = "Check Docker Version"
        docker_pkg_list = []
        docker_pkg_list.append("docker")

        docker_version = \
            self._strip_version_str(self.sw_version_info['docker_version'])
        docker_pkg_ver_list = []
        docker_pkg_ver_list.append(docker_version)

        invalid_docker_pkg_list = []
        invalid_docker_cmd_list = []

        err_str = ""
        for pkg, ver in zip(docker_pkg_list, docker_pkg_ver_list):
            show_command = ['/usr/bin/rpm', '-qa', pkg]
            error_found = 0
            try:
                output = subprocess.check_output(show_command)  # nosec
            except subprocess.CalledProcessError:
                error_found = 1
            except OSError:
                error_found = 1

            if error_found:
                invalid_docker_cmd_list.append(pkg)
            elif sds_check:
                try:
                    curr_version_match = re.search('([a-z-]+)([0-9.]+)', output)
                    min_ver_prefix = "1"
                    if pkg == 'docker':
                        min_ver = "1.10"
                        min_ver_suffix = "10"
                    else:
                        min_ver = "1.9"
                        min_ver_suffix = "9"

                    try:
                        curr_version_prefix = curr_version_match.group(2)

                        if re.search('^([0-9]+).([0-9]+).([0-9]+)$', \
                                curr_version_prefix.strip()):

                            main_ver = \
                                re.search('([0-9.]+)([0-9]+)', curr_version_prefix)
                            true_main_ver = main_ver.group(1).rstrip(".")

                        elif re.search('^([0-9]+).([0-9]+)$', curr_version_prefix):
                            main_ver = \
                                re.search('([0-9.]+)([0-9]+)', \
                                          curr_version_prefix.strip())
                            true_main_ver = main_ver.group(1)

                        true_main_ver_prefix = true_main_ver.split(".")[0]
                        true_main_ver_sufffix = true_main_ver.split(".")[1]

                        if int(true_main_ver_prefix) < int(min_ver_prefix):
                            err_str = pkg + \
                                " min version of " + min_ver + " missing;"
                            invalid_docker_pkg_list.append(err_str)
                        elif int(true_main_ver_prefix) == int(min_ver_prefix):
                            if int(true_main_ver_sufffix) >= int(min_ver_suffix):
                                pass
                            else:
                                err_str = pkg + \
                                    " min version of " + min_ver + " missing;"
                                invalid_docker_pkg_list.append(err_str)
                        else:
                            pass

                    except AttributeError:
                        err_str = pkg + " min version of " + min_ver + " missing;"
                        invalid_docker_pkg_list.append(err_str)

                except AttributeError:
                    err_str = pkg + " min version of " + min_ver + " missing;"
                    invalid_docker_pkg_list.append(err_str)

            elif not re.search(ver, output):
                err_str = pkg + " version of " + ver + " missing;"
                invalid_docker_pkg_list.append(err_str)

        if invalid_docker_cmd_list:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="rpm -qa" + \
                                            ' '.join(invalid_docker_cmd_list) + \
                                        "execution Failed;" + self.reimage_str)
            return

        if invalid_docker_pkg_list:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=' '.join(invalid_docker_pkg_list))
            return

        self.set_validation_results(check_info)

        return

    def check_mgmt_node_tag(self):
        '''Checks Management Node Tag'''

        error_found = 0
        found_tag_info = 0
        check_info = "Check Management Node Tag"
        command_list = []
        output_list = []

        show_command = ['/usr/bin/cat', '/etc/cisco-mercury-release']
        command_list.append(show_command)

        for curr_command in command_list:
            try:
                output = subprocess.check_output(curr_command)  # nosec
                output_list.append(output)
            except subprocess.CalledProcessError:
                error_found = 1
            except OSError:
                error_found = 1

        if error_found:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=": Linux Info Not Found;" + \
                                        self.reimage_str)
            return

        for item in output_list[0].splitlines():
            if re.search('([0-9]+)', str(item.strip())):
                found_tag_info = 1
                break

        err_list = []
        if not found_tag_info:
            err_str = "Management node tag not found at " \
                      "/etc/cisco-mercury-release;" + \
                self.reimage_str
            err_list.append(err_str)
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=' '.join(err_list))
        else:
            self.set_validation_results(check_info)

        return

    def check_kernel_version(self, sds_check=0):
        '''Checks the Kernel Version'''

        error_found = 0
        found_kernel_info = 0
        check_info = "Check Kernel Version"
        command_list = []
        output_list = []
        expected_rhel_version_list = \
            self.sw_version_info['rhel_release_version']

        show_command = ['/usr/bin/cat', '/etc/system-release']
        command_list.append(show_command)

        for curr_command in command_list:
            try:
                output = subprocess.check_output(curr_command)  # nosec
                output_list.append(output)
            except subprocess.CalledProcessError:
                error_found = 1
            except OSError:
                error_found = 1

        if error_found:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=": Linux Info Not Found;" + \
                                        self.reimage_str)
            return

        kernel_found = 0

        for item in output_list[0].splitlines():
            if sds_check:
                if re.search(r'7.', item.strip()):
                    kernel_found = 1
                    break
            elif any(self._strip_version_str(release_ver) in item.strip()
                     for release_ver in expected_rhel_version_list):
                kernel_found = 1
                break

        if kernel_found == 1:
            found_kernel_info = 1

        err_list = []
        if not kernel_found:
            if sds_check:
                err_str = "Kernel of RHEL7.x not found;" + self.reimage_str
            else:
                err_str = "Kernel of RHEL7.5 not found;" + self.reimage_str

            err_list.append(err_str)

        if not found_kernel_info:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=":" + ' '.join(err_list))
        else:
            self.set_validation_results(check_info)

        return

    def check_bond_intf_presence(self, br_mgmt_chk=1, sds_check=0):
        '''Check if Management node has a bond intf'''

        error_found = 0
        check_info = "Check Bond Intf. Settings"

        bond_list = []
        bridge_list = []

        mgmt_int = "br_mgmt"
        api_int = "br_api"
        if sds_check:
            mgmt_int = "br_private"
            api_int = "br_public"

        output = ""
        bond_intf_state = []
        bridge_intf_state = []
        bond_intf_member_list = []
        bond_list.append("bond0")

        bond1_found = 1

        # Handle the case where br_api is sharing the same
        # physical interface as br_mgmt
        if not common_utils.is_br_api_mgmt_collapsed():
            bond_list.append("bond1")
            bond1_found = 0

        bridge_list.append(mgmt_int)
        bridge_list.append(api_int)
        bond0_found = 0

        br_mgmt_found = 0
        br_api_found = 0

        # Get the Bond state
        for bond_info in bond_list:
            if not br_mgmt_chk and bond_info == 'bond0':
                continue

            show_command = ['/usr/sbin/ip', 'addr', 'show', bond_info]

            try:
                output = subprocess.check_output(show_command)  # nosec
            except subprocess.CalledProcessError:
                error_found = 1
            except OSError:
                error_found = 1

            if error_found:
                self.set_validation_results(check_info,
                                            status='FAIL',
                                            err=": Intf not set to Bonding;" + \
                                            self.reimage_str)
                return

            for item in output.splitlines():
                if re.search(r'bond0', item) and re.search(mgmt_int, item) \
                        and re.search('UP', item) and \
                        not re.search('NO-CARRIER|state.*DOWN', item):
                    bond0_found = 1
                elif re.search(r'bond1', item) and re.search(api_int, item) \
                        and re.search('UP', item) and \
                        not re.search('NO-CARRIER|state.*DOWN', item):
                    bond1_found = 1

        if br_mgmt_chk and not bond0_found:
            bond_intf_state.append("bond0")

        if not bond1_found:
            bond_intf_state.append("bond1")

        # Get the brdige state
        for brdige_info in bridge_list:
            if not br_mgmt_chk and brdige_info == mgmt_int:
                continue

            show_command = ['/usr/sbin/ip', 'addr', 'show', brdige_info]

            try:
                output = subprocess.check_output(show_command)  # nosec
            except subprocess.CalledProcessError:
                error_found = 1
            except OSError:
                error_found = 1

            if error_found:
                self.set_validation_results(check_info,
                                            status='FAIL',
                                            err=": Intf not set for Brdging;" + \
                                            self.reimage_str)
                return

            for item in output.splitlines():
                if re.search(mgmt_int, item) and re.search('UP', item):
                    br_mgmt_found = 1
                elif re.search(api_int, item) and re.search('UP', item):
                    br_api_found = 1

        if br_mgmt_chk and not br_mgmt_found:
            bridge_intf_state.append(mgmt_int)

        if not br_api_found:
            bridge_intf_state.append(api_int)

        show_command = ['/usr/sbin/ip', '-d', '-o', 'link']

        try:
            output = subprocess.check_output(show_command)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=": Intf not set to Bonding;" + \
                                        self.reimage_str)
            return

        err_list = []
        error_found = 0

        for bond_info in bond_list:
            if not br_mgmt_chk and bond_info == 'bond0':
                continue

            bond_slave_count = 0
            bond_master_count = 0
            found_bond_info = 1
            for item in output.splitlines():
                if re.search(bond_info, item.strip()):
                    if re.search(r'team_slave|bond_slave', item.strip()) and \
                            not re.search(r'state DOWN', item.strip()):
                        bond_slave_count = bond_slave_count + 1
                    elif re.search(r'MASTER|master', item.strip()) and \
                            not re.search(r'state DOWN', item.strip()) and \
                            not re.search(r'bond0.[0-9]+@bond0', item.strip()):
                        bond_master_count = bond_master_count + 1

            if bond_master_count != 1:
                found_bond_info = 0
                error_found = 1
                err_str = "Master intf not found for " + str(bond_info) + ";"
                err_list.append(err_str)

            if re.search(r'bond1', bond_info):
                min_bond_slave_count = 1
                if bond_slave_count < min_bond_slave_count:
                    found_bond_info = 0
                    error_found = 1
                    err_str = "Min. slave intf count for " + str(bond_info) + \
                        " is:" + str(bond_slave_count) + " Expected: 2;"
                    err_list.append(err_str)

            if not found_bond_info:
                bond_intf_member_list.append(bond_info)

        if bond_intf_state:
            error_found = 1
            err_str = "Bond Intf state is not valid for " + \
                      ' '.join(bond_intf_state)
            err_list.append(err_str)

        if bridge_intf_state:
            error_found = 1
            err_str = "Brdige Intf state is not valid for " + \
                      ' '.join(bond_intf_state)
            err_list.append(err_str)

        if error_found:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="" + ';'.join(err_list) + \
                                        self.reimage_str)

        else:
            self.set_validation_results(check_info)

        return

    def check_lvm_partition(self):
        '''The second partition is a LVM PV, assigned to VG <hostname>_vg_root'''
        #pvs
        #PV         VG               Fmt  Attr PSize PFree
        #/dev/sda2  ii26-13_vg_root  lvm2 a--  3.27t 314.45g

        error_found = 0
        check_info = "Check LVM partition"
        show_command = ['/usr/sbin/pvs']
        try:
            output = subprocess.check_output(show_command,
                                             stderr=subprocess.STDOUT)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found:
            err_msg = "Not able to get LVM info; execute pvs to check"
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)
            return

        found_vg = 0
        for item in output.splitlines():
            if re.search(\
                    r"(sd[a-z]+|md|nvme[0-9]+n[0-9]+p)[0-9]+ .*{} .*lvm2 ".format(\
                    self.vg_name), item):
                found_vg += 1

        if found_vg != 1:
            err_msg = "LVM partition not set to {}; execute pvs to check".format(
                self.vg_name)
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)
        else:
            self.set_validation_results(check_info)

        return

    def check_lvm_partition_of_raid_drives(self):
        '''A second LVM VG called vg_var also exists made out of the RAID drives'''
        #execute cat /proc/mdstat, get the anchor PV and and execute
        #pvs and ensure the VG for it is vg_var for each one of them
        error_found = 0
        check_info = "Check Raid Drive Partition"
        show_command = ['cat', '/proc/mdstat']
        try:
            output = subprocess.check_output(show_command)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=": Not able to get RAID drive info;" + \
                                        self.reimage_str)
            return

        raid_drive_list = []
        grep_pattern = re.compile(r'([0-9a-z]+).* :.* active.* raid')
        for item in output.splitlines():
            if re.search(grep_pattern, item):
                raid_info = re.search(grep_pattern, item)
                raid_drive_list.append(raid_info.group(1))

        show_command = ['/usr/sbin/pvs']
        try:
            output_pvs = subprocess.check_output(
                show_command, stderr=subprocess.STDOUT)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=": Not able to get RAID drive info;" + \
                                        self.reimage_str)
            return

        missing_raid_partition = []
        for raid_info in raid_drive_list:
            search_str = raid_info + ".* vg_var.* lvm2"
            found_match = 0
            for item in output_pvs.splitlines():
                if re.search(search_str, item):
                    found_match = 1
                    break
            if not found_match:
                missing_raid_partition.append(raid_info)

        if missing_raid_partition:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="Raid Info missing for " + \
                                            ' '.join(missing_raid_partition) + \
                                        self.reimage_str)
        else:
            self.set_validation_results(check_info)

        return

    def check_ff_lvm_access_partition(self):
        '''The second partition of flexflash is a LVM PV, assigned to vg_root'''
        # [root@bacon-build-c240 ~]# pvs
        # PV         VG      Fmt  Attr PSize  PFree
        # /dev/md125 vg_var  lvm2 a--   4.09t   1.64t
        # /dev/md126 vg_var  lvm2 a--   2.46t      0
        # /dev/md127 vg_var  lvm2 a--   2.46t 512.00m
        # /dev/sdu2  vg_root lvm2 a--  55.47g  40.00m

        error_found = 0
        check_info = "Check FF LVM Access"
        show_command = ['/usr/sbin/pvs']
        try:
            output = subprocess.check_output(show_command,
                                             stderr=subprocess.STDOUT)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="Not able to get FF LVM info; \
                                            execute pvs to check;" + \
                                            self.reimage_str)
            return

        found_ff_access = 0
        for item in output.splitlines():
            if re.search(r'2.* vg_root.* lvm2', item):
                found_ff_access = 1
                break

        if not found_ff_access:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="2nd FF Partition not set to vg_root; \
                                            execute pvs to check;" + \
                                            self.reimage_str)
        else:
            self.set_validation_results(check_info)

        return

    def check_lv_swap_settings(self):
        '''A 32Gb swap partition should be one of the LV in VG <hostname>_vg_root'''
        #/usr/sbin/lvs --unit=g | grep lv_swap
        #lv_swap     ii26-13_vg_root -wi-ao----   32.00g

        check_info = "Check LV Swap Settings"

        command_list = ['/usr/sbin/lvs', '--unit=g']
        grep_pattern = re.compile(r' ([0-9.]+)g$')
        minsize = 32.0
        maxsize = 33.0
        anchor_pattern = self.vg_name

        docker_check = self.check_mount_point_size(command_list, grep_pattern,
                                                   minsize, maxsize,
                                                   anchor_pattern,
                                                   extra_pattern="lv_swap")

        if re.search(r'SubProcessCallFailed', docker_check):
            err_msg = "LV Swap partition not set via lvs"
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)
            return

        if re.search(r'CheckFailed', docker_check):
            err_msg = ("LV Swap partition not set to {}G @ {}; "
                       "checked via lvs").format(minsize, self.vg_name)
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)
        else:
            self.set_validation_results(check_info)

        return

    def check_lv_swap_settings_ff(self):
        '''A 32Gb swap partition should be one of the LV in vg_var'''
        #[root@bacon-build-c240 ~]# lvs | grep lv_swap
        #lv_swap     vg_var  -wi-ao----  32.00g

        check_info = "Check LV Swap Settings"

        command_list = ['/usr/sbin/lvs']
        grep_pattern = re.compile(r'([0-9.]+)([t|g|m])')
        minsize = 32.0
        maxsize = 33.0
        anchor_pattern = "vg_var"

        docker_check = self.check_mount_point_size(command_list, \
                                                   grep_pattern, \
                                                   minsize, \
                                                   maxsize, \
                                                   anchor_pattern, \
                                                   extra_pattern="lv_swap")

        if re.search(r'SubProcessCallFailed', docker_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="LV Swap partition not set via lvs;" + \
                                        self.reimage_str)
            return

        if re.search(r'CheckFailed', docker_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="LV Swap partition not set \
                                        to 32G @ vg_var; checked via lvs;" + \
                                        self.reimage_str)
        else:
            self.set_validation_results(check_info)

        return

    def check_boot_partition_settings(self):
        '''Check the boot partition is 4Gb in size and mounted as /boot'''
        #df -BG --output=source,size,target /boot
        #Filesystem     1G-blocks Mounted on
        #/dev/sda1             4G /boot

        check_info = "Check Boot Partition Settings"
        command_list = ['df', '-BG', '--output=source,size,target', '/boot']

        grep_pattern = re.compile(r'([0-9.]+)G\s+/boot')
        minsize = 3.5
        maxsize = 4.0
        anchor_pattern = "/boot"

        home_dir_check = self.check_mount_point_size(command_list,
                                                     grep_pattern, minsize,
                                                     maxsize, anchor_pattern,
                                                     extra_pattern="no")

        if re.search(r'SubProcessCallFailed', home_dir_check):
            err_msg = "Boot partition not set"
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)
            return

        if re.search(r'CheckFailed', home_dir_check):
            err_msg = "Boot partition not set to {}G @ /boot".format(maxsize)
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)
        else:
            self.set_validation_results(check_info)

        return

    def check_ff_partition_settings(self):
        '''Check the first partition on flexflash is \
        4Gb in size and mounted as /boot'''
        #df -h /boot
        #Filesystem      Size  Used Avail Use% Mounted on
        #/dev/sdi1       3.9G  137M  3.5G   4% /boot

        check_info = "Check FF Partition Settings"
        command_list = ['df', '-h', '/boot']

        grep_pattern = re.compile(r'([0-9.]+)([T|G|M]).* /boot')
        minsize = 3.5
        maxsize = 4.0
        anchor_pattern = "/boot"

        home_dir_check = self.check_mount_point_size(command_list, \
                                                     grep_pattern, \
                                                     minsize, \
                                                     maxsize, \
                                                     anchor_pattern, \
                                                     extra_pattern="no")

        if re.search(r'SubProcessCallFailed', home_dir_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="FlexFlash partition not set;" + \
                                        self.reimage_str)
            return

        if re.search(r'CheckFailed', home_dir_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="FlexFlash partition not set to 4G \
                                        @ /boot;" + self.reimage_str)
        else:
            self.set_validation_results(check_info)

        return

    def check_home_dir_settings(self):
        '''Check /home is 2Gb in size is a LV in VG <hostname>_vg_root'''
        #df -BG --output=source,size,target /home
        #Filesystem                                   1G-blocks Mounted on
        #/dev/mapper/ii26--13_vg_root-lv_home         2G        /home

        command_list = ['df', '-BG', '--output=source,size,target', '/home']
        grep_pattern = re.compile(r'([0-9.]+)G\s+/home')
        minsize = 2.0
        maxsize = 0.0
        anchor_pattern = "/home"

        check_info = "Check Home Dir Partition"
        home_dir_check = self.check_mount_point_size(
            command_list, grep_pattern, minsize, maxsize, anchor_pattern,
            extra_pattern="{}-lv".format(self.df_name))

        if re.search(r'SubProcessCallFailed', home_dir_check):
            err_msg = (": No partition set @ /home for filesystem ").format(
                self.df_name)
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)
            return

        if re.search(r'CheckFailed', home_dir_check):
            err_msg = "Partition @ /home not set to {}G".format(minsize)
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)
        else:
            self.set_validation_results(check_info)

        return

    def check_home_dir_settings_ff(self):
        '''Check /home is 2Gb in size is an LV in vg_root'''
        #df -h /home
        #Filesystem                   Size  Used Avail Use% Mounted on
        #/dev/mapper/vg_root-lv_home  2.0G   33M  2.0G   2% /home

        command_list = ['df', '-h', '/home']
        grep_pattern = re.compile(r'([0-9.]+)([T|G|M]).* /home')
        minsize = 2.0
        maxsize = 0.0
        anchor_pattern = "/home"

        check_info = "Check Home Dir Partition"
        home_dir_check = self.check_mount_point_size(command_list, \
                                                     grep_pattern, \
                                                     minsize, \
                                                     maxsize, \
                                                     anchor_pattern, \
                                                     extra_pattern="vg_root.*lv")

        if re.search(r'SubProcessCallFailed', home_dir_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=": No partition set @ /home for \
                                            filesystem vg_root;" + self.reimage_str)
            return

        if re.search(r'CheckFailed', home_dir_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="Partition @ /home not set to 2.0G;" + \
                                        self.reimage_str)
        else:
            self.set_validation_results(check_info)

        return

    def check_root_dir_settings(self):
        '''Check / is at least 20Gb in size and is a LV in VG <hostname>_vg_root'''
        #df -BG --output=source,size,target /
        #Filesystem                                  1G-blocks Mounted on
        #/dev/mapper/ii26--13_vg_root-lv_root        60G       /

        command_list = ['df', '-BG', '--output=source,size,target', '/']
        grep_pattern = re.compile(r'([0-9.]+)G\s+/')
        minsize = 20
        maxsize = 0.0
        anchor_pattern = "/"

        check_info = "Check Root Dir Partition"
        home_dir_check = self.check_mount_point_size(
            command_list, grep_pattern, minsize, maxsize, anchor_pattern,
            extra_pattern="{}-lv".format(self.df_name))

        if re.search(r'SubProcessCallFailed', home_dir_check):
            err_msg = "No partion set at /; execute df -BG / to check"
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)
            return

        if re.search(r'CheckFailed', home_dir_check):
            err_msg = ("Partition @ / needs to be a min of {}G for filesystem "
                       "{}; execute df -BG / to check").format(minsize,
                                                               self.df_name)
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)

        else:
            self.set_validation_results(check_info)

        return

    def check_root_dir_settings_ff(self):
        '''Check / is at least 20Gb in size and is an LV in vg_root'''
        #df -h /
        #Filesystem                   Size  Used Avail Use% Mounted on
        #/dev/mapper/vg_root-lv_root   54G  1.2G   53G   3% /


        command_list = ['df', '-h', '/']
        grep_pattern = re.compile(r'([0-9.]+)([T|G|M]).* /')
        minsize = 20
        maxsize = 0.0
        anchor_pattern = "/"

        check_info = "Check Root Dir Partition"
        home_dir_check = self.check_mount_point_size(command_list, \
                                                     grep_pattern, \
                                                     minsize, \
                                                     maxsize, \
                                                     anchor_pattern, \
                                                     extra_pattern="vg_root.*lv")

        if re.search(r'SubProcessCallFailed', home_dir_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="No partion set at /; \
                                            execute df -f / to check;" + \
                                        self.reimage_str)
            return

        if re.search(r'CheckFailed', home_dir_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="Partition @ / needs to be a min of 20G \
                                            for filesystem vg_root; execute df -h / \
                                            to check;" + self.reimage_str)

        else:
            self.set_validation_results(check_info)

        return

    def check_available_disk_space(self):
        '''Check / is max of 80% full in size and is an LV in vg_root'''
        #df -k /
        #Filesystem   1K-blocks    Used Available Use% Mounted on
        #/dev/mapper/f24--michigan_vg_root-lv_root  52395008 2046060  50348948   4% /


        command_list = ['df', '-k', '/var']
        grep_pattern = re.compile(r'([0-9.]+)([%]).* /')
        minsize = 0
        maxsize = 80
        anchor_pattern = "/"

        check_info = "Check Available Disk Space"
        home_dir_check = self.check_mount_point_size(command_list, \
                                                     grep_pattern, \
                                                     minsize, \
                                                     maxsize, \
                                                     anchor_pattern, \
                                                     extra_pattern="vg_root.*lv")

        if re.search(r'SubProcessCallFailed', home_dir_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="No partion set at /var; \
                                            execute df -k /var to check;" + \
                                        self.reimage_str)
            return

        if re.search(r'CheckFailed', home_dir_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="Disk usage @ /var cannot be more than "
                                            "80% full for filesystem vg_root; "
                                            "execute df -k /var to check;" \
                                            + self.reimage_str)

        else:
            self.set_validation_results(check_info)

        return

    def check_var_settings(self):
        '''Check /var partition should be one of the LV in VG <hostname>_vg_root'''
        #df -BG --output=source,size,target /var
        #Filesystem                               1G-blocks Mounted on
        #/dev/mapper/ii26--13_vg_root-lv_var      2683G     /var

        command_list = ['df', '-BG', '--output=source,size,target', '/var']
        grep_pattern = re.compile(r'([0-9.]+)G\s+/var')
        minsize = 1.0
        maxsize = 0.0
        anchor_pattern = "/var"

        check_info = "Check /var Partition"
        home_dir_check = self.check_mount_point_size(
            command_list, grep_pattern, minsize, maxsize, anchor_pattern,
            extra_pattern="{}-lv".format(self.df_name))

        if re.search(r'SubProcessCallFailed', home_dir_check):
            err_msg = "No /var partion is set; execute df -BG /var to cehck"
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)
            return

        if re.search(r'CheckFailed', home_dir_check):
            err_msg = ("Partition not set to non-zero size @ /var for "
                       "filesystem {}; execute df -BG /var to check").format(
                           self.df_name)
            err_msg += self.reimage_str
            self.set_validation_results(check_info, status='FAIL', err=err_msg)
        else:
            self.set_validation_results(check_info)

        return

    def check_var_settings_ff(self):
        '''Check /var partition should be one of the LV in vg_var.'''
        #df -h /var
        #Filesystem                 Size  Used Avail Use% Mounted on
        #/dev/mapper/vg_var-lv_var  2.3T   26G  2.2T   2% /var


        command_list = ['df', '-h', '/var']
        grep_pattern = re.compile(r'([0-9.]+)([T|G|M]).* /var')
        minsize = 1.0
        maxsize = 0.0
        anchor_pattern = "/var"

        check_info = "Check /var Partition"
        home_dir_check = self.check_mount_point_size(command_list, \
                                                     grep_pattern, \
                                                     minsize, \
                                                     maxsize, \
                                                     anchor_pattern, \
                                                     extra_pattern="vg_var.*lv")

        if re.search(r'SubProcessCallFailed', home_dir_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="No /var partion is set; \
                                            execute df -h /var to check;" + \
                                        self.reimage_str)
            return

        if re.search(r'CheckFailed', home_dir_check):
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="Partition not set to non-zero \
                                            size @ /var for filesystem vg_var; \
                                            execute df -h /var to check;" + \
                                        self.reimage_str)
        else:
            self.set_validation_results(check_info)

        return

    def check_attached_mount_point(self):
        '''Validate /mnt directory is not already mounted'''

        check_info = "Check if /mnt dir is already mounted"
        found_mounted_point = 0
        error_found = 0

        show_command = ['/usr/bin/mount']
        try:
            output = subprocess.check_output(show_command)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1

        if error_found:
            err_str = "Cant execute %s" % (' '.join(show_command))
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err=err_str)
            return

        for item in output.splitlines():
            if re.search(r' /mnt ', item.strip()):
                found_mounted_point = 1
                break

        if found_mounted_point:
            self.set_validation_results(check_info,
                                        status='FAIL',
                                        err="/mnt dir is already mounted")
        else:
            self.set_validation_results(check_info)

        return

    def check_mount_point_size(self, command_list, grep_pattern, minsize, maxsize, \
                               anchor_pattern, extra_pattern="no"):
        '''checks the mount point and size'''

        error_found = 0
        found_home_mount = 0

        try:
            output = subprocess.check_output(command_list,
                                             stderr=subprocess.STDOUT)  # nosec
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found:
            return "SubProcessCallFailed"

        if re.search(r'no', extra_pattern):
            extra_pattern = "([A-Za-z]+)"

        for item in output.splitlines():
            if re.search(anchor_pattern, item.strip()) and \
                    re.search(extra_pattern, item.strip()):
                size_info_str = re.search(grep_pattern, item.strip())

                try:
                    size_info = float(size_info_str.group(1))
                    if maxsize == 0.0:
                        if size_info >= minsize:
                            found_home_mount = 1
                    else:
                        if (size_info >= minsize) and \
                                (size_info <= maxsize):
                            found_home_mount = 1

                    if found_home_mount == 1:
                        break
                except IndexError:
                    found_home_mount = 0
                except AttributeError:
                    found_home_mount = 0

        if not found_home_mount:
            return "CheckFailed"

        return "CheckPassed"

    def validate_buildnode(self, checkType="all",
                           supressOutput=0,
                           skip_restapi_check=0,
                           debugMode=False,
                           skip_version_check=0,
                           br_mgmt_check=1,
                           cloud_deploy=0,
                           sds_check=0,
                           insight_check=0,
                           argus_check=0,
                           podtype=''):
        '''execute Management node tests from function'''

        if not cloud_deploy:
            mgmt_node_type = common_utils.fetch_mgmt_node_type()
            if mgmt_node_type == "vm":
                cloud_deploy = 1

        if not skip_version_check:
            # Check Kernel Version
            self.check_kernel_version(sds_check)

            # Check Ansible Version
            self.check_ansible_version()

            # Check Docker Version
            self.check_docker_version(sds_check)

        # Check management node tag
        if not cloud_deploy:
            self.check_mgmt_node_tag()

        #Check Bond Intf on Mgmt Node
        self.check_bond_intf_presence(br_mgmt_check, sds_check)

        # Check Root Passwd Entry
        if not cloud_deploy:
            self.check_root_pwd_entry()

        # Check Rest API server Status
        if not skip_restapi_check:
            self.check_restapi_server_status()

        if self.flexflash_flag:
            # Check FlexFlash Partition Settings
            self.check_ff_partition_settings()

            # Check Raid Drive Partition Settings
            self.check_lvm_partition_of_raid_drives()

            # Check FlexFlash 2nd Partition
            self.check_ff_lvm_access_partition()

            # Check LV Swap Settings
            self.check_lv_swap_settings_ff()


            # Check Home Dir Settings
            self.check_home_dir_settings_ff()

            # Check Root Settings
            self.check_root_dir_settings_ff()

            # Check Var Settings
            self.check_var_settings_ff()

        elif cloud_deploy:
            pass
        else:
            # Check Boot Partition Settings
            self.check_boot_partition_settings()

            # Check LV Swap Settings
            self.check_lv_swap_settings()

            # Check Home Dir Settings
            self.check_home_dir_settings()

            # Check Root Settings
            self.check_root_dir_settings()

            # Check Var Settings
            self.check_var_settings()

            # Check LVM Partition
            self.check_lvm_partition()

            # Check if mount point is attached
            self.check_attached_mount_point()

            #Check available disk space
            self.check_available_disk_space()

        if re.search(r'all|runtime', checkType):
            # Check RHEL Pkg Install State
            if not cloud_deploy:
                self.check_rhel_pkg_install_state(podtype, sds_check,
                                                  insight_check, argus_check)

        if not supressOutput:
            self.display_validation_results(debugMode)
        bn_result = self.check_validation_results()

        overall_status = {}
        overall_status = self.get_validation_report_in_array()
        overall_status['status'] = bn_result['status']
        return overall_status


def run(run_args={}):
    '''
    Run method. Invoked from common runner.
    '''
    import time

    flexflash = False
    try:
        for disk in os.listdir('/dev/disk/by-id/'):
            if re.search('usb-(CiscoVD|HV)_Hypervisor.*-part[12]{1}$', disk):
                flexflash = True
                break
    except OSError:
        flexflash = True

    validator = BNValidator(flexflash_flag=flexflash)
    time.sleep(1)

    overall_status = validator.validate_buildnode(run_args['checkType'])
    return overall_status


def check_status():
    '''
    Check Status
    '''
    return (BNValidator.STAGE_COUNT,
            BNValidator.OPER_STAGE)


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

    input_args = {}
    args = parser.parse_args()
    input_args['checkType'] = args.CheckType

    main(input_args)
