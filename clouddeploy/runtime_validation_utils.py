#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
 Validations:
==============

Validations Module:
---------------------------------------
The First step to the to perform a validation on the user input
file.

"""

import argparse
import os
import re
import subprocess   # nosec
import time

import clouddeploy.validations as validations
import clouddeploy.config_manager as config_manager
import utils.logger as logger
import utils.config_parser as config_parser
import utils.common as common
import kubernetes.openstack_lib.osclient as osclient

DEFAULT_CFG_DIR = "openstack-configs"
DEFAULT_SETUP_FILE = "setup_data.yaml"
BACKUP_SETUP_FILE = ".backup_setup_data.yaml"
COBBLER_DATA_YAML = ".cobbler_data.yaml"
TOOLS_DIR = '/tools/'

class RTValidationStatus(object):
    '''Class to return results'''

    def __init__(self, status, message):
        self.status = status
        self.message = message

class RunTimeValidatorUtils(object):
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
            self.log.debug("RunTime Utils Validator Initialized")

        self.cfgmgr = config_manager.ConfigManager(userinput=self.setup_file)
        self.ymlhelper = config_parser.YamlHelper(
            user_input_file=self.setup_file)

    def get_homedir(self):
        '''
        Get the current username
        '''
        homedir = os.path.expanduser("~")
        return homedir

    def execute_rt_action_precheck(self, action, server_string,
                                   forceyes=False):
        '''Executes a particular function, against a server string'''

        ret_info = ""
        if re.search(r'power_on|power_off|reboot|remove|replace', action):
            ret_info = self.power_mgmt_rt_pre_check(action, server_string, forceyes)

        if re.search(r'PASS', ret_info):
            status = 1
        else:
            status = 0

        return RTValidationStatus(status, ret_info)

    def execute_rt_action_postpowerup(self, server_string):
        '''executes checks post power up on the servers'''

        baremetal_servers_list = server_string.strip().split(",")
        ping_check_status = \
            self.ping_check_to_target_nodes(baremetal_servers_list)

        if re.search(r'ERROR:', ping_check_status):
            status = 0
            return RTValidationStatus(status, ping_check_status)

        hypvervisor_check = \
            self.check_nova_hypervisor_list(baremetal_servers_list)
        if re.search(r'ERROR:', hypvervisor_check):
            status = 0
            return RTValidationStatus(status, hypvervisor_check)

        rt_valid_status = \
            self.execute_cloud_sanity(2)

        if not rt_valid_status:
            err_msg = 'ERROR: Cloud Sanity Failed post server ' \
                      'power on of %s' % (','.join(baremetal_servers_list))
            status = 0
            return RTValidationStatus(status, err_msg)

        msg = "All Checks Passed"
        return RTValidationStatus(1, msg)

    def is_ip_reachable(self, hostname, **kwargs):
        '''Checks if IP address is reachable from management node'''

        ip_addr = kwargs['mgmt_ip']
        err_str = "ERROR: Ping to %s:%s from Management node FAILED" \
            % (hostname, ip_addr)
        try:
            ping_info_str = "Will Ping to %s:%s from Management node" \
                % (hostname, ip_addr)
            self.log.info(ping_info_str)
            ping = subprocess.Popen(['/usr/bin/ping',
                                     '-c10', '-W2', '-I', 'br_mgmt', ip_addr], \
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out = ping.communicate()[0]

            if not out:
                self.log.info(err_str)
                return 0

            for item in out.splitlines():
                if re.search(r'100% packet loss', item):
                    self.log.info(err_str)
                    return 0

        except subprocess.CalledProcessError:
            self.log.info(err_str)
            return 0

        success_msg = "Ping to %s:%s from mgmt Node Passed" % (hostname, ip_addr)
        self.log.info(success_msg)
        return 1

    def ping_check_to_target_nodes(self, baremetal_servers_list):
        '''Ping to all servers from the mangement node'''

        cobbler_yaml = common.get_contents_of_file(self.cobbler_data_file)
        if not len(cobbler_yaml):
            err_msg = "ERROR: Contents of %s is empty, can't proceed" \
                % (self.cobbler_data_file)
            self.log.info(err_msg)
            return err_msg

        mgmt_node_info = {}

        for key, value in cobbler_yaml.iteritems():
            if key in baremetal_servers_list:
                curr_power_status = value.get('power_status')

                if curr_power_status is not None and curr_power_status == 'on':
                    try:
                        current_mgmt_ip = \
                            value.get('bonds').get('management').get('ipaddress')
                        mgmt_node_info[key] = current_mgmt_ip

                    except KeyError:
                        pass

        num_try = 0
        tot_try = 20
        sleep_time = 30
        while num_try < tot_try:
            threadlist = []
            ping_chk_fail_list = []

            for hostname, mgmt_ip in mgmt_node_info.iteritems():
                kwargs = {}
                kwargs['mgmt_ip'] = mgmt_ip
                newthread = common.ExecThread(hostname,
                                              self.is_ip_reachable,
                                              **kwargs)
                newthread.start()
                threadlist.append(newthread)

            for mythread in threadlist:
                mythread.join()
                if mythread.oper_status != 1:
                    ping_chk_fail_list.append(mythread.lineup)
                    self.log.info("ERROR: Ping from mgmt node to %s:%s Failed; "
                                  "try:%s of %s, will try in %s secs", \
                                  mythread.lineup, mgmt_node_info[mythread.lineup],
                                  num_try, tot_try, sleep_time)

            if len(ping_chk_fail_list):
                num_try += 1
                time.sleep(sleep_time)
            else:
                num_try = tot_try

        if len(ping_chk_fail_list):
            err_str = "ERROR: Ping to %s from Management node FAILED" \
                % (','.join(ping_chk_fail_list))
            self.log.info(err_str)
            return err_str

        success_msg = "Ping to nodes %s from Management node over " \
            "mgmt network PASSED" % (','.join(baremetal_servers_list))
        self.log.info(success_msg)
        return success_msg

    def check_nova_hyperv_list(self, baremetal_servers_list):
        '''Checks if the server is back in the nova hypervisor list'''

        validation = validations.Validator(None)

        fixed_retry = 20
        max_vm_count = 0
        for srv in baremetal_servers_list:
            vm_count = int(validation.get_vms_per_hypervisor(srv).strip())
            if vm_count > max_vm_count:
                max_vm_count = vm_count

        tot_try = max_vm_count*2 + fixed_retry
        num_try = 0
        sleep_time = 30
        while num_try < tot_try:
            target_server_state_down = 0
            server_list_down_state = []
            hypervisor_list = validation.get_hypervisors_list()
            for comp_server in baremetal_servers_list:
                for item in hypervisor_list.splitlines():
                    try:
                        if comp_server in item:
                            server = item.split("|")[2].strip(" ")
                            state = item.split("|")[3].strip(" ")
                            if comp_server == server and state == "down":
                                self.log.info("ERROR: nova hypervisor-list " \
                                    "state is %s; try:%s of %s", \
                                    item, num_try, tot_try)
                                target_server_state_down = 1
                                server_list_down_state.append(comp_server)
                    except IndexError:
                        pass

            if target_server_state_down:
                err_msg = "ERROR: Server(s) %s in nova hypervisor-list is not up, " \
                    "post powered up, try:%s of %s, " "will try in %s secs" \
                          % (','.join(server_list_down_state),
                             num_try, tot_try, sleep_time)
                self.log.info(err_msg)
                time.sleep(sleep_time)
                num_try += 1
            else:
                msg = "Server(s) %s in nova hypervisor-list state are up, " \
                      "post powered up, try:%s of %s, " \
                      % (','.join(baremetal_servers_list), num_try, tot_try)
                self.log.info(msg)
                num_try = tot_try
                break

        if target_server_state_down:
            return err_msg
        else:
            return msg

    def execute_cloud_sanity(self, num_try=1):
        '''Run Ansible playbook and check cloud status'''

        validation = validations.Validator(None)
        tmp_srv_list = []
        role_list = []
        role_list.append('all')

        cur_try = 0
        sleep_time = 30

        cloud_sanity_status = ""
        while cur_try < num_try:
            cloud_sanity_status = \
                validation.check_currentcloud_status(tmp_srv_list,
                                                     role_list)

            if len(cloud_sanity_status) and cur_try < num_try:
                msg = "Cloud Sanity Check Failed in %s of %s attempt; \n; " \
                    "Failure Details:\n%s" \
                    % (cur_try, num_try, cloud_sanity_status)
                self.log.info(msg)
                msg = "Will sleep for %s and check again" % (sleep_time)
                self.log.info(msg)
                cur_try += 1
                time.sleep(sleep_time)
            else:
                cur_try = num_try + 1

        if len(cloud_sanity_status):
            self.log.info("ERROR: Cloud Sanity Check Failed")
            self.log.info(cloud_sanity_status)
            return 0
        else:
            self.log.info("Cloud Sanity Check Passed")
            return 1

    def check_vm_running_on_host(self, server_name):
        '''checks if VM is running on host via API'''

        int_lb_v6_info = self.ymlhelper.get_data_from_userinput_file(
            ['internal_lb_vip_ipv6_address'])

        int_lb_v4_info = self.ymlhelper.get_data_from_userinput_file(
            ['internal_lb_vip_address'])

        my_env = {}
        if int_lb_v6_info is None:
            my_env, cloud_status = \
                common.generate_cloud_env(int_lb_v4_info, via_v6=0)
        else:
            my_env, cloud_status = \
                common.generate_cloud_env(int_lb_v6_info, via_v6=1)

        if not cloud_status:
            print "ERROR: Issue with getting env from Openrc file"
            return


        if 'OS_CACERT' in my_env.keys():
            #Handle TLS and Keystonev3
            conn = osclient.OSClient(auth_url=my_env['OS_AUTH_URL'],
                                     region=my_env['OS_REGION_NAME'],
                                     project_name=my_env['OS_PROJECT_NAME'],
                                     username=my_env['OS_USERNAME'],
                                     password=my_env['OS_PASSWORD'],
                                     cacert=my_env['OS_CACERT'],
                                     user_domain_name=my_env['OS_USER_DOMAIN_NAME'],
                                     project_domain_name=my_env[\
                                         'OS_PROJECT_DOMAIN_NAME'],
                                     endpoint_type="internal")

        else:
            #Handle no TLS and Keystonev3
            conn = osclient.OSClient(auth_url=my_env['OS_AUTH_URL'],
                                     region=my_env['OS_REGION_NAME'],
                                     project_name=my_env['OS_PROJECT_NAME'],
                                     username=my_env['OS_USERNAME'],
                                     password=my_env['OS_PASSWORD'],
                                     user_domain_name=my_env['OS_USER_DOMAIN_NAME'],
                                     project_domain_name=my_env[\
                                         'OS_PROJECT_DOMAIN_NAME'],
                                     endpoint_type="internal")

        conn.create_connection()

        status, msg = conn.is_vm_running_on_server(server_name)
        return status, msg


    def check_vm_running_on_host_via_oscli(self, server_name):
        '''checks if VM is running on host'''

        my_env = {}
        my_env, cloud_status = common.generate_cloud_env()
        if not cloud_status:
            err_msg = "ERROR: Issue with getting env from Openrc file"
            return 0, err_msg

        host_info = "--host=" + str(server_name)
        output = ""
        show_command = ['openstack', 'server', 'list', host_info]
        show_command_str = ' '.join(show_command)

        error_found = 0
        try:
            output = subprocess.check_output(show_command, \
                                             env=dict(os.environ, **my_env))
        except subprocess.CalledProcessError:
            error_found = 1
        except OSError:
            error_found = 1

        if error_found:
            err_msg = "ERROR: Exception in executing " + str(show_command_str)
            return 0, err_msg
        elif not error_found:
            for item in output.splitlines():
                if re.search(r'ACTIVE', item):
                    msg = "VM found on %s" % (server_name)
                    self.log.info(msg)
                    return 1, server_name
                elif re.search(r'Missing value auth-url required', item):
                    msg = "ERROR: " + str(item)
                    return 0, msg

        msg = "No VM Found on %s" % (server_name)
        return 0, msg

    def power_mgmt_rt_pre_check(self, action, server_string, force):
        '''Execute the power on precheck for servers
        Test Cloud Sanity and for power off check if VM
        is running on compute'''

        tgt_compute_list = server_string.strip().split(",")

        # execute cloud sanity only for power-on
        if action == "power_on":
            cloud_sanity_status = self.execute_cloud_sanity()
            if not cloud_sanity_status:
                err_msg = "ERROR: Cloud Sanity Failed, " \
                    "can't proceed with %s" % (action)
                return err_msg

        # Check no VM is running before we do power off
        if action in ["power_off", "reboot", "remove", "replace"] and not force:
            vm_server_status = []
            vm_found = 0

            for item in tgt_compute_list:
                try:
                    status, msg = self.check_vm_running_on_host(item)
                    if status:
                        vm_server_status.append(msg)
                        vm_found = 1
                except Exception:
                    msg = "ERROR: Openstack Exception occurred for " \
                        "node %s. Please Run Cloud Sanity before " \
                        "retrying" % (item)
                    return msg

            if vm_found:
                msg = "ERROR: VM found on %s, cannot proceed with %s" \
                    % (','.join(vm_server_status), action)
                return msg

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

    validator = RunTimeValidatorUtils(curr_setupfileloc)


    if run_args['Action'] == 'postpower_on':
        retStatus = \
            validator.execute_rt_action_postpowerup(run_args['ServerInfo'])

    elif not re.match(r'NotDefined', run_args['SetupFileLocation']):
        retStatus = \
            validator.execute_rt_action_precheck(run_args['Action'],
                                                 run_args['ServerInfo'],
                                                 run_args['SetupFileLocation'])
    else:
        retStatus = \
            validator.execute_rt_action_precheck(run_args['Action'],
                                                 run_args['ServerInfo'])

    if 'EnableDebug' in run_args and run_args['EnableDebug']:
        print retStatus.status, retStatus.message
    return retStatus.status, retStatus.message



def main(check_type={}):
    '''
    Config Manager main.
    '''
    print "RunTime Validation Utils"
    run(run_args=check_type)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Runner/RestAPI RunTime Validation")

    parser.add_argument("--setup_file_location", dest="SetupFileLocation",
                        default="NotDefined", help="setup file location")

    parser.add_argument("--action", dest="Action",
                        choices=["power_off", "power_on", "add_compute",
                                 "add_osds", "replace_controller",
                                 "remove_computes", "remove_osd",
                                 "postpower_on"])

    parser.add_argument("--enable_debug", dest="EnableDebug",
                        action="store_true", default=False,
                        help="Enable Debug Flag")

    parser.add_argument("--server_info", dest="ServerInfo",
                        help=", separated server string to act on")

    input_args = {}
    args = parser.parse_args()
    input_args['SetupFileLocation'] = args.SetupFileLocation
    input_args['Action'] = args.Action
    input_args['ServerInfo'] = args.ServerInfo
    input_args['EnableDebug'] = args.EnableDebug

    main(input_args)
