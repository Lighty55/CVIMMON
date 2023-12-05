#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import subprocess
import re
import requests
import six
import sys
import yaml

from keystoneauth1 import session
from keystoneclient.auth.identity import v3 as keystone_v3
from novaclient import client as novaclient
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set Python Path 	25
#sys.path.insert(1, os.getcwd())
#from ..import utils.config_parser as config_parser

def get_openstack_configs_loc():
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

    if error_found or not len(output):
        return ""

    dir_name = os.path.dirname(output)
    return dir_name

def generate_cloud_env():
    '''Generates the cloud env file'''

    openrc_err = 0
    my_env = {}
    os_cfg_loc = get_openstack_configs_loc()

    if not len(os_cfg_loc):
        return my_env, 0

    openrc_loc = os_cfg_loc + "/openstack-configs/openrc"
    if not os.path.isfile(openrc_loc):
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
        return my_env, 0

    return my_env, 1

def check_cloudcontroller_status(controller_list):
    '''Run Cloudpulse and Check its status'''

    my_env = {}
    my_env, cloud_status = generate_cloud_env()
    if not cloud_status:
        print "FAIL: Issue with getting env from Openrc file"
        return

    output = ""
    show_command = ['openstack', 'compute', 'service', 'list']
    show_command_str = ' '.join(show_command)

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
        print "FAIL: Exception in executing " + str(show_command_str)
        return
    elif not error_found:

        cntl_svr_list = controller_list.split(" ")

        for cntl_server in cntl_svr_list:
            for item in output.splitlines():
                parsed_op = ""
                if "|" in item:
                    parsed_op = [i.strip() for i in item.split("|")]
                if re.search(r'nova-scheduler', item) and \
                        re.search(r'up', item) and cntl_server in parsed_op:
                    num_active_controllers += 1

    if num_active_controllers != len(cntl_svr_list):
        print "FAIL: Number of active controller: " + str(num_active_controllers) + \
              " but Expected: " + str(len(cntl_svr_list))
        return
    else:
        print "PASS"

def is_ip_reachable(ip_addr):
    '''Checks if IP address is reachable'''

    err_str = "IP Address Unreachable"
    try:
        ping = subprocess.Popen(['/usr/bin/ping', '-c5', '-W2', ip_addr], \
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = ping.communicate()[0]

        if not out:
            return 0

        for item in out.splitlines():
            if re.search(r'100% packet loss', item):
                return 0

    except subprocess.CalledProcessError:
        return 0

    return 1


def get_current_install_link():
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

    if error_found or not len(output):
        err_msg = "ERROR: Couldnot find path to /root/openstack-configs"
        return err_msg

    dir_name = os.path.dirname(output)
    return dir_name


def get_contents_of_file(file_path):
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
        return {}

    return doc


def get_cobbler_path():
    '''gets the cobbler data in a dict'''

    # Get the current install link
    curr_install_link = get_current_install_link()
    if re.search(r'ERROR', curr_install_link):
        err_msg = "FAIL: current install link is not defined:%s" \
                  % (curr_install_link)
        return err_msg

    # Get the cobbler_data contents
    cobbler_yaml_path = \
        curr_install_link + "/openstack-configs/.cobbler_data.yaml"
    if not os.path.isfile(cobbler_yaml_path):
        err_msg = "FAIL: path for %s doesn't exist" % (cobbler_yaml_path)
        return err_msg

    return cobbler_yaml_path

def check_cloudcompute_ping_status(compute_mgmt_ip):
    '''Check Ping for all computes'''

    unreachable_node_list = []
    compute_mgmt_ip_list = compute_mgmt_ip.split(" ")

    cobbler_yaml_path = get_cobbler_path()
    if re.search(r'FAIL:', cobbler_yaml_path):
        print cobbler_yaml_path
        return

    cobbler_yaml = get_contents_of_file(cobbler_yaml_path)
    if not len(cobbler_yaml):
        err_msg = "FAIL: Contents of %s is empty, can't proceed" \
            % (cobbler_yaml_path)
        print err_msg
        return

    # find the mgmt_ip, power_status for each server
    for key, value in cobbler_yaml.iteritems():
        mgmt_ip = value.get('bonds').get('management').get('ipaddress')
        power_status = value.get('power_status')

        if mgmt_ip is None:
            err_msg = "FAIL: management_ip missing for %s in %s" \
                      % (key, cobbler_yaml_path)
            print err_msg
            return

        if power_status is None:
            err_msg = "FAIL: power_status is missing for %s in %s" \
                      % (key, cobbler_yaml_path)
            print err_msg
            return

        # ping check mgmt ip for each server if power_status is on
        if mgmt_ip in compute_mgmt_ip_list and power_status == 'on':
            if not is_ip_reachable(mgmt_ip):
                tmp = "%s:%s" % (key, mgmt_ip)
                unreachable_node_list.append(tmp)

        if len(unreachable_node_list):
            msg = "FAIL: Management IP not reachable from " \
                "management node for: %s" % (','.join(unreachable_node_list))
            print msg
            return

    print "PASS"
    return


def get_os_credentials():
    credentials = {}
    openrc_file = "/root/openstack-configs/openrc"
    if os.path.exists(openrc_file):
        export_re = re.compile('export OS_([A-Z_]*)="?(.*)')
        for line in open(openrc_file):
            mstr = export_re.match(line.strip())
            if mstr:
                name, value = mstr.group(1), mstr.group(2)
                if value.endswith('"'):
                    value = value[:-1]
                if name == 'USERNAME':
                    credentials['username'] = value
                elif name == 'AUTH_URL':
                    credentials['auth_url'] = value
                elif name == 'PASSWORD':
                    credentials['password'] = value
                elif name == "PROJECT_NAME":
                    credentials['project_name'] = value
                elif name == "PROJECT_DOMAIN_NAME":
                    credentials['project_domain_name'] = value
                elif name == "USER_DOMAIN_NAME":
                    credentials['user_domain_name'] = value
                elif name == 'OS_CACERT':
                    credentials['cacert'] = value
        return credentials


def get_os_session():
    credentials = get_os_credentials()
    auth = keystone_v3.Password(**credentials)
    sess = session.Session(auth=auth, verify=False)
    return sess

def check_cloudcompute_status(compute_list):
    '''Run nova hypervisor test'''

    my_env, cloud_status = generate_cloud_env()
    if not cloud_status:
        print "FAIL: Issue with getting env from Openrc file"
        return

    cobbler_yaml_path = get_cobbler_path()
    if re.search(r'FAIL', cobbler_yaml_path):
        print cobbler_yaml_path
        return

    cobbler_yaml = get_contents_of_file(cobbler_yaml_path)
    if not len(cobbler_yaml):
        err_msg = "FAIL: Contents of %s is empty, can't proceed" \
            % (cobbler_yaml_path)
        print err_msg
        return

    powered_up_compute_list = []
    comp_svr_list = compute_list.split(" ")
    for key, value in cobbler_yaml.iteritems():
        power_status = value.get('power_status')

        if power_status is None:
            err_msg = "FAIL: power_status is missing for %s in %s" \
                      % (key, cobbler_yaml_path)
            print err_msg
            return

        # ping check mgmt ip for each server if power_status is on
        if key in comp_svr_list and power_status == 'on':
            powered_up_compute_list.append(key)

    expected_powered_up_computes = len(powered_up_compute_list)
    expected_compute_sever = len(comp_svr_list)

    # Returns a list of compute service
    #  host mapped to each of the hypervisors.
    nova_hypervisor_state = {}
    sess = get_os_session()
    nova_client = novaclient.Client('2', session=sess)
    nova_hypervisors = nova_client.hypervisors.list()
    for hypervisor in nova_hypervisors:
        nova_hypervisor_state.update(
            {hypervisor.service.get('host'): hypervisor.state})

    print nova_hypervisor_state

    num_compute_server = len(nova_hypervisor_state.keys())
    powered_num_compute_server = len(
        [h for h,s in six.iteritems(nova_hypervisor_state) if s.lower() == 'up'])

    if expected_compute_sever > num_compute_server:
        print "FAIL: Num of computes found: [%i] but Expected: [%i]" \
              % (num_compute_server, expected_compute_sever)
        return

    if expected_powered_up_computes > powered_num_compute_server:
        print "FAIL: Num of compute UP [%i] but Expected [%i]" \
              % (powered_num_compute_server, expected_powered_up_computes)
        return

    print "PASS"
    return


if __name__ == "__main__":
    if re.search(r'check_cloudcontroller_status', sys.argv[1]):
        check_cloudcontroller_status(sys.argv[2])

    compute_list = []
    if re.search(r'check_cloudcompute_status|check_cloudcompute_ping_status', sys.argv[1]):
        backup_file = "/root/openstack-configs/.backup_setup_data.yaml"

        if not os.path.isfile(backup_file):
            print "FAIL: Backup setupdata is missing..."

        with open(backup_file, "r") as data:
            backup = yaml.safe_load(data)
            if 'ROLES' not in backup:
                print "FAIL: ROLES is missing in backup setupdata"

            roles = backup['ROLES']
            if 'compute' not in roles:
                print "FAIL: compute is missing in backup setupdata"

            compute_list = backup['ROLES']['compute']
        if re.search(r'check_cloudcompute_status', sys.argv[1]):
            check_cloudcompute_status(' '.join(compute_list))
        elif re.search(r'check_cloudcompute_ping_status', sys.argv[1]):
            check_cloudcompute_ping_status(' '.join(compute_list))