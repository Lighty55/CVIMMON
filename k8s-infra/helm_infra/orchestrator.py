#!/usr/bin/env python
# -*- coding: utf-8 -*-

from copy import deepcopy
import logging
import pprint
import os
import re
import sys
import subprocess
import utils.common as common_utils
import utils.logger as logger
import utils.config_parser as config_parser
import yaml


DEFAULTS_FILE = "/root/openstack-configs/defaults.yaml"
SETUPDATA_FILE = "/root/openstack-configs/setup_data.yaml"
BACKUP_SETUPDATA_FILE = '/root/openstack-configs/.backup_setup_data.yaml'
CVIMMONHA_FILE = "/root/openstack-configs/cvim_mon_ha.yaml"
PLAYBOOK_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "playbooks")
SITE_PLAYBOOK = os.path.join(PLAYBOOK_DIR, "site-deploy.yaml")
STACK_PLAYBOOK = os.path.join(PLAYBOOK_DIR, "stack-deploy.yaml")
POST_UPDATE_PLAYBOOK = os.path.join(PLAYBOOK_DIR, "post-update.yaml")
INSTALLER_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))


class OrchestratorStatus(object):
    """
    Status
    """
    OPER_STAGE = "INIT"
    STAGE_COUNT = 0


class Orchestrator(object):
    """
    Bootstrap CVIM MON HA deployment.
    """

    def __init__(self):
        """
        Initialize.
        """
        ################################################
        # Set up logging
        ################################################
        self.loginst = logger.Logger(name=__name__)
        self.log = self.loginst.get_logger()
        self.name = __name__
        self.run_args = {}
        self.log.debug("Orchestrator: Initialized")
        self.features_file = os.path.join(PLAYBOOK_DIR, "stack_features.yaml")
        self.metro_file = os.path.join(PLAYBOOK_DIR,
                                       "roles/prometheus/templates/metro.yaml")
        self.dhcp_mode = "v4"
        self.parsed_config = dict()

    def set_oper_stage(self, msg):
        """
        Set Operation stage status.
        """
        OrchestratorStatus.OPER_STAGE = msg
        OrchestratorStatus.STAGE_COUNT += 1


    def execute_ansible_cmd(self, playbook_dir, ansible_cmd):
        results = dict()
        results['status'] = 'PASS'

        # Pass management v4 IP to ansible playbooks
        v4_mgmt_ip = common_utils.get_ip_by_interface('br_mgmt')
        ansible_cmd.extend(["-e", "management_node_ip={}".format(v4_mgmt_ip)])

        self.log.debug("ANSIBLE CMD: %s", ansible_cmd)
        sproc = subprocess.Popen(ansible_cmd, cwd=playbook_dir,
                                 stdout=subprocess.PIPE)
        console = self.loginst.loggerconfig.get_module_console_logging(self.name)
        while True:
            try:
                nextline = sproc.stdout.readline()
                if nextline == '' and sproc.poll() is not None:
                    if sproc.returncode:
                        results['status'] = 'FAIL'
                    break
                results = monitor_and_validate_ansible_output(self, nextline, results)
                if console:
                    sys.stdout.write(nextline)
                    sys.stdout.flush()
            except KeyboardInterrupt:
                set_run_result(results, 'status', 'FAIL')
                set_run_result(results, 'err_msg', "Installer killed by user")
                return results

        return results

    def get_dhcp_mode(self):
        dhcp_mode = 'v4'
        if not self.parsed_config:
            self.log.error("Couldn't get DHCP mode")
            return dhcp_mode
        argus_config = self.parsed_config.get('ARGUS_BAREMETAL')
        if argus_config:
            dhcp_mode = argus_config.get('DHCP_MODE', 'v4')
        else:
            self.log.debug("There's not argus config in setup_data.yaml file")
        return dhcp_mode

    def get_argus_cluster_name(self):
        cluster_name = "test-cluster"
        if not self.parsed_config:
            self.log.error("Couldn't get Cluster Name")
            return cluster_name
        try:
            cluster_name = self.parsed_config['ARGUS_BAREMETAL']['SITE_CONFIG']['clusters'][0]['name']
            return cluster_name
        except TypeError:
            return cluster_name
        except KeyError:
            return cluster_name

    def get_stacks_to_add_or_delete_pod(self, parsed_config, backup_config):
        """ In add or delete pod operation, get all the info of the stack to be
            operated on by comparing setup_data with backup setup files
            (which are given already parsed)
        """
        if not parsed_config or not backup_config:
            self.log.error("Error getting the cached config")
            return None
        stacks_to_perform_op = []
        backup_dic = backup_config.get("cvim-mon-stacks")
        for stack in parsed_config['cvim-mon-stacks']:
            for backup_stack in backup_config['cvim-mon-stacks']:
                if stack['name'] == backup_stack['name']:
                    if cmp(stack, backup_stack):
                        stacks_to_perform_op.append(stack)
                    break

        return stacks_to_perform_op

    def get_stacks_to_add_or_delete(self, parsed_config, backup_config):
        """ In add or delete stack operation, get all the info of the stack to be
            added or deleted comparing setup_data with backup setup files
            (which are given already parsed)
        """
        if not parsed_config or not backup_config:
            self.log.error("Error getting the cached config")
            return None

        backup_dic = backup_config.get("cvim-mon-stacks")
        backup_stacks = list()
        for stack in backup_dic:
            backup_stacks.append(stack.get('name', None))
        stacks = parsed_config.get("cvim-mon-stacks")
        curr_stacks = list()
        for stack in stacks:
            curr_stacks.append(stack.get('name', None))
        stacknames_added_or_removed = list(set(backup_stacks) - set(curr_stacks))
        stacks_to_add_or_delete = []
        for i in range(len(backup_dic)):
            if backup_dic[i]['name'] in stacknames_added_or_removed:
                stacks_to_add_or_delete.append(backup_dic[i])
        return stacks_to_add_or_delete

    def execute_ansible_playbooks(self, setup_data, backup_setup_data):
        """
        Execute Ansible Playbooks.
        """
        results = dict({'status': 'PASS'})
        self.log.debug("Executing Ansible Playbook")

        if (not os.path.exists(DEFAULTS_FILE) or
                not os.path.exists(CVIMMONHA_FILE) or
                not os.path.exists(STACK_PLAYBOOK) or
                not os.path.exists(SITE_PLAYBOOK)):
            self.log.error("Required config files for playbooks don't exist")
            return {'status': 'FAIL'}

        self.parsed_config = setup_data
        if not self.parsed_config:
            self.log.error("Error: Could not load setup data file")
            return {'status': 'FAIL'}

        stacknames_to_delete = []
        action = self.run_args.get('action', None)
        if action and action == 'add-stack':
            first_dic = backup_setup_data
            second_dic = self.parsed_config
            region_details = self.get_stacks_to_add_or_delete(first_dic, second_dic)
            self.log.debug("Stacks to add: %s" % (str(region_details)))
        elif action and action == 'delete-stack':
            first_dic = self.parsed_config
            second_dic = backup_setup_data
            region_details = self.get_stacks_to_add_or_delete(first_dic, second_dic)
            self.log.debug("Stacks to delete: %s" % (str(region_details)))
        elif action and (action == 'add-cvim-pod' or action == 'delete-cvim-pod'):
            first_dic = self.parsed_config
            second_dic = backup_setup_data
            region_details = self.get_stacks_to_add_or_delete_pod(first_dic, second_dic)
            self.log.debug("Stacks to perform add/delete cvim pod operation: %s" % (str(region_details)))
        else:
            region_details = setup_data.get("cvim-mon-stacks")
        if not region_details:
            self.log.debug("Setup_data doesn't contain any stack details")

        self.dhcp_mode = self.get_dhcp_mode()
        self.cluster_name = self.get_argus_cluster_name()
        ansible_cmd = ["ansible-playbook", SITE_PLAYBOOK, "-e", "@" + DEFAULTS_FILE,
                       "-e", "@" + SETUPDATA_FILE, "-e", "@" + CVIMMONHA_FILE,
                       "-e DHCP_MODE=%s" % self.dhcp_mode ,
                       "-e CLUSTER_NAME=%s" % self.cluster_name]
        if action:
            ansible_cmd.append("-e ACTION=%s" % action)
        resp_ansible = self.execute_ansible_cmd(PLAYBOOK_DIR, ansible_cmd)

        if resp_ansible['status'] != 'PASS':
            self.log.error("Playbook execution failed: {}".format(ansible_cmd))
            return {'status': 'FAIL'}
        for site in region_details:
            to_delete = False
            if (action and action == 'delete-stack'):
                to_delete = True
            self.get_stack_feature_values(site, to_delete)
            stackname = site.get('name')

            custom_conf_stackname = self.run_args.get('stack-name', None)
            if custom_conf_stackname:
                if stackname != custom_conf_stackname:
                    continue

            ansible_cmd = ["ansible-playbook", STACK_PLAYBOOK, "-e", "@" + DEFAULTS_FILE,
                           "-e", "@" + SETUPDATA_FILE, "-e", "@" + CVIMMONHA_FILE,
                           "-e", "@" + self.features_file, "-e metro_name=" + stackname,
                           "-e install_dir=" + INSTALLER_DIR]
            if action:
                ansible_cmd.append("-e ACTION=%s" % action)
            resp_ansible = self.execute_ansible_cmd(PLAYBOOK_DIR, ansible_cmd)

            if resp_ansible['status'] != 'PASS':
                self.log.error("Playbook execution failed: {}".format(ansible_cmd))
                return {'status': 'FAIL'}

            if os.path.exists(self.features_file):
                os.remove(self.features_file)
        ansible_cmd = ["ansible-playbook", POST_UPDATE_PLAYBOOK, "-e", "@" + DEFAULTS_FILE,
                       "-e", "@" + SETUPDATA_FILE, "-e", "@" + CVIMMONHA_FILE,
                       "-e DHCP_MODE=%s" % self.dhcp_mode]
        if action:
            ansible_cmd.append("-e ACTION=%s" % action)
        resp_ansible = self.execute_ansible_cmd(PLAYBOOK_DIR, ansible_cmd)

        if resp_ansible['status'] != 'PASS':
            self.log.error("Playbook execution failed: {}".format(ansible_cmd))
            return {'status': 'FAIL'}

        return results

    def get_region_info_in_stack(self, regions):
        """ Function that gets all region information from a stack
            TBD: For now we write the region info into the self.metro_file file
                 It'd be much better to put it different for each stack.
        """
        if not regions:
            return
        if not self.metro_file:
            self.log.error("There's not metro filename associated yet")
            return
        info_pods = []
        for region in regions:
            labels = {}
            metros = region.get('metros',[])
            region_name = region.get('name')
            if region_name:
                labels['region'] = region_name
            elif 'region' in labels:
                del labels['region']
            for metro in metros:
                pods = metro.get('pods',[])
                metro_name = metro.get('name')
                if metro_name:
                    labels['metro'] = metro_name
                elif 'metro' in labels:
                    del labels['metro']
                for pod in pods:
                    pod_config = {}
                    static_cfg = {}
                    pod_auth = pod.get('cvim_mon_proxy_password', None)
                    if pod_auth:
                        basic_auth = {}
                        basic_auth['username'] = pod.get('username')
                        basic_auth['password'] = pod.get('cvim_mon_proxy_password')
                        pod_config['basic_auth'] = basic_auth
                        tls_config = {}
                        tls_config['ca_file'] = '/data/certs/' + os.path.basename(pod.get('cert'))
                        pod_config['tls_config'] = tls_config
                        pod_config['scheme'] = "https"
                    else:
                        pod_config['scheme'] = "http"
                    ip_list = []
                    ip_list.append(pod.get('ip'))
                    static_cfg['targets'] = ip_list
                    if labels:
                        static_cfg['labels'] = labels.copy()
                    pod_config['job_name'] = pod.get('name')
                    pod_config['honor_labels'] = True
                    pod_config['static_configs'] = [static_cfg]
                    info_pods.append(pod_config)

        noalias_dumper = yaml.dumper.SafeDumper
        noalias_dumper.ignore_aliases = lambda self, data: True
        with open(self.metro_file, 'w') as f:
            yaml.dump(info_pods, f, default_flow_style=False, Dumper=noalias_dumper)
            self.log.debug("METRO INFO:")
            self.log.debug("==========")
            self.log.debug(pprint.pformat(info_pods))
            self.log.debug("----------\n")

    def get_stack_feature_values(self, site, to_delete=False):
        """ Given the site dict, calculate all the features parameters and
            generate 2 files:
              - stack_features.yaml for all the feature data (subset of setup_data.yaml)
              - and metro.yaml file for the region information of the stack
            These files will be overrided every time this function gets called
        """
        metrics = dict()
        info_pods = []

        stackname = site.get("name")
        metrics["stackname"] = stackname
        metrics["DHCP_MODE"] = self.get_dhcp_mode()

        if site.get("stack_ca_cert"):
            metrics["stack_ca_cert"] = site.get("stack_ca_cert")

        if site.get("SNMP"):
            snmp_info = site.get("SNMP")
            metrics["SNMP"] = site.get("SNMP")
        ldap_check = False
        if "ldap" in site.keys():
            ldap_check = True
        metrics["LDAP"] = ldap_check
        if not to_delete:
            metrics["metrics_retention"] = site.get("metrics_retention")
            metrics["metrics_volume_size_gb"] = site.get("metrics_volume_size_gb")
            metrics["scrape_interval"] = site.get("scrape_interval")
            metrics["max_node_count"] = site.get("max_node_count","1K").upper()
            if 'Gi' not in str(metrics["metrics_volume_size_gb"]):
                metrics["metrics_volume_size_gb"] = str(metrics["metrics_volume_size_gb"]) + 'Gi'

            regions = site.get('regions', [])
            if regions:
                self.get_region_info_in_stack(regions)
            else:
                #Empty metro file for when we have stack with no targets
                with open(self.metro_file,"w+") as f:
                    pass
                self.log.debug("No pods in stack: %s" % stackname)

        noalias_dumper = yaml.dumper.SafeDumper
        noalias_dumper.ignore_aliases = lambda self, data: True
        with open(self.features_file, 'w') as f:
            yaml.dump(metrics, f, default_flow_style=False, Dumper=noalias_dumper)
            self.log.debug("FEATURES INFO:")
            self.log.debug("=============")
            self.log.debug(pprint.pformat(metrics))
            self.log.debug("-------------\n")


def set_run_result(resobj, key, value):
    """
    """
    robj = resobj

    # Never change status from FAIL to PASS.
    if key == "status":
        try:
            if resobj[key] == "PASS":
                robj[key] = value
        except KeyError:
            robj[key] = value
    else:
        robj[key] = value


def monitor_and_validate_ansible_output(orchestrator,
                                        nextline, result):
    """
    Monitor ansible output and check for key error patterns to report
    error.
    """
    TASK_PATTERN = re.compile(r'.*TASK  *\[(\w+(?:[-\w]*\w)) *\ : *(.*) *]')
    # First check if this is a Task pattern.
    mobj = TASK_PATTERN.match(nextline)
    if mobj:
        msg = mobj.group(1) + "-" + mobj.group(2)
        orchestrator.set_oper_stage(msg)
        set_run_result(result, 'status', 'PASS')
        return result

    _err_patterns = [r".*fatal:.*", r".*error.*", r".*failed=1.*"]
    for pattern in _err_patterns:
        mobj = re.match(pattern, nextline, flags=re.IGNORECASE)
        if mobj:
            msg = mobj.group(0)
            orchestrator.set_oper_stage(msg)
            set_run_result(result, 'status', 'FAIL')
            print logger.stringc(msg, 'red')
            return result

    set_run_result(result, 'status', 'PASS')
    return result


def run(run_args=dict()):
    """
    Run method is invoked from the runner.
    """

    orchestrator = Orchestrator()
    orchestrator.run_args = run_args

    results = {'status': 'PASS'}
    resobj = dict()
    set_run_result(resobj, 'status', 'PASS')

    setup_data = orchestrator.run_args.get('cvimmonha_setup')
    backup_setup_data = orchestrator.run_args.get('backup_cvimmonha_setup')

    # Run ansible playbooks
    results = orchestrator.execute_ansible_playbooks(setup_data, backup_setup_data)
    if results['status'] != 'PASS':
        orchestrator.log.debug("Bootstrap post validation failed")
        return results

    return results


def check_status():
    """
    Checkstart.
    """
    return (OrchestratorStatus.STAGE_COUNT,
            OrchestratorStatus.OPER_STAGE)

def main():
    """"
    main. Only to be invoked for manual test runs.
    """
    run()


if __name__ == '__main__':
    main()
