#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import sys
import subprocess
import utils.common as common_utils
import utils.logger as logger
import yaml

TASK_PATTERN = re.compile(r'.*TASK  *\[(\w+(?:[-\w]*\w)) *\ : *(.*) *]')
DEFAULT_CFG_DIR = "openstack-configs"
DEFAULT_SETUP_FILE = "setup_data.yaml"
DEFAULTS_FILE = "defaults.yaml"
INSTALLER_ROOT = os.getcwd()


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

    def set_oper_stage(self, msg):
        """
        Set Operation stage status.
        """
        OrchestratorStatus.OPER_STAGE = msg
        OrchestratorStatus.STAGE_COUNT += 1


def execute_ansible_playbooks(orchestrator):
    """
    Execute Ansible Playbooks.
    """
    results = dict()
    results['status'] = 'PASS'
    orchestrator.log.debug("Executing Ansible Playbook")

    homedir = os.path.expanduser("~")
    cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)
    defaults_file = os.path.join(cfg_dir, DEFAULTS_FILE)
    setupdata_file = os.path.join(cfg_dir, DEFAULT_SETUP_FILE)
    with open(setupdata_file, 'r') as f:
        try:
            doc = yaml.safe_load(f)
        except yaml.parser.ParserError as e:
            found_error = 1
        except yaml.scanner.ScannerError as e:
            found_error = 1

    dhcp_mode = doc.get('ARGUS_BAREMETAL').get('DHCP_MODE', 'v4')
    dhcp_var = "-e DHCP_MODE=" + dhcp_mode


    if not os.path.exists(cfg_dir) or \
            not os.path.exists(defaults_file) or \
            not os.path.exists(setupdata_file):
        orchestrator.log.error("Required config files for playbooks " + \
                               "doesn't exist")
        results['status'] = 'FAIL'
        return results

    defaults_file = "@" + defaults_file
    setupdata_file = "@" + setupdata_file

    playbook_dir = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "playbooks")
    playbook_file = "k8s-all.yaml"
    ansible_playbook = os.path.join(playbook_dir, playbook_file)

    if not os.path.exists(ansible_playbook):
        orchestrator.log.error(logger.stringc("File %s does not exist", "red"),
                               ansible_playbook)
        return {'status', 'FAIL'}

    ansible_cmd = ["ansible-playbook", ansible_playbook,
                   "-e", defaults_file, "-e", setupdata_file, dhcp_var]
    ansible_options = ""

    tags = orchestrator.run_args.get('tags')
    controller = orchestrator.run_args.get('replace_node', None)
    if controller:
        if tags == "delete_controller":
            ansible_cmd = ["ansible-playbook", "delete-node.yaml", "-e",
                           defaults_file, "-e", setupdata_file, dhcp_var]
        else:
            ansible_cmd = ["ansible-playbook", "replace-controller.yaml", "-e",
                           defaults_file, "-e", setupdata_file, dhcp_var]
        ansible_option = ansible_options + "-e server=:&%s" % "".join(controller)
        ansible_cmd.append(ansible_option)

        ansible_option = ansible_options + "-e node_operation_host=%s" % "".join(controller)
        ansible_option = ansible_option + " -e ACTION=%s" % "replace-master"
        ansible_cmd.append(ansible_option)

    worker = orchestrator.run_args.get('remove_node', None)
    if worker:
        ansible_cmd = ["ansible-playbook", "delete-node.yaml", "-e",
                       defaults_file, "-e", setupdata_file, dhcp_var]
        ansible_option = ansible_options + "-e server=:&%s" % "".join(worker)
        ansible_cmd.append(ansible_option)

        ansible_option = ansible_options + "-e node_operation_host=%s" % "".join(worker)
        ansible_option = ansible_option + " -e ACTION=%s" % "remove-worker"
        ansible_cmd.append(ansible_option)

    worker = orchestrator.run_args.get('add_node', None)
    if worker:
        ansible_cmd = ["ansible-playbook", "add-worker.yaml", "-e",
                       defaults_file, "-e", setupdata_file, dhcp_var]
        ansible_option = ansible_options + "-e server=:&%s" % "".join(worker)
        ansible_cmd.append(ansible_option)

        ansible_option = ansible_options + "-e node_operation_host=%s" % "".join(worker)
        ansible_cmd.append(ansible_option)

    action = orchestrator.run_args.get('action', None)
    if action and action == "k8s-renew-certs":
        ansible_cmd = ["ansible-playbook", "kubernetes_renew_certs.yaml" , "-e",
                       defaults_file, "-e", setupdata_file, dhcp_var]

    if action and action == "etcd-renew-certs":
        ansible_cmd = ["ansible-playbook", "etcd_upgrade_utility.yaml" , "-e",
                       defaults_file, "-e", setupdata_file, dhcp_var]
        ansible_option = ansible_options + "-e ACTION=%s" % action
        ansible_cmd.append(ansible_option)
    if action and action == "update":
        playbook_dir = os.path.join(os.path.dirname(
                         os.path.abspath(__file__)), "playbooks")
        playbook_file = "k8s-update.yaml"
        ansible_playbook = os.path.join(playbook_dir, playbook_file)
        new_cfg_dir = os.path.join(os.getcwd(), "openstack-configs")
        defaults_file = os.path.join(new_cfg_dir, "defaults.yaml")
        setupdata_file = os.path.join(new_cfg_dir, DEFAULT_SETUP_FILE)
        defaults_file = "@" + defaults_file
        setupdata_file = "@" + setupdata_file

        if not os.path.exists(ansible_playbook):
            orchestrator.log.error(logger.stringc("File %s does not exist", "red"),
                                   ansible_playbook)
        ansible_cmd = ["ansible-playbook", ansible_playbook,
                       "-e", defaults_file, "-e", setupdata_file, dhcp_var]

        ansible_option = ansible_options + "-e ACTION=%s" % "update"
        ansible_cmd.append(ansible_option)

    if tags:
        ansible_cmd.append("--tags=%s" % tags)

    skip_tags = orchestrator.run_args.get('skip_tags')
    if skip_tags:
        ansible_cmd.append("--skip-tags=%s" % skip_tags)

    # Pass management v4 IP to ansible playbooks
    v4_mgmt_ip = common_utils.get_ip_by_interface('br_mgmt')
    ansible_cmd.extend(["-e", "management_node_ip={}".format(v4_mgmt_ip)])

    orchestrator.log.debug("ANSIBLE CMD: %s", ansible_cmd)
    # Start ansible playbook as a subprocess.
    sproc = subprocess.Popen(ansible_cmd,
                             cwd=playbook_dir,
                             stdout=subprocess.PIPE)
    console_logging = orchestrator.loginst. \
        loggerconfig.get_module_console_logging(orchestrator.name)

    while True:
        try:
            nextline = sproc.stdout.readline()
            if nextline == '' and sproc.poll() is not None:
                if sproc.returncode:
                    results['status'] = 'FAIL'
                break

            results = monitor_and_validate_ansible_output(
                orchestrator, nextline, results)

            if console_logging:
                sys.stdout.write(nextline)
                sys.stdout.flush()
        except KeyboardInterrupt:
            set_run_result(results, 'status', 'FAIL')
            set_run_result(results, 'err_msg', "Installer killed by user")

    return results


def set_run_result(resobj, key, value):
    """
    Set the run result
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
            print (logger.stringc(msg, 'red'))
            return result

    set_run_result(result, 'status', 'PASS')
    return result


def run(run_args=dict()):
    """
    Run method is invoked from the runner.
    """

    orchestrator = Orchestrator()
    orchestrator.run_args = run_args

    resobj = dict()
    set_run_result(resobj, 'status', 'PASS')

    # Run ansible playbooks
    orchestrator.log.debug("Args are %s" % (str(orchestrator.run_args)))
    results = execute_ansible_playbooks(orchestrator)
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
