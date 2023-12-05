#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import itertools
import re
import signal
import sys
import os
import traceback
import shutil
import yaml
import yaml.parser
import json
import paramiko
from ConfigParser import SafeConfigParser
from ConfigParser import NoOptionError
from prettytable import PrettyTable
from threading import Thread


sys.path.insert(1, os.getcwd())
import clouddeploy.validations as validations
from utils.manage_dashboards import *
from utils.get_cvimmon_endpoints import *
from cvimmon_backup import cvimmon_ha_backup as cvimmon_autobackup
import utils.logger as logger
import utils.config_parser as config_parser
from utils.common import send_data_to_sds, is_runner_running, \
    signal_term_handler
import argus.bootstrap
import argus.baremetal
import utils.manage_cvimmonha_setup as manage_setup
from database import constants as cv # constants_variables
from database import database as DB # Class
import validate_operations as vo
import k8s_parser


MSUCCESS = 0
MFAILURE = 1
STAGES_TO_RUN = dict()
RUNNER_CONSOLE_LOG = "runner_console.log"
DEFAULT_CFG_DIR = "openstack-configs"
SETUP_FILE = "/root/openstack-configs/setup_data.yaml"
BACKUP_SETUP_FILE = "/root/openstack-configs/.backup_setup_data.yaml"
SECRET_PATH = "/root/openstack-configs/secrets.yaml"
BACKUP_SECRET_PATH = "/root/openstack-configs/.secrets.yaml"
STATUS_FILE = "/opt/cisco/k8s_status.json"
OPT_DIR = "/opt/cisco/"
INSTALLER_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_FILE = INSTALLER_DIR + "/openstack-configs/defaults.yaml"
INVENTORY_FILE = "/root/openstack-configs/cvimmon_inventory.yaml"
INSTALLER_STAGE_FILE = \
    os.path.join(INSTALLER_DIR,
                 os.path.join(DEFAULT_CFG_DIR,
                              "tech-support/.tech_support_stage.cfg"))

signal.signal(signal.SIGINT, signal_term_handler)
signal.signal(signal.SIGTERM, signal_term_handler)

class RunnerConfig(object):
    """
    The class handles the parsing of the runner setup
    config file.
    """

    def __init__(self, runner_cfg_file="./runner_configs/config.txt"):
        """
        Initializing Runner Config
        """
        self.cfgfile = get_absolute_path_for_file(runner_cfg_file)
        self.cfgparser = SafeConfigParser()
        self.cfgparser.read(self.cfgfile)
        self.operpattern = re.compile(r'STAGE[-|_](\w+)')

    def parse_all_operations(self):
        """
        Return a dict list with parsed operations.
        """
        operations = list()
        for section in self.cfgparser.sections():
            operation = dict()
            mobj = self.operpattern.match(section)
            if mobj:
                operation['name'] = mobj.group(1)
                operation['modulename'] = \
                    self.get_option_value(section, "module")
                operation['id'] = self.get_option_value(section, "id")
                operation['tags'] = self.get_option_value(section, "tags")
                operation['skip_tags'] = self.get_option_value(section,
                                                               "skip_tags")
                operations.append(operation)

        return operations

    def get_option_value(self, section, option):
        """
        Get the option from the section.
        Set it to None if option not specified.
        """
        try:
            return self.cfgparser.get(section, option).strip("\"")
        except NoOptionError:
            return None


class OperMonitor(Thread):
    """
    Thread to monitor operations.
    """

    def __init__(self, operation, stage, oper_count, info):
        """
        Initialize monitor thread.
        """
        super(OperMonitor, self).__init__()
        self.operation = operation
        self.stage = stage
        self.oper_count = oper_count
        self.done = False
        self.prog_count = 0
        self.runner_info = info

    def capstr(self, s, l):
        """
        Cap string to the length (l)
        """
        return s if len(s) <= l else s[0:l - 3] + '...'

    def set_status_string(self, stage_str, mod_str, fin_str):
        """
        Set the status string
        """
        str1 = stage_str.ljust(4)
        str2 = self.capstr(mod_str, 70).ljust(73)
        str3 = fin_str.ljust(10)

        return str1 + str2 + str3

    def run(self):
        """
        Monitor something
        """
        old_operid, old_oper_stage = self.operation['module'].check_status()
        log_dir = self.runner_info.get("log_dir", None)
        with open(os.path.join(log_dir, RUNNER_CONSOLE_LOG), "a+", 0) as f:
            for c in itertools.cycle(r"/-\|"):
                operid, oper_stage = self.operation['module'].check_status()
                stage_str = \
                    "[" + str(self.stage) + "/" + str(self.oper_count) + "]"
                mod_str = "[" + self.operation['name'] + ": " + \
                          str(oper_stage) + "]"

                elapsed_m, elapsed_s = divmod(int(self.prog_count), 60)
                mtxt = "mins"
                stxt = "secs"
                if elapsed_m <= 1:
                    mtxt = "min"
                if elapsed_s <= 1:
                    stxt = "sec"
                elapsedm = str(elapsed_m) + mtxt
                elapseds = str(elapsed_s) + stxt

                elapsed_str = "[   " + c + "   ]   " + " " + elapsedm + " " \
                              + elapseds + '  '
                if self.done is not True and operid == old_operid:

                    status_str = self.set_status_string(stage_str,
                                                        mod_str,
                                                        elapsed_str)
                    sys.stdout.write(status_str)
                    sys.stdout.write('\r')
                    sys.stdout.flush()
                    sys.stdout.flush()
                    self.prog_count += 0.05
                    time.sleep(0.05)
                else:
                    fin_str = "[ DONE! ]"
                    mod_str = "[" + self.operation['name'] + ": " + \
                              str(old_oper_stage) + "]"
                    status_str = self.set_status_string(stage_str,
                                                        mod_str, fin_str)
                    print(status_str)
                    completed_time = elapsedm + " " + elapseds
                    msg = mod_str + " completed around : " + completed_time
                    f.write(msg)
                    f.write("\n")
                    if self.done is True:
                        break
                old_operid = operid
                old_oper_stage = oper_stage

    def stop_monitor_thread(self, op_name, op_id, status="[Fail]"):
        """
        Stop Monitor
        """
        # Write the operation that we were executing to the
        # file which tech-support will use to determine the stage
        # runner finished
        msg = "##########################################\n" + \
              "# RUNNER CURRENT STAGE for TECH-SUPPORT   \n" + \
              "##########################################\n" + \
              "# This file is autogenerated, please do not modify\n" + \
              "# Generated at " + time.strftime("%Y%m%d-%H%M%S") + "\n" + \
              "[" + op_name + "]\nid: " + str(op_id) + \
              "\nstatus: " + status

        path = os.path.split(INSTALLER_STAGE_FILE)
        if not os.path.exists(path[0]):
            os.makedirs(path[0])

        # Check if the stage was already recorded
        stage_id_read = 0
        if os.path.exists(INSTALLER_STAGE_FILE):
            try:
                with open(INSTALLER_STAGE_FILE, 'r') as ts_file:
                    for l in ts_file:
                        idnum = re.search('id: (.+?)', l.strip("\n"))
                        if idnum:
                            stage_id_read = idnum.group(1)
            except (OSError, IOError) as e:
                print(logger.stringc("Error %s getting the stage id" % (e),
                                     "red"))
        if op_id < stage_id_read:
            # If a higher stage was recorded earlier, then ignore it
            self.done = True
            return

        # Recording new stage
        try:
            with open(INSTALLER_STAGE_FILE, 'w+') as ts_file:
                ts_file.write("%s" % msg)
        except (OSError, IOError) as e:
            msg = "Error %s registering the stage %s" % (e, op_name)
            print(logger.stringc(msg, "red"))
        self.done = True


class Runner(object):
    """
    Run Forest Run.
    """
    ######################
    # Operation status.
    ######################

    OPER_STATUS_NOTRUNNING = 0
    OPER_STATUS_RUNNING = 1
    OPER_STATUS_PASSED = 2
    OPER_STATUS_FAILED = 3

    def __init__(self):
        """
        Initialize Runner.
        """
        self.runcfg = None
        self.setupdata_file = None
        self.operations = list()
        self.skip_steps = list()
        self.perform_steps = list()
        self.replace_master = list()
        self.add_worker = list()
        self.remove_worker = list()
        self.install = False
        self.regenerate_secrets = False
        self.regenerate_certs = False
        self.k8s_renew_certs = False
        self.etcd_renew_certs = False
        self.update = False
        self.rollback = False
        self.commit = False
        self.reconfigure = False
        self.reconfigure_stack = False
        self.add_stack = False
        self.delete_stack = False
        self.add_cvim_pod = False
        self.delete_cvim_pod = False
        self.alertmanager_config = None
        self.alerting_rules_config = None
        self.reconfigure_cvim_pod = False
        self.runner_info = dict()
        self.logdir = "/var/log/cvimmonha/"
        self.logger_inst = None
        self.log = None
        # this flag is set basef on defaults flag
        # and can be set to false for a few operations that
        # do not want an auto backup
        self.autobackup = False
        # This flag is set at the end of runner_run_sequential()
        # to tell autoback() whether it should auto-backup or not
        # based on last operation
        self.last_op_autobackup = False
        self.full_installation_allowed = False
        self.running_full_installation = False
        self.timestamp = False
        with open(DEFAULT_FILE, "r") as f:
            data = f.read()
        try:
            self.autobackup = yaml.safe_load(data)["autobackup"]
        except KeyError:
            pass

    def set_log_dir(self):
        """set log directory."""
        self.timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S_%f')
        log_dir_ts = self.logdir + self.timestamp
        logger.set_log_dir(log_dir_ts)
        self.runner_info['log_dir'] = log_dir_ts

        self.logger_inst = logger.Logger(name="Runner", level="debug")
        self.log = self.logger_inst.get_logger()
        self.log.debug("Start Runner...")

    def archive_logs(self):
        """Archive all the logs that were in /var/log/cvimmonha/<date>"""
        log_dir = self.runner_info.get('log_dir')
        log_files = os.listdir(log_dir)

        self.logger_inst.archive_runner_logs(log_files, 'cvimmonha')
        print("The logs for this run are available at {}\n".format(log_dir))

    def runner_run_sequential(self, setup_data_info):
        """
        The method will run all the Operations/Stages in a sequence.
        """
        global STAGES_TO_RUN

        title = "CVIM MON HA ORCHESTRATOR"
        print("")
        print("")
        print("\t\t\t" + "#" * (len(title) + 4))
        print("\t\t\t " + title)
        print("\t\t\t" + "#" * (len(title) + 4))
        print("")
        print("")
        # bu default assume the operation failed and does not need auto-backup
        self.last_op_autobackup = False

        oper_list = list()
        if self.perform_steps:
            oper_list = filter(lambda op: op['id'] in self.perform_steps,
                               self.operations)

        soperlist = sorted(oper_list or self.operations, key=lambda k: k['id'])
        # soperlist has details about each steps to be performed, each element correspond to a step
        for operation in soperlist:
            if operation['id'] in self.skip_steps:
                continue
            op_id = operation['id']
            STAGES_TO_RUN[op_id] = dict()
            STAGES_TO_RUN[op_id]["name"] = operation["name"]
            STAGES_TO_RUN[op_id]["status"] = "ToRun"
        oper_count = len(soperlist)
        self.last_action = "Unknown__step__0"

        for stage, operation in enumerate(soperlist):
            # Lets get the lowest operation
            if operation['id'] in self.skip_steps:
                print("Skip %s: %-20s " % (operation['name'], operation['id']))
                continue
            modargs = self.get_module_args(operation, setup_data_info)

            action = None

            if self.replace_master:
                action = cv.OP_REPLACE_MASTER
                self.log.debug("Replacing Kubernetes Master %s",
                               self.replace_master)
                modargs['replace_node'] = self.replace_master

            elif self.add_worker:
                action = cv.OP_ADD_MASTER
                self.log.debug("Adding Worker(s) %s", self.add_worker)
                modargs['add_node'] = self.add_worker

            elif self.remove_worker:
                action = cv.OP_REMOVE_WORKER
                self.log.debug("Removing Worker(s) %s", self.remove_worker)
                modargs['remove_node'] = self.remove_worker

            elif self.regenerate_secrets:
                action = cv.OP_REGENERATE_SECRETS
                self.log.debug("Regenerating Application Secrets")
                modargs['action'] = 'regenerate-password'

            elif self.regenerate_certs:
                action = cv.OP_REGENERATE_CERTS
                self.log.debug("Regenerating Application Certs")
                modargs['action'] = 'regenerate-certs'

            elif self.k8s_renew_certs:
                action = cv.OP_RENEW_CERTS
                self.autobackup = False
                self.log.debug("Regenerating Kubernetes Certs")
                modargs['action'] = 'k8s-renew-certs'

            elif self.etcd_renew_certs:
                action = cv.OP_ETCD_RENEW_CERTS
                self.autobackup = False
                self.log.debug("Regenerating ETCD Certs")
                modargs['action'] = 'etcd-renew-certs'

            elif self.reconfigure:
                action = cv.OP_RECONFIGURE
                self.log.debug("Reconfigure global CVIMMONHA parameters")
                modargs['action'] = 'reconfigure'

            elif self.reconfigure_stack:
                action = cv.OP_RECONFIGURE_STACK
                self.log.debug("Reconfigure CVIM MON Stacks")
                modargs['action'] = 'reconfigure-stack'

            elif self.add_stack:
                action = cv.OP_ADD_STACK
                self.log.debug("Add CVIM MON Stacks")
                modargs['action'] = 'add-stack'

            elif self.delete_stack:
                action = cv.OP_DELETE_STACK
                self.log.debug("Delete CVIM MON Stacks")
                modargs['action'] = 'delete-stack'

            elif self.add_cvim_pod:
                action = cv.OP_ADD_CVIM_POD
                self.log.debug("Add CVIM MON target pod to stack")
                modargs['action'] = 'add-cvim-pod'

            elif self.delete_cvim_pod:
                action = cv.OP_DELETE_CVIM_POD
                self.log.debug("Delete CVIM MON target pod from stack")
                modargs['action'] = 'delete-cvim-pod'

            elif self.alertmanager_config:
                action = cv.OP_CUSTOM_ALERT_CONFIG
                self.log.debug("Add Custom alertmanager config to a chosen stack")
                modargs['action'] = 'custom-alert-config'
                modargs['stack-name'] = self.stack_name

            elif self.alerting_rules_config:
                action = cv.OP_CUSTOM_ALERT
                self.log.debug("Add Custom alert rules to a chosen stack")
                modargs['action'] = 'custom-alerts'
                modargs['stack-name'] = self.stack_name

            elif self.reconfigure_cvim_pod:
                action = cv.OP_RECONFIGURE_CVIM_POD
                self.log.debug("Reconfigure CVIM MON target pod credentials")
                modargs['action'] = 'reconfigure-cvim-pod'

            elif self.install:
                action = cv.OP_INSTALL
                self.log.debug("Starting Install operation")

            elif self.update:
                action = cv.OP_UPDATE
                self.autobackup = False
                self.log.debug("Starting Update operation")
                modargs['action'] = 'update'

            elif self.rollback:
                action = cv.OP_ROLLBACK
                self.log.debug("Starting Rollback operation")
                modargs['action'] = 'rollback'

            elif self.commit:
                action = cv.OP_COMMIT
                self.log.debug("Starting Commit operation")
                modargs['action'] = 'commit'

            step = modargs.get('id', 0)
            dump_action = action + "__step__" + str(step)
            self.last_action = dump_action

            # Validate allowed operations
            ''' For internal Development
                The validations can be override by dumping a fake entry with status=success
                For this, run from installer directory
                -> python bootstrap/k8s-infra/validate_operations.py -s
            '''
            # For step 1 we never need to validate as it is always allowed
            if step != 1:
                valid_operation = self.validate_operation.is_operation_allowed(action)
                if not valid_operation:
                    return MFAILURE

            # Process monitor
            monitor = OperMonitor(operation, stage + 1,
                                  oper_count, self.runner_info)
            monitor.start()

            # Dump running status only if it is not step 1
            if step != 1:
                if self.running_full_installation:
                    self.db.insert_install_entry(dump_action, cv.STATUS_RUNNING, self.timestamp)
                else:
                    self.db.insert_operation_entry(dump_action, cv.STATUS_RUNNING, self.timestamp)

            op_id = operation['id']
            STAGES_TO_RUN[op_id]["status"] = "Running"
            STAGES_TO_RUN[op_id]["created_at"] = get_current_time()
            stage_entry = {"operation_name": action,
                           "status": "",
                           "workspace_info": INSTALLER_DIR}

            try:
                robj = operation['module'].run(run_args=modargs)
            except Exception as exp:
                msg = "Exception %s thrown by module %s Trace; [%s] " % \
                      (exp, operation['modulename'], traceback.format_exc())
                print(logger.stringc(msg, 'red'))
                robj = None

            if robj:
                status = robj.get('status', None)
                if status is None or status == "FAIL":
                    if robj.get('err_msg', None):
                        msg = "ERROR: [" + operation['name'] + \
                              " " + robj['err_msg'] + " ]"
                    else:
                        msg = "ERROR: [" + operation['name'] + "  FAILED]"
                else:
                    msg = None
            else:
                msg = "ERROR: Module: %s returned None. " % operation[
                    'modulename']
            if msg:
                monitor.stop_monitor_thread(operation['name'], operation['id'])
                monitor.join()
                print(logger.stringc(msg, 'red'))
                print(logger.stringc("*** Exiting the installer ***", "red"))
                if op_id == '1':
                    # Step 1 validation failed
                    # Revert secrets if validations fails.
                    if action == "reconfigure_stack" and \
                            os.path.exists(BACKUP_SECRET_PATH):
                        shutil.copy(BACKUP_SECRET_PATH, SECRET_PATH)
                        os.remove(BACKUP_SECRET_PATH)
                stage_entry["status"] = "Failed"
                # Operation failed
                if step != 1:
                    if self.running_full_installation:
                        self.db.insert_install_entry(dump_action, cv.STATUS_FAIL)
                    else:
                        self.db.insert_operation_entry(dump_action, cv.STATUS_FAIL)
                return MFAILURE

            # at this point we are guaranteed the operation succeeded

            monitor.stop_monitor_thread(operation['name'], operation['id'],
                                        "[Success]")
            monitor.join()
            msg = "\nEnded Installation [%s] [Success]\n" % (operation['name'])
            print(logger.stringc(msg, "green"))

            # Operation Successful
            if step != 1:
                if self.running_full_installation:
                    self.db.insert_install_entry(dump_action, cv.STATUS_SUCCESS)
                    # step 7 success => backup setupfileset
                    # This is the only place where a there is a backup of the setupdata on full install
                    if step == 7:
                        setup_data_info.backup()
                else:
                    self.db.insert_operation_entry(dump_action, cv.STATUS_SUCCESS)
            stage_entry["status"] = "Success"

            # Step 7 success
            if step == 7:
                # Register to SDS only for install, commit, update, rollback
                # and reconfigure; if Step 7 passes.
                # Register with SDS server optionally
                sds_registry = get_sds_registry()
                if sds_registry:
                    request_type = 'put' if self.update else 'post'
                    send_data_to_sds(self.log, request_type, sds_registry,
                                     component='cvimmon')

            if not os.path.exists(OPT_DIR):
                os.makedirs(OPT_DIR, 0o755)

            with open(STATUS_FILE, "w") as status_file:
                json.dump(stage_entry, status_file, ensure_ascii=False,
                          indent=4)

        # At this point we are garanteed all the steps of the operation succeeded
        # Autobackup when requested
        if self.autobackup:
            # Get the last operation dict
            op_dict = soperlist[-1]
            self.last_op_autobackup = op_dict["name"] in ["KUBERNETES_PROVISIONER",
                                                          "HELM_INFRA",
                                                          "GENERATE_INVENTORY"]
            # caller must invoke autobackup() after making sure the
            # setupfile and backup setupfile are in sync

        if self.update:
            reboot_nodes = check_nodes_reboot_required()
            if reboot_nodes:
                ptable = PrettyTable(["Nodes", "Reboot Required"])

                for node in reboot_nodes:
                    ptable.add_row([node, "YES"])

                print("=========================================================")
                print("     !!  THE FOLLOWING NODES NEEDS TO BE REBOOTED  !!    ")
                print("=========================================================")
                print(ptable)

        return MSUCCESS

    def auto_backup_mgmt_node(self):
        """Perform an autobackup of the management node if necessary.

        This method must be called only after a successfull call to runner_run_sequential()
        and will only auto backup if necessary.
        It assumes that the ref setupfile has been synced to backup file prior to call.
        """
        if self.last_op_autobackup:
            print("Executing autobackup for HA CVIM-MON")
            if not cvimmon_autobackup.main(self.log, "autobackup"):
                print("WARNING: HA CVIM-MON Auto-backup failed. View logs for " \
                      "more info.")
            self.last_op_autobackup = False

    def validate_operation_module(self, module):
        """
        We want to make sure that the plugin modules
        have the correct functions available.
        """
        for func_name in ['run', 'check_status']:
            if not hasattr(module, func_name):
                raise ImportError("Module %s has not implemented %s function"
                                  % (module.__class__, func_name))

    def get_module_args(self, operation, setup_data_info):
        """
        Set the module args from the operation.
        """
        modargs = dict()
        modargs['id'] = int(operation['id'])
        modargs['tags'] = operation['tags']
        modargs['skip_tags'] = operation['skip_tags']
        modargs['cvimmonha_setup'] = setup_data_info.ref_setup_set.get_setup_data()
        modargs['backup_cvimmonha_setup'] = setup_data_info.backup_setup_set.get_setup_data()
        return modargs

    def exec_manage_dashboards(self, save_dashboard, list_dashboard,
                               upload_dashboard, dir_path, dry_run,
                               force, preserve_dashboard, stack_name):
        """
        Set command for persisting dashboards
        """

        status = dict()
        save_status = dict()
        upload_status = dict()
        dpath = dir_path
        if dpath:
            path_list = dpath.split("/")
            if path_list[-1] != "":
                dir_path = dir_path + "/"

        if dry_run:
            self.log.info("No Changes will be made as --dry-run option "
                          "is selected")
            print("No Changes will be made as --dry-run was selected")

        stack_list, _ = self.get_stack_vip(stack_name)
        if stack_name and not stack_list:
            print("Invalid Stack Name:{}. Aborting operation.".format(
                stack_name))
            return MFAILURE

        domain_suffix = self.get_domain_suffix_name()
        if domain_suffix is None:
            print("ERROR: 'cvimmon_domain_suffix' key not found in setupdata")
            return MFAILURE

        if save_dashboard:
            save_status = save_custom_dashboards(self.log, dry_run,
                                                 force, dir_path,
                                                 central=True,
                                                 stack_name=stack_name,
                                                 domain_suffix=domain_suffix)

            status = list_custom_dashboards(self.log,
                                            domain_suffix=domain_suffix,
                                            central=True,
                                            stack_name=stack_name)
        if list_dashboard:
            status = list_custom_dashboards(self.log, domain_suffix,
                                            central=True,
                                            stack_name=stack_name)
        if upload_dashboard:
            upload_status = upload_custom_dashoard(self.log, dry_run,
                                                   force,
                                                   preserve_dashboard,
                                                   dir_path,
                                                   central=True,
                                                   stack_name=stack_name,
                                                   domain_suffix=domain_suffix)

            status = list_custom_dashboards(self.log,
                                            domain_suffix=domain_suffix,
                                            central=True,
                                            stack_name=stack_name)

        if save_status:
            print(save_status)
        if upload_status:
            print(upload_status)

        new_dash = status.get("new_dashboard", "(N/A)")
        delete_dash = status.get("deleted_dashboard", "(N/A)")
        unchanged_dashboard = status.get("unchanged_dashboard", "(N/A)")
        modified_dashboard = status.get("modified_dashboard", "(N/A)")

        if not new_dash:
            new_dash = "(N/A)"
        if not delete_dash:
            delete_dash = "(N/A)"
        if not unchanged_dashboard:
            unchanged_dashboard = "(N/A)"
        if not modified_dashboard:
            modified_dashboard = "(N/A)"

        print("\nExecuting list custom dashboards:\n")
        print("New Dashboard: {}".format(new_dash))
        print("Deleted Dashboard: {}".format(delete_dash))
        print("Unchanged Dashboard: {}".format(unchanged_dashboard))
        print("Modified Dashboard: {}".format(modified_dashboard))

        if "faultstring" in upload_status.keys():
            return MFAILURE

        return MSUCCESS

    def get_domain_suffix_name(self):
        """
        return domain suffic name
        """

        with open(BACKUP_SETUP_FILE, 'r') as setupfile:
            setup_data = yaml.safe_load(setupfile)

        domain_suffix_name = setup_data["cvimmon_domain_suffix"]

        return domain_suffix_name

    def get_stack_vip(self, stack_name):
        """

        :return: list of stack names
        """

        all_stack_list = list()
        stack_list = list()

        with open(BACKUP_SETUP_FILE, 'r') as setupfile:
            setup_data = yaml.safe_load(setupfile)

        external_vip_addr = setup_data["external_loadbalancer_ip"]

        for stack_info in setup_data["cvim-mon-stacks"]:
            all_stack_list.append(stack_info["name"])

        if stack_name.lower() == "all":
            return all_stack_list, external_vip_addr

        if stack_name not in all_stack_list:
            print("Invalid namespace: [{}].".format(stack_name))
        else:
            stack_list.append(stack_name)

        return stack_list, external_vip_addr

    def exec_get_endpoints(self, namespace):
        """

        :param namespace: get namespace for which endpoints are required
        :return: True
        """

        stack_list, external_vip_addr = self.get_stack_vip(namespace)
        if not stack_list:
            print("No Stack or Invalid Namespace passed.")
            return MFAILURE
        if not get_endpoint(stack_list, external_vip_addr):
            print("Fetching endpoint failed.")
            return MFAILURE

        return MSUCCESS

    def exec_get_password(self, secret_key):
        """
        This function will check the key if present in secret file.
        If there then password for that key will be displayed.
        The secret key provided should be in the exact same
        format as there in secret file.
        For eg: Grafana-Password-scalestack(Username:admin) is a valid key.
        """

        with open(SECRET_PATH, 'r') as secret_file:
            data_secret = yaml.safe_load(secret_file)

        password = data_secret.get(secret_key, None)

        if not password:
            print("ERROR: Invalid key provided: {}".format(secret_key))
            print("Execute --list-secrets to view valids secret lists.")
            return MFAILURE

        self.print_password_table(secret_key, password)
        return MSUCCESS

    def exec_get_secrets(self, namespace):
        """
        This function will get all the Secrets Key from
        /root/openstack-configs/secrets.yaml and display in pretty table. if
        namespace passed is "all" then secrets key for all stacks will be listed
        out for all stacks else it will do a search on the basis of the name
        provided and display in output.

        :param namespace: get namespace for which endpoints are required
        :return: list of secrets keys and not values.

        secret file in /root/openstack-configs/ has to be a yaml file for eg:
        Grafana-Password-scalestack(Username:admin):
        V/JQ9LiUqopTJp366UtVXSat9hwxqlyXMY92Axd/Rv4=
        Calipso_API-Password-korennica2(Username:admin):
        36c74b02d8ea33e174d6c635f71c5ecb40fc5bfd24617a6f26fd7f567d5820e6
        """

        if not os.path.exists(SECRET_PATH):
            print("ERROR: Missing secret file at :{}".format(SETUP_FILE))
            return MFAILURE

        with open(SECRET_PATH, 'r') as secret_file:
            data_secret = yaml.safe_load(secret_file)

        if not data_secret:
            print("ERROR: Secret file is empty. " \
                  "Terminating list-secret operation.")
            return MFAILURE

        secret_list = data_secret.keys()
        namespace_secret_list = list()

        if namespace and namespace.lower() != "all":
            for key in secret_list:
                secret_namespace = key.split("-")[-1]
                secret_namespace = re.sub(r" ?\([^)]+\)", "", secret_namespace)
                if "cvimmon-monitor" in key:
                    secret_namespace = "cvimmon-monitor"
                if namespace == secret_namespace:
                    namespace_secret_list.append(key)
            if not namespace_secret_list:
                print("ERROR: Invalid namespace:{}".format(namespace))
                return MFAILURE
            self.print_secret_table(namespace_secret_list, namespace)
            return MSUCCESS


        self.print_secret_table(secret_list)
        return MSUCCESS

    def exec_change_secrets(self, file_path):
        """
        file_path is a yaml file for which validation is taken care below. This
        file should comprise of all valid secret key which are currently there
        in secrets.yaml.
        The new file should only have the existing keys with
        new values. If an invalid key is passed the operation will terminate.
        if there is no change in the value of old and new secrets then the
        operation will terminate.

        :param file_path: file from to change secrets
        :return: True/False
        """

        # Validate file type
        with open(file_path, 'r') as new_secret_file:
            try:
                new_data_secret = yaml.safe_load(new_secret_file)
            except Exception as e:
                print("\nERROR: Failed to parse :{} file.".format(file_path))
                return MFAILURE

        if not isinstance(new_data_secret, dict):
            print("\nERROR: Not a valid file type for changing secrets.")
            return MFAILURE

        # Check for duplicate keys in new secret file.
        validator = validations.Validator(self.setupdata_file)
        duplicate_list = validator.report_nonunique_keys(file_path)
        if duplicate_list:
            print("\nERROR: Duplicate Info for: " + ','.join(duplicate_list))
            return MFAILURE

        with open(SECRET_PATH, 'r') as secret_file:
            data_secret = yaml.safe_load(secret_file)

        #Check if same secret is passed or not; if yes the error out.
        if new_data_secret == data_secret:
            print("\nERROR: No difference between {0} and {1} " \
                  "\nTerminating Operation.".format(file_path, SECRET_PATH))
            return MFAILURE

        new_secret_list = new_data_secret.keys()

        old_secret_list = data_secret.keys()

        # Check if extra keys are passed as a part of custom password
        invalid_keys = set(new_secret_list) - set(old_secret_list)

        if invalid_keys:
            print("\nERROR: Invalid key: {} detected to change password. " \
                  "\nTerminating Operation.".format(invalid_keys))
            return MFAILURE

        # Take backup of current secret
        if os.path.exists(BACKUP_SECRET_PATH):
            os.remove(BACKUP_SECRET_PATH)

        shutil.copy(SECRET_PATH, BACKUP_SECRET_PATH)

        # counter to verify if there is a change then only execute the
        # reconfigure-stack operation
        for secret_key in new_secret_list:
            if not self.validate_secret_value(str(new_data_secret[secret_key])):
                print("\nINFO: Allowed special characters [_@./#+-=]")
                print("\nERROR: Password condition failed for \n{0}:" \
                      "{1}".format(secret_key, new_data_secret[secret_key]))
                err_msg = "Only Alpha Numeric and Special Characters " \
                          "for secrets allowed, and passwords must contain" \
                          " at least 1 letter, 1 special character, " \
                          "1 digit, without whitespaces and length " \
                          "should be >=8 and <= 44"
                print("\nERROR: {}".format(err_msg))
                return MFAILURE
            data_secret[secret_key] = new_data_secret[secret_key]

        try:
            with open(SECRET_PATH, 'w') as final_secret:
                yaml.safe_dump(data_secret, final_secret,
                               default_flow_style=False)
        except (OSError, IOError) as e:
            msg = "\nERROR: Unable to modify existing secret"
            print(msg)
            return MFAILURE

        return MSUCCESS

    def populate_runner_info(self):
        """
        Parse the user configuration file.
        """
        if self.replace_master:
            self.runcfg = RunnerConfig(
                "./runner_configs/replace-controller.txt")
        elif self.add_worker:
            self.runcfg = RunnerConfig("./runner_configs/add-worker.txt")
        elif self.remove_worker:
            self.runcfg = RunnerConfig("./runner_configs/remove-worker.txt")
        else:
            self.runcfg = RunnerConfig()
        self.operations = self.runcfg.parse_all_operations()
        for operation in self.operations:
            operation['status'] = Runner.OPER_STATUS_NOTRUNNING
            __import__(operation['modulename'])
            operation['module'] = sys.modules[operation['modulename']]
            self.validate_operation_module(operation['module'])

    def print_operations(self):
        """
        Display all the available steps
        """
        soperlist = sorted(self.operations, key=lambda k: k["id"])

        ptable = PrettyTable(["Operations", "Operation ID"])
        ptable.align["Operations"] = "l"

        for _, operation in enumerate(soperlist):
            ptable.add_row([operation['name'], operation['id']])

        print("")
        print("     !!  CVIM MON HA ORCHESTRATOR  !!    ")
        print("=========================================")
        print(ptable)

    def print_secret_table(self, secret_list, namespace=None):
        """
        Display all secret list
        """

        ptable = PrettyTable(["Secret Keys"])
        ptable.align["Secret Keys"] = "l"

        for secrets in secret_list:
            ptable.add_row([secrets])

        print("")
        ptable.sortby = "Secret Keys"
        print(ptable)

    def print_password_table(self, secret_key, password):
        """
        Display secret key and password
        """

        ptable = PrettyTable(["Secret Key", "Password"])
        ptable.add_row([secret_key, password])
        print("")
        print(ptable)

    def validate_secret_value(self, secret):
        """
        Only Alpha Numeric and Special Characters for secrets allowed, and
        passwords must contain at least 1 letter, 1 special character, 1 digit,
        without whitespaces and length should be >=8 and <= 44.
        Allowed special chars : [_@./#+-=]
        :param secret: validate secret value
        :return: True/False
        """
        if not re.match(r'^[A-Za-z0-9_@./#+-=]*$', secret):
            return False
        secret_length = len(secret)
        if secret_length not in range(8, 45):
            return False

        return True

    def set_install(self):
        """
        Perform the full install of CVIM-MON HA
        """
        self.install = True

    def set_skip_steps(self, input_value, skip_prompt):
        """
        Set the skip steps if provided
        """
        self.skip_steps = input_value.strip().split(",")
        msg = "\nSkipping steps %s. Continue (Y/N)" % self.skip_steps
        return self.get_user_answer(msg, skip_prompt)

    def set_perform_steps(self, input_value, skip_prompt):
        """
        Set the perform steps if provided
        """
        self.perform_steps = input_value.strip().split(",")
        msg = "\nPerform steps %s. Continue (Y/N)" % self.perform_steps
        return self.get_user_answer(msg, skip_prompt)

    def set_setupdata_file(self, setupdata_file):
        """
        Use the user input setupdata file
        """
        self.setupdata_file = setupdata_file

    def set_replace_master(self, master_hostname):
        """
        Set the master to be replaced
        """
        self.replace_master = master_hostname.strip().split(",")
        if len(self.replace_master) != 1:
            print("")
            print("Replacing 1 master at a time is only supported")
            print("")
            return MFAILURE
        return MSUCCESS

    def set_add_worker(self, workers):
        """
        Set the workers to be added
        """
        self.add_worker = workers.strip().split(",")
        if len(self.add_worker) != 1:
            print("")
            print("Adding 1 worker at a time is only supported")
            print("")
            return MFAILURE
        return MSUCCESS

    def set_remove_worker(self, workers):
        """
        Set the workers to be removed
        """
        self.remove_worker = workers.strip().split(",")
        if len(self.remove_worker) != 1:
            print("")
            print("Removing 1 worker at a time is only supported")
            print("")
            return MFAILURE
        return MSUCCESS

    def set_regenerate_secrets(self):
        """
        Function to regenerate application secrets
        """
        self.regenerate_secrets = True
        self.perform_steps = ['1', '7']

    def set_regenerate_certs(self):
        """
        Function to regenerate application certificates
        """
        self.regenerate_certs = True
        self.perform_steps = ['1', '7']

    def set_renew_k8s_certs(self):
        """
        Function to regenerate k8s infra certificates
        """
        self.k8s_renew_certs = True
        self.perform_steps = ['1', '6']

    def set_renew_etcd_certs(self):
        """
        Function to regenerate etcd certificates
        """
        self.etcd_renew_certs = True
        self.perform_steps = ['1', '6']

    def set_reconfigure(self):
        """
        Function to reconfigure global CVIM MON HA settings
        """
        self.reconfigure = True
        self.perform_steps = ['1', '2', '5', '7']

    def set_reconfigure_stack(self):
        """
        Function to reconfigure cvim mon stacks
        """
        self.reconfigure_stack = True
        self.perform_steps = ['1', '7']

    def set_add_stack(self):
        """
        Function to add cvim mon stacks
        """
        self.add_stack = True
        self.perform_steps = ['1', '7']

    def set_delete_stack(self):
        """
        Function to delete cvim mon stacks
        """
        self.delete_stack = True
        self.perform_steps = ['1', '7']

    def set_add_cvim_pod(self):
        """
        Function to add cvim target to stack
        """
        self.add_cvim_pod = True
        self.perform_steps = ['1', '7']

    def set_delete_cvim_pod(self):
        """
        Function to add cvim target to stack
        """
        self.delete_cvim_pod = True
        self.perform_steps = ['1', '7']

    def set_alertmanager_config(self, alertmanager_config, stack_name):
        """
        set user alertmanager_config file on reconfiguring
        """

        stack_list, _ = self.get_stack_vip(stack_name)
        if stack_name and not stack_list:
            print("Invalid Stack Name:{}. Aborting operation.".format(
                stack_name))
            return MFAILURE

        self.alertmanager_config = alertmanager_config
        self.stack_name = stack_name
        self.perform_steps = ['1', '7']
        return MSUCCESS

    def set_alerting_rules_config(self, alerting_rules_config, stack_name):
        """
        set user alerting_rules_config file
        """

        stack_list, _ = self.get_stack_vip(stack_name)
        if stack_name and not stack_list:
            print("Invalid Stack Name:{}. Aborting operation.".format(
                stack_name))
            return MFAILURE

        self.alerting_rules_config = alerting_rules_config
        self.stack_name = stack_name
        self.perform_steps = ['1', '7']
        return MSUCCESS

    def set_reconfigure_cvim_pod(self):
        """
        Function to reconfigure cvim target
        """
        self.reconfigure_cvim_pod = True
        self.perform_steps = ['1', '7']

    def set_update_op(self):
        """
        Function to start update
        """
        self.update = True
        self.perform_steps = ['2', '3', '5', '6', '7']

    def set_rollback_op(self):
        """
        Function to start rollback
        """
        self.rollback = True
        self.perform_steps = ['2', '3', '7']

    def set_commit_op(self):
        """
        Function to start commit
        """
        self.commit = True
        self.perform_steps = ['3', '7']

    @staticmethod
    def get_user_answer(msg, force_yes):
        """
        Function to get user input
        """
        if force_yes:
            print(msg, " Y ")
        else:
            user_input = raw_input(msg)
            if user_input.lower() != "y":
                return MFAILURE
        return MSUCCESS

    def validate_steps(self, input_value):
        """
        Function to validate user provided steps
        return: list of steps that are not allowed
                None if all provided steps are valid
        """
        steps_to_validate = set(input_value.strip().split(","))
        operation_list = set([op['id'] for op in self.operations])
        if not steps_to_validate.issubset(operation_list):
            return sorted(list(steps_to_validate - operation_list))
        return None

def check_nodes_reboot_required():
    """
    Check that Kubernetes Nodes Required Reboot
    """
    if not os.path.exists(INVENTORY_FILE):
        return []

    with open(INVENTORY_FILE, 'r') as inventoryfile:
        node_data = yaml.safe_load(inventoryfile)

    nodes = node_data.keys()
    reboot_required_nodes = []
    for node in nodes:
        for retries in range(0, 10):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(
                    paramiko.AutoAddPolicy())
                client.connect(node, timeout=60)
                cmd = "/usr/bin/needs-restarting -r"
                stdin, stdout, stderr = client.exec_command(cmd) # nosec
                if stdout.channel.recv_exit_status():
                    reboot_required_nodes.append(node)
                client.close()
                break
            except Exception as ex:
                print("Exception while checking reboot status for {}: " \
                      "{}".format(node, ex))
                time.sleep(10)
    return reboot_required_nodes

def get_current_time():
    """
    Get Current Time
    """
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def get_absolute_path_for_file(file_name, splitdir=None):
    """
    Return the filename in absolute path for any file
    passed as relative path.
    """
    base = os.path.basename(__file__)
    if splitdir is not None:
        splitdir = splitdir + "/" + base
    else:
        splitdir = base

    if os.path.isabs(__file__):
        abs_file_path = os.path.join(__file__.split(splitdir)[0],
                                     file_name)
    else:
        abs_file = os.path.abspath(__file__)
        abs_file_path = os.path.join(abs_file.split(splitdir)[0],
                                     file_name)

    return abs_file_path


def get_sds_registry():
    """
    Check if registry_name is specified in setupfile.
    If REGISTRY_NAME exists then we assume SDS is enabled
    """
    parsed_userinput = config_parser.YamlHelper(user_input_file=SETUP_FILE)
    registry_name = parsed_userinput.get_data_from_userinput_file(
        ['REGISTRY_NAME'])
    return registry_name if registry_name else None

def is_full_install(args):
    """Check is this ia a full installation.

    A full installation is when --install is provided without skip step or perform step
    or when step 7 is included in the skip step/perform step

    """
    if args.install:
        if args.perform_steps:
            selected_steps = args.perform_steps.strip().split(",")
            return '7' in selected_steps
        if args.skip_steps:
            skipped_steps = args.skip_steps.strip().split(",")
            return '7' not in skipped_steps
        return True
    return False

def install_need_setup_rollback(args):
    """Check in what case an install operation needs a ref setupfile rollback.

    We need to rollback the ref setupfile when the user passes step 1 and/or step 2 only
    regardless of success or failure if these steps.
    We do not rollback the ref setupfile for any steps beyond 2
    """
    if not args.perform_steps:
        return False
    selected_steps = set(args.perform_steps.strip().split(","))
    return selected_steps == set(['1']) or selected_steps == set(['1', '2'])

def main():
    parser = k8s_parser.get_parser()
    parser = k8s_parser.add_arguments(parser)
    if len(sys.argv) == 1:
        parser.print_help()
        return(MFAILURE)
    args = parser.parse_args()

    runner = Runner()
    runner.set_log_dir()
    runner.db = DB.Database(cv.SQLITE_DB_PATH, runner.log)
    runner.validate_operation = vo.ValidateOperation(runner.db, runner.log)

    runner.full_installation_allowed = runner.validate_operation.is_full_installation_allowed()

    last_install_entry = runner.db.get_last_install_entry()
    # Format: attributes of last_install_entry => op_name, status, timestamp
    runner.log.debug("Last install: {}:{}"\
        .format(last_install_entry.op_name, last_install_entry.status))

    # # Use the runner file name only, not using __file__:
    # #  -> Not set in non-standard import mechanism.
    # #  -> Not defined in the interactive interpreter.
    if is_runner_running('k8s_runner'):
        print("Another k8s-runner process already running. Please Wait. Exiting......")
        runner.log.debug(cv.OP_FAIL_STRICT)
        return(MFAILURE)

    # Allow bypass if an operation is running in db (last operation crashed)
    if runner.validate_operation.is_last_operation_running():
        if args.force:
            print("The Last operation was killed or failed unexpectedly.... "
                  "The --force argument is passed. Continuing with the operation")
            runner.log.debug(cv.OP_FORCE)
        else:
            print("The Last operation was killed or failed unexpectedly.... "
                  "Use --force argument to Override")
            runner.log.debug(cv.OP_FAIL_CRIT)
            return(MFAILURE)

    # Log the command invoked
    runner.log.debug("The command executed was : {}".format(' '.join(sys.argv)))

    # validate_args will validate all the combinations of the arguments provided
    return_code = k8s_parser.validate_args(args)
    if return_code != MSUCCESS:
        return(return_code)

    # Check for full installation
    # Possible options include:
    # 1) Only providing --install argument no steps provided
    # 2) Providing --install and --perform_steps includes step 7
    #    (e.g. 2,3,4,5,6,7 or 4,5,6,7 or 7)
    if is_full_install(args):
        if runner.full_installation_allowed:
            runner.running_full_installation = True
            runner.log.debug(cv.OP_FIRST_INSTALL)
        else:
            # full install is not allowed
            print("Full installation is not allowed on a successful pre-installed testbed."
                  "Use --force argument to Override.")
            runner.log.debug(cv.OP_FAIL_INVALID)
            return(MFAILURE)

    # populate_runner_args will populate the 'operation steps to run' in runner instance
    # For example: which steps to run, which steps are skipped, etc
    return_code, operation, status, runner = k8s_parser.populate_runner_ops(args, runner)
    if return_code:
        runner.log.error("Failed while populating runner ops at operation: {}".format(operation))
        return(return_code)

    # This function will populate the details about the operations
    # For example: config file paths, etc
    runner.populate_runner_info()

    if args.list_steps:
        # this cannot be called before populate_runner_info() is called
        runner.print_operations()
        return(MSUCCESS)

    # Load the ref and backup config fileset
    setup_data_info = manage_setup.CvimmonSetup()

    # Check if the reference setup data is consistent with backup setup data.
    # In case of any difference, fail the current operation.
    # For install we bypass this check completely as we're going to
    # load the candidate setupfile regardless of current state and we will
    # backup only if step 7 succeeds
    if not args.install:
        if not setup_data_info.reference_equal_backup() and \
                (not runner.full_installation_allowed or not args.force):
            print("Error: Reference setupdata is different from backup setupdata. "
                  "This can be caused by an accidental overwrite of the reference setupdata "
                  "file or by a previously aborted failed operation. The cluster needs to be "
                  "checked for consistency and the reference setup data reverted before this "
                  "operation can proceed.")
            return(MFAILURE)

    # The following operations doesn't require any steps to run
    # and will exit process right after the execution
    if args.manage_custom_dashboards:
        return_code = runner.exec_manage_dashboards(args.save_dashboard, args.list_dashboard,
                                                    args.upload_dashboard, args.dir_path,
                                                    args.dry_run, args.force,
                                                    args.preserve_dashboard, args.stack_name)
        return(return_code)

    if args.get_endpoint:
        namespace_name = args.get_endpoint
        if not namespace_name:
            namespace_name = "all"
        return_code = runner.exec_get_endpoints(namespace_name)
        return(return_code)

    if args.get_secrets:
        namespace_name = args.get_secrets
        if not namespace_name:
            namespace_name = "all"
        return_code = runner.exec_get_secrets(namespace_name)
        return(return_code)

    if args.get_password:
        return_code = runner.exec_get_password(args.get_password)
        return(return_code)

    if args.skip_steps or args.perform_steps:
        steps = args.skip_steps or args.perform_steps
        invalid_steps = runner.validate_steps(steps)
        if invalid_steps:
            print("Error! \n Unknown operation ID provided: {}\n" \
                    .format(",".join(invalid_steps)))
            runner.print_operations()
            return(MFAILURE)

    # Following two functions need user prompt
    if args.skip_steps:
        return_code = runner.set_skip_steps(args.skip_steps, args.skip_prompt)
        if return_code:
            return(return_code)

    if args.perform_steps:
        return_code = runner.set_perform_steps(args.perform_steps, args.skip_prompt)
        if return_code:
            return(return_code)

    cfg_dir = os.environ['HOME'] + '/' + DEFAULT_CFG_DIR
    cfgd = INSTALLER_DIR + '/' + DEFAULT_CFG_DIR

    if os.path.exists(cfg_dir) and runner.update:
        link_dir = os.readlink(cfg_dir)
        if link_dir == cfgd:
            print("Error: Update cannot be run from the same workspace")
            return(MFAILURE)

    if os.path.exists(cfg_dir) and (runner.rollback or runner.commit):
        update_file = os.path.join(cfgd, "update.yaml")
        if not os.path.exists(update_file):
            print("Error: Rollback or Commit can run only on updated workspace")
            return(MFAILURE)

    if os.path.exists(
            cfg_dir) and not runner.update and not runner.rollback and \
            not runner.commit:
        os.unlink(cfg_dir)
        os.symlink(cfgd, cfg_dir)
    elif not os.path.exists(cfg_dir):
        os.symlink(cfgd, cfg_dir)

    # At this point we can be sure that setupfile when passed is legit
    # After loading, if any operation fails, we will have to call rollback
    # so that the target workspace setupfileset is restored
    candidate_loaded = False
    if runner.setupdata_file:
        setup_data_info.load_candidate(runner.setupdata_file)
        candidate_loaded = True
    elif runner.update:
        # update is from old/current workspace to new workspace
        # load the setup data fileset from the old workspace to the new workspace
        setup_data_info.load_candidate(cfg_dir + "/setup_data.yaml")
        candidate_loaded = True

    return_code = 0

    if runner.alertmanager_config and runner.stack_name:
        alertmanager_config = "/opt/cisco/cvimmon-metros/" + \
            runner.stack_name + \
            "/prometheus/alertmanager_custom_config.yaml"
        if os.path.exists(runner.alertmanager_config):
            if os.path.realpath(runner.alertmanager_config) != alertmanager_config:
                shutil.copy(runner.alertmanager_config, alertmanager_config)
        else:
            print("Error! Input file: {} does not exist." \
                  "Please enter a valid input file with --alertmanager_config option" \
                .format(runner.alertmanager_config))
            return_code = MFAILURE

    elif runner.alerting_rules_config and runner.stack_name:
        alerting_rules_config = "/opt/cisco/cvimmon-metros/" + \
            runner.stack_name + \
            "/prometheus/alerting_custom_rules.yaml"
        if os.path.exists(runner.alerting_rules_config):
            if os.path.realpath(
                    runner.alerting_rules_config) != alerting_rules_config:
                shutil.copy(runner.alerting_rules_config, alerting_rules_config)
        else:
            print("Error! Input file: {} does not exist." \
                  "Please enter a valid input file" \
                .format(runner.alerting_rules_config))
            return_code = MFAILURE

    read_files = setup_data_info.get_ref_setup_data()
    if not read_files:
        print("Error! Input file is empty.")
        return_code = MFAILURE
    else:
        log_dir = runner.runner_info.get("log_dir")
        print("The logs for this run are available at {}\n".format(log_dir))
        try:
            return_code = runner.runner_run_sequential(setup_data_info)
        except Exception as exc:
            # We should never come here
            print("The Runner Sequential Failed Unexpectedly.....")
            print(str(exc))
            return_code = MFAILURE
            if runner.running_full_installation:
                runner.db.insert_install_entry(runner.last_action, cv.STATUS_FAIL, runner.timestamp)
            else:
                runner.db.insert_operation_entry(runner.last_action, cv.STATUS_FAIL, runner.timestamp)
        # always archive the log regardless of result
        runner.archive_logs()

    # Upon operation termination we must either rollback on error or backup on success
    # if a candidate setup file set was loaded
    if candidate_loaded:
        if args.install:
            # this is for those -p1 or -p1,2
            # in that case we do not want to leave the candidate setupfile in ref
            if install_need_setup_rollback(args):
                setup_data_info.rollback()
        else:
            # all other non install operations
            # install is special because we can backup only if step 7 is successful
            # (this is done in runner_run_sequential)
            # all other cases of partial steps should cause a revert even if successful
            # e.g. step 1 validation
            if return_code:
                setup_data_info.rollback()
            else:
                setup_data_info.backup()

    # Last step is to performa an auto-backup if necessary
    # this will check if the last runner.runner_run_sequential() was successful
    # and requires an auto backup
    runner.auto_backup_mgmt_node()

    return(return_code)

if __name__ == '__main__':
    ret_code = main()
    sys.exit(ret_code)
