#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""This module handles the argparse for k8s_runner."""

import argparse
import os

from database import constants as cv # constants_variables

from k8s_runner import MSUCCESS
from k8s_runner import MFAILURE

INSTALLER_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SETUP_FILE = INSTALLER_DIR + "/openstack-configs/setup_data.yaml"
BACKUP_SETUP_FILE = INSTALLER_DIR + "/openstack-configs/.backup_setup_data.yaml"

def get_parser():
    """This function returns an instance of argparse."""
    parser = argparse.ArgumentParser(
        description="CVIM MON HA ORCHESTRATOR",
        formatter_class=argparse.RawTextHelpFormatter)
    return parser

def add_arguments(parser):
    """This function ha the definiton of arguments required in k8s_runner."""

    # Group of arguments that are actual commands/operations
    # Only one can be selected by the user
    pod_oper_grp = parser.add_mutually_exclusive_group(required=False)
    pod_oper_grp.add_argument("--install", action="store_true",
                              dest="install",
                              help="Install CVIM-MON HA")
    pod_oper_grp.add_argument("--replace-master", type=str,
                              dest="replace_master",
                              help="Replace a Kubernetes Master")
    pod_oper_grp.add_argument("--add-worker", type=str, dest="add_worker",
                              help="Add a Worker")
    pod_oper_grp.add_argument("--remove-worker", type=str, dest="remove_worker",
                              help="Remove a Worker")
    pod_oper_grp.add_argument("--regenerate-secrets", action="store_true",
                              dest="regenerate_secrets",
                              help="Regenerate Application Secrets")
    pod_oper_grp.add_argument("--regenerate-certs", action="store_true",
                              dest="regenerate_certs",
                              help="Regenerate Application Certificates")
    pod_oper_grp.add_argument("--renew-k8s-certs", action="store_true",
                              dest="renew_k8s_certs",
                              help="Regenerate Kubernetes Infra Certificates")
    pod_oper_grp.add_argument("--renew-etcd-certs", action="store_true",
                              dest="renew_etcd_certs",
                              help="Regenerate ETCD Certificates")
    pod_oper_grp.add_argument("--reconfigure", action="store_true",
                              dest="reconfigure",
                              help="Reconfigure CVIM MON global settings: "
                                   "[log_rotation_*]")
    pod_oper_grp.add_argument("--reconfigure-stack", action="store_true",
                              dest="reconfigure_stack",
                              help="Modify CVIM MON Stack")
    pod_oper_grp.add_argument("--add-stack", action="store_true",
                              dest="add_stack",
                              help="Add CVIM MON Stack")
    pod_oper_grp.add_argument("--delete-stack", action="store_true",
                              dest="delete_stack",
                              help="Delete CVIM MON Stack")
    pod_oper_grp.add_argument("--add-cvim-pod", action="store_true",
                              dest="add_cvim_pod",
                              help="Add CVIM MON Pod")
    pod_oper_grp.add_argument("--delete-cvim-pod", action="store_true",
                              dest="delete_cvim_pod",
                              help="Delete CVIM MON Pod")
    pod_oper_grp.add_argument("--reconfigure-cvim-pod", action="store_true",
                              dest="reconfigure_cvim_pod",
                              help="Reconfigure CVIM MON Pod")
    pod_oper_grp.add_argument("--alertmanager_config", type=str,
                              dest="alertmanager_config",
                              help="User input custom alertmanager file and " \
                              "stack name")
    pod_oper_grp.add_argument("--alerting_rules_config", type=str,
                              dest="alerting_rules_config",
                              help="User input custom alerts file and stack name")
    pod_oper_grp.add_argument("--update", action="store_true", dest="update",
                              help="Update CVIM MON HA pod")
    pod_oper_grp.add_argument("--rollback", action="store_true",
                              dest="rollback",
                              help="Rollback CVIM MON HA pod")
    pod_oper_grp.add_argument("--commit", action="store_true", dest="commit",
                              help="Commit an update in CVIM MON HA pod")
    pod_oper_grp.add_argument("--cvimmon-custom-dashboards",
                              action="store_true",
                              dest="manage_custom_dashboards",
                              help="Required key to execute operations on "
                                   "grafana custom dashboards(list/save/"
                                   "upload)")
    pod_oper_grp.add_argument("--get-endpoint", type=str, dest="get_endpoint",
                              help="Fetch endpoint fqdn. Pass individual "
                                   "stack-name or all")
    pod_oper_grp.add_argument("--list-secrets", dest="get_secrets",
                              help="List Password Secret Keys. "
                                   "Use <stack_name> or 'all' to view all "
                                   "secret keys.")
    pod_oper_grp.add_argument("--get-password", dest="get_password",
                              help="Get Password of secret key provided. "
                                   "Secret key name to get the password.")
    pod_oper_grp.add_argument("--set-secrets", action="store",
                              dest="new_secret_path",
                              help="path to file to set new password for "
                                   "Prometheus/Alertmanager and Grafana.")
    pod_oper_grp.add_argument("-l", "--list-steps", dest="list_steps",
                             action="store_true",
                             help="List steps")

    # These are additional arguments that are conditional to the selected
    # operation argument
    parser.add_argument("--save-dashboards", action="store_true",
                        dest="save_dashboard",
                        help="Persist custom dashboards from Grafana "
                             "onto the management node")
    parser.add_argument("--list-dashboards", action="store_true",
                        dest="list_dashboard",
                        help="List custom dashboards")
    parser.add_argument("--upload-dashboards", action="store_true",
                        dest="upload_dashboard",
                        help="Upload custom dashboards from the management "
                             "node to Grafana")
    parser.add_argument("--force", action='store_true', default=False,
                        dest="force",
                        help="Delete dashboards in the destination "
                             "if they are missing in the source.")
    parser.add_argument("--preserve", action='store_true', default=False,
                        dest="preserve_dashboard",
                        help="Preserve dashboards in the destination "
                             "if they are missing in the source")
    parser.add_argument("--dir-path", action="store", type=str,
                        dest="dir_path",
                        help="Upload- will be persisted on the management node "
                             "and uploaded to Grafana\n Save- will be "
                             "persisted on custom dir from Grafana server")
    parser.add_argument("--dry-run", action="store_true",
                        dest="dry_run", default=False,
                        help="To view what changes will be made on grafana. "
                             "No actual changes will be made.")
    parser.add_argument("--stack-name", action="store", type=str,
                        dest="stack_name",
                        help="Name of the CVIM-MON stack onto which "
                             "the requested operation will be applied")

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-s", "--skip_steps", default=None, dest="skip_steps",
                       help="Comma separated list of steps to skip. eg -s 2,3")
    group.add_argument("-p", "--perform_steps", default=None,
                       dest="perform_steps",
                       help="Comma separated list of steps to perform. eg "
                            "-p 2,3")

    parser.add_argument("-y", "--yes", dest="skip_prompt", action="store_true",
                        help="Yes option to skip steps without prompt")
    parser.add_argument("--setupfile",
                        type=str, dest="setupfile",
                        help="Location of the candidate setupdata file")

    return parser

def is_setupfile_mandatory(args):
    """Check if the setupfile is mandatory for the selected arg-operation."""
    # List of operations that require a setup file:
    setupfile_mandatory = [args.install,
                           args.replace_master,
                           args.add_worker,
                           args.remove_worker,
                           args.reconfigure,
                           args.reconfigure_stack,
                           args.add_stack,
                           args.delete_stack,
                           args.add_cvim_pod,
                           args.delete_cvim_pod,
                           args.reconfigure_cvim_pod,
                           args.regenerate_certs]
    return any(setupfile_mandatory)


def has_operation_arg(args):
    """Check that at least one operation argument is being chosen."""
    # check if arg with setupfile
    if is_setupfile_mandatory(args):
        return True
    # These are operations that do not allow a setupfile
    other_operations = [
        args.regenerate_secrets,
        args.get_password,
        args.renew_k8s_certs,
        args.renew_etcd_certs,
        args.alertmanager_config,
        args.alerting_rules_config,
        args.update, args.rollback, args.commit,
        args.manage_custom_dashboards,
        args.get_endpoint,
        args.get_secrets,
        args.new_secret_path,
        args.list_steps,
        args.list_dashboard
    ]
    return any(other_operations)

def validate_args(args):
    """This function validates just the arguments provided by the user.

    return MSUCCESS if OK
    """

    return_code = MSUCCESS

    # Make sure that the user passes at least 1 operation in the argument lists
    # the parser will take care of making suere there is at least one (exclusion list)
    if not has_operation_arg(args):
        print("Error: you must specify one operation in the argument list")
        return MFAILURE

    # If setupfile is provided, check it exists and is neither of the ref or backup file
    if args.setupfile:
        # check that the command is allowed to have a setupfile
        if not is_setupfile_mandatory(args):
            print("Error: --setupfile is prohibited for the requested operation")
            return_code = MFAILURE
        if not os.path.exists(args.setupfile):
            print("Error: Enter a valid input file with --setupfile option")
            return MFAILURE
        if os.path.realpath(args.setupfile) == SETUP_FILE:
            print("Error: Cannot pass reference setupdata file with " \
                  "--setupfile option")
            return MFAILURE
        if os.path.realpath(args.setupfile) == BACKUP_SETUP_FILE:
            print("Error: Cannot pass backup setupdata file with --setupfile option")
            return MFAILURE
    else:
        # no --setupfile was passed
        if is_setupfile_mandatory(args):
            # all operations listed in setupfile_mandatory
            # must have a setup data file passed
            print("--setupfile is mandatory for the requested operation")
            return MFAILURE

    # skip steps and perform steps are only allowed with --install
    if (args.skip_steps or args.perform_steps) and not args.install:
        print("Error: --skip_steps or --perform__steps are only supported "
              "with --install")
        return MFAILURE

    if args.alertmanager_config and not args.stack_name:
        print("Stack name is mandatory with custom alertmanager config")
        return_code = MFAILURE

    if args.alerting_rules_config and not args.stack_name:
        print("Stack name is mandatory with custom alerting rules")
        return_code = MFAILURE

    dashboard_operation = [args.save_dashboard, args.list_dashboard,
                           args.upload_dashboard, args.stack_name,
                           args.preserve_dashboard, args.dir_path]

    if any(dashboard_operation) and not (args.manage_custom_dashboards or
                                         args.alertmanager_config or
                                         args.alerting_rules_config):
        print("ERROR: [--save-dashboard, --list-dashboard, "
              "--upload-dashboard, "
              "--force, --preserve-dashboard, --dir-path] "
              "are only supported with --cvimmon-custom-dashboards")
        return_code = MFAILURE

    elif args.manage_custom_dashboards and not (args.save_dashboard or
                                                args.list_dashboard or
                                                args.upload_dashboard or
                                                args.force or
                                                args.preserve_dashboard or
                                                args.dir_path):
        print("ERROR: Atleast one of [--save-dashboard, --list-dashboard, "
              "--upload-dashboard, --force, --preserve-dashboard, --dir-path] "
              "should be passed  with --cvimmon-custom-dashboards")
        return_code = MFAILURE

    elif args.manage_custom_dashboards:
        if not args.stack_name:
            print("--stack-name is mandatory")
            return_code = MFAILURE
        elif args.stack_name.lower() == "all":
            print("Stack name all is not supported with --cvimmon-custom-dashboards")
            return_code = MFAILURE

    if args.upload_dashboard:
        if not args.dir_path:
            print("ERROR: --dir-path is mandatory with upload option for dashboards")
            return_code = MFAILURE
        if not (args.preserve_dashboard or args.force):
            print("ERROR: --preserve or --force needs to be passed with "
                  "--upload-dashboard")
            return_code = MFAILURE

    if args.new_secret_path:
        file_path = args.new_secret_path
        if not os.path.exists(file_path):
            print("\nERROR: Missing file to change secrets.")
            return_code = MFAILURE
        if not os.path.isfile(file_path):
            print("\nERROR: {} is not a valid file type".format(file_path))
            return_code = MFAILURE

    return return_code

def populate_runner_ops(args, runner):
    """
    This module will set up the operation steps (to be performed) in the runner instance.
    However, this function does not populate
    the details like: config file to use, etc
    """
    return_code = MSUCCESS
    status = None
    operation = None

    if args.setupfile:
        runner.set_setupdata_file(args.setupfile)

    # Following args are grouped, only one of them is allowed
    if args.replace_master:
        return_code = runner.set_replace_master(args.replace_master)

    elif args.add_worker:
        return_code = runner.set_add_worker(args.add_worker)

    elif args.remove_worker:
        return_code = runner.set_remove_worker(args.remove_worker)

    elif args.regenerate_secrets:
        runner.set_regenerate_secrets()

    elif args.regenerate_certs:
        runner.set_regenerate_certs()

    elif args.renew_k8s_certs:
        runner.set_renew_k8s_certs()

    elif args.renew_etcd_certs:
        runner.set_renew_etcd_certs()

    elif args.reconfigure:
        runner.set_reconfigure()

    elif args.reconfigure_stack:
        runner.set_reconfigure_stack()

    elif args.add_stack:
        runner.set_add_stack()

    elif args.delete_stack:
        runner.set_delete_stack()

    elif args.add_cvim_pod:
        runner.set_add_cvim_pod()

    elif args.delete_cvim_pod:
        runner.set_delete_cvim_pod()

    elif args.reconfigure_cvim_pod:
        runner.set_reconfigure_cvim_pod()

    elif args.install:
        runner.set_install()

    elif args.update:
        runner.set_update_op()

    elif args.rollback:
        runner.set_rollback_op()

    elif args.commit:
        runner.set_commit_op()

    elif args.alertmanager_config:
        return_code = runner.set_alertmanager_config(args.alertmanager_config,
                                                     args.stack_name)
        operation = cv.ALERTING_RULES_CONFIG['op']

    elif args.alerting_rules_config:
        return_code = runner.set_alerting_rules_config(args.alerting_rules_config,
                                                       args.stack_name)
        operation = cv.ALERTING_RULES_CONFIG['op']

    elif args.new_secret_path:
        file_path = args.new_secret_path
        return_code = runner.exec_change_secrets(file_path)
        operation = cv.OP_GET_SECRETS
        status = MFAILURE
        runner.set_reconfigure_stack()

    return return_code, operation, status, runner
