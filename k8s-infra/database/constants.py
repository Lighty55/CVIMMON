#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""This module stores the contants which are shared by the following modules:
k8s_runner, validate_operations, database
"""
# For logs
SQLITE_DB_PATH = '/opt/cisco/cvimmon-k8s/k8s-operations.db'
OP_FAIL_CRIT = "SQLITE DB: Error Critical! The operation is not allowed. Use force operation"
OP_FAIL_STRICT = "SQLITE DB: Error Strict! K8s_runner process already running. Can't proceed"
OP_FAIL_INVALID = "SQLITE DB: Warning! The operation is not allowed"
OP_SUCESS = "SQLITE DB: The operation is successfully Completed"
OP_FORCE = "SQLITE DB: The Force argument is used"
OP_FIRST_INSTALL = "SQLITE DB: First Installation, allowing full installation"

STATUS_FAIL_STRICT = "Strict Not Allowed"
STATUS_FAIL_CRIT = "Not Allowed"
STATUS_FAIL = "failed"
STATUS_SUCCESS = "success"
STATUS_RUNNING = "running"
STATUS_USER_DECLINE = "User Declined"
OP_SKIP_STEPS = "skip_steps"
OP_PERFORM_STEPS = "perform_steps"
OP_SKIP_PERFORM_STEPS = "skip_perform_steps"

SETUP_DATA_ERROR = {'err_status': "Invalid Setup Data",\
                    'log': "Invalid Setup Data provided. Please Check..."}
REPLACE_MASTER = {'log': "Could not perform replace master operation"}
ADD_WORKER = {'log': "Could not perform add worker operation"}
REMOVE_WORKER = {'log': "Could not perform remove worker operation"}
ALERTMANAGER_CONFIG = {'op': "alertmanager_config", 'log': "", }
ALERTING_RULES_CONFIG = {'op': "alerting_rules_config", 'log': ""}

# The following are the possible entries in db status
FULL_INSTALL_STEP_7 = 'install__step__7'
FULL_INSTALL_FIRST_OP = 'install__step__1'
INITIAL_STATUS = 'first_status'
INITIAL_OP = "operation__step__0"
INITIAL_TS = "dummy_timestamp"
OP_INSTALL_STEP_2 = 'install__step__2'

# Operations allowed by k8s-runner
OP_CUSTOM_DASHBOARD = "manage_custom_dashboards"
OP_UPLOAD_DASHBOARD = "upload_dashboard"
OP_GET_SECRETS = "get_secrets"
OP_ADD_MASTER = "add_master"
OP_REMOVE_WORKER = "remove_worker"
OP_REPLACE_MASTER = "replace_master"
OP_RECONFIGURE = "reconfigure"
OP_UPDATE = "update"
OP_ROLLBACK = "rollback"
OP_COMMIT = "commit"
OP_REGENERATE_SECRETS = "regenerate_secrets"
OP_REGENERATE_CERTS = "regenerate_certs"
OP_RENEW_CERTS = "k8s_renew_certs"
OP_ETCD_RENEW_CERTS = "etcd_renew_certs"
OP_RECONFIGURE_STACK = "reconfigure_stack"
OP_ADD_STACK = "add_stack"
OP_DELETE_STACK = "delete_stack"
OP_ADD_CVIM_POD = "add_cvim_pod"
OP_DELETE_CVIM_POD = "delete_cvim_pod"
OP_CUSTOM_ALERT_CONFIG = "custom_alert_config"
OP_CUSTOM_ALERT = "custom_alerts"
OP_RECONFIGURE_CVIM_POD = "reconfigure_cvim_pod"
OP_LIST_STEPS = "list_steps"
OP_GET_ENDPOINT = "get_endpoint"
OP_INSTALL = "install"
