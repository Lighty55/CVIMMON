#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import sys
import shutil
import stat
import subprocess
import yaml
import utils.common as common_utils
import utils.logger as logger
import utils.config_parser as config_parser
import clouddeploy.validations as validations
import clouddeploy.hw_validations as hw_validations

TASK_PATTERN = re.compile(r'.*TASK  *\[(\w+(?:[-\w]*\w)) *\ : *(.*) *]')
DEFAULT_CFG_DIR = "/root/openstack-configs"
DEFAULTS_FILE = "/root/openstack-configs/defaults.yaml"
DEFAULT_ARGUS_SITE_FILE = "argus_site.yaml"
SETUP_DATA_FILE = "/root/openstack-configs/setup_data.yaml"
ARGUS_SITE_FILE = "/root/openstack-configs/argus_site.yaml"
DEFAULTS_FILE_NAME = "defaults.yaml"
DOCKER_FILE = "cvim_mon_ha.yaml"
CFG_DIR = "openstack-configs"

INSTALLER_ROOT = os.getcwd()


class OrchestratorStatus(object):
    """
    Status
    """
    OPER_STAGE = "INIT"
    STAGE_COUNT = 0


class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)


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


def build_ansible_cmd(orchestrator, setupdata_file, defaults_file,
                      docker_file, argussite_file, ansible_playbook):
    """
    Build the ansible cmd string based on the setup files,
    and arguments passed to the orchestrator module.
    """

    playbook_dir = os.path.dirname(os.path.abspath(__file__))
    action = orchestrator.run_args.get('action', None)

    tags = orchestrator.run_args.get('tags')

    if action in ["update"] and tags != "common_setup":
        old_cfg_dir = DEFAULT_CFG_DIR
        new_cfg_dir = os.path.join(os.getcwd(), CFG_DIR)
        if not os.path.exists(old_cfg_dir):
            orchestrator.log.error("Old workspace doesn't exist")
            return None

        file_list = ['defaults.yaml', 'update_scope.yaml',
                     'change_manifest.yaml',
                     'update.yaml', 'upgrade.yaml',
                     'alerting_custom_rules.yml.EXAMPLE',
                     'alertmanager_custom_config.yml.EXAMPLE',
                     'argus_baremetal.EXAMPLE',
                     'argus_cluster.yaml.EXAMPLE',
                     'argus_node.yaml.EXAMPLE',
                     'argus_site.yaml.EXAMPLE',
                     'bmc.yaml.CVIMMONHA.EXAMPLE',
                     'insight_setup_data.yaml.Standalone_EXAMPLE',
                     'ironic_inventory.yaml.EXAMPLE',
                     'sds_setup_data.yaml.EXAMPLE',
                     'setup_data.yaml.Argus.EXAMPLE',
                     'setup_data.yaml.B_Series_EXAMPLE',
                     'setup_data.yaml.CentralCeph_EXAMPLE',
                     'setup_data.yaml.CentralMgmt.EXAMPLE',
                     'setup_data.yaml.C_Series_EXAMPLE',
                     'setup_data.yaml.CVIMMONHA.EXAMPLE', 'README',
                     'tech_support_cfg.yaml', 'tech_support_argus.yaml',
                     'tech_support_sds.yaml', 'tech_support_cvimmon.yaml',
                     'script_EXAMPLE.sh', '.tech_support_stage.cfg',
                     'QCILxDiag_V1.3.3S_2_S5BT_RTN_20181113_Custom.tar.xz',
                     'SCELNX64_v5.03.1111.zip', 'SKU_SPEC_Check_1.4.20181227.zip',
                     'policy_exec_plan.yaml', 'telegraf_plugins_intervals.yaml']

        def skip_file_copy(path, names):
            ignore_list = []
            for name in names:
                if name in file_list:
                    ignore_list.append(name)
            return ignore_list

        def copytree(src, dst, symlinks=False, ignore=None):
            if not os.path.exists(dst):
                os.makedirs(dst)
                shutil.copystat(src, dst)
            lst = os.listdir(src)
            if ignore:
                excl = ignore(src, lst)
                lst = [x for x in lst if x not in excl]
            for item in lst:
                s = os.path.join(src, item)
                d = os.path.join(dst, item)
                if symlinks and os.path.islink(s):
                    if os.path.lexists(d):
                        os.remove(d)
                    os.symlink(os.readlink(s), d)
                    try:
                        st = os.lstat(s)
                        mode = stat.S_IMODE(st.st_mode)
                        os.lchmod(d, mode)
                    except Exception:  # nosec
                        pass  # lchmod not available
                elif os.path.isdir(s):
                    copytree(s, d, symlinks, ignore)
                else:
                    shutil.copy2(s, d)

        for name in os.listdir(old_cfg_dir):
            file_path = os.path.join(old_cfg_dir, name)
            if os.path.isdir(file_path):
                dir_path = os.path.join(new_cfg_dir, name)
                copytree(file_path, dir_path, ignore=skip_file_copy)
            else:
                if name not in file_list:
                    shutil.copy(file_path, new_cfg_dir)

        old_ws = "-esl_insdir=" + os.readlink(old_cfg_dir)
        os.unlink(old_cfg_dir)
        os.symlink(new_cfg_dir, old_cfg_dir)
        action_var = "-eACTION=" + action

        ansible_cmd = ["ansible-playbook", ansible_playbook,
                       "-e", "@" + defaults_file, "-e", "@" + setupdata_file,
                       "-e", "@" + argussite_file,
                       action_var, old_ws]

    elif action in ["update"] and tags == "common_setup":

        old_cfg_dir = DEFAULT_CFG_DIR
        new_cfg_dir = os.path.join(os.getcwd(), CFG_DIR)
        if not os.path.exists(old_cfg_dir):
            orchestrator.log.error("Old workspace doesn't exist")
            return None
        old_ws = "-esl_insdir=" + os.readlink(old_cfg_dir)
        action_var = "-eACTION=" + action

        ansible_cmd = ["ansible-playbook", ansible_playbook,
                       "-e", "@" + defaults_file, "-e", "@" + setupdata_file,
                       "-e", "@" + argussite_file,
                       action_var, old_ws]

    elif action == "rollback":
        action_var = "-eACTION=" + action
        ansible_cmd = ["ansible-playbook", ansible_playbook, "-e",
                       "@" + docker_file,
                       "-e", "@" + defaults_file, "-e", "@" + setupdata_file,
                       "-e", "@" + argussite_file,
                       action_var]

    else:
        ansible_cmd = ["ansible-playbook", ansible_playbook,
                       "-e", "@" + defaults_file, "-e", "@" + setupdata_file,
                       "-e", "@" + argussite_file]

    ansible_options = ""
    controller = orchestrator.run_args.get('replace_node', None)
    if controller:
        ansible_option = ansible_options + "-e server=:&%s" % "".join(
            controller)
        ansible_cmd.append(ansible_option)

    add_worker = orchestrator.run_args.get('add_node', None)
    if add_worker:
        ansible_option = ansible_options + "-e server=:&%s" % "".join(
            add_worker)
        ansible_cmd.append(ansible_option)

    tags = orchestrator.run_args.get('tags')
    ansible_cmd.append("--tags=%s" % tags)
    if tags == "mgmt_setup":
        ansible_cmd.extend(["-i", "localhost"])
    if tags == "common_setup":
        ansible_cmd.extend(["-e", "@" + docker_file])

    return ansible_cmd


def execute_getartifacts(orchestrator, action):
    """
    Execute getartifacts and fetch all CVIM MON HA artifacts
    """
    results = {'status': 'PASS'}

    orchestrator.log.debug("Executing Get Artifacts Phase")
    logging_dir = orchestrator.loginst.loggerconfig.get_global_logging_dir()

    tools_dir = os.path.join(INSTALLER_ROOT, "tools")
    configparser = config_parser.YamlHelper()
    regmode = configparser.get_install_type()
    proxy_required = configparser.get_https_proxy_server()
    release_server = configparser.get_registry_name()
    installmode = configparser.get_install_mode()
    releasetag = ""

    if action in ["update"]:
        new_cfg_dir = os.path.join(INSTALLER_ROOT, "openstack-configs")
        defaults_file = os.path.join(new_cfg_dir, "defaults.yaml")
    else:
        defaults_file = DEFAULTS_FILE

    with open(defaults_file, "r") as f:
        def_data = yaml.safe_load(f.read())
        artifacts_dir = str(def_data["ARTIFACT_PATH"])
        if regmode == "internal":
            releasetag = str(def_data["image_tag"])
        else:
            releasetag = str(def_data["RELEASE_TAG"])

    try:
        if installmode == "connected":
            artifact_log = os.path.join(logging_dir, "getartifacts.log")
            if not os.path.exists(artifacts_dir):
                os.makedirs(artifacts_dir)
            msg = "Get Artifacts Phase...Takes Time !!"
            orchestrator.set_oper_stage(msg)
            reguser, regpasswd = configparser.get_registry_credentials()
            getartscmd = ["./getartifacts.py", "-t", releasetag, "-u",
                          reguser, "-p", regpasswd, "--local", artifacts_dir,
                          "--mgmtk8s"]

            if regmode == "internal":
                getartscmd.append("-I")
            else:
                if proxy_required:
                    getartscmd.append("--proxy")
                    getartscmd.append(proxy_required)

            if release_server:
                getartscmd.extend(["--releaseserver", release_server])
            else:
                getartscmd.extend(["--releaseserver",
                                  str(def_data["registry"])])

            for index, item in enumerate(getartscmd):
                if item == "-p":
                    getartscmd[index + 1] = "*****"
                    orchestrator.log.debug("getartifacts cmd : %s",
                                           getartscmd)
                    getartscmd[index + 1] = regpasswd

            with open(artifact_log, 'w') as output_log:
                ret = subprocess.call(getartscmd,
                                      cwd=tools_dir,
                                      stdout=output_log,
                                      stderr=output_log)
            if ret:
                orchestrator.log.debug("Get Artifacts step failed")
                results['status'] = "FAIL"
                return results
        else:
            with open(defaults_file, "r") as f:
                image_tag = str(yaml.safe_load(f.read())["image_tag"])
            status_file = "download_complete_%s" % image_tag
            if not os.path.exists(os.path.join(artifacts_dir, status_file)):
                orchestrator.log.debug("Please run "
                                       "getartifacts/import_artifacts for "
                                       "disconnected install")
                results['status'] = "FAIL"
                return results

        install_rpms = ["python-websocket-client-0.32.0-116.el7.noarch.rpm",
                        "python-docker-pycreds-1.10.6-4.el7.noarch.rpm",
                        "python-docker-py-1.10.6-4.el7.noarch.rpm"]
        for rpm in install_rpms:
            try:
                rpm_path = os.path.join(artifacts_dir, rpm)
                if os.path.exists(rpm_path):
                    subprocess.check_call(["/usr/bin/rpm", "--nosignature",
                                           "-U", "--force",
                                           artifacts_dir + "/" + rpm])
            except subprocess.CalledProcessError:
                orchestrator.log.debug("RPM install failed: %s", rpm)
                results['status'] = "FAIL"

    except KeyboardInterrupt:
        set_run_result(results, 'status', 'FAIL')
        set_run_result(results, 'err_msg', "Installer killed by user")
        return results

    return results


def execute_ansible_playbooks(orchestrator):
    """
    Execute Ansible Playbooks.
    """
    results = dict()
    results['status'] = 'PASS'
    orchestrator.log.debug("Executing Ansible Playbook")

    action = orchestrator.run_args.get('action', None)
    tags = orchestrator.run_args.get('tags', None)
    setupdata_file = SETUP_DATA_FILE
    argussite_file = ARGUS_SITE_FILE
    defaults_file = DEFAULTS_FILE
    docker_file = os.path.join(DEFAULT_CFG_DIR, DOCKER_FILE)
    remove_worker = orchestrator.run_args.get('remove_node', None)
    add_worker = orchestrator.run_args.get('add_node', None)
    playbook_dir = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "playbooks")
    orchestrator.log.debug("Playbook Dir: %s", playbook_dir)

    if action in ["reconfigure"]:
        playbook_file = "reconfigure.yaml"
    elif action in ["update", "rollback"]:
        playbook_file = "registry-update.yaml"
        new_cfg_dir = os.path.join(os.getcwd(), "openstack-configs")
        defaults_file = os.path.join(new_cfg_dir, "defaults.yaml")
        docker_file = os.path.join(new_cfg_dir, DOCKER_FILE)
    else:
        if tags != "common_setup" and (add_worker or remove_worker):
            playbook_file = "hosts-update.yaml"
        else:
            playbook_file = "registry-install.yaml"
        if tags != "common_setup":
            docker_file = None

    if not os.path.exists(DEFAULT_CFG_DIR) or \
            not os.path.exists(DEFAULTS_FILE) or \
            not os.path.exists(SETUP_DATA_FILE) or \
            not os.path.exists(ARGUS_SITE_FILE):
        orchestrator.log.error("Required config files for playbooks "
                               "doesn't exist")
        results['status'] = 'FAIL'
        return results

    if action != "update" and docker_file and not os.path.exists(docker_file):
        orchestrator.log.error("Required docker file doesn't exist")
        return {'status': 'FAIL'}

    ansible_playbook = os.path.join(playbook_dir, playbook_file)

    if not os.path.exists(ansible_playbook):
        orchestrator.log.error(logger.stringc("File %s does not exist", "red"),
                               ansible_playbook)
        return {'status', 'FAIL'}

    ansible_cmd = build_ansible_cmd(orchestrator, setupdata_file, defaults_file,
                                    docker_file, argussite_file,
                                    ansible_playbook)

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


def monitor_and_validate_ansible_output(orchestrator, nextline, result):
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
            print logger.stringc(msg, 'red')
            return result

    set_run_result(result, 'status', 'PASS')
    return result


def get_timezone():
    """ Get Timezone string configured in the current server
    """
    out = subprocess.Popen(['timedatectl'],  # nosec
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)

    output = out.stdout.read()
    try:
        for item in output.splitlines():
            if re.search('Time zone:', item):
                return item.split()[2]
    except IndexError:
        pass
    return None


def generate_argus_site(orchestrator):
    results = dict()
    results['status'] = 'PASS'

    found_error = 0

    with open(SETUP_DATA_FILE, 'r') as f:
        try:
            doc = yaml.safe_load(f)
        except yaml.parser.ParserError as e:
            found_error = 1
        except yaml.scanner.ScannerError as e:
            found_error = 1

    if found_error:
        orchestrator.log.error("InCorrect setup_data.yaml syntax; "
                               "Error Info: " + str(e))
        results['status'] = 'FAIL'
        return results

    argus_site = doc['ARGUS_BAREMETAL']['SITE_CONFIG']
    argus_info = argus_site['common_info']
    ntp_servers = doc.get('ntp_servers')
    if not ntp_servers:
        orchestrator.log.error("Could not get ntp_servers")
        return {'status': 'FAIL'}
    argus_info['ntp_servers'] = ntp_servers
    dns_servers = doc.get('domain_name_servers')
    if not dns_servers:
        orchestrator.log.error("Could not get domain_name_server")
        return {'status': 'FAIL'}
    argus_info['domain_name_servers'] = dns_servers
    domain_name = doc.get('cvimmon_domain_suffix')
    if not domain_name:
        orchestrator.log.error("Could not get domain_name")
        return {'status': 'FAIL'}
    argus_info['domain_name'] = domain_name
    ntp_servers = doc.get('ntp_servers')
    if not ntp_servers:
        orchestrator.log.error("Could not get ntp_servers")
        return {'status': 'FAIL'}
    timezone = get_timezone()
    if not timezone:
        orchestrator.log.error("Could not get ntp_servers")
        return {'status': 'FAIL'}
    argus_info['time_zone'] = get_timezone()
    iso_info = doc.get('ARGUS_BAREMETAL').get('ISO')
    flavor_info = create_flavor(orchestrator, iso_info)
    if not flavor_info:
        orchestrator.log.error("Could not get flavor_info")
        results['status'] = 'FAIL'
        return results
    argus_info['flavor'] = flavor_info

    with open(ARGUS_SITE_FILE, 'w') as yaml_file:
        yaml.dump(argus_site, yaml_file, Dumper=MyDumper,
                  default_flow_style=False)
    return results


def validate_cvim_mon_ha_schema(orchestrator):
    """Validation and schema validation of cvim_mon_ha"""
    results = dict()
    results['status'] = 'PASS'

    input_args = dict()
    input_args['checkType'] = "static"
    input_args['SetupFileLocation'] = SETUP_DATA_FILE
    input_args['viaCLI'] = False
    input_args['cvimmonha_setup'] = orchestrator.run_args.get('cvimmonha_setup', None)
    input_args['backup_cvimmonha_setup'] = orchestrator.run_args.get('backup_cvimmonha_setup', None)

    action = orchestrator.run_args.get('action', None)
    if action:
        input_args['cvim_mon_action'] = action

    custom_conf_stackname = orchestrator.run_args.get('stack-name', None)
    if custom_conf_stackname:
        input_args['stack-name'] = custom_conf_stackname

    remove_worker = orchestrator.run_args.get('remove_node', None)
    add_worker = orchestrator.run_args.get('add_node', None)
    replace_master = orchestrator.run_args.get('replace_node', None)

    if remove_worker:
        input_args['cvim_mon_pod_oper'] = {'remove_worker': remove_worker}

    if add_worker:
        input_args['cvim_mon_pod_oper'] = {'add_worker': add_worker}

    if replace_master:
        input_args['cvim_mon_pod_oper'] = {'replace_master': replace_master}

    results = validations.run(input_args)

    return results


def create_flavor(orchestrator, iso_info):
    """Check if ARGUS_BAREMETAL key is present or not"""

    prefix_iso = iso_info.keys()[0]
    location = iso_info.values()[0]
    flavor = ""
    try:
        output = subprocess.check_output(('isoinfo', '-d', '-i', location))
        for line in output.splitlines():
            if "CiscoVIM" not in line:
                continue
            flavor = "%s-%s" % (prefix_iso, line.split('-')[1].strip())
    except subprocess.CalledProcessError:
        orchestrator.log.error("Could not find iso information: %s", location)

    return flavor


def validate_hardware(orchestrator):
    """Hardware validation argus for cvim_mon_ha"""
    results = dict()
    results['status'] = 'PASS'

    found_error = 0

    with open(SETUP_DATA_FILE, 'r') as f:
        try:
            doc = yaml.safe_load(f)
        except yaml.parser.ParserError as e:
            found_error = 1
        except yaml.scanner.ScannerError as e:
            found_error = 1

    if found_error:
        orchestrator.log.error("InCorrect setup_data.yaml syntax; "
                               "Error Info: " + str(e))
        results['status'] = 'FAIL'
        return results

    ipv6 = doc.get('ARGUS_BAREMETAL').get('DHCP_MODE', 'v4')

    hw_validator = hw_validations.HWValidator(
        setupfileloc=SETUP_DATA_FILE)
    if ipv6 == 'v6':
        use_case_list = ['firmware', 'argus_nw_adapter', 'argus_disks']
    else:
        use_case_list = ['firmware', 'hba', 'argus_nw_adapter',
                         'redfish_config', 'argus_disks']
    results = hw_validator.validate_hw_details(use_case_list)
    return results


def run(run_args=dict()):
    """
    Run method is invoked from the runner.
    """

    orchestrator = Orchestrator()
    orchestrator.run_args = run_args

    results = {'status': 'PASS'}
    resobj = dict()
    set_run_result(resobj, 'status', 'PASS')
    action = orchestrator.run_args.get("action", None)

    if action and (action == "rollback" or action == "commit"):
        new_cfg_dir = os.path.join(INSTALLER_ROOT, "openstack-configs")
        update_file = os.path.join(new_cfg_dir, "update.yaml")
        if not os.path.exists(update_file):
            err_msg = "Please check if the workspaces was updated. " + \
                      ("%s can run only run on updated workspaces" % action)
            orchestrator.log.error(err_msg)
            set_run_result(results, 'status', 'FAIL')
            set_run_result(results, 'err_msg', err_msg)
            return results

    # First step is to run get artifacts
    oper_id = orchestrator.run_args.get("id")
    if oper_id == 1 and (not action or action != "update"):

        # Validate cvim_mon_ha setupfile
        results = validate_cvim_mon_ha_schema(orchestrator)
        if results['status'] != 'PASS':
            orchestrator.log.debug("Schema Validation failed")
            return results

        if 'action' not in orchestrator.run_args.keys():
            results = validate_hardware(orchestrator)
            if results['Hardware Validation']['Overall_HW_Result'][
                'status'] != 'PASS':
                orchestrator.log.debug("Hardware Validation failed")
                results['status'] = 'FAIL'
            else:
                results['status'] = 'PASS'
        return results

    if oper_id == 2:
        if (action == "reconfigure"):
            results = execute_ansible_playbooks(orchestrator)
            return results

        if not action or action != "update" or action != "rollback":
            results = generate_argus_site(orchestrator)
            if results['status'] != 'PASS':
                orchestrator.log.debug("Create ISO Flavor Failed")
                return results
        results = execute_getartifacts(orchestrator, action)
        if results['status'] != 'PASS':
            orchestrator.log.debug("Get artifacts failed")
            return results

    if oper_id == 4:
        if not action or action != "update" or action != "rollback":
            results = generate_argus_site(orchestrator)
            if results['status'] != 'PASS':
                orchestrator.log.debug("Create Argus Site Failed")
                return results

    # Run the ansible playbooks
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
