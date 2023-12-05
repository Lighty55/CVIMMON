#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Validations:
==============

Validations Module:
---------------------------------------
Validates the basic setup data.yaml
On Failure backs it up and fixes the setup_data.yaml as well

"""
import argparse
import os
import re
import datetime
import random
import string
import shutil
import subprocess   # nosec
import time
import yaml
import utils.logger as logger
import clouddeploy.validations as validations
import utils.config_parser as config_parser

DEFAULT_CFG_DIR = "openstack-configs"
DEFAULT_SETUP_FILE = "setup_data.yaml"
BACKUP_SETUP_FILE = ".backup_setup_data.yaml"
DEFAULT_SECRET_FILE = "secrets.yaml"
DEFAULT_OS_CFG_FILE = "openstack_config.yaml"
DEFAULT_COBBLER_FILE = ".cobbler_data.yaml"


class TranslateConfigFile(object):
    '''
    Validator class.
    '''
    OPER_STAGE = "INIT"
    STAGE_COUNT = 0

    def __init__(self, setupfileloc):
        '''
        Initialize validator
        '''
        self.validation_results = []
        self.loginst = logger.Logger(name=__name__)
        self.log = self.loginst.get_logger()

        homedir = self.get_homedir()
        self.cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)
        cfgd = os.path.join("/bootstrap/", DEFAULT_CFG_DIR)
        if not os.path.exists(self.cfg_dir):
            os.symlink(os.getcwd() + cfgd, self.cfg_dir)

        if setupfileloc is not None:
            self.setup_file = setupfileloc
            curr_backup_file_dir = os.path.dirname(self.setup_file)
            self.backup_setup_file = os.path.join(curr_backup_file_dir,
                                                  BACKUP_SETUP_FILE)
        else:
            self.setup_file = os.path.join(self.cfg_dir, DEFAULT_SETUP_FILE)
            self.backup_setup_file = os.path.join(self.cfg_dir, BACKUP_SETUP_FILE)

        self.ymlhelper = config_parser.YamlHelper(user_input_file=self.setup_file)
        self.secret_file = os.path.join(self.cfg_dir, DEFAULT_SECRET_FILE)
        self.os_cfg_file = os.path.join(self.cfg_dir, DEFAULT_OS_CFG_FILE)
        self.cobbler_cfg_file = os.path.join(self.cfg_dir, DEFAULT_COBBLER_FILE)

        self.modargs = {}
        self.modargs['checkType'] = "static"
        self.modargs['supressOutput'] = True
        self.modargs['InstallType'] = "upgrade"
        self.modargs['testType'] = 'nonblocking'
        self.modargs['SetupFileLocation'] = self.setup_file

        self.validation_result = {}
        self.remove_key_list = []

    def get_homedir(self):
        '''
        Get the current username
        '''
        homedir = os.path.expanduser("~")
        return homedir

    def get_target_keys_to_remove(self, info):
        '''Gets the target keys to remove from the info'''

        invalid_input_str = "Input not allowed for this entry for dictionary value"
        if re.search(r'Extra Keys found in setup_data.yaml', info):
            curr_key_str = info.split(":")[1].strip()
            temp_list = curr_key_str.split(",")
            for tmp in temp_list:
                self.remove_key_list.append(tmp)

        elif re.search(invalid_input_str, info):
            curr_error_list = info.split("::")
            for item in curr_error_list:
                if re.search(invalid_input_str, item):
                    all_keys = re.findall(r"\[(['A-Za-z0-9_-]+')\]", item)
                    for cur_item in all_keys:
                        tmp = cur_item.strip("\"")
                        tmp2 = tmp.strip("\'")
                        self.remove_key_list.append(tmp2)

    def cleanup_setupdata(self):
        '''execute Management node tests from function'''

        search_str = "Schema Validation of Input File|Check for Valid Keys"
        self.validation_result = validations.run(run_args=self.modargs)

        for key, value in self.validation_result.iteritems():
            if re.search(r'Software Validation', key):
                for key_sw, value_sw in value.iteritems():

                    if re.search(search_str, key_sw) and \
                            re.search(r'Fail', value_sw['status']):
                        self.get_target_keys_to_remove(value_sw['reason'])

        if len(self.remove_key_list):
            print "Need to translate setup_data for: %s" \
                  % (','.join(self.remove_key_list))
            curr_backup_file_dir = os.path.dirname(self.setup_file)
            curr_time = datetime.datetime.now()
            curr_backup_file = "setup_data_backup_" + \
                               str(curr_time) + ".yaml"
            curr_backup_file_path = os.path.join(curr_backup_file_dir,
                                                 curr_backup_file)

            target_file = "setup_data_tgt_" + str(curr_time) + ".yaml"
            tgt_file_path = os.path.join(curr_backup_file_dir, target_file)

            try:
                shutil.copy2(self.setup_file, curr_backup_file_path)
            except OSError:
                return False

            remove_key_pattern = ':|'.join(self.remove_key_list)
            with open(self.setup_file, 'r') as input_file, \
                    open(tgt_file_path, 'w') as output_file:
                for line in input_file:
                    if re.search(remove_key_pattern, line.strip()):
                        if re.search(r'CIMC-COMMON', line.strip()) and \
                                re.search(r'cimc_iplist', line.strip()):

                            target_list = []
                            tmp_dict = yaml.safe_load(line.strip())
                            for k, v in tmp_dict['CIMC-COMMON'].iteritems():
                                if re.search(r'cimc_iplist', str(k)):
                                    continue
                                else:
                                    tmp = str(k) + ": " + str(v)
                                    target_list.append(tmp)
                            target_str = ', '.join(target_list)
                            target_line = "CIMC-COMMON: {" + target_str + "}\n"
                            output_file.write(target_line)
                        else:
                            lhs_entry = line.split(":")[0]
                            if not re.match(r'-', lhs_entry.strip()):
                                continue
                            else:
                                d = re.sub('[a-z_]', '', lhs_entry)
                                output_file.write(d)
                                output_file.write("\n")
                    else:
                        output_file.write(line)

            try:
                shutil.move(tgt_file_path, self.setup_file)
                shutil.copy2(self.setup_file, self.backup_setup_file)
            except OSError:
                return False
        else:
            msg = "No Translation needed for setup_data.yaml"
            self.log.info(msg)

        print "\n\n Output of final setup_data.yaml validation"
        self.modargs['supressOutput'] = False

        validation_result2 = validations.run(run_args=self.modargs)
        translation_status = True
        for key, value in validation_result2.iteritems():
            if re.search(r'Software Validation', key):
                for key_sw, value_sw in value.iteritems():

                    if re.search(search_str, key_sw) and \
                            re.search(r'Fail', value_sw['status']):
                        translation_status = False

        return translation_status

    def generate_secrets(self, size):
        '''
        Generate secrets
        '''
        secret = ""  # nosec
        chars = string.digits + string.ascii_letters
        for _ in range(100):
            secret = ''.join(random.choice(chars) for _ in range(size))   # nosec
            if re.match('^(?=.*\d)(?=.*[a-zA-Z]).{8,}$', secret):
                break

        return secret

    def generate_aes_key(self):
        """
        Generate 256 bit hex string
        """
        new_key = random.getrandbits(256)
        return '{:064x}'.format(new_key)

    def cleanup_secrets_file(self):
        '''Check if secrets file has HORIZON_SECRET_KEY
        if not update it with the info'''

        if not os.path.isfile(self.secret_file):
            self.log.info("ERROR: Secrets file %s not found", self.secret_file)
            return False

        curr_backup_file_dir = os.path.dirname(self.secret_file)
        now = datetime.datetime.now()
        curr_time = now.strftime("%Y-%m-%d-%H-%M-%S")
        curr_backup_file = "pre_upg_secrets_int_" + \
            str(curr_time) + ".yaml"
        curr_backup_file_path = os.path.join(curr_backup_file_dir,
                                             curr_backup_file)

        target_file = "secrets_tgt_int_" + str(curr_time) + ".yaml"
        tgt_file_path = os.path.join(curr_backup_file_dir, target_file)

        found_horizon_sec_key = 0
        found_cvim_mon_key = 0

        update_secret_info = 0
        found_cvim_mon_key = 0
        found_volume_encrypt_key = 0
        with open(self.secret_file, 'r') as input_file, \
                open(tgt_file_path, 'w') as output_file:
            for line in input_file:
                if re.match(r'HORIZON_SECRET_KEY', line.strip()):
                    found_horizon_sec_key = 1
                elif re.match(r'CVIM_MON_READ_ONLY_PASSWORD', line.strip()):
                    found_cvim_mon_key = 1
                elif re.match(r'CVIM_MON_SERVER_PASSWORD', line.strip()):
                    found_cvim_mon_key = 1
                elif re.match(r'VOLUME_ENCRYPTION_KEY', line.strip()):
                    found_volume_encrypt_key = 1
                    if self.ymlhelper.get_pod_type() == 'ceph':
                        update_secret_info = 1
                        continue
                elif re.match(r'NFVIMON_RABBITMQ_PASSWORD', line.strip()):
                    continue
                else:
                    # Translate ELK_PASSWORD into KIBANA_PASSWORD
                    if re.match(r'ELK_PASSWORD:', line.strip()):
                        kibana_pwd = line[14:-1]
                        output_file.write("KIBANA_PASSWORD: %s\n" % kibana_pwd)
                        update_secret_info = 1
                        continue
                output_file.write(line)

            if self.ymlhelper.get_pod_type() == 'ceph':
                found_horizon_sec_key = 1
            if self.ymlhelper.get_pod_type() == 'ceph':
                found_volume_encrypt_key = 1
            cvim_mon_config = self.ymlhelper.get_cvim_mon_info()
            if cvim_mon_config is not None and cvim_mon_config['enabled']:
                if not found_cvim_mon_key:
                    cvim_secret = self.generate_secrets(16)
                    update_secret_info = 1
                    cvim_mon_key_str = 'CVIM_MON_READ_ONLY_PASSWORD: ' + str(cvim_secret)
                    output_file.write(cvim_mon_key_str)
                    output_file.write('\n')
            if not found_horizon_sec_key:
                curr_secret = self.generate_secrets(64)
                update_secret_info = 1
                horizon_key_str = 'HORIZON_SECRET_KEY: ' + str(curr_secret)
                output_file.write(horizon_key_str)
            if not found_cvim_mon_key:
                curr_secret = self.generate_secrets(16)
                update_secret_info = 1
                cvimmon_key_str = 'CVIM_MON_SERVER_PASSWORD: ' + str(curr_secret)
                output_file.write(cvimmon_key_str)
                output_file.write('\n')
            if not found_volume_encrypt_key:
                curr_aes = self.generate_aes_key()
                update_secret_info = 1
                volume_key_str = 'VOLUME_ENCRYPTION_KEY: ' + str(curr_aes)
                output_file.write(volume_key_str)
                output_file.write('\n')

            if update_secret_info:
                try:
                    shutil.copy2(self.secret_file, curr_backup_file_path)
                    shutil.move(tgt_file_path, self.secret_file)
                except OSError as e:
                    self.log.info("ERROR: Copy of files failed:%s, %s, %s",
                                  e.errno, e.filename, e.strerror)
                    return False

        if os.path.isfile(tgt_file_path):
            show_command = ['/usr/bin/rm', tgt_file_path]
            subprocess.check_output(show_command)  # nosec

        return True

    def cleanup_openstack_configs_file(self):
        '''Check if os configs file has elk_rotation_del_older
        if not update it with the info'''

        if self.ymlhelper.get_pod_type() == 'ceph':
            return True

        if not os.path.isfile(self.os_cfg_file):
            self.log.info("ERROR: openstack_configs file %s not found",
                          self.os_cfg_file)
            return False

        curr_backup_file_dir = os.path.dirname(self.os_cfg_file)
        now = datetime.datetime.now()
        curr_time = now.strftime("%Y-%m-%d-%H-%M-%S")
        curr_backup_file = "pre_upg_os_cfg_" + \
                           str(curr_time) + ".yaml"
        curr_backup_file_path = os.path.join(curr_backup_file_dir,
                                             curr_backup_file)

        target_file = "os_cfg_tgt_" + str(curr_time) + ".yaml"
        tgt_file_path = os.path.join(curr_backup_file_dir, target_file)

        found_elk_rotation_del_older = 0
        found_es_snapshot_info = 0
        need_update = 0
        found_nova_cpu_oversub_ratio = 0
        found_gnocchi_log = 0
        found_ironic_log = 0

        es_info_list = []
        es_info_list.append('ES_SNAPSHOT_AUTODELETE:')
        es_info_list.append('  enabled: True')
        es_info_list.append('  period: \"hourly\"')
        es_info_list.append('  threshold_warning: 60')
        es_info_list.append('  threshold_low: 50')
        es_info_list.append('  threshold_high: 80')

        with open(self.os_cfg_file, 'r') as input_file, \
                open(tgt_file_path, 'w') as output_file:
            for line in input_file:
                if re.match(r'elk_rotation_del_older', line.strip()):
                    found_elk_rotation_del_older = 1
                elif re.match(r'ES_SNAPSHOT_AUTODELETE', line.strip()):
                    found_es_snapshot_info = 1
                elif re.match(r'NOVA_CPU_ALLOCATION_RATIO', line.strip()):
                    found_nova_cpu_oversub_ratio = 1
                elif re.match(r'GNOCCHI_VERBOSE_LOGGING', line.strip()):
                    found_gnocchi_log = 1
                elif re.match(r'IRONIC_VERBOSE_LOGGING', line.strip()):
                    found_ironic_log = 1

                if re.search(r'COLLECTD_RECONFIGURE|interval:', line.strip()):
                    need_update = 1
                    continue
                else:
                    output_file.write(line)

            if not found_nova_cpu_oversub_ratio:
                tgt_str = "NOVA_CPU_ALLOCATION_RATIO: 16.0"
                output_file.write(tgt_str)
                output_file.write('\n')
                need_update = 1

            if not found_gnocchi_log:
                tgt_str = "GNOCCHI_VERBOSE_LOGGING: True"
                output_file.write(tgt_str)
                output_file.write('\n')
                tgt_str = "GNOCCHI_DEBUG_LOGGING: False"
                output_file.write(tgt_str)
                output_file.write('\n')
                need_update = 1

            if not found_ironic_log:
                tgt_str = "IRONIC_VERBOSE_LOGGING: True"
                output_file.write(tgt_str)
                output_file.write('\n')
                tgt_str = "IRONIC_DEBUG_LOGGING: False"
                output_file.write(tgt_str)
                output_file.write('\n')
                need_update = 1

            if not found_elk_rotation_del_older:
                tgt_str = "elk_rotation_del_older: 10"
                output_file.write(tgt_str)
                output_file.write('\n')
                need_update = 1

            if not found_es_snapshot_info:
                need_update = 1
                for item in es_info_list:
                    output_file.write(item)
                    output_file.write('\n')

            if need_update:
                try:
                    shutil.copy2(self.os_cfg_file, curr_backup_file_path)
                    shutil.move(tgt_file_path, self.os_cfg_file)
                except OSError as e:
                    self.log.info("ERROR: Copy of files failed:%s, %s, %s",
                                  e.errno, e.filename, e.strerror)
                    return False

        if os.path.isfile(tgt_file_path):
            show_command = ['/usr/bin/rm', tgt_file_path]
            subprocess.check_output(show_command)  # nosec

        return True

    def is_info_defined_in_file(self, file_name, pattern):
        '''Check if pattern is defined in setup_data'''

        with open(file_name, 'r') as searchfile:
            for line in searchfile:
                if pattern in line:
                    return 1
        return 0


    def create_parsed_yaml(self, yaml_file):
        """
        Create a parsed yaml dictionalry from the yaml file.
        """
        try:
            fp = open(yaml_file)
        except IOError as ioerr:
            self.log.error("Failed to open file %s [%s]", yaml_file, ioerr)
            raise IOError(ioerr)

        try:
            parsed = yaml.safe_load(fp)
        except yaml.error.YAMLError as perr:
            self.log.error("Failed to Parse %s [%s]", yaml_file, perr)
            return None

        fp.close()
        return parsed

    def dump_dict_to_yaml(self, data, yaml_file):
        """
        Method to dump the dict to a output yaml file
        """
        #http://pyyaml.org/ticket/91
        with open(yaml_file, "a+") as f:
            Dumper = yaml.SafeDumper
            Dumper.ignore_aliases = lambda self, data: True
            f.write(yaml.dump(data, default_flow_style=False, Dumper=Dumper))

        if os.path.isfile(yaml_file):
            os.chmod(yaml_file, 0600)


    def update_cobbler_data_file(self):
        '''Update the cobbler file with power status info'''

        if not os.path.isfile(self.cobbler_cfg_file):
            self.log.info("ERROR: openstack_configs file %s not found",
                          self.cobbler_cfg_file)
            return False

        curr_backup_file_dir = os.path.dirname(self.cobbler_cfg_file)
        now = datetime.datetime.now()
        curr_time = now.strftime("%Y-%m-%d-%H-%M-%S")
        curr_backup_file = "pre_upg_cobbler_cfg_" + \
                           str(curr_time) + ".yaml"
        curr_backup_file_path = os.path.join(curr_backup_file_dir,
                                             curr_backup_file)

        info_pattern = "power_status:"
        if self.is_info_defined_in_file(self.cobbler_cfg_file, \
                                        pattern=info_pattern):
            success_msg = "%s Exists in %s; no need to update" \
                          % (info_pattern, self.cobbler_cfg_file)
            self.log.info(success_msg)
            return True

        try:
            shutil.copy2(self.cobbler_cfg_file, curr_backup_file_path)
        except OSError as e:
            self.log.info("ERROR: Copy of files failed:%s, %s, %s",
                          e.errno, e.filename, e.strerror)

        msg = "Will update %s with %s" % (self.cobbler_cfg_file, info_pattern)
        self.log.info(msg)

        cobbler_file_dict = self.create_parsed_yaml(self.cobbler_cfg_file)
        powered_cobbler_data = dict(cobbler_file_dict)

        for server in powered_cobbler_data:
            powered_cobbler_data[server]['power_status'] = "on"

        self.log.info("Removing old cobbler data.")
        os.remove(self.cobbler_cfg_file)
        self.dump_dict_to_yaml(powered_cobbler_data, self.cobbler_cfg_file)


        if not self.is_info_defined_in_file(self.cobbler_cfg_file,
                                            pattern=info_pattern):
            err_msg = "ERROR: Update of Power status failed in %s" \
                      % (self.cobbler_cfg_file)
            self.log.info(err_msg)
            return False

        else:
            success_msg = "Backup and Update of %s Successful" \
                % (self.cobbler_cfg_file)
            self.log.info(success_msg)
            return True


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
                err_str = "Input file: " + curr_setupfileloc + " doesn't exist"

            elif not os.access(curr_setupfileloc, os.R_OK):
                err_str = "Input file: " + curr_setupfileloc + " is not readable"

            if len(err_str):
                print err_str
                input_file_chk['status'] = "FAIL"
                return input_file_chk

    except KeyError:
        curr_setupfileloc = None


    translator = TranslateConfigFile(curr_setupfileloc)

    '''
    tot_trans_attempt = 5
    trans_count = 1
    # Need to translate few times so that all enteries are fixed
    while trans_count <= tot_trans_attempt:
        trans_status = translator.cleanup_setupdata()
        if trans_status:
            break
        else:
            trans_count += 1
            print "Attempting %s of %s translations" \
                % (trans_count, tot_trans_attempt)
            time.sleep(2)
    '''

    translator.cleanup_secrets_file()
    translator.cleanup_openstack_configs_file()

    return


def main(run_args={}):
    '''
    Config Manager main.
    '''
    run(run_args=run_args)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Verify Input Validation")

    parser.add_argument("--setup_file_location", dest="SetupFileLocation",
                        default="NotDefined", help="setup file location")

    input_args = {}
    args = parser.parse_args()
    input_args['checkType'] = "static"
    input_args['SetupFileLocation'] = args.SetupFileLocation
    main(input_args)
