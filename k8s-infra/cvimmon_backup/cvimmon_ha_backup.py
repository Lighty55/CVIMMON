#!/usr/bin/python

import argparse
import logging
import os
import time
import sys
import datetime
import shutil
import subprocess # nosec
import prettytable
import json
import yaml
import stat
from logging.config import dictConfig
from br_validator import RestoreValidationEngine
from br_validator import RestoreChecksumEngine

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
CURRENT_WS = os.path.dirname(CURRENT_DIR)
DEFAULT_FILE = CURRENT_WS + '/../../openstack-configs/defaults.yaml'
CVIM_MON_SETUP_FILE = CURRENT_WS + '/../../openstack-configs/setup_data.yaml'
RESTORE_WS = os.getcwd() + '/'
BACKUP_PLAYBOOK = CURRENT_WS + '/cvimmon_backup/playbooks/backup-cvimmon.yaml'
RESTORE_PLAYBOOK = CURRENT_WS + '/cvimmon_backup/playbooks/restore-cvimmon.yaml'
LOGDIR = '/var/log/cvimmonha_backup/'
LOGFILE = 'cvimmonha_backup.log'
ARTIFACTS_DIR = "/var/cisco/artifacts/"
BACKUP_DIR = '/var/cisco/cvimmonha_backup/'
AUTO_BACKUP_DIR = '/var/cisco/cvimmonha_autobackup'
STATUS_FILE = '/opt/cisco/k8s_status.json'
VERSION_FILE = '/etc/mercury-version.txt'
MAX_BACKUPS = 2
MAX_LOGS = 10
UPDATE_FILE = '/root/openstack-configs/update.yaml'
CVIMMON_RESTORE_SCRIPT = "cvimmon_restore"
INTEGRITY_SCRIPT = "cvimmonha_integrity_check"
CVIMHA_CERTS = "/root/cvimha_certs/"



def set_logger(name, logdir, logfile):
    """
    Helper function to set logger for Cvim Mon HA backup.
    :return:
    logger object for cvim mon ha backup
    """

    log_config = dict(
        version=1,
        formatters={
            'f': {
                'format':
                    '%(asctime)s %(levelname)-5.5s [%(name)s]: '
                    '%(message)s'
            }
        },
        handlers={
            'logfile': {
                'class': 'logging.handlers.RotatingFileHandler',
                'maxBytes': 3000000,
                'backupCount': 10,
                'filename': logdir + logfile,
                'level': 'DEBUG',
                'formatter': 'f'
            },
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'f',
                'level': logging.DEBUG
            }
        },
        loggers={
            name: {
                'handlers': ['logfile'],
                'level': logging.DEBUG
            }
        }
    )

    if "--debug" in sys.argv:
        log_config['loggers'][name]['handlers'].append('console')
        sys.argv.remove('--debug')

    dictConfig(log_config)
    cvimmonha_log = logging.getLogger(name)
    return cvimmonha_log


def exit_and_print_failed_results(log, action, err_info):
    """Print Common Failure"""

    ptable = get_pretty_table(40)

    status = "\033[91mFAIL\033[0m"
    err_info = err_info + " Please view logs for more info."

    ptable.add_row(["CVIM_Mon" + action + " Status", status, err_info])
    if log:
        log.info("\n\n\nCVIM Mon Central %s Info!" % (action))
        log.info("\n{0}".format(ptable))
        log.info("\nFAILED: CVIM Mon Central %s!\n" % (action))

    else:
        print "\n\n\nCVIM Mon Central %s Info!" % (action)
        print ptable
        print "\nFAILED: CVIM Mon Central %s!" % (action)

    return False

def get_files_with_prefix(path, prefix, log=None, delete=False):
    """ Function that returns the files in the 'path' directory which start
        with 'prefix' and deletes them if 'delete' is True
    """
    remote_files_list = []
    err1 = ("Needs to provide a prefix") if not prefix else ""
    err2 = ("Needs to provide a path") if not path else ""
    if not prefix or not path:
        if log:
            log.error("%s. %s" % (err1, err2))
        else:
            print("%s. %s" % (err1, err2))
        return remote_files_list
    try:
        for i in os.listdir(path):
            f = os.path.join(path, i)
            if os.path.isfile(f) and prefix in i:
                remote_files_list.append(f)
                if delete:
                    os.remove(f)
    except Exception as exc:
        err = ("Issue trying to delete files with prefix %s" % prefix)
        if log:
            log.error("%s: %s" % (str(exc), err))
        else:
            print("%s: %s" % (str(exc), err))
    return remote_files_list


def get_pretty_table(det_max_width):
    """Create and return a pretty table"""

    ptable = prettytable.PrettyTable(["Description", "Status", "Details"])
    ptable.align["Description"] = "l"
    ptable.align["Status"] = "l"
    ptable.align["Details"] = "l"
    ptable.max_width["Details"] = det_max_width

    return ptable

def delete_backupdir(backup_path):
    """
    Delete backupdir if found exception, as it becomes invalid
    for restore.
    """
    log.info("Exception occurred, deleting backupdir {0} as found invalid "
             "for restore.".format(backup_path))

    shutil.rmtree(backup_path)

def cleanup_dir(dir_path, child_prefix, max_child):
    ''' Maintain a given count of files/directories in a directory '''

    list_of_children = os.listdir(dir_path)
    active_children = []

    for child in list_of_children:
        if not child.startswith(child_prefix):
            continue
        child_path = os.path.join(dir_path, child)
        stat = os.lstat(child_path)
        active_children.append((child_path, stat.st_mtime))
    active_children.sort(key=lambda x: x[1], reverse=True)

    index = 1
    for child in active_children:
        if index > max_child:
            if os.path.isdir(child[0]):
                shutil.rmtree(child[0])
            else:
                os.remove(child[0])
        index += 1


def get_backupdir(backup_dir, action):
    """Create insight backup directory name"""

    file_name = "cvimmonha_backup_"
    if action == "autobackup":
        file_name = "cvimmonha_autobackup_"
    gts = time.time()
    file_defaults = open(DEFAULT_FILE, 'r')
    file_defaults = yaml.safe_load(file_defaults)
    release_tag = str(file_defaults['RELEASE_TAG'])

    backup_dir = os.path.join(backup_dir, file_name + release_tag +
                              "_" + datetime.datetime.
                              fromtimestamp(gts).strftime('%Y-%m-%d_%H:%M:%S'))
    return backup_dir


def check_cvimmonha_status():
    """ Check if last op on CVIM MON HA is in success or not """

    # get status of cvim mon ha data
    with open(STATUS_FILE, "r") as status_data:
        data = json.load(status_data)


    return data


def get_playbook_cmd(playbook):

    """ Method to construct the ansible playbook command """

    if not os.path.isfile(playbook):
        print "[ERROR] '{0}' playbook is not found. Exiting..".format(playbook)
        sys.exit(1)

    playbook_cmd = ["ansible-playbook", '-v', playbook]

    return playbook_cmd


def execute_playbook_command(log, playbook_cmd):
    """ Method to execute the ansible playbook """

    playbook_path = os.path.abspath(__file__)
    playbook_path = os.path.dirname(playbook_path)
    log.info("Executing playbook command ----> {0}".format(' '.join(playbook_cmd)))
    try:
        sproc = subprocess.Popen(playbook_cmd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 cwd=playbook_path)  # nosec
        if log:
            with sproc.stdout:
                for line in iter(sproc.stdout.readline, b''):
                    log.info('{}'.format(line).rstrip('\n'))
            with sproc.stderr:
                for line in iter(sproc.stderr.readline, b''):
                    # Workaround for ansible sometimes throwing WARNING
                    # runner logs this as stderr
                    if "WARNING" not in line:
                        log.info('{}'.format(line).rstrip('\n'))
            sproc.wait()
        else:
            soutput, serror = sproc.communicate()
            log.info("Executing ansible playbook command.... {0}".format(soutput))
            log.info("Executing ansible playbook command.... {0}".format(serror))
    except OSError:
        if log:
            log.exception("Fatal error, operation failed due to exception")
        return False
    if sproc.returncode:
        return False
    return True

def execute_cmd(cmd, use_shell=False):
    """Execute command and perform logging"""

    try:
        cmd_proc = subprocess.Popen(cmd, shell=use_shell,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE) # nosec

        with cmd_proc.stdout:
            for line in iter(cmd_proc.stdout.readline, b''):
                log.info('{}'.format(line.rstrip(' \n')))
        with cmd_proc.stderr:
            for line in iter(cmd_proc.stderr.readline, b''):
                log.info('{}'.format(line.rstrip(' \n')))

        cmd_proc.wait()

        if cmd_proc.returncode != 0:
            return False

    except OSError as e:
        log.info("Executing {0} command failed: {1}".format(cmd, str(e)))
        return False

    log.info("")
    return True

def get_setupfile_values():
    """ Return Setupfile data """

    with open(CVIM_MON_SETUP_FILE, "rb") as setupfile:
        data = yaml.safe_load(setupfile)

    return data

def get_iso_image_path(action):
    """ Get ISO Image Path """

    data = get_setupfile_values()
    iso_image_key = data["ARGUS_BAREMETAL"]["ISO"].keys()[0]
    image_path = data["ARGUS_BAREMETAL"]["ISO"][iso_image_key]
    if not os.path.exists(image_path) and "backup" in action:
        return False

    return image_path

def create_restore_script(restore_script):
    """ Create restore script in the backup dir """

    restore_cmd = '.{}/cvimmon_ha_backup.py --restore' \
        .format(CURRENT_DIR)
    bootstrap_dir = CURRENT_WS + '/../../'
    restore_script_path = os.path.join(CURRENT_DIR, CVIMMON_RESTORE_SCRIPT)
    with open(restore_script_path, 'r') as rscript_template:
        rfile_data = rscript_template.read()
        rfile_data = rfile_data.replace('$PATH_TO_WS', '{}'.format(bootstrap_dir))
        rfile_data = rfile_data.replace('$COMMAND_ENABLE_VERBOSE',
                                        '{} --debug'.format(restore_cmd))
        new_data = rfile_data.replace('$COMMAND_DISABLE_VERBOSE',
                                      restore_cmd)

    with open(restore_script, 'w') as rfile:
        rfile.write(new_data)
    os.chmod(restore_script, stat.S_IREAD | stat.S_IEXEC)


def create_integrity_script(integrity_script):
    """ Create Integrity script """

    path = os.path.join(CURRENT_DIR, INTEGRITY_SCRIPT)
    path = path.lstrip('/')
    path = path + " $@"
    with open(integrity_script, 'w') as ifile:
        ifile.write(path)
    os.chmod(integrity_script, stat.S_IREAD | stat.S_IEXEC)

def execute_backup_restore(log, action, backup_path):
    """
    :param log: logging
    :param backup_path: backup path
    :return: success/failure
    """

    argus_image_path = get_iso_image_path(action)
    argus_path = os.path.split(argus_image_path)[0]
    argus_image_name = os.path.split(argus_image_path)[1]
    playbook_path = BACKUP_PLAYBOOK
    if action == "restore":
        playbook_path = RESTORE_PLAYBOOK
    playbook_cmd = get_playbook_cmd(playbook_path)
    playbook_cmd.extend(["-e", "backupdir=%s" % backup_path])
    playbook_cmd.extend(["-e", "argus_image_path=%s" % argus_path])
    playbook_cmd.extend(["-e", "argus_image_name=%s" % argus_image_name])



    return execute_playbook_command(log, playbook_cmd)

def validate_backup(log):
    """ Validate all checks prior running backup """

    cvim_mon_ha_status = check_cvimmonha_status()
    dir_name = CURRENT_WS.rstrip("/k8s-infra")
    dir_name = dir_name.strip("bootstrap")
    dir_name = dir_name.rstrip("/")
    if cvim_mon_ha_status["workspace_info"] != dir_name:
        msg = "Backup needs to be executed from the same workspace " \
              "through which installation was initiated."
        log.error(msg)
        exit_and_print_failed_results(log, "backup", msg)
        return False

    if os.path.exists(UPDATE_FILE):
        msg = "Backup can not be executed in the middle of update. " \
              "Aborting backup."
        log.error(msg)
        exit_and_print_failed_results(log, "backup", msg)
        return False

    if not os.path.exists(CVIMHA_CERTS):
        msg = "Missing cert dir at: {}".format(CVIMHA_CERTS)
        log.error(msg)
        exit_and_print_failed_results(log, "backup", msg)
        return False

    if os.path.exists(CVIMHA_CERTS):
        unwanted_file_list = list()
        cert_list = os.listdir(CVIMHA_CERTS)
        for certs in cert_list:
            if not certs.endswith(".crt") and os.path.isfile(certs):
                unwanted_file_list.append(certs)
        if unwanted_file_list:
            msg = "Unwanted files detected in the certificate directory."
            log.error(msg + "Unwanted file list:{}".format(unwanted_file_list))
            exit_and_print_failed_results(log, "backup", msg)
            return False

    return True



def validate_restore(log):
    """ Validate before executing restore """

    log.info("Executing system validations...")

    checksumValidator = RestoreChecksumEngine()
    if checksumValidator.run():
        print("Restore Checksum Validation Passed")
    else:
        msg = "Restore Checksum Validation Failed, please run " \
              "check_integrity to see changes"
        exit_and_print_failed_results(log, "restore", msg)
        log.error(msg)
        return False

    restoreValidator = RestoreValidationEngine()
    if restoreValidator.run():
        print("Restore Validation Passed")
    else:
        for vResult in restoreValidator.results:
            log.error(vResult.reason)
        msg = "Restore Validation Failed with " \
              "reason: {} ".format(vResult.reason)
        exit_and_print_failed_results(log, "restore", msg)
        return False

    if os.path.exists('/root/openstack-configs'):
        msg = "Fatal Error: Previous installation detected please re-install " \
              "the management node with correct iso"
        log.error(msg)
        exit_and_print_failed_results(log, "restore", msg)
        return False

    log.info("[DONE] Validation of Restore completed initiating "
             "Restore process")
    return True

def restore_cvimmonha_ws(action, log):
    """ Sync backup dir ws"""

    wspath = None
    bdir = CURRENT_WS

    wsfile = bdir + '/../../openstack-configs/.workspace'
    if not os.path.exists(wsfile):
        log.error("Backup directory is incomplete, ws metadata file not "
                  "present ... ")
        return False

    with open(wsfile, 'r') as wsfd:
        wspath = wsfd.readline().rstrip()

    # Get the backupdir by removing workspace path from absolute file path
    bdir = bdir[:bdir.find(wspath)]
    wsbackuppath = os.path.join(bdir, wspath.lstrip('/'))
    if not os.path.exists(wsfile):
        log.error("Backup directory is incomplete workspace dir not "
                  "present ... ")
        return False
    log.debug(
        "Sync workspace directory .. %s %s" % (wsbackuppath, '/root'))
    cmd_rsync_ws = ["rsync", "-avrz", "-X", wsbackuppath, '/root']
    #Validate restore before WS rsync.
    if not validate_restore(log):
        log.error("Validation for Restore failed.")
        return False
    log.info("Executing rsync command to backup Cvim Mon workspace "
             "-----> {0}".format(' '.join(cmd_rsync_ws)))
    if not execute_cmd(cmd_rsync_ws):
        log.error("{0} of Cvim Mon workspace failed." \
            .format(action))
        return False

    log.info("[Done] with Workspace backup at :{0}".format(bdir))

    return True





def run(log, action, backup_path=None):
    """ Execute backup """

    if "backup" in action:
        log.info("Executing {0} at :{1}".format(action, backup_path))
        if not validate_backup(log):
            log.error("ERROR: Backup validation failed.")
            return False

        if not os.path.exists(backup_path):
            os.makedirs(backup_path, 0600)
        create_restore_script(os.path.join(backup_path, './cvimmon_restore'))
        create_integrity_script(os.path.join(backup_path, './check_integrity'))
    else:
        log.info("Executing Restore of Cvim Mon Node")
        log.info("Initiating Restore Validations and Workspace")
        backup_path = RESTORE_WS
        if "/var/cisco/" not in backup_path:
            msg = "Restore must be executed from /var/cisco/ directory. " \
                  "Aborting Restore operation."
            log.error(msg)
            exit_and_print_failed_results(log, action, msg)
            return False

        if not restore_cvimmonha_ws(action, log):
            msg = "Restore Operation failed"
            log.error(msg)
            exit_and_print_failed_results(log, "restore", msg)
            return False

    print "Executing {0} at :{1}".format(action, backup_path)
    if not execute_backup_restore(log, action, backup_path):
        log.error("{} Execution Failed. Aborting backup..".format(action))
        if "backup" in action:
            delete_backupdir(backup_path)
            log.info("Deleting Backup dir: {}".format(backup_path))
        msg = "{0} Execution Failed. Aborting {0}".format(action)
        exit_and_print_failed_results(log, action, msg)
        return False

    msg = "[DONE] {} of CVIM MON HA Node successfully.".format(action)
    log.info(msg)
    child_name = "cvimmonha_backup"
    if action == "autobackup":
        child_name = "cvimmonha_autobackup"
    cleanup_dir(os.path.dirname(backup_path), child_name, MAX_BACKUPS)
    print msg
    return True



def main(log, action, backup_path=None):
    """ Initialize and run the backup """

    backupdir = BACKUP_DIR
    if action == "autobackup":
        backupdir = AUTO_BACKUP_DIR
    if not backup_path and "backup" in action:
        backup_path = get_backupdir(backupdir, action)

    log.info("Inititating Cvim Mon Central :{}...".format(action))

    if not run(log, action, backup_path):
        return False

    return True

if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser(
        description='Command-line interface for cvim mon central backup',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    arg_parser.add_argument('--dir-path', action="store", type=str,
                            dest="backup_path",
                            help='custom dir for backup')
    arg_parser.add_argument('--debug', action='store_true',
                            dest="debug",
                            help='Print debugging output')
    arg_parser.add_argument('--backup', action='store_true',
                            dest="backup",
                            help='Execute backup for cvim mon node')
    arg_parser.add_argument('--restore', action='store_true',
                            dest="restore",
                            help=argparse.SUPPRESS)

    parsed_args = arg_parser.parse_args()

    if not parsed_args.backup and not parsed_args.restore:
        print "--backup or --restore needs to passed."
        sys.exit(1)

    if parsed_args.backup and parsed_args.restore:
        print "--backup and --restore are mutually exclusive"
        sys.exit(1)

    gbackup = False
    grestore = False
    action = "backup"
    msg_action = "Backup"

    if parsed_args.restore:
        action = "restore"
        msg_action = "Restore"

    logdir = LOGDIR
    logfile = LOGFILE
    if action == "restore":
        logdir = "/var/log/cvimmonha_restore/"
        logfile = "cvimmonha_restore.log"

    gts = time.time()
    logfile = logfile + "_" + \
        datetime.datetime.fromtimestamp(gts).strftime('%Y-%m-%d_%H:%M:%S')

    if not os.path.exists(logdir):
        os.makedirs(logdir)
    gdebug_mode = parsed_args.debug

    gbackup_path = None
    if parsed_args.backup_path:
        gbackup_path = get_backupdir(parsed_args.backup_path, action)

    log_name = 'cvimmonha_backup'
    if action == "restore":
        log_name = 'cvimmonha_restore'
    log = set_logger(log_name, logdir, logfile)
    print "Executing {}:\n".format(msg_action)
    if not main(log, action, gbackup_path):
        print "ERROR:{} Failed. View logs for more info.".format(msg_action)
        print "Logs for {0} are located at {1}".format(msg_action, logdir + logfile)
        sys.exit(1)

    print "Logs for {0} are located at {1}".format(msg_action, logdir + logfile)
