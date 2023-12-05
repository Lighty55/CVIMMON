import filecmp
import fnmatch
import hashlib
import os
import subprocess
import tempfile
import time
import yaml

PUBLIC_REGISTRY = "cvim-registry.com"

class ValidationResult:
    valid = True
    reason = "Validation Passed."


class ValidationEngine:
    def __init__(self):
        self.validators = []
        self.results = []

    def run(self):
        for validator in self.validators:
            valid = validator.validate()
            if not valid:
                self.results.append(validator.vResult)
        return not self.results

class RestoreValidationEngine(ValidationEngine):
    def __init__(self):
        ValidationEngine.__init__(self)
        self.validators.append(FreshInstallValidator())
        self.validators.append(VersionValidator())
        self.validators.append(NetworkChangeValidator())
        self.validators.append(TimezoneValidator())
        self.validators.append(HostnameValidator())

class RestoreChecksumEngine(ValidationEngine):
    def __init__(self):
        ValidationEngine.__init__(self)
        self.validators.append(CompleteBackupValidator())

class Validator:
    def __init__(self):
        self.vResult = ValidationResult()
        self.bdir = os.path.dirname(os.path.realpath(__file__))

    def validate(self):
        self.vResult.valid = True
        self.vResult.reason = "Validation passed."

        return self.vResult.valid

    def _get_workspace_dir(self):
        wsfile = os.path.join(self.bdir, '../../../openstack-configs/.workspace')
        wsfile = os.path.abspath(wsfile)
        if not os.path.exists(wsfile):
            return None
        wspath = None
        with open(wsfile, 'r') as wsfd:
            wspath = wsfd.readline().rstrip()
        return wspath

    def _exec_cmd_pipe(self, command_list, stdin):
        cmd = command_list.pop(0)
        p = subprocess.Popen(cmd.split(), stdin=stdin, stdout=subprocess.PIPE)
        if command_list:
            return self._exec_cmd_pipe(command_list, p.stdout)
        return p.stdout

class FreshInstallValidator(Validator):
    def __init__(self):
        Validator.__init__(self)

    def validate(self):
        df = subprocess.Popen(["/usr/bin/docker", "info"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        output = df.communicate()[0]
        info_parts = output.split("\n")
        container_output = [x for x in info_parts if x.startswith('Containers')]
        containers = container_output[0].split(": ")[1]
        if int(containers) != 0:
            self.vResult.valid = False
            self.vResult.reason = "Operation can only be done on a fresh iso install"
        return self.vResult.valid

class VersionValidator(Validator):
    def __init__(self):
        Validator.__init__(self)

    def _get_changeid_version(self):
        dfile = os.path.join(self.bdir, '../../../openstack-configs/defaults.yaml')
        file_defaults = open(dfile, 'r')
        file_defaults = yaml.safe_load(file_defaults)
        if file_defaults.get('registry') == PUBLIC_REGISTRY:
            return file_defaults.get('RELEASE_TAG').strip()
        return str(file_defaults.get('image_tag')).strip()

    def _get_changeid_release(self, release_file):
        with open(release_file, 'r') as vfile:
            changeid = vfile.readline().strip()

        return changeid

    def validate(self):
        target_release_file = "/etc/mercury-version.txt"

        if not os.path.exists(target_release_file):
            self.vResult.valid = False
            self.vResult.reason = ("Management release file does not exist, "
                                   "cannot verify version matching")
            return self.vResult.valid


        target_changeid = self._get_changeid_release(target_release_file)
        backup_changeid = self._get_changeid_version()
        if target_changeid != backup_changeid:
            self.vResult.valid = False
            self.vResult.reason = ("Backup can only be restored to target with "
                                   "same version. Install version %s of Management "
                                   "Node" % backup_changeid)
        return self.vResult.valid


class NetworkChangeValidator(Validator):
    def __init__(self):
        Validator.__init__(self)

    def _qualify_net(self, network_props):
        result = []
        prefix = ""
        for prop in network_props:
            if prop.startswith("DEVICE"):
                prefix = prop.split("=")[1]
            else:
                result.append("%s %s" % (prefix, prop))
        return result

    def _get_changed_prop(self, curr_prop, prop_list):
        result = None
        curr_name = curr_prop.split("=")[0]
        for prop in prop_list:
            if prop.startswith(curr_name):
                result = prop
                break
        return result

    def _get_change_message(self):
        stored_network = []
        current_network = []

        cmd = ("/usr/bin/ls /etc/sysconfig/network-scripts/ifcfg-br_api"
               " /etc/sysconfig/network-scripts/ifcfg-br_mgmt "
               "| /usr/bin/sort | /usr/bin/xargs cat | /usr/bin/grep -v DNS "
               "| /usr/bin/grep -v NM_CONTROLLED")
        computed_stream = self._exec_cmd_pipe(cmd.split("|"), None)

        for line in computed_stream:
            current_network.append(line.strip("\n"))

        workspace_dir = self._get_workspace_dir()
        backup_dir = self.bdir.split(workspace_dir)[0]
        network_file = os.path.join(backup_dir, '.network_file')
        if not os.path.exists(network_file):
            return (".network_file was not found")

        with open(network_file, 'r') as nfile:
            for line in nfile:
                stored_network.append(line.strip("\n"))
        stored_network = self._qualify_net(stored_network)
        current_network = self._qualify_net(current_network)

        stored_set = set(stored_network)
        current_set = set(current_network)
        deleted_set = stored_set - current_set
        added_set = current_set - stored_set

        result = {}
        for net_val in deleted_set:
            result[net_val] = " was deleted"

        for net_val in added_set:
            changed_prop = self._get_changed_prop(net_val, result)
            if changed_prop:
                result[changed_prop] = " was modified"
            else:
                result[net_val] = " was added"

        change_blob = ""
        for k, v in result.iteritems():
                change_blob = change_blob + k + v + "\n"
        return change_blob

    def validate(self):
        workspace_dir = self._get_workspace_dir()

        if not workspace_dir:
            self.vResult.valid = False
            self.vResult.reason = "Management backup workspace path not found"
            return self.vResult.valid

        backup_dir = self.bdir.split(workspace_dir)[0]
        network_hash_file = os.path.join(backup_dir, '.network_hash')

        if not os.path.exists(network_hash_file):
            self.vResult.valid = False
            self.vResult.reason = ("Management backup was not complete, "
                                   ".network_hash was not found")
            return self.vResult.valid

        hash_value_stored = None
        with open(network_hash_file, 'r') as hfile:
            hash_value_stored = hfile.readline().rstrip()

        # Computing hash of br_api and br_mgmt interface files
        cmd = ("ls /etc/sysconfig/network-scripts/ifcfg-br_api "
               "/etc/sysconfig/network-scripts/ifcfg-br_mgmt "
               "| /usr/bin/sort | xargs cat | /usr/bin/grep -v DNS "
               "| /usr/bin/grep -v NM_CONTROLLED | /usr/bin/sha1sum")
        hash_stream = self._exec_cmd_pipe(cmd.split("|"), None)
        hash_value_computed = hash_stream.readline().strip("\n").split()[0]

        if hash_value_stored != hash_value_computed:
            self.vResult.valid = False
            reason = self._get_change_message()
            self.vResult.reason = ("Management network was modified: \n%s"
                                   % reason)
        return self.vResult.valid

class TimezoneValidator(Validator):
    def __init__(self):
        Validator.__init__(self)

    def validate(self):
        workspace_dir = self._get_workspace_dir()
        self.vResult.valid = False
        if not workspace_dir:
            self.vResult.reason = ("Management backup workspace path (%s)"
                                   " not found" % workspace_dir)
            return self.vResult.valid

        bkp_dir = self.bdir.split(workspace_dir)[0]
        bkp_tz_file = os.path.join(bkp_dir, '.timezone')
        if not os.path.exists(bkp_tz_file):
            self.vResult.reason = ("Management backup timezone file (%s)"
                                   " not found" % bkp_tz_file)
            return self.vResult.valid

        tz_stored = None
        try:
            with open(bkp_tz_file, 'r') as f:
                tz_stored = f.readline().strip()
        except (OSError, IOError) as e:
            self.vResult.reason = ("Unable to open or read file"
                                   "(%s)" % bkp_tz_file)
            return self.vResult.valid

        if not tz_stored:
            self.vResult.reason = ("Management backup timezone not read")
            return self.vResult.valid

        # Get local timezone
        cmd = subprocess.Popen(["/usr/bin/timedatectl"], stdout=subprocess.PIPE)
        tz = cmd.communicate()[0].strip()
        tstr = None
        for str in tz.split('\n'):
            if 'Time zone' in str:
                tstr = str.split(':')[1].split('(')[0].strip()

        if tstr != tz_stored:
            self.vResult.reason = ("Management backup timezone is %s but "
                                   "expecting %s" % (tstr, tz_stored))
            return self.vResult.valid

        self.vResult.valid = True
        return self.vResult.valid

class HostnameValidator(Validator):
    def __init__(self):
        Validator.__init__(self)

    def validate(self):
        workspace_dir = self._get_workspace_dir()
        if not workspace_dir:
            self.vResult.valid = False
            self.vResult.reason = ("Management backup workspace path (%s) "
                                   "not found" % workspace_dir)
            return self.vResult.valid

        bkp_dir = self.bdir.split(workspace_dir)[0]
        bkp_hostname = os.path.join(bkp_dir, '.hostname')
        if not os.path.exists(bkp_hostname):
            self.vResult.valid = False
            self.vResult.reason = ("Management backup was not complete, "
                                   ".hostname was not found")
            return self.vResult.valid

        if filecmp.cmp('/etc/hostname', bkp_hostname, shallow=False):
            self.vResult.valid = True
            return self.vResult.valid
        else:
            self.vResult.valid = False
            self.vResult.reason = ("Hostname is different than the one configured "
                                   " earlier")
            return self.vResult.valid

class CompleteBackupValidator(Validator):
    def __init__(self):
        Validator.__init__(self)

    def _get_relative_path(self, path, backup_path):
        backup_dir = os.path.basename(os.path.normpath(backup_path))
        path_part = path.split(backup_dir)

        if len(path_part) == 1:
            return path_part[0]
        return "." + path_part[1]

    def file_hasher(self, filename):
        BUF_SIZE = 65536
        sha1 = hashlib.sha1()
        with open(filename, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha1.update(data)
        return sha1.hexdigest()

    def checksummer(self, directory, change_files=False):
        backup_dir = directory

        file_ignore_list = ['.backup_hash', '.backup_files']

        filename_list = []
        for dir_name, subdir_list, file_list in os.walk(backup_dir):
            if 'kolla' in dir_name.split(os.sep):
                continue
            for file_name in file_list:
                if file_name in file_ignore_list:
                    continue
                if fnmatch.fnmatch(file_name, '*.pyc'):
                    continue
                filename_list.append(os.path.join(dir_name, file_name))

        hash_list = []
        if change_files:
            hash_filedict = {}
        for filename in filename_list:
            hash_list.append(self.file_hasher(filename))
            if change_files:
                hash_filedict[self.file_hasher(filename)] = filename

        hash_list.sort()
        if change_files:
            hash_sorted_filedict = {}
            keylist = hash_filedict.keys()
            keylist.sort()
            for i in keylist:
                hash_sorted_filedict[i] = hash_filedict[i]
            return hash_sorted_filedict

        buffer = '\n'.join(hash_list) + '\n'
        sha1 = hashlib.sha1()
        sha1.update(buffer)

        return sha1.hexdigest()

    def _get_changed_files(self, backup_dir):
        captured_backup_files = {}
        current_backup_files = {}

        backup_hash_file = os.path.join(backup_dir, '.backup_files')
        with open(backup_hash_file, 'r') as hfile:
            for line in hfile:
                line_parts = line.split()
                captured_backup_files[line_parts[0]] = line_parts[1]

        current_backup_files = self.checksummer(backup_dir, change_files=True)

        captured_set = set(captured_backup_files.keys())
        current_set = set(current_backup_files.keys())
        deleted_set = captured_set - current_set
        added_set = current_set - captured_set

        result = {}
        for hash_val in deleted_set:
            bfile = self._get_relative_path(captured_backup_files[hash_val],
                                            backup_dir)
            result[bfile] = " was deleted"

        for hash_val in added_set:
            bfile = self._get_relative_path(current_backup_files[hash_val],
                                            backup_dir)
            if bfile in result.keys():
                result[bfile] = " was modified"
            else:
                result[bfile] = " was added"
        return result


    def validate(self):
        workspace_dir = self._get_workspace_dir()

        if not workspace_dir:
            self.vResult.valid = False
            self.vResult.reason = "Management backup workspace path not found"
            return self.vResult.valid

        backup_dir = self.bdir.split(workspace_dir)[0]
        backup_hash_file = os.path.join(backup_dir, '.backup_hash')

        if not os.path.exists(backup_hash_file):
            self.vResult.valid = False
            self.vResult.reason = ("Management backup was not complete, "
                                   ".backup_hash was not found")
            return self.vResult.valid

        hash_value_stored = None
        with open(backup_hash_file, 'r') as hfile:
            hash_value_stored = hfile.readline().rstrip()

        # Computing hash of all files in backup directory except:
        # kolla pathnames and filename .backup_hash and ending in pyc
        hash_value_computed = self.checksummer(backup_dir)

        if hash_value_stored != hash_value_computed:
            self.vResult.valid = False
            change_dictionary = self._get_changed_files(backup_dir)
            change_blob = ""
            for k, v in change_dictionary.iteritems():
                change_blob += "  " + k + v + "\n"
            self.vResult.reason = ("Management backup was modified, stored hash "
                                   "does not match computed hash: \n%s"
                                   % change_blob)
        return self.vResult.valid


def main():

    restoreValidator = RestoreValidationEngine()
    restoreChecksum = RestoreChecksumEngine()


    if restoreValidator.run():
        print("Restore Validation Passed")
    else:
        print("Restore Validation Failed:")
        for vResult in restoreValidator.results:
            print(vResult.reason)

    if restoreChecksum.run():
        print("Restore Checksum Validation Passed")
    else:
        print("Restore Checksum Validation Failed:")
        for vResult in restoreChecksum.results:
            print(vResult.reason)


if __name__ == "__main__":
    main()

