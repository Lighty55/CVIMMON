#!/usr/bin/env python

import os
import re
import yaml
import argparse
import socket
from subprocess import Popen, PIPE

LOG_PREFIX = "check_promtool.py: "
# Supported SNMP severities and fault codes
SNMP_SEVERITIES = ['emergency', 'critical', 'major', 'alert', 'informational']
SNMP_CODES = [
    'other', 'resourceUsage', 'resourceThreshold',
    'serviceFailure', 'hardwareFailure', 'networkConnectivity'
]

def check_custom_rules(custom_rules, verbose=False,
                       promtool_path="/opt/cisco/promtool"):
    """Perform the validation check of customer provided custom rules file.

    It uses promtool for general check, but omits some of its checks, when
    changing or deleting prexisting alert rules.
    The script takes 3 arguments:
        custom_rules  -- custom file to be checked for format correctness
        verbose       -- displaying/logging the statistics when set to true
        promtool_path -- specifies promtool path (if not default)
    """
    if os.stat(custom_rules).st_size == 0:
        if verbose:
            print(LOG_PREFIX + "warning: ")
            print(LOG_PREFIX + "   " +
                  "Custom rules file is empty. This will reset to the default alerting rules.")
        return True

    try:
        custom = open(custom_rules, "r")
        custom_j = yaml.safe_load(custom.read())
    except yaml.scanner.ScannerError:
        if verbose:
            print(LOG_PREFIX + "failure: ")
            print(LOG_PREFIX + "   " +
                  "Custom rules file has incorrect YAML format")
        return False
    except Exception:
        if verbose:
            print(LOG_PREFIX + "failure: ")
            print(LOG_PREFIX + "   " +
                  "Could not open custom rules file")
        return False
    custom.close()

    if verbose:
        print(LOG_PREFIX + "checking " + custom_rules)
    sub = Popen([promtool_path, "check", "rules", custom_rules],
                stdout=PIPE, stderr=PIPE)
    output, error_output = sub.communicate()
    failures = []

    # Check if the errors are not caused by chaning/deleting rules format
    if error_output:
        # line 10: field error not found in type rulefmt.Rule
        for (line, error) in re.findall('line\s(\d+)\:\s(.*)', error_output):
            failures.append("line " + line + ": " + error)
        # group "new_group", rule 0, "new_alert": could not parse expression:
        #    could not parse remaining input "$"...
        for (group, rule, name, error) in re.findall('group."(.*)",.rule.(.*)'
                                                     ',.*["](.*)["]:.(.*)',
                                                     error_output):
            # When adding a new alert, expression or/and summary fields
            # are mandatory. However, custom config is still valid when
            # mentioned fields are not present when deleting/changing rules.
            if group != "change-rules" and group != "delete-rules":
                if (error != "field 'expr' must be set in rule"):
                    failures.append("group \"" + group +
                                    "\", rule " + rule +
                                    ", \"" + name +
                                    "\": " + error)

    # Check if the SNMP properties (severity, fault_code) specified for
    # the new or changed alerting rules are supported.
    try:
        for group in range(len(custom_j["groups"])):
            for i in range(len(custom_j["groups"][group]["rules"])):
                # Only evaluate new and changed rules
                if (custom_j["groups"][group]["name"] != "delete-rules"):
                    if "labels" in custom_j["groups"][group]["rules"][i]:
                        if ("snmp_fault_code" in
                        custom_j["groups"][group]["rules"][i]["labels"]):
                            if (custom_j["groups"][group]["rules"][i]["labels"]
                            ["snmp_fault_code"] not in SNMP_CODES):
                                failures.append("group \"" +
                                                custom_j["groups"][group]["name"] +
                                                "\", rule " + str(i) + ", \"" +
                                                custom_j["groups"][group]["rules"]
                                                [i]["alert"] +
                                                "\": " + "invalid SNMP_fault_code")
                        if ("snmp_fault_severity" in
                        custom_j["groups"][group]["rules"][i]["labels"]):
                            if (custom_j["groups"][group]["rules"][i]["labels"]
                            ["snmp_fault_severity"] not in SNMP_SEVERITIES):
                                failures.append("group \"" +
                                                custom_j["groups"][group]["name"] +
                                                "\", rule " + str(i) + ", \"" +
                                                custom_j["groups"][group]["rules"]
                                                [i]["alert"] + "\": " +
                                                "invalid SNMP_fault_severity")
    except:
        if verbose:
            print(LOG_PREFIX + "failure: ")
            print(LOG_PREFIX + "   " +
                  "Could not read custom rules")
        return False

    if not failures:
        if verbose:
            counters = {}       # Track new/changed/deleted rules counters
            new = 0
            for group in range(len(custom_j["groups"])):
                for i in range(len(custom_j["groups"][group]["rules"])):
                    if custom_j["groups"][group]["name"] not in counters:
                        counters[custom_j["groups"][group]["name"]] = 1
                    else:
                        counters[custom_j["groups"][group]["name"]] += 1
            print(LOG_PREFIX + "success: ")
            for group in counters:
                if group != "change-rules" and group != "delete-rules":
                    new += counters[group]
                elif group == "change-rules":
                    print(LOG_PREFIX +
                          " rules to be changed: " + str(counters[group]))
                else:
                    print(LOG_PREFIX +
                          " regular expressions for rules to be deleted: " +
                          str(counters[group]))
            if new != 0:
                print(LOG_PREFIX + " rules to be added: " + str(new))
        return True
    else:
        if verbose:
            print(LOG_PREFIX + "failure: ")
            for err in failures:
                print(LOG_PREFIX + "   " + err)
        return False

def validate_and_enforce_mandatory_values(custom_rules):
    """
    Check the attributes in the custom config and enforce mandatory values
    """
    pod_id = socket.gethostname()
    for elem in custom_rules['groups']:
        if 'labels' in elem:
            for alert in elem['rules']:
                if 'snmp_node' in alert['labels']:
                    alert['labels']['snmp_node'] = '{{ $labels.instance }}'
            for alert in elem['rules']:
                if 'snmp_node' in alert['labels']:
                    alert['labels']['snmp_podid'] = pod_id
    return custom_rules

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Check if the custom alerts file is valid.'
    )
    parser.add_argument(
        'custom_rules',
        type=str,
        help='input file to be checked'
    )
    parser.add_argument(
        '-v', '--verbose',
        help='increase output verbosity',
        action='store_true'
    )
    parser.add_argument(
        '--path',
        type=str,
        help='provide promtool location, if different that /opt/cisco/promtool')
    args = parser.parse_args()
    if args.path:
        if os.path.exists(args.path):
            check_custom_rules(args.custom_rules, args.verbose, args.path)
    else:
        check_custom_rules(args.custom_rules, args.verbose)
