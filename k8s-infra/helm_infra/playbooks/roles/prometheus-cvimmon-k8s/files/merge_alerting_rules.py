#!/usr/bin/env python

import yaml
import re
import os
import sys
import argparse
from check_promtool import check_custom_rules, validate_and_enforce_mandatory_values

LOG_PREFIX = "merge_alerting_rules.py: "


def merge_rules(custom_rules, default_rules, output_rules,
                promtool_path="/opt/cisco/promtool"):
    """Perform the merge of two alerting rules files into one.

    It uses check_promtool to perform initial validation of custom rules.
    The script takes 4 arguments:
        custom_rules  -- custom file with rules to be added/changed/deleted
        default_rules -- preexisting alerting rules
        output_rules  -- output file, where the result of this script will
                         be stored
        promtool_path -- path to promtool, used to verify the validity of
                         custom alerting rules file, default: /opt/cisco/promtool
    """
    if check_custom_rules(custom_rules, verbose=True,
       promtool_path=promtool_path):  # will log the output
        custom = open(custom_rules, "r")
        default = open(default_rules, "r")
        output = open(output_rules, "w")
        custom_j = yaml.safe_load(custom.read())
        custom_j = validate_and_enforce_mandatory_values(custom_j)
        default_j = yaml.safe_load(default.read())
        custom.close()
        default.close()

        delete_rules = []       # alerts to be deleted (exact name or regexp)
        existing_rules = []     # rules from custom_rules.yml
        default_rules = []      # rules from default_rules.yml
        existing_groups = []    # rules groups names from custom_rules.yml
        change_rules = []       # default rules to be changed
        n_added = 0             # counters to keep track of changes performed
        n_changed = 0
        n_deleted = 0

        # Stores preexisting rules' names.
        # Used only to keep changes counters accurate.
        for group in range(len(default_j["groups"])):
            for i in range(len(default_j["groups"][group]["rules"])):
                default_rules.append(default_j["groups"][group]["rules"]
                                     [i]["alert"])

        # Iterates on groups in custom file to perform initial differences
        # check. Custom file has priority over default file! In case there is
        # a rule with the same name in both files, only the one from custom
        # file will be kept as a result of this merge.
        for group in range(len(custom_j["groups"])):
            existing_groups.append(custom_j["groups"][group]["name"])
            for i in range(len(custom_j["groups"][group]["rules"])):
                if custom_j["groups"][group]["name"] == "delete-rules":
                    delete_rules.append(custom_j["groups"][group]["rules"]
                                        [i]["alert"])
                # allow to change summary, expression, and severities
                elif custom_j["groups"][group]["name"] == "change-rules":
                    summary = None
                    expr = None
                    severity = None
                    snmp_fault_severity = None
                    for_alert = None
                    snmp_fault_code = None
                    snmp_fault_source = None
                    description = None
                    if "annotations" in custom_j["groups"][group]["rules"][i]:
                        if ("summary" in custom_j["groups"][group]["rules"][i]
                                                 ["annotations"]):
                            summary = (
                                custom_j["groups"][group]["rules"][i]
                                        ["annotations"]["summary"]
                            )
                        if ("description" in custom_j["groups"][group]["rules"][i]
                                                 ["annotations"]):
                            description = (
                                custom_j["groups"][group]["rules"][i]
                                        ["annotations"]["description"]
                            )
                    if "expr" in custom_j["groups"][group]["rules"][i]:
                        expr = custom_j["groups"][group]["rules"][i]["expr"]
                    if "for" in custom_j["groups"][group]["rules"][i]:
                        for_alert = custom_j["groups"][group]["rules"][i]["for"]
                    if "labels" in custom_j["groups"][group]["rules"][i]:
                        if ("severity" in custom_j["groups"][group]["rules"][i]
                                                 ["labels"]):
                            severity = (
                                custom_j["groups"][group]["rules"][i]
                                        ["labels"]["severity"]
                            )
                        if ("snmp_fault_severity" in custom_j["groups"][group]
                                                 ["rules"][i]["labels"]):
                            snmp_fault_severity = (
                                custom_j["groups"][group]["rules"][i]
                                        ["labels"]["snmp_fault_severity"]
                            )
                        if ("snmp_fault_code" in custom_j["groups"][group]
                                                 ["rules"][i]["labels"]):
                            snmp_fault_code = (
                                custom_j["groups"][group]["rules"][i]
                                        ["labels"]["snmp_fault_code"]
                            )
                        if ("snmp_fault_source" in custom_j["groups"][group]
                                                 ["rules"][i]["labels"]):
                            snmp_fault_source = (
                                custom_j["groups"][group]["rules"][i]
                                        ["labels"]["snmp_fault_source"]
                            )
                    change_rules.append({
                        "alert":
                            custom_j["groups"][group]["rules"][i]["alert"],
                        "summary":
                            summary,
                        "description":
                            description,
                        "expr":
                            expr,
                        "for":
                            for_alert,
                        "severity":
                            severity,
                        "snmp_fault_severity":
                            snmp_fault_severity,
                        "snmp_fault_code":
                            snmp_fault_code,
                        "snmp_fault_source":
                            snmp_fault_source
                    })
                else:           # When this is a new rule to be added
                    existing_rules.append(
                        custom_j["groups"][group]["rules"][i]["alert"]
                    )
                    if (custom_j["groups"][group]["rules"][i]["alert"] not in
                       default_rules):
                        n_added += 1
                        print(LOG_PREFIX + "addeed new alert rule " +
                              custom_j["groups"][group]["rules"][i]["alert"])

        # Remove delete-rules from output
        for group in range(len(custom_j["groups"])):
            if custom_j["groups"][group]["name"] == "delete-rules":
                custom_j["groups"].pop(group)
                break

        # Remove change-rules from output
        for group in range(len(custom_j["groups"])):
            if custom_j["groups"][group]["name"] == "change-rules":
                custom_j["groups"].pop(group)
                break

        delete_alerts = []     # Alerts from default_rules.yml not to be merged
        for group in default_j["groups"]:
            for i in range(len(group["rules"])):
                for delete_rule in delete_rules:
                    # Find exact rules to be deleted (that match regex)
                    if re.match(delete_rule, group["rules"][i]["alert"]):
                        delete_alerts.append(group["rules"][i]["alert"])
                        n_deleted += 1
                        print(LOG_PREFIX +
                              "deleted previously existing rule: " +
                              group["rules"][i]["alert"])
                for j in range(len(change_rules)):  # change existing rules
                    if group["rules"][i]["alert"] in change_rules[j]["alert"]:
                        expr_changed = False
                        summary_changed = False
                        severity_changed = False
                        snmp_severity_changed = False
                        for_changed = False
                        description_changed = False
                        snmp_fault_code_changed = False
                        snmp_fault_source_changed = False
                        if (group["rules"][i]["expr"] != change_rules[j]
                           ["expr"] and change_rules[j]["expr"]):
                            group["rules"][i]["expr"] = change_rules[j]["expr"]
                            expr_changed = True
                            print(LOG_PREFIX +
                                  "expression changed for rule: " +
                                  change_rules[j]["alert"])
                        if (group["rules"][i]["for"] != change_rules[j]
                           ["for"] and change_rules[j]["for"]):
                            group["rules"][i]["for"] = change_rules[j]["for"]
                            for_changed = True
                            print(LOG_PREFIX +
                                  "for changed for rule: " +
                                  change_rules[j]["alert"])
                        if (group["rules"][i]["annotations"]["summary"] !=
                           change_rules[j]["summary"] and
                           change_rules[j]["summary"]):
                            group["rules"][i]["annotations"]["summary"] = (
                                change_rules[j]["summary"]
                            )
                            summary_changed = True
                            print(LOG_PREFIX +
                                  "summary changed for rule: " +
                                  change_rules[j]["alert"])
                        if (group["rules"][i]["annotations"]["description"] !=
                           change_rules[j]["description"] and
                           change_rules[j]["description"]):
                            group["rules"][i]["annotations"]["description"] = (
                                change_rules[j]["description"]
                            )
                            description_changed = True
                            print(LOG_PREFIX +
                                  "description changed for rule: " +
                                  change_rules[j]["alert"])
                        if (group["rules"][i]["labels"]["severity"] !=
                           change_rules[j]["severity"] and
                           change_rules[j]["severity"]):
                            group["rules"][i]["labels"]["severity"] = (
                                change_rules[j]["severity"]
                            )
                            severity_changed = True
                            print(LOG_PREFIX +
                                  "severity changed for rule: " +
                                  change_rules[j]["alert"])
                        if (group["rules"][i]["labels"]
                           ["snmp_fault_severity"] != change_rules[j]
                           ["snmp_fault_severity"] and change_rules[j]
                           ["snmp_fault_severity"]):
                            (group["rules"][i]["labels"]
                               ["snmp_fault_severity"]) = (
                                change_rules[j]["snmp_fault_severity"]
                            )
                            snmp_severity_changed = True
                            print(LOG_PREFIX +
                                  "snmp_fault_severity changed for rule: " +
                                  change_rules[j]["alert"])
                        if (group["rules"][i]["labels"]
                           ["snmp_fault_code"] != change_rules[j]
                           ["snmp_fault_code"] and change_rules[j]
                           ["snmp_fault_code"]):
                            (group["rules"][i]["labels"]
                               ["snmp_fault_code"]) = (
                                change_rules[j]["snmp_fault_code"]
                            )
                            snmp_fault_code_changed = True
                            print(LOG_PREFIX +
                                  "snmp_fault_code changed for rule: " +
                                  change_rules[j]["alert"])
                        if (group["rules"][i]["labels"]
                           ["snmp_fault_source"] != change_rules[j]
                           ["snmp_fault_source"] and change_rules[j]
                           ["snmp_fault_source"]):
                            (group["rules"][i]["labels"]
                               ["snmp_fault_source"]) = (
                                change_rules[j]["snmp_fault_source"]
                            )
                            snmp_fault_source_changed = True
                            print(LOG_PREFIX +
                                  "snmp_fault_source changed for rule: " +
                                  change_rules[j]["alert"])
                        if (expr_changed or summary_changed or severity_changed
                            or snmp_severity_changed or description_changed
                            or for_changed or snmp_fault_code_changed
                            or snmp_fault_source_changed):
                            n_changed += 1

            for i in range(len(group["rules"])):
                # Merge only those alert rules that are not present yet
                if (group["rules"][i]["alert"] not in delete_alerts and
                   group["rules"][i]["alert"] not in existing_rules):
                    # Create new rules group if non existing
                    if group["name"] not in existing_groups:
                        custom_j["groups"].append({
                            "name": group["name"],
                            "rules": []}
                        )
                        existing_groups.append(group["name"])
                    for j in range(len(custom_j["groups"])):
                        if custom_j["groups"][j]["name"] == group["name"]:
                            custom_j["groups"][j]["rules"].append(
                                group["rules"][i]
                            )

        output.seek(0)
        output.write("{% raw %}\n")
        output.write(yaml.dump(custom_j, default_flow_style=False))
        output.write("\n{% endraw %}")
        output.truncate()

        print(LOG_PREFIX + "success: ")
        if (n_added == 0 and n_changed == 0 and n_deleted == 0):
            print (LOG_PREFIX + " not merged because identical")
        else:
            print(LOG_PREFIX + " summary of changes: ")
            print(LOG_PREFIX + "  rules actually added: " + str(n_added))
            print(LOG_PREFIX + "  rules actually changed: " + str(n_changed))
            print(LOG_PREFIX + "  rules actually deleted: " + str(n_deleted))
    else:
        print(LOG_PREFIX + "unable to merge custom rules - "
              "provided input is incorrect.")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Merge custom and default alerting rules for prometheus.'
    )
    parser.add_argument(
        'custom_rules',
        type=str,
        help='custom rules file'
    )
    parser.add_argument(
        'default_rules',
        type=str,
        help='default rules file'
    )
    parser.add_argument(
        'output_rules',
        type=str,
        help='output rules file'
    )
    parser.add_argument(
        '--promtool_path',
        type=str,
        help='provide promtool location, if different that /opt/cisco/promtool')
    args = parser.parse_args()
    if args.promtool_path:
        if os.path.exists(args.promtool_path):
            merge_rules(args.custom_rules, args.default_rules,
                args.output_rules, promtool_path=args.promtool_path)
    else:
        merge_rules(args.custom_rules, args.default_rules,
            args.output_rules)
