#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2015 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

DOCUMENTATION = '''
---
module: monitor
author: Behzad Dastur
version_added: "1.0"
short_description:Monitor module for checking things on host.
description:
     - Monitoring for services on hosts.

'''

EXAMPLES = '''
Build docker image if required. Path should contains Dockerfile to build image:

- hosts: web
  sudo: yes
  tasks:
  - name: check or build image
    docker_image: path="/path/to/build/dir" name="my/app" state=present

'''

import subprocess


class Monitor(object):
    '''
    Monitoring operations on remote hosts.
    '''
    OPERATIONS = {
        'check_cluster_size': 'rabbitmq_validate'}

    def __init__(self,
                 module):
        '''
        Initialize Monitor class.
        '''
        self.module = module

    def execute_operation(self):
        '''
        Generic execute method. Will invoke
        specific monitoring tasks based on the operation specified.
        '''
        operation = self.module.params.get('operation', None)
        if not operation:
            self.module.fail_json(failed=True, msg="Invalid Operation")

        func = Monitor.OPERATIONS.get(operation, None)
        if not func:
            self.module.fail_json(failed=True,
                                  msg="Invalid operation. Not supported")
        func = getattr(self, func)

        result = {}
        result['params'] = self.module.params
        result['result'] = func()

        if result['result']['status'] == 'PASS':
            self.module.exit_json(changed=False, **result)
        elif result['result']['status'] == 'FAIL':
            self.module.fail_json(failed=True,
                                  msg="Operation status failed",
                                  **result)

    ##################################################
    # Operations handlers.
    ##################################################

    def rabbitmq_validate(self):
        '''
        Validate RabbitMQ Cluster
        '''
        result = {}
        imagetag = self.module.params.get('image_tag', None)
        rabbit_container = "rabbitmq_" + imagetag
        cluster_cmd = ["docker", "exec", rabbit_container, "rabbitmqctl",
                       "cluster_status", ]
        sproc = subprocess.Popen(cluster_cmd,
                                 stdout=subprocess.PIPE)
        (output, err) = sproc.communicate()

        expected_clust_sz = self.module.params.get('clust_sz', None)
        newstr = ""
        for line in output.splitlines():
            if re.match(r".*Cluster status.*", line) or \
                    re.match(r".*done", line) or \
                    re.match(r".*cluster_name.*", line):
                continue
            newstr = newstr + line.strip()

        nodestr = newstr.split("{running_nodes")
        nodelist = nodestr[0].split("rabbit@")
        result['nodelist'] = len(nodelist) - 1

        if str(result['nodelist']) != str(expected_clust_sz):
            result['status'] = 'FAIL'
            result['msg'] = "Expected: %s, Nodelist: %s. Failed" % \
                (str(expected_clust_sz), str(result['nodelist']))
        else:
            result['status'] = 'PASS'

        result['output'] = output
        result['err'] = err

        return result


def check_dependencies(module):
    '''
    Check if the required packages are present.
    '''
    pass


def main():
    module = AnsibleModule(
        argument_spec=dict(
            operation=dict(required=True, alias=['args']),
            arguments=dict(aliases=['args'], default=''),
            username=dict(aliases=['username'], default='guest'),
            password=dict(aliases=['password'], default='rabbitpass'),
            clust_sz=dict(aliases=['clust_sz'], default=1),
            image_tag=dict(aliases=['image_tag'], default='latest'),
        ),
        supports_check_mode=True
    )

    if module.params['operation'] is None:
        module.fail_json(msg="Operation not specified")

    check_dependencies(module)

    monitor = Monitor(module)
    monitor.execute_operation()


from ansible.module_utils.basic import *
main()
