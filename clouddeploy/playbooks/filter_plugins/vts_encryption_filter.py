#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2017 Cisco Systems, Inc.
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

import sys
import os
import paramiko
sys.path.append(os.path.dirname(__file__))
import VtsUtils


class FilterModule(object):
    def filters(self):
        return {'vts_encrypt': self.vts_encrypt}

    @staticmethod
    def vts_encrypt(vts_parameters_dic):

        ip = vts_parameters_dic['VTS_NCS_IP']
        u = vts_parameters_dic['VTC_SSH_USERNAME']
        p = vts_parameters_dic['VTC_SSH_PASSWORD']

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=u, password=p, timeout=10)
            out = client.exec_command('/opt/vts/bin/version_info | head -n1')[1].read()
            client.close()
            version = int(out.strip('vts_version=').replace('.', ''))
        except (paramiko.ssh_exception.NoValidConnectionsError, paramiko.ssh_exception.AuthenticationException):
            version = 0

        # By default encrypt the password
        password = vts_parameters_dic['VTS_PASSWORD']
        return VtsUtils.encrypt(password, 'ncs', None) \
            if not version or version >= 260 else password
