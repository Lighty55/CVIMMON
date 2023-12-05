#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Openstack End to End Validations
'''

import json
import os
import signal
import logging
import sys
import tempfile
import re
import time
import subprocess
import requests
from xml.dom import minidom
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
import openstackclients.credentials as credentials
import openstackclients.osnetwork_client as neutronclient
import openstackclients.osnova_client as novaclient
import utils.common as common
import utils.config_parser as config_parser
import utils.logger as logger
import yaml
import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore", UserWarning)
    import paramiko

VMTP_TIMEOUT = 3600
class vmtpAlarm(Exception):
    pass

def vmtpSigHandler(signum, frame):
    raise vmtpAlarm

DEFAULT_CFG_DIR = "openstack-configs"
DEFAULT_SETUP_FILE = "setup_data.yaml"

class SshClient(object):
    def __init__(self, hostname, password, username, port):

        self.hostname = hostname
        self.password = password
        self.username = username
        self.port = port

        try:
            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(hostname=hostname, port=port,
                                username=username, password=password)
            self._shell_channel = self.client.invoke_shell(width=1024)
            self._shell_channel.settimeout(60)

        except Exception as e:
            print(e)

    def send_command(self, command):
        stdin, stdout, stderr = self.client.exec_command(command)
        # print (stdout.readlines())
        return stdout

class VMTP(object):
    '''
    VMTP Test helper.
    '''
    def __init__(self, threaded=False):
        '''
        Initialize
        '''
        ########################################
        # Setup logging
        ########################################
        self.loginst = logger.Logger(name=__name__)
        self.log = self.loginst.get_logger()
        self.run_args = {}
        self.bootstrap_path = None
        self.rcfile = None

        self.homedir = common.get_homedir()
        self.cfg_dir = os.path.join(self.homedir, DEFAULT_CFG_DIR)
        setupfile = os.path.join(self.cfg_dir, DEFAULT_SETUP_FILE)
        self.os_creds = None
        self.os_api_version = None
        self.cacert = False
        self.region_name = None
        self.vts_test_data = []
        self.vmtp_tag = None
        self.managed = False
        self.rtr = 'pns-router'
        self.osg = 'vmtp-vts-pns-sg'
        self.sg_id = None

        if not os.path.exists(setupfile):
            print "Invalid setup file"
            return
        dfsfile = '/root/openstack-configs/defaults.yaml'
        self.ymlhelper = config_parser.YamlHelper(user_input_file=setupfile)
        self.dfshelper = config_parser.YamlHelper(user_input_file=dfsfile)
        if not self.ymlhelper:
            self.log.error("VMTP-TEST: ymlhelper is None")
            return None
        if not threaded:
            signal.signal(signal.SIGALRM, vmtpSigHandler)
            signal.alarm(VMTP_TIMEOUT)  # set vmtp timeout

        self.log.debug("VMTP Validation Initialized")

    def check_vmtp_section_exists(self):
        '''
        Check if VMTP section present in setup_data. If
        not skip VMTP step.
        '''
        if not self.ymlhelper.check_section_exists('VMTP_VALIDATION'):
            self.log.info("VMTP section not present. Skipping it")
            return False
        else:
            return True

    def set_auth_parameters(self):
        '''
        Set the Openrc auth parameters.
        '''
        homedir = common.get_homedir()
        cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)

        self.rcfile = cfg_dir + "/openrc"

        if not os.path.exists(self.rcfile):
            print "RC FILE Not found"
            return {'status': 'FAIL'}

        creds = credentials.Credentials(self.rcfile)
        credict = creds.get_credentials()
        self.os_creds = credict
        self.os_api_version = creds.rc_identity_api_version
        self.cacert = creds.rc_cacert
        self.region_name = creds.rc_region_name
        return {'status': 'PASS'}

    def cleanup_net(self, net_list):
        # Cleaning openstack networks, ports and VMs
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)
        for net in net_list:
            networks = neutron_handle.neutron_get_networks(external=False,
                                                           network_name=net)
            if len(networks) != 0:
                net_id = networks[0]['id']
                subnet_id = neutron_handle.\
                    neutron_get_net_params(net_name=net,
                                           net_params=['subnets'])[0]['subnets'][0]
                rports = self.get_subnet_port_list(subnet_id, 'router')
                if len(rports) != 0:
                    # Remove ports from router
                    for rport in rports:
                        self.remove_router_port_sub(rport['device_id'], subnet_id)

                hports = self.get_subnet_port_list(subnet_id, 'host')
                if len(hports) != 0:
                    # Delete active VM instances if such present
                    print('Delete Active Instances')
                    self.log.info('Delete Active Instances')
                    nova_handle = novaclient.NovaManage(self.os_creds,
                                                        self.os_api_version,
                                                        self.cacert)
                    for hport in hports:
                        try:
                            nova_handle.novaclient.servers.delete(hport['device_id'])
                        except Exception as e:
                            print('Error: ', e)
                        time.sleep(10)
                uports = self.get_subnet_port_list(subnet_id, 'unbound')
                if len(uports) != 0:
                    for uport in uports:
                        neutron_handle.neutron_delete_port(uport['port_id'])

                print('Delete network {}'.format(net))
                self.log.info('Delete network {}'.format(net))
                # Delete network
                net_delete = neutron_handle.neutron_delete_networks(external=False,
                                                                    network_name=net)

        networks = neutron_handle.neutron_get_networks(external=False,
                                                       network_name=net)
        # self.delete_sgs(self.osg)
        if len(networks) != 0:
            raise Exception("Cleanup failed")

    def create_net_sub(self, net_name, subnet_name, prefix, mgmt_node_ip):
        # Create new vmtp networks and subnetworks
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)
        dst_gw = '.'.join(prefix.split('.')[0:3]) + '.2'
        networks = neutron_handle.neutron_get_networks(external=False,
                                                       network_name=net_name)
        # print ('Check if Network {} is exist'.format(net_name))
        if len(networks) == 0:
            # We will create a new network based on parameters
            #
            network = {'network': {
                'name': net_name,
                'admin_state_up': True,
            }}
            subnet = {'subnet': {
                'name': subnet_name,
                'cidr': prefix,
                'ip_version': 4,
                'host_routes':
                    [{'destination': mgmt_node_ip + '/32',
                      'nexthop': dst_gw}]
            }}
            print('Create net {} with subnet {}'.format(net_name, subnet_name))
            self.log.info('Create net {} with subnet {}'.format(net_name,
                                                                subnet_name))
            new_net = neutron_handle.neutron_create_network(
                net_dict=network,
                subnet_dict=subnet)

            if new_net is None:
                print('Failed to create VTS  network')
                self.log.info('Failed to create VTS  network')
                return {'status': 'FAIL'}

            networks = neutron_handle.neutron_get_networks(external=False,
                                                           network_name=net_name)

        else:
            # Cleanup openstack vmtp networks and subnetworks if exists
            self.cleanup_net([net_name])
            self.create_net_sub(net_name, subnet_name, prefix, mgmt_node_ip)
            networks = neutron_handle.neutron_get_networks(external=False,
                                                           network_name=net_name)

        nets = networks[0]['id']
        return nets

    def get_subnet_id(self, subnet_name, net_id):
        # Get subnet ID for a network
        subnet = None
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)

        subnets = neutron_handle.neutron_get_subnets(subnet_name=subnet_name,
                                                     network_id=net_id)
        if len(subnets) != 0:
            subnet = subnets[0]['id']
        return subnet

    def get_subnet_port_list(self, subnet_id, device):
        # Get port list based on a device type
        if device == 'router':
            d_owner = 'network:router_interface'
        elif device == 'host':
            dev_type = 'vhostuser'
        elif device == 'dhcp':
            d_owner = 'network:dhcp'
        elif device == 'unbound':
            dev_type = device

        # print("Get Subnet {} ports type {}".format(subnet_id, device))
        subnet_ports = []
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)
        port_list = neutron_handle.neutron_get_ports()
        for port in port_list:
            if device in ['unbound', 'host']:
                if (port['fixed_ips'][0]['subnet_id'] == subnet_id and
                        port['binding:vif_type'] == dev_type and
                        port['device_owner'] != 'network:dhcp'):
                    subnet_ports.append({'port_id': port['id'],
                                         'device_id': port['device_id'],
                                         'status': port['status'],
                                         'host': port['binding:host_id'],
                                         'ip_address':
                                             port['fixed_ips'][0]['ip_address']})
            else:
                if (port['fixed_ips'][0]['subnet_id'] == subnet_id and
                        port['device_owner'] == d_owner):
                    subnet_ports.append({'port_id': port['id'],
                                         'device_id': port['device_id'],
                                         'status': port['status'],
                                         'host': port['binding:host_id'],
                                         'ip_address':
                                             port['fixed_ips'][0]['ip_address']})

        return subnet_ports

    def add_router_port_sub(self, router_id, subnet_id):
        # Attach vmtp router to a specific subnet
        print('Add port on router pns-router')
        self.log.info('Add port on router pns-router')
        # print("Add port on router {} for subnet {} ".format(router_id, subnet_id))
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)
        rport = neutron_handle.neutron_router_add_port_sub(router_id, subnet_id)
        return rport

    def remove_router_port_sub(self, router_id, subnet_id):
        # Detach vmtp router to a specific subnet
        print('Remove port on router pns-router')
        self.log.info('Remove port on router pns-router')
        # print("Remove port on router {} for subnet {} ".
        #      format(router_id, subnet_id))
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)
        rport = neutron_handle.neutron_router_remove_port_sub(router_id, subnet_id)
        return rport

    def create_router(self, router_name):
        # Create vmtp router
        print('Create router {}'.format(router_name))
        self.log.info('Create router {}'.format(router_name))
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)

        router_a_exists = \
            neutron_handle.neutron_get_routers(router_name=router_name)
        if len(router_a_exists) == 0:
            # We will create a new network based on parameters
            #
            router = {'router': {'name': router_name,
                                 'admin_state_up': True}}

            neutron_handle.neutron_create_router(router_dict=router)

            routers = neutron_handle.neutron_get_routers(router_name=router_name)
            if len(routers) == 0:
                print('Failed to create router {}'.format(router_name))
                self.log.info('Failed to create router {}'.format(router_name))
                rts = routers
            else:
                rts = routers[0]['id']
        else:
            print('Router already exist {}'.format(router_a_exists[0]['id']))
            self.log.info('Router already exist {}'.format(router_a_exists[0]['id']))
            rts = router_a_exists[0]['id']

        return rts

    def delete_router(self, router_name):
        # Delete vmtp router
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)
        neutron_handle.neutron_delete_routers(router_name)

    def create_port(self, network_id, subnet_id, net_prefix, port_name):
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)
        ip_addr = '.'.join(net_prefix.split('.')[0:3]) + '.4'
        print('IP reservation for build node {}'.format(ip_addr))
        # net_mask = net_prefix.split('/')[1]
        port_dict = {"port": {
            "admin_state_up": 'true',
            "fixed_ips": [{"ip_address": ip_addr, "subnet_id": subnet_id}],
            "name": port_name,
            "network_id": network_id
        }}
        try:
            port = neutron_handle.neutron_create_port(port_dict)
            # print port['port']
        except Exception as e:
            print('IP reservation for build node failed')

        if port is not None:
            return port

    def create_sg(self, sg_name):
        # Create vmtp security group to pass any type of traffic
        print('Create security group {}'.format(sg_name))
        self.log.info('Create security group {}'.format(sg_name))
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)
        sgs = neutron_handle.neutron_get_security_groups(sg_name)
        if len(sgs) != 0:
            for sg in sgs:
                neutron_handle.neutron_delete_security_group(sg['id'])
                print('Delete old security group {}'.format(sg_name))
                self.log.info('Delete security group {}'.format(sg_name))
                # print("Delete old security group {} {}".format(sg_name, sg['id']))

        security_group = {'security_group': {
            'name': sg_name,
            'description': 'VMTP Test Security Group'
        }}

        sg = neutron_handle.neutron_create_security_group(security_group)
        return sg

    def delete_sgs(self, sg_name):
        # Delete vmtp security group
        print('Delete security group {}'.format(sg_name))
        self.log.info('Delete security group {}'.format(sg_name))
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)
        sgs = neutron_handle.neutron_get_security_groups(sg_name)
        if len(sgs) != 0:
            for sg in sgs:
                neutron_handle.neutron_delete_security_group(sg['id'])

    def create_sg_rules(self, sg_id):
        neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                     self.os_api_version,
                                                     self.cacert)
        sg_rule_allow_tcp = {"security_group_rule": {
            "direction": "ingress",
            "ethertype": "IPv4",
            "port_range_min": 1,
            "port_range_max": 65000,
            "protocol": "tcp",
            "security_group_id": sg_id
        }}
        sg_rule_allow_udp = {"security_group_rule": {
            "direction": "ingress",
            "ethertype": "IPv4",
            "port_range_min": 1,
            "port_range_max": 65000,
            "protocol": "udp",
            "security_group_id": sg_id
        }}
        sg_rule_allow_icmp = {"security_group_rule": {
            "direction": "ingress",
            "ethertype": "IPv4",
            "protocol": "icmp",
            "security_group_id": sg_id
        }}
        neutron_handle.neutron_create_security_group_rule(sg_rule_allow_icmp)
        neutron_handle.neutron_create_security_group_rule(sg_rule_allow_udp)
        neutron_handle.neutron_create_security_group_rule(sg_rule_allow_tcp)

    def cleanup_vts_all(self):
    # Cleaning all created objects for TORs, openstack
    # build node and dhcp backdoor remote node
        if self.managed is True:
            # Cleaning config TORs through VTC if VTS is managed
            try:
                try:
                    if self.vts_test_data[2]['phase'] > 0:
                        # Check if this config phase was performed
                        # Then cleanup VLANs and EVPN
                        self.cleanup_tor_ncs(self.vts_test_data[2]['vts_data'],
                                             self.vts_test_data[0]['tor'],
                                             self.vts_test_data[0]['net_id'],
                                             self.vts_test_data[0]['vlan_tag'])
                        self.cleanup_tor_ncs(self.vts_test_data[2]['vts_data'],
                                             self.vts_test_data[0]['tor'],
                                             self.vts_test_data[1]['net_id'],
                                             self.vts_test_data[1]['vlan_tag'])
                        self.cleanup_tor_ncs(self.vts_test_data[2]['vts_data'],
                                             self.vts_test_data[1]['tor'],
                                             self.vts_test_data[0]['net_id'],
                                             self.vts_test_data[0]['vlan_tag'])
                        self.cleanup_tor_ncs(self.vts_test_data[2]['vts_data'],
                                             self.vts_test_data[1]['tor'],
                                             self.vts_test_data[1]['net_id'],
                                             self.vts_test_data[1]['vlan_tag'])
                except Exception as e:
                        print e

                try:
                    if self.vts_test_data[2]['phase'] > 1:
                        # Check if this config phase was performed
                        # Then cleanup routing and interfaces on a build node
                        self.cleanup_bld_node_all()

                except Exception as e:
                    print e

            except Exception as e:
                print e

        try:
            # Cleaning networks from an opnestack
            self.cleanup_net([self.vts_test_data[0]['net_name'],
                              self.vts_test_data[1]['net_name']])

            os.system('ip netns delete {} &> /dev/null'.format(self.vmtp_tag))
            self.delete_sgs(self.osg)
            self.delete_router(self.rtr)
            if self.managed is False:
                print('Cleanup routing, links and namespaces')
                for val in self.vts_test_data:
                    # Cleaning build node routes towards dhcp backdoor
                    os.system('ip route del {} &> /dev/null'.
                              format(val['net_prefix']))
                    try:
                        # Cleaning dhcp backdoor routing and veth interfaces
                        time.sleep(10)
                        self.cleanup_dhcp_ns(val['net_id'], val['dhcp_node_ip'])
                        self.cleanup_dhcp_ns(val['net_id'], val['dhcp_node_ip'])
                    except Exception as e:
                        print e

        except Exception as e:
            print e

        except KeyboardInterrupt:
            print('VMTP cleanup process was interrupted')
            print('Please see debug for manual cleanup:')
            self.log.info('VMTP cleanup process was interrupted')
            self.log.info('Please see debug for manual cleanup:')
            if len(self.vts_test_data) > 0:
                for val in self.vts_test_data:
                    print(val)
                    self.log.info(val)
            sys.exit(0)

    def get_vts_request(self, vts_request, vts_data):
        # VTC client requesting information from VTC
        # This method only used for managed VTS
        xmldoc = []
        ip_addr = vts_data['VTS_NCS_IP']
        username = vts_data['VTC_SSH_USERNAME']
        password = vts_data['VTC_SSH_PASSWORD']
        session = requests.Session()
        session.verify = False
        try:
            resp_raw = session.get(url='https://{}:{}/api/running/{}'.
                                   format(ip_addr, '8888', vts_request),
                                   auth=HTTPBasicAuth(username, password))
        except Exception as e:
            print('Error: ', e)

        if resp_raw.content is not None and resp_raw.status_code == 200:
            xmldoc.append(minidom.parseString(resp_raw.content))
            xmldoc.append(ET.fromstring(resp_raw.content))
            # print(resp_raw.content)
        elif resp_raw.status_code == 404:
            print('No such data: ' + vts_request)
            self.log.info('No such data: ' + vts_request)
            xmldoc = None
        else:
            print('Unable to complete request: ' + vts_request)
            self.log.info('Unable to complete request: ' + vts_request)
            xmldoc = None

        return xmldoc

    def get_vts_network(self, vts_data, net_id, mode='ingress-replication'):
        # Get VNI and multicast group information from VTC
        # This method only used for managed VTS
        mcast = None
        vni = None
        vts_request = 'cisco-vts/tenants/tenant/admin/topologies/topology/' \
                      'admin/networks/network/{}/'.format(net_id)
        xmldoc = self.get_vts_request(vts_request, vts_data)
        if xmldoc is not None:
            vni_elem = xmldoc[0].getElementsByTagName('vts-allocated-vni')
            vni = vni_elem[0].firstChild.nodeValue
            if mode == 'multicast':
                mcast_elem = \
                    xmldoc[0].getElementsByTagName('vts-allocated-multicast')
                mcast = mcast_elem[0].firstChild.nodeValue
            # print(vni, mcast)
            return {'vni': vni, 'mcast': mcast}

    def get_vts_vlans(self, device, vts_data):
        # Get all VLANs information for TOR device
        # This method only used for managed VTS
        vlans = None
        device = device['hostname']
        vts_request = 'devices/device/{}/config/nx:vlan/'.format(device)
        xmldoc = self.get_vts_request(vts_request, vts_data)
        if xmldoc is not None:
            vlans = [vlan.firstChild.data.encode('utf-8') for vlan in
                     xmldoc[0].getElementsByTagName('id')]
        return vlans

    def get_vlan_segment(self, device, vts_data, vlan_tag):
        # Get VLAN to VNI mapping information for TOR device
        # This method only used for managed VTS
        vn_segment = None
        device = device['hostname']
        vts_request = 'devices/device/{}/config/nx:vlan/' \
                      'vlan-list/{}/vn-segment'.format(device, vlan_tag)
        xmldoc = self.get_vts_request(vts_request, vts_data)
        if xmldoc is not None:
            vn_s_el = xmldoc[0].getElementsByTagName('vn-segment')
            vn_segment = vn_s_el[0].firstChild.nodeValue
        return vn_segment

    def get_vts_pochan(self, device, vts_data):
        # Get VMTP (build node) interface
        # This method only used for managed VTS
        chan = None
        port = device['br_mgmt_port_info'].split('Ethernet')[1]
        vtc = device['hostname']
        vts_request = 'devices/device/{}/config/nx:interface/Ethernet/'.format(vtc)
        xmldoc = self.get_vts_request(vts_request, vts_data)
        if xmldoc is not None:
            xreq = ".//{http://tail-f.com/ned/cisco-nx}Ethernet[" \
                   "{http://tail-f.com/ned/cisco-nx}name='" + port + "']" + "/" \
                   "{http://tail-f.com/ned/cisco-nx}channel-group/" \
                   "{http://tail-f.com/ned/cisco-nx}id"
            chan = xmldoc[1].find(xreq).text
        return chan

    def get_vts_rep_mode(self, domain, vts_data):
        # Check BGP EVPN replication mode
        # This method only used for managed VTS
        rep_mode = None
        vts_request = 'cisco-vts/infra-policy/admin-domains/admin-domain/{}/' \
                      'l2-gateway-groups/l2-gateway-group/L2GW-0/' \
                      'policy-parameters/packet-replication'.format(domain)
        xmldoc = self.get_vts_request(vts_request, vts_data)
        if xmldoc is not None:
            r_elem = xmldoc[0].getElementsByTagName('packet-replication')
            r_mode = r_elem[0].firstChild.nodeValue
            try:
                rep_mode = r_mode.split(':')[1].strip()
            except Exception as e:
                print('Error {}'.format(e))
        return rep_mode

    def configure_tor_ncs(self, vts_par, tor_par, net_id, vlan_tag):
        # Configure TOR swithces VLANs and BGP EVPN
        # This method only used for managed VTS
        ssh_node = SshClient(vts_par['VTS_NCS_IP'], vts_par['VTC_SSH_PASSWORD'],
                             vts_par['VTC_SSH_USERNAME'], port=22)
        tor_name = tor_par['hostname']
        self.cleanup_vlan_seg(vts_par, tor_par, vlan_tag)
        try:
            portchan = self.get_vts_pochan(tor_par, vts_par)
            rep_mode = self.get_vts_rep_mode('NFVI', vts_par)
            net_par = self.get_vts_network(vts_par, net_id, rep_mode)
            if (portchan and rep_mode and net_par) is not None:
                pass
            else:
                print('Switch configuration operation failed')
                self.log.info('Switch configuration operation failed')
                self.cleanup_vts_all()
                sys.exit(0)

        except Exception as e:
            print('Switch configuration operation failed')
            print('Error: {}'.format(e))
            self.log.info('Switch configuration operation failed')
            self.log.info('Error: {}'.format(e))
            self.cleanup_vts_all()
            sys.exit(0)

        if (portchan and rep_mode and net_par) is not None:
            op_status = None
            print('Configure {} port {} vlan {} vni {}'.format(tor_name,
                                                               portchan,
                                                               vlan_tag,
                                                               net_par['vni']))
            self.log.info('Configure {} port {} '
                          'vlan {} vni {}'.format(tor_name, portchan, vlan_tag,
                                                  net_par['vni']))

            ncs_cli = '/opt/nso/current/bin/ncs_cli'
            devconf = 'set devices device {} config'.format(tor_name)
            comr = "echo -e 'configure\n{}commit\n' | " + ncs_cli
            com = '{} nx:nv overlay evpn\n'.format(devconf)
            com += '{} nx:feature nv overlay\n'.format(devconf)
            com += '{} nx:feature vn-segment-vlan-based\n'.format(devconf)

            com += '{} nx:vlan vlan-list {} vn-segment {}\n'.format(devconf,
                                                                    vlan_tag,
                                                                    net_par['vni'])

            com += '{} nx:interface port-channel {} switchport trunk allowed ' \
                   'vlan ids {}\n'.format(devconf, portchan, vlan_tag)
            com += '{} nx:interface nve 1 source-interface loopback0 ' \
                   'host-reachability protocol bgp\n'.format(devconf)
            if rep_mode == 'multicast':
                com += '{} nx:interface nve 1 member vni {} mcast-group {}\n'. \
                    format(devconf, net_par['vni'], net_par['mcast'])
            else:
                com += '{} nx:interface nve 1 member vni {} ' \
                       'ingress-replication protocol bgp\n'. \
                    format(devconf, net_par['vni'])

            com += '{} nx:evpn vni {} l2 rd auto\n'.format(devconf, net_par['vni'])
            com += '{} nx:evpn vni {} l2 rd auto route-target export auto\n'. \
                format(devconf, net_par['vni'])
            com += '{} nx:evpn vni {} l2 rd auto route-target import auto\n'. \
                format(devconf, net_par['vni'])
            try:
                op_status = ssh_node.send_command(comr.format(com))

            except Exception as e:
                print('Switch configuration operation failed')
                print('Error: {}'.format(e))
                self.log.info('Switch configuration operation failed')
                self.log.info('Error: {}'.format(e))
                self.cleanup_vts_all()
                sys.exit(0)

            if op_status is not None:
                for line in op_status:
                    op_check = re.search('Commit complete.', line)
                    if op_check is None:
                        print('Switch configuration operation failed')
                        print('Please repeat test again')
                        self.log.info('Switch configuration operation failed')
                        self.cleanup_vts_all()
                        sys.exit(0)

            time.sleep(2)
        else:
            print('Failed')

    def get_test_vlans(self, dev_par_a, dev_par_b, vts_data):
        # Obtain free VLAN information
        # This method only used for managed VTS
        used_vlans_a = self.get_vts_vlans(dev_par_a, vts_data)
        used_vlans_b = self.get_vts_vlans(dev_par_b, vts_data)
        if used_vlans_a and used_vlans_b is not None:
            free_vlans_tor_a = [str(x) for x in range(1000, 3000)
                                if str(x) not in used_vlans_a]
            free_vlans_tor_b = [str(x) for x in range(1000, 3000)
                                if str(x) not in used_vlans_b]
            free_vlans = [x for x in free_vlans_tor_a if x in free_vlans_tor_b]
        else:
            raise Exception('Can not obtain test VLANs')
        return free_vlans

    def get_dhcp_node_name(self, subnet_id, dhcp_address):
        # Get DHCP node hostname for specific subnet
        # based on port IP address
        dhcp_node = None
        print "Get control node for subnet_id {}".format(subnet_id)
        dports = self.get_subnet_port_list(subnet_id, 'dhcp')
        if len(dports) != 0:
            for dport in dports:
                if dport['ip_address'] == dhcp_address:
                    dhcp_node = dport['host']

        return dhcp_node

    def get_dhcp_node_ip(self, dhcp_node_name):
        # Get DHCP node IP address based on a host name
        node_ip = None
        fd = open('/root/openstack-configs/mercury_servers_info')
        for line in fd.readlines():
            line.strip()
            result = re.search(dhcp_node_name, line)
            if result is not None:
                lsplit = line.split("|")
                node_ip = lsplit[3].strip()
        if node_ip is None:
            print ('Can not get control node ip')
        return node_ip

    def set_node_ip_and_local_route(self, net_prefix, subnet_id):
        # Configure routing information on vmtp node
        print('Configure local routing')
        dhcp_ip = ".".join(net_prefix.split('.')[0:3]) + ".2"
        dhcp_node_name = self.get_dhcp_node_name(subnet_id, dhcp_ip)
        dhcp_node_ip = self.get_dhcp_node_ip(dhcp_node_name)
        os.system('ip route del {} &> /dev/null'.format(net_prefix))
        os.system('ip route add {} via {}'.format(net_prefix, dhcp_node_ip))

        return dhcp_node_ip

    def configure_dhcp_ns(self, net_id, med_net, sub_pref,
                          dhcp_node_ip, mgmt_host_ip):
        # Configure routing and veth interfaces for dhcp node
        med_pref = '.'.join(med_net.split('.')[0:3])
        net_mark = net_id[-7:]
        ssh_node = SshClient(dhcp_node_ip, password='',
                             username='root', port=22)
        print('Configure remote links and routing')

        ssh_node.send_command('ip link add dev vmtp-1-{} type veth '
                              'peer name vmtp-2-{}'.format(net_mark, net_mark))
        ssh_node.send_command('ip link set vmtp-1-{} up'.format(net_mark))
        ssh_node.send_command('ip a a {}.1/30 dev vmtp-1-{}'.format(med_pref,
                                                                    net_mark))
        ssh_node.send_command('ip link set vmtp-2-{} netns '
                              'qdhcp-{}'.format(net_mark, net_id))
        ssh_node.send_command('ip netns exec qdhcp-{} ip link '
                              'set vmtp-2-{} up'.format(net_id, net_mark))
        ssh_node.send_command('ip netns exec qdhcp-{} ip a a {}.2/30 '
                              'dev vmtp-2-{}'.format(net_id, med_pref, net_mark))
        ssh_node.send_command('ip route add {} via {}.2 dev '
                              'vmtp-1-{}'.format(sub_pref, med_pref, net_mark))
        ssh_node.send_command('ip netns exec qdhcp-{} ip route add {}/32 '
                              'via {}.1 dev vmtp-2-{}'.format(net_id, mgmt_host_ip,
                                                              med_pref, net_mark))

    def cleanup_tor_ncs(self, vts_par, tor_par, net_id, vlan_tag):
        # Cleanup TOR switches VLANs and BGP EVPN
        # This method only used for managed VTS
        ncs_cli = '/opt/nso/current/bin/ncs_cli'
        ssh_node = SshClient(vts_par['VTS_NCS_IP'], vts_par['VTC_SSH_PASSWORD'],
                             vts_par['VTC_SSH_USERNAME'], port=22)
        tor_name = tor_par['hostname']
        try:
            portchan = self.get_vts_pochan(tor_par, vts_par)
            rep_mode = self.get_vts_rep_mode('NFVI', vts_par)
            net_par = self.get_vts_network(vts_par, net_id, rep_mode)
        except Exception as e:
            print('Error: {}'.format(e))
            self.log.info('Error: {}'.format(e))

        if portchan is not None and rep_mode is not None and net_par is not None:
            print('Cleanup {} port {} vlan {} vni {}'.format(tor_name,
                                                             portchan,
                                                             vlan_tag,
                                                             net_par['vni']))
            self.log.info('Cleanup {} port {} vlan {} vni {}'.format(tor_name,
                                                                     portchan,
                                                                     vlan_tag,
                                                                     net_par['vni']))
            devconf = 'delete devices device {} config'.format(tor_name)
            comr = "echo -e 'configure\n{}commit\n' | " + ncs_cli
            com = '{} nx:evpn vni {}\n'.format(devconf, net_par['vni'])
            com += '{} nx:interface nve 1 member vni {}\n'.format(devconf,
                                                                  net_par['vni'])
            com += '{} nx:interface port-channel {} switchport trunk ' \
                   'allowed vlan ids {}\n'.format(devconf, portchan, vlan_tag)
            com += '{} nx:vlan vlan-list {}\n'.format(devconf, vlan_tag)
            ssh_node.send_command(comr.format(com))
            time.sleep(2)

    def cleanup_vlan_seg(self, vts_par, tor_par, vlan_tag):
        # Cleaning VLAN to VNI mapping on TORs
        # This method only used for managed VTS
        ncs_cli = '/opt/nso/current/bin/ncs_cli'
        ssh_node = SshClient(vts_par['VTS_NCS_IP'], vts_par['VTC_SSH_PASSWORD'],
                             vts_par['VTC_SSH_USERNAME'], port=22)
        tor_name = tor_par['hostname']
        devconf = 'delete devices device {} config'.format(tor_name)
        comr = "echo -e 'configure\n{}commit\n' | " + ncs_cli
        com = '{} nx:vlan vlan-list {}\n'.format(devconf, vlan_tag)
        ssh_node.send_command(comr.format(com))
        time.sleep(2)

    def cleanup_dhcp_ns(self, net_id, dhcp_node_ip):
        # Cleaning DHCP namespaces and interfaces
        net_mark = net_id[-7:]
        ssh_node = SshClient(dhcp_node_ip, password='', username='root', port=22)
        ssh_node.send_command('ip link delete dev vmtp-1-{}'.format(net_mark))
        ssh_node.send_command('ip netns delete qdhcp-{}'.format(net_id)).read()
        # print 'ip link delete dev vmtp-1-{}'.format(net_mark)
        # print 'ip netns delete qdhcp-{}'.format(net_id)


    def sync_vts(self, vts_par, tor_par):
        # Syncing configuration from TOR to VTC
        # This method only used for managed VTS
        ncs_cli = '/opt/nso/current/bin/ncs_cli'
        ssh_node = SshClient(vts_par['VTS_NCS_IP'], vts_par['VTC_SSH_PASSWORD'],
                             vts_par['VTC_SSH_USERNAME'], port=22)
        tor_name = tor_par['hostname']
        com = 'request devices device {} sync-from\n'.format(tor_name)
        comr = "echo -e '{}' | " + ncs_cli
        # print(comr.format(com))
        ssh_node.send_command(comr.format(com))
        time.sleep(3)

    def configure_vmtp_container(self, node_ip, rpath):
        # Configuring VMTP docker container
        print('Configure VMTP docker')
        self.log.info('Configure VMTP docker')
        vmtp_tag = self.vmtp_tag
        os.system('systemctl stop docker-vmtp.service')
        os.system('docker rm {} &> /dev/null'.format(vmtp_tag))
        os.system('ip netns del {} &> /dev/null'.format(vmtp_tag))
        if self.managed is True:
            # If VTS managed configuring docker bridge network mode
            os.system('docker run -v /var/log/vmtp:/var/log/vmtp:z -td --name '
                      '{} {}:5000/{}/vmtp:{} &> /dev/null'.
                      format(vmtp_tag, node_ip, rpath, vmtp_tag.split('vmtp_')[1]))
        elif self.managed is False:
            # If VTS unmanaged configuring docker host network mode
            os.system('docker run -v /var/log/vmtp:/var/log/vmtp:z'
                      ' -td --net host --name '
                      '{} {}:5000/{}/vmtp:{} &> /dev/null'.
                      format(vmtp_tag, node_ip, rpath, vmtp_tag.split('vmtp_')[1]))

        os.system('docker stop -t 8 {} &> /dev/null'.format(vmtp_tag))
        time.sleep(20)
        os.system('systemctl start docker-vmtp.service')
        time.sleep(10)
        if self.managed is True:
            # If VTS managed linking docker name space to host /var/run/
            proc_id = subprocess.check_output("docker inspect -f '{{.State.Pid}}' " +
                                              vmtp_tag, shell=True)
            print('container: {}  process id: {} '.format(vmtp_tag, proc_id.strip()))
            self.log.info('container: {}  process id: {} '.format(vmtp_tag,
                                                                  proc_id.strip()))
            if os.path.isdir("/var/run/netns") is not True:
                os.system('mkdir /var/run/netns')
            os.system('ln -sf /proc/{}/ns/net /var/run/netns/{}'.
                      format(proc_id.strip(), vmtp_tag))

    def configure_bld_node_net(self, net_prefix, net_vlan):
        # Configuring interfaces for host and vmtp container
        # This method only used for managed VTS
        print('Configure build node vlan {}'.format(net_vlan))
        self.log.info('Configure build node vlan {}'.format(net_vlan))
        bld_ip = ".".join(net_prefix.split('.')[0:3]) + ".4"
        mask = net_prefix.split('/')[1]
        vmtp_tag = self.vmtp_tag
        os.system('ip link add link br_mgmt name br_mgmt.{} type vlan id {}'.
                  format(net_vlan, net_vlan))
        os.system('ip link set up dev br_mgmt.{}'.format(net_vlan))
        os.system('ip link add dev vmtp-h-{} type veth peer name vmtp-c-{}'.
                  format(net_vlan, net_vlan))
        os.system('ip link add dev br_vmtp_{} type bridge'.format(net_vlan))
        os.system('ip link set dev br_mgmt.{} master br_vmtp_{}'.
                  format(net_vlan, net_vlan))
        os.system('ip link set dev vmtp-h-{} master br_vmtp_{}'.
                  format(net_vlan, net_vlan))
        os.system('ip link set up dev br_vmtp_{}'.format(net_vlan, net_vlan))
        os.system('ip link set up dev vmtp-h-{}'.format(net_vlan))
        os.system('ip link set netns {} dev vmtp-c-{}'.format(vmtp_tag, net_vlan))
        os.system('ip netns exec {} ip a a {}/{} dev vmtp-c-{}'.
                  format(vmtp_tag, bld_ip, mask, net_vlan))
        os.system('ip netns exec {} ip link set up dev vmtp-c-{}'.
                  format(vmtp_tag, net_vlan))

    def cleanup_bld_node_all(self):
        # Cleanup interfaces for host and vmtp container
        # This method only used for managed VTS
        print('Cleanup build node')
        self.log.info('Cleanup build node')
        os.system("ip link | command grep -o 'br_mgmt\..*@' | cut -d'@' -f1 | "
                  "xargs -I % ip link del dev %")
        os.system("ip link | grep -o 'vmtp-h-.*@' | cut -d'@' -f1 | "
                  "xargs -I % ip link delete dev %")
        os.system("ip link | command grep -o 'br_vmtp_.*' | cut -d'@' -f1 | "
                  "xargs -I % ip link del dev %")

    def get_mgmt_node_ip(self, net_data):
        # Get build node IP address
        for key in net_data['networks']:
            if 'management' in key['segments']:
                mgmt_net = '.'.join(key['subnet'].split('.')[0:3])
        mgmt_host_res = os.popen("ip a | grep 'inet {}'".format(mgmt_net)).read()
        mgmt_s_ip = re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
                              mgmt_host_res)
        mgmt_host_ip = mgmt_s_ip.group(0)
        return mgmt_host_ip

    def setup_networks(self):
        '''
        Create an external and/or provider network that needs to be used
        for VMTP test.
        '''
        net_data = self.ymlhelper.get_setup_data_property('VMTP_VALIDATION')
        if not net_data:
            msg = "User did not provide information for VM throughput test"
            print logger.stringc(msg, 'red')
            return {'status': 'FAIL'}
        ucsm_info = self.ymlhelper.get_setup_data_property('UCSMCOMMON')
        mech_driver = self.ymlhelper.get_mechanism_driver().lower()
        create_sriov = self.ymlhelper.create_sriov()
        pure_intel = self.ymlhelper.use_intel_nic()
        vic_nic_combo = self.ymlhelper.is_cisco_vic_intel_sriov()
        if pure_intel and mech_driver in ["openvswitch", "vpp"]:
            physnet_prov = "physnet1"
            physnet_ext = "physnet1"
        elif vic_nic_combo and create_sriov:
            physnet_prov = "physnet1"
            physnet_ext = "phys_ext"
        else:
            physnet_prov = "phys_prov"
            physnet_ext = "phys_ext"
        if ucsm_info:
            if 'ENABLE_PROV_FI_PIN' in ucsm_info:
                # If no physnet is specified default to FIA
                physnet_prov = "phys_prov_fia"
        if mech_driver in ["vts"] and not "replace_controller" in self.run_args:
            try:
                # Gathering all information from setup_data
                # Setting nets/subnets names
                net_data = self.ymlhelper.get_setup_data_property('VMTP_VALIDATION')
                net_data2 = self.ymlhelper.get_setup_data_property('NETWORKING')
                vts_data = self.ymlhelper.get_setup_data_property('VTS_PARAMETERS')
                net_name_a = 'pns-internal-net'
                subnet_name_a = net_name_a + '-subnet'
                net_name_b = 'pns-internal-net2'
                subnet_name_b = net_name_b + '-subnet'

            except KeyError as kerr:
                print
                "KeyError: %s", kerr
                return {'status': 'FAIL'}

            # Get all networks and vlans information from configs
            net_list = [net['subnet'] for net in net_data2['networks']
                        if 'subnet' in net]
            vlan_list = [net['vlan_id'] for net in net_data2['networks']
                         if 'vlan_id' in net]

            # Defining free network range from nets list
            first_octet = [int(octet.split('.')[0]) for octet in net_list]
            free_range = [val for val in range(1, 15) if val not in first_octet]

            # Allocating IP addresses for vmtp networks and
            # mediation network for dhcp backdoor
            prefix_net_a = str(free_range[2]) + '.10.10.0/28'
            prefix_net_b = str(free_range[3]) + '.11.11.0/28'
            med_net_a = str(free_range[0]) + '.2.3.4/30'
            med_net_b = str(free_range[1]) + '.2.3.4/30'
            managed = vts_data.get('MANAGED')

            # 2 bellow commented lines unblocking manged vts function
            # if managed not in [None, False]:
            #     self.managed = True

            # Cleaning build node and networks before test start
            # just to be sure nothing is left from the previous
            # test attempts
            self.cleanup_bld_node_all()
            self.cleanup_net([net_name_a, net_name_b])

            mgmt_host_ip = self.get_mgmt_node_ip(net_data2)
            self.vmtp_tag = self.get_vmtp_container_name()

            try:
                # Naming router and security group
                self.rtr = 'pns-router'
                self.osg = 'vmtp-vts-pns-sg'
                # Creating security group
                self.sg_id = self.create_sg(self.osg)
                # Creating security rules for security group
                self.create_sg_rules(self.sg_id)
                # Storing information for cleanup
                # names and prefixes network A
                self.vts_test_data.append({'net_name': net_name_a})
                self.vts_test_data[0]['subnet_name'] = subnet_name_a
                self.vts_test_data[0]['net_prefix'] = prefix_net_a
                # Creating net and subnet A
                new_net = self.create_net_sub(net_name_a,
                                              subnet_name_a, prefix_net_a,
                                              mgmt_host_ip)
                # Requesting subnet A ID
                new_subnet = self.get_subnet_id(subnet_name_a, new_net)
                # Storing information for cleanup net A ID
                self.vts_test_data[0]['net_id'] = new_net
                # Storing information for cleanup
                # names and prefixes network B
                self.vts_test_data.append({'net_name': net_name_b})
                self.vts_test_data[1]['subnet_name'] = subnet_name_b
                self.vts_test_data[1]['net_prefix'] = prefix_net_b
                # Creating net and subnet B
                new_net2 = self.create_net_sub(net_name_b,
                                               subnet_name_b, prefix_net_b,
                                               mgmt_host_ip)
                # Requesting subnet B ID
                new_subnet2 = self.get_subnet_id(subnet_name_b, new_net2)
                # Storing information for cleanup net B ID
                self.vts_test_data[1]['net_id'] = new_net2
                # Cleaning vmtp router if exist and creating new one
                self.delete_router(self.rtr)
                new_router = self.create_router(self.rtr)
                # Attaching router ports to subnets A and B
                self.add_router_port_sub(new_router, new_subnet)
                self.add_router_port_sub(new_router, new_subnet2)
                # Check the namespace in setup_data
                namespace = self.dfshelper.get_setup_data_property('namespace')

                if self.managed is True:
                    # If VTS is managed VXLAN tunnels terminated on TORS
                    print('Managed VTS')
                    # Get TORs info
                    tor_data = self.ymlhelper.get_setup_data_property('TORSWITCHINFO')
                    tor_a = tor_data['SWITCHDETAILS'][0]
                    tor_b = tor_data['SWITCHDETAILS'][1]
                    # IP addresses reservation for build node nets A and B
                    self.create_port(new_net, new_subnet,
                                     prefix_net_a, 'vmtp_bld_a')
                    self.create_port(new_net2, new_subnet2,
                                     prefix_net_b, 'vmtp_bld_b')
                    # Allocating VLANs for test
                    free_vlans = self.get_test_vlans(tor_a, tor_b, vts_data)
                    test_vlans = [x for x in free_vlans if x not in vlan_list]
                    print('Allocating free VLANs: {}'.format(test_vlans[0:2]))
                    self.log.info('Allocating free VLANs: {}'.
                                  format(test_vlans[0:2]))

                    # Storing data for cleanup vlans and TOR names
                    self.vts_test_data.append({'vts_data': vts_data})
                    self.vts_test_data[0]['vlan_tag'] = test_vlans[0]
                    self.vts_test_data[1]['vlan_tag'] = test_vlans[1]
                    self.vts_test_data[0]['tor'] = tor_a
                    self.vts_test_data[1]['tor'] = tor_b

                    # Configuring VMTP container docker bridge network mode
                    self.configure_vmtp_container(mgmt_host_ip, namespace)

                    time.sleep(20)
                    # Syncing TORs config with VTC
                    self.sync_vts(vts_data, tor_a)
                    self.sync_vts(vts_data, tor_b)
                    time.sleep(10)

                    self.vts_test_data[2]['phase'] = 1
                    # Configuring VLAN and BGP EVPN on TORs
                    self.configure_tor_ncs(vts_data, tor_a, new_net, test_vlans[0])
                    self.configure_tor_ncs(vts_data, tor_a, new_net2, test_vlans[1])
                    self.configure_tor_ncs(vts_data, tor_b, new_net, test_vlans[0])
                    self.configure_tor_ncs(vts_data, tor_b, new_net2, test_vlans[1])

                    self.vts_test_data[2]['phase'] = 2
                    # Configuring build node
                    self.configure_bld_node_net(prefix_net_a, test_vlans[0])
                    self.configure_bld_node_net(prefix_net_b, test_vlans[1])

                elif self.managed is False:
                    # If VTS is managed DHCP backdoor is used
                    print('Unmanaged VTS')
                    # Configuring VMTP container docker host network mode
                    self.configure_vmtp_container(mgmt_host_ip, namespace)
                    # Obtaining DHCP backdoor node for network A
                    dhcp_node_ip_a = self.set_node_ip_and_local_route(prefix_net_a,
                                                                  new_subnet)
                    # Storing cleanup information for net A
                    self.vts_test_data[0]['dhcp_node_ip'] = dhcp_node_ip_a
                    print ('DHCP node IP for subnet {} is {} '.
                           format(prefix_net_a, dhcp_node_ip_a))
                    # Configuring DHCP node namespace for network A
                    self.configure_dhcp_ns(new_net, med_net_a, prefix_net_a,
                                           dhcp_node_ip_a, mgmt_host_ip)
                    # Obtaining DHCP backdoor node for network A
                    dhcp_node_ip_b = self.set_node_ip_and_local_route(prefix_net_b,
                                                                  new_subnet2)
                    # Storing cleanup information for net B
                    self.vts_test_data[1]['dhcp_node_ip'] = dhcp_node_ip_b
                    print ('DHCP node IP for subnet {} is {} '.
                           format(prefix_net_b, dhcp_node_ip_b))
                    # Configuring DHCP node namespace for network A
                    self.configure_dhcp_ns(new_net2, med_net_b, prefix_net_b,
                                           dhcp_node_ip_b, mgmt_host_ip)


            except KeyboardInterrupt:
                print "VMTP killed by the user"
                self.cleanup_vts_all()
                # sys.exit(0)
                return {'status': 'FAIL'}

            except Exception as e:
                print e
                self.cleanup_vts_all()
                # sys.exit(0)
                return {'status': 'FAIL'}

            return {'status': 'PASS'}

        else:
            if 'EXT_NET' in net_data:
                try:
                    ext_net_name = net_data['EXT_NET']['NET_NAME']
                    ext_subnet = net_data['EXT_NET']['NET_SUBNET']
                    ext_ip_start = net_data['EXT_NET']['NET_IP_START']
                    ext_ip_end = net_data['EXT_NET']['NET_IP_END']
                    ext_gateway = net_data['EXT_NET']['NET_GATEWAY']
                    dns_servers = []
                    dns_servers.append(net_data['EXT_NET']['DNS_SERVER'])
                except KeyError as kerr:
                    print "KeyError: %s", kerr
                    return {'status': 'FAIL'}
                neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                             self.os_api_version,
                                                             self.cacert)
                net_exists = \
                    neutron_handle.neutron_get_networks(external=True,
                                                        network_name=ext_net_name)
                if len(net_exists) == 0:
                    # We will create a new network based on parameters
                    # provided in setup data.
                    if self.ymlhelper.use_intel_nic() \
                            and mech_driver in ["openvswitch", "vpp"]:
                        segmentation_id = net_data['EXT_NET'].get('SEGMENTATION_ID')
                        if segmentation_id is None:
                            # derive from setup data
                            segmentation_id = \
                                self.ymlhelper.nw_get_specific_vnic_info(
                                    "external", "vlan_id")
                        network = {
                            'network': {
                                'name': ext_net_name,
                                'admin_state_up': True,
                                'shared': True,
                                'router:external': True,
                                'provider:network_type': 'vlan',
                                'provider:segmentation_id': segmentation_id,
                                'provider:physical_network': physnet_ext

                            }
                        }
                    elif mech_driver == 'aci':
                        aci_dn_net_name = "uni/tn-common/out-%s/" \
                                          "instP-%s" % (ext_net_name, ext_net_name)
                        network = {
                            'network': {
                                'name': ext_net_name,
                                'admin_state_up': True,
                                'shared': True,
                                'router:external': True,
                                'apic:distinguished_names': {
                                    "ExternalNetwork": aci_dn_net_name
                                }
                            }
                        }
                    else:
                        network = {
                            'network': {
                                'name': ext_net_name,
                                'admin_state_up': True,
                                'shared': True,
                                'router:external': True,
                                'provider:network_type': 'flat',
                                'provider:physical_network': physnet_ext
                            }
                        }
                    subnet = {
                        'subnet': {
                            'name': 'subnet-ext',
                            'enable_dhcp': False,
                            'cidr': ext_subnet,
                            'allocation_pools': [{'start': ext_ip_start,
                                                  'end': ext_ip_end}],
                            'dns_nameservers': dns_servers,
                            'gateway_ip': ext_gateway,
                            'ip_version': 4
                        }
                    }
                    new_net = neutron_handle.neutron_create_network(
                        net_dict=network,
                        subnet_dict=subnet)
                    if new_net is None:
                        print "Failed to create external network",
                        return {'status': 'FAIL'}
            if 'PROV_NET' in net_data:
                try:
                    prov_net_name = net_data['PROV_NET']['NET_NAME']
                    prov_subnet = net_data['PROV_NET']['NET_SUBNET']
                    prov_ip_start = net_data['PROV_NET']['NET_IP_START']
                    prov_ip_end = net_data['PROV_NET']['NET_IP_END']
                    prov_gateway = net_data['PROV_NET']['NET_GATEWAY']
                    segmentation_id = net_data['PROV_NET']['SEGMENTATION_ID']
                    dns_servers = []
                    dns_servers.append(net_data['PROV_NET']['DNS_SERVER'])
                    if net_data['PROV_NET'].get('PHYSNET_NAME', None):
                        physnet_prov = net_data['PROV_NET'].get('PHYSNET_NAME',
                                                                None)

                except KeyError as kerr:
                    print "KeyError: %s", kerr
                    return {'status': 'FAIL'}
                neutron_handle = neutronclient.NeutronManage(self.os_creds,
                                                             self.os_api_version,
                                                             self.cacert)
                net_exists = \
                    neutron_handle.neutron_get_networks(external=False,
                                                        network_name=prov_net_name)
                if len(net_exists) == 0:
                    # We will create a new network based on parameters
                    # provided in setup data.
                    network = {
                        'network': {
                            'name': prov_net_name,
                            'admin_state_up': True,
                            'shared': True,
                            'provider:network_type': 'vlan',
                            'provider:segmentation_id': segmentation_id,
                            'provider:physical_network': physnet_prov
                        }
                    }
                    subnet = {
                        'subnet': {
                            'name': 'subnet-prov',
                            'enable_dhcp': True,
                            'cidr': prov_subnet,
                            'allocation_pools': [{'start': prov_ip_start,
                                                  'end': prov_ip_end}],
                            'dns_nameservers': dns_servers,
                            'gateway_ip': prov_gateway,
                            'ip_version': 4
                        }
                    }
                    ipv6_mode = net_data['PROV_NET'].get('IPV6_MODE', None)
                    if ipv6_mode:
                        subnet['subnet']['ip_version'] = 6
                        if ipv6_mode == 'dhcpv6-stateful':
                            subnet['subnet']['ipv6_ra_mode'] = ipv6_mode
                        subnet['subnet']['ipv6_address_mode'] = ipv6_mode

                    vnic_type = net_data['PROV_NET'].get('VNIC_TYPE', None)
                    # This is needed for ipv4 networks since vmtp relies on
                    # this flag to inject network guest customization files
                    if not ipv6_mode and \
                            (vnic_type and vnic_type.lower() == 'direct'):
                        subnet['subnet'].update({'enable_dhcp': False})

                    new_net = neutron_handle.neutron_create_network(
                        net_dict=network,
                        subnet_dict=subnet)
                    if new_net is None:
                        print "Failed to create provider network",
                        return {'status': 'FAIL'}

            return {'status': 'PASS'}

    def get_vmtp_container_name(self):
        '''
        Determine the container name for VMTP based on docker.yaml
        '''
        with open(self.cfg_dir + "/docker.yaml", 'r') as stream:
            data = stream.read()
            images = yaml.safe_load(data)
        return "vmtp_" + str(images["docker"]["vmtp"]["image_tag"])

    def run_vmtp_cmd(self, vmtp_exec, provider=False, jsonop=False):
        '''
        Run VMTP
        '''

        vmtp_output_json = None
        if provider:
            vmtp_output_json = "/tmp/p_vmtp.json"  # nosec
        else:
            vmtp_output_json = "/tmp/e_vmtp.json"  # nosec

        if jsonop:
            vmtp_exec = vmtp_exec + " --json " + vmtp_output_json
        vmtp_container_name = self.get_vmtp_container_name()
        vmtp_cmd = ["docker", "exec", vmtp_container_name, "bin/bash", "-c",
                    vmtp_exec]
        sproc = subprocess.Popen(vmtp_cmd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)

        while True:
            try:
                nextline = sproc.stdout.readline()
                if nextline == '' and sproc.poll() is not None:
                    break
                sys.stdout.write(nextline)
                sys.stdout.flush()
            except KeyboardInterrupt:
                print "VMTP killed by the user"
            except vmtpAlarm:
                print "VMTP run timed out, check vmtp logs for additional info"
                sproc.terminate()

        if sproc.returncode != 0:
            print "VMTP exited with error above"
            return {'status': 'FAIL'}

        if jsonop:
            print "Starting docker json"
            data = {}
            try:
                remote_file = vmtp_container_name + ":" + vmtp_output_json
                tmp_dir = tempfile.mkdtemp()
                filename = 'vmtp.json'
                local_file = os.path.join(tmp_dir, filename)
                docker_cp = ['docker', 'cp', remote_file, local_file]
                retcode = subprocess.call(docker_cp)
                if not retcode and os.path.isfile(local_file):
                    with open(local_file) as data_file:
                        data = json.load(data_file)  # nosec
                    os.remove(local_file)
                os.rmdir(tmp_dir)
                return data
            except:
                return {}
        else:
            return {}

    def configure_container(self):
        '''
        Upload any needed configuration data to container
        '''

        vmtp_container_name = self.get_vmtp_container_name()

        # Upload CA certificate file
        if self.cacert:
            try:
                remote_file = vmtp_container_name + ":/haproxy-ca.crt"
                docker_cp = ["docker", "cp", self.cacert,
                             remote_file]
                subprocess.Popen(docker_cp)
            except:
                return {'status': 'FAIL'}

        return {'status': 'PASS'}

    def get_cloud_image(self):
        """ Method to return the rhel guest image name and location
        :return: name of the image
        """
        qcow_image_location = "/usr/share/rhel-guest-image-7"
        vmtp_container_name = self.get_vmtp_container_name()
        cmd = ["docker", "exec", vmtp_container_name, "bash", "-c",
               "ls " + qcow_image_location + "/*.qcow2"]

        sproc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        rhel_image = sproc.stdout.readline().rstrip('\n')

        if rhel_image:
            return "file://" + rhel_image
        else:
            return None

    def generate_vmtp_config_file(self, net_type):
        """ Method to generate the vmtp config file
        """
        yaml_file = "/tmp/mercury_vmtp_cfg_%s.yaml" % net_type  # nosec
        vmtp_cfg = {}
        vmtp_cfg['image_name'] = "RHEL-guest-image"
        vmtp_cfg['ssh_vm_username'] = "cloud-user"
        vmtp_cfg['availability_zone'] = "nova"
        # depending on the system speed, nova create can take more than 100
        # seconds (50 retries x 2 seconds) to transition from BUILD to ACTIVE
        # increase the default generic_retry_count from 50 to 100 to handle
        # the increased guest image size from ~250MB to ~450MB
        vmtp_cfg['generic_retry_count'] = 100
        # this is a temp fix until vmtp supports injecting cloud-init script
        # related bug https://access.redhat.com/solutions/2132881
        vmtp_cfg['ssh_retry_count'] = 100
        vmtp_cfg['user_data_file'] = "/tmp/vmtp_cloud_init"  # nosec
        net_data = self.ymlhelper.get_setup_data_property('VMTP_VALIDATION')
        vmtp_cfg['dns_nameservers'] = set()

        mech_driver = self.ymlhelper.get_setup_data_property('MECHANISM_DRIVERS')
        if mech_driver == 'vts':
            vmtp_cfg['router_name'] = self.rtr
            vmtp_cfg['security_group_name'] = self.osg
            vmtp_cfg['internal_network_name'] = [self.vts_test_data[0]['net_name'],
                                                 self.vts_test_data[1]['net_name']]
            vmtp_cfg['internal_subnet_name'] = [self.vts_test_data[0]['subnet_name'],
                                                self.vts_test_data[1]['subnet_name']]
            vmtp_cfg['internal_cidr'] = [self.vts_test_data[0]['net_prefix'],
                                         self.vts_test_data[1]['net_prefix']]
        else:
            if net_type == 'EXT_NET' and 'EXT_NET' in net_data:
                vmtp_cfg['dns_nameservers'].add(net_data['EXT_NET']['DNS_SERVER'])
                vmtp_cfg['ext_net_name'] = net_data['EXT_NET']['NET_NAME']
            if net_type == 'PROV_NET' and 'PROV_NET' in net_data:
                vmtp_cfg['dns_nameservers'].add(net_data['PROV_NET']['DNS_SERVER'])
                vmtp_cfg['ipv6_mode'] = net_data['PROV_NET'].get('IPV6_MODE', None)

        vmtp_cfg['dns_nameservers'] = list(vmtp_cfg.get('dns_nameservers'))

        if mech_driver in ['vpp', 'vts']:
            vmtp_cfg['flavor'] = {
                'extra_specs': {
                    'hw:cpu_policy': 'dedicated',
                    'hw:mem_page_size': 'large'
                }
            }

        # Enable below to allow VMTP to send results to fluentd
        # vmtp_cfg['fluentd'] = {
        #     'logging_tag': 'vmtp',
        #     'ip': '127.0.0.1',
        #     'port': 7081
        # }

        with open(yaml_file, "w+") as f:
            f.write(yaml.dump(vmtp_cfg, default_flow_style=False))

        vmtp_container_name = self.get_vmtp_container_name()
        try:
            remote_file = vmtp_container_name + ":" + yaml_file
            docker_cp = ["docker", "cp", yaml_file,
                         remote_file]
            subprocess.Popen(docker_cp)
        except:
            return False

        return True

    def start_throughput_test(self, jsonop=False):
        '''
        Initiate the VMTP throughput test
        '''

        net_data = self.ymlhelper.get_setup_data_property('VMTP_VALIDATION')
        stop_on_error = self.ymlhelper.vmtp_stop_on_error()
        jsondata = {}
        mech_driver = self.ymlhelper.get_mechanism_driver().lower()

        cloud_image = self.get_cloud_image()
        if cloud_image is None:
            print "No valid rhel guest image found for VMTP."
            return {'status': 'FAIL'}

        if self.os_api_version == 2:
            vmtp_env = "export OS_USERNAME=" + self.os_creds['username'] + \
                       ";export OS_PASSWORD=" + self.os_creds['password'] + \
                       ";export OS_TENANT_NAME=" + self.os_creds['tenant_name'] + \
                       ";export OS_AUTH_URL=" + self.os_creds['auth_url'] + \
                       ";export OS_REGION_NAME=" + self.region_name + \
                       ";export OS_CACERT=/haproxy-ca.crt;"
        elif self.os_api_version == 3:
            vmtp_env = "export OS_USERNAME=" + self.os_creds['username'] + \
                       ";export OS_PASSWORD=" + self.os_creds['password'] + \
                       ";export OS_PROJECT_NAME=" + self.os_creds['project_name'] + \
                       ";export OS_PROJECT_DOMAIN_NAME=" + \
                       self.os_creds['project_domain_name'] + \
                       ";export OS_USER_DOMAIN_NAME=" + \
                       self.os_creds['user_domain_name'] + \
                       ";export OS_AUTH_URL=" + self.os_creds['auth_url'] + \
                       ";export OS_IDENTITY_API_VERSION=3" + \
                       ";export OS_CACERT=/haproxy-ca.crt;"

        vmtp_keygen = \
            "echo -e 'y\n'|ssh-keygen -b 2048 " \
            "-t rsa -f ~/.ssh/id_rsa -q -N '';"

        vmtp_cmd_base = "vmtp " \
                   "--tp-tool iperf " \
                   "--inter-node-only " \
                   "--protocols TI " \
                   "--log-file /var/log/vmtp/vmtp.log " \
                   "--vm-image-url " \
                   + cloud_image

        if stop_on_error:
            vmtp_cmd_base += " --stop-on-error"

        if "add_computes" in self.run_args:
            for host in self.run_args["add_computes"][:2]:
                vmtp_cmd_base += " --hypervisor nova:%s" % host
        elif "replace_controller" in self.run_args:
            nova_handle = novaclient.NovaManage(self.os_creds,
                                                self.os_api_version,
                                                self.cacert)
            host = self.run_args["replace_controller"][0]
            roles = self.ymlhelper.get_server_cimc_role(host, allroles=True)
            if 'compute' in roles:
                vmtp_cmd_base += " --hypervisor nova:%s" % host
            else:
                print "Skipping VMTP for replace_controller on fullon deployment."
                return {'status': 'PASS'}


        if mech_driver in ["vts"]:
            if not self.generate_vmtp_config_file(net_type='VTS'):
                print "Generating vmtp config file failed"
                return {'status': 'FAIL'}
            vmtp_cmd = vmtp_cmd_base + " --config /tmp/mercury_vmtp_cfg_VTS.yaml "
            vmtp_cmd += " --no-floatingip"
            vmtp_exec = vmtp_env + vmtp_keygen + vmtp_cmd
            jsondata['VTS'] = self.run_vmtp_cmd(vmtp_exec, provider=False,
                                                jsonop=True)
            self.cleanup_vts_all()

        if ('PROV_NET' in net_data and mech_driver is not ["vts"]):
            if not self.generate_vmtp_config_file(net_type='PROV_NET'):
                print "Generating vmtp config file failed"
                return {'status': 'FAIL'}
            vmtp_cmd = vmtp_cmd_base + " --config /tmp/mercury_vmtp_cfg_PROV_NET.yaml "
            vmtp_cmd += " --reuse_network_name " + net_data['PROV_NET']['NET_NAME']

            vnic_type = net_data['PROV_NET'].get('VNIC_TYPE', None)
            ipv6_mode = net_data['PROV_NET'].get('IPV6_MODE', None)
            if vnic_type:
                vmtp_cmd += " --vnic-type " + net_data['PROV_NET']['VNIC_TYPE']
            # Note: the --no-dhcp flag needs to be set only for IPv4
            # networks since vmtp depends on this flag to determine
            # if network interface files need to be generated for
            # network guest customization.  Not needed for IPv6 if
            # RAs are properly sent by router
            if not ipv6_mode and \
                    (vnic_type and vnic_type.lower() == 'direct'):
                vmtp_cmd += ' --no-dhcp'

            # Ensure support for ipv6-only networks
            if (vnic_type and vnic_type.lower() == 'direct') or ipv6_mode:
                vmtp_cmd += " --use-config-drive"

            vmtp_exec = vmtp_env + vmtp_keygen + vmtp_cmd
            jsondata['PROV_NET'] = self.run_vmtp_cmd(vmtp_exec, provider=True,
                                                     jsonop=True)

        if 'EXT_NET' in net_data:
            if not self.generate_vmtp_config_file(net_type='EXT_NET'):
                print "Generating vmtp config file failed"
                return {'status': 'FAIL'}
            vmtp_cmd = vmtp_cmd_base + " --config /tmp/mercury_vmtp_cfg_EXT_NET.yaml "
            if net_data['EXT_NET'].get('VNIC_TYPE', None):
                vmtp_cmd = vmtp_cmd_base + " --vnic-type " + net_data['EXT_NET']['VNIC_TYPE']

            vmtp_exec = vmtp_env + vmtp_keygen + vmtp_cmd
            jsondata['EXT_NET'] = self.run_vmtp_cmd(vmtp_exec, provider=False,
                                                    jsonop=True)

        status = "PASS"
        for key in jsondata:
            # VTS, EXT_NET, PROV_NET
            flows = jsondata[key].get('flows', [])
            if len(flows) == 0:
                status = "FAIL"
            else:
                for flow in flows[0].get('results', []):
                    if 'error' in flow:
                        status = "FAIL"
                        break
        jsondata['status'] = status

        return jsondata if jsonop else {'status': jsondata.get("status", "FAIL")}


def run(run_args={}, jsonop=True):
    '''
    Cloud Validations Runner.
    '''

    homedir = common.get_homedir()
    cfg_dir = os.path.join(homedir, DEFAULT_CFG_DIR)
    setupfile = os.path.join(cfg_dir, DEFAULT_SETUP_FILE)
    ymlhelper = config_parser.YamlHelper(user_input_file=setupfile)
    pure_intel = ymlhelper.use_intel_nic()
    vic_nic_combo = ymlhelper.is_cisco_vic_intel_sriov()
    create_sriov = ymlhelper.create_sriov()
    mech_driver = ymlhelper.get_mechanism_driver().lower()
    same_physnet = ymlhelper.parsed_defaults_config.get('USE_SAME_PHYSNET')
    vmtp_data = ymlhelper.parsed_config.get('VMTP_VALIDATION')
    run_provider = False
    run_external = False
    ext_sriov = None
    prov_sriov = None

    if vmtp_data:
        if mech_driver != 'vts':
            run_external = True if vmtp_data.get('EXT_NET', None) else False
            run_provider = True if vmtp_data.get('PROV_NET', None) else False
            if run_external:
                ext_sriov = vmtp_data['EXT_NET'].get('VNIC_TYPE')
            if run_provider:
                prov_sriov = vmtp_data['PROV_NET'].get('VNIC_TYPE')
        else:
            pass

    result = {}
    result['status'] = 'PASS'
    vmtp = VMTP(threaded=jsonop)
    vmtp_json_file = '/root/openstack-configs/.vmtp.json'
    if os.path.isfile(vmtp_json_file):
        os.remove(vmtp_json_file)
    if vmtp.check_vmtp_section_exists():
        if (pure_intel and same_physnet) or \
                (vic_nic_combo and run_provider and not run_external):
            result['status'] = "RunnerSkipped"
        elif vic_nic_combo and run_provider and run_external:
            # pradeech: need to restrict running provider vmtp
            pass
        else:
            vmtp.run_args = run_args
            result = vmtp.set_auth_parameters()
            if result['status'] != 'PASS':
                return result

            result = vmtp.setup_networks()
            if result['status'] != 'PASS':
                return result

            result = vmtp.configure_container()
            if result['status'] != 'PASS':
                return result

            result = vmtp.start_throughput_test(jsonop=jsonop)
    else:
        result['status'] = "RunnerSkipped"

    if os.path.isdir('/root/openstack-configs'):
        install_dir = os.readlink('/root/openstack-configs')
        with open(install_dir + '/.vmtp.json', 'w') as f:
            json.dump(result, f)

    return result


def check_status():
    '''
    Check the status of operation
    '''
    return (1, "INIT")
