#/*
# *------------------------------------------------------------------
# * vpfa_reg.py
# *
# * register VPFA with VTC
# *
# * June 2017, Parag Jain
# *
# * Copyright (c) 2017 by cisco Systems, Inc.
# * All rights reserved.
# *------------------------------------------------------------------
# */

import collections
import time
import subprocess
import ConfigParser
from vsocrc.vpfa.vpfa_log import vpfa_log_info, vpfa_log_debug, \
    vpfa_log_med, vpfa_log_err, vpfa_log_init
from twisted.web.client import HTTPConnectionPool
from twisted.web.http_headers import Headers
from StringIO import StringIO

from twisted.web.client import Agent
from twisted.internet.ssl import ClientContextFactory
from base64 import b64encode
from twisted.web.client import FileBodyProducer

from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol, connectionDone
import treq
from twisted.internet import reactor
# ujson doesn't seem to work with VTC registration
import json
import datetime
from twisted.web.http import UNAUTHORIZED
#import vpfa_intf
#import vpfa_tbls
import vpfa_common
import re

# Stores HTTP Authentication Results for both username and password
VTSAuthValidation = collections.namedtuple("VTSAuthValidation",
                                           "username_valid, password_valid")

# Day 0 config file name
__DAY0_FILE__ = "/etc/vpe/vpfa/vpfa.ini"
# Day 0 debug string
__DAY0_STR__ = "DAY0: "
# Day 0 config, VTS section
__DAY0_SECTION_VTS__ = "VTS"
__DAY0_VTS_URL_FIELD__ = "VTS_REGISTRATION_API"
__DAY0_VTS_USER_FIELD__ = "VTS_USERNAME"
__DAY0_VTS_PWD_FIELD__ = "VTS_PASSWORD"
__DAY0_VTS_IP_FIELD__ = "VTS_ADDRESS"
# Day 0 config, NETWORK section
__DAY0_SECTION_NW__ = "NETWORK"
__DAY0_NW_METHOD__ = "NETWORK_CONFIG_METHOD"
__DAY0_NW_IPADDR__ = "NETWORK_IP_ADDRESS"
__DAY0_NW_IPMASK__ = "NETWORK_IP_NETMASK"
__DAY0_NW_IPGW__ = "NETWORK_IP_GATEWAY"
__DAY0_HOSTNAME__ = "HOSTNAME"
__DAY0_UNDERLAY_IP_NET_LIST__ = "UNDERLAY_IP_NET_LIST"
__DAY0_UNDERLAY_IF_NAME__ = "UNDERLAY_IF_NAME"
# Day 0 config, OTHER section
__DAY0_SECTION_OTHER__ = "OTHER"
__DAY0_CH_HOSTNAME__ = "COMPUTE_HOST_NAME"
__DAY0_USERNAME__ = "USERNAME"
__DAY0_PWD_HASH__ = "PASSWORD_HASH"
__DAY0_TLS_VERSION__ = "TLS_VERSION"
__DAY0_VIF_TYPE__ = "VIF_TYPE"
__DAY0_LOCKOUT_COUNT__ = "LOCKOUT_COUNT"
__DAY0_LOCKOUT_SECONDS__ = "LOCKOUT_SECONDS"
__DAY0_LOCKOUT_WINDOW_SECONDS__ = "LOCKOUT_WINDOW_SECONDS"

DEFAULT_LOCKOUT_COUNT = 4
DEFAULT_LOCKOUT_SECONDS = 1200
DEFAULT_LOCKOUT_WINDOW_SECONDS = 60

NCS_DATA_VTF = "vtf"
IP = "ip"
LOCALMAC = "local-mac"
USER = "username"
GW = "gateway-ip"
HOSTNAME = "binding-host-name"
VPP = "vpp-client-name"
VPP_MODE = "mode"

NCS_DATA = {
    NCS_DATA_VTF:
    {
        IP: "",
        LOCALMAC : "",
        USER : "",
        GW : "",
        HOSTNAME: "",
        VPP : "",
        VPP_MODE : "",
    }
}

class ReadHtmlBody(Protocol):
    def __init__(self, finished, length, log):
        self.log = log
        if length < 0:
            self.log("VTF-REG: ","Invalid message body length: %d", length)
            length = 0
        self.finished = finished
        self.length = min([length, 500])
        self.data_received = ""
        self.display_done = False

    def dataReceived(self, data):
        self.data_received += data
        #IF it is already logged or if it has empty body return
        if self.display_done or self.length == 0:
            self.log("VTF-REG: ","Html Body returned.Length 0 or already logged !!!")
            return
        if len(self.data_received) >= self.length:
            self.log("VTF-REG: ","Html Body Information: %s!!!", self.data_received[:self.length])
            self.display_done = True

    def connectionLost(self, reason=connectionDone):
        self.log("VTF_REG: ","Finished receiving Html body: %s", reason.getErrorMessage())
        self.finished.callback(None)

class WebClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)

class GlbNetworking(object):
    ''' Handles networking for VTF by configuring underlay interface '''

    def __init__(self, glb):
        ''' Constructor '''
        self.underlay_if_created = False
        self.glb = glb

    def get_underlay_mac(self):
        '''Get the  underlay (eth0) MAC '''

        # MACs are supposed to be in file below
        mac_file = open("/etc/vpe/vpfa/underlay_mac", "r")
        if mac_file == None:
            vpfa_log_err("GLB: ", "no MAC file")
            return
        # Read all the lines in the file
        lines = mac_file.readlines()
        mac_file.close()

        if lines == None:
            vpfa_log_err("GLB: ", "MAC file is empty")
            return
        # Go over each MAC
        for line in lines:
            # Get rid of CR/LF
            mac = line.rstrip("\r\n")
            vpfa_log_debug("GLB: ", "Underlay MAC[%s]", mac)
            # For now we only handle 1 MAC (the underlay MAC)
            self.glb.set_underlay_mac(mac)

    def phys_if_notif(self, mac_str, sw_if_index, intf_name):
        ''' We are notified of "physical" intf create in VPP'''
        if mac_str == vpfa_common.MAC_ALL_ZEROS:
            return
        if mac_str != self.glb.underlay_mac:
            # The MAC is not the underlay MAC, got to be trunk
            if vpfa_intf.trunkInterfaceMAC == None:
                vpfa_intf.trunkInterfaceMAC = mac_str
            return

        # Depending on day0 parameter(UNDERLAY_IF_NAME), the inteface type
        # can be determined. If 'bond' is part of underlay interface name,
        # it is a bonded interface. ex) UNDERLAY_IF_NAME=bond-active-backup
        # When VPP notifies inteface info via callback, it will include 'Bond'
        # if it is a bonded interface. ex) BondEthernet0
        if 'bond' in self.glb.underlay_intf_name and 'Bond' not in intf_name:
            # If there's no 'Bond' string, then it's not a bonded interface.
            return

        if not self.underlay_if_created:
            if mac_str == self.glb.underlay_mac:
                vpfa_log_med("GLB-UPD:", "Creating underlay MAC[%s], DHCP=%s!",
                             mac_str, str(self.glb.use_dhcp))

                # This creates the underlay i/f in VPFA and maps it to
                # the GigabitEthernetX/Y/Z in VPP
                self.glb.root.if_tbl.create(
                    vpfa_common.INTF_NAME_UNDERLAY,
                    mac=mac_str, dhcp=self.glb.use_dhcp)

                self.underlay_if_created = True

                # If static configure the IP address
                # Default route etc will be added via interface callback
                # which ends up calling update_default_route()
                if not self.glb.use_dhcp:
                    # Static networking
                    if self.glb.underlay_ip_addr != None and \
                           self.glb.underlay_ip_mask != None:
                        vpfa_log_med("GLB-UPD: ", "Setting underlay IP to %s",
                                     self.glb.underlay_ip_addr + "/" +
                                     self.glb.underlay_ip_mask)
                        self.glb.root.if_tbl.set_prefix(
                            vpfa_common.INTF_NAME_UNDERLAY,
                            self.glb.underlay_ip_addr + "/" +
                            self.glb.underlay_ip_mask)
                    else:
                        vpfa_log_err("GLB-UPD: ",
                                     "Missing static networking info")

        # We only flush the update queue from main thread now

class VpfaGlb:
    def __init__(self, root):
        self.root = root
        self.hostname = None
        self.gw_addr = None
        self.dhcp_addr = None
        self.underlay_ip_addr = None
        self.underlay_ip_mask = None
        self.underlay_mac = None
        self.oui_mac = 0
        # By default DHCP is on
        self.use_dhcp = False
        self.networking = GlbNetworking(self)

        self.compute_host_name = None
        self.username = None
        self.password_hash = None
        self.tls_version = None

        self.ncs_reg_url = None
        self.ncs_username = None
        self.ncs_password = None
        self.ncs_data = NCS_DATA
        self.ncs_ip = None
        self.vif_type = None
        self.underlay_ip_net_list = None
        self.underlay_intf_name = 'None'

        self.auth_fail_info = {
            "last_fail_time" : None,
            "locked_out": False,
            "num_fail" : 0
        }

        self.pool = HTTPConnectionPool(reactor, persistent=False)
        self.pool.maxPersistentPerHost = 1

        self.__read_day0_config__()

    def __read_day0_config__(self):
        Config = ConfigParser.ConfigParser()
        files = Config.read(__DAY0_FILE__)
        if (len(files) == 0):
            vpfa_log_err(__DAY0_STR__, "File '%s' not found", __DAY0_FILE__)
            return

        # Registration API
        try:
            self.ncs_reg_url = Config.get(__DAY0_SECTION_VTS__,
                                          __DAY0_VTS_URL_FIELD__)
            vpfa_log_med(__DAY0_STR__, "VTS reg url %s",
                         self.ncs_reg_url)
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s", __DAY0_VTS_URL_FIELD__)

        # Registration username
        try:
            self.ncs_username = Config.get(__DAY0_SECTION_VTS__,
                                          __DAY0_VTS_USER_FIELD__)
            vpfa_log_med(__DAY0_STR__, "Got username")
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s", __DAY0_VTS_USER_FIELD__)

        # Registration password
        try:
            self.ncs_password = Config.get(__DAY0_SECTION_VTS__,
                                          __DAY0_VTS_PWD_FIELD__)
            vpfa_log_med(__DAY0_STR__, "Got password")
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s", __DAY0_VTS_PWD_FIELD__)

        # Registration IP address
        try:
            self.ncs_ip = Config.get(__DAY0_SECTION_VTS__,
                                          __DAY0_VTS_IP_FIELD__)
            vpfa_log_med(__DAY0_STR__, "Got vts ip")
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s", __DAY0_VTS_IP_FIELD__)

        # And now the networking side
        # Start with networking method (dhcp v/s static)
        try:
            nw_method = Config.get(__DAY0_SECTION_NW__,
                                   __DAY0_NW_METHOD__)
            vpfa_log_med(__DAY0_STR__, "NW method is '%s'", nw_method)
            if nw_method == "dhcp":
                self.use_dhcp = True
            elif nw_method == "static":
                self.use_dhcp = False
            else:
                vpfa_log_err(__DAY0_STR__, "unsupported n/w method %s",
                             nw_method)
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s", __DAY0_NW_METHOD__)

        # Get static network info only if we're set to static
        if self.use_dhcp == False:
            # Static IP addr
            try:
                self.underlay_ip_addr = Config.get(__DAY0_SECTION_NW__,
                                                   __DAY0_NW_IPADDR__)
                vpfa_log_med(__DAY0_STR__, "IP addr is '%s'",
                             self.underlay_ip_addr)

            except:
                vpfa_log_err(__DAY0_STR__, "No field %s", __DAY0_NW_IPADDR__)

            # Netmask
            try:
                self.underlay_ip_mask = Config.get(__DAY0_SECTION_NW__,
                                                   __DAY0_NW_IPMASK__)
                vpfa_log_med(__DAY0_STR__, "IP mask is '%s'",
                             self.underlay_ip_mask)

            except:
                vpfa_log_err(__DAY0_STR__, "No field %s", __DAY0_NW_IPMASK__)

            # GW
            try:
                self.gw_addr = Config.get(__DAY0_SECTION_NW__,
                                          __DAY0_NW_IPGW__)
                vpfa_log_med(__DAY0_STR__, "IP gw is '%s'",
                             self.gw_addr)

            except:
                vpfa_log_err(__DAY0_STR__, "No field %s", __DAY0_NW_IPGW__)

        # Hostname (optional)
        try:
            self.hostname = Config.get(__DAY0_SECTION_NW__,
                                       __DAY0_HOSTNAME__)
            vpfa_log_med(__DAY0_STR__, "Got hostname '%s'", self.hostname)
        except:
            vpfa_log_med(__DAY0_STR__, "No field %s", __DAY0_HOSTNAME__)

        # Compute hostname
        try:
            self.compute_hostname = Config.get(__DAY0_SECTION_OTHER__,
                                               __DAY0_CH_HOSTNAME__)
            vpfa_log_med(__DAY0_STR__, "Got compute hostname '%s'",
                         self.compute_hostname)
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s", __DAY0_CH_HOSTNAME__)

        # Username
        try:
            self.username = Config.get(__DAY0_SECTION_OTHER__,
                                      __DAY0_USERNAME__)
            vpfa_log_med(__DAY0_STR__, "Got username '%s'",
                         self.username)
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s", __DAY0_USERNAME__)

        # Password hash
        try:
            self.password_hash = Config.get(__DAY0_SECTION_OTHER__,
                                            __DAY0_PWD_HASH__)
            vpfa_log_med(__DAY0_STR__, "Got password hash '%s'",
                         self.password_hash)
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s", __DAY0_PWD_HASH__)

        # TLS Version
        try:
            self.tls_version = Config.get(__DAY0_SECTION_OTHER__,
                                          __DAY0_TLS_VERSION__)
            vpfa_log_med(__DAY0_STR__, "Got TLS Version '%s'",
                         self.tls_version)
            if self.tls_version not in ['1.0', '1.1', '1.2']:
                vpfa_log_err(__DAY0_STR__, "Invalid TLS Version. Defaulting to 1.2")
                self.tls_version = '1.2'
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s. Defaulting to 1.2", __DAY0_TLS_VERSION__)
            self.tls_version = '1.2'

        # VIF Type
        try:
            self.vif_type = Config.get(__DAY0_SECTION_OTHER__,
                                       __DAY0_VIF_TYPE__)
            vpfa_log_med(__DAY0_STR__, "Got vif_type '%s'",
                         self.vif_type)
        except:
            vpfa_log_med(__DAY0_STR__,
                         "No field %s. Defaulting to normal VM mode",
                         __DAY0_VIF_TYPE__)
        # Lockout Count
        try:
            self.lockout_count = int(Config.get(__DAY0_SECTION_OTHER__,
                                                __DAY0_LOCKOUT_COUNT__))
            vpfa_log_med(__DAY0_STR__, "Got Lockout Count '%d'",
                         self.lockout_count)
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s. Defaulting to %d", __DAY0_LOCKOUT_COUNT__, DEFAULT_LOCKOUT_COUNT)
            self.lockout_count = DEFAULT_LOCKOUT_COUNT

        # Lockout Time Window
        try:
            self.lockout_window_seconds = int(Config.get(__DAY0_SECTION_OTHER__,
                                                  __DAY0_LOCKOUT_WINDOW_SECONDS__))
            vpfa_log_med(__DAY0_STR__, "Got Lockout Window Seconds '%d'",
                         self.lockout_window_seconds)
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s. Defaulting to %d", __DAY0_LOCKOUT_WINDOW_SECONDS__, DEFAULT_LOCKOUT_WINDOW_SECONDS)
            self.lockout_window_seconds = DEFAULT_LOCKOUT_WINDOW_SECONDS

        # Lockout Time
        try:
            self.lockout_seconds = int(Config.get(__DAY0_SECTION_OTHER__,
                                                  __DAY0_LOCKOUT_SECONDS__))
            vpfa_log_med(__DAY0_STR__, "Got Lockout Seconds '%d'",
                         self.lockout_seconds)
        except:
            vpfa_log_err(__DAY0_STR__, "No field %s. Defaulting to %d", __DAY0_LOCKOUT_COUNT__, DEFAULT_LOCKOUT_SECONDS)
            self.lockout_seconds = DEFAULT_LOCKOUT_SECONDS

        # IP network list for adding route to the underlay interface
        try:
            self.underlay_ip_net_list = Config.get(__DAY0_SECTION_OTHER__,
                                                   __DAY0_UNDERLAY_IP_NET_LIST__)
            vpfa_log_med(__DAY0_STR__, "Got Underlay IP network list '%s'",
                         self.underlay_ip_net_list)
        except:
            vpfa_log_med(__DAY0_STR__, "No field %s. Defaulting to None",
                         __DAY0_UNDERLAY_IP_NET_LIST__)

        # underlay interface name
        try:
            self.underlay_intf_name = Config.get(__DAY0_SECTION_OTHER__,
                                                 __DAY0_UNDERLAY_IF_NAME__)
            vpfa_log_med(__DAY0_STR__, "Got Underlay Interface name '%s'",
                         self.underlay_intf_name)
        except:
            vpfa_log_med(__DAY0_STR__, "No field %s. Defaulting to None",
                         __DAY0_UNDERLAY_IF_NAME__)

    def __str__(self):
        name = ("gw=" + self.gw_addr + " dhcp=" + self.dhcp_addr +
                " und=" + self.underlay_ip_addr)
        return name

    def validate_vts_username_password(self, username, password):
        ''' Returns whether the username and passwords are correct'''
        return VTSAuthValidation(
                username == self.ncs_username,
                password == self.ncs_password)

    def validate_req_username_password(self, request):
        ''' Returns True if req auth parms matches VTS/NCS auth parms'''
        username = request.getUser()
        password = request.getPassword()
        auth_result = self.validate_vts_username_password(username, password)
        # Username/password validation is split to support
        # SEC-USR-MESS: Log only valid usernames for failed login attempts
        login_time = time.ctime()
        login_dt = datetime.datetime.strptime(
                login_time, "%a %b %d %H:%M:%S %Y")
        prev_fail_dt = None
        if self.auth_fail_info["last_fail_time"] != None:
            prev_fail_dt = datetime.datetime.strptime(
                    self.auth_fail_info["last_fail_time"],
                    "%a %b %d %H:%M:%S %Y")
        if self.auth_fail_info["locked_out"]:
            if (login_dt - prev_fail_dt) > datetime.timedelta(seconds=self.lockout_seconds):
                self.auth_fail_info["locked_out"] = False
                self.auth_fail_info["failures_since_prev_login"] = 0
            else:
                self.auth_fail_info["num_fail"] += 1
                self.auth_fail_info["last_fail_time"] = login_time
                vpfa_log_err("AUTH: ", "Failed login attempt - User: %s URI:%s Host:%s Method:%s", self.auth_fail_info["last_fail_user"],
                             str(request.uri), str(request.getHost()), request.method)
                request.setResponseCode(UNAUTHORIZED)
                return False
        if not auth_result.username_valid or not auth_result.password_valid:
            if prev_fail_dt != None and (login_dt - prev_fail_dt) < datetime.timedelta(seconds=self.lockout_window_seconds):
                self.auth_fail_info["failures_since_prev_login"] += 1
                if self.auth_fail_info["failures_since_prev_login"] > self.lockout_count:
                    self.auth_fail_info["locked_out"] = True
            else:
                self.auth_fail_info["failures_since_prev_login"] = 0
            self.auth_fail_info["num_fail"] += 1
            self.auth_fail_info["last_fail_request"] = str(request)
            self.auth_fail_info["last_fail_user"] = \
                username if auth_result.username_valid else "Invalid Username"
            self.auth_fail_info["last_fail_time"] = login_time
            self.auth_fail_info["last_fail_ip"] = request.getClientIP()
            vpfa_log_err("AUTH: ", "Failed login attempt - User: %s URI:%s Host:%s Method:%s", self.auth_fail_info["last_fail_user"],
                         str(request.uri), str(request.getHost()), request.method)
            request.setResponseCode(UNAUTHORIZED)
            return False
        #vpfa_log_med("AUTH: ", "Successful Login - User: %s URI:%s Host:%s Method:%s", username,
        #             str(request.uri), str(request.getHost()), request.method)
        return True

    def handle_response_success(self, response):
        ''' Call-back for registration with NCS '''
        if response.code in [200, 201, 204]:
            print "VTF-REG: Return code:{} phrase:{}!!!".format(response.code, response.phrase)
            vpfa_log_med("VTF-REG: ", "Return code:%d phrase:%s!!!", response.code, response.phrase)
            #Read the html body in the response received
            finished = Deferred()
            response.deliverBody(ReadHtmlBody(finished, response.length, vpfa_log_med))
        else:
            print "VTF-REG-ERR: Failure code:{} phrase:{}!!!".format(response.code, response.phrase)
            vpfa_log_err("VTF-REG-ERR: ", "Failure code:%d phrase:%s!!!",
                         response.code, response.phrase)
            #Read the html body in the response received
            finished = Deferred()
            response.deliverBody(ReadHtmlBody(finished, response.length, vpfa_log_err))
            #reactor.callLater(30, self.register_ncs)
        reactor.stop()

    def handle_response_error(self, failure):
        ''' Error-back for registration with NCS '''
        print "Failure code %s!!!!!!" % failure.__str__()
        print "Failure %s !!!!!" % str(failure.__dict__)
        vpfa_log_err("VTF-REG-ERR: ", "Code %s failure %s",
                      failure.__str__(), str(failure.__dict__))
        #reactor.callLater(30, self.register_ncs)
        reactor.stop()

    def set_ncs_data(self):
        self.ncs_data[NCS_DATA_VTF][IP] = self.underlay_ip_addr
        self.ncs_data[NCS_DATA_VTF][LOCALMAC] = self.underlay_mac
        self.ncs_data[NCS_DATA_VTF][USER] = self.username
        self.ncs_data[NCS_DATA_VTF][GW] = self.gw_addr
        self.ncs_data[NCS_DATA_VTF][HOSTNAME] = self.compute_hostname
        if self.hostname != None:
            self.ncs_data[NCS_DATA_VTF][VPP] = self.hostname
        else:
            self.ncs_data[NCS_DATA_VTF][VPP] = "vtf"

        mode = "vhost"
        if self.vif_type and self.vif_type == "vhostuser":
            mode = "vhost"

        self.ncs_data[NCS_DATA_VTF][VPP_MODE] = "cisco-vts-identities:" + mode


    def register_ncs(self):
        auth= b64encode(''.join([self.ncs_username,
                                 ':',
                                 self.ncs_password]))
        hdr1 = Headers()
        hdr1.addRawHeader("Content-type", "application/vnd.yang.data+json")
        hdr1.addRawHeader("authorization", b"Basic " + auth)

        uri = self.ncs_reg_url #+ "/" + self.underlay_ip_addr
        self.set_ncs_data()

        contextFactory = WebClientContextFactory()
        agent = Agent(reactor, contextFactory)

        body = FileBodyProducer(StringIO(json.dumps(self.ncs_data)))
        def1 = agent.request("PATCH", uri, hdr1, body)

        #def1 = treq.put(uri, auth=(self.ncs_username, self.ncs_password),
        #    data=json.dumps(self.ncs_data), headers=hdr1, pool=self.pool)
        def1.addCallback(self.handle_response_success)
        def1.addErrback(self.handle_response_error)
        print "VTF-REG: Sent PATCH {} to {}".format(json.dumps(self.ncs_data), uri)
        vpfa_log_med("VTF-REG: ", "Sent PATCH %s to %s",
                     json.dumps(self.ncs_data), uri)

    def set_gw_addr(self, gw_addr):
        ''' Private function to set GW '''
        self.gw_addr = gw_addr
        self.root.rdb.modify_default_route_next_hop()

    def __set_dhcp_addr(self, dhcp_addr):
        ''' Private function to set DHCP host addr '''
        self.dhcp_addr = dhcp_addr

    def __set_hostname(self, hostname):
        ''' Private function to set hostname '''
        if len(hostname) == 0:
            return
        self.hostname = hostname

    def set_underlay_ip_addr(self, underlay_ip_addr):
        self.underlay_ip_addr = underlay_ip_addr

    def set_underlay_mac(self, underlay_mac):
        self.underlay_mac = underlay_mac
        # Generate OUI from underlay MAC
        self.oui_mac = (int(underlay_mac[0:2], 16) << 16) + \
            (int(underlay_mac[3:5], 16) << 8) + int(underlay_mac[6:8], 16)


    def set_dhcp_info(self, hostname, dhcp_addr, gw_addr):
        self.__set_hostname(hostname)
        self.__set_dhcp_addr(dhcp_addr)
        self.set_underlay_ip_addr(dhcp_addr)
        self.set_gw_addr(gw_addr)


        # Register VTF with NCS
        self.register_ncs()

    def get_json(self, args=None):
        obj = collections.OrderedDict()
        obj["hostname"] = str(self.hostname)
        obj["gw-addr"] = str(self.gw_addr)
        obj["dhcp-addr"] = str(self.dhcp_addr)
        obj["underlay-ip-addr"] = str(self.underlay_ip_addr)
        obj["underlay-mac"] = self.underlay_mac
        obj["auth-fail-info"] = self.auth_fail_info
        return obj

if __name__ == '__main__':

    class myRoot:
        def __init__(self):
            self.glb = VpfaGlb(self)
            self.nw = GlbNetworking(self.glb)
            self.nw.get_underlay_mac()
            self.glb.register_ncs()

    vpfa_log_init()

    my_root = myRoot()

    reactor.run()
