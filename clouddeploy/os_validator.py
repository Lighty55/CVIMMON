#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import socket
import json
import urllib
import httplib


class OSValidator(object):
    def __init__(self, options):
        self.options = options

    def get_rabbit_cluster_size(self, **kwargs):
        '''
        Get the rabbit cluster size
        '''
        print kwargs
        conn = httplib.HTTPConnection(kwargs['monit_host'],
                                      kwargs['monit_port'])

        headers = {"Content-Type": "application/json"}
        body = {}
        body['operation'] = "cluster_size"
        body['username'] = kwargs['rabbit_user']
        body['hostname'] = kwargs['rabbit_host']
        body = json.dumps(body)

        path = "/rabbit/"

        try:
            conn.request('GET', path, body, headers)
        except socket.error:
            print "Could not connect",
            sys.exit(0)

        resp = conn.getresponse()
        print "res status: ", resp.status
        print "resp.read(): ", resp.read()



def main():
    '''
    Main
    '''
    print "In main"
    validator = OSValidator(None)
    kwargs = {}
    kwargs['rabbit_host'] = "172.22.191.199"
    kwargs['monit_host'] = "172.22.191.199"
    kwargs['monit_port'] = 5025
    kwargs['rabbit_user'] = "guest"
    validator.get_rabbit_cluster_size(**kwargs)

if __name__ == '__main__':
    main()
