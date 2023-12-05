#!/usr/bin/env python
"""
    This script prepares remote pods configurations in Calipso replication client ready-to-use format
    based on setup data and k8s configuration of central calipso-mongo deployment.

    Input arguments:
        --src (str, required): Path to setup_data.yaml source file.
        --dest (str, required): Path to target yaml config file (with filename).
        --host (str, optional): Central calipso-mongo deployment host (FQDN or IP)
        --pwd (str, optional): Central calipso-mongo deployment password

    If --host or --pwd arguments are not supplied, the "central" section of output will not be rendered,
    which implies that Calipso replication client will discover the central calipso-mongo credentials on its own.

    Output (yaml):
        central:
          host: calipso-mongo-cluster-monitor.cisco.com
          mongo_pwd: 1e40e23a3d4c10f8af88e8910ada14697f64375a76ef427fed9c8afc9b9362e7
        remotes:
        - api_pwd: h3263vAvYnXn6M4u
          host: 172.28.123.141
          ip_version: 4
          metro: calipso-metro
          mongo_pwd: iPiiNIfrSJjFNIn5
          name: minnesota
          region: calipso-region
          stack: calipso-stack
          username: calipso
        - api_pwd: sV2GZWwDYEJG5dG6
          host: '[2001:420:293:2424:172:29:84:210]'
          ip_version: 6
          metro: calipso-metro
          mongo_pwd: Lf58fpQK5Qjhq6Ww
          name: moscow
          region: calipso-region
          stack: calipso-stack
          username: calipso
"""

import argparse
import os

from yaml import safe_load, dump

try:
    from yaml import CDumper as Dumper
    from yaml.emitter import Emitter
except ImportError:
    from yaml import Dumper
    from yaml.emitter import Emitter


# TODO: to be enabled when scheduler is ready
# DEFAULTS = {
#     'discovery_interval': '24h',
#     'replication_interval': '24h',
#     'volume_size': '1000Gi'
# }


# Exclude class tags from dump
Emitter.process_tag = lambda x, *args, **kwargs: None


def auto_repr(cls):
    def __repr__(self):
        return '%s(%s)' % (
            type(self).__name__,
            ', '.join('%s=%s' % item for item in vars(self).items())
        )
    cls.__repr__ = __repr__
    return cls


# TODO: to be enabled when scheduler is ready
# @auto_repr
# class InvDiscSettings:
#     def __init__(self, discovery_interval, replication_interval, volume_size):
#         self.discovery_interval = discovery_interval
#         self.replication_interval = replication_interval
#         self.volume_size = volume_size


@auto_repr
class PodData:
    def __init__(self, stack, region, metro, name, vip, inv_api_pwd, inv_mongo_pwd, inv_username):
        self.stack = stack
        self.region = region
        self.metro = metro
        self.name = name
        self.username = inv_username
        self.api_pwd = inv_api_pwd
        self.mongo_pwd = inv_mongo_pwd

        vip_parts = vip.split(":")
        if len(vip_parts) == 1:
            self.host = vip
            self.ip_version = 4
        elif len(vip_parts) == 2:
            self.host = vip_parts[0]
            self.ip_version = 4
        else:
            self.host = ":".join(vip_parts[:-1])
            self.ip_version = 6

    def __repr__(self):
        return '%s(%s)' % (
            type(self).__name__,
            ', '.join('%s=%s' % item for item in vars(self).items())
        )


# @auto_repr
# class Stack:
#     def __init__(self, settings, pods):
#         self.settings = settings
#         self.pods = pods


def get_pods_config(setup_data_yaml):
    setup_data = safe_load(setup_data_yaml)
    cvim_mon_stacks = setup_data.get('cvim-mon-stacks', [])
    if not cvim_mon_stacks:
        return []

    # stacks = []
    pods = []
    for stack in cvim_mon_stacks:
        # TODO: to be enabled when scheduler is ready
        # settings = InvDiscSettings(
        #     discovery_interval=stack.get('inventory_discovery_interval', DEFAULTS.get('discovery_interval')),
        #     replication_interval=stack.get('inventory_replication_interval', DEFAULTS.get('replication_interval')),
        #     volume_size=stack.get('inventory_volume_size_gb', DEFAULTS.get('volume_size'))
        # )

        # pods = []
        for region in stack.get('regions', []):
            for metro in region.get('metros', []):
                for pod in metro.get('pods', []):
                    if "inventory_api_password" not in pod or "inventory_mongo_password" not in pod:
                        continue
                    pods.append(PodData(stack=stack['name'],
                                        region=region['name'],
                                        metro=metro['name'],
                                        name=pod['name'],
                                        vip=pod['ip'],
                                        inv_username=pod.get('inventory_username', 'calipso'),
                                        inv_api_pwd=pod['inventory_api_password'],
                                        inv_mongo_pwd=pod['inventory_mongo_password']))

        # stacks.append(Stack(settings=settings, pods=pods))

    # return stacks
    return pods


def run(args):
    with open(args.src) as setup_data:
        pods = get_pods_config(setup_data)

    config = {"remotes": pods}
    if args.host and args.pwd:
        config["central"] = {
            "host": args.host,
            "mongo_pwd": args.pwd
        }

    with open(os.path.join(args.dest), "w") as f:
        dump(config, f, default_flow_style=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    required_group = parser.add_argument_group("required arguments")
    required_group.add_argument("--src", required=True, help="Path to setup_data.yaml source file")
    required_group.add_argument("--dest", required=True, help="Path to target yaml config file (with filename)")
    parser.add_argument("--host", required=False, help="Central calipso-mongo deployment host (FQDN or IP)")
    parser.add_argument("--pwd", required=False, help="Central calipso-mongo deployment password")
    cli_args = parser.parse_args()
    run(cli_args)
