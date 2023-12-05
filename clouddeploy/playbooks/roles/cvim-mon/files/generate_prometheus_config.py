#!/usr/bin/python

from optparse import OptionParser
import socket
import subprocess
import yaml

def insert_servers_under_jobs_config(config_file, servers, job_name):
    if servers:
        for elem in config_file['scrape_configs']:
            if 'job_name' in elem and elem['job_name'] == job_name:
                elem['static_configs'][0]['targets'] = servers
                break
        else:
            config_file['scrape_configs'].append({'job_name': job_name,
                                                  'static_configs': [{'targets': servers}]})

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config",
                      help="Prometheus config template")
    parser.add_option("-i", "--ip", dest="ip",
                      help="Host (where Prometheus will run) IPv4")
    parser.add_option("-w", "--workspace", dest="workspace",
                      help="Workspace",)
    (options, args) = parser.parse_args()
    with open(options.workspace + "/openstack-configs/setup_data.yaml", 'r') as f:
        setup_data = f.read()
        setup_file = yaml.safe_load(setup_data)
    with open(options.workspace + "/openstack-configs/.cobbler_data.yaml", 'r') as f:
        cobbler_data = f.read()
        cobbler_file = yaml.safe_load(cobbler_data)
    with open(options.config, 'r') as f:
        config_file = yaml.safe_load(f.read())

    mgmt_hostname = socket.gethostname()

    config_file['alerting']['alertmanagers'][0]['static_configs'][0]['targets'] = ["localhost:9093"]
    if not config_file.get('rule_files'):
        config_file['rule_files'] = ['alerting_rules.yml']

    prometheus_servers = ["localhost:9090"]

    # Telegraf Servers
    telegraf_servers = {mgmt_hostname + ":9273"}
    try:
        for host in setup_file["ROLES"]["block_storage"]:
            telegraf_servers.add(host + ":9273")
    except:
        print('No block storage ROLE in the setup_data')
    try:
        for host in setup_file["ROLES"]["compute"]:
            telegraf_servers.add(host + ":9273")
    except:
        print('No compute ROLE in the setup_data')
    try:
        for host in setup_file["ROLES"]["control"]:
            telegraf_servers.add(host + ":9273")
    except:
        print('No control ROLE in the setup_data')
    try:
        for host in setup_file["ROLES"]["cephosd"]:
            telegraf_servers.add(host + ":9273")
    except:
        print('No cephosd ROLE in the setup_data')
    try:
        for host in setup_file["ROLES"]["cephcontrol"]:
            telegraf_servers.add(host + ":9273")
    except:
        print('No cephcontrol ROLE in the setup_data')
    try:
        for host in setup_file["CVIM_MON"]["external_servers"]:
            if ':' in host:
                host = '[' + host + ']'
            telegraf_servers.add(host + ":9273")
    except:
        print("No extern ROLE in the setup_data")

    telegraf_servers = list(telegraf_servers)

    # assign all servers to its jobs
    insert_servers_under_jobs_config(config_file, prometheus_servers, 'prometheus')
    insert_servers_under_jobs_config(config_file, telegraf_servers, 'telegraf')

    with open("/var/lib/prometheus_conf/prometheus.yml", 'w') as f:
        f.write(yaml.dump(config_file, default_flow_style=False))
