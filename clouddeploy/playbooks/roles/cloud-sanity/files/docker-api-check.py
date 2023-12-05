#!/usr/bin/env python
# -*- coding: utf-8 -*-

import docker
import sys
import os
import re
import yaml
import json
import subprocess

CVIM_NAME_SPACE_LIST = ["cloud-docker.cisco.com", "cvim-registry.com",
                        "cvim-rhel7-osp12-k8s", "cvim34-rhel7-osp13",
                        "cvim-registry-internal"]

CONTAINER_NAME_TRANSLATOR = { 'mycobbler': 'dockblerapp',
                              'glancer': 'glanceregistry',
                              'novaconduct': 'novaconductor'}

CONTAINER_SKIP_LIST = ["rallymaster", "cvim_ps_rally", "cvimpsrally", "insight", "mariadb"]


def docker_yaml_data(display=True):
    docker_file = "/root/openstack-configs/docker.yaml"
    if not os.path.isfile(docker_file):
        print("FAIL: Docker.yaml file is missing...")
        return
    expected_tags = {}
    with open(docker_file, 'r') as stream:
        try:
            docker_data = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print("FAIL: {0}".format(exc))
            return
    container_detail = docker_data['docker']
    for container in container_detail:
        name = str(container.replace('_', ''))
        if 'image_tag' in container_detail[container]:
            detail = container_detail[container]
            expected_tags.update({name: str(detail['image_tag'])})
            container_name_path = str(detail['name']).strip(',')
            container_name = container_name_path.split('/')[-1].replace('-', '')
            if container_name != name:
                expected_tags.update({container_name: str(detail['image_tag'])})
    if display:
        print(json.dumps(expected_tags, ensure_ascii=True, sort_keys=True, indent=4, separators=(',', ': ')))
    else:
        return expected_tags


def is_ip_reachable(ip_addr):
    err_str = "IP Address Unreachable"
    try:
        ping = subprocess.Popen(['/usr/bin/ping', '-c5', '-W2', ip_addr], \
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = ping.communicate()[0]
        if not out:
            return 0
        for item in out.splitlines():
            if re.search(r'100% packet loss', item):
                return 0
    except subprocess.CalledProcessError:
        return 0
    return 1


def get_remote_data(remote_host):
    remote_cmd = "/usr/bin/docker ps -a --no-trunc --format \"{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}\""
    ssh_cmd = ["/usr/bin/ssh",
               "-oStrictHostKeyChecking=no",
               "root@{0}".format(remote_host),
               remote_cmd]
    sproc = subprocess.Popen(ssh_cmd,  # nosec
                             stdout=subprocess.PIPE)
    containers_data = []
    while True:
        try:
            line = sproc.stdout.readline()
            if line == '' and sproc.poll() is not None:
                break
            else:
                line_items = line.split('|')
                container_info = {"Id": line_items[0],
                          "Names": line_items[1],
                          "Image": line_items[2],
                          "Status": line_items[3]}
                containers_data.append(container_info)
        except Exception:
            return containers_data
    return containers_data


def get_actual_docker_data(display=True, remote_host=None):
    if remote_host:
        if is_ip_reachable(remote_host):
            containers = get_remote_data(remote_host)
        else:
            print("SKIP: Remote host {0} not reachable".format(remote_host))
            return {}
    else:
        client = docker.from_env()
        if client.ping() != 'OK':
            print("FAIL: Docker client ping status: {0}".format(client.ping()))
            return
        containers = client.containers()
    actual_tags = {}
    for container in containers:
        if str(container['Status']).startswith("Up"):
            if remote_host:
                container_names = str(container['Names'].strip('/'))
            else:
                container_names = str(container['Names'][0].strip('/'))

            try:
                image_name_data = container_names.split('_')
                container_tag = image_name_data[-1]
                container_name = "".join(image_name_data[0:-1])
                container_image = str(container['Image'])

                # Skip if any Non CVIM container(s) running on Mgmt node
                #if not any(name in container_image for name in CVIM_NAME_SPACE_LIST):
                #    continue

                image_tag = container_image.split(':')[-1]
                image_path = container_image.split(':')[-2]
                image_name = image_path.split('/')[-1].replace("-", "")
            except Exception:
                actual_tags.update({str(container['Id']): {'name': container_names,
                                                           'tag': 'unknown',
                                                           'image_name': container_names}})
                continue

            if image_tag.isdigit() and container_tag.isdigit():
                if int(image_tag) == int(container_tag):
                    actual_tags.update({str(container['Id']): {'name': container_name,
                                                               'tag': container_tag,
                                                               'image_name': image_name}})
                else:
                    print("FAIL: Actual container/image tag mismatch: {0}".format(container_name))
    if display:
        print(json.dumps(actual_tags, ensure_ascii=True, sort_keys=True, indent=4, separators=(',', ': ')))
    else:
        return actual_tags


def verify_container_tag(container_name, image_name, tag):
    expected_tags = docker_yaml_data(display=False)

    if container_name in CONTAINER_NAME_TRANSLATOR.keys():
        container_name = CONTAINER_NAME_TRANSLATOR[container_name]

    if container_name in expected_tags:
        expected_tag = expected_tags[container_name]
    elif container_name in CONTAINER_SKIP_LIST:
        print("SKIP: Container {0} in skip_list".format(container_name))
        return
    else:
        print("FAIL: Non-CVIM Container: {0} not found in docker.yaml".format(container_name))
        return

    if expected_tag != tag:
        print("FAIL: Invalid container({0}) tag, Expected: {1},  Actual: {2}".format(container_name, expected_tag, tag))
    else:
        print("PASS: Container {0} tag matches docker.yaml version".format(container_name))


def get_exited_containers(display=True, remote_host=None):
    cont_exited = {}
    if remote_host:
        exited_containers = get_remote_data(remote_host)
        for container in exited_containers:
            if str(container['Status']).startswith("Exited"):
                raw_container_name = container['Names']
                container_name_list = raw_container_name.split('_')
                container_name = "".join(container_name_list[0:-1])
                container_tag = container_name_list[-1]
                cont_exited.update({str(container['Id']): {'raw_name': raw_container_name,
                                                           'name': container_name,
                                                           'tag': container_tag}})
    else:
        client = docker.from_env()
        if client.ping() != 'OK':
            print("FAIL: Docker client ping status: {0}".format(client.ping()))
            return
        exited_containers = client.containers(filters={'status': 'exited'})
        for container in exited_containers:
            raw_container_name = container['Names'][0].decode().strip('/')
            container_name_list = raw_container_name.split('_')
            container_name = "".join(container_name_list[0:-1])
            container_tag = container_name_list[-1]
            cont_exited.update({str(container['Id']): {'raw_name': raw_container_name,
                                                       'name': container_name,
                                                       'tag': container_tag}})

    if display:
        print(json.dumps(cont_exited, ensure_ascii=True, sort_keys=True, indent=4, separators=(',', ': ')))
    else:
        return cont_exited


def verify_container_status(raw_container_name, container_name, container_tag):
    expected_tags = docker_yaml_data(display=False)

    if container_name in CONTAINER_NAME_TRANSLATOR.keys():
        container_name = CONTAINER_NAME_TRANSLATOR[container_name]

    if container_name in expected_tags:
        if int(expected_tags[container_name]) == int(container_tag):
            print("FAIL: Container {0} in unexpected exited state".format(raw_container_name))
        else:
            print("SKIP: Container {0} in exited state: expected".format(raw_container_name))

    print("Complete: Container status check")


def verify_compute_container_tags(compute_host, skip_list):
    if not is_ip_reachable(compute_host):
        print("SKIP: Remote host {0} not reachable".format(compute_host))
        return {}
    actual_container_tags = get_actual_docker_data(display=False, remote_host=compute_host)
    clean_skip_list = [name.replace('_', '') for name in skip_list.split(',')]
    for container_id in actual_container_tags:
        container_info = actual_container_tags[container_id]
        if container_info['name'].replace('_', '') in clean_skip_list:
            print("SKIP: Container {0} in skip list".format(container_info['name']))
            continue
        verify_container_tag(container_info['name'],
                             container_info['image_name'],
                             container_info['tag'])


def verify_compute_container_status(compute_host, skip_list):
    if not is_ip_reachable(compute_host):
        print("SKIP: Remote host {0} not reachable". format(compute_host))
        return {}

    exited_containers = get_exited_containers(display=False, remote_host=compute_host)
    clean_skip_list = [name.replace('_', '') for name in skip_list.split(',')]
    for container_id in exited_containers:
        container_info = exited_containers[container_id]
        if container_info['name'].replace('_', '') in clean_skip_list:
            print("SKIP: Container {0} in skip list".format(container_info['name']))
            continue
        verify_container_status(container_info['raw_name'],
                                container_info['name'],
                                container_info['tag'])


if __name__ == "__main__":

    if re.search(r'obtain_expected_data', sys.argv[1]):
        docker_yaml_data()
    elif re.search(r'get_actual_docker_data', sys.argv[1]):
        get_actual_docker_data()
    elif re.search(r'verify_container_tag', sys.argv[1]):
        verify_container_tag(sys.argv[2], sys.argv[3], sys.argv[4])
    elif re.search(r'verify_compute_container_tags', sys.argv[1]):
        verify_compute_container_tags(sys.argv[2], sys.argv[3])
    elif re.search(r'get_exited_containers', sys.argv[1]):
        get_exited_containers()
    elif re.search(r'verify_container_status', sys.argv[1]):
        verify_container_status(sys.argv[2], sys.argv[3], sys.argv[4])
    elif re.search(r'verify_compute_container_status', sys.argv[1]):
        verify_compute_container_status(sys.argv[2], sys.argv[3])
    else:
        print("FAIL: Unknown command {0}".format(sys.argv[1]))

