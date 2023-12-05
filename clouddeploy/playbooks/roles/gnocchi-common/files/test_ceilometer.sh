#!/bin/bash

#set -x

function init() {
    $(source ~/openstack-configs/openrc)
}

function get_image_counters() {
    inst=`openstack metric resource list | grep "image\." | awk '{print $2}'`
    for id in ${inst[@]}; do
        echo "========================================="
        echo "Got output for instance: $id"
        echo "========================================="

        array2=($(openstack metric resource show $id | awk '{ print $(NF-1) }'))
        array=($(openstack metric resource show $id | awk '{ print $(NF-2) }'))
        for ((i=0;i<${#array[@]};++i)); do
            printf "+ %s\n%s\n" "${array[i]}" "$(openstack metric measures show ${array2[i]})"
        done
    done
}

function get_instance_counters() {
    inst=`openstack metric resource list | grep "instance" | grep -v "instance_disk" | awk '{print $2}'`
    for id in ${inst[@]}; do
        echo "========================================="
        echo "Got output for instance: $id"
        echo "========================================="

        array2=($(openstack metric resource show $id | grep -vE "cr|start|end" | grep ":" | awk '{ print $(NF-1) }'))
        array=($(openstack metric resource show $id | grep -vE "cr|start|end" | grep ":" | awk '{ print $(NF-2) }'))
        for ((i=0;i<${#array[@]};++i)); do
            printf "+ %s\n%s\n" "${array[i]}" "$(openstack metric measures show ${array2[i]})"
        done
    done
}

function get_instance_disk_counters() {
    idisk=`openstack metric resource list | grep instance_disk | awk '{print $2}'`

    for id in ${idisk[@]}; do
        echo "========================================="
        echo "Got output for instance_disk: $id"
        echo "========================================="

        array=($(openstack metric resource show $id | grep "disk\.device\." | awk '{ print $(NF-2) }'))
        array2=($(openstack metric resource show $id | grep "disk\.device\." | awk '{ print $(NF-1) }'))
        for ((i=0;i<${#array[@]};++i)); do
            printf "+ %s\n%s\n" "${array[i]}" "$(openstack metric measures show ${array2[i]})"
        done
    done
}

function get_instance_net_counters() {
    net_intfs=`openstack metric resource list | grep instance_network_interface | awk '{print $2}'`

    for id in ${net_intfs[@]}; do
        echo "========================================="
        echo "Got output for instance_network_interface: $id"
        echo "========================================="

        array=($(openstack metric resource show $id | grep "network\." | awk '{ print $(NF-2) }'))
        array2=($(openstack metric resource show $id | grep "network\." | awk '{ print $(NF-1) }'))
        for ((i=0;i<${#array[@]};++i)); do
            printf "+ %s\n%s\n" "${array[i]}" "$(openstack metric measures show ${array2[i]})"
        done
    done
}

init
get_image_counters
get_instance_counters
get_instance_disk_counters
get_instance_net_counters
