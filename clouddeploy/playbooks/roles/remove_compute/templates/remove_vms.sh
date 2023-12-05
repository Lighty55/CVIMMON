#!/bin/bash
set -e

#########################################
# Steps to delete VM's on compute node
#########################################

function delete_vms {
    for RM_HOSTNAME in ${HOSTNAME}; do
        vm_exists=$(nova --os-endpoint-type internal list --all-tenants --host=${RM_HOSTNAME} | awk '{print $2}' | grep -v ^ID)
        while [ "$vm_exists" != "" ]; do
            vm_exists=$(nova --os-endpoint-type internal list --all-tenants --host=${RM_HOSTNAME} | awk '{print $2}' | grep -v ^ID)
            for host in $(nova --os-endpoint-type internal list --all-tenants --host=${RM_HOSTNAME} | awk '{print $2}' | grep -v ^ID | grep -v ^$); do
                set +e
                nova --os-endpoint-type internal force-delete $host
                set -e
                sleep 1
            done
        done
    done
}

while getopts "n:" Option;
do
    case $Option in
        n) HOSTNAME=$OPTARG;;
    esac
done
delete_vms
