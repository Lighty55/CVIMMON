#!/bin/bash
set -e

#########################################
# Steps to remove compute entries from DB
#########################################

function remove_host_from_aggregates {
    for RM_HOSTNAME in ${HOSTNAME}; do
        for aggregate in $(openstack --os-interface internal aggregate list -c Name -f value --quote none); do
            for host in $(openstack --os-interface internal aggregate show ${aggregate} -c hosts -f yaml | grep -v hosts | awk '{print $2}'); do
                if [ "$host" = "$RM_HOSTNAME" ]; then
                    openstack --os-interface internal aggregate remove host ${aggregate} ${host}
                 fi
            done
        done
    done
}

function remove_computes {
    for RM_HOSTNAME in ${HOSTNAME}; do
        # Remove the network agents first
        for agent in $(openstack --os-interface internal network agent list --host ${RM_HOSTNAME} | awk '{print $2}' | grep -v ^id | grep -v ^$ | grep -v ID); do
             openstack --os-interface internal network agent delete $agent
        done
        # Next remove the "nova-compute" binary first.
        # If this is not removed first, any subsequent removal of the services will be prevented by
        # the nova.exception.ComputeHostNotFound exception since the record for the host in the compute_nodes
        # table gets flagged as deleted and any further subsequent clean up operation results in this exception
        # resulting in compute_nodes/resource_provider/host_mapping/services tables going out of sync
        compute_service=$(openstack --os-interface internal compute service list --host ${RM_HOSTNAME} --service nova-compute -c ID -f value)
        if [ ! -z "$compute_service" ]; then
            openstack --os-interface internal compute service delete $compute_service
        fi
        # Lastly remove the remainder compute services
        echo $(openstack --os-interface internal compute service list --host ${RM_HOSTNAME} | awk '{print $2}' | grep -v ^Id | grep -v ^$)
        for service in $(openstack --os-interface internal compute service list --host ${RM_HOSTNAME} | awk '{print $2}' | grep -v ^Id | grep -v ^$); do
            if [[ $service =~ ^-?[0-9]+$ ]]; then
                openstack --os-interface internal compute service delete $service
            fi
        done
    done
}

while getopts "n:" Option;
do
    case $Option in
        n) HOSTNAME=$OPTARG;;
    esac
done
remove_host_from_aggregates
remove_computes
