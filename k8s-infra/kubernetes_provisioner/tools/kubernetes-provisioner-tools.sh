#!/bin/bash

set -e

# Pretty colors.
red='\033[0;31m'
green='\033[0;32m'
neutral='\033[0m'

# Global Configuration Files
setupdata_file="/root/openstack-configs/setup_data.yaml"
defaults_file="/root/openstack-configs/defaults.yaml"
inventory_file="../playbooks/inventory/generate_inventory.py"

# read in which version to install
if [ $# -eq 0 ]; then
  echo "
        Usage: ./kubernetes-provisioner-tools.sh <action>

        #####   Supported Actions are:

        * uninstall: Uninstalls Kubernetes Cluster along with all CVIMMON applications

        * etcd-regenerate-certs: Regenerates etcd Certificates changing the validity

        * etcd-backup: Backs up all ETCD data

        * etcd-restore: Restores ETCD Cluster to Current State based on Backup

        * regenerate-kubernetes-certs: Regenerates All Kubernetes API and Kubelet Certs (Validity: 1 Year)"
  exit 1
else
  action=$1
fi
########UNINSTALL#######################
if [ "$action" = uninstall ]; then
  playbook="../playbooks/cleanup-all-vms.yaml"
fi
if [ "$action" = uninstall ]; then
  read -p "Uninstalling the Kubernetes Cluster, Quit the same if not intended. Choose Y(Yes) or N (No). Do you want to proceed?:" -n 1 -r
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      ANSIBLE_STDOUT_CALLBACK=debug ansible-playbook -i $inventory_file $playbook -e @$setupdata_file -e @$defaults_file |  grep -ohe 'TASK .*'
  fi
fi
########ETCD-REGENERATE-CERTS#######################
if [ "$action" = etcd-regenerate-certs ]; then
  playbook="../playbooks/etcd_upgrade_utility.yaml"
  option="ACTION=etcd-regenerate-certs"
fi
if [ "$action" = etcd-regenerate-certs ]; then
  read -p "This Regenerates Cluster etcd Certificates which changes the validity. Choose Y(Yes) or N (No). Do you want to proceed?:" -n 1 -r
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      ANSIBLE_STDOUT_CALLBACK=debug ansible-playbook -i $inventory_file $playbook -e @$setupdata_file -e @$defaults_file -e $option |  grep -ohe 'TASK .*'
  fi
fi
#################ETCD-BACKUP########################
if [ "$action" = etcd-backup ]; then
  playbook="../playbooks/etcd_upgrade_utility.yaml"
  option="ACTION=etcd-backup"
  vars="../playbooks/roles/etcd_upgrade/defaults/"
fi
if [ "$action" = etcd-backup ]; then
  read -p "This Regenerates Cluster etcd Certificates which changes the validity. Choose Y(Yes) or N (No). Do you want to proceed?:" -n 1 -r
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      ANSIBLE_STDOUT_CALLBACK=debug ansible-playbook -i $inventory_file $playbook -e @$setupdata_file -e @$defaults_file -e $option -e $vars |  grep -ohe 'TASK .*'
  fi
fi
#################ETCD-RESTORE########################
if [ "$action" = etcd-restore ]; then
  playbook="../playbooks/etcd_upgrade_utility.yaml"
  option="ACTION=etcd-restore"
  vars="../playbooks/roles/etcd_upgrade/defaults/"
fi
if [ "$action" = etcd-restore ]; then
  read -p "This Restore any Master node with the Active Master status based on etcd. Choose Y(Yes) or N (No). Do you want to proceed?:" -n 1 -r
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      ANSIBLE_STDOUT_CALLBACK=debug ansible-playbook -i $inventory_file $playbook -e @$setupdata_file -e @$defaults_file -e $option -e $vars |  grep -ohe 'TASK .*'
  fi
fi
#################Kubernetes-Cert-Regenerate########################
if [ "$action" = regenerate-kubernetes-certs ]; then
  playbook="../playbooks/kubernetes_renew_certs.yaml"
fi
if [ "$action" = regenerate-kubernetes-certs ]; then
  read -p "This Regenerates All Kubernetes API Certs and Kubelet Certs which also Renews Validity. Choose Y(Yes) or N (No). Do you want to proceed?:" -n 1 -r
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      ANSIBLE_STDOUT_CALLBACK=debug ansible-playbook -i $inventory_file $playbook -e @$setupdata_file -e @$defaults_file | grep -ohe 'TASK .*'
  fi
fi
