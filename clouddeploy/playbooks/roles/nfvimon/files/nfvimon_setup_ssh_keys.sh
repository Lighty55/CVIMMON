#!/usr/bin/env bash

SSH_KEYS_DIR="$HOME/.ssh"
WORK_DIR="/opt/cisco/"

function generate_ssh_keys {
    echo "Generating SSH Keys"

    set -e
    if [ ! -d $SSH_KEYS_DIR ]; then
        echo "Log Directory [${SSH_KEYS_DIR}] does not exist. creating.."
        mkdir -p ${SSH_KEYS_DIR}
        chmod 700 ${SSH_KEYS_DIR}
    else
        printf "CHECK SSH_KEYS_DIR: OK"
    fi

    #Only generate the key if one doesn't previously exist
    if [ ! -e ${SSH_KEYS_DIR}/zenoss_id_rsa ]; then
        ssh-keygen -t rsa -N "" -f ${SSH_KEYS_DIR}/zenoss_id_rsa -C "NFVIMON"
    fi

    set +e

}

generate_ssh_keys
