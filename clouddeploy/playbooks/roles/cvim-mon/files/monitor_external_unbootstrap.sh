#!/bin/bash

# Remove telegraf service on external servers for central monitoring.

CONFIG_FILE="/etc/telegraf.conf"

if ! systemctl stop telegraf; then
  echo "Error: Could not stop telegraf service"
fi

if ! systemctl disable telegraf; then
  echo "Error: Could not disable telegraf service"
fi

if ! yum -y remove telegraf > /dev/null 2>&1; then
  echo "Error: Failed to remove telegraf"
fi

if ! yum clean all > /dev/null 2>&1; then
  echo "Error: Failed to yum clean all"
fi

if [ -f ${CONFIG_FILE} ]; then
  rm ${CONFIG_FILE} > /dev/null 2>&1
fi
