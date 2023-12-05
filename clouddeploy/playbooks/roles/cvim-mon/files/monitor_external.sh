#!/bin/bash

# Install telegraf binary on external servers for central monitoring.

CONFIG_PATH="/etc/telegraf.conf"
CONFIG_FILE="external.conf"
TELEGRAF_FILE="telegraf*.rpm"

diff_config=false

if [ ! -f ${CONFIG_FILE} ]; then
  echo "Error: File ${CONFIG_FILE} not found."
  exit 1
fi

if [ ! -f ${TELEGRAF_FILE} ]; then
	echo "Error: Telegraf rpm file not found."
	exit 1
fi

HOSTNAME="$(hostname -f)"
sed -i 's/^hostname .*$/hostname = "'"${HOSTNAME}"'"/' ${CONFIG_FILE}

if [ -f ${CONFIG_PATH} ]; then
  if ! diff ${CONFIG_FILE} ${CONFIG_PATH} > /dev/null 2>&1; then
    diff_config=true
  fi
elif ! cp ${CONFIG_FILE} ${CONFIG_PATH} > /dev/null 2>&1; then
  echo "Error: Copy of ${CONFIG_FILE} to ${CONFIG_PATH} failed"
  exit 1
fi

if ! yum -y install ipmitool > /dev/null 2>&1; then
  echo "Error: Failed to download ipmitool"
  exit 1
fi

if rpm -q $(basename ${TELEGRAF_FILE} .rpm) > /dev/null 2>&1; then
  echo "Info: Telegraf rpm is already installed."
else
  rpm -Uvh ${TELEGRAF_FILE} > /dev/null 2>&1
fi

if ! systemctl enable telegraf; then
  echo "Error: Could not enable telegraf"
  exit 1
fi

if ! systemctl is-enabled telegraf.service > /dev/null 2>&1; then
  echo "Error: Telegraf service is not enabled or telegraf service is missing"
  exit 1
fi

if [ "$diff_config" = true ] ; then
  if ! cp ${CONFIG_FILE} ${CONFIG_PATH} > /dev/null 2>&1; then
    echo "Error: Copy of new ${CONFIG_FILE} to ${CONFIG_PATH} failed"
    exit 1
  fi
  if ! systemctl restart telegraf; then
    exit 1
  fi
elif ! systemctl start telegraf; then
  exit 1
fi

if systemctl status telegraf > /dev/null 2>&1; then
  echo "Success: Telegraf installation succeeded"
else
  echo "Error: Telegraf installation failed"
  exit 1
fi
