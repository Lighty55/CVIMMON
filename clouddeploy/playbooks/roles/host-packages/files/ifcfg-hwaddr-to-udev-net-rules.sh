#!/bin/bash

# Set persistent NIC device name with PCI slot via udev instead of MAC address
intf_file=/etc/sysconfig/network-scripts/ifcfg-*
net_rule_file=/etc/udev/rules.d/70-persistent-net.rules

for file in $(grep -El "^HWADDR=" /${intf_file}); do
    device=$(awk -F '=' '/^DEVICE=/ {print $NF}' ${file})
    hwaddr=$(awk -F '=' '/^#?HWADDR=/ {print tolower($NF)}' ${file})
    if [[ ${device} == "" || ${hwaddr} == "" ]]; then
        continue
    fi
    name_pattern=NAME:=\"${device}\"
    if grep -w ${name_pattern} ${net_rule_file}; then
        sed -i "/${name_pattern}/d" ${net_rule_file}
    fi
    address_pattern=ATTR{address}==\"${hwaddr}\"
    if grep -w ${address_pattern} ${net_rule_file}; then
        sed -i "/${address_pattern}/d" ${net_rule_file}
    fi
    echo "ACTION==\"add\", SUBSYSTEM==\"net\", ${address_pattern}, ATTR{type}==\"1\", ${name_pattern}" >> ${net_rule_file}
    if grep -w ${name_pattern} ${net_rule_file} && grep -w ${address_pattern} ${net_rule_file}; then
        sed -i 's/^HWADDR=/#HWADDR=/g' ${file}
    fi
done
