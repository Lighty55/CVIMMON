#!/bin/bash

teamdevname=bond_lacp
teamslaveprefix=eth

if ip -o -d link show ${teamdevname} | grep -w team > /dev/null; then
    echo "Team ${teamdevname} interface found"
else
    echo "No ${teamdevname} interface found"
    exit 1
fi

ports=($(teamnl ${teamdevname} ports | awk -F ':' "match(\$2,/${teamslaveprefix}([0-9]+)/,port_num) {print port_num[1]}"))
if [[ ${#ports[@]} -gt 0 ]]; then
    echo "Team ${teamdevname} slave ports found: ${ports[*]}"
else
    echo "No ${teamdevname} slave port found"
    exit 2
fi

vnics_raw=($(systemctl list-units | awk "match(\$0,/teamd@(.*)\.service/,team) && team[1] != \"${teamdevname}\" {print team[1]}"))
if [[ ${#vnics_raw[@]} -gt 0 ]]; then
    echo "vNICs found: ${vnics_raw[*]}"
else
    echo "No vNIC found that need to be monitored"
    exit 3
fi

# On VPP deployment, "p", "e", and "t" interfaces will be taken by VPP, so pop them out
if systemctl list-units | grep -q -E 'docker-neutron_vpp|docker-neutron_vtf'; then
    echo "Removing p/e/t vNICs from monitoring list..."
    vnics=()
    for v in ${vnics_raw[*]}; do
        [[ $v != p ]] && [[ $v != e ]] && [[ $v != t ]] && vnics+=($v)
    done
    echo "Updated vNICs list to be monitored: ${vnics[*]}"
else
    vnics=("${vnics_raw[@]}")
fi

while true; do
    for port in ${ports[*]}; do
        lacp_state=$(teamnl -p ${teamslaveprefix}${port} ${teamdevname} getoption enabled)
        if [[ ${lacp_state} == "true" || ${lacp_state} == "false" ]]; then
            for vnic in ${vnics[*]}; do
                vnic_state=$(teamnl -p ${vnic}${port} ${vnic} getoption enabled)
                if [[ ${vnic_state} == "true" || ${vnic_state} == "false" ]]; then
                    if [[ ${vnic_state} != ${lacp_state} ]]; then
                        echo "Changing ${vnic}${port} state from ${vnic_state} to ${lacp_state}"
                        teamnl -p ${vnic}${port} ${vnic} setoption enabled ${lacp_state} &
                    fi
                fi
            done
        fi
    done
    wait
    sleep 1
done
