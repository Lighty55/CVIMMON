#!/bin/bash
STATE=$3

if [[ $STATE == "MASTER" ]]; then
    grep -qxF '200 mgmt' /etc/iproute2/rt_tables  || echo '200 mgmt' >> /etc/iproute2/rt_tables
    grep -qxF '300 api' /etc/iproute2/rt_tables  || echo '300 api' >> /etc/iproute2/rt_tables
    ip rule add iif mgmt lookup mgmt
    ip rule add from {{ internal_lb_vip_address }} lookup mgmt
    ip rule add iif api lookup api
    ip rule add from {{  external_lb_vip_address }} lookup api
    ip route add {{ ipv4_external | ipaddr('host/prefix') |  ipaddr('subnet') }} dev api table api
    ip route add {{ ipv4_internal | ipaddr('host/prefix') | ipaddr('subnet') }} dev mgmt table mgmt
    ip route add default via {{ api_gw }} dev api table api
    ip route add default via {{ mgmt_gw }} dev mgmt table mgmt
    ip route add default via {{ api_gw }} dev api
{% if external_lb_vip_ipv6_address is defined and external_lb_vip_ipv6_address != "" %}
    ip -6 rule add from {{ internal_lb_vip_ipv6_address }} lookup mgmt
    ip -6 rule add from {{ external_lb_vip_ipv6_address }} lookup api
    ip -6 route add {{ ipv6_external | ipaddr('host/prefix') |  ipaddr('subnet') }} dev api table api
    ip -6 route add {{ ipv6_internal | ipaddr('host/prefix') | ipaddr('subnet') }} dev mgmt table mgmt
    ip -6 route add default via {{ api_ipv6_gw }} dev api table api
    ip -6 route add default via {{ mgmt_ipv6_gw }} dev mgmt table mgmt
    ip -6 route add default via {{ api_ipv6_gw }} dev api
{% endif %}
    rm -rf /run/BACKUP; touch /run/MASTER
fi

if [[ $STATE == "BACKUP" ]]; then
    rm -rf /run/MASTER; touch /run/BACKUP
fi
