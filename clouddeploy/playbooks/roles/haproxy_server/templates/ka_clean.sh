#!/bin/bash
pkill keepalived
rm -f /run/keepalived.pid /run/checkers.pid /run/vrrp.pid
ip addr del {{ external_lb_vip_address }}/{{ api_cidr }} dev api 2>&1 > /dev/null
ip addr del {{ internal_lb_vip_address }}/{{ control_cidr }} dev mgmt 2>&1 > /dev/null
{% if internal_lb_vip_ipv6_address is defined and internal_lb_vip_ipv6_address != "" %}
ip -6 addr del {{ internal_lb_vip_ipv6_address }}/{{ mgmt_ipv6_subnet_len }} dev mgmt 2>&1 > /dev/null
{% endif %}
{% if external_lb_vip_ipv6_address is defined and external_lb_vip_ipv6_address != "" %}
ip -6 addr del {{ external_lb_vip_ipv6_address }}/{{ api_ipv6_subnet_len }} dev api 2>&1 > /dev/null
{% endif %}
