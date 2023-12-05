#!/bin/sh

errorExit() {
    echo "*** $*" 1>&2
    exit 1
}

curl -g --silent --max-time 3 --insecure https://localhost:9283/metrics -o /dev/null || errorExit "Error GET https://localhost:9283/metrics"
{% if (external_lb_vip_ipv6_address is defined and external_lb_vip_ipv6_address != "") %}
if ip addr | grep -q {{ external_lb_vip_ipv6_address }}; then
    curl -6 -g --silent --max-time 3 --insecure https://[{{ external_lb_vip_ipv6_address }}]:9283/metrics -o /dev/null || errorExit "Error GET https://[{{ external_lb_vip_ipv6_address }}]:9283/metrics"
fi
{% else %}
if ip addr | grep -q {{ external_lb_vip_address }}; then
    curl -g --silent --max-time 3 --insecure https://{{ external_lb_vip_address }}:9283/metrics -o /dev/null || errorExit "Error GET https://{{ external_lb_vip_address }}:9283/metrics"
fi
{% endif %}
