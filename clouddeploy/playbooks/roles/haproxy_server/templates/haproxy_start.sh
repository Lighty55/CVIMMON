#!/bin/bash -xe


: ${external_lb_vip_address:=192.168.111.250}
: ${VIRTUAL_ROUTER_ID:=35}
: ${HAPROXY_STAGING_DIR:="/docker/haproxy"}

#ipvsadm -L

cp ${HAPROXY_STAGING_DIR}/haproxy.cfg /etc/haproxy/.
cp ${HAPROXY_STAGING_DIR}/supervisord.conf /etc/supervisord.conf

if [[ -e ${HAPROXY_STAGING_DIR}/haproxy.pem ]]; then
    mkdir -p /etc/pki/haproxy/private
    cp ${HAPROXY_STAGING_DIR}/haproxy.pem /etc/pki/haproxy/private/.
fi

# keepalived won't restart
rm -f /var/run/*.pid

# enable rsyslog on loopback and only log haproxy to /var/log/haproxy/haproxy.log file
cat > /etc/rsyslog.d/haproxy.conf << EOF
\$ModLoad imudp
\$UDPServerRun 514
\$UDPServerAddress 127.0.0.1
if \$programname == 'haproxy' then -/var/log/haproxy/haproxy.log
& stop
EOF

cp /docker/haproxy/keepalived.conf /etc/keepalived/keepalived.conf

{% set _priority = (VRRP_PRIORITY_INDEX - groups['haproxy_mgmt_ip'].index(inventory_hostname)) %}

export HAPROXY_PRIORITY={{ _priority }}
export EXTERNAL_VIP_INTERFACE={{ VIP_INTERFACE }}
export INTERNAL_VIP_INTERFACE={{ MGMT_VIP_INTERFACE }}

ka_conf=/etc/keepalived/keepalived.conf
sed -i '
    s|@VIP_INTERFACE@|'"$EXTERNAL_VIP_INTERFACE"'|g
    s|@VIP_IP_ADDRESS@|'"$external_lb_vip_address"/{{ api_cidr }}'|g
    s|@HAPROXY_PRIORITY@|'"$HAPROXY_PRIORITY"'|g
    s|@VIRTUAL_ROUTER_ID@|'"${VIRTUAL_ROUTER_ID}"'|g
    s|@HAPROXY_STATE@|'"${HAPROXY_STATE}"'|g
    s|@MGMT_VIP_INTERFACE@|'"$INTERNAL_VIP_INTERFACE"'|g
    s|@MGMT_VIP_IP_ADDRESS@|'"$internal_lb_vip_address"/{{ control_cidr }}'|g
' $ka_conf

{% if api_ipv6_subnet_len is defined and api_ipv6_subnet_len != "" %}
sed -i 's|@VIP_IPV6_ADDRESS@|'"$external_lb_vip_ipv6_address"/{{ api_ipv6_subnet_len }}'|g' $ka_conf
{% endif %}
{% if mgmt_ipv6_subnet_len is defined and mgmt_ipv6_subnet_len != "" %}
sed -i 's|@MGMT_VIP_IPV6_ADDRESS@|'"$internal_lb_vip_ipv6_address"/{{ mgmt_ipv6_subnet_len }}'|g' $ka_conf
{% endif %}

# setting unique primary address for vrrp use from the internal subnet
ip addr replace {{ VRRP_INTERNAL_SUBNET | ipaddr(_priority) }} dev {{ MGMT_VIP_INTERFACE }}


exec /usr/bin/supervisord -c /etc/supervisord.conf

