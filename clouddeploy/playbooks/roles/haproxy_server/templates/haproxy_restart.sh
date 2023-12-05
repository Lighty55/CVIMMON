#!/bin/bash

CONTAINER="haproxy_{{ docker.haproxy.image_tag }}";
docker start $CONTAINER  > /dev/null 2>&1

lo_created=False
{% raw %}
for i in `seq 1 50`; do
    if [ "`docker inspect -f {{.State.Running}} $CONTAINER 2>/dev/null`" == "true" ]; then
        check_lo=$(docker exec $CONTAINER ip link show lo)
        if [[ $check_lo ]]; then
            lo_created=True
            break
        fi
    fi
    sleep 0.1
done;
{% endraw %}

if [[ ${lo_created} == False ]]; then
    exit 1
fi

dangling_mgmt=$(ip link | grep mgmt-out)
if [[ ${dangling_mgmt} ]]; then
    ip link del dev mgmt-out
fi

dangling_api=$(ip link | grep api-out)
if [[ ${dangling_api} ]]; then
    ip link del dev api-out
fi

mgmt_created=False
mgmt_mtu=$(ip link show br_mgmt | awk 'match($0,/mtu ([0-9]+)/,mtu) {print mtu[1]}')
{% raw %}
for i in `seq 1 3`; do
    ip link add mgmt-out mtu ${mgmt_mtu} type veth peer name mgmt-in
    ip link set mgmt-out mtu ${mgmt_mtu} up
    check_mgmt=$(ip link | grep mgmt-out | grep UP)
    if [[ $check_mgmt ]]; then
        brctl addif br_mgmt mgmt-out
        mgmt_created=True
        break
    fi
    sleep 0.1
done;
{% endraw %}

if [[ ${mgmt_created} == False ]]; then
    exit 1
fi

api_created=False
api_mtu=$(ip link show br_api | awk 'match($0,/mtu ([0-9]+)/,mtu) {print mtu[1]}')
{% raw %}
for i in `seq 1 3`; do
    ip link add api-out mtu ${api_mtu} type veth peer name api-in
    ip link set api-out mtu ${api_mtu} up
    check_api=$(ip link | grep api-out | grep UP)
    if [[ $check_api ]]; then
        brctl addif br_api api-out
        api_created=True
        break
    fi
    sleep 0.1
done;
{% endraw %}

if [[ ${api_created} == False ]]; then
    exit 1
fi

{% raw %}
pid=$(docker inspect -f '{{.State.Pid}}' `docker ps -a |  grep $CONTAINER  | awk '{print $1}'`)
{% endraw %}

mkdir -p /var/run/netns
rm -rf /var/run/netns/haproxy-*
restorecon /var/run/netns
ln -s /proc/$pid/ns/net /var/run/netns/haproxy-$pid

api_up=False
ip link set api-in netns haproxy-$pid
ip netns exec haproxy-$pid ip link set dev api-in name api
{% raw %}
for i in `seq 1 3`; do
    docker exec $CONTAINER ip link set api up
    check_api=$(docker exec $CONTAINER ip link | grep api | grep UP)
    if [[ ${check_api} ]]; then
        api_up=True
        break
    fi
    sleep 0.1
done;
{% endraw %}
if [[ ${api_up} == False ]]; then
    exit 1
fi

ip link set mgmt-in netns haproxy-$pid
ip netns exec haproxy-$pid ip link set dev mgmt-in name mgmt
mgmt_up=False
{% raw %}
for i in `seq 1 3`; do
    docker exec $CONTAINER ip link set mgmt up
    check_mgmt=$(docker exec $CONTAINER ip link | grep mgmt | grep UP)
    if [[ ${check_mgmt} ]]; then
        mgmt_up=True
        break
    fi
    sleep 0.1
done;
{% endraw %}
if [[ ${mgmt_up} == False ]]; then
    exit 1
fi

cp `which arping` /docker/haproxy/
cp `which ping` /docker/haproxy/

docker exec $CONTAINER  /docker/haproxy/haproxy_start.sh
