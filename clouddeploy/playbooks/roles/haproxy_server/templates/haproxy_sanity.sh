#!/bin/bash

haproxy_status="Down"
for i in `seq 1 12`; do
    haproxy_pid=$(docker exec haproxy_{{ docker.haproxy.image_tag }} ps -C haproxy -o pid=)
    if [[ ${haproxy_pid} ]]; then
        haproxy_status="Up"
        break
    fi
    sleep 5
done;

if [[ $haproxy_status == "Down" ]]; then
    echo "FAIL"
    docker kill haproxy_{{ docker.haproxy.image_tag }}
fi

docker exec -u root haproxy_{{ docker.haproxy.image_tag }} ls /run/MASTER > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    api=$(docker exec haproxy_{{ docker.haproxy.image_tag }} ip a show | grep api | grep {{ external_lb_vip_address }})
    if [[ -z ${api} ]]; then
        echo "FAIL"
        docker kill haproxy_{{ docker.haproxy.image_tag }}
    fi

    mgmt=$(docker exec haproxy_{{ docker.haproxy.image_tag }} ip a show | grep  mgmt | grep {{ internal_lb_vip_address }})
    if [[ -z ${mgmt} ]]; then
        echo "FAIL"
        docker kill haproxy_{{ docker.haproxy.image_tag }}
    fi
fi

docker exec -u root haproxy_{{ docker.haproxy.image_tag }} ls /run/BACKUP > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    api=$(docker exec haproxy_{{ docker.haproxy.image_tag }} ip a show | grep api)
    if [[ -z ${api} ]]; then
        echo "FAIL"
        docker kill haproxy_{{ docker.haproxy.image_tag }}
    fi
    mgmt=$(docker exec haproxy_{{ docker.haproxy.image_tag }} ip a show | grep  mgmt)
    if [[ -z ${mgmt} ]]; then
        echo "FAIL"
        docker kill haproxy_{{ docker.haproxy.image_tag }}
    fi
fi
