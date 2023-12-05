import yaml
import sys

update_scope = sys.argv[1]
build_node_containers = ["dockbler-web",
                         "dockbler-rhel-7-server-optional-rpms",
                         "dockbler-cisco-rhel-server-7-openstack-13-plus-hotfix-rpms",
                         "dockbler-rhel-7-server-rpms",
                         "dockbler-rhel-7-server-extras-rpms",
                         "dockbler-rhel-ha-for-rhel-7-server-rpms",
                         "dockbler-repofiles",
                         "dockbler-mercury-cvim-k8s-rpms",
                         "dockbler-mercury-buildnode-rpms",
                         "dockbler-mercury-calipso-rpms",
                         "dockbler-rhel-7-server-rh-common-rpms",
                         "dockbler-mercury-common-rpms"]

with open(update_scope, "r") as f:
    data = f.read()
    containers_to_be_updated = yaml.safe_load(data)

    if set(containers_to_be_updated).intersection(set(build_node_containers)):
        print "update_repo"
