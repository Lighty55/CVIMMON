import os
import yaml
import sys

def gen_update_scope(old_cfg_dir, new_cfg_dir):
    chg_mfest = "change_manifest.yaml"
    container_property = new_cfg_dir + "/../container_property.yaml"
    containers_super_set = None
    if os.path.isfile(container_property):
        with open(container_property, "r") as f:
            containers_super_set = yaml.safe_load(f)
            no_update_containers = \
                containers_super_set.get("NO_UPDATE_CONTAINERS")
    if not os.path.exists(os.path.join(old_cfg_dir, chg_mfest)) \
            or not os.path.exists(os.path.join(new_cfg_dir, chg_mfest)):
        containers = ["dockbler-web", "dockbler-repofiles",
                      "dockbler-mercury-common-rpms",
                      "dockbler-mercury-buildnode-rpms",
                      "dockbler-mercury-calipso-rpms",
                      "dockbler-rhel-7-server-rpms",
                      "dockbler-rhel-7-server-extras-rpms",
                      "dockbler-rhel-7-server-optional-rpms",
                      "dockbler-cisco-rhel-server-7-openstack-13-plus-hotfix-rpms",
                      "dockbler-rhel-7-server-rh-common-rpms",
                      "dockbler-rhel-ha-for-rhel-7-server-rpms",
                      "dockbler-mercury-cvim-k8s-rpms",
                      "etcd", "argus-agent", "argus-rest-api",
                      "log-rotate", "snmp", "cvim_mon",
                      "calipso_api", "calipso_mongo"]
    else:
        with open(os.path.join(old_cfg_dir, "change_manifest.yaml"), "a+") as f:
            data = f.read()
            old_manifest = yaml.safe_load_all(data)

        with open(os.path.join(new_cfg_dir, "change_manifest.yaml"), "a+") as f:
            data = f.read()
            new_manifest = yaml.safe_load_all(data)

        new_manifest_dict = {}
        [new_manifest_dict.update(review) for review in new_manifest]

        for review in old_manifest:
            new_manifest_dict.pop(review.keys()[0], None)

        containers_for_update = []
        for val in new_manifest_dict.values():
            containers_for_update.extend(val)

        containers = set(containers_for_update).\
            difference(set(no_update_containers))

    with open(os.path.join(new_cfg_dir, "update_scope.yaml"), "w+") as f:
        f.write(yaml.dump(list(containers), default_flow_style=False))

if __name__ == "__main__":
    gen_update_scope(sys.argv[1], sys.argv[2])
