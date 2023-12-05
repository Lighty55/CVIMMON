"""
Module to render/generate cvim_mon_ha.yaml in several scenarios
1. During deployment direct jinja2 rendering
2. For update generate a consolidated cvim_mon_ha.yaml from old and new workspace
3. For upgrade generate a consolidated cvim_mon_ha.yaml which accounts for non upgradable
containers (ex: docker registry, data containers)
4. For reconfigure to bring in new service when needed
Module needs to be idempotent on reruns
"""

import jinja2
import os
import yaml
import shutil

from optparse import OptionParser


def render_template(template_file, cfg_values, destination_file=None):
    """
        Render template at specified destionation
    """
    template_loader = jinja2.FileSystemLoader(searchpath="/")
    template_env = jinja2.Environment(loader=template_loader, autoescape=True)
    template_cfg = template_env.get_template(os.path.abspath(template_file))

    if destination_file:
        with open(destination_file, "wb") as f:
            f.write(template_cfg.render(cfg_values))

    return template_cfg.render(cfg_values)


def render_docker_yaml(workspace, managementip, destination_file=None):
    """
        Simple cvim_mon_ha.yaml rendering
    """
    with open(workspace + "openstack-configs/defaults.yaml", "r") as f:
        defaults_data = f.read()
        defaults_file = yaml.safe_load(defaults_data)

    # Regular deployment just render with no merge
    with open(workspace + "openstack-configs/setup_data.yaml", "r") as f:
        setup_data = f.read()
        setup_file = yaml.safe_load(setup_data)

    if 'REGISTRY_NAME' in setup_file:
        registry = setup_file['REGISTRY_NAME']
    else:
        registry = defaults_file['registry']

    cfg_values = {"namespace": defaults_file["namespace"],
                  "management_node_ip": managementip,
                  "image_tag": defaults_file["image_tag"],
                  }

    docker_yaml_template = \
        "bootstrap/k8s-infra/bootstrap_infra/playbooks/roles/common/templates/cvim_mon_ha.yaml.template"
    if destination_file:
        return render_template(workspace + docker_yaml_template,
                               cfg_values,
                               destination_file)
    else:
        return render_template(workspace + docker_yaml_template,
                               cfg_values)


def generate_docker_yaml(deploy_action, old_workspace, new_workspace,
                         managementip):
    """
        Function to generate cvim_mon_ha.yaml for different deployment
        scenarios
    """

    if not deploy_action:
        render_docker_yaml(new_workspace, managementip,
                           new_workspace + "openstack-configs/cvim_mon_ha.yaml")

    elif deploy_action in ["update", "rollback"]:

        # during update:
        # old_workspace = starting workspace
        # new_workspace = destination workspace where update is going to run
        # during rollback:
        # old_workspace = starting workspace where update ran,rollback will run
        # new_workspace = destination workspace
        with open(old_workspace + "openstack-configs/cvim_mon_ha.yaml", "r") as f:
            olddocker_file = yaml.safe_load(f)

        if deploy_action == "rollback":
            # during rollback, we don't have to generate cvim_mon_ha.yaml
            # load the old cvim_mon_ha.yaml in that workspace
            with open(new_workspace + "openstack-configs/cvim_mon_ha.yaml", "r") as f:
                newdocker_file = yaml.safe_load(f)
        else:
            # during update, the destination workspace doesn't have a docker
            # yaml. So, render it.
            newdocker_data = render_docker_yaml(new_workspace, managementip)
            newdocker_file = yaml.safe_load(newdocker_data)

        with open(new_workspace + "container_property.yaml", "r") as f:
            new_prop_file = yaml.safe_load(f)

        # only the workspace where update ran will have the update_scope.yaml
        ws = new_workspace
        if deploy_action == "rollback":
            ws = old_workspace
        with open(ws + "openstack-configs/update_scope.yaml", "r") as f:
            scope_file = yaml.safe_load(f)

        with open(new_workspace + "openstack-configs/defaults.yaml", "r") as f:
            new_defaults_file = yaml.safe_load(f)

        no_rollback = new_prop_file.get('NO_ROLLBACK_CONTAINERS')
        marker = "/opt/cisco/update/completed_repo"

        # Start with the new cvim_mon_ha.yaml first
        for image in newdocker_file["docker"]:
            # no update/rollback/commit for this image
            if image == "common":
                continue

            # ignore this, just an assignment
            new_dkfile_image = newdocker_file["docker"][image]
            if 'type' in new_dkfile_image and new_dkfile_image['type'] == "cvimmonha_image":
                continue
            old_dkfile_image = None
            if image in olddocker_file["docker"]:
                old_dkfile_image = olddocker_file["docker"][image]

            # during any action other than rollback, once the new cvim_mon_ha.yaml
            # is rendered, we first have to make it look just like the old
            # docker yaml. The reason why we do this way instead of just
            # reading the old docker yaml is, because the new docker yaml might
            # be bringing in new containers and if we just use the old docker
            # yaml then we wont bring in the new changes/containers. once we
            # restore the new docker yaml as old, the new docker yaml will be
            # new_docker_yaml = old_docker_yaml + new_containers (if any)
            if deploy_action != "rollback" and image in olddocker_file["docker"]:
                new_dkfile_image["image_tag"] = old_dkfile_image["image_tag"]
                if '/' in old_dkfile_image["name"] and '/' in new_dkfile_image["name"]:
                    new_dkfile_image["name"] = old_dkfile_image["name"].split('/')[0] + \
                                               '/' + new_dkfile_image["name"].split('/')[1]
                else:
                    new_dkfile_image["name"] = old_dkfile_image["name"]

            # Now just process the containers that are found in the scope file.
            # only these containers will be updated/rolled back/committed.
            for updated_image in scope_file:
                if '/' in new_dkfile_image["name"]:
                    new_docker_image = new_dkfile_image["name"].split('/')[1]
                else:
                    new_docker_image = new_dkfile_image["name"]

                if updated_image == new_docker_image:
                    if deploy_action == "rollback":
                        # during rollback:
                        # we don't support rollback for certain containers
                        # that are defined in NO_ROLLBACK_CONTAINERS of
                        # container_property.yaml. So, during rollback if
                        # the image name matches with the no_rollback_container
                        # We do not change the tag back to old one.
                        if updated_image in no_rollback:
                            marker_file = marker + "/" + updated_image
                            if os.path.isfile(marker_file) and old_dkfile_image:
                                # If this path file exists, it means that the
                                # no_rollback_container was never updated
                                # successfully in the first place. So,
                                # don't change the new cvim_mon_ha.yaml tag.
                                # Just use the old image_tag.
                                current_tag = old_dkfile_image["image_tag"]
                                current_image = old_dkfile_image["name"]
                                new_dkfile_image["image_tag"] = current_tag
                                new_dkfile_image["name"] = current_image
                            else:
                                # the update of no_rollback container has
                                # happened successfully. So do not change
                                # the tag back to the old one. Just leave it
                                # as it is.
                                pass
                        else:
                            # updated image is not in no_rollback
                            # So, can be rolled back. Now for the tag,
                            # just look at the workspace where we are rolling
                            #  back to.
                            # old_tag = new_dkfile_image["image_tag"]
                            # old_image = new_dkfile_image["name"]
                            # new_dkfile_image["image_tag"] = old_tag
                            # new_dkfile_image["name"] = old_image
                            pass
                    else:
                        # during update/commit:
                        # Now for each container that is going to be updated
                        # (list of containers from update_scope.yaml in the
                        # new_workspace) change the tag in the new cvim_mon_ha.yaml.
                        # old_tag -> new_tag
                        # In order to render the new cvim_mon_ha.yaml with the new
                        # tag, we refer to the current/destination workspace
                        # defaults.yaml.
                        new_tag = new_defaults_file["image_tag"]
                        new_image = new_dkfile_image["name"].split('/')[0] + "/" +\
                                    updated_image
                        new_dkfile_image["image_tag"] = new_tag
                        new_dkfile_image["name"] = new_image

        # finally write the docker yaml in memory to the workspace
        # new_workspace changes depending on update/rollback
        # just refer to the comments above to see where that will be.
        with open(new_workspace + "/openstack-configs/cvim_mon_ha.yaml", 'w') as doc:
            doc.write(yaml.dump(newdocker_file, default_flow_style=False))

        # remove repo marker file which was created by the ansible playbook
        # repo_container_start.yaml when the repo containers were updated.
        if deploy_action == "rollback" and os.path.exists(marker):
            shutil.rmtree(marker)

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-a", "--action", dest="install_action",
                      help="The install action")
    parser.add_option("-o", "--oldworkspace", dest="old_ws",
                      help="Old workspace location(used for update)")
    parser.add_option("-n", "--workspace", dest="current_ws",
                      help="Path to workspace")
    parser.add_option("-m", "--managementip", dest="mgmt_ip",
                      help="Management node ip address")
    (options, args) = parser.parse_args()
    generate_docker_yaml(options.install_action, options.old_ws,
                         options.current_ws, options.mgmt_ip)
