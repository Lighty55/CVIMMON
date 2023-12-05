import horizon
from openstack_dashboard import policy
from openstack_dashboard.dashboards.identity.users import tables as users
from openstack_dashboard.dashboards.project.images.images import tables as images
from openstack_dashboard.dashboards.project.instances import tables as instances
{% if OPENSTACK_READONLY_ROLE|bool %}
from openstack_dashboard.dashboards.readonly.instances import panel
{% endif %}


original_allow_detach = instances.DetachInterface.allowed
original_allow_update_metadata = images.UpdateMetadata.allowed
original_allow_launch = images.LaunchImage.allowed


def allow_detach(self, request, instance=None):
    policy_rules = (("compute", "compute:detach_interfaces"),)
    if not policy.check(policy_rules, request):
        return False
    else:
        return original_allow_detach(self, request, instance)


def allow_update_metadata(self, request, image=None):
    policy_rules = (("compute", "compute:update_instance_metadata"),)
    if not policy.check(policy_rules, request):
        return False
    else:
        return original_allow_update_metadata(self, request, image)


def allow_launch(self, request, image=None):
    policy_rules = (("compute", "compute:create"),)
    if not policy.check(policy_rules, request):
        return False
    else:
        return original_allow_launch(self, request, image)


def allow_change_password(self, request, user=None):
    cvim_managed_users = ['admin', 'cinder', 'glance', 'heat',
                          'heat_domain_admin', 'neutron', 'nova',
                          'placement', 'cloudpulse']
    if user and user.name in cvim_managed_users:
        return False
    else:
        return True


instances.DetachInterface.allowed = allow_detach
images.UpdateMetadata.allowed = allow_update_metadata
images.LaunchImage.allowed = allow_launch
users.ChangePasswordLink.allowed = allow_change_password


def allow_password_change_panel(context):
    cvim_managed_users = ['admin', 'cinder', 'glance', 'heat',
                          'heat_domain_admin', 'neutron', 'nova',
                          'placement', 'cloudpulse']
    request = context['request']
    if request.user.username in cvim_managed_users:
        return False
    return True


settings = horizon.get_dashboard("settings")
password_panel = settings.get_panel("password")
password_panel.allowed = allow_password_change_panel
