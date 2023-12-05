import sys
import os
import apic_api as apic_api
class APICInterface(object):
    """
    Interface to APIC operations
    """
    def __init__(self, module):
        self.module = module
        self.apic_ip = module.params["apic_ip"]
        self.apic_username = module.params["apic_username"]
        self.apic_password = module.params["apic_password"]
        self.action = module.params["action"]
        if self.action == "associate_vmm_aep":
            self.vmm_domain = module.params["vmm_domain"]
            self.aep_name = module.params["aep_name"]
        if self.action == "configure_tenant_vlan_pools":
            self.vlan_name = module.params['vlan_name']
            self.vlan_ranges = module.params['vlan_ranges']
        self.api_handle = apic_api.APICAPI(self.apic_ip,
                                           self.apic_username,
                                           self.apic_password)
        self.api_handle.do_login()

    def associate_vmm_aep(self):
        """
        Associate a VMM domain with aep
        """
        self.api_handle.associate_vmm_aep(self.aep_name, self.vmm_domain)

    def configure_tenant_vlan_pools(self):
        """
        CSCvf87851:
        Workaround until AIM plugin provides fix to support multiple segments
        """
        self.api_handle.configure_additional_tenant_vlans(self.vlan_name, self.vlan_ranges)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            apic_ip=dict(required=True, type='list'),
            apic_username=dict(required=True, type='str'),
            apic_password=dict(required=True, type='str'),
            action=dict(choices=['associate_vmm_aep',
                                 'configure_tenant_vlan_pools']),
            vmm_domain=dict(type="str"),
            aep_name=dict(type="str"),
            vlan_name=dict(type="str"),
            vlan_ranges=dict(type="str")
        ),
    )
    apic_api_handle = APICInterface(module)

    if module.params["action"] == "associate_vmm_aep":
        if not module.params["vmm_domain"]:
            module.fail_json(msg="VMM domain not specified")
        if not module.params["aep_name"]:
            module.fail_json(msg="AEP Name not specified")
        apic_api_handle.associate_vmm_aep()
        module.exit_json(changed=True,
                                  msg="VMM domain associated with AEP")

    if module.params["action"] == "configure_tenant_vlan_pools":
        if not module.params["vlan_name"]:
            module.fail_json(msg="VLAN name not specified")
        if not module.params["vlan_ranges"]:
            module.fail_json(msg="VLAN range not specified")
        apic_api_handle.configure_tenant_vlan_pools()
        module.exit_json(changed=True,
                         msg="Tenant VLAN range configured")

from ansible.module_utils.basic import *
main()
