# Ansible Playbooks To setup Kubernetes HA on Redhat Enterprise Linux 7 for CVIM-MON-HA and Unified Management Node.

* This repository provides Ansible Playbooks To setup Kubernetes HA on Redhat Enterprise Linux 7 which includes
  * Install etcd in HA mode (host based install)
  * Installs Keepalived on all the listed masters, configures the VIP
  * Installs Calico as CNI

#Prerequisites:

RHEL 7.2+
Install python pip:
```
wget http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
rpm -ivh epel-release-latest-7.noarch.rpm
yum install python-pip
```


Install ansible on your manager machine that has ssh access to all the other machines

* You can do:
```
pip install ansible
```

* Setup ssh access from master to workers.
* Setup ssh access from first master to the other masters (optional to be able to use scp)

# Environment preparation:

* Clone the repo:
 In the machine that you want to use as ansible master (can be your laptop or any other machine that has ssh access to the target machines):
 ```
 git clone <current_repo>
 ```

* Create inventory/mycluster
and declare your machines such as:
```
myhostname.domain.com ansible_usehost=<ip> ansible_user=<user>
```

There are different groups being defined and used, you can reuse mycluster file defined in inventory folder:
```
[all-masters] # these are all the masters
[all-workers] # these are all the worker nodes
[all-vms] # these are all vms/machines/servers of the cluster
```


You can check that you can ping all the machines:

```
ansible -m ping all -i inventory/mycluster
```
# Install a highly available kubernetes using kubeadm

You can now run k8s-all playbook to get your cluster setup.
You can also run the different playbooks separately for different purposes (setting up docker, etcd, keepalived, kubeadm ...).

```
ansible-playbook -i inventory/mycluster  playbooks/k8s-all.yaml
```

# What k8s-all.yaml includes:

- Installing docker
- Generating etcd certificates and installing ha etcd cluster on all the master nodes
- Installing keepalived and setting up vip management
- Installing kubeadm, kubelet and kubectl
- Setting up kubernetes masters
- Adding the nodes to the cluster
- Reconfiguring the nodes and components to use the vip

# Restarting the install:

If you need to restart the process using kubeadm reset, please use the cleanup-all-vms playbook that deletes the state from all vms. Some of the commands might fail but you can ignore that.

# Encrypting Secrets at rest:

If you want to add an extra layer of securing your secrets by encrypting them at rest you can use the "encrypting-secrets.yaml playbook". You can add it to the k8s-all.yaml or use it separately.

Before using it, update the inventory file to change the encryption key variable "encoded_secret".
To generate a new encryption key you can do the following:

```
head -c 32 /dev/urandom | base64
```
Copy the output and save it in the inventory variable.

After that run the playbook:

```
ansible-playbook -i inventory/mycluster  playbooks/encrypting-secrets.yaml
```

# Upgrading Kubernetes and Kubelet

Mention the Upgrade Version for Kubeadm and Kubelet in the playbook file.

```
ansible-playbook -i inventory/mycluster_sample playbooks/kubeadm-upgrade.yaml
```

# TO_DO

* Clean and Polish
* Implement Istio and Weave Scope Roles
