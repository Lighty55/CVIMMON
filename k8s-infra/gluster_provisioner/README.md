# gluster-kubernetes

## Prerequisites for a Kubernetes Cluster

This project includes a vagrant setup in the `vagrant/` directory to spin up a
Kubernetes cluster in VMs. To run the vagrant setup, you'll need to have the
following pre-requisites on your machine:

 * 4GB of memory
 * 32GB of storage minimum, 112GB recommended
 * ansible
 * vagrant
 * libvirt or VirtualBox

Next, copy the `deploy/` directory to the master node of the cluster.

You will have to provide your own topology file. A sample topology file is
included in the `deploy/` directory (default location that gk-deploy expects)
which can be used as the topology for the vagrant libvirt setup. When
creating your own topology file:

 * Make sure the topology file only lists block devices intended for heketi's
 use. heketi needs access to whole block devices (e.g. /dev/sdb, /dev/vdb)
 which it will partition and format.

 * The `hostnames` array is a bit misleading. `manage` should be a list of
 hostnames for the node, but `storage` should be a list of IP addresses on
 the node for backend storage communications.

At this point, verify the Kubernetes installation by making sure all nodes are
Ready:

```bash
$ kubectl get nodes
NAME      STATUS    AGE
master    Ready     22h
node0     Ready     22h
node1     Ready     22h
node2     Ready     22h
```

**NOTE**: To see the version of Kubernetes (which will change based on
latest official releases) simply do `kubectl version`. This will help in
troubleshooting.

Next, to deploy heketi and GlusterFS, run the following:

```bash
$ ./gk-deploy -g
```

If you already have a pre-existing GlusterFS cluster, you do not need the
`-g` option.

After this completes, GlusterFS and heketi should now be installed and ready
to go. You can set the `HEKETI_CLI_SERVER` environment variable as follows so
that it can be read directly by `heketi-cli` or sent to something like `curl`:

```bash
$ export HEKETI_CLI_SERVER=$(kubectl get svc/heketi --template 'http://{{.spec.clusterIP}}:{{(index .spec.ports 0).port}}')

$ echo $HEKETI_CLI_SERVER
http://10.42.0.0:8080

$ curl $HEKETI_CLI_SERVER/hello
Hello from Heketi
```

Your Kubernetes cluster should look something like this:

```bash
$ kubectl get nodes,pods
NAME      STATUS    AGE
master    Ready     22h
node0     Ready     22h
node1     Ready     22h
node2     Ready     22h
NAME                               READY     STATUS              RESTARTS   AGE
glusterfs-node0-2509304327-vpce1   1/1       Running             0          1d
glusterfs-node1-3290690057-hhq92   1/1       Running             0          1d
glusterfs-node2-4072075787-okzjv   1/1       Running             0          1d
heketi-3017632314-yyngh            1/1       Running             0          1d
```

You should now also be able to use `heketi-cli` or any other client of the
heketi REST API (like the GlusterFS volume plugin) to create/manage volumes and
then mount those volumes to verify they're working. To see an example of how
to use this with a Kubernetes application, see the following:

[Hello World application using GlusterFS Dynamic Provisioning](./docs/examples/hello_world/README.md)

## Storage Class Example

```
---
apiVersion: storage.k8s.io/v1beta1
kind: StorageClass
metadata:
  name: glusterfs-storage
provisioner: kubernetes.io/glusterfs
parameters:
  resturl: "http://192.168.2.87:8080"
```

resturl in the manifest above refers to the Service:Cluster_IP of the heketi svc

```
[root@maverick-kube1 ~]# kubectl get svc | grep hek
heketi                                                  ClusterIP   10.101.26.11     <none>        8080/TCP                     17d
```
