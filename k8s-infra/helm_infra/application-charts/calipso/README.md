# Calipso

Learn about Calipso [here](https://calipso.io/)

## TL;DR

```console
$ helm install calipso
```

## Introduction

This chart bootstraps a [Calipso](https://calipso.io/) deployment on a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

## Prerequisites

Tested with Helm version 2.10, Docker version 17.03, Kubernetes version 1.9.7, many other variances using kubernetes > 1.8 should work too

## Installing the Chart

To install the chart with the release name `my-release`:

```console
$ helm install --name my-release calipso
```

The command deploys Calipso on the Kubernetes cluster in the default configuration. The [configuration](#configuration) section lists the parameters that can be configured during installation.


## Uninstalling the Chart

To uninstall/delete the `my-release` deployment:

```console
$ helm delete my-release
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Upgrading from previous chart versions.

To be described

## Configuration

The following table lists the notable configurable parameters of the Calipso chart and their default values.

Parameter | Description | Default
--------- | ----------- | -------
`calipsoApi.image.repository`| calipso-api container image repository | `cloud-docker.cisco.com/cvim34-rhel7-osp13/calipso-api`
`calipsoApi.image.tag` | calipso-api container image tag | `9999`
`calipsoApi.deploymentStrategy` | calipso-api pod deployment strategy | `Recreate`
`calipsoApi.persistentVolume.enabled` | If `true`, calipso-api will create a Persistent Volume Claim | `false`
`calipsoApi.persistentVolume.accessModes` | calipso-api data Persistent Volume access modes | `[ReadWriteMany]`
`calipsoApi.persistentVolume.annotations` | Annotations for calipso-api Persistent Volume Claim | `{}`
`calipsoApi.persistentVolume.existingClaim` | calipso-api data Persistent Volume existing claim name | `""`
`calipsoApi.persistentVolume.mountPath` | calipso-api data Persistent Volume mount root path | `/data`
`calipsoApi.persistentVolume.size` | calipso-api data Persistent Volume size | `1Gi`
`calipsoApi.persistentVolume.storageClass` | calipso-api data Persistent Volume Storage Class | `portworx-sc`
`calipsoApi.persistentVolume.subPath` | Subdirectory of calipso-api data Persistent Volume to mount | `""`
`calipsoApi.replicas` | desired number of calipso-api pods | `1`
`calipsoApi.service.type` | type of calipso-api service | `ClusterIP`
`calipsoApi.service.servicePort` | calipso-api service port | `8747`
`calipsoApi.ingress.enabled` | If true, calipso-api Ingress will be created | `true`
`calipsoApi.ingress.annotations` | calipso-api Ingress annotations | `{}`
`calipsoApi.ingress.extraLabels` | calipso-api Ingress additional labels | `{}`
`calipsoApi.ingress.hosts` | calipso-api Ingress hostnames | `[]`
`calipsoApi.ingress.tls` | calipso-api Ingress TLS configuration (YAML) | `[]`
`calipsoMongo.image.repository`| calipso-mongo container image repository | `cloud-docker.cisco.com/cvim34-rhel7-osp13/calipso-mongo`
`calipsoMongo.image.tag` | calipso-mongo container image tag | `9999`
`calipsoMongo.deploymentStrategy` | calipso-mongo pod deployment strategy | `Recreate`
`calipsoMongo.persistentVolume.enabled` | If `true`, calipso-mongo will create a Persistent Volume Claim | `true`
`calipsoMongo.persistentVolume.accessModes` | calipso-mongo data Persistent Volume access modes | `[ReadWriteMany]`
`calipsoMongo.persistentVolume.annotations` | Annotations for calipso-mongo Persistent Volume Claim | `{}`
`calipsoMongo.persistentVolume.existingClaim` | calipso-mongo data Persistent Volume existing claim name | `""`
`calipsoMongo.persistentVolume.mountPath` | calipso-mongo data Persistent Volume mount root path | `/data`
`calipsoMongo.persistentVolume.size` | calipso-mongo data Persistent Volume size | `100Gi`
`calipsoMongo.persistentVolume.storageClass` | calipso-mongo data Persistent Volume Storage Class | `portworx-sc`
`calipsoMongo.persistentVolume.subPath` | Subdirectory of calipso-mongo data Persistent Volume to mount | `""`
`calipsoMongo.replicas` | desired number of calipso-mongo pods | `1`
`calipsoMongo.service.type` | type of calipso-mongo service | `ClusterIP`
`calipsoMongo.service.servicePort` | calipso-mongo service port | `27017`
`calipsoMongo.ingress.enabled` | If true, calipso-mongo Ingress will be created | `true`
`calipsoMongo.ingress.annotations` | calipso-mongo Ingress annotations | `{}`
`calipsoMongo.ingress.extraLabels` | calipso-mongo Ingress additional labels | `{}`
`calipsoMongo.ingress.hosts` | calipso-mongo Ingress hostnames | `[]`
`calipsoMongo.ingress.tls` | calipso-mongo Ingress TLS configuration (YAML) | `[]`
`calipsoApiConfig.configDir` | calipso-api config directory | `/var/lib/calipso`
`calipsoApiConfig.bind` | calipso-api server bind port | `8747`
`calipsoApiConfig.user` | calipso-api username | `calipso`
`calipsoApiConfig.certFilename` | calipso-api TLS certificate filename (without extension) | `calipso`
`calipsoApiConfig.secretName` | calipso-api auth secret name | `calipso-api-auth-k8s`
`calipsoMongoConfig.configDir` | calipso-mongo config directory | `/var/lib/calipso`
`calipsoMongoConfig.authDb` | calipso-mongo auth database | `calipso`
`calipsoMongoConfig.host` | calipso-mongo service hostname for internal access | `calipso-mongo.calipso.svc.cluster.local`
`calipsoMongoConfig.user` | calipso-mongo database user | `calipso`
`calipsoMongoConfig.pwd` | calipso-mongo database password | `none`
`calipsoMongoConfig.certFilename` | calipso-mongo TLS certificate filename (without extension) | `calipso`
`calipsoMongoConfig.secretName` | calipso-mongo auth secret name | `calipso-mongo-auth-k8s`

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`. For example,

```console
$ helm install calipso --name my-release \
    --set calipsoApi.deploymentStrategy=RollingUpdate
```

Alternatively, a YAML file that specifies the values for the above parameters can be provided while installing the chart. For example,

```console
$ helm install calipso --name my-release -f values.yaml
```
