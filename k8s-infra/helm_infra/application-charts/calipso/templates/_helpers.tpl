{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "calipso.name" -}}
{{- default .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create unified labels for calipso components
*/}}
{{- define "calipso.common.matchLabels" -}}
app: {{ template "calipso.name" . }}
release: {{ .Release.Name | quote }}
{{- end -}}
{{- define "calipso.common.metaLabels" -}}
chart: {{ .Chart.Name }}-{{ .Chart.Version }}
heritage: {{ .Release.Service }}
{{- end -}}


{{- define "calipso.calipsoApi.labels" -}}
{{ include "calipso.common.matchLabels" . }}
{{ include "calipso.common.metaLabels" . }}
{{- end -}}
{{- define "calipso.calipsoApi.matchLabels" -}}
component: {{ .Values.calipsoApi.name | quote }}
{{ include "calipso.common.matchLabels" . }}
{{- end -}}

{{- define "calipso.calipsoMongo.labels" -}}
{{ include "calipso.common.matchLabels" . }}
{{ include "calipso.common.metaLabels" . }}
{{- end -}}
{{- define "calipso.calipsoMongo.matchLabels" -}}
component: {{ .Values.calipsoMongo.name | quote }}
{{ include "calipso.common.matchLabels" . }}
{{- end -}}

{{/*
Create a fully qualified calipso-api name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}

{{- define "calipso.calipsoApi.fullname" -}}
{{- if .Values.calipsoApi.fullnameOverride -}}
{{- .Values.calipsoApi.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.calipsoApi.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.calipsoApi.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create a fully qualified calipso-mongo name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}

{{- define "calipso.calipsoMongo.fullname" -}}
{{- if .Values.calipsoMongo.fullnameOverride -}}
{{- .Values.calipsoMongo.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.calipsoMongo.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.calipsoMongo.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "calipso.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}
