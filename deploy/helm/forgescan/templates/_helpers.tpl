{{/*
Expand the name of the chart.
*/}}
{{- define "forgescan.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "forgescan.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "forgescan.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "forgescan.labels" -}}
helm.sh/chart: {{ include "forgescan.chart" . }}
{{ include "forgescan.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: forgescan-platform
{{- end }}

{{/*
Selector labels
*/}}
{{- define "forgescan.selectorLabels" -}}
app.kubernetes.io/name: {{ include "forgescan.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
API labels
*/}}
{{- define "forgescan.api.labels" -}}
{{ include "forgescan.labels" . }}
app.kubernetes.io/component: api
{{- end }}

{{- define "forgescan.api.selectorLabels" -}}
{{ include "forgescan.selectorLabels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
Scanner labels
*/}}
{{- define "forgescan.scanner.labels" -}}
{{ include "forgescan.labels" . }}
app.kubernetes.io/component: scanner
{{- end }}

{{/*
Create the name of the service account to use for API
*/}}
{{- define "forgescan.api.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (printf "%s-api" (include "forgescan.fullname" .)) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for scanners
*/}}
{{- define "forgescan.scanner.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (printf "%s-scanner" (include "forgescan.fullname" .)) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Database URL
*/}}
{{- define "forgescan.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:%s@%s-postgresql:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "forgescan.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- printf "postgresql://%s:%s@%s:%d/%s" .Values.postgresql.external.username .Values.postgresql.external.password .Values.postgresql.external.host (.Values.postgresql.external.port | int) .Values.postgresql.external.database }}
{{- end }}
{{- end }}

{{/*
Redis URL
*/}}
{{- define "forgescan.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://%s-redis-master:6379" (include "forgescan.fullname" .) }}
{{- else }}
{{- if .Values.redis.external.password }}
{{- printf "redis://:%s@%s:%d" .Values.redis.external.password .Values.redis.external.host (.Values.redis.external.port | int) }}
{{- else }}
{{- printf "redis://%s:%d" .Values.redis.external.host (.Values.redis.external.port | int) }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "forgescan.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
