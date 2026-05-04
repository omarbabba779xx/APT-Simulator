{{/*
Expand the name of the chart.
*/}}
{{- define "apt-simulator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "apt-simulator.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "apt-simulator.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "apt-simulator.labels" -}}
app.kubernetes.io/name: {{ include "apt-simulator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end }}

{{- define "apt-simulator.orchestrator.name" -}}
{{ include "apt-simulator.fullname" . }}-orchestrator
{{- end }}

{{- define "apt-simulator.agent.name" -}}
{{ include "apt-simulator.fullname" . }}-agent
{{- end }}
