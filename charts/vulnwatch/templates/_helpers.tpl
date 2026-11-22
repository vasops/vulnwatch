{{/* Chart name, truncated to the 63-character label limit. */}}
{{- define "vulnwatch.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name. */}}
{{- define "vulnwatch.fullname" -}}
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

{{- define "vulnwatch.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "vulnwatch.labels" -}}
helm.sh/chart: {{ include "vulnwatch.chart" . }}
{{ include "vulnwatch.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "vulnwatch.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vulnwatch.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "vulnwatch.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vulnwatch.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "vulnwatch.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ $tag }}
{{- end -}}
{{- end }}

{{- define "vulnwatch.claimName" -}}
{{- .Values.persistence.existingClaim | default (printf "%s-state" (include "vulnwatch.fullname" .)) }}
{{- end }}

{{- define "vulnwatch.newsClaimName" -}}
{{- printf "%s-news" (include "vulnwatch.fullname" .) }}
{{- end }}

{{- define "vulnwatch.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else if .Values.secrets.create }}
{{- include "vulnwatch.fullname" . }}
{{- end }}
{{- end }}

{{/*
config-override.yaml: values.configOverride plus the chart's metrics settings.
*/}}
{{- define "vulnwatch.configOverride" -}}
{{- $cfg := deepCopy (.Values.configOverride | default dict) }}
{{- with .Values.metrics.pushgateway }}
{{- if .url }}
{{- $m := dict "pushgateway_url" .url }}
{{- with .job }}{{ $_ := set $m "job" . }}{{ end }}
{{- with .grouping }}{{ $_ := set $m "grouping" . }}{{ end }}
{{- $cfg = mustMergeOverwrite $cfg (dict "metrics" $m) }}
{{- end }}
{{- end }}
{{- with .Values.metrics.dashboard.url }}
{{- $cfg = mustMergeOverwrite $cfg (dict "outputs" (dict "slack" (dict "dashboard_url" .))) }}
{{- end }}
{{- if $cfg }}{{ toYaml $cfg }}{{ else }}{}{{ end }}
{{- end }}

{{- define "vulnwatch.sourcesOverride" -}}
{{- $src := deepCopy (.Values.sourcesOverride | default dict) }}
{{- if .Values.trivy.enabled }}
{{- $src = mustMergeOverwrite $src (dict "sources" (dict "trivy" (dict "enabled" true))) }}
{{- end }}
{{- if $src }}{{ toYaml $src }}{{ else }}{}{{ end }}
{{- end }}

{{/* Pod spec shared by the CronJob and the bootstrap Job. Call with (dict "ctx" $ "args" list). */}}
{{- define "vulnwatch.podSpec" -}}
{{- $ := .ctx -}}
serviceAccountName: {{ include "vulnwatch.serviceAccountName" $ }}
automountServiceAccountToken: {{ or $.Values.serviceAccount.automountServiceAccountToken $.Values.trivy.enabled }}
restartPolicy: Never
{{- with $.Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $.Values.priorityClassName }}
priorityClassName: {{ . }}
{{- end }}
{{- with $.Values.runtimeClassName }}
runtimeClassName: {{ . }}
{{- end }}
securityContext:
  {{- toYaml $.Values.podSecurityContext | nindent 2 }}
containers:
  - name: vulnwatch
    image: {{ include "vulnwatch.image" $ }}
    imagePullPolicy: {{ $.Values.image.pullPolicy }}
    args:
      {{- toYaml .args | nindent 6 }}
    env:
      - name: STACK_CONFIG
        value: /config/stack.yaml
      - name: VULNWATCH_CONFIG
        value: /config/config.yaml,/config/config-override.yaml
      - name: VULNWATCH_SOURCES
        value: /config/sources.yaml,/config/sources-override.yaml
      - name: STATE_DB
        value: /data/vulnwatch.db
      - name: TMPDIR
        value: /tmp
      # The container's memory limit; vulnwatch sets its Go soft limit
      # (GOMEMLIMIT) to 90% of it, so the GC works harder before an OOM kill.
      - name: VULNWATCH_MEMORY_LIMIT
        valueFrom:
          resourceFieldRef:
            containerName: vulnwatch
            resource: limits.memory
      {{- if not (hasKey ($.Values.env | default dict) "VULNWATCH_LANDLOCK") }}
      - name: VULNWATCH_LANDLOCK
        value: {{ $.Values.landlock | quote }}
      {{- end }}
      {{- range $k, $v := $.Values.env }}
      - name: {{ $k }}
        value: {{ $v | quote }}
      {{- end }}
      {{- range $k, $ref := $.Values.secretEnv }}
      - name: {{ $k }}
        valueFrom:
          secretKeyRef:
            name: {{ required (printf "secretEnv.%s.name is required" $k) $ref.name }}
            key: {{ required (printf "secretEnv.%s.key is required" $k) $ref.key }}
            {{- if hasKey $ref "optional" }}
            optional: {{ $ref.optional }}
            {{- end }}
      {{- end }}
      {{- with $.Values.extraEnv }}
      {{- toYaml . | nindent 6 }}
      {{- end }}
    {{- $secret := include "vulnwatch.secretName" $ }}
    {{- if or $secret $.Values.envFromSecrets $.Values.envFrom }}
    envFrom:
      {{- with $secret }}
      - secretRef:
          name: {{ . }}
      {{- end }}
      {{- range $.Values.envFromSecrets }}
      - secretRef:
          name: {{ . }}
      {{- end }}
      {{- with $.Values.envFrom }}
      {{- toYaml . | nindent 6 }}
      {{- end }}
    {{- end }}
    securityContext:
      {{- toYaml $.Values.securityContext | nindent 6 }}
    resources:
      {{- toYaml $.Values.resources | nindent 6 }}
    volumeMounts:
      - name: config
        mountPath: /config
        readOnly: true
      - name: data
        mountPath: /data
      - name: tmp
        mountPath: /tmp
volumes:
  - name: config
    projected:
      sources:
        - configMap:
            name: {{ include "vulnwatch.fullname" $ }}
        {{- with $.Values.existingStackConfigMap }}
        {{- if .name }}
        - configMap:
            name: {{ .name }}
            items:
              - key: {{ .key | default "stack.yaml" }}
                path: stack.yaml
        {{- end }}
        {{- end }}
  - name: data
    {{- if $.Values.persistence.enabled }}
    persistentVolumeClaim:
      claimName: {{ .claim | default (include "vulnwatch.claimName" $) }}
    {{- else }}
    emptyDir: {}
    {{- end }}
  - name: tmp
    emptyDir:
      sizeLimit: {{ $.Values.tmpDir.sizeLimit }}
{{- with $.Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $.Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $.Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/* Arguments of the daily run. */}}
{{- define "vulnwatch.runArgs" -}}
{{- $args := list "run" "--output" (join "," .Values.run.outputs) "--log-format" (.Values.run.logFormat | default "json") "--log-level" .Values.run.logLevel }}
{{- if has "html" .Values.run.outputs }}{{ $args = concat $args (list "--html-path" "/data/report.html") }}{{ end }}
{{- if has "json" .Values.run.outputs }}{{ $args = concat $args (list "--json-path" "/data/report.json") }}{{ end }}
{{- toYaml (concat $args .Values.run.extraArgs) }}
{{- end }}

{{/* Arguments of the news check. */}}
{{- define "vulnwatch.newsArgs" -}}
{{- $args := list "news" "--output" (join "," .Values.news.outputs) "--log-format" (.Values.run.logFormat | default "json") "--log-level" .Values.run.logLevel }}
{{- if .Values.news.repost }}
{{- $args = concat $args (list "--repost" (toString (int .Values.news.repost))) }}
{{- end }}
{{- toYaml $args }}
{{- end }}
