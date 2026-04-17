## airlock {{ .Tag }}

### Changelog

{{- if .Changelog }}
{{ .Changelog }}
{{- else }}
No changes since last release.
{{- end }}

---

**Installation:**

```bash
curl -fsSL https://raw.githubusercontent.com/muneebs/airlock/main/install.sh | bash
```

Or download the archive for your platform from the assets below.

**Checksums:**

```
{{ .Checksum }}
```