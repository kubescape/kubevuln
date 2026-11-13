# Kubevuln
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/kubescape/kubevuln/badge)](https://securityscorecards.dev/viewer/?uri=github.com/kubescape/kubevuln)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkubescape%2Fkubevuln.svg?type=shield&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkubescape%2Fkubevuln?ref=badge_shield&issueType=license)

The Kubevuln component is an in-cluster component of the Kubescape security platform.
It [scans container images for vulnerabilities](https://www.armosec.io/blog/code-repository-container-image-registry-scanning/?utm_source=github&utm_medium=repository), using Grype as its engine.

## Vulnerability report time

`VulnerabilityManifest.spec.metadata.report.createdAt` records when vulnerability
evaluation successfully generated the report, in UTC. Image and relevancy reports
have their own evaluation times, including successful reports with no findings.
Cache hits and SecurityException-only changes preserve the original report time;
it is not the time the latest scan request completed. Legacy reports without a
timestamp remain unknown until a fresh vulnerability evaluation replaces them.

Consumers should label this field "Last vulnerability evaluation" or "Report
generated" and display `Unknown` when it is absent or null. Kubernetes
`metadata.creationTimestamp` and the summary's scan-start `kubescape.io/timestamp`
annotation describe different events. Summaries reference the full and relevant
manifests; they do not carry this report field themselves.

Report time does not change existing concurrent-write ordering or make manifest,
summary, and VEX writes atomic. A later upload failure does not invalidate a
successfully generated report's timestamp.

## Build Kubevuln
`make` builds the Linux/amd64 binary that goes into the container image. To build for your
own platform instead, run `go build -o kubevuln ./cmd/http`.

## Configuration

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the complete configuration reference
(environment variables, the `clusterData.json` schema, and validation).

kubevuln reads `clusterData.json` from the directory named by the `CONFIG_DIR` environment
variable (default `/etc/config`) and always listens on port 8080. To run it locally without a
backend or a cluster:

```bash
mkdir -p .dev/config
cat > .dev/config/clusterData.json << 'EOF'
{
  "keepLocal": true,
  "clusterName": "dev-cluster"
}
EOF

CONFIG_DIR=.dev/config KS_API_AUTH_DISABLED=true go run ./cmd/http
```

`KS_API_AUTH_DISABLED=true` is what lets it start without a cluster. By default every API route
except the probes and `/metrics` requires a Kubernetes service-account token, and kubevuln exits
at startup when `POD_NAMESPACE` is not set. Never set it in a cluster. See
[API authentication](docs/API.md#api-authentication).

## Development

[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) covers building, testing, debugging, and sample
VS Code and GoLand run configurations.

## Changelog

Kubevuln changes are tracked on the [release](https://github.com/kubescape/kubevuln/releases) page

Operational metrics, traces, export controls, and deployment requirements are documented in
[Operational telemetry](docs/OPERATIONAL_TELEMETRY.md).
