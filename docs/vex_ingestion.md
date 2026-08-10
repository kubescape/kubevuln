# External VEX Feed Ingestion (VEXSource)

Kubescape supports ingesting external Vulnerability Exploitability eXchange (VEX) documents (such as OpenVEX and CSAF feeds) directly into the cluster. This allows users to automatically suppress false-positive CVE findings during image scanning based on trusted vendor advisories.

## The `VEXSource` CRD

To ingest a new VEX feed, cluster administrators apply a `VEXSource` Custom Resource. 

The Kubescape `kubevuln` component includes a background controller that will automatically download, parse, and synchronize the remote feed at the requested interval.

### Example: OpenVEX Feed

```yaml
apiVersion: softwarecomposition.kubescape.io/v1beta1
kind: VEXSource
metadata:
  name: chainguard-openvex
  namespace: kubescape
spec:
  url: "https://packages.cgr.dev/os/security.json"
  format: OpenVEX
  refreshInterval: 12h
```

### Example: CSAF Feed

```yaml
apiVersion: softwarecomposition.kubescape.io/v1beta1
kind: VEXSource
metadata:
  name: redhat-csaf
  namespace: kubescape
spec:
  url: "https://access.redhat.com/security/data/csaf/v2/advisories/cve.json"
  format: CSAF
  refreshInterval: 24h
```

## How It Works

1. **Ingestion**: The `VEXSource` Reconciler detects the custom resource and performs an HTTP GET request to fetch the payload.
2. **Streaming Parser**: Because VEX feeds can exceed 100MB+, the parser uses a memory-safe JSON stream to tokenize the data without causing OOM panics.
3. **Storage**: Parsed statements are safely persisted into the Kubernetes API Server via `OpenVulnerabilityExchangeContainer` CRDs.
4. **Scan Time Join**: When an image scan is triggered, Grype findings are dynamically joined against the VEX statements. If a CVE is marked as `not_affected` and the subcomponent matches (via PURL evaluation), the CVE is automatically suppressed and marked with a security justification.

## Troubleshooting

You can monitor the status of a VEX feed ingestion by checking the `Status` conditions of your `VEXSource` object:

```bash
kubectl get vexsource chainguard-openvex -n kubescape -o yaml
```

Look for the `Synced` condition. If the URL is unreachable or the JSON format is invalid, a `Failed` condition will be emitted with the exact error message.
