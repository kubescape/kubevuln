# Verified registry SBOM reuse

Status: experimental, disabled by default; design review is tracked in
[designs-and-proposals#22](https://github.com/kubescape/designs-and-proposals/issues/22).

Set `sbomReusePolicyFile` in `clusterData.json`, or `SBOMREUSEPOLICYFILE` in the
environment, to an administrator-owned JSON policy file. An empty path preserves
normal generation. Invalid enabled configuration fails startup. Restart kubevuln
after changing the policy: this first version does not watch mounted files.

The initial profile supports immutable image references in registry scans without
runtime relevancy. Workload/instance scans, mutable tags, unavailable attachments,
ambiguous attestations, signature failures and incompatible inventories use the
configured in-process or sidecar generator. Node-agent-owned generation and
`proxyRegistryMap` cannot be combined with this feature yet. Ordinary HTTP proxy,
TLS and registry credentials are reused.

A valid signature proves who signed an inventory, not that its packages are
complete. Enable this only for approved build producers whose inventories have
been compared against local generation. The supported document schema is Syft
JSON 16.0.39, with an exact configured producer version. Other schemas fall back.

Each policy repository is an exact canonical name, for example
`registry.example/team/application`. Its producer has `publicKeys` (PKIX PEM
Ed25519 public keys), `syftVersion`, and `schemaVersion` fields. Policy limits are
`maxBytes` (default 8 MiB, range 1 KiB–64 MiB), `maxCandidates` (default 8, maximum
32), and `timeoutSeconds` (default 10, maximum 60). Each acquisition also has a
64-request ceiling and a total body-byte budget of twice `maxBytes` plus 8 MiB.

Imported inventories retain their producer version and record the signer,
artifact digest, immutable subject/platform, verification time and policy
fingerprint in `kubescape.io/sbom-import-*` annotations. Every imported cache hit
rechecks policy eligibility. Imported vulnerability reports are matched again
rather than bypassing that check through the CVE cache. Locally generated cache
entries retain their existing behavior. Turning reuse off rejects imported
inventory on subsequent requests and returns to normal generation.
