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
32), and `timeoutSeconds` (default 10, maximum 60). Each credential attempt also has a
64-request ceiling and a total body-byte budget of twice `maxBytes` plus 8 MiB.

Imported inventories retain their producer version and record the signer,
artifact digest, immutable subject/platform, verification time and policy
fingerprint in `kubescape.io/sbom-import-*` annotations. Every imported cache hit
rechecks policy eligibility. Imported vulnerability reports are matched again
rather than bypassing that check through the CVE cache. Locally generated cache
entries retain their existing behavior. Turning reuse off rejects imported
inventory on subsequent requests and returns to normal generation.


## Publisher example

The producer must generate native Syft JSON with the same cataloging configuration
as kubevuln. Do not convert SPDX or CycloneDX into this profile. Extract the exact
`descriptor.version` from that inventory when creating the policy. A standard
Syft release with a different schema or cataloger configuration is not assumed
equivalent to Kubescape's pinned fork.

Create an Ed25519 signing key, and distribute only its public key to kubevuln:

```sh
openssl genpkey -algorithm ED25519 -out producer.key
openssl pkey -in producer.key -pubout -out producer.pub
```

For an existing `inventory.json` and an immutable **platform manifest** reference,
create a policy using the actual producer version and public key:

```sh
jq -n --arg repo registry.example/team/application \
  --rawfile key producer.pub \
  --arg version "$(jq -r .descriptor.version inventory.json)" \
  '{repositories:{($repo):{publicKeys:[$key],syftVersion:$version,schemaVersion:"16.0.39"}}}' \
  > sbom-reuse-policy.json

go run ./examples/sbom-publish \
  -image 'registry.example/team/application@sha256:REPLACE_WITH_PLATFORM_DIGEST' \
  -sbom inventory.json -key producer.key
```

The example uses Docker's default registry credentials and writes content-addressed
blobs and an OCI manifest. Repeating the same publication is idempotent. Its
`-insecure` option is intended for a local HTTP test registry. Keep signing keys
outside kubevuln; rotate trusted public keys through policy deployment and restart.

The artifact has `application/vnd.in-toto+json` as its artifact type, a subject
matching the image manifest descriptor, and exactly one
`application/vnd.dsse.envelope.v1+json` layer. The DSSE payload type is
`application/vnd.in-toto+json`. Its in-toto Statement v1 has exactly one subject
(the canonical repository name and resolved image digest), predicate type
`https://anchore.com/syft`, and the original native Syft document as its predicate.
The signature covers DSSE PAE bytes. OCI referrers are required; legacy attachment
tags and paginated or ambiguous listings cause fallback. This initial profile does
not implement keyless identity, transparency logs, or general cosign bundles.

Multi-platform image indexes require an explicit exact OS/architecture/variant
match. For example, `linux/arm64/v8` is distinct from `linux/arm64`. Every lookup
and credential attempt shares the acquisition timeout; each credential attempt
has its own bounded transport budget. Cache eligibility trusts cluster storage
and revalidates policy, signer, content digest, source identity and compatibility;
it does not fetch a new remote signature on every cache hit.

## Reproducing real inventory parity

With Docker running, export fixtures and run the opt-in registry integration test:

```sh
docker save alpine:3.19 -o /tmp/sbom-reuse-alpine.tar
docker save nginx:1.25 -o /tmp/sbom-reuse-nginx.tar
TMPDIR=/tmp \
  SBOM_REUSE_ALPINE_TAR=/tmp/sbom-reuse-alpine.tar \
  SBOM_REUSE_NGINX_TAR=/tmp/sbom-reuse-nginx.tar \
  go test -tags dockerfixture ./adapters/v1 -run TestRegistrySBOMRealParity -count=1 -v
```

The test generates inventories with the actual Syft adapter, publishes signed
attachments to an ephemeral OCI registry, checks complete package and Grype match
record equality against local generation, checks storage/cache eligibility, and
counts image-layer requests. It also verifies the real generator fallback before
an attachment exists. Without tar paths only the empty-image fixture runs; that
case alone is not evidence of parity on a populated image. Results depend on the
image architecture/digest and fixed test database; see the PR validation output
for the exact observed counts and database checksum.
