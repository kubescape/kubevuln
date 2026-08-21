# VEX

kubevuln can publish a [VEX](https://openvex.dev/) document alongside every vulnerability
manifest it stores. VEX (Vulnerability Exploitability eXchange) is a machine-readable
assertion about whether a vulnerability that a scanner *found* in an image is actually
*exploitable* in it. A scanner reports what is present; a VEX document says what that
presence means.

That distinction is the whole point of the feature here. Relevancy data and
`SecurityException` CRDs both change how a finding should be read without changing whether
Grype matched it, and a VEX document is how kubevuln states that in a format other tools
can consume.

This page covers the document kubevuln **produces**. Consuming VEX documents published by
someone else is not implemented; see [Ingestion](#ingestion-not-implemented) at the end.

- [Enabling it](#enabling-it)
- [Where the document lives](#where-the-document-lives)
- [Document shape](#document-shape)
- [Statement identity and authorship](#statement-identity-and-authorship)
- [How a status is chosen](#how-a-status-is-chosen)
- [Relevancy](#relevancy)
- [When a document is written](#when-a-document-is-written)
- [The completeness gate](#the-completeness-gate)
- [Updating an existing document](#updating-an-existing-document)
- [The canonical hash](#the-canonical-hash)
- [Legacy statement repair](#legacy-statement-repair)
- [Ingestion, not implemented](#ingestion-not-implemented)
- [Troubleshooting](#troubleshooting)

## Enabling it

| setting | default | effect |
| --- | --- | --- |
| `vexGeneration` | `false` | publish VEX documents |
| `storage` | `false` | required: VEX is written through the storage API server, so nothing is published without it |
| `riskAcceptance` | `false` | required for `SecurityException` CRDs to influence statements at all |

```json
{
  "storage": true,
  "vexGeneration": true,
  "riskAcceptance": true
}
```

`vexGeneration` is checked in one place, `ScanService.storeVEX` in
[`core/services/scan.go`](../core/services/scan.go). When it is off, that function returns
immediately and no call site knows the difference. When it is on but `storage` is off, the
scan flows never reach the call at all, since VEX is only written on paths already gated on
storage.

Failure to store a VEX document is logged as a warning and the scan continues. The CVE
manifest is written before the VEX document at every call site, and the report sent to the
backend does not depend on VEX, so a scan result stands without it.

## Where the document lives

Documents are stored as `OpenVulnerabilityExchangeContainer` custom resources in the
configured namespace, one per stored vulnerability manifest. The container's name, labels
and annotations are taken from the manifest being described.

The name is the part worth knowing, because it differs by flow:

| flow | document named after | granularity |
| --- | --- | --- |
| `ScanCP` with relevancy | the relevancy-filtered manifest, whose name is the instance ID slug | one per container instance |
| `ScanCVE`, `ScanRegistry`, cache-hit republish | the image manifest, whose name is the image slug | one per image |

That falls out of `StoreVEX` naming the container after its `cvep` argument. Both call
shapes are covered under [When a document is written](#when-a-document-is-written).

Note that `StoreVEX`'s `withRelevancy` parameter is accepted by the port interface and
discarded by the API server implementation. What actually distinguishes a relevancy
document from a plain one is *which manifests are passed*, not the flag.

## Document shape

The `Spec` is an OpenVEX document:

```yaml
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: OpenVulnerabilityExchangeContainer
metadata:
  name: <cve manifest name>
spec:
  "@context": https://openvex.dev/ns/v0.2.0
  "@id": <canonical hash, see below>
  author: kubescape.io
  role: "smart vulnerability scanner :-)"
  timestamp: <RFC3339, set once at creation>
  last_updated: <RFC3339, bumped on every real change>
  version: 0
  tooling: kubescape-vulnerability-analyzer
  statements:
    - ...
```

The document metadata is embedded directly in `spec` rather than nested under a
`metadata` key, since `VEX` embeds `Metadata` without a JSON tag. The container's own
`metadata` is the usual Kubernetes `ObjectMeta`.

`version` starts at `0` and increments only when an update actually changes something.

Each statement covers one (vulnerability, package) pair:

```yaml
- "@id": https://kubescape.io/vex/statement/CVE-2024-3094/pkg:deb%2Fxz-utils@5.6.0
  vulnerability:
    "@id": <data source URL from the Grype match>
    name: CVE-2024-3094
    description: <vulnerability description>
    aliases: [<related vulnerability IDs>]
  products:
    - "@id": pkg:oci/<image>?repository_url=<repo>
      subcomponents:
        - "@id": pkg:deb/xz-utils@5.6.0
  status: not_affected
  justification: vulnerable_code_not_present
  impact_statement: Vulnerable component is not loaded into the memory
```

The product is the image, the subcomponent is the package the finding is in. Both are
purls. The image purl is built from the `kubescape.io/image-id` annotation on the manifest.

`vulnerability.@id` holds the Grype match's data source URL and `vulnerability.name` holds
the CVE identifier. Documents written by older versions have these two swapped; see
[Legacy statement repair](#legacy-statement-repair).

## Statement identity and authorship

Every statement kubevuln writes gets an `@id` of the form:

```
https://kubescape.io/vex/statement/<cve name>/<package purl>
```

That prefix is what makes a statement *ours*. `isLocalStatement` tests for it, and every
step that maintains a document (reset-to-baseline, mark-affected, mark-ignored, and the
dedup that decides whether to append) is local-only.

This matters because the container is not assumed to be exclusively kubevuln's. A
statement carrying a different `@id`, or none, is another author's assessment and is left
strictly alone: not reset, not re-marked, and not treated as covering a finding for dedup
purposes. If Grype reports a vulnerability that an external statement already discusses,
kubevuln appends its own statement beside that one rather than overwriting it, so the two
assessments sit side by side.

The trade-off is deliberate. Treating an external statement as ours would silently drop
kubescape's own view of a finding from the document.

## How a status is chosen

Every local statement starts at the same baseline and is then narrowed:

```
not_affected / vulnerable_code_not_present
impact: "Vulnerable component is not loaded into the memory"
```

From there:

**The finding is relevant.** If the vulnerability also appears in the relevancy-filtered
manifest, meaning the vulnerable file was actually loaded at runtime, the statement becomes
`affected`, justification and impact statement are cleared, and an action statement is set.
When the match carries a fixed state with known fix versions, the action statement names
them; otherwise it falls back to `Upgrade the vulnerable component to a version that is not
affected`.

**The finding was suppressed.** Suppressed findings arrive as `IgnoredMatches`, and the
statement depends on where the suppression came from. `ignoredMatchAssessment` in
[`repositories/apiserver.go`](../repositories/apiserver.go) is the single place that decides:

| suppression source | status | impact statement |
| --- | --- | --- |
| `SecurityException` CRD, default | `not_affected` | `Vulnerability was ignored by a SecurityException` |
| `SecurityException` with `fixed` status | `fixed` | cleared, justification cleared |
| `SecurityException` with `affected` status | `affected` | cleared, action statement records the accepted risk |
| backend-delivered exception policy | `not_affected` | `Vulnerability was ignored by an exception policy` |
| anything else | `not_affected` | `Vulnerability was ignored by an external VEX document or scanner configuration` |

A `SecurityException` carrying a justification or impact statement of its own has those
copied onto the statement, and an unrecognised status falls back to the safe
`not_affected` shape rather than being propagated.

The bottom two rows are worth separating carefully. Backend-delivered exception policies
suppress through the same code path as CRDs but never go through `buildPolicy`, so they
carry no `sourceKind` and their ignore rule carries no `SourceKind`. Provenance is
recovered from rule *shape* instead: kubevuln writes exactly one rule per suppression and
never sets `Package`, while Grype expresses its own ignore rules in terms of a package, so
a rule with a package did not come from us. Only rules failing that test get the "external
VEX document or scanner configuration" wording.

Today nothing produces that last row. `ApplySecurityExceptions` is the only writer of
`IgnoredMatches`, and Grype is handed no VEX documents or ignore rules. It exists for the
ingestion work in [#387](https://github.com/kubescape/kubevuln/issues/387).

## Relevancy

Two manifests reach the VEX builder:

- `cve`, every match found in the image
- `cvep`, the matches that survived relevancy filtering, meaning the vulnerable file was
  actually loaded

Statements are created from `cve`, so a document describes the whole image. `cvep` is then
used only to promote statements to `affected`. A finding present in the image but never
loaded stays `not_affected` with the default impact statement, which is what makes the
document more useful than the raw manifest.

On flows with no relevancy data, the same manifest is passed as both arguments, so
everything Grype found is reported as `affected`.

## When a document is written

`storeVEX` has three call sites.

**`ScanCVE` and `ScanRegistry`**, via `storeFilteredCVE`. Both pass the exception-filtered
manifest as `cve` and `cvep`, so there is no relevancy dimension and the document is named
after the image.

**`ScanCP`**, after relevancy-filtered results exist. This is the only call passing two
genuinely different manifests, and the only one producing a per-container document. It is
gated on both manifests having been filtered against a complete exception set.

**Cache hits**, via `reconcileCachedCVE`. A manifest served from cache was filtered against
whatever exception set was live when it was stored, so a deleted exception or an
`ExpiredOnFix` transition since then has to un-suppress findings on a cache hit exactly as
it would on a fresh scan. When re-filtering actually changes the suppression set, the
manifest is rewritten and its VEX document republished, because a document describing the
previous manifest is now stale.

`ScanCP` opts out of that republish and does it itself later, once relevancy-filtered
results are also available, so that it publishes once with both dimensions rather than
twice.

## The completeness gate

Every VEX publish is gated on the exception set having been fetched completely. The
manifest is not gated the same way, and the asymmetry is intentional.

An incomplete exception set can only *under*-suppress. It can miss a suppression the user
configured, but it can never invent one, so persisting the manifest is safe: additions are
real, and the only risk is that some suppression has not been applied yet.

A VEX document is a published assertion about which vulnerabilities are suppressed, and one
built from a partial set understates that. Leaving the previous document in place, written
when the set was known complete, is better than replacing it with a weaker claim. So the
two can briefly disagree until the next complete scan.

The cache-hit path adds a further rule for the same reason. The manifest is persisted on the
looser condition `exceptionsComplete || !hasRemovals`, so a transient `SecurityException`
list failure cannot look like a deletion and wipe suppression from a stored manifest.

## Updating an existing document

`StoreVEX` checks for an existing container first, so the common case, every scan after the
first for a given image, goes straight to the update path without building and hashing a
full document only to discard it on `AlreadyExists`. A concurrent creator between the read
and the create falls through to the update path rather than surfacing the raw error.

Updates run under `RetryOnConflict`. The first attempt reuses the object already fetched;
any retry does a fresh read for the current `resourceVersion`.

One detail there is load-bearing and easy to undo. The read must **not** use
`GetOptions{ResourceVersion: "metadata"}`, even though the sibling `Store*` methods do. That
option returns an `ObjectMeta`-only object with a zero `Spec`, which is fine for methods
that overwrite `Spec` wholesale, but `updateVEX` merges into `Spec.Statements`. A
metadata-only read would silently drop every previously stored statement and then fail
parsing the zeroed timestamp. The fake clientset used in tests ignores `GetOptions`
entirely, so no test can catch a regression here.

The update itself:

1. Append a statement for any (vulnerability, package) pair not already covered by a local
   statement.
2. Reset every local statement to the baseline `not_affected` shape, discarding the previous
   scan's conclusions. External statements are skipped.
3. Re-apply suppression assessments, then promote relevant findings to `affected`.
4. Merge the manifest's labels and annotations into the container's.
5. If the resulting document is byte-identical to the stored one ignoring `last_updated`,
   `version` and `@id`, and the labels and annotations are unchanged, return without
   writing.

Step 5 is what keeps repeated scans of an unchanged image from producing an endless stream
of no-op updates with a bumped version each time. Only when something genuinely changed are
`last_updated` and `version` advanced and the hash recomputed.

The reset in step 2 is why status is never sticky. A vulnerability that was `affected` last
scan and is no longer relevant this scan goes back to `not_affected`, rather than the
document accumulating every status a finding has ever held.

## The canonical hash

`metadata.@id` is a hash over the document's meaningful content, following the OpenVEX
canonicalisation algorithm: document timestamp, version and author, then every statement in
sorted order contributing its vulnerability, status, justification, timestamp and sorted
product strings, each length-prefixed.

Length-prefixing every field is what stops two different documents hashing the same by
shifting a delimiter into a value. Sorting is what stops Go's randomised map iteration
producing a different hash for identical content on consecutive runs.

## Legacy statement repair

`updateVEX` opens with two passes that exist purely to reconcile documents written by older
versions. Both are worth knowing about when reading a document that has been around a while.

**ID-less statements.** Statements stored before kubevuln started setting an `@id` have
none, and treating an empty ID as ours was later stopped so that an external feed's ID-less
statement would not be overwritten. Correct, but it also left every pre-existing kubevuln
statement looking like another author's: skipped by the reset, by every marking step, and by
the dedup, so a second statement got appended beside it for the same finding on every scan.
The repair stamps the ID kubevuln would write today onto statements carrying wording of its
own, which brings them back under management and leaves anything else alone. Both the
impact statement and the action statement are checked, since a statement last written while
`affected` had its impact statement blanked and only an action statement left on it.

**Swapped fields.** Statements written before the ID/Name mapping was corrected carry the
CVE identifier in `@id` and the data source URL in `name`. They are normalised in place so
the dedup, which keys on `name`, finds them instead of appending a duplicate for each.

## Ingestion, not implemented

Consuming VEX documents published by an image vendor is [#387](https://github.com/kubescape/kubevuln/issues/387)
and is not implemented. Nothing in this repository calls Grype's VEX matching: a repo-wide
search for `ApplyVEX`, `vex.NewProcessor` and `vex.Processor` turns up nothing outside
Grype's own library code.

Several primitives exist for it, each closing one concrete blocker, none of them wired into
a scan:

| package | what it is for |
| --- | --- |
| [`internal/safefetch`](../internal/safefetch) | fetching a user-supplied URL without turning it into an SSRF. https only, dial-time IP validation against private, loopback, link-local, carrier-grade NAT and NAT64-embedded addresses, a redirect hop limit with per-hop scheme checking, and a response size bound |
| [`internal/vexdoc`](../internal/vexdoc) | writing a fetched document to a temp file. Grype's `vex.Processor` accepts only real file paths, so anything handing it a fetched document has to write one first. Random filename, `0600`, always inside `os.TempDir()` |
| [`internal/csafresolve`](../internal/csafresolve) | resolving a CSAF advisory's composite product IDs into real purls. Grype's CSAF matcher compares purls by string equality but only looks for one directly on a relationships entry, which real Red Hat advisories never populate |

The "ignored by an external VEX document or scanner configuration" impact statement
described [above](#how-a-status-is-chosen) is the other half of the same preparation: the
assessment path already distinguishes an ignore that did not come from kubevuln's own
exception machinery, so an ingested document's suppressions would be labelled correctly
rather than being reported as a `SecurityException`.

## Troubleshooting

**No `OpenVulnerabilityExchangeContainer` appears.** Check `vexGeneration` and `storage` are
both true. With `vexGeneration` off, `storeVEX` returns before doing anything and logs
nothing, so silence is expected rather than a symptom.

**A document exists but a `SecurityException` is not reflected in it.** Check
`riskAcceptance` is enabled. With `storage` on and `riskAcceptance` off, matching CRDs are
silently ignored: a warning is logged at startup, but no error or metric flags it.

**A document is stale relative to the manifest.** Most likely the exception set was
incomplete when the scan ran, so the manifest was persisted and the VEX publish was skipped
by [the completeness gate](#the-completeness-gate). This resolves on the next scan with a
complete set. `storing VEX` at warning level indicates the write itself failed instead.

**`version` never advances.** Expected when nothing changed. Updates are skipped entirely
when the document is equal to the stored one ignoring `last_updated`, `version` and `@id`.

**Duplicate statements for one finding.** Statements not carrying a kubescape `@id` are
treated as another author's and are never deduped against. See
[Legacy statement repair](#legacy-statement-repair) for the versions this affected.

## See also

- [ARCHITECTURE.md](ARCHITECTURE.md) for where the VEX phase sits in a scan
- [CONFIGURATION.md](CONFIGURATION.md) for the full settings reference
- [security-exception-design.md](security-exception-design.md) for how suppressions are produced in the first place
- [OpenVEX specification](https://github.com/openvex/spec)
