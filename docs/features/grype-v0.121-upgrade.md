# Grype v0.121.0 / Syft v1.55.0 upgrade

This page records what changed for kubevuln when the scanning stack moved from Grype
v0.104.1 / Syft v1.42.3 to Grype v0.121.0 / Syft v1.55.0, because three of the changes are
behavioural rather than mechanical and are not obvious from the version numbers.

The pinned set is Grype v0.121.0, Syft v1.55.0, Stereoscope v0.3.4, go-containerregistry
v0.22.1, Clio v0.1.1, Go 1.26.8.

- [New matchers mean new findings](#new-matchers-mean-new-findings)
- [Relationships now reach the matchers](#relationships-now-reach-the-matchers)
- [Source resolution is pinned to one provider](#source-resolution-is-pinned-to-one-provider)
- [A 429 now takes longer to surface](#a-429-now-takes-longer-to-surface)
- [The CSAF library is held back](#the-csaf-library-is-held-back)
- [Forks kubevuln carries](#forks-kubevuln-carries)
- [Vulnerability surface](#vulnerability-surface)

## New matchers mean new findings

`matcher.NewDefaultMatchers` gained a **hex** matcher (Erlang/Elixir) and a **pacman**
matcher (Arch Linux), and the dpkg and rpm matchers are now constructed with their own
config rather than as bare structs. kubevuln calls `NewDefaultMatchers` and so picks all of
this up automatically.

The practical effect: images with Erlang/Elixir or Arch packages can report vulnerabilities
they did not report before. That is new coverage, not a regression, but it will look like a
finding-count jump on the affected images.

Nothing changed for the images already covered. The pinned-DB fixtures scan to exactly the
same 63 and 456 matches as before, with the same CVE/package/version sets in the same order.

## Relationships now reach the matchers

`pkg.FromCollection` gained a `relationships` parameter, and kubevuln passes the SBOM's
`s.Relationships` through it — which is what Grype's own providers do, and what kubevuln
could not do before because the parameter did not exist.

Those relationships populate `Package.RelatedPackages`. In v0.104.1 that field did not exist
at all; overlap handling lived in an unexported `removePackagesByOverlap` that only ran
inside `pkg.Provide`, a path kubevuln has never used. In v0.121.0 the apk, rpm and dpkg
(Ubuntu ESM) matchers consume `RelatedPackages` to suppress a finding on a package whose
files are owned by an OS package that already reported the same vulnerability.

So this argument can **reduce** findings on images that mix OS packages with non-OS content
overlapping the same files — previously kubevuln reported both, where Grype's CLI reported
one. Measured on the pinned-DB fixtures it changes nothing: scanning them with `nil`
relationships and with `s.Relationships` both give 63 and 456 matches. The alpine fixture has
no overlap relationships at all and the nginx one has a single overlap that no matcher
suppresses, so neither exercises the suppression. Expect the difference, if anywhere, on
RPM-based images carrying bundled binaries.

## Source resolution is pinned to one provider

Syft v1.55 added an `oci-model` source provider for OCI model artifacts and tagged it
`registry`, alongside the `oci-registry` provider that actually pulls container images.

That matters because `syft.GetSource` wraps a single provider failure with `%w` but formats
two or more with `%s`. With both providers selected, every registry failure came back as
flat text with no error chain, and `errors.As` could no longer find the typed
`*image.ErrPlatformMismatch`. A platform mismatch was then reported as a generic
"SBOM generation failed" instead of `platform-not-found`.

`GetSourceConfig` in [`internal/syftsource`](../../internal/syftsource) therefore selects the
`oci-registry` provider **by name** rather than by the `registry` tag. kubevuln only ever
pulls container images, so this restores exactly the pre-upgrade provider set and keeps the
typed error intact.

## A 429 now takes longer to surface

go-containerregistry now retries HTTP 429 inside its own transport (three steps, 1s then
3s). kubevuln's `source_resolution` retry already retried 429 three times on top of that, so
the two nest: a rate-limited registry now takes roughly 14 seconds to surface a 429 instead
of returning almost immediately.

Classification is unaffected at the default five-minute scan timeout — the error still
arrives as `too-many-requests`. It only matters if a caller sets a scan timeout shorter than
the combined retry budget, in which case the deadline fires first and the scan is reported
`Incomplete` with no reason.

## The CSAF library is held back

Grype v0.121.0 requires `github.com/gocsaf/csaf/v3` v3.5.1, which added
`DisallowUnknownFields()` to its advisory decoder. Its Go struct spells the field `acknowledgements`, but the CSAF 2.0
schema — the one the library itself bundles — spells it `acknowledgments`. Strict decoding
therefore rejects any spec-conformant advisory that carries that section, including the Red
Hat advisories kubevuln's own tests use.

`ValidateCSAF` in [`internal/vexvalidate`](../../internal/vexvalidate) is the entry point for
customer-supplied CSAF VEX documents, so this would have rejected real input. go.mod pins
the library back to v3.3.0 with a `replace`. The bug is still present in v3.7.0; the pin
should be revisited when upstream fixes the spelling or drops strict decoding.

## Forks kubevuln carries

Four `replace` directives, all load-bearing:

| Module | Replacement | Why |
|--------|-------------|-----|
| `github.com/anchore/stereoscope` | `github.com/matthyx/stereoscope` v0.3.4-ks.1 | kubescape patches |
| `github.com/google/go-containerregistry` | `github.com/matthyx/go-containerregistry` pseudo-version | `schema1.ConfigFile()` support |
| `github.com/anchore/syft` | `github.com/kubescape/syft` v1.55.0-ks.2 | ELF pre-filter and selective directory indexing |
| `github.com/gocsaf/csaf/v3` | held at v3.3.0 | v3.5.1 strict decoding rejects real advisories |

The go-containerregistry replace has to live in **this** go.mod even though the stereoscope
fork declares the same one: a `replace` inside a dependency is ignored by the main module, so
dropping it here silently builds against upstream go-containerregistry and loses
`schema1.ConfigFile()`.

Of the syft fork's patches, only the ELF pre-filter affects kubevuln — it speeds up the
binary, golang, rust and java catalogers. Selective directory indexing activates only on
directory sources, and kubevuln scans container images through stereoscope, so it is inert
here. The `-ks.2` tag fixes the pre-filter skipping Mach-O and PE binaries outright; that is
also inert for kubevuln, whose images are ELF, and was confirmed by re-measuring the fixtures
(unchanged at 63 and 456).

## Vulnerability surface

`govulncheck -mode=binary` against the shipped `linux/amd64` binary reports two findings, both
in `github.com/docker/docker` / `docker-credential-helpers` with no fix available. Those
module versions are unchanged by this upgrade, so they are pre-existing.

The upgrade also **resolves [#854](https://github.com/kubescape/kubevuln/issues/854)**: Syft
v1.42.3 pulled `github.com/nwaples/rardecode` v1.1.3, whose unfixed RAR-decoder DoS
(CVE-2025-11579) was reachable from both SBOM paths. v1.55.0 drops v1 entirely and leaves only
`rardecode/v2`, which is unaffected.

One gap worth tracking rather than celebrating: Syft v1.55 added `syft/internal/elfutil`, which
bounds the decompressed size a compressed ELF section may declare, because `debug/elf` sizes its
buffer from the file's own header and a small crafted binary can drive a fatal OOM. Neither
v1.42.3 nor the old `v1.32.0-ks.2` fork had this at all, so the upgrade is a clear net gain. But
the fork's own `binutils` pre-filters call `debug/elf.NewFile` directly, ahead of the bounded
parse, so the golang, rust and elf-package catalogers do not yet get the new protection. Closing
that is a change to the fork, not to kubevuln.
