package v1

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	containerRegistryV1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/anchore/syft/syft/source"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/containerscan"
	"github.com/google/uuid"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_domainToArmo(t *testing.T) {
	tests := []struct {
		name                             string
		grypeDocument                    v1beta1.GrypeDocument
		vulnerabilityExceptionPolicyList []armotypes.VulnerabilityExceptionPolicy
		want                             []containerscan.CommonContainerVulnerabilityResult
		wantErr                          bool
	}{
		{
			name: "Test domainToArmo with description",
			grypeDocument: v1beta1.GrypeDocument{
				Source: &v1beta1.Source{
					Target: json.RawMessage(`{"userInput":"","imageID":"","manifestDigest":"","mediaType":"","tags":null,"imageSize":0,"layers":[{"mediaType":"","digest":"dummyLayer","size":0}],"manifest":null,"config":null,"repoDigests":null,"architecture":"","os":""}`),
				},
				Matches: []v1beta1.Match{{
					Vulnerability: v1beta1.Vulnerability{
						VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
							ID:          "CVE-2021-21300",
							Description: "test description",
						},
						Fix: v1beta1.Fix{
							Versions: []string{"1.0.0"},
						},
					},
				}},
			},
			want: []containerscan.CommonContainerVulnerabilityResult{{
				IntroducedInLayer: dummyLayer,
				Vulnerability: containerscan.Vulnerability{
					Description: "test description",
					Name:        "CVE-2021-21300",
					Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-21300",
					Fixes:       containerscan.VulFixes{{Version: "1.0.0"}},
				},
				Layers:        []containerscan.ESLayer{{LayerHash: dummyLayer}},
				RelevantLinks: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-21300", ""},
				IsLastScan:    1,
				IsFixed:       1,
			}},
		},
		{
			name: "Test domainToArmo with related description",
			grypeDocument: v1beta1.GrypeDocument{
				Source: &v1beta1.Source{
					Target: json.RawMessage(`{"userInput":"","imageID":"","manifestDigest":"","mediaType":"","tags":null,"imageSize":0,"layers":[{"mediaType":"","digest":"dummyLayer","size":0}],"manifest":null,"config":null,"repoDigests":null,"architecture":"","os":""}`),
				},
				Matches: []v1beta1.Match{{
					Vulnerability: v1beta1.Vulnerability{
						VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
							ID: "CVE-2021-21300",
						},
						Fix: v1beta1.Fix{
							Versions: []string{"1.0.0"},
						},
					},
					RelatedVulnerabilities: []v1beta1.VulnerabilityMetadata{{
						Description: "related description",
					}},
				}},
			},
			want: []containerscan.CommonContainerVulnerabilityResult{{
				IntroducedInLayer: dummyLayer,
				Vulnerability: containerscan.Vulnerability{
					Description: "related description",
					Name:        "CVE-2021-21300",
					Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-21300",
					Fixes:       containerscan.VulFixes{{Version: "1.0.0"}},
				},
				Layers:        []containerscan.ESLayer{{LayerHash: dummyLayer}},
				RelevantLinks: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-21300", ""},
				IsLastScan:    1,
				IsFixed:       1,
			}},
		},
		{
			name: "Detect fixed vulnerability with CPE match",
			grypeDocument: v1beta1.GrypeDocument{
				Source: &v1beta1.Source{
					Target: json.RawMessage(`{"userInput":"","imageID":"","manifestDigest":"","mediaType":"","tags":null,"imageSize":0,"layers":[{"mediaType":"","digest":"dummyLayer","size":0}],"manifest":null,"config":null,"repoDigests":null,"architecture":"","os":""}`),
				},
				Matches: []v1beta1.Match{{
					Vulnerability: v1beta1.Vulnerability{
						VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
							ID: "CVE-2021-21300",
						},
					},
					RelatedVulnerabilities: []v1beta1.VulnerabilityMetadata{{
						Description: "related description",
					}},
					MatchDetails: []v1beta1.MatchDetails{{
						Type:  "cpe-match",
						Found: json.RawMessage(`{"vulnerabilityID":"CVE-2018-20200","versionConstraint":">= 3.0.0, <= 3.12.0 (unknown)","cpes":["cpe:2.3:a:squareup:okhttp:*:*:*:*:*:*:*:*"]}`),
					}},
				}},
			},
			want: []containerscan.CommonContainerVulnerabilityResult{{
				IntroducedInLayer: dummyLayer,
				Vulnerability: containerscan.Vulnerability{
					Description: "related description",
					Name:        "CVE-2021-21300",
					Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-21300",
					Fixes:       containerscan.VulFixes{{Version: "unknown"}},
				},
				Layers:        []containerscan.ESLayer{{LayerHash: dummyLayer}},
				RelevantLinks: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-21300", ""},
				IsLastScan:    1,
				IsFixed:       1,
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
			ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
			ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})
			got, err := DomainToArmo(ctx, tt.grypeDocument, tt.vulnerabilityExceptionPolicyList)
			if (err != nil) != tt.wantErr {
				t.Errorf("DomainToArmo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got[0].ContainerScanID = ""
			got[0].Timestamp = 0
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_parseLayersPayload(t *testing.T) {
	c := containerRegistryV1.ConfigFile{
		History: []containerRegistryV1.History{
			{EmptyLayer: false},
			{EmptyLayer: false},
		},
		RootFS: containerRegistryV1.RootFS{
			DiffIDs: []containerRegistryV1.Hash{
				{Algorithm: "sha256", Hex: "5f6201014d118db78bfb090a1e932db880c3dce93d9c2dc29289bc389148b666"},
				{Algorithm: "sha256", Hex: "55b314485cd7090cd64730398b85f42bd9b6d3bb33b6eddfc043154692c51b99"},
			},
		},
	}
	config, _ := json.Marshal(c)
	tests := []struct {
		target  source.ImageMetadata
		want    map[string]containerscan.ESLayer
		name    string
		wantErr bool
	}{
		{
			name: "missing config",
			want: map[string]containerscan.ESLayer{},
		},
		{
			name:    "malformed config",
			target:  source.ImageMetadata{RawConfig: []byte(`{`)},
			wantErr: true,
		},
		{
			name: "Test parseLayersPayload",
			target: source.ImageMetadata{
				RawConfig: config,
			},
			want: map[string]containerscan.ESLayer{
				"sha256:5f6201014d118db78bfb090a1e932db880c3dce93d9c2dc29289bc389148b666": {
					LayerInfo: &containerscan.LayerInfo{
						CreatedTime: &time.Time{},
					},
					LayerHash: "sha256:5f6201014d118db78bfb090a1e932db880c3dce93d9c2dc29289bc389148b666",
				},
				"sha256:55b314485cd7090cd64730398b85f42bd9b6d3bb33b6eddfc043154692c51b99": {
					LayerInfo: &containerscan.LayerInfo{
						CreatedTime: &time.Time{},
						LayerOrder:  1,
					},
					LayerHash:       "sha256:55b314485cd7090cd64730398b85f42bd9b6d3bb33b6eddfc043154692c51b99",
					ParentLayerHash: "sha256:5f6201014d118db78bfb090a1e932db880c3dce93d9c2dc29289bc389148b666",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLayersPayload(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseLayersPayload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// Test_layerOrder_consistentBetweenManifestAndVulnerabilities guards #617: a vulnerability's
// LayerOrder (via parseLayersPayload, which DomainToArmo attaches to each vulnerability) and
// the same layer's LayerOrder in ParseImageManifest's output must agree, so a consumer can
// correlate a vulnerability to its build step. History mixes metadata-only entries (no layer)
// between real, layer-producing ones, which is what previously made the two disagree.
func Test_layerOrder_consistentBetweenManifestAndVulnerabilities(t *testing.T) {
	config := containerRegistryV1.ConfigFile{
		History: []containerRegistryV1.History{
			{CreatedBy: "ENV BASE=1", EmptyLayer: true},
			{CreatedBy: "FROM base", EmptyLayer: false},
			{CreatedBy: "ENV FOO=bar", EmptyLayer: true},
			{CreatedBy: "LABEL x=y", EmptyLayer: true},
			{CreatedBy: "COPY app /app", EmptyLayer: false},
			{CreatedBy: "CMD [\"/app\"]", EmptyLayer: true},
		},
		RootFS: containerRegistryV1.RootFS{
			DiffIDs: []containerRegistryV1.Hash{
				{Algorithm: "sha256", Hex: "aaaa000000000000000000000000000000000000000000000000000000000000"},
				{Algorithm: "sha256", Hex: "bbbb000000000000000000000000000000000000000000000000000000000000"},
			},
		},
	}
	configBytes, err := json.Marshal(config)
	assert.NoError(t, err)

	imageMetadata := source.ImageMetadata{
		RawConfig: configBytes,
		Layers: []source.LayerMetadata{
			{Digest: "sha256:aaaa000000000000000000000000000000000000000000000000000000000000", Size: 100},
			{Digest: "sha256:bbbb000000000000000000000000000000000000000000000000000000000000", Size: 200},
		},
	}
	targetBytes, err := json.Marshal(imageMetadata)
	assert.NoError(t, err)

	layerMap, err := parseLayersPayload(imageMetadata)
	assert.NoError(t, err)

	imageManifest, err := ParseImageManifest(&v1beta1.GrypeDocument{
		Source: &v1beta1.Source{Type: "image", Target: targetBytes},
	})
	assert.NoError(t, err)

	require.Len(t, imageManifest.Layers, 6)
	require.Len(t, layerMap, 2)
	assert.Equal(t, 1, layerMap[imageMetadata.Layers[0].Digest].LayerOrder)
	assert.Equal(t, 4, layerMap[imageMetadata.Layers[1].Digest].LayerOrder)
	assert.Equal(t, imageMetadata.Layers[0].Digest, layerMap[imageMetadata.Layers[1].Digest].ParentLayerHash)
	checked := 0
	for _, layer := range imageManifest.Layers {
		if layer.LayerHash == "" {
			continue
		}
		vulnLayer, ok := layerMap[layer.LayerHash]
		assert.True(t, ok, "layer %s missing from parseLayersPayload's map", layer.LayerHash)
		assert.Equal(t, vulnLayer.LayerOrder, layer.LayerOrder,
			"LayerOrder for layer %s disagrees between ParseImageManifest and parseLayersPayload", layer.LayerHash)
		checked++
	}
	assert.Equal(t, 2, checked, "expected to check both real layers")

	document := layeredDocument(imageMetadata.Layers[1].Digest)
	document.Source.Target = targetBytes
	ctx := context.WithValue(t.Context(), domain.WorkloadKey{}, domain.ScanCommand{})
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, "scan-history-orders")
	results, err := DomainToArmo(ctx, document, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Len(t, results[0].Layers, 1)
	assert.Equal(t, 4, results[0].Layers[0].LayerOrder)
	assert.Equal(t, imageMetadata.Layers[1].Digest, results[0].IntroducedInLayer)
}

func TestParseImageManifest_IncompleteLayerMetadata(t *testing.T) {
	history := []containerRegistryV1.History{
		{CreatedBy: "ENV BASE=1", EmptyLayer: true},
		{CreatedBy: "ADD base"},
		{CreatedBy: "LABEL x=y", EmptyLayer: true},
		{CreatedBy: "RUN install"},
		{CreatedBy: "CMD app", EmptyLayer: true},
	}
	diffIDs := []containerRegistryV1.Hash{
		{Algorithm: "sha256", Hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Algorithm: "sha256", Hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}
	layers := []source.LayerMetadata{
		{Digest: diffIDs[0].String(), Size: 100},
		{Digest: diffIDs[1].String(), Size: 200},
	}
	for _, tt := range []struct {
		name    string
		history []containerRegistryV1.History
		layers  []source.LayerMetadata
		diffIDs []containerRegistryV1.Hash
	}{
		{"complete", history, layers, diffIDs},
		{"missing raw layers", history, nil, diffIDs},
		{"truncated raw layers", history, layers[:1], diffIDs},
		{"truncated diff IDs", history, layers, diffIDs[:1]},
		{"metadata only", []containerRegistryV1.History{history[0], history[2], history[4]}, nil, nil},
		{"no history", nil, layers, diffIDs},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := containerRegistryV1.ConfigFile{
				History: tt.history,
				RootFS:  containerRegistryV1.RootFS{DiffIDs: tt.diffIDs},
			}
			for i := range config.History {
				config.History[i].Created = containerRegistryV1.Time{Time: time.Unix(int64(i), 0).UTC()}
			}
			rawConfig, err := json.Marshal(config)
			require.NoError(t, err)
			metadata := source.ImageMetadata{RawConfig: rawConfig, Layers: tt.layers}
			target, err := json.Marshal(metadata)
			require.NoError(t, err)
			manifest, err := ParseImageManifest(&v1beta1.GrypeDocument{Source: &v1beta1.Source{Target: target}})
			require.NoError(t, err)
			require.Len(t, manifest.Layers, len(tt.history))
			byOrder := make(map[int]containerscan.ESLayer)
			for i, layer := range manifest.Layers {
				byOrder[layer.LayerOrder] = layer
				assert.Equal(t, i, layer.LayerOrder)
				assert.Equal(t, config.History[i].CreatedBy, layer.CreatedBy)
				assert.Equal(t, &config.History[i].Created.Time, layer.CreatedTime)
			}
			assert.Len(t, byOrder, len(tt.history), "order-keyed consumers retain the complete history")
			payload, err := parseLayersPayload(metadata)
			require.NoError(t, err)
			if len(tt.history) == 0 || tt.history[1].EmptyLayer {
				assert.Empty(t, payload)
				for _, layer := range manifest.Layers {
					assert.Empty(t, layer.LayerHash)
					assert.Zero(t, layer.Size)
				}
				return
			}
			for physical, order := range []int{1, 3} {
				if physical < len(tt.layers) {
					assert.Equal(t, tt.layers[physical].Digest, manifest.Layers[order].LayerHash)
					assert.EqualValues(t, tt.layers[physical].Size, manifest.Layers[order].Size)
				} else {
					assert.Empty(t, manifest.Layers[order].LayerHash)
					assert.Zero(t, manifest.Layers[order].Size)
				}
				if physical < len(tt.diffIDs) {
					layer, ok := payload[tt.diffIDs[physical].String()]
					require.True(t, ok)
					assert.Equal(t, order, layer.LayerOrder)
				}
			}
			assert.Len(t, payload, len(tt.diffIDs))
		})
	}
}

func Test_suggestedVersion(t *testing.T) {
	tests := []struct {
		name         string
		current      string
		versions     []string
		artifactType v1beta1.SyftType
		want         string
	}{
		{
			name:     "Test with empty versions",
			current:  "1.0.0",
			versions: []string{},
			want:     "",
		},
		{
			name:     "Test with empty current",
			current:  "",
			versions: []string{"1.0.0", "2.0.0"},
			want:     "1.0.0",
		},
		{
			name:     "Test with one version",
			current:  "1.0.0",
			versions: []string{"2.0.0"},
			want:     "2.0.0",
		},
		{
			name:     "Test with real versions",
			current:  "14.7.0",
			versions: []string{"10.24.0", "12.21.0", "14.16.0", "15.10.0"},
			want:     "14.16.0",
		},
		{
			// versions is not guaranteed to be sorted; the fix listed first for an
			// older branch must not win over the nearer fix listed later.
			name:     "unsorted branch list picks the nearest fix, not the first entry",
			current:  "14.7.0",
			versions: []string{"15.10.0", "10.24.0", "14.16.0"},
			want:     "14.16.0",
		},
		{
			// every listed fix version is for a branch already superseded by current;
			// there is no upgrade to suggest, so this must not fall back to versions[0]
			// and suggest a downgrade.
			name:     "no version above current returns empty rather than a downgrade",
			current:  "16.0.0",
			versions: []string{"10.0.0", "12.0.0"},
			want:     "",
		},
		{
			name:     "current equal to the only candidate returns empty, not a downgrade",
			current:  "2.0.0",
			versions: []string{"2.0.0"},
			want:     "",
		},
		{
			name:     "unparseable entries are skipped in favour of a valid nearer fix",
			current:  "1.0.0",
			versions: []string{"not-a-version", "3.0.0", "2.0.0"},
			want:     "2.0.0",
		},
		{
			// current parses, but nothing in versions does: there is no comparable
			// candidate, so nothing is suggested.
			name:     "current parses but every version is unparseable returns empty",
			current:  "1.0.0",
			versions: []string{"not-a-version", "also-not-a-version"},
			want:     "",
		},
		{
			// #955: an epoch-prefixed dpkg/rpm version (e.g. after an epoch bump) is not
			// valid semver, so it used to fail to parse and fall back to versions[0]
			// unconditionally - suggesting this very downgrade. Grype's own deb comparator
			// understands the epoch and must not suggest going backwards.
			name:         "deb epoch: no version above current returns empty, never a downgrade",
			current:      "1:1.2.11.dfsg-2ubuntu1.2",
			versions:     []string{"1:1.2.11.dfsg-2ubuntu1.1"},
			artifactType: "deb",
			want:         "",
		},
		{
			name:         "deb epoch: a real newer fix across an epoch is still found",
			current:      "1:1.2.11.dfsg-2ubuntu1.1",
			versions:     []string{"1:1.2.11.dfsg-2ubuntu1.3", "1:1.2.11.dfsg-2ubuntu1.2"},
			artifactType: "deb",
			want:         "1:1.2.11.dfsg-2ubuntu1.2",
		},
		{
			// rpm versions carry the same epoch:version-release shape as deb.
			name:         "rpm epoch: no version above current returns empty, never a downgrade",
			current:      "1:1.12.8-26.el8",
			versions:     []string{"1:1.12.8-25.el8"},
			artifactType: "rpm",
			want:         "",
		},
		{
			// #955: Alpine apk release revisions ("-rN") are numeric, but generic semver
			// treats them as prerelease identifiers and orders "-r10" before "-r9"
			// lexically, hiding a real, newer fix. Grype's own apk comparator orders them
			// numerically.
			name:         "apk revision: a real newer fix at a two-digit revision is found",
			current:      "3.4.7-r9",
			versions:     []string{"3.4.7-r10"},
			artifactType: "apk",
			want:         "3.4.7-r10",
		},
		{
			name:         "apk revision: nearest of several revisions is picked, not the first",
			current:      "3.4.7-r9",
			versions:     []string{"3.4.7-r99", "3.4.7-r10"},
			artifactType: "apk",
			want:         "3.4.7-r10",
		},
		{
			// A recognized distro artifact whose current version fails to parse under its
			// own ecosystem's comparator must not fall through to semver and guess
			// versions[0]: semver was never meant to parse an apk version either, and
			// "not-a-version" gives no proof any of these candidates is actually newer.
			name:         "apk artifact with an unparseable current returns empty, not the first entry",
			current:      "not-a-version",
			versions:     []string{"1.0.0", "2.0.0"},
			artifactType: "apk",
			want:         "",
		},
		{
			// Grype's RPM comparator only compares epochs when both sides carry one
			// explicitly, instead of treating a missing epoch as 0 per RPM's own spec. A
			// current version with an explicit higher epoch can therefore be judged older
			// than a candidate that merely omits its epoch, even though the candidate is
			// really the same or an older release: "1" compares as newer than "1:0" by
			// version string alone once epochs are skipped. This must not be trusted as a
			// real upgrade.
			name:         "rpm mixed epoch presence is not trusted as an upgrade",
			current:      "1:0",
			versions:     []string{"1"},
			artifactType: "rpm",
			want:         "",
		},
		{
			// Grype's RPM tokenizer has no notion of "^" (RPM's post-release/snapshot
			// marker): the caret is dropped and the surrounding digits are compared as an
			// ordinary numeric segment, so "1.0^20250611" ranks above "1.0.1" even though
			// RPM itself orders a caret-tagged snapshot below the release that supersedes
			// it. This must not be trusted as a real upgrade either.
			name:         "rpm caret release is not trusted as an upgrade",
			current:      "1.0.1",
			versions:     []string{"1.0^20250611"},
			artifactType: "rpm",
			want:         "",
		},
		{
			// The epoch/caret guards must not reject ordinary RPM comparisons: same
			// epoch-presence on both sides, no caret, is unaffected.
			name:         "rpm ordinary comparison is unaffected by the safety guards",
			current:      "1:1.12.8-25.el8",
			versions:     []string{"1:1.12.8-27.el8", "1:1.12.8-26.el8"},
			artifactType: "rpm",
			want:         "1:1.12.8-26.el8",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, suggestedVersion(tt.current, tt.versions, tt.artifactType))
		})
	}
}

// Test_rpmSafeToCompare exercises the guard in isolation, independent of
// suggestedVersion's candidate-selection logic.
func Test_rpmSafeToCompare(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "neither side has an epoch", a: "1.12.8-25.el8", b: "1.12.8-26.el8", want: true},
		{name: "both sides have an epoch", a: "1:1.12.8-25.el8", b: "1:1.12.8-26.el8", want: true},
		{name: "a has an epoch, b does not", a: "1:0", b: "1", want: false},
		{name: "b has an epoch, a does not", a: "1", b: "1:0", want: false},
		{name: "caret in a", a: "1.0^20250611", b: "1.0.1", want: false},
		{name: "caret in b", a: "1.0.1", b: "1.0^20250611", want: false},
		{name: "caret in both", a: "1.0^1", b: "1.0^2", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rpmSafeToCompare(tt.a, tt.b))
		})
	}
}

func Test_linkToVuln(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{
			name: "GHSA advisory",
			id:   "GHSA-jc7w-c686-c4v9",
			want: "https://github.com/advisories/GHSA-jc7w-c686-c4v9",
		},
		{
			name: "EUVD advisory",
			id:   "EUVD-2022-1234",
			want: "https://euvd.enisa.europa.eu/enisa/EUVD-2022-1234",
		},
		{
			name: "RHSA advisory",
			id:   "RHSA-2026:49525",
			want: "https://access.redhat.com/errata/RHSA-2026:49525",
		},
		{
			name: "USN advisory",
			id:   "USN-6896-1",
			want: "https://ubuntu.com/security/notices/USN-6896-1/",
		},
		{
			name: "DSA advisory",
			id:   "DSA-1234",
			want: "https://security-tracker.debian.org/tracker/DSA-1234",
		},
		{
			name: "ELSA advisory",
			id:   "ELSA-2026-1234",
			want: "https://linux.oracle.com/errata/ELSA-2026-1234.html",
		},
		{
			name: "RLSA advisory",
			id:   "RLSA-2026:1111",
			want: "https://errata.rockylinux.org/RLSA-2026:1111",
		},
		{
			name: "ALAS advisory",
			id:   "ALAS-2026-123",
			want: "https://alas.aws.amazon.com/ALAS-2026-123.html",
		},
		{
			name: "ALAS2 advisory",
			id:   "ALAS2-2026-123",
			want: "https://alas.aws.amazon.com/AL2/ALAS-2026-123.html",
		},
		{
			name: "ALAS2023 advisory",
			id:   "ALAS2023-2026-123",
			want: "https://alas.aws.amazon.com/AL2023/ALAS-2026-123.html",
		},
		{
			name: "CVE defaults to NVD",
			id:   "CVE-2021-21300",
			want: "https://nvd.nist.gov/vuln/detail/CVE-2021-21300",
		},
		{
			name: "short corrupt id not EUVD",
			id:   "E",
			want: "https://nvd.nist.gov/vuln/detail/E",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, linkToVuln(tt.id))
		})
	}
}

// threeLayerSource describes an image with three layers, so a package can be placed in one
// that is not the base.
const threeLayerSource = `{"userInput":"","imageID":"","manifestDigest":"","mediaType":"","tags":null,"imageSize":0,"layers":[{"mediaType":"","digest":"sha256:l1","size":0},{"mediaType":"","digest":"sha256:l2","size":0},{"mediaType":"","digest":"sha256:l3","size":0}],"manifest":null,"config":null,"repoDigests":null,"architecture":"","os":""}`

func layeredDocument(fileSystemIDs ...string) v1beta1.GrypeDocument {
	locations := make([]v1beta1.SyftCoordinates, 0, len(fileSystemIDs))
	for _, id := range fileSystemIDs {
		locations = append(locations, v1beta1.SyftCoordinates{FileSystemID: id})
	}
	return v1beta1.GrypeDocument{
		Source: &v1beta1.Source{Target: json.RawMessage(threeLayerSource)},
		Matches: []v1beta1.Match{{
			Vulnerability: v1beta1.Vulnerability{
				VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-21300"},
			},
			Artifact: v1beta1.GrypePackage{Name: "pkg", Locations: locations},
		}},
	}
}

// IntroducedInLayer is the earliest layer a package appears in. It used to be resolved by
// walking the parent chain from "", which only ever completed for a package present in the
// image's first layer: nothing could start the chain for one added later, so every package
// outside the base layer reported no introducing layer at all.
func Test_domainToArmo_introducedInLayer(t *testing.T) {
	tests := []struct {
		name      string
		locations []string
		want      string
	}{
		{"base layer", []string{"sha256:l1"}, "sha256:l1"},
		{"middle layer", []string{"sha256:l2"}, "sha256:l2"},
		{"top layer", []string{"sha256:l3"}, "sha256:l3"},
		{"several layers, earliest wins", []string{"sha256:l3", "sha256:l2"}, "sha256:l2"},
		{"several layers, already ordered", []string{"sha256:l2", "sha256:l3"}, "sha256:l2"},
		{"layer not in the image", []string{"sha256:unknown"}, "sha256:unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, domain.ScanCommand{ImageHash: "h", ImageTagNormalized: "t"})
			ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
			ctx = context.WithValue(ctx, domain.ScanIDKey{}, "scan-1")

			got, err := DomainToArmo(ctx, layeredDocument(tt.locations...), nil)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, tt.want, got[0].IntroducedInLayer)
		})
	}
}

// An order-keyed consumer must retain every build step, including metadata-only entries.
func TestParseImageManifest_LayerOrderNamesOneLayer(t *testing.T) {
	rawConfig := []byte(`{
	  "architecture":"amd64","os":"linux",
	  "rootfs":{"type":"layers","diff_ids":[
	    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]},
	  "history":[
	    {"created":"2024-01-01T00:00:00Z","created_by":"ADD file"},
	    {"created":"2024-01-01T00:00:01Z","created_by":"ENV x=1","empty_layer":true},
	    {"created":"2024-01-01T00:00:02Z","created_by":"CMD [\"sh\"]","empty_layer":true},
	    {"created":"2024-01-01T00:00:03Z","created_by":"RUN apk add"}]
	}`)
	target, err := json.Marshal(source.ImageMetadata{
		RawConfig: rawConfig,
		Layers: []source.LayerMetadata{
			{Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", Size: 100},
			{Digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222", Size: 200},
		},
	})
	require.NoError(t, err)

	im, err := ParseImageManifest(&v1beta1.GrypeDocument{Source: &v1beta1.Source{Type: "image", Target: target}})
	require.NoError(t, err)
	require.Len(t, im.Layers, 4, "every history entry is still reported")

	seen := map[int]int{}
	for i, l := range im.Layers {
		assert.Equal(t, i, l.LayerOrder)
		seen[l.LayerInfo.LayerOrder]++
	}
	assert.Equal(t, map[int]int{0: 1, 1: 1, 2: 1, 3: 1}, seen,
		"every history entry must have a distinct chronological order")
}

// TestDomainToArmo_IsFixedAgreesWithFixes pins the two "is there a fix?" answers a single
// report record carries, which are produced from different halves of hasKnownFix.
//
// IsFixed comes from the bool. Fixes[].Version comes from the version string, and the
// backend summary counts fixes from that, via containerscan.CalculateFixed, which ignores
// an entry whose Version is "" or "None". So an empty version alongside a true bool makes a
// record contradict itself: IsFixed=1, yet contributing 0 to FixAvailableOfTotalCount.
//
// The two cases below are the ones that reach it, both being "a fix exists but nothing
// above what is installed": every listed fix version older than current, and the only
// listed one equal to it.
func TestDomainToArmo_IsFixedAgreesWithFixes(t *testing.T) {
	tests := []struct {
		name        string
		installed   string
		fixVersions []string
		wantVersion string
	}{
		{
			name:        "a real upgrade is suggested",
			installed:   "1.0.0",
			fixVersions: []string{"1.5.0", "1.2.0"},
			wantVersion: "1.2.0",
		},
		{
			name:        "every fix version is older than installed",
			installed:   "2.0.0",
			fixVersions: []string{"1.5.0", "1.2.0"},
			wantVersion: unknownFixVersion,
		},
		{
			name:        "the only fix version equals installed",
			installed:   "1.5.0",
			fixVersions: []string{"1.5.0"},
			wantVersion: unknownFixVersion,
		},
		{
			name:        "installed version is not a version",
			installed:   "not-a-version",
			fixVersions: []string{"1.5.0"},
			wantVersion: "1.5.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := v1beta1.GrypeDocument{
				Source: &v1beta1.Source{Target: json.RawMessage(threeLayerSource)},
				Matches: []v1beta1.Match{{
					Vulnerability: v1beta1.Vulnerability{
						VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2024-0001", Severity: "High"},
						Fix:                   v1beta1.Fix{State: fixStateFixed, Versions: tt.fixVersions},
					},
					Artifact: v1beta1.GrypePackage{Name: "pkg", Version: tt.installed},
				}},
			}

			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
			ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
			ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})

			got, err := DomainToArmo(ctx, doc, nil)
			require.NoError(t, err)
			require.Len(t, got, 1)

			r := got[0]
			require.Len(t, r.Fixes, 1)
			assert.Equal(t, tt.wantVersion, r.Fixes[0].Version)

			// The property itself: a record that says it is fixed has to count as fixed.
			assert.Equal(t, 1, r.IsFixed)
			assert.Equal(t, 1, containerscan.CalculateFixed(r.Fixes),
				"IsFixed=%d but CalculateFixed=%d: the record contradicts itself",
				r.IsFixed, containerscan.CalculateFixed(r.Fixes))
		})
	}
}
