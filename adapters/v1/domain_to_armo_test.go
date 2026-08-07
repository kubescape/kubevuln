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

func Test_suggestedVersion(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		versions []string
		want     string
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, suggestedVersion(tt.current, tt.versions))
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
