package v1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/anchore/syft/syft/source"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/cluster-container-scanner-api/containerscan"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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
			got, err := domainToArmo(ctx, tt.grypeDocument, tt.vulnerabilityExceptionPolicyList)
			if (err != nil) != tt.wantErr {
				t.Errorf("domainToArmo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got[0].ContainerScanID = ""
			got[0].Timestamp = 0
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_parseLayersPayload(t *testing.T) {
	c := v1.ConfigFile{
		History: []v1.History{
			{EmptyLayer: false},
			{EmptyLayer: false},
		},
		RootFS: v1.RootFS{
			DiffIDs: []v1.Hash{
				{Algorithm: "sha256", Hex: "5f6201014d118db78bfb090a1e932db880c3dce93d9c2dc29289bc389148b666"},
				{Algorithm: "sha256", Hex: "55b314485cd7090cd64730398b85f42bd9b6d3bb33b6eddfc043154692c51b99"},
			},
		},
	}
	data, _ := json.Marshal(c)
	config := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(config, data)
	tests := []struct {
		name    string
		target  source.ImageMetadata
		want    map[string]containerscan.ESLayer
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
