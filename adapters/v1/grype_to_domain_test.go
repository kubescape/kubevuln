package v1

import (
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/source"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func Test_grypeToDomain(t *testing.T) {
	tests := []struct {
		name     string
		grypeDoc models.Document
		want     *v1beta1.GrypeDocument
		wantErr  bool
	}{
		{
			name: "Test grypeToDomain",
			grypeDoc: models.Document{
				IgnoredMatches: []models.IgnoredMatch{{
					AppliedIgnoreRules: []models.IgnoreRule{{}},
				}},
				Matches: []models.Match{{
					Artifact: models.Package{
						Locations: []source.Coordinates{{}},
						Upstreams: []models.UpstreamPackage{{}},
					},
					MatchDetails:           []models.MatchDetails{{}},
					RelatedVulnerabilities: []models.VulnerabilityMetadata{{}},
					Vulnerability: models.Vulnerability{
						Advisories: []models.Advisory{{}},
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							Cvss: []models.Cvss{{}},
						},
					},
				}},
			},
			want: &v1beta1.GrypeDocument{
				IgnoredMatches: []v1beta1.IgnoredMatch{{
					AppliedIgnoreRules: []v1beta1.IgnoreRule{{}},
				}},
				Matches: []v1beta1.Match{{
					Artifact: v1beta1.GrypePackage{
						Locations: []v1beta1.SyftCoordinates{{}},
						Upstreams: []v1beta1.UpstreamPackage{{}},
					},
					MatchDetails:           []v1beta1.MatchDetails{{}},
					RelatedVulnerabilities: []v1beta1.VulnerabilityMetadata{{}},
					Vulnerability: v1beta1.Vulnerability{
						Advisories: []v1beta1.Advisory{{}},
						VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
							Cvss: []v1beta1.Cvss{{}},
						},
					},
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := grypeToDomain(tt.grypeDoc)
			if (err != nil) != tt.wantErr {
				t.Errorf("grypeToDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
