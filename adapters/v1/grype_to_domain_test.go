package v1

import (
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/file"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
						Locations: file.Locations{{}},
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

// models.IgnoredMatch embeds models.Match, so an ignored match goes through the same
// conversion as a regular one. The case above leaves that embedded Match zero, which would
// let the two paths disagree without failing anything.
func Test_grypeToDomain_ignoredMatchConvertsLikeAMatch(t *testing.T) {
	m := models.Match{
		Vulnerability: models.Vulnerability{
			VulnerabilityMetadata: models.VulnerabilityMetadata{
				ID:          "CVE-2021-44228",
				DataSource:  "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
				Namespace:   "nvd:cpe",
				Severity:    "Critical",
				URLs:        []string{"https://logging.apache.org/log4j/2.x/security.html"},
				Description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
				Cvss: []models.Cvss{{
					Version: "3.1",
					Vector:  "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
					Metrics: models.CvssMetrics{BaseScore: 10.0},
				}},
			},
			Fix:        models.Fix{Versions: []string{"2.15.0"}, State: "fixed"},
			Advisories: []models.Advisory{{ID: "GHSA-jfh8-c2jp-5v3q", Link: "https://github.com/advisories"}},
		},
		RelatedVulnerabilities: []models.VulnerabilityMetadata{{ID: "GHSA-jfh8-c2jp-5v3q", Namespace: "github:language:java"}},
		MatchDetails:           []models.MatchDetails{{Type: "exact-indirect-match", Matcher: "java-matcher"}},
		Artifact: models.Package{
			Name:      "log4j-core",
			Version:   "2.14.1",
			Type:      "java-archive",
			Language:  "java",
			Licenses:  []string{"Apache-2.0"},
			CPEs:      []string{"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
			PURL:      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			Upstreams: []models.UpstreamPackage{{Name: "log4j"}},
		},
	}

	got, err := grypeToDomain(models.Document{
		Matches: []models.Match{m},
		IgnoredMatches: []models.IgnoredMatch{{
			Match:              m,
			AppliedIgnoreRules: []models.IgnoreRule{{Vulnerability: "CVE-2021-44228"}},
		}},
	})
	require.NoError(t, err)
	require.Len(t, got.Matches, 1)
	require.Len(t, got.IgnoredMatches, 1)

	assert.Equal(t, got.Matches[0], got.IgnoredMatches[0].Match)

	// so the comparison above is not two zero values agreeing with each other
	assert.Equal(t, "CVE-2021-44228", got.IgnoredMatches[0].Vulnerability.ID)
	assert.Equal(t, "log4j-core", got.IgnoredMatches[0].Artifact.Name)
	assert.Equal(t, []string{"2.15.0"}, got.IgnoredMatches[0].Vulnerability.Fix.Versions)
	assert.Len(t, got.IgnoredMatches[0].Vulnerability.VulnerabilityMetadata.Cvss, 1)
	assert.Len(t, got.IgnoredMatches[0].AppliedIgnoreRules, 1)
}
