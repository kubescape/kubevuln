package v1

import (
	"encoding/json"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/file"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func grypeToDomain(grypeDoc models.Document) (*v1beta1.GrypeDocument, error) {
	doc := v1beta1.GrypeDocument{
		Matches:        grypeToDomainMatches(grypeDoc.Matches),
		IgnoredMatches: grypeToDomainIgnoredMatches(grypeDoc.IgnoredMatches),
		Distro: v1beta1.Distribution{
			Name:    grypeDoc.Distro.Name,
			Version: grypeDoc.Distro.Version,
			IDLike:  grypeDoc.Distro.IDLike,
		},
		Descriptor: v1beta1.Descriptor{
			Name:                  grypeDoc.Descriptor.Name,
			Version:               grypeDoc.Descriptor.Version,
			Configuration:         toRawMessage(grypeDoc.Descriptor.Configuration),
			VulnerabilityDBStatus: toRawMessage(grypeDoc.Descriptor.VulnerabilityDBStatus),
		},
	}
	if grypeDoc.Source != nil {
		doc.Source = &v1beta1.Source{
			Type:   grypeDoc.Source.Type,
			Target: toRawMessage(grypeDoc.Source.Target),
		}
	}
	return &doc, nil
}

func toRawMessage(v interface{}) json.RawMessage {
	if v == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	return b
}

func grypeToDomainMatches(matches []models.Match) []v1beta1.Match {
	var result []v1beta1.Match
	for _, m := range matches {
		result = append(result, v1beta1.Match{
			Vulnerability: v1beta1.Vulnerability{
				VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
					ID:          m.Vulnerability.VulnerabilityMetadata.ID,
					DataSource:  m.Vulnerability.VulnerabilityMetadata.DataSource,
					Namespace:   m.Vulnerability.VulnerabilityMetadata.Namespace,
					Severity:    m.Vulnerability.VulnerabilityMetadata.Severity,
					URLs:        m.Vulnerability.VulnerabilityMetadata.URLs,
					Description: m.Vulnerability.VulnerabilityMetadata.Description,
					Cvss:        grypeToDomainMatchesCvss(m.Vulnerability.VulnerabilityMetadata.Cvss),
				},
				Fix: v1beta1.Fix{
					Versions: m.Vulnerability.Fix.Versions,
					State:    m.Vulnerability.Fix.State,
				},
				Advisories: grypeToDomainMatchesAdvisories(m.Vulnerability.Advisories),
			},
			RelatedVulnerabilities: grypeToDomainMatchesRelatedVulnerabilities(m.RelatedVulnerabilities),
			MatchDetails:           grypeToDomainMatchesMatchDetails(m.MatchDetails),
			Artifact: v1beta1.GrypePackage{
				Name:         m.Artifact.Name,
				Version:      m.Artifact.Version,
				Type:         v1beta1.SyftType(m.Artifact.Type),
				Locations:    grypeToDomainMatchesLocations(m.Artifact.Locations),
				Language:     v1beta1.SyftLanguage(m.Artifact.Language),
				Licenses:     m.Artifact.Licenses,
				CPEs:         m.Artifact.CPEs,
				PURL:         m.Artifact.PURL,
				Upstreams:    grypeToDomainMatchesUpstreams(m.Artifact.Upstreams),
				MetadataType: v1beta1.MetadataType(m.Artifact.MetadataType),
				Metadata:     toRawMessage(m.Artifact.Metadata),
			},
		})
	}
	return result
}

func grypeToDomainMatchesCvss(cvss []models.Cvss) []v1beta1.Cvss {
	var result []v1beta1.Cvss
	for _, c := range cvss {
		result = append(result, v1beta1.Cvss{
			Version: c.Version,
			Vector:  c.Vector,
			Metrics: v1beta1.CvssMetrics{
				BaseScore:           c.Metrics.BaseScore,
				ExploitabilityScore: c.Metrics.ExploitabilityScore,
				ImpactScore:         c.Metrics.ImpactScore,
			},
			VendorMetadata: toRawMessage(c.VendorMetadata),
		})
	}
	return result
}

func grypeToDomainMatchesAdvisories(advisories []models.Advisory) []v1beta1.Advisory {
	var result []v1beta1.Advisory
	for _, a := range advisories {
		result = append(result, v1beta1.Advisory{
			ID:   a.ID,
			Link: a.Link,
		})
	}
	return result
}

func grypeToDomainMatchesRelatedVulnerabilities(relatedVulnerabilities []models.VulnerabilityMetadata) []v1beta1.VulnerabilityMetadata {
	var result []v1beta1.VulnerabilityMetadata
	for _, v := range relatedVulnerabilities {
		result = append(result, v1beta1.VulnerabilityMetadata{
			ID:          v.ID,
			DataSource:  v.DataSource,
			Namespace:   v.Namespace,
			Severity:    v.Severity,
			URLs:        v.URLs,
			Description: v.Description,
			Cvss:        nil,
		})
	}
	return result
}

func grypeToDomainMatchesMatchDetails(matchDetails []models.MatchDetails) []v1beta1.MatchDetails {
	var result []v1beta1.MatchDetails
	for _, m := range matchDetails {
		result = append(result, v1beta1.MatchDetails{
			Type:       m.Type,
			Matcher:    m.Matcher,
			SearchedBy: toRawMessage(m.SearchedBy),
			Found:      toRawMessage(m.Found),
		})
	}
	return result
}

func grypeToDomainMatchesLocations(locations []file.Coordinates) []v1beta1.SyftCoordinates {
	var result []v1beta1.SyftCoordinates
	for _, l := range locations {
		result = append(result, v1beta1.SyftCoordinates{
			RealPath:     l.RealPath,
			FileSystemID: l.FileSystemID,
		})
	}
	return result
}

func grypeToDomainMatchesUpstreams(upstreams []models.UpstreamPackage) []v1beta1.UpstreamPackage {
	var result []v1beta1.UpstreamPackage
	for _, u := range upstreams {
		result = append(result, v1beta1.UpstreamPackage{
			Name:    u.Name,
			Version: u.Version,
		})
	}
	return result
}

func grypeToDomainIgnoredMatches(ignoredMatches []models.IgnoredMatch) []v1beta1.IgnoredMatch {
	var result []v1beta1.IgnoredMatch
	for _, m := range ignoredMatches {
		result = append(result, v1beta1.IgnoredMatch{
			Match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{
					VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
						ID:          m.Vulnerability.VulnerabilityMetadata.ID,
						DataSource:  m.Vulnerability.VulnerabilityMetadata.DataSource,
						Namespace:   m.Vulnerability.VulnerabilityMetadata.Namespace,
						Severity:    m.Vulnerability.VulnerabilityMetadata.Severity,
						URLs:        m.Vulnerability.VulnerabilityMetadata.URLs,
						Description: m.Vulnerability.VulnerabilityMetadata.Description,
						Cvss:        grypeToDomainMatchesCvss(m.Vulnerability.VulnerabilityMetadata.Cvss),
					},
					Fix: v1beta1.Fix{
						Versions: m.Vulnerability.Fix.Versions,
						State:    m.Vulnerability.Fix.State,
					},
					Advisories: grypeToDomainMatchesAdvisories(m.Vulnerability.Advisories),
				},
				RelatedVulnerabilities: grypeToDomainMatchesRelatedVulnerabilities(m.RelatedVulnerabilities),
				MatchDetails:           grypeToDomainMatchesMatchDetails(m.MatchDetails),
				Artifact: v1beta1.GrypePackage{
					Name:         m.Artifact.Name,
					Version:      m.Artifact.Version,
					Type:         v1beta1.SyftType(m.Artifact.Type),
					Locations:    grypeToDomainMatchesLocations(m.Artifact.Locations),
					Language:     v1beta1.SyftLanguage(m.Artifact.Language),
					Licenses:     m.Artifact.Licenses,
					CPEs:         m.Artifact.CPEs,
					PURL:         m.Artifact.PURL,
					Upstreams:    grypeToDomainMatchesUpstreams(m.Artifact.Upstreams),
					MetadataType: v1beta1.MetadataType(m.Artifact.MetadataType),
					Metadata:     toRawMessage(m.Artifact.Metadata),
				},
			},
			AppliedIgnoreRules: grypeToDomainIgnoredMatchesAppliedIgnoreRules(m.AppliedIgnoreRules),
		})
	}
	return result
}

func grypeToDomainIgnoredMatchesAppliedIgnoreRules(appliedIgnoreRules []models.IgnoreRule) []v1beta1.IgnoreRule {
	var result []v1beta1.IgnoreRule
	for _, r := range appliedIgnoreRules {
		result = append(result, v1beta1.IgnoreRule{
			Vulnerability: r.Vulnerability,
			FixState:      r.FixState,
			Package:       (*v1beta1.IgnoreRulePackage)(r.Package),
		})
	}
	return result
}
