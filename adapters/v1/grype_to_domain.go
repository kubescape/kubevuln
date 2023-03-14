package v1

import (
	"encoding/json"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/source"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
)

func grypeToDomain(grypeDoc models.Document) (*softwarecomposition.GrypeDocument, error) {
	doc := softwarecomposition.GrypeDocument{
		Matches:        grypeToDomainMatches(grypeDoc.Matches),
		IgnoredMatches: grypeToDomainIgnoredMatches(grypeDoc.IgnoredMatches),
		Distro: softwarecomposition.Distribution{
			Name:    grypeDoc.Distro.Name,
			Version: grypeDoc.Distro.Version,
			IDLike:  grypeDoc.Distro.IDLike,
		},
		Descriptor: softwarecomposition.Descriptor{
			Name:                  grypeDoc.Descriptor.Name,
			Version:               grypeDoc.Descriptor.Version,
			Configuration:         toRawMessage(grypeDoc.Descriptor.Configuration),
			VulnerabilityDBStatus: toRawMessage(grypeDoc.Descriptor.VulnerabilityDBStatus),
		},
	}
	if grypeDoc.Source != nil {
		doc.Source = &softwarecomposition.Source{
			Type:   grypeDoc.Source.Type,
			Target: toRawMessage(grypeDoc.Source.Target),
		}
	}
	return &doc, nil
}

func toRawMessage(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func grypeToDomainMatches(matches []models.Match) []softwarecomposition.Match {
	var result []softwarecomposition.Match
	for _, m := range matches {
		result = append(result, softwarecomposition.Match{
			Vulnerability: softwarecomposition.Vulnerability{
				VulnerabilityMetadata: softwarecomposition.VulnerabilityMetadata{
					ID:          m.Vulnerability.VulnerabilityMetadata.ID,
					DataSource:  m.Vulnerability.VulnerabilityMetadata.DataSource,
					Namespace:   m.Vulnerability.VulnerabilityMetadata.Namespace,
					Severity:    m.Vulnerability.VulnerabilityMetadata.Severity,
					URLs:        m.Vulnerability.VulnerabilityMetadata.URLs,
					Description: m.Vulnerability.VulnerabilityMetadata.Description,
					Cvss:        grypeToDomainMatchesCvss(m.Vulnerability.VulnerabilityMetadata.Cvss),
				},
				Fix: softwarecomposition.Fix{
					Versions: m.Vulnerability.Fix.Versions,
					State:    m.Vulnerability.Fix.State,
				},
				Advisories: grypeToDomainMatchesAdvisories(m.Vulnerability.Advisories),
			},
			RelatedVulnerabilities: grypeToDomainMatchesRelatedVulnerabilities(m.RelatedVulnerabilities),
			MatchDetails:           grypeToDomainMatchesMatchDetails(m.MatchDetails),
			Artifact: softwarecomposition.GrypePackage{
				Name:         m.Artifact.Name,
				Version:      m.Artifact.Version,
				Type:         softwarecomposition.SyftType(m.Artifact.Type),
				Locations:    grypeToDomainMatchesLocations(m.Artifact.Locations),
				Language:     softwarecomposition.SyftLanguage(m.Artifact.Language),
				Licenses:     m.Artifact.Licenses,
				CPEs:         m.Artifact.CPEs,
				PURL:         m.Artifact.PURL,
				Upstreams:    grypeToDomainMatchesUpstreams(m.Artifact.Upstreams),
				MetadataType: softwarecomposition.MetadataType(m.Artifact.MetadataType),
				Metadata:     toRawMessage(m.Artifact.Metadata),
			},
		})
	}
	return result
}

func grypeToDomainMatchesCvss(cvss []models.Cvss) []softwarecomposition.Cvss {
	var result []softwarecomposition.Cvss
	for _, c := range cvss {
		result = append(result, softwarecomposition.Cvss{
			Version: c.Version,
			Vector:  c.Vector,
			Metrics: softwarecomposition.CvssMetrics{
				BaseScore:           c.Metrics.BaseScore,
				ExploitabilityScore: c.Metrics.ExploitabilityScore,
				ImpactScore:         c.Metrics.ImpactScore,
			},
			VendorMetadata: toRawMessage(c.VendorMetadata),
		})
	}
	return result
}

func grypeToDomainMatchesAdvisories(advisories []models.Advisory) []softwarecomposition.Advisory {
	var result []softwarecomposition.Advisory
	for _, a := range advisories {
		result = append(result, softwarecomposition.Advisory{
			ID:   a.ID,
			Link: a.Link,
		})
	}
	return result
}

func grypeToDomainMatchesRelatedVulnerabilities(relatedVulnerabilities []models.VulnerabilityMetadata) []softwarecomposition.VulnerabilityMetadata {
	var result []softwarecomposition.VulnerabilityMetadata
	for _, v := range relatedVulnerabilities {
		result = append(result, softwarecomposition.VulnerabilityMetadata{
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

func grypeToDomainMatchesMatchDetails(matchDetails []models.MatchDetails) []softwarecomposition.MatchDetails {
	var result []softwarecomposition.MatchDetails
	for _, m := range matchDetails {
		result = append(result, softwarecomposition.MatchDetails{
			Type:       m.Type,
			Matcher:    m.Matcher,
			SearchedBy: toRawMessage(m.SearchedBy),
			Found:      toRawMessage(m.Found),
		})
	}
	return result
}

func grypeToDomainMatchesLocations(locations []source.Coordinates) []softwarecomposition.SyftCoordinates {
	var result []softwarecomposition.SyftCoordinates
	for _, l := range locations {
		result = append(result, softwarecomposition.SyftCoordinates{
			RealPath:     l.RealPath,
			FileSystemID: l.FileSystemID,
		})
	}
	return result
}

func grypeToDomainMatchesUpstreams(upstreams []models.UpstreamPackage) []softwarecomposition.UpstreamPackage {
	var result []softwarecomposition.UpstreamPackage
	for _, u := range upstreams {
		result = append(result, softwarecomposition.UpstreamPackage{
			Name:    u.Name,
			Version: u.Version,
		})
	}
	return result
}

func grypeToDomainIgnoredMatches(ignoredMatches []models.IgnoredMatch) []softwarecomposition.IgnoredMatch {
	var result []softwarecomposition.IgnoredMatch
	for _, m := range ignoredMatches {
		result = append(result, softwarecomposition.IgnoredMatch{
			Match: softwarecomposition.Match{
				Vulnerability: softwarecomposition.Vulnerability{
					VulnerabilityMetadata: softwarecomposition.VulnerabilityMetadata{
						ID:          m.Vulnerability.VulnerabilityMetadata.ID,
						DataSource:  m.Vulnerability.VulnerabilityMetadata.DataSource,
						Namespace:   m.Vulnerability.VulnerabilityMetadata.Namespace,
						Severity:    m.Vulnerability.VulnerabilityMetadata.Severity,
						URLs:        m.Vulnerability.VulnerabilityMetadata.URLs,
						Description: m.Vulnerability.VulnerabilityMetadata.Description,
						Cvss:        grypeToDomainMatchesCvss(m.Vulnerability.VulnerabilityMetadata.Cvss),
					},
					Fix: softwarecomposition.Fix{
						Versions: m.Vulnerability.Fix.Versions,
						State:    m.Vulnerability.Fix.State,
					},
					Advisories: grypeToDomainMatchesAdvisories(m.Vulnerability.Advisories),
				},
				RelatedVulnerabilities: grypeToDomainMatchesRelatedVulnerabilities(m.RelatedVulnerabilities),
				MatchDetails:           grypeToDomainMatchesMatchDetails(m.MatchDetails),
				Artifact: softwarecomposition.GrypePackage{
					Name:         m.Artifact.Name,
					Version:      m.Artifact.Version,
					Type:         softwarecomposition.SyftType(m.Artifact.Type),
					Locations:    grypeToDomainMatchesLocations(m.Artifact.Locations),
					Language:     softwarecomposition.SyftLanguage(m.Artifact.Language),
					Licenses:     m.Artifact.Licenses,
					CPEs:         m.Artifact.CPEs,
					PURL:         m.Artifact.PURL,
					Upstreams:    grypeToDomainMatchesUpstreams(m.Artifact.Upstreams),
					MetadataType: softwarecomposition.MetadataType(m.Artifact.MetadataType),
					Metadata:     toRawMessage(m.Artifact.Metadata),
				},
			},
			AppliedIgnoreRules: grypeToDomainIgnoredMatchesAppliedIgnoreRules(m.AppliedIgnoreRules),
		})
	}
	return result
}

func grypeToDomainIgnoredMatchesAppliedIgnoreRules(appliedIgnoreRules []models.IgnoreRule) []softwarecomposition.IgnoreRule {
	var result []softwarecomposition.IgnoreRule
	for _, r := range appliedIgnoreRules {
		result = append(result, softwarecomposition.IgnoreRule{
			Vulnerability: r.Vulnerability,
			FixState:      r.FixState,
			Package:       (*softwarecomposition.IgnoreRulePackage)(r.Package),
		})
	}
	return result
}
