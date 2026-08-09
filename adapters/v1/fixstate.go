package v1

import (
	"encoding/json"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	// fixStateFixed is the Grype fix state indicating a fix has been released.
	fixStateFixed = "fixed"
	// unknownFixVersion is reported when a fix is known to exist but no concrete
	// version can be derived from the match.
	unknownFixVersion = "unknown"
)

// hasKnownFix reports whether a fix exists for a Grype match, along with the version
// to suggest for it. The version is "unknown" when a fix exists but no concrete
// version is available, and empty when no fix is known.
//
// A fix is considered known when any of the following hold:
//  1. The vulnerability carries concrete fixed versions.
//  2. Grype reports the fix state as "fixed".
//  3. A CPE match bounds the vulnerable range from above ("<"), which implies a fixed
//     version exists somewhere above that range.
//
// Both the in-cluster manifest path (ApplySecurityExceptions) and the backend report
// path (DomainToArmo) must decide "is this fixed?" the same way. When they disagree, an
// ExpiredOnFix exception is honoured on one surface and expired on the other, so the
// same CVE shows up as ignored in the VulnerabilityManifest but active in the report.
func hasKnownFix(m v1beta1.Match) (bool, string) {
	if len(m.Vulnerability.Fix.Versions) != 0 {
		return true, suggestedVersion(m.Artifact.Version, m.Vulnerability.Fix.Versions)
	}
	if m.Vulnerability.Fix.State == fixStateFixed {
		return true, unknownFixVersion
	}
	// no concrete version: fall back to CPE matches
	for _, detail := range m.MatchDetails {
		var found match.CPEResult
		if err := json.Unmarshal(detail.Found, &found); err != nil {
			continue
		}
		// we assume that if a higher version is mentioned in the CPE, then it is fixed somewhere
		if strings.Contains(found.VersionConstraint, "<") {
			return true, unknownFixVersion
		}
	}
	return false, ""
}
