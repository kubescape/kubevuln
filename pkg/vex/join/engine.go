package join

import (
	"strings"

	"github.com/kubescape/kubevuln/pkg/vex/parser"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	packageurl "github.com/package-url/packageurl-go"
)

// JoinEngine matches Grype scan findings against ingested VEX statements.
type JoinEngine struct {
	statements map[string][]parser.VEXStatement
}

// NewJoinEngine creates a JoinEngine indexed by CVE ID for O(1) lookups.
func NewJoinEngine(statements []parser.VEXStatement) *JoinEngine {
	index := make(map[string][]parser.VEXStatement)
	for _, stmt := range statements {
		index[stmt.CVE] = append(index[stmt.CVE], stmt)
	}
	return &JoinEngine{statements: index}
}

// ApplyVEXFilter filters doc.Matches against ingested VEX statements.
// Includes strict nil guards to prevent panics when doc or doc.Matches is nil (Issue #518).
// Appends provenance tracking metadata to doc.IgnoredMatches (Issue #488).
func (je *JoinEngine) ApplyVEXFilter(doc *v1beta1.GrypeDocument) map[string]int {
	suppressedCount := map[string]int{}
	if doc == nil || doc.Matches == nil || len(je.statements) == 0 {
		return suppressedCount
	}

	var remaining []v1beta1.Match
	for _, m := range doc.Matches {
		if stmts, found := je.statements[m.Vulnerability.ID]; found {
			var matchedStmt *parser.VEXStatement
			for i := range stmts {
				stmt := &stmts[i]
				// Match PURL using the OpenVEX-aligned packageurl-go algorithm (PR #542)
				if stmt.ProductPURL == "" || PURLMatches(stmt.ProductPURL, m.Artifact.PURL) {
					if stmt.Status == "not_affected" || stmt.Status == "fixed" {
						matchedStmt = stmt
						break
					}
				}
			}

			if matchedStmt != nil {
				// Enrich with provenance details directly on the manifest (Issue #488)
				doc.IgnoredMatches = append(doc.IgnoredMatches, v1beta1.IgnoredMatch{
					Match: m,
					AppliedIgnoreRules: []v1beta1.IgnoreRule{
						{
							Vulnerability: m.Vulnerability.ID,
							SourceKind:    "VEXSource",
							SourceName:    matchedStmt.StatementRef,
							Justification: matchedStmt.Justification,
						},
					},
				})
				suppressedCount["VEXSource"]++
				continue
			}
		}
		remaining = append(remaining, m)
	}

	doc.Matches = remaining
	return suppressedCount
}

// PURLMatches reports whether a VEX statement's PURL covers the scanned package PURL.
// Aligned with PR #542 (adapters/v1/subcomponent.go): unversioned PURLs match any version,
// version-qualified PURLs match only that version. Unparseable inputs fail closed (return false).
func PURLMatches(subcomponent, purl string) bool {
	if subcomponent == "" || purl == "" {
		return false
	}
	sub, err := packageurl.FromString(subcomponent)
	if err != nil {
		return false
	}
	pkg, err := packageurl.FromString(purl)
	if err != nil {
		return false
	}

	if !strings.EqualFold(sub.Type, pkg.Type) || sub.Namespace != pkg.Namespace || sub.Name != pkg.Name {
		return false
	}
	if sub.Version != "" && sub.Version != pkg.Version {
		return false
	}
	pkgQualifiers := pkg.Qualifiers.Map()
	for key, want := range sub.Qualifiers.Map() {
		if pkgQualifiers[key] != want {
			return false
		}
	}
	if sub.Subpath != "" && sub.Subpath != pkg.Subpath {
		return false
	}
	return true
}
