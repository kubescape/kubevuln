package join

import (
	"testing"
	"time"

	"github.com/kubescape/kubevuln/pkg/vex/parser"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPURLMatches_Rules(t *testing.T) {
	tests := []struct {
		name         string
		subcomponent string
		purl         string
		want         bool
	}{
		{
			name:         "exact version match",
			subcomponent: "pkg:alpine/openssl@3.0.2?arch=x86_64",
			purl:         "pkg:alpine/openssl@3.0.2?arch=x86_64",
			want:         true,
		},
		{
			name:         "unversioned subcomponent matches any version",
			subcomponent: "pkg:alpine/openssl",
			purl:         "pkg:alpine/openssl@3.0.2",
			want:         true,
		},
		{
			name:         "version mismatch",
			subcomponent: "pkg:alpine/openssl@3.0.2",
			purl:         "pkg:alpine/openssl@3.0.1",
			want:         false,
		},
		{
			name:         "qualifier mismatch",
			subcomponent: "pkg:alpine/openssl@3.0.2?arch=x86_64",
			purl:         "pkg:alpine/openssl@3.0.2?arch=arm64",
			want:         false,
		},
		{
			name:         "unconstrained qualifier in subcomponent",
			subcomponent: "pkg:alpine/openssl@3.0.2",
			purl:         "pkg:alpine/openssl@3.0.2?arch=x86_64",
			want:         true,
		},
		{
			name:         "fail-closed on unparseable subcomponent",
			subcomponent: "invalid-purl",
			purl:         "pkg:alpine/openssl@3.0.2",
			want:         false,
		},
		{
			name:         "fail-closed on unparseable pkg purl",
			subcomponent: "pkg:alpine/openssl@3.0.2",
			purl:         "not-a-purl",
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PURLMatches(tt.subcomponent, tt.purl)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestJoinEngine_ApplyVEXFilter(t *testing.T) {
	statements := []parser.VEXStatement{
		{
			CVE:           "CVE-2026-1000",
			Status:        "not_affected",
			Justification: "vulnerable_code_not_in_execute_path",
			StatementRef:  "http://example.com/vex/statement/1",
			ProductPURL:   "pkg:alpine/openssl@3.0.2",
			Timestamp:     time.Now(),
		},
	}

	engine := NewJoinEngine(statements)

	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2026-1000"}},
				Artifact:      v1beta1.GrypePackage{PURL: "pkg:alpine/openssl@3.0.2"},
			},
			{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2026-2000"}},
				Artifact:      v1beta1.GrypePackage{PURL: "pkg:alpine/curl@7.88.0"},
			},
		},
	}

	counts := engine.ApplyVEXFilter(doc)

	// Verify one vulnerability was suppressed
	assert.Equal(t, 1, counts["VEXSource"])
	require.Len(t, doc.Matches, 1)
	assert.Equal(t, "CVE-2026-2000", doc.Matches[0].Vulnerability.ID)

	// Verify provenance details were appended
	require.Len(t, doc.IgnoredMatches, 1)
	assert.Equal(t, "CVE-2026-1000", doc.IgnoredMatches[0].Match.Vulnerability.ID)
	require.Len(t, doc.IgnoredMatches[0].AppliedIgnoreRules, 1)
	assert.Equal(t, "VEXSource", doc.IgnoredMatches[0].AppliedIgnoreRules[0].SourceKind)
	assert.Equal(t, "http://example.com/vex/statement/1", doc.IgnoredMatches[0].AppliedIgnoreRules[0].SourceName)
	assert.Equal(t, "vulnerable_code_not_in_execute_path", doc.IgnoredMatches[0].AppliedIgnoreRules[0].Justification)
}

func TestJoinEngine_NilGuards(t *testing.T) {
	engine := NewJoinEngine([]parser.VEXStatement{})

	// Should not panic on nil document
	counts := engine.ApplyVEXFilter(nil)
	assert.Empty(t, counts)

	// Should not panic on nil Matches
	doc := &v1beta1.GrypeDocument{Matches: nil}
	counts = engine.ApplyVEXFilter(doc)
	assert.Empty(t, counts)
}
