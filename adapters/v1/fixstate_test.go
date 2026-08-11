package v1

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/google/uuid"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
)

// cpeMatchDetail builds a cpe-match detail carrying the given version constraint, the
// shape Grype emits when a CVE is matched through a CPE rather than a distro advisory.
func cpeMatchDetail(constraint string) v1beta1.MatchDetails {
	return matchDetail("cpe-match", constraint)
}

func matchDetail(detailType, constraint string) v1beta1.MatchDetails {
	return v1beta1.MatchDetails{
		Type:  detailType,
		Found: json.RawMessage(`{"vulnerabilityID":"CVE-2024-13176","versionConstraint":"` + constraint + `","cpes":["cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"]}`),
	}
}

func TestHasKnownFix(t *testing.T) {
	tests := []struct {
		name        string
		match       v1beta1.Match
		wantFixed   bool
		wantVersion string
	}{
		{
			name:      "no fix signals at all",
			match:     v1beta1.Match{},
			wantFixed: false,
		},
		{
			name: "concrete fix versions win and suggest a version",
			match: v1beta1.Match{
				Artifact:      v1beta1.GrypePackage{Version: "1.0.0"},
				Vulnerability: v1beta1.Vulnerability{Fix: v1beta1.Fix{State: fixStateFixed, Versions: []string{"2.17.0"}}},
			},
			wantFixed:   true,
			wantVersion: "2.17.0",
		},
		{
			name: "fix state fixed without versions",
			match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{Fix: v1beta1.Fix{State: fixStateFixed}},
			},
			wantFixed:   true,
			wantVersion: unknownFixVersion,
		},
		{
			// The #449 shape: Grype reports no fix, but the CPE range is bounded above.
			name: "upper-bounded CPE constraint implies a fix",
			match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{Fix: v1beta1.Fix{State: "unknown"}},
				MatchDetails:  []v1beta1.MatchDetails{cpeMatchDetail(">= 3.0.0, < 3.0.16")},
			},
			wantFixed:   true,
			wantVersion: unknownFixVersion,
		},
		{
			name: "unbounded CPE constraint implies no fix",
			match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{Fix: v1beta1.Fix{State: "not-fixed"}},
				MatchDetails:  []v1beta1.MatchDetails{cpeMatchDetail(">= 3.0.0")},
			},
			wantFixed: false,
		},
		{
			name: "malformed match detail is skipped, later detail still counts",
			match: v1beta1.Match{
				MatchDetails: []v1beta1.MatchDetails{
					{Type: "cpe-match", Found: json.RawMessage(`not json`)},
					cpeMatchDetail(">= 1.0.2, < 1.0.2zl"),
				},
			},
			wantFixed:   true,
			wantVersion: unknownFixVersion,
		},
		{
			name: "malformed match detail alone implies no fix",
			match: v1beta1.Match{
				MatchDetails: []v1beta1.MatchDetails{{Type: "cpe-match", Found: json.RawMessage(`not json`)}},
			},
			wantFixed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixed, version := hasKnownFix(tt.match)
			assert.Equal(t, tt.wantFixed, fixed)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}

// singleLayerSource is the minimal image source the domainToArmo tests use, so these
// tests exercise the exception logic rather than layer/config parsing.
var singleLayerSource = &v1beta1.Source{
	Target: json.RawMessage(`{"userInput":"","imageID":"","manifestDigest":"","mediaType":"","tags":null,"imageSize":0,"layers":[{"mediaType":"","digest":"dummyLayer","size":0}],"manifest":null,"config":null,"repoDigests":null,"architecture":"","os":""}`),
}

// alpineMatch returns the CVE-2024-13176 match from the repo's real Grype output. That
// match is the exact divergence shape from #449: fix state "unknown" with no fix
// versions, but a CPE constraint bounded above.
func alpineMatch(t *testing.T) v1beta1.Match {
	t.Helper()

	var doc v1beta1.GrypeDocument
	require.NoError(t, json.Unmarshal(fileContent("testdata/alpine-cve.format.json"), &doc))

	for _, m := range doc.Matches {
		if m.Vulnerability.ID != "CVE-2024-13176" {
			continue
		}
		require.Empty(t, m.Vulnerability.Fix.Versions, "fixture no longer has the CPE-only shape")
		require.NotEqual(t, fixStateFixed, m.Vulnerability.Fix.State, "fixture no longer has the CPE-only shape")
		return m
	}

	t.Fatal("CVE-2024-13176 not found in testdata/alpine-cve.format.json")
	return v1beta1.Match{}
}

func expiredOnFixException(cve string) domain.CVEExceptions {
	return domain.CVEExceptions{
		{
			PolicyType:            "vulnerabilityExceptionPolicy",
			Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
			VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: cve}},
			ExpiredOnFix:          ptr.To(true),
		},
	}
}

// TestExpiredOnFixAgreesAcrossPaths is the regression test for #449. The in-cluster
// manifest path (ApplySecurityExceptions) and the backend report path (DomainToArmo)
// used to compute "is this fixed?" differently, so a CPE-matched CVE was hidden in the
// VulnerabilityManifest while being reported as active to the backend. Both paths now
// share hasKnownFix, so they must reach the same verdict.
func TestExpiredOnFixAgreesAcrossPaths(t *testing.T) {
	match := alpineMatch(t)
	exceptions := expiredOnFixException(match.Vulnerability.ID)

	ctx := context.WithValue(context.Background(), domain.TimestampKey{}, time.Now().Unix())
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})

	// storage path
	doc := &v1beta1.GrypeDocument{Source: singleLayerSource, Matches: []v1beta1.Match{match}}
	ApplySecurityExceptions(doc, exceptions, nil)
	storageSuppressed := len(doc.IgnoredMatches) == 1

	// report path
	results, err := DomainToArmo(ctx, v1beta1.GrypeDocument{Source: singleLayerSource, Matches: []v1beta1.Match{match}}, exceptions)
	require.NoError(t, err)
	require.Len(t, results, 1)
	reportSuppressed := len(results[0].ExceptionApplied) > 0

	assert.Equal(t, reportSuppressed, storageSuppressed,
		"storage and report paths disagree on whether the ExpiredOnFix exception applies")

	// A fix exists for this CVE, so expiredOnFix expires the exception on both surfaces.
	assert.False(t, storageSuppressed, "CVE with a known fix should not be ignored in the manifest")
	assert.False(t, reportSuppressed, "CVE with a known fix should not carry an applied exception")
	assert.Equal(t, 1, results[0].IsFixed)
}

// TestExpiredOnFixAgreesAcrossPathsWhenUnfixed is the counterpart: with no fix signal at
// all the exception has not expired, so both paths must suppress the CVE.
func TestExpiredOnFixAgreesAcrossPathsWhenUnfixed(t *testing.T) {
	match := alpineMatch(t)
	match.MatchDetails = nil // strip the CPE constraint, leaving no fix signal
	exceptions := expiredOnFixException(match.Vulnerability.ID)

	ctx := context.WithValue(context.Background(), domain.TimestampKey{}, time.Now().Unix())
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})

	doc := &v1beta1.GrypeDocument{Source: singleLayerSource, Matches: []v1beta1.Match{match}}
	ApplySecurityExceptions(doc, exceptions, nil)

	results, err := DomainToArmo(ctx, v1beta1.GrypeDocument{Source: singleLayerSource, Matches: []v1beta1.Match{match}}, exceptions)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Len(t, doc.IgnoredMatches, 1, "CVE without a fix should be ignored in the manifest")
	assert.NotEmpty(t, results[0].ExceptionApplied, "CVE without a fix should carry an applied exception")
	assert.Equal(t, 0, results[0].IsFixed)
}

// A distro detail unmarshals into match.CPEResult just as cleanly as a CPE one, so the
// constraint is only read when the detail actually came from a CPE match.
func TestHasKnownFixOnlyReadsCPEDetails(t *testing.T) {
	for _, detailType := range []string{"exact-direct-match", "exact-indirect-match"} {
		t.Run(detailType, func(t *testing.T) {
			m := v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{
					VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2024-13176"},
					Fix:                   v1beta1.Fix{State: "unknown"},
				},
				MatchDetails: []v1beta1.MatchDetails{matchDetail(detailType, ">= 1.0.2, < 1.0.2zl")},
			}

			fixed, version := hasKnownFix(m)

			assert.False(t, fixed, "an upper-bounded constraint outside a cpe-match is not a fix signal")
			assert.Empty(t, version)
		})
	}
}
