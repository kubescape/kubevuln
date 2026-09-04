package vexbatch

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/grype/vex/status"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/require"
)

const testPURL = "pkg:apk/alpine/libcrypto3@3.0.8-r3"

func TestApply_MixedFormats(t *testing.T) {
	openvexPath := "testdata/openvex.json"
	csafPath := "testdata/csaf.json"

	pkgContext := &pkg.Context{
		Source: &source.Description{
			Name:    "alpine",
			Version: "3.17",
			Metadata: source.ImageMetadata{
				RepoDigests: []string{
					"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				},
			},
		},
	}

	libCryptoPackage := pkg.Package{
		ID:      "cc8f90662d91481d",
		Name:    "libcrypto3",
		Version: "3.0.8-r3",
		Type:    "apk",
		PURL:    testPURL,
		Upstreams: []pkg.UpstreamPackage{
			{Name: "openssl"},
		},
	}

	newMatches := func() match.Matches {
		return match.NewMatches(
			match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-1255",
						Namespace: "alpine:distro:alpine:3.17",
					},
				},
				Package: libCryptoPackage,
			},
			match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-3817",
						Namespace: "alpine:distro:alpine:3.17",
					},
				},
				Package: libCryptoPackage,
			},
		)
	}

	ignoreRules := []match.IgnoreRule{
		{
			VexStatus: string(status.Fixed),
		},
		{
			VexStatus:        string(status.NotAffected),
			VexJustification: "vulnerable_code_not_present",
		},
	}

	t.Run("old single processor", func(t *testing.T) {
		matches := newMatches()

		processor, err := vex.NewProcessor(vex.ProcessorOptions{
			Documents:   []string{openvexPath, csafPath},
			IgnoreRules: ignoreRules,
		})
		require.NoError(t, err)

		remaining, ignored, err := processor.ApplyVEX(
			pkgContext,
			&matches,
			nil,
		)
		require.NoError(t, err)

		// A single Grype processor selects its parser from the first
		// document, so the CSAF document is not applied when OpenVEX
		// is first in the mixed batch.
		require.Len(t, remaining.GetByPkgID(libCryptoPackage.ID), 1)
		require.Len(t, ignored, 1)
		require.Equal(
			t,
			"CVE-2023-1255",
			ignored[0].Match.Vulnerability.Reference.ID,
		)
	})

	t.Run("grouped processors", func(t *testing.T) {
		matches := newMatches()

		remaining, ignored, err := Apply(
			[]Document{
				{
					Format: FormatOpenVEX,
					Path:   openvexPath,
				},
				{
					Format: FormatCSAF,
					Path:   csafPath,
				},
			},
			pkgContext,
			&matches,
			nil,
			ignoreRules,
		)
		require.NoError(t, err)

		require.Empty(t, remaining.GetByPkgID(libCryptoPackage.ID))
		require.Len(t, ignored, 2)

		ignoredIDs := make(map[string]struct{}, len(ignored))
		for _, m := range ignored {
			ignoredIDs[m.Match.Vulnerability.Reference.ID] = struct{}{}
		}

		require.Contains(t, ignoredIDs, "CVE-2023-1255")
		require.Contains(t, ignoredIDs, "CVE-2023-3817")
	})
}
