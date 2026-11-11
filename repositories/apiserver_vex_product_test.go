package repositories

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	grypevex "github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/source"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

// The VEX document kubevuln publishes is meant to be read by other tools, and Grype is the
// one kubevuln itself runs. Grype identifies a scanned image the way the purl-spec oci type
// does: the name is the last segment of the repository, and repository_url is the whole
// repository, name included (pkg:oci/debian@sha256:...?repository_url=docker.io/library/debian).
// go-vex then requires every qualifier the document states to be present with the same value,
// so a repository_url that stops short of the image name matches none of the identities Grype
// offers, and the statement is never applied to the image it was written for.
func TestLocalVEXStatementAppliesToTheScannedImageInGrype(t *testing.T) {
	const digest = "sha256:45fb8ed886902c0c49e044b1f8870fad61c1022fa23c4943098302a8f1c5b75f"
	const packagePURL = "pkg:apk/alpine/libcrypto3@3.0.8-r3?arch=x86_64&distro=alpine-3.17.3"

	tests := []struct {
		name          string
		imagePullable string
		metadata      source.ImageMetadata
	}{
		{
			name:          "registry with a nested repository",
			imagePullable: "gcr.io/google-samples/microservices-demo/adservice@" + digest,
			metadata:      source.ImageMetadata{RepoDigests: []string{"gcr.io/google-samples/microservices-demo/adservice@" + digest}},
		},
		{
			name:          "docker hub official image",
			imagePullable: "docker.io/library/nginx@" + digest,
			metadata:      source.ImageMetadata{RepoDigests: []string{"nginx@" + digest}},
		},
		{
			// a registry scan has no digest to go by, only the tag it was asked for
			name:          "registry scan by tag",
			imagePullable: "quay.io/prometheus/node-exporter:v1.8.2",
			metadata:      source.ImageMetadata{Tags: []string{"quay.io/prometheus/node-exporter:v1.8.2"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt, err := newLocalStatement(v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
					ID:         "CVE-2023-1255",
					DataSource: "https://nvd.nist.gov/vuln/detail/CVE-2023-1255",
				}},
				Artifact: v1beta1.GrypePackage{Name: "libcrypto3", Version: "3.0.8-r3", PURL: packagePURL},
			}, tt.imagePullable)
			require.NoError(t, err)

			doc := v1beta1.VEX{
				Metadata: v1beta1.Metadata{
					Context:   "https://openvex.dev/ns/v0.2.0",
					ID:        "https://kubescape.io/vex/test",
					Author:    "kubescape.io",
					Timestamp: "2026-11-12T00:00:00Z",
					Version:   1,
				},
				Statements: []v1beta1.Statement{stmt},
			}
			b, err := json.Marshal(doc)
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "vex.json")
			require.NoError(t, os.WriteFile(path, b, 0o600))

			processor, err := grypevex.NewProcessor(grypevex.ProcessorOptions{Documents: []string{path}})
			require.NoError(t, err)

			pkgContext := &pkg.Context{Source: &source.Description{Metadata: tt.metadata}}
			matches := match.NewMatches(match.Match{
				Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{
					ID:        "CVE-2023-1255",
					Namespace: "alpine:distro:alpine:3.17",
				}},
				Package: pkg.Package{ID: "cc8f90662d91481d", Name: "libcrypto3", Version: "3.0.8-r3", Type: "apk", PURL: packagePURL},
			})

			remaining, ignored, err := processor.ApplyVEX(pkgContext, &matches, nil)
			require.NoError(t, err)
			require.Len(t, ignored, 1, "the not_affected statement kubevuln wrote for this image must apply to it; product %q", stmt.Products[0].ID)
			require.Empty(t, remaining.Sorted())
		})
	}
}
