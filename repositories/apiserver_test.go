package repositories

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akyoto/cache"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/retry"
)

const name = "k8s.gcr.io-kube-proxy-sha256-c1b13"

func TestAPIServerStore_GetCVE(t *testing.T) {
	type args struct {
		ctx                context.Context
		name               string
		SBOMCreatorVersion string
		CVEScannerVersion  string
		CVEDBVersion       string
	}
	tests := []struct {
		name         string
		args         args
		cve          domain.CVEManifest
		wantEmptyCVE bool
	}{
		{
			"valid CVE is retrieved",
			args{
				ctx:  context.TODO(),
				name: name,
			},
			domain.CVEManifest{
				Name: name,
				Annotations: map[string]string{
					"foo": "bar",
				},
				Content: &v1beta1.GrypeDocument{},
			},
			false,
		},
		{
			"CVEScannerVersion mismatch",
			args{
				ctx:               context.TODO(),
				name:              name,
				CVEScannerVersion: "v1.1.0",
			},
			domain.CVEManifest{
				Name:              name,
				CVEScannerVersion: "v1.0.0",
				Content:           &v1beta1.GrypeDocument{},
			},
			true,
		},
		{
			"CVEDBVersion mismatch",
			args{
				ctx:          context.TODO(),
				name:         name,
				CVEDBVersion: "v1.1.0",
			},
			domain.CVEManifest{
				Name:         name,
				CVEDBVersion: "v1.0.0",
				Content:      &v1beta1.GrypeDocument{},
			},
			true,
		},
		{
			"empty name",
			args{
				ctx:          context.TODO(),
				name:         "",
				CVEDBVersion: "v1.1.0",
			},
			domain.CVEManifest{
				Name:         "",
				CVEDBVersion: "v1.0.0",
				Content:      &v1beta1.GrypeDocument{},
			},
			true,
		},
	}
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewFakeAPIServerStorage("kubescape")
			_, err := a.GetCVE(tt.args.ctx, tt.args.name, tt.args.SBOMCreatorVersion, tt.args.CVEScannerVersion, tt.args.CVEDBVersion)
			require.NoError(t, err)
			tt.args.ctx = context.WithValue(tt.args.ctx, domain.WorkloadKey{}, workload)
			err = a.StoreCVE(tt.args.ctx, tt.cve, false)
			require.NoError(t, err)
			gotCve, _ := a.GetCVE(tt.args.ctx, tt.args.name, tt.args.SBOMCreatorVersion, tt.args.CVEScannerVersion, tt.args.CVEDBVersion)
			if !tt.wantEmptyCVE {
				assert.NotNil(t, gotCve.Content)
				assert.Equal(t, "bar", gotCve.Annotations["foo"])
			}
		})
	}
}

func TestAPIServerStore_UpdateCVE(t *testing.T) {
	ctx := context.TODO()
	a := NewFakeAPIServerStorage("kubescape")
	cvep := domain.CVEManifest{
		Name: name,
		Content: &v1beta1.GrypeDocument{
			Descriptor_: v1beta1.Descriptor{
				Version: "v1.0.0",
			},
		},
	}
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)
	err := a.StoreCVE(ctx, cvep, true)
	require.NoError(t, err)
	cvep.Content.Descriptor_.Version = "v1.1.0"
	err = a.StoreCVE(ctx, cvep, true)
	assert.NoError(t, err)
	got, err := a.GetCVE(ctx, name, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, got.Content.Descriptor_.Version, "v1.1.0")
}

func TestAPIServerStore_GetSBOM(t *testing.T) {
	type args struct {
		ctx                context.Context
		name               string
		SBOMCreatorVersion string
	}
	tests := []struct {
		name                    string
		args                    args
		sbom                    domain.SBOM
		wantErr                 error
		wantEmptySBOM           bool
		wantSBOMCreatorVersion  string
		checkSBOMCreatorVersion bool
	}{
		{
			"valid SBOM is retrieved",
			args{
				ctx:  context.TODO(),
				name: name,
			},
			domain.SBOM{
				Name:    name,
				Content: &v1beta1.SyftDocument{},
			},
			nil,
			false,
			"",
			false,
		},
		{
			"invalid timestamp, SBOM is still retrieved",
			args{
				ctx:  context.TODO(),
				name: name,
			},
			domain.SBOM{
				Name:    name,
				Content: &v1beta1.SyftDocument{},
			},
			nil,
			false,
			"",
			false,
		},
		{
			// The stored manifest predates the version the caller wants: content it was
			// never validated against would otherwise be served as if it were current.
			"SBOMCreatorVersion mismatch, manifest older than requested",
			args{
				ctx:                context.TODO(),
				name:               name,
				SBOMCreatorVersion: "v1.1.0",
			},
			domain.SBOM{
				Name:               name,
				SBOMCreatorVersion: "v1.0.0",
				Content:            &v1beta1.SyftDocument{},
			},
			domain.ErrOutdatedSBOM,
			false,
			"v1.0.0",
			true,
		},
		{
			// The stored manifest is newer than the caller's version, e.g. written by a
			// different-versioned replica during a rolling deploy/rollback of the same
			// image slug. The caller's own version has no compatibility guarantee with it
			// either, so this must be discarded exactly like the older-manifest case (#768).
			"SBOMCreatorVersion mismatch, manifest newer than requested",
			args{
				ctx:                context.TODO(),
				name:               name,
				SBOMCreatorVersion: "v1.0.0",
			},
			domain.SBOM{
				Name:               name,
				SBOMCreatorVersion: "v1.1.0",
				Content:            &v1beta1.SyftDocument{},
			},
			domain.ErrOutdatedSBOM,
			false,
			"v1.1.0",
			true,
		},
		{
			// On a match, the returned SBOMCreatorVersion must be what the manifest actually
			// records, not merely echo the caller's requested value back (#768).
			"SBOMCreatorVersion match",
			args{
				ctx:                context.TODO(),
				name:               name,
				SBOMCreatorVersion: "v1.2.3",
			},
			domain.SBOM{
				Name:               name,
				SBOMCreatorVersion: "v1.2.3",
				Content:            &v1beta1.SyftDocument{},
			},
			nil,
			false,
			"v1.2.3",
			true,
		},
		{
			"empty name",
			args{
				ctx:                context.TODO(),
				name:               "",
				SBOMCreatorVersion: "v1.1.0",
			},
			domain.SBOM{
				Name:               "",
				SBOMCreatorVersion: "v1.0.0",
				Content:            &v1beta1.SyftDocument{},
			},
			nil,
			true,
			"",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewFakeAPIServerStorage("kubescape")
			_, err := a.GetSBOM(tt.args.ctx, tt.args.name, tt.args.SBOMCreatorVersion)
			require.NoError(t, err)
			err = a.StoreSBOM(tt.args.ctx, tt.sbom, false)
			require.NoError(t, err)
			gotSBOM, err := a.GetSBOM(tt.args.ctx, tt.args.name, tt.args.SBOMCreatorVersion)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			if (gotSBOM.Content == nil) != tt.wantEmptySBOM {
				t.Errorf("GetSBOM() gotSBOM.Content = %v, wantEmptySBOM %v", gotSBOM.Content, tt.wantEmptySBOM)
				return
			}
			if tt.checkSBOMCreatorVersion {
				require.Equal(t, tt.wantSBOMCreatorVersion, gotSBOM.SBOMCreatorVersion,
					"GetSBOM() must return the manifest's own recorded version, not the caller's requested one")
			}
		})
	}
}

func TestAPIServerStore_parseSeverities(t *testing.T) {
	nginxCVECriticalSeveritiesNumber := int64(72)
	nginxCVEHighSeveritiesNumber := int64(128)
	nginxCVEMediumSeveritiesNumber := int64(98)
	nginxCVELowSeveritiesNumber := int64(56)
	nginxCVENegligibleSeveritiesNumber := int64(102)
	nginxCVEUnknownSeveritiesNumber := int64(0)

	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	severities := parseSeverities(cveManifest, cveManifest, false)
	assert.Equal(t, nginxCVECriticalSeveritiesNumber, severities.Critical.All)
	assert.Equal(t, nginxCVEHighSeveritiesNumber, severities.High.All)
	assert.Equal(t, nginxCVEMediumSeveritiesNumber, severities.Medium.All)
	assert.Equal(t, nginxCVELowSeveritiesNumber, severities.Low.All)
	assert.Equal(t, nginxCVENegligibleSeveritiesNumber, severities.Negligible.All)
	assert.Equal(t, nginxCVEUnknownSeveritiesNumber, severities.Unknown.All)

	assert.Equal(t, int64(0), severities.Critical.Relevant)
	assert.Equal(t, int64(0), severities.High.Relevant)
	assert.Equal(t, int64(0), severities.Medium.Relevant)
	assert.Equal(t, int64(0), severities.Low.Relevant)
	assert.Equal(t, int64(0), severities.Negligible.Relevant)
	assert.Equal(t, int64(0), severities.Unknown.Relevant)

	severities = parseSeverities(cveManifest, cveManifest, true)
	assert.Equal(t, nginxCVECriticalSeveritiesNumber, severities.Critical.All)
	assert.Equal(t, nginxCVEHighSeveritiesNumber, severities.High.All)
	assert.Equal(t, nginxCVEMediumSeveritiesNumber, severities.Medium.All)
	assert.Equal(t, nginxCVELowSeveritiesNumber, severities.Low.All)
	assert.Equal(t, nginxCVENegligibleSeveritiesNumber, severities.Negligible.All)
	assert.Equal(t, nginxCVEUnknownSeveritiesNumber, severities.Unknown.All)

	assert.Equal(t, nginxCVECriticalSeveritiesNumber, severities.Critical.Relevant)
	assert.Equal(t, nginxCVEHighSeveritiesNumber, severities.High.Relevant)
	assert.Equal(t, nginxCVEMediumSeveritiesNumber, severities.Medium.Relevant)
	assert.Equal(t, nginxCVELowSeveritiesNumber, severities.Low.Relevant)
	assert.Equal(t, nginxCVENegligibleSeveritiesNumber, severities.Negligible.Relevant)
	assert.Equal(t, nginxCVEUnknownSeveritiesNumber, severities.Unknown.Relevant)
}

func TestAPIServerStore_parseVulnerabilitiesComponents(t *testing.T) {
	namespace := "namespace"

	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	res := parseVulnerabilitiesComponents(cveManifest, cveManifest, namespace, false)
	assert.Equal(t, res.ImageVulnerabilitiesObj.Name, cveManifest.Name)
	assert.Equal(t, res.ImageVulnerabilitiesObj.Namespace, namespace)
	assert.Equal(t, res.WorkloadVulnerabilitiesObj.Name, "")
	assert.Equal(t, res.WorkloadVulnerabilitiesObj.Namespace, "")

	res = parseVulnerabilitiesComponents(cveManifest, cveManifest, namespace, true)
	assert.Equal(t, res.ImageVulnerabilitiesObj.Name, cveManifest.Name)
	assert.Equal(t, res.ImageVulnerabilitiesObj.Namespace, namespace)
	assert.Equal(t, res.WorkloadVulnerabilitiesObj.Name, cveManifest.Name)
	assert.Equal(t, res.WorkloadVulnerabilitiesObj.Namespace, namespace)
}

// func TestAPIServerStore_storeCVESummary(t *testing.T) {
// 	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
// 	a := NewFakeAPIServerStorage("namespace")

// 	err := a.StoreCVESummary(context.TODO(), cveManifest, cveManifest, false)
// 	assert.Equal(t, nil, err, "1 StoreCVESummary")

// 	err = a.StoreCVESummary(context.TODO(), cveManifest, cveManifest, true)
// 	assert.Equal(t, nil, err, "2 StoreCVESummary")
// }

func TestAPIServerStore_storeVEX(t *testing.T) {
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	a := NewFakeAPIServerStorage("kubescape")

	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	// Test first store and read
	err := a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	assert.Equal(t, err, nil)

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	assert.Equal(t, err, nil)
	assert.NotEqual(t, vexContainer, nil)
	assert.Equal(t, vexContainer.Name, cveManifest.Name)

	relevant := 0
	for _, stmt := range vexContainer.Spec.Statements {
		if stmt.Status == v1beta1.Status(vex.StatusAffected) {
			relevant++
		}
	}
	all := len(vexContainer.Spec.Statements)

	// First store should have all the CVEs and the relevant ones
	assert.Equal(t, len(cveManifestFiltered.Content.Matches), relevant)
	assert.Equal(t, len(cveManifest.Content.Matches), all)

	// Test second store and read (update)
	cveManifestFiltered2 := tools.FileToCVEManifest("testdata/nginx-cve-filtered-2.json")

	err = a.StoreVEX(ctx, cveManifest, cveManifestFiltered2, false)
	assert.Equal(t, err, nil)

	vexContainer, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	assert.Equal(t, err, nil)

	relevant2 := 0
	for _, stmt := range vexContainer.Spec.Statements {
		if stmt.Status == v1beta1.Status(vex.StatusAffected) {
			relevant2++
		}
	}

	// Second should have one more relevant CVE than the first one
	assert.Equal(t, relevant+1, relevant2)
}

func TestAPIServerStore_storeVEX_ignoredMatches_append(t *testing.T) {
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	// Inject an IgnoredMatch into the original cveManifest
	cveManifest.Content.IgnoredMatches = append(cveManifest.Content.IgnoredMatches, v1beta1.IgnoredMatch{
		Match: v1beta1.Match{
			Vulnerability: v1beta1.Vulnerability{
				VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
					ID:         "CVE-IGNORE-TEST",
					DataSource: "GHSA-IGNORE-TEST",
				},
			},
			Artifact: v1beta1.GrypePackage{
				Name:    "ignored-package",
				Version: "1.0",
			},
		},
	})

	a := NewFakeAPIServerStorage("kubescape")

	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	err := a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	assert.NoError(t, err)

	// Inject a second IgnoredMatch to trigger updateVEX and verify it correctly handles new ignored matches
	// and preserves existing ones
	cveManifest.Content.IgnoredMatches = append(cveManifest.Content.IgnoredMatches, v1beta1.IgnoredMatch{
		Match: v1beta1.Match{
			Vulnerability: v1beta1.Vulnerability{
				VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
					ID:         "CVE-IGNORE-TEST-2",
					DataSource: "GHSA-IGNORE-TEST-2",
				},
			},
			Artifact: v1beta1.GrypePackage{
				Name:    "ignored-package-2",
				Version: "2.0",
			},
		},
	})

	// Second call triggers the updateVEX path
	err = a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	assert.NoError(t, err)

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.NotNil(t, vexContainer)

	var foundIgnored1, foundIgnored2 bool
	for _, stmt := range vexContainer.Spec.Statements {
		if stmt.Vulnerability.Name == "CVE-IGNORE-TEST" {
			foundIgnored1 = true
			assert.Equal(t, v1beta1.Status(vex.StatusNotAffected), stmt.Status)
			assert.Equal(t, v1beta1.Justification(vex.VulnerableCodeNotPresent), stmt.Justification)
			assert.Equal(t, "Vulnerability was ignored by an external VEX document or scanner configuration", stmt.ImpactStatement)
		}
		if stmt.Vulnerability.Name == "CVE-IGNORE-TEST-2" {
			foundIgnored2 = true
			assert.Equal(t, v1beta1.Status(vex.StatusNotAffected), stmt.Status)
			assert.Equal(t, v1beta1.Justification(vex.VulnerableCodeNotPresent), stmt.Justification)
			assert.Equal(t, "Vulnerability was ignored by an external VEX document or scanner configuration", stmt.ImpactStatement)
		}
	}
	assert.True(t, foundIgnored1, "First IgnoredMatch should be preserved in the VEX document during update")
	assert.True(t, foundIgnored2, "Second IgnoredMatch should be included in the VEX document during update")
}

func TestAPIServerStore_storeVEX_ignoredMatchesDoNotCollide(t *testing.T) {
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	// Keep the test completely focused on the two synthetic ignored matches.
	cveManifest.Content.Matches = nil
	cveManifest.Content.IgnoredMatches = nil
	cveManifestFiltered.Content.Matches = nil
	cveManifestFiltered.Content.IgnoredMatches = nil

	// These two (vulnerability, PURL) pairs collide when represented as
	// Vulnerability.ID + Artifact.PURL:
	//
	//   A  + BC = ABC
	//   AB + C  = ABC
	//
	// A composite key must keep these two findings distinct.
	cveManifest.Content.IgnoredMatches = []v1beta1.IgnoredMatch{
		{
			Match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{
					VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
						ID:         "A",
						DataSource: "https://example.test/A",
					},
				},
				Artifact: v1beta1.GrypePackage{
					PURL: "BC",
				},
			},
			AppliedIgnoreRules: []v1beta1.IgnoreRule{{
				Vulnerability:   "A",
				SourceKind:      "SecurityException",
				SourceName:      "SecurityException/default/A",
				SourceNamespace: "default",
				FixState:        string(sev1beta1.VulnerabilityStatusNotAffected),
				Justification:   "justification-A",
				ImpactStatement: "impact-A",
			}},
		},
		{
			Match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{
					VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
						ID:         "AB",
						DataSource: "https://example.test/AB",
					},
				},
				Artifact: v1beta1.GrypePackage{
					PURL: "C",
				},
			},
			AppliedIgnoreRules: []v1beta1.IgnoreRule{{
				Vulnerability:   "AB",
				SourceKind:      "SecurityException",
				SourceName:      "SecurityException/default/AB",
				SourceNamespace: "default",
				FixState:        string(sev1beta1.VulnerabilityStatusNotAffected),
				Justification:   "justification-AB",
				ImpactStatement: "impact-AB",
			}},
		},
	}

	a := NewFakeAPIServerStorage("kubescape")

	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	// First call creates the VEX document with both ignored statements.
	err := a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	require.NoError(t, err)

	// Change the filtered manifest before the second call so StoreVEX
	// must execute the update path instead of treating the scan as a no-op.
	secondFiltered := cveManifestFiltered
	secondFiltered.Content = &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{
				Vulnerability: v1beta1.Vulnerability{
					VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
						ID:         "CVE-UPDATE-TRIGGER",
						DataSource: "https://example.test/CVE-UPDATE-TRIGGER",
					},
				},
				Artifact: v1beta1.GrypePackage{
					PURL: "pkg:deb/example/update-trigger@1.0",
				},
			},
		},
		IgnoredMatches: cveManifestFiltered.Content.IgnoredMatches,
	}

	// Second call must execute updateVEX. The ignored-match map is rebuilt
	// during this update, which is the path where the composite-key bug occurs.
	err = a.StoreVEX(ctx, cveManifest, secondFiltered, false)
	require.NoError(t, err)

	vexContainer, err := a.StorageClient.
		OpenVulnerabilityExchangeContainers(a.Namespace).
		Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, vexContainer)

	var statementA, statementAB *v1beta1.Statement

	for i := range vexContainer.Spec.Statements {
		stmt := &vexContainer.Spec.Statements[i]

		switch {
		case stmt.Vulnerability.Name == "A" &&
			statementHasPURL(stmt.Products, "BC"):
			statementA = stmt

		case stmt.Vulnerability.Name == "AB" &&
			statementHasPURL(stmt.Products, "C"):
			statementAB = stmt
		}
	}

	require.NotNil(t, statementA, "statement for A/BC should exist")
	require.NotNil(t, statementAB, "statement for AB/C should exist")

	// The assessments must remain associated with their own
	// (vulnerability, PURL) pair. With the old concatenated-string
	// lookup, A/BC and AB/C both resolve to the same key: "ABC".
	assert.Equal(t, "justification-A", string(statementA.Justification))
	assert.Equal(t, "impact-A", statementA.ImpactStatement)

	assert.Equal(t, "justification-AB", string(statementAB.Justification))
	assert.Equal(t, "impact-AB", statementAB.ImpactStatement)
}

func TestAPIServerStore_storeVEX_preservesSecurityExceptionSemantics(t *testing.T) {
	ignoredMatches := []v1beta1.IgnoredMatch{
		{
			Match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{
					VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-NOT-AFFECTED", DataSource: "https://example.test/CVE-NOT-AFFECTED"},
				},
				Artifact: v1beta1.GrypePackage{PURL: "pkg:deb/debian/not-affected@1.0"},
			},
			AppliedIgnoreRules: []v1beta1.IgnoreRule{{
				Vulnerability:   "CVE-NOT-AFFECTED",
				SourceKind:      "SecurityException",
				SourceName:      "SecurityException/default/not-affected",
				SourceNamespace: "default",
				FixState:        string(sev1beta1.VulnerabilityStatusNotAffected),
				Justification:   "component is compiled without the vulnerable feature",
				ImpactStatement: "runtime path is unreachable in this deployment",
			}},
		},
		{
			Match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{
					VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-FIXED", DataSource: "https://example.test/CVE-FIXED"},
				},
				Artifact: v1beta1.GrypePackage{PURL: "pkg:deb/debian/fixed@2.0"},
			},
			AppliedIgnoreRules: []v1beta1.IgnoreRule{{
				Vulnerability:   "CVE-FIXED",
				SourceKind:      "SecurityException",
				SourceName:      "SecurityException/default/fixed",
				SourceNamespace: "default",
				FixState:        string(sev1beta1.VulnerabilityStatusFixed),
				Justification:   "patch validated in downstream image build",
				ImpactStatement: "rolled out via golden base image",
			}},
		},
		{
			Match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{
					VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-AFFECTED", DataSource: "https://example.test/CVE-AFFECTED"},
				},
				Artifact: v1beta1.GrypePackage{PURL: "pkg:deb/debian/affected@3.0"},
			},
			AppliedIgnoreRules: []v1beta1.IgnoreRule{{
				Vulnerability:   "CVE-AFFECTED",
				SourceKind:      "SecurityException",
				SourceName:      "SecurityException/default/affected",
				SourceNamespace: "default",
				FixState:        string(sev1beta1.VulnerabilityStatusAffected),
				Justification:   "accepted risk",
				ImpactStatement: "compensating controls limit exposure",
			}},
		},
	}

	cveManifest := domain.CVEManifest{
		Name: name,
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey: "registry.k8s.io/coredns/coredns:v1.10.1",
		},
		Content: &v1beta1.GrypeDocument{
			IgnoredMatches: ignoredMatches,
		},
	}
	cveManifestFiltered := cveManifest
	cveManifestFiltered.Content = &v1beta1.GrypeDocument{
		IgnoredMatches: append([]v1beta1.IgnoredMatch(nil), ignoredMatches...),
	}

	a := NewFakeAPIServerStorage("kubescape")

	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	err := a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	require.NoError(t, err)
	err = a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	require.NoError(t, err, "updateVEX should preserve the same SecurityException-derived semantics")

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	got := map[string]v1beta1.Statement{}
	for _, stmt := range vexContainer.Spec.Statements {
		got[stmt.Vulnerability.Name] = stmt
	}

	require.Contains(t, got, "CVE-NOT-AFFECTED")
	assert.Equal(t, v1beta1.Status(vex.StatusNotAffected), got["CVE-NOT-AFFECTED"].Status)
	assert.Equal(t, v1beta1.Justification("component is compiled without the vulnerable feature"), got["CVE-NOT-AFFECTED"].Justification)
	assert.Equal(t, "runtime path is unreachable in this deployment", got["CVE-NOT-AFFECTED"].ImpactStatement)
	assert.Empty(t, got["CVE-NOT-AFFECTED"].ActionStatement)
	assert.Empty(t, got["CVE-NOT-AFFECTED"].StatusNotes)

	require.Contains(t, got, "CVE-FIXED")
	assert.Equal(t, v1beta1.Status(sev1beta1.VulnerabilityStatusFixed), got["CVE-FIXED"].Status)
	assert.Empty(t, got["CVE-FIXED"].Justification)
	assert.Empty(t, got["CVE-FIXED"].ImpactStatement)
	assert.Empty(t, got["CVE-FIXED"].ActionStatement)
	assert.Equal(t, "justification: patch validated in downstream image build; impact: rolled out via golden base image", got["CVE-FIXED"].StatusNotes)

	require.Contains(t, got, "CVE-AFFECTED")
	assert.Equal(t, v1beta1.Status(vex.StatusAffected), got["CVE-AFFECTED"].Status)
	assert.Empty(t, got["CVE-AFFECTED"].Justification)
	assert.Empty(t, got["CVE-AFFECTED"].ImpactStatement)
	assert.Equal(t, securityExceptionAcceptedRiskAction, got["CVE-AFFECTED"].ActionStatement)
	assert.Equal(t, "justification: accepted risk; impact: compensating controls limit exposure", got["CVE-AFFECTED"].StatusNotes)
}

// TestAPIServerStore_storeVEX_updateRestoresNotAffected guards against a regression where
// updateVEX only ever promoted statements to "affected" and never reset them back to
// "not_affected" once the corresponding CVE/package pair stopped being relevant.
func TestAPIServerStore_storeVEX_updateRestoresNotAffected(t *testing.T) {
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")
	require.NotEmpty(t, cveManifestFiltered.Content.Matches)

	a := NewFakeAPIServerStorage("kubescape")

	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	// First store makes the filtered CVEs "affected".
	require.NoError(t, a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false))

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	affectedBefore := 0
	for _, stmt := range vexContainer.Spec.Statements {
		if stmt.Status == v1beta1.Status(vex.StatusAffected) {
			affectedBefore++
		}
	}
	assert.Equal(t, len(cveManifestFiltered.Content.Matches), affectedBefore)

	// Second store with an empty filtered manifest: none of the CVEs are relevant anymore,
	// so every previously "affected" statement should revert to "not_affected".
	emptyFiltered := cveManifestFiltered
	emptyContent := *cveManifestFiltered.Content
	emptyContent.Matches = nil
	emptyFiltered.Content = &emptyContent

	require.NoError(t, a.StoreVEX(ctx, cveManifest, emptyFiltered, false))

	vexContainer, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	affectedAfter := 0
	for _, stmt := range vexContainer.Spec.Statements {
		if stmt.Status == v1beta1.Status(vex.StatusAffected) {
			affectedAfter++
		}
		assert.Empty(t, stmt.ActionStatement, "not_affected statement %q must not carry an action_statement", stmt.Vulnerability.Name)
	}
	assert.Equal(t, 0, affectedAfter, "statements that are no longer relevant should be reset to not_affected")
}

// TestAPIServerStore_storeVEX_duplicateLocalStatementsBothUpdated guards against a regression
// where buildLocalVexStatementIndex's map[vexStatementKey]int kept only the last statement
// index for a (vulnerability, PURL) key, so mark-affected/mark-ignored only touched one of two
// duplicate local statements sharing that key. Such duplicates predate the ID/Name-swap
// normalization above and can still exist in already-persisted VEX documents.
func TestAPIServerStore_storeVEX_duplicateLocalStatementsBothUpdated(t *testing.T) {
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")
	require.NotEmpty(t, cveManifestFiltered.Content.Matches)

	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	require.NoError(t, a.StoreVEX(ctx, cveManifest, domain.CVEManifest{Name: cveManifest.Name}, false))

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, vexContainer.Spec.Statements)

	// Simulate a pre-existing document with a duplicate local statement for the same
	// (vulnerability, PURL) key as the first statement.
	dup := *vexContainer.Spec.Statements[0].DeepCopy()
	vexContainer.Spec.Statements = append(vexContainer.Spec.Statements, dup)
	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(context.Background(), vexContainer, metav1.UpdateOptions{})
	require.NoError(t, err)

	targetName := dup.Vulnerability.Name
	targetPURL := dup.Products[0].Subcomponents[0].ID

	filtered := domain.CVEManifest{
		Name: cveManifest.Name,
		Content: &v1beta1.GrypeDocument{
			Matches: []v1beta1.Match{},
		},
	}
	for _, m := range cveManifest.Content.Matches {
		if m.Vulnerability.ID == targetName && m.Artifact.PURL == targetPURL {
			filtered.Content.Matches = append(filtered.Content.Matches, m)
		}
	}
	require.NotEmpty(t, filtered.Content.Matches, "expected to find the duplicated match in the source manifest")

	require.NoError(t, a.StoreVEX(ctx, cveManifest, filtered, false))

	vexContainerAfterUpdate, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	affectedCount := 0
	for _, s := range vexContainerAfterUpdate.Spec.Statements {
		if s.Vulnerability.Name == targetName && statementHasPURL(s.Products, targetPURL) {
			if s.Status == v1beta1.Status(vex.StatusAffected) {
				affectedCount++
			}
		}
	}
	assert.Equal(t, 2, affectedCount, "both duplicate local statements sharing the key must be promoted to affected")
}

func TestAPIServerStore_storeVEX_noopUpdatePreservesMetadata(t *testing.T) {
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")
	cveManifestFiltered2 := tools.FileToCVEManifest("testdata/nginx-cve-filtered-2.json")

	clientset := newFakeStorageClientset()
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())

	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	require.NoError(t, a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false))

	initial, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	initialVersion := initial.Spec.Version
	initialID := initial.Spec.ID
	initialLastUpdated := initial.Spec.LastUpdated

	updateCalls := 0
	clientset.PrependReactor("update", "openvulnerabilityexchangecontainers", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return false, nil, nil
	})

	require.NoError(t, a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false))

	unchanged, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	assert.Equal(t, 0, updateCalls, "no-op rescans must not issue a storage update")
	assert.Equal(t, initialVersion, unchanged.Spec.Version, "no-op rescans must not bump the VEX version")
	assert.Equal(t, initialID, unchanged.Spec.ID, "no-op rescans must preserve the canonical VEX ID")
	assert.Equal(t, initialLastUpdated, unchanged.Spec.LastUpdated, "no-op rescans must preserve LastUpdated")

	require.NoError(t, a.StoreVEX(ctx, cveManifest, cveManifestFiltered2, false))

	changed, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	assert.Equal(t, initialVersion+1, changed.Spec.Version, "changed rescans must still bump the VEX version")
	assert.NotEqual(t, initialID, changed.Spec.ID, "changed rescans must still recalculate the canonical VEX ID")
}

// TestAPIServerStore_storeVEX_affectedStatementsHaveActionStatement guards against a regression
// where markRelevantVulnerabilitiesAsAffectedInVex set an "affected" status without also setting
// an ActionStatement, which the storage API type comments require for that status.
func TestAPIServerStore_storeVEX_affectedStatementsHaveActionStatement(t *testing.T) {
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	a := NewFakeAPIServerStorage("kubescape")

	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	require.NotEmpty(t, cveManifestFiltered.Content.Matches)

	err := a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	assert.Equal(t, err, nil)

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	assert.Equal(t, err, nil)

	foundAffected := false
	for _, stmt := range vexContainer.Spec.Statements {
		if stmt.Status == v1beta1.Status(vex.StatusAffected) {
			foundAffected = true
			assert.NotEmpty(t, stmt.ActionStatement, "affected statement %q must carry an action_statement", stmt.Vulnerability.Name)
			assert.Empty(t, stmt.ImpactStatement, "affected statement %q must not carry an impact_statement", stmt.Vulnerability.Name)
		}
	}
	require.True(t, foundAffected, "expected at least one affected statement in test fixture")
}

// TestAPIServerStore_storeVEX_updatePreservesFieldMapping guards against a regression where
// updateVEX swapped Vulnerability.ID and Vulnerability.Name for statements appended during an
// update, while createVEX used the opposite (correct) mapping for the very same match data.
func TestAPIServerStore_storeVEX_updatePreservesFieldMapping(t *testing.T) {
	cveManifestFull := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	require.NotEmpty(t, cveManifestFull.Content.Matches)
	require.Greater(t, len(cveManifestFull.Content.Matches), 1)

	// First store only a subset of the matches, so the remaining match(es) are appended
	// later via the update path rather than the create path.
	cveManifestSubset := cveManifestFull
	subsetMatches := make([]v1beta1.Match, len(cveManifestFull.Content.Matches)-1)
	copy(subsetMatches, cveManifestFull.Content.Matches[:len(cveManifestFull.Content.Matches)-1])
	subsetContent := *cveManifestFull.Content
	subsetContent.Matches = subsetMatches
	cveManifestSubset.Content = &subsetContent

	lastMatch := cveManifestFull.Content.Matches[len(cveManifestFull.Content.Matches)-1]

	a := NewFakeAPIServerStorage("kubescape")

	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	// Create with the subset of matches.
	require.NoError(t, a.StoreVEX(ctx, cveManifestSubset, cveManifestFiltered, false))

	vexContainerBeforeUpdate, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifestSubset.Name, metav1.GetOptions{})
	require.NoError(t, err)
	statementCountBeforeUpdate := len(vexContainerBeforeUpdate.Spec.Statements)

	// Update with the full set of matches, causing updateVEX to append a new statement
	// for lastMatch via its "not found" branch.
	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Greater(t, len(vexContainer.Spec.Statements), statementCountBeforeUpdate)

	var appended *v1beta1.Statement
	for i := range vexContainer.Spec.Statements {
		s := &vexContainer.Spec.Statements[i]
		if s.Vulnerability.Name == lastMatch.Vulnerability.ID && len(s.Products) > 0 && len(s.Products[0].Subcomponents) > 0 &&
			s.Products[0].Subcomponents[0].ID == lastMatch.Artifact.PURL {
			appended = s
			break
		}
	}
	require.NotNil(t, appended, "expected the statement appended during update to have Name == Vulnerability.ID and matching PURL, matching the create-path mapping")
	assert.Equal(t, lastMatch.Vulnerability.ID, appended.Vulnerability.Name)
	assert.Equal(t, lastMatch.Vulnerability.DataSource, appended.Vulnerability.ID)
}

// TestAPIServerStore_updateVEX_normalizesLegacyStatements guards against a regression where
// statements written with the pre-fix, swapped ID/Name mapping would no longer match the
// current Name-keyed dedup in updateVEX, causing every legacy statement to be duplicated
// (and left permanently un-promotable to "affected") on the next scan.
func TestAPIServerStore_updateVEX_normalizesLegacyStatements(t *testing.T) {
	cveManifestFull := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")
	require.NotEmpty(t, cveManifestFull.Content.Matches)

	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)
	statementCountAfterCreate := len(vexContainer.Spec.Statements)

	// Simulate a document written by the pre-fix update path: ID holds the CVE
	// identifier and Name holds the data source URL, the opposite of the current mapping.
	for i := range vexContainer.Spec.Statements {
		s := &vexContainer.Spec.Statements[i]
		s.Vulnerability.ID, s.Vulnerability.Name = s.Vulnerability.Name, s.Vulnerability.ID
	}
	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(context.Background(), vexContainer, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Re-running the same scan should normalize the legacy statements in place rather
	// than appending duplicates for each of them.
	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))

	vexContainerAfterUpdate, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, statementCountAfterCreate, len(vexContainerAfterUpdate.Spec.Statements))

	for _, s := range vexContainerAfterUpdate.Spec.Statements {
		assert.Contains(t, s.Vulnerability.ID, "://", "expected ID to hold the data source URL after normalization")
		assert.NotContains(t, s.Vulnerability.Name, "://", "expected Name to hold the CVE identifier after normalization")
	}
}

func TestAPIServerStore_updateVEX_doesNotNormalizeCorrectShapeWithNonURLDataSource(t *testing.T) {
	cveManifestFull := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")
	require.NotEmpty(t, cveManifestFull.Content.Matches)

	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)
	statementCountAfterCreate := len(vexContainer.Spec.Statements)

	// A correct-shape statement whose data source happens not to be a URL (ID holds
	// it verbatim) must not be mistaken for a legacy statement and swapped.
	for i := range vexContainer.Spec.Statements {
		vexContainer.Spec.Statements[i].Vulnerability.ID = "nvd"
	}
	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(context.Background(), vexContainer, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))

	vexContainerAfterUpdate, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, statementCountAfterCreate, len(vexContainerAfterUpdate.Spec.Statements))

	for _, s := range vexContainerAfterUpdate.Spec.Statements {
		assert.Equal(t, "nvd", s.Vulnerability.ID)
		assert.NotContains(t, s.Vulnerability.Name, "://")
	}
}

func TestAPIServerStore_updateVEX_mergesMetadataOnUpdate(t *testing.T) {
	cveManifestFull := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")
	require.NotEmpty(t, cveManifestFull.Content.Matches)

	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	// Create with initial annotations/labels preserving existing metadata
	if cveManifestFull.Annotations == nil {
		cveManifestFull.Annotations = make(map[string]string)
	}
	cveManifestFull.Annotations["keep-me"] = "init-val"
	cveManifestFull.Annotations["k1"] = "v1"

	if cveManifestFiltered.Annotations == nil {
		cveManifestFiltered.Annotations = make(map[string]string)
	}
	cveManifestFiltered.Annotations["keep-me"] = "init-val"
	cveManifestFiltered.Annotations["k1"] = "v1"

	if cveManifestFull.Labels == nil {
		cveManifestFull.Labels = make(map[string]string)
	}
	cveManifestFull.Labels["l1"] = "v2"

	if cveManifestFiltered.Labels == nil {
		cveManifestFiltered.Labels = make(map[string]string)
	}
	cveManifestFiltered.Labels["l1"] = "v2"

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))

	// Verify they are created correctly
	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "v1", vexContainer.Annotations["k1"])
	assert.Equal(t, "v2", vexContainer.Labels["l1"])
	assert.Equal(t, "init-val", vexContainer.Annotations["keep-me"])

	// Update with new annotations/labels (omitting keep-me to verify merge retention)
	cveManifestFull.Annotations = map[string]string{"k1": "new-v1", "k2": "v2"}
	cveManifestFull.Labels = map[string]string{"l1": "new-v2", "l2": "v3"}
	cveManifestFiltered.Annotations = map[string]string{"k1": "new-v1", "k2": "v2"}
	cveManifestFiltered.Labels = map[string]string{"l1": "new-v2", "l2": "v3"}

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))

	// Verify they are merged on update
	vexContainerAfterUpdate, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "new-v1", vexContainerAfterUpdate.Annotations["k1"])
	assert.Equal(t, "v2", vexContainerAfterUpdate.Annotations["k2"])
	assert.Equal(t, "init-val", vexContainerAfterUpdate.Annotations["keep-me"])
	assert.Equal(t, "new-v2", vexContainerAfterUpdate.Labels["l1"])
	assert.Equal(t, "v3", vexContainerAfterUpdate.Labels["l2"])
}

func TestAPIServerStore_StoreCVESummaryStub(t *testing.T) {
	workload := domain.ScanCommand{
		Wlid:          "wlid://cluster-kind/namespace-local-path-storage/deployment-local-path-provisioner",
		ContainerName: "local-path-provisioner",
	}
	stubCtx := func() context.Context {
		ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)
		return context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
	}

	t.Run("fresh create writes a zeroed summary with the status annotation", func(t *testing.T) {
		a := NewFakeAPIServerStorage("kubescape")
		ctx := stubCtx()

		require.NoError(t, a.StoreCVESummaryStub(ctx, helpersv1.Incomplete))

		ns, err := GetCVESummaryK8sResourceNamespace(ctx)
		require.NoError(t, err)
		resourceName, err := GetCVESummaryK8sResourceName(ctx)
		require.NoError(t, err)

		got, err := a.StorageClient.VulnerabilityManifestSummaries(ns).Get(context.Background(), resourceName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, helpersv1.Incomplete, got.Annotations[helpersv1.StatusMetadataKey])
		assert.Equal(t, workload.Wlid, got.Annotations[helpersv1.WlidMetadataKey])
		assert.Equal(t, "local-path-provisioner", got.Labels[helpersv1.RelatedNameMetadataKey])
		assert.Equal(t, helpersv1.ContextMetadataKeyNonFiltered, got.Labels[helpersv1.ContextMetadataKey])
		assert.False(t, summaryHasVulnerabilityData(got), "stub Spec should be empty")
	})

	t.Run("update over an existing stub refreshes the status, Spec stays empty", func(t *testing.T) {
		a := NewFakeAPIServerStorage("kubescape")
		ctx := stubCtx()

		require.NoError(t, a.StoreCVESummaryStub(ctx, helpersv1.Incomplete))
		require.NoError(t, a.StoreCVESummaryStub(ctx, helpersv1.TooLarge))

		ns, err := GetCVESummaryK8sResourceNamespace(ctx)
		require.NoError(t, err)
		resourceName, err := GetCVESummaryK8sResourceName(ctx)
		require.NoError(t, err)

		got, err := a.StorageClient.VulnerabilityManifestSummaries(ns).Get(context.Background(), resourceName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, helpersv1.TooLarge, got.Annotations[helpersv1.StatusMetadataKey], "status should be refreshed")
		assert.False(t, summaryHasVulnerabilityData(got))
	})

	t.Run("update over a real summary preserves Spec and does not clobber its status", func(t *testing.T) {
		a := NewFakeAPIServerStorage("kubescape")
		ctx := stubCtx()

		ns, err := GetCVESummaryK8sResourceNamespace(ctx)
		require.NoError(t, err)
		resourceName, err := GetCVESummaryK8sResourceName(ctx)
		require.NoError(t, err)

		// Seed a real summary (non-zero severities) directly in storage
		real := &v1beta1.VulnerabilityManifestSummary{
			ObjectMeta: metav1.ObjectMeta{Name: resourceName},
			Spec: v1beta1.VulnerabilityManifestSummarySpec{
				Severities: v1beta1.SeveritySummary{
					High: v1beta1.VulnerabilityCounters{All: 3, Relevant: 1},
				},
			},
		}
		_, err = a.StorageClient.VulnerabilityManifestSummaries(ns).Create(context.Background(), real, metav1.CreateOptions{})
		require.NoError(t, err)

		require.NoError(t, a.StoreCVESummaryStub(ctx, helpersv1.Incomplete))

		got, err := a.StorageClient.VulnerabilityManifestSummaries(ns).Get(context.Background(), resourceName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, int64(3), got.Spec.Severities.High.All, "real Spec must be preserved")
		assert.NotEqual(t, helpersv1.Incomplete, got.Annotations[helpersv1.StatusMetadataKey], "real summary status must not be clobbered by the stub")
	})
}

// TestAPIServerStore_StoreCVESummaryStub_DoesNotUseMetadataGet guards the
// data-preservation guard in StoreCVESummaryStub: its retry-path Get must fetch
// the full object, not request ResourceVersion "metadata" (which kubescape/
// storage returns as an ObjectMeta-only object with a zeroed Spec). The fake
// clientset ignores GetOptions, so a behavioral test cannot reproduce the
// resulting data loss; only an assertion on the requested GetOptions can.
func TestAPIServerStore_StoreCVESummaryStub_DoesNotUseMetadataGet(t *testing.T) {
	workload := domain.ScanCommand{
		Wlid:          "wlid://cluster-kind/namespace-local-path-storage/deployment-local-path-provisioner",
		ContainerName: "local-path-provisioner",
	}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))

	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)

	ns, err := GetCVESummaryK8sResourceNamespace(ctx)
	require.NoError(t, err)
	resourceName, err := GetCVESummaryK8sResourceName(ctx)
	require.NoError(t, err)

	// Seed a real summary so the stub's Create returns AlreadyExists and the
	// retry-path Get executes.
	real := &v1beta1.VulnerabilityManifestSummary{
		ObjectMeta: metav1.ObjectMeta{Name: resourceName},
		Spec: v1beta1.VulnerabilityManifestSummarySpec{
			Severities: v1beta1.SeveritySummary{
				High: v1beta1.VulnerabilityCounters{All: 3, Relevant: 1},
			},
		},
	}
	_, err = wrapped.VulnerabilityManifestSummaries(ns).Create(context.Background(), real, metav1.CreateOptions{})
	require.NoError(t, err)

	require.NoError(t, a.StoreCVESummaryStub(ctx, helpersv1.Incomplete))

	require.NotNil(t, wrapped.vulnSummaries[ns], "summary sub-client must have been exercised")
	require.Empty(t, wrapped.vulnSummaries[ns].getResourceVersion,
		"StoreCVESummaryStub must not request the metadata-only Get")
}

func TestAPIServerStore_enrichSummaryManifestObjectLabels(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		k8sResourceType      string
		k8sResourceGroup     string
		k8sResourceVersion   string
		k8sResourceName      string
		k8sResourceNamespace string
		labels               map[string]string
		workload             domain.ScanCommand
	}{
		{
			k8sResourceType:      "deployment",
			k8sResourceGroup:     "apps",
			k8sResourceVersion:   "v1",
			k8sResourceName:      "ccc",
			k8sResourceNamespace: "bbb",
			labels:               make(map[string]string),
			workload: domain.ScanCommand{
				ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
				InstanceID:    "",
				Wlid:          "wlid://cluster-aaa/namespace-bbb/deployment-ccc",
				ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
				ContainerName: "contName",
			},
		},
		{
			k8sResourceType:      "cronjob",
			k8sResourceGroup:     "batch",
			k8sResourceVersion:   "v1",
			k8sResourceName:      "123",
			k8sResourceNamespace: "456",
			labels:               make(map[string]string),
			workload: domain.ScanCommand{
				ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
				InstanceID:    "",
				Wlid:          "wlid://cluster-aaa/namespace-456/cronjob-123",
				ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
				ContainerName: "contNameCronJob",
			},
		},
		{
			k8sResourceType:      "job",
			k8sResourceGroup:     "batch",
			k8sResourceVersion:   "v1",
			k8sResourceName:      "anyJob",
			k8sResourceNamespace: "anyNamespaceJob",
			labels:               make(map[string]string),
			workload: domain.ScanCommand{
				ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
				InstanceID:    "",
				Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
				ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
				ContainerName: "anyJobContName",
			},
		},
		{
			k8sResourceType:      "",
			k8sResourceGroup:     "",
			k8sResourceVersion:   "",
			k8sResourceName:      "",
			k8sResourceNamespace: "",
			labels:               make(map[string]string),
			workload: domain.ScanCommand{
				ImageHash:          "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
				ImageTag:           "registry.k8s.io/coredns/coredns:v1.10.1",
				ImageTagNormalized: "registry.k8s.io/coredns/coredns:v1.10.1",
				ImageSlug:          "registry-k8s-io-coredns-coredns-v1-10-1",
				Wlid:               "",
				ContainerName:      "contNameRegistryScan",
			},
		},
	}

	for i := range tests {
		ctx = context.WithValue(ctx, domain.WorkloadKey{}, tests[i].workload)
		enrichedLabels, err := enrichSummaryManifestObjectLabels(ctx, tests[i].labels, true)
		assert.NoError(t, err)

		if tests[i].workload.Wlid != "" {
			val, exist := enrichedLabels[helpersv1.ApiGroupMetadataKey]
			assert.True(t, exist)
			assert.Equal(t, tests[i].k8sResourceGroup, val)

			val, exist = enrichedLabels[helpersv1.ApiVersionMetadataKey]
			assert.True(t, exist)
			assert.Equal(t, tests[i].k8sResourceVersion, val)

			val, exist = enrichedLabels[helpersv1.RelatedKindMetadataKey]
			assert.True(t, exist)
			assert.Equal(t, tests[i].k8sResourceType, val)

			val, exist = enrichedLabels[helpersv1.RelatedNameMetadataKey]
			assert.True(t, exist)
			assert.Equal(t, tests[i].k8sResourceName, val)

			val, exist = enrichedLabels[helpersv1.RelatedNamespaceMetadataKey]
			assert.True(t, exist)
			assert.Equal(t, tests[i].k8sResourceNamespace, val)
		} else {
			_, exist := enrichedLabels[helpersv1.ApiGroupMetadataKey]
			assert.False(t, exist)
			_, exist = enrichedLabels[helpersv1.ApiVersionMetadataKey]
			assert.False(t, exist)
			_, exist = enrichedLabels[helpersv1.RelatedKindMetadataKey]
			assert.False(t, exist)
			_, exist = enrichedLabels[helpersv1.RelatedNameMetadataKey]
			assert.False(t, exist)
			_, exist = enrichedLabels[helpersv1.RelatedNamespaceMetadataKey]
			assert.False(t, exist)
		}

		val, exist := enrichedLabels[helpersv1.ContainerNameMetadataKey]
		assert.True(t, exist)
		assert.Equal(t, tests[i].workload.ContainerName, val)
	}

}

func TestAPIServerStore_StoreCVESummary_EmptyWlid(t *testing.T) {
	a := NewFakeAPIServerStorage("kubescape")
	workload := domain.ScanCommand{
		ImageTag:           "registry.k8s.io/coredns/coredns:v1.10.1",
		ImageTagNormalized: "registry.k8s.io/coredns/coredns:v1.10.1",
		ImageSlug:          "registry-k8s-io-coredns-coredns-v1-10-1",
		Wlid:               "",
		ContainerName:      "coredns",
	}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))

	cve := domain.CVEManifest{
		Name: "registry-k8s-io-coredns-coredns-v1-10-1",
	}

	err := a.StoreCVESummary(ctx, cve, domain.CVEManifest{}, false)
	require.NoError(t, err)

	got, err := a.StorageClient.VulnerabilityManifestSummaries("kubescape").Get(context.Background(), cve.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, cve.Name, got.Name)
	assert.Equal(t, helpersv1.ContextMetadataKeyNonFiltered, got.Labels[helpersv1.ContextMetadataKey])
	assert.Equal(t, "coredns", got.Labels[helpersv1.ContainerNameMetadataKey])
	assert.NotContains(t, got.Labels, helpersv1.ApiGroupMetadataKey)
}

func TestAPIServerStore_StoreCVESummaryStub_EmptyWlid(t *testing.T) {
	a := NewFakeAPIServerStorage("kubescape")
	workload := domain.ScanCommand{
		ImageTag:           "registry.k8s.io/coredns/coredns:v1.10.1",
		ImageTagNormalized: "registry.k8s.io/coredns/coredns:v1.10.1",
		ImageSlug:          "registry-k8s-io-coredns-coredns-v1-10-1",
		Wlid:               "",
		ContainerName:      "coredns",
	}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))

	err := a.StoreCVESummaryStub(ctx, helpersv1.UnsupportedSchema)
	require.NoError(t, err)

	got, err := a.StorageClient.VulnerabilityManifestSummaries("kubescape").Get(context.Background(), "registry-k8s-io-coredns-coredns-v1-10-1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, helpersv1.UnsupportedSchema, got.Annotations[helpersv1.StatusMetadataKey])
	assert.Equal(t, "coredns", got.Labels[helpersv1.ContainerNameMetadataKey])
	assert.NotContains(t, got.Labels, helpersv1.ApiGroupMetadataKey)
}

func TestAPIServerStore_enrichSummaryManifestObjectAnnotations(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		annotations map[string]string
		workload    domain.ScanCommand
	}{
		{
			annotations: make(map[string]string),
			workload: domain.ScanCommand{
				ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
				InstanceID:    "",
				Wlid:          "wlid://cluster-aaa/namespace-bbb/deployment-ccc",
				ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
				ContainerName: "contName",
			},
		},
		{
			annotations: make(map[string]string),
			workload: domain.ScanCommand{
				ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
				InstanceID:    "",
				Wlid:          "wlid://cluster-aaa/namespace-456/cronjob-123",
				ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
				ContainerName: "contNameCronJob",
			},
		},
		{
			annotations: make(map[string]string),
			workload: domain.ScanCommand{
				ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
				InstanceID:    "",
				Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
				ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
				ContainerName: "anyJobContName",
			},
		},
	}

	for i := range tests {
		var timestamp int64 = 1734957372
		ctx = context.WithValue(ctx, domain.WorkloadKey{}, tests[i].workload)
		ctx = context.WithValue(ctx, domain.TimestampKey{}, timestamp)
		enrichedAnnotations, err := enrichSummaryManifestObjectAnnotations(ctx, tests[i].annotations)
		assert.Equal(t, err, nil)

		val, exist := enrichedAnnotations[helpersv1.WlidMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].workload.Wlid)

		val, exist = enrichedAnnotations[helpersv1.ContainerNameMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].workload.ContainerName)

		val, exist = enrichedAnnotations[timestampMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, "1734957372")
	}

}

// The key is part of the shape of every summary manifest already in storage: changing it
// would strand the old annotation on those objects and silently stop anything reading it.
// Worth pinning explicitly, since the code and the test above both go through the constant
// now and would agree with each other whatever it said.
func TestTimestampMetadataKeyIsStable(t *testing.T) {
	assert.Equal(t, "kubescape.io/timestamp", timestampMetadataKey)
}

func TestAPIServerStore_getCVESummaryK8sResourceName(t *testing.T) {
	tests := []struct {
		expRes   string
		workload domain.ScanCommand
		cveName  string
	}{
		{
			workload: domain.ScanCommand{
				Wlid:          "wlid://cluster-aaa/deployment-default/deployment-nginx",
				ContainerName: "nginx",
			},
			expRes: "deployment-nginx-nginx",
		},
		{
			workload: domain.ScanCommand{
				Wlid:          "wlid://cluster-aaa/deployment-default/deployment-nginx",
				ContainerName: "nginx",
			},
			expRes: "deployment-nginx-nginx",
		},
		{
			workload: domain.ScanCommand{
				Wlid:          "wlid://cluster-aaa/deployment-kubescape/deployment-kubescape",
				ContainerName: "kubescape",
			},
			expRes: "deployment-kubescape-kubescape",
		},
		{
			workload: domain.ScanCommand{
				Wlid:          "wlid://cluster-aaa/namespace-kubescape/deployment-kubevuln",
				ContainerName: "kubevuln",
			},
			expRes: "deployment-kubevuln-kubevuln",
		},
		{
			workload: domain.ScanCommand{
				Wlid:          "wlid://cluster-aaa/namespace-kubescape/deployment-operator",
				ContainerName: "operator",
			},
			expRes: "deployment-operator-operator",
		},
		{
			workload: domain.ScanCommand{
				Wlid:          "wlid://cluster-aaa/namespace-kube-system/pod-etcd-control-plane",
				ContainerName: "etcd-control-plane",
			},
			expRes: "pod-etcd-control-plane-etcd-control-plane",
		},
		{
			workload: domain.ScanCommand{},
			cveName:  "docker.io-rancher-system-upgrade-controller-sha256-7b334b59a48c",
			expRes:   "docker.io-rancher-system-upgrade-controller-sha256-7b334b59a48c",
		},
	}

	testsErrorCases := []struct {
		notWorkload any
		err         error
	}{
		{
			err: domain.ErrCastingWorkload,
		},
	}

	for i := range tests {
		ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, tests[i].workload)
		name, err := GetCVESummaryK8sResourceNameWithCVEName(ctx, tests[i].cveName)
		assert.Equal(t, err, nil)
		assert.Equal(t, tests[i].expRes, name)
	}

	for i := range testsErrorCases {
		ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, testsErrorCases[i].notWorkload)
		name, err := GetCVESummaryK8sResourceName(ctx)
		assert.NotEqual(t, err, nil)
		assert.Equal(t, err, testsErrorCases[i].err)
		assert.Equal(t, name, "")
	}
}

func TestMergeMaps(t *testing.T) {
	tests := []struct {
		name     string
		existing map[string]string
		new      map[string]string
		expected map[string]string
	}{
		{
			name:     "merge with no conflicts",
			existing: map[string]string{"key1": "value1"},
			new:      map[string]string{"key2": "value2"},
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name:     "merge with conflicts",
			existing: map[string]string{"key1": "value1"},
			new:      map[string]string{"key1": "newValue1", "key2": "value2"},
			expected: map[string]string{"key1": "newValue1", "key2": "value2"},
		},
		{
			name:     "merge with empty new map",
			existing: map[string]string{"key1": "value1"},
			new:      map[string]string{},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "merge with empty existing map",
			existing: map[string]string{},
			new:      map[string]string{"key1": "value1"},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "merge with both maps empty",
			existing: map[string]string{},
			new:      map[string]string{},
			expected: map[string]string{},
		},
		{
			name:     "merge with nil existing map",
			existing: nil,
			new:      map[string]string{"key1": "value1"},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "merge with nil existing and nil new maps",
			existing: nil,
			new:      nil,
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeMaps(tt.existing, tt.new)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestAPIServerStore_StoreCVE_mergesMetadataOnUpdate(t *testing.T) {
	seeded := &v1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kubescape",
		},
	}
	clientset := newFakeStorageClientset(seeded)
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())

	cve := domain.CVEManifest{
		Name:        name,
		Annotations: map[string]string{"k1": "v1"},
		Labels:      map[string]string{"l1": "v2"},
	}
	require.NoError(t, a.StoreCVE(context.TODO(), cve, false))

	got, err := a.StorageClient.VulnerabilityManifests("kubescape").Get(context.TODO(), name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Annotations["k1"])
	assert.Equal(t, "v2", got.Labels["l1"])
}

func TestAPIServerStore_GetCVE_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("get", "vulnerabilitymanifests", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	_, err := a.GetCVE(context.TODO(), name, "", "", "")
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_GetSBOM_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("get", "sbomsyfts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	_, err := a.GetSBOM(context.TODO(), name, "")
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreCVE_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "vulnerabilitymanifests", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err := a.StoreCVE(context.TODO(), domain.CVEManifest{Name: name}, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreSBOM_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "sbomsyfts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err := a.StoreSBOM(context.TODO(), domain.SBOM{Name: name}, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreSBOMFiltered_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "sbomsyftfiltereds", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err := a.StoreSBOM(context.TODO(), domain.SBOM{Name: name}, true)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreCVESummary_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		InstanceID:    "",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	err := a.StoreCVESummary(ctx, cveManifest, domain.CVEManifest{}, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreCVE_updateGetFailure_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "vulnerabilitymanifests", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "vulnerabilitymanifests"}, name)
	})
	clientset.PrependReactor("get", "vulnerabilitymanifests", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err := a.StoreCVE(context.TODO(), domain.CVEManifest{Name: name}, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreSBOM_updateGetFailure_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "sbomsyfts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "sbomsyfts"}, name)
	})
	clientset.PrependReactor("get", "sbomsyfts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err := a.StoreSBOM(context.TODO(), domain.SBOM{Name: name}, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreSBOMFiltered_updateGetFailure_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "sbomsyftfiltereds", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "sbomsyftfiltereds"}, name)
	})
	clientset.PrependReactor("get", "sbomsyftfiltereds", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err := a.StoreSBOM(context.TODO(), domain.SBOM{Name: name}, true)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreCVESummary_updateGetFailure_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "vulnerabilitymanifestsummaries"}, name)
	})
	clientset.PrependReactor("get", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		InstanceID:    "",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	err := a.StoreCVESummary(ctx, cveManifest, domain.CVEManifest{}, false)
	require.ErrorIs(t, err, injectedErr)
}

// NOTE: the missing Annotations/Labels seeds here are load-bearing — they drive the
// nil-map update path (the mergeMaps crash). See also the SBOM/summary/stub
// retryExhausted tests. Do NOT re-add empty map seeds; that silently deletes the
// regression coverage. The "merged and saved" half is covered by
// TestAPIServerStore_StoreCVE_mergesMetadataOnUpdate.
func TestAPIServerStore_StoreCVE_retryExhausted_transientError(t *testing.T) {
	seeded := &v1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kubescape",
		},
	}
	clientset := newFakeStorageClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "vulnerabilitymanifests", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "vulnerabilitymanifests"}, name, fmt.Errorf("conflict"))
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err := a.StoreCVE(context.TODO(), domain.CVEManifest{Name: name}, false)
	require.True(t, apierrors.IsConflict(err))
	require.Equal(t, retry.DefaultRetry.Steps, updateCalls)
}

func TestAPIServerStore_StoreSBOM_retryExhausted_transientError(t *testing.T) {
	seeded := &v1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kubescape",
		},
	}
	clientset := newFakeStorageClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "sbomsyfts", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "sbomsyfts"}, name, fmt.Errorf("conflict"))
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err := a.StoreSBOM(context.TODO(), domain.SBOM{Name: name}, false)
	require.True(t, apierrors.IsConflict(err))
	require.Equal(t, retry.DefaultRetry.Steps, updateCalls)
}

func TestAPIServerStore_StoreSBOMFiltered_retryExhausted_transientError(t *testing.T) {
	seeded := &v1beta1.SBOMSyftFiltered{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kubescape",
		},
	}
	clientset := newFakeStorageClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "sbomsyftfiltereds", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "sbomsyftfiltereds"}, name, fmt.Errorf("conflict"))
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err := a.StoreSBOM(context.TODO(), domain.SBOM{Name: name}, true)
	require.True(t, apierrors.IsConflict(err))
	require.Equal(t, retry.DefaultRetry.Steps, updateCalls)
}

func TestAPIServerStore_StoreCVESummary_retryExhausted_transientError(t *testing.T) {
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		InstanceID:    "",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")

	resourceName, err := GetCVESummaryK8sResourceNameWithCVEName(ctx, name)
	require.NoError(t, err)
	ns, err := GetCVESummaryK8sResourceNamespace(ctx)
	require.NoError(t, err)

	seeded := &v1beta1.VulnerabilityManifestSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceName,
			Namespace: ns,
		},
	}
	clientset := newFakeStorageClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "vulnerabilitymanifestsummaries"}, resourceName, fmt.Errorf("conflict"))
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err = a.StoreCVESummary(ctx, cveManifest, domain.CVEManifest{}, false)
	require.True(t, apierrors.IsConflict(err))
	require.Equal(t, retry.DefaultRetry.Steps, updateCalls)
}

func TestAPIServerStore_StoreCVESummaryStub_transientError(t *testing.T) {
	workload := domain.ScanCommand{
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))

	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err := a.StoreCVESummaryStub(ctx, helpersv1.UnsupportedSchema)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreCVESummaryStub_retryExhausted_transientError(t *testing.T) {
	workload := domain.ScanCommand{
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))

	resourceName, err := GetCVESummaryK8sResourceName(ctx)
	require.NoError(t, err)
	ns, err := GetCVESummaryK8sResourceNamespace(ctx)
	require.NoError(t, err)

	seeded := &v1beta1.VulnerabilityManifestSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceName,
			Namespace: ns,
		},
	}
	clientset := newFakeStorageClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "vulnerabilitymanifestsummaries"}, resourceName, fmt.Errorf("conflict"))
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err = a.StoreCVESummaryStub(ctx, helpersv1.UnsupportedSchema)
	require.True(t, apierrors.IsConflict(err))
	require.Equal(t, retry.DefaultRetry.Steps, updateCalls)
}

func TestAPIServerStore_StoreVEX_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "openvulnerabilityexchangecontainers", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	cve := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}
	err := a.StoreVEX(context.TODO(), cve, cve, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreVEX_updateGetFailure_transientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "openvulnerabilityexchangecontainers", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "openvulnerabilityexchangecontainers"}, name)
	})
	var getCalls int
	clientset.PrependReactor("get", "openvulnerabilityexchangecontainers", func(k8stesting.Action) (bool, runtime.Object, error) {
		getCalls++
		if getCalls == 1 {
			// the initial existence check: let it fall through to the tracker, which
			// reports NotFound since nothing has been created yet
			return false, nil, nil
		}
		// the Get inside the retry-on-conflict loop, after createVEX raced to AlreadyExists
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	cve := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}
	err := a.StoreVEX(context.TODO(), cve, cve, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreVEX_retryExhausted_transientError(t *testing.T) {
	seeded := &v1beta1.OpenVulnerabilityExchangeContainer{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   "kubescape",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: v1beta1.VEX{
			Metadata: v1beta1.Metadata{Timestamp: time.Now().Format(time.RFC3339)},
		},
	}
	clientset := newFakeStorageClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "openvulnerabilityexchangecontainers", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "openvulnerabilityexchangecontainers"}, name, fmt.Errorf("conflict"))
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	cve := domain.CVEManifest{
		Name:        name,
		Annotations: map[string]string{"kubescape.io/test": "updated"},
		Content:     &v1beta1.GrypeDocument{},
	}
	err := a.StoreVEX(context.TODO(), cve, cve, false)
	require.True(t, apierrors.IsConflict(err))
	require.Equal(t, retry.DefaultRetry.Steps, updateCalls)
}

// TestAPIServerStore_StoreVEX_concurrentCreateRace guards against a regression where a
// caller whose Create lost the race (another writer created the container between this
// caller's own NotFound-returning Get and its Create call) received the raw AlreadyExists
// error instead of falling back to an update, unlike every other Store* method in this file.
func TestAPIServerStore_StoreVEX_concurrentCreateRace(t *testing.T) {
	clientset := newFakeStorageClientset()
	var createCalls int
	clientset.PrependReactor("create", "openvulnerabilityexchangecontainers", func(action k8stesting.Action) (bool, runtime.Object, error) {
		createCalls++
		// Simulate a concurrent writer's createVEX beating this caller's Create:
		// insert the object directly into the tracker (bypassing the Fake's own
		// action-invocation lock, which is already held while this reactor runs,
		// to avoid deadlocking on a reentrant call through the client) and report
		// AlreadyExists back to the caller, exactly as the real apiserver would.
		created := action.(k8stesting.CreateAction).GetObject().(*v1beta1.OpenVulnerabilityExchangeContainer).DeepCopy()
		require.NoError(t, clientset.Tracker().Create(action.GetResource(), created, action.GetNamespace()))
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "openvulnerabilityexchangecontainers"}, name)
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	cve := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}
	err := a.StoreVEX(context.TODO(), cve, cve, false)
	require.NoError(t, err)
	require.Equal(t, 1, createCalls)

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, vexContainer)
	require.Equal(t, name, vexContainer.Name)
}

// TestAPIServerStore_StoreVEX_recoversFromTransientConflict guards against a regression
// where the retry loop stops actually retrying (e.g. a future refactor hoists the Get
// outside the closure and keeps retrying against a stale resourceVersion). It asserts the
// headline behaviour promised by RetryOnConflict: a single transient conflict is absorbed
// and the second attempt succeeds.
func TestAPIServerStore_StoreVEX_recoversFromTransientConflict(t *testing.T) {
	seeded := &v1beta1.OpenVulnerabilityExchangeContainer{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   "kubescape",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: v1beta1.VEX{
			Metadata: v1beta1.Metadata{Timestamp: time.Now().Format(time.RFC3339)},
		},
	}
	clientset := newFakeStorageClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "openvulnerabilityexchangecontainers", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		if updateCalls == 1 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "openvulnerabilityexchangecontainers"}, name, fmt.Errorf("conflict"))
		}
		return false, nil, nil // fall through to the tracker's default update handling
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	cve := domain.CVEManifest{
		Name:        name,
		Annotations: map[string]string{"kubescape.io/test": "updated"},
		Content:     &v1beta1.GrypeDocument{},
	}
	require.NoError(t, a.StoreVEX(context.TODO(), cve, cve, false))
	require.Equal(t, 2, updateCalls)

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Greater(t, vexContainer.Spec.Metadata.Version, int64(0))
}

// The k8s fake clientset's generated typed clients (k8s.io/client-go/gentype) drop the
// caller's ctx before it ever reaches a PrependReactor, so a reactor cannot observe
// cancellation and can't be used to prove ctx propagation. These wrappers instead record
// the exact ctx.Context each call received, so tests can assert the caller's ctx (tagged
// with a canary value) is the one that actually reaches the storage client, rather than
// some context.Background()/context.TODO() substitute.
type ctxCapturingVulnerabilityManifests struct {
	spdxv1beta1.VulnerabilityManifestInterface
	getCtx, createCtx, updateCtx context.Context
}

func (w *ctxCapturingVulnerabilityManifests) Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1beta1.VulnerabilityManifest, error) {
	w.getCtx = ctx
	return w.VulnerabilityManifestInterface.Get(ctx, name, opts)
}

func (w *ctxCapturingVulnerabilityManifests) Create(ctx context.Context, obj *v1beta1.VulnerabilityManifest, opts metav1.CreateOptions) (*v1beta1.VulnerabilityManifest, error) {
	w.createCtx = ctx
	return w.VulnerabilityManifestInterface.Create(ctx, obj, opts)
}

func (w *ctxCapturingVulnerabilityManifests) Update(ctx context.Context, obj *v1beta1.VulnerabilityManifest, opts metav1.UpdateOptions) (*v1beta1.VulnerabilityManifest, error) {
	w.updateCtx = ctx
	return w.VulnerabilityManifestInterface.Update(ctx, obj, opts)
}

type ctxCapturingSBOMSyfts struct {
	spdxv1beta1.SBOMSyftInterface
	getCtx, createCtx, updateCtx context.Context
}

func (w *ctxCapturingSBOMSyfts) Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1beta1.SBOMSyft, error) {
	w.getCtx = ctx
	return w.SBOMSyftInterface.Get(ctx, name, opts)
}

func (w *ctxCapturingSBOMSyfts) Create(ctx context.Context, obj *v1beta1.SBOMSyft, opts metav1.CreateOptions) (*v1beta1.SBOMSyft, error) {
	w.createCtx = ctx
	return w.SBOMSyftInterface.Create(ctx, obj, opts)
}

func (w *ctxCapturingSBOMSyfts) Update(ctx context.Context, obj *v1beta1.SBOMSyft, opts metav1.UpdateOptions) (*v1beta1.SBOMSyft, error) {
	w.updateCtx = ctx
	return w.SBOMSyftInterface.Update(ctx, obj, opts)
}

type ctxCapturingOVECs struct {
	spdxv1beta1.OpenVulnerabilityExchangeContainerInterface
	getCtx, createCtx, updateCtx context.Context
}

func (w *ctxCapturingOVECs) Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1beta1.OpenVulnerabilityExchangeContainer, error) {
	w.getCtx = ctx
	return w.OpenVulnerabilityExchangeContainerInterface.Get(ctx, name, opts)
}

func (w *ctxCapturingOVECs) Create(ctx context.Context, obj *v1beta1.OpenVulnerabilityExchangeContainer, opts metav1.CreateOptions) (*v1beta1.OpenVulnerabilityExchangeContainer, error) {
	w.createCtx = ctx
	return w.OpenVulnerabilityExchangeContainerInterface.Create(ctx, obj, opts)
}

func (w *ctxCapturingOVECs) Update(ctx context.Context, obj *v1beta1.OpenVulnerabilityExchangeContainer, opts metav1.UpdateOptions) (*v1beta1.OpenVulnerabilityExchangeContainer, error) {
	w.updateCtx = ctx
	return w.OpenVulnerabilityExchangeContainerInterface.Update(ctx, obj, opts)
}

type ctxCapturingVulnerabilityManifestSummaries struct {
	spdxv1beta1.VulnerabilityManifestSummaryInterface
	getCtx, createCtx, updateCtx context.Context
	getResourceVersion           string
}

func (w *ctxCapturingVulnerabilityManifestSummaries) Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1beta1.VulnerabilityManifestSummary, error) {
	w.getCtx = ctx
	w.getResourceVersion = opts.ResourceVersion
	return w.VulnerabilityManifestSummaryInterface.Get(ctx, name, opts)
}

func (w *ctxCapturingVulnerabilityManifestSummaries) Create(ctx context.Context, obj *v1beta1.VulnerabilityManifestSummary, opts metav1.CreateOptions) (*v1beta1.VulnerabilityManifestSummary, error) {
	w.createCtx = ctx
	return w.VulnerabilityManifestSummaryInterface.Create(ctx, obj, opts)
}

func (w *ctxCapturingVulnerabilityManifestSummaries) Update(ctx context.Context, obj *v1beta1.VulnerabilityManifestSummary, opts metav1.UpdateOptions) (*v1beta1.VulnerabilityManifestSummary, error) {
	w.updateCtx = ctx
	return w.VulnerabilityManifestSummaryInterface.Update(ctx, obj, opts)
}

type ctxCapturingSBOMSyftFiltereds struct {
	spdxv1beta1.SBOMSyftFilteredInterface
	getCtx, createCtx, updateCtx context.Context
}

func (w *ctxCapturingSBOMSyftFiltereds) Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1beta1.SBOMSyftFiltered, error) {
	w.getCtx = ctx
	return w.SBOMSyftFilteredInterface.Get(ctx, name, opts)
}

func (w *ctxCapturingSBOMSyftFiltereds) Create(ctx context.Context, obj *v1beta1.SBOMSyftFiltered, opts metav1.CreateOptions) (*v1beta1.SBOMSyftFiltered, error) {
	w.createCtx = ctx
	return w.SBOMSyftFilteredInterface.Create(ctx, obj, opts)
}

func (w *ctxCapturingSBOMSyftFiltereds) Update(ctx context.Context, obj *v1beta1.SBOMSyftFiltered, opts metav1.UpdateOptions) (*v1beta1.SBOMSyftFiltered, error) {
	w.updateCtx = ctx
	return w.SBOMSyftFilteredInterface.Update(ctx, obj, opts)
}

type ctxCapturingContainerProfiles struct {
	spdxv1beta1.ContainerProfileInterface
	getCtx, createCtx, updateCtx context.Context
}

func (w *ctxCapturingContainerProfiles) Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1beta1.ContainerProfile, error) {
	w.getCtx = ctx
	return w.ContainerProfileInterface.Get(ctx, name, opts)
}

func (w *ctxCapturingContainerProfiles) Create(ctx context.Context, obj *v1beta1.ContainerProfile, opts metav1.CreateOptions) (*v1beta1.ContainerProfile, error) {
	w.createCtx = ctx
	return w.ContainerProfileInterface.Create(ctx, obj, opts)
}

func (w *ctxCapturingContainerProfiles) Update(ctx context.Context, obj *v1beta1.ContainerProfile, opts metav1.UpdateOptions) (*v1beta1.ContainerProfile, error) {
	w.updateCtx = ctx
	return w.ContainerProfileInterface.Update(ctx, obj, opts)
}

// ctxCapturingClient wraps a real (fake) SpdxV1beta1Interface, swapping in ctx-recording
// wrappers for the sub-clients exercised by the ctxPropagated tests below, while delegating
// everything else untouched.
type ctxCapturingClient struct {
	spdxv1beta1.SpdxV1beta1Interface
	vulnManifests     map[string]*ctxCapturingVulnerabilityManifests
	sbomSyfts         map[string]*ctxCapturingSBOMSyfts
	ovecs             map[string]*ctxCapturingOVECs
	vulnSummaries     map[string]*ctxCapturingVulnerabilityManifestSummaries
	sbomSyftFiltereds map[string]*ctxCapturingSBOMSyftFiltereds
	containerProfiles map[string]*ctxCapturingContainerProfiles
}

// The accessor methods below are called once per storage operation (e.g. StoreVEX calls
// OpenVulnerabilityExchangeContainers(ns) separately for its Get and then again for its
// Create/Update), so the wrapper must be memoized rather than replaced on every call, or
// later calls' captured ctx would clobber earlier ones.

func (c *ctxCapturingClient) VulnerabilityManifests(namespace string) spdxv1beta1.VulnerabilityManifestInterface {
	if c.vulnManifests == nil {
		c.vulnManifests = map[string]*ctxCapturingVulnerabilityManifests{}
	}
	if _, ok := c.vulnManifests[namespace]; !ok {
		c.vulnManifests[namespace] = &ctxCapturingVulnerabilityManifests{VulnerabilityManifestInterface: c.SpdxV1beta1Interface.VulnerabilityManifests(namespace)}
	}
	return c.vulnManifests[namespace]
}

func (c *ctxCapturingClient) SBOMSyfts(namespace string) spdxv1beta1.SBOMSyftInterface {
	if c.sbomSyfts == nil {
		c.sbomSyfts = map[string]*ctxCapturingSBOMSyfts{}
	}
	if _, ok := c.sbomSyfts[namespace]; !ok {
		c.sbomSyfts[namespace] = &ctxCapturingSBOMSyfts{SBOMSyftInterface: c.SpdxV1beta1Interface.SBOMSyfts(namespace)}
	}
	return c.sbomSyfts[namespace]
}

func (c *ctxCapturingClient) OpenVulnerabilityExchangeContainers(namespace string) spdxv1beta1.OpenVulnerabilityExchangeContainerInterface {
	if c.ovecs == nil {
		c.ovecs = map[string]*ctxCapturingOVECs{}
	}
	if _, ok := c.ovecs[namespace]; !ok {
		c.ovecs[namespace] = &ctxCapturingOVECs{OpenVulnerabilityExchangeContainerInterface: c.SpdxV1beta1Interface.OpenVulnerabilityExchangeContainers(namespace)}
	}
	return c.ovecs[namespace]
}

func (c *ctxCapturingClient) VulnerabilityManifestSummaries(namespace string) spdxv1beta1.VulnerabilityManifestSummaryInterface {
	if c.vulnSummaries == nil {
		c.vulnSummaries = map[string]*ctxCapturingVulnerabilityManifestSummaries{}
	}
	if _, ok := c.vulnSummaries[namespace]; !ok {
		c.vulnSummaries[namespace] = &ctxCapturingVulnerabilityManifestSummaries{VulnerabilityManifestSummaryInterface: c.SpdxV1beta1Interface.VulnerabilityManifestSummaries(namespace)}
	}
	return c.vulnSummaries[namespace]
}

func (c *ctxCapturingClient) SBOMSyftFiltereds(namespace string) spdxv1beta1.SBOMSyftFilteredInterface {
	if c.sbomSyftFiltereds == nil {
		c.sbomSyftFiltereds = map[string]*ctxCapturingSBOMSyftFiltereds{}
	}
	if _, ok := c.sbomSyftFiltereds[namespace]; !ok {
		c.sbomSyftFiltereds[namespace] = &ctxCapturingSBOMSyftFiltereds{SBOMSyftFilteredInterface: c.SpdxV1beta1Interface.SBOMSyftFiltereds(namespace)}
	}
	return c.sbomSyftFiltereds[namespace]
}

func (c *ctxCapturingClient) ContainerProfiles(namespace string) spdxv1beta1.ContainerProfileInterface {
	if c.containerProfiles == nil {
		c.containerProfiles = map[string]*ctxCapturingContainerProfiles{}
	}
	if _, ok := c.containerProfiles[namespace]; !ok {
		c.containerProfiles[namespace] = &ctxCapturingContainerProfiles{ContainerProfileInterface: c.SpdxV1beta1Interface.ContainerProfiles(namespace)}
	}
	return c.containerProfiles[namespace]
}

type ctxCanaryKey struct{}

// canaryCtx returns a context carrying a unique, per-call marker value so tests can assert
// on referential identity (via the canary) rather than just "a context was passed" - a nil
// or unrelated context.Context would not carry this value.
func canaryCtx() context.Context {
	return context.WithValue(context.Background(), ctxCanaryKey{}, "canary")
}

func requireCanaryCtx(t *testing.T, got context.Context) {
	t.Helper()
	require.NotNil(t, got)
	require.Equal(t, "canary", got.Value(ctxCanaryKey{}))
}

func TestAPIServerStore_GetCVE_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	_, _ = a.GetCVE(canaryCtx(), name, "", "", "")
	require.Contains(t, wrapped.vulnManifests, a.Namespace)
	requireCanaryCtx(t, wrapped.vulnManifests[a.Namespace].getCtx)
}

func TestAPIServerStore_GetSBOM_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	_, _ = a.GetSBOM(canaryCtx(), name, "")
	require.Contains(t, wrapped.sbomSyfts, a.Namespace)
	requireCanaryCtx(t, wrapped.sbomSyfts[a.Namespace].getCtx)
}

func TestAPIServerStore_GetCVESummary_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(canaryCtx(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
	_, _ = a.GetCVESummary(ctx)
	require.Contains(t, wrapped.vulnSummaries, "anyNamespaceJob")
	requireCanaryCtx(t, wrapped.vulnSummaries["anyNamespaceJob"].getCtx)
}

func TestAPIServerStore_GetCVESummary_WorkloadNamespace(t *testing.T) {
	clientset := newFakeStorageClientset()
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	workload := domain.ScanCommand{
		Wlid: "wlid://cluster-aaa/namespace-custom-workload-ns/deployment-my-deployment",
		Args: map[string]interface{}{
			domain.ArgsName:      "my-deployment",
			domain.ArgsNamespace: "custom-workload-ns",
		},
		ContainerName: "main",
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		ImageTag:      "nginx:latest",
	}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))

	require.NoError(t, a.StoreCVESummaryStub(ctx, "Success"))

	summary, err := a.GetCVESummary(ctx)
	require.NoError(t, err)
	require.NotNil(t, summary)
	require.Equal(t, "deployment-my-deployment-main", summary.Name)

	storedInNs, err := clientset.SpdxV1beta1().VulnerabilityManifestSummaries("custom-workload-ns").Get(ctx, "deployment-my-deployment-main", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, storedInNs)

	_, err = clientset.SpdxV1beta1().VulnerabilityManifestSummaries("kubescape").Get(ctx, "deployment-my-deployment-main", metav1.GetOptions{})
	require.Error(t, err)
	require.True(t, apierrors.IsNotFound(err))
}

func TestAPIServerStore_GetCVESummary_FallbackNamespace(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)

	workload := domain.ScanCommand{
		ImageHash: "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		ImageTag:  "nginx:latest",
	}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)
	_, _ = a.GetCVESummary(ctx)

	require.Contains(t, wrapped.vulnSummaries, "kubescape")
}

func TestAPIServerStore_GetCVESummary_returnsTransientError(t *testing.T) {
	clientset := newFakeStorageClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("get", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
	_, err := a.GetCVESummary(ctx)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreCVE_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	require.NoError(t, a.StoreCVE(canaryCtx(), domain.CVEManifest{Name: name}, false))
	require.Contains(t, wrapped.vulnManifests, a.Namespace)
	requireCanaryCtx(t, wrapped.vulnManifests[a.Namespace].createCtx)
}

func TestAPIServerStore_StoreSBOM_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	require.NoError(t, a.StoreSBOM(canaryCtx(), domain.SBOM{Name: name}, false))
	require.Contains(t, wrapped.sbomSyfts, a.Namespace)
	requireCanaryCtx(t, wrapped.sbomSyfts[a.Namespace].createCtx)
}

func TestAPIServerStore_StoreVEX_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	cve := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}
	require.NoError(t, a.StoreVEX(canaryCtx(), cve, cve, false))
	require.Contains(t, wrapped.ovecs, a.Namespace)
	requireCanaryCtx(t, wrapped.ovecs[a.Namespace].getCtx)
	requireCanaryCtx(t, wrapped.ovecs[a.Namespace].createCtx)
}

// TestAPIServerStore_GetSecurityExceptions_PropagatesListErrors is a regression test for
// #477: GetSecurityExceptions used to only log a List() failure and always return a nil
// error, which silently defeated the cacheable=false guard in
// BackendAdapter.GetCVEExceptions (that guard only fires when this method's error is
// non-nil). A List() failure on either the namespaced or cluster-scoped resource must now
// surface as a non-nil returned error.
func TestAPIServerStore_GetSecurityExceptions_PropagatesListErrors(t *testing.T) {
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))

	tests := []struct {
		name         string
		namespace    string
		failResource string
	}{
		{name: "namespaced list fails", namespace: "kubescape", failResource: "securityexceptions"},
		{name: "cluster-scoped list fails", namespace: "kubescape", failResource: "clustersecurityexceptions"},
		{name: "cluster-scoped list fails, no namespace given", namespace: "", failResource: "clustersecurityexceptions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
				securityExceptionGVR:        "SecurityExceptionList",
				clusterSecurityExceptionGVR: "ClusterSecurityExceptionList",
			})
			dynClient.PrependReactor("list", tt.failResource, func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, injectedErr
			})
			a := &APIServerStore{DynamicClient: dynClient, Namespace: "kubescape"}

			_, _, err := a.GetSecurityExceptions(context.TODO(), tt.namespace)
			require.Error(t, err, "a List() failure must surface as a non-nil error, not just a log line")
			assert.True(t, stderrors.Is(err, injectedErr))
		})
	}
}

// TestAPIServerStore_GetSecurityExceptions_NoErrorOnSuccess guards against a regression in
// the other direction: joining a nil error slice must still return nil, not a non-nil
// "empty" error, so a successful call keeps behaving exactly as before.
func TestAPIServerStore_GetSecurityExceptions_NoErrorOnSuccess(t *testing.T) {
	a := NewFakeAPIServerStorage("kubescape")
	se, cse, err := a.GetSecurityExceptions(context.TODO(), "kubescape")
	require.NoError(t, err)
	assert.Empty(t, se)
	assert.Empty(t, cse)
}

// TestAPIServerStore_GetSecurityExceptions_CachesAcrossWorkloads is a regression test for
// #510: GetSecurityExceptions used to issue a fresh List() call for both CRD types on every
// invocation, even though the raw list is identical for every workload sharing the same
// namespace (SecurityException) or the same cluster (ClusterSecurityException). List() call
// counters prove the cache collapses repeated calls within the TTL into a single List(), and
// that a genuinely new namespace still gets its own namespaced list while reusing the
// already-cached cluster-scoped one.
func TestAPIServerStore_GetSecurityExceptions_CachesAcrossWorkloads(t *testing.T) {
	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		securityExceptionGVR:        "SecurityExceptionList",
		clusterSecurityExceptionGVR: "ClusterSecurityExceptionList",
	})

	var seListCalls, cseListCalls int32
	dynClient.PrependReactor("list", "securityexceptions", func(k8stesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(&seListCalls, 1)
		return false, nil, nil
	})
	dynClient.PrependReactor("list", "clustersecurityexceptions", func(k8stesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(&cseListCalls, 1)
		return false, nil, nil
	})

	a := &APIServerStore{
		DynamicClient:              dynClient,
		Namespace:                  "kubescape",
		securityExceptionListCache: cache.New(time.Minute),
	}

	// Two calls for the same namespace, simulating two distinct workloads/images scanned in it.
	_, _, err := a.GetSecurityExceptions(context.TODO(), "ns-a")
	require.NoError(t, err)
	_, _, err = a.GetSecurityExceptions(context.TODO(), "ns-a")
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&seListCalls), "second call for the same namespace should be served from cache")
	assert.Equal(t, int32(1), atomic.LoadInt32(&cseListCalls), "second call should also reuse the cached cluster-scoped list")

	// A different namespace needs its own namespaced list, but the cluster-scoped list is
	// shared across every namespace and must still come from cache.
	_, _, err = a.GetSecurityExceptions(context.TODO(), "ns-b")
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&seListCalls), "a new namespace is a cache miss for the namespaced list")
	assert.Equal(t, int32(1), atomic.LoadInt32(&cseListCalls), "ClusterSecurityExceptions are cluster-wide and must not be re-listed per namespace")
}

// TestAPIServerStore_GetSecurityExceptions_DoesNotCacheListFailures guards the self-healing
// property #477 relies on: a List() failure must never populate the cache, or a transient
// apiserver hiccup would be pinned as "no exceptions" for the full cache TTL instead of being
// retried on the next call.
func TestAPIServerStore_GetSecurityExceptions_DoesNotCacheListFailures(t *testing.T) {
	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		securityExceptionGVR:        "SecurityExceptionList",
		clusterSecurityExceptionGVR: "ClusterSecurityExceptionList",
	})

	var calls int32
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	dynClient.PrependReactor("list", "clustersecurityexceptions", func(k8stesting.Action) (bool, runtime.Object, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return true, nil, injectedErr
		}
		return false, nil, nil
	})

	a := &APIServerStore{
		DynamicClient:              dynClient,
		Namespace:                  "kubescape",
		securityExceptionListCache: cache.New(time.Minute),
	}

	_, _, err := a.GetSecurityExceptions(context.TODO(), "")
	require.Error(t, err)

	_, _, err = a.GetSecurityExceptions(context.TODO(), "")
	require.NoError(t, err, "a failed List() must not be cached, so the next call retries instead of replaying the failure")
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
}

// TestAPIServerStore_ListSecurityExceptions_DoesNotRepopulateAfterRacingInvalidation is a
// regression test for #733: enableSecurityExceptionCacheInvalidation evicts a cache key as soon
// as its CRD changes, but a List() already in flight for that key when the change lands used to
// still write its now-stale result back to the cache once it returned, silently undoing the
// invalidation. The hook blocks the fake client's List() call exactly where the real one would
// be in flight against a real apiserver, letting the test fire the informer's invalidation
// handler while List() hasn't returned yet - the same interleaving the issue describes.
func TestAPIServerStore_ListSecurityExceptions_DoesNotRepopulateAfterRacingInvalidation(t *testing.T) {
	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		securityExceptionGVR:        "SecurityExceptionList",
		clusterSecurityExceptionGVR: "ClusterSecurityExceptionList",
	})
	wrapped := &ctxCapturingDynamicClient{Interface: dynClient}

	listInFlight := make(chan struct{})
	releaseList := make(chan struct{})
	wrapped.resources = map[schema.GroupVersionResource]*ctxCapturingResource{
		securityExceptionGVR: {
			ResourceInterface: dynClient.Resource(securityExceptionGVR),
			hook: func(context.Context) {
				close(listInFlight)
				<-releaseList
			},
		},
	}

	a := &APIServerStore{
		DynamicClient:              wrapped,
		Namespace:                  "kubescape",
		securityExceptionListCache: cache.New(time.Minute),
	}

	done := make(chan struct{})
	var listErr error
	go func() {
		defer close(done)
		_, _, listErr = a.GetSecurityExceptions(context.Background(), "ns-a")
	}()

	select {
	case <-listInFlight:
	case <-time.After(5 * time.Second):
		t.Fatal("List() never reached the point where it should be in flight")
	}

	// Simulate a SecurityException change in ns-a landing while the List() above is still in
	// flight, the same way the informer's event handler would invoke this on a real change.
	a.invalidateSecurityExceptionCacheForObject(&unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"namespace": "ns-a"},
	}})

	close(releaseList)
	select {
	case <-done:
		assert.NoError(t, listErr)
	case <-time.After(5 * time.Second):
		t.Fatal("GetSecurityExceptions never returned")
	}

	_, ok := a.securityExceptionListCache.Get("se/ns-a")
	assert.False(t, ok, "a List() that raced an invalidation must not repopulate the cache with its now-stale result")
}

// TestAPIServerStore_ListClusterSecurityExceptions_DoesNotRepopulateAfterRacingInvalidation is
// the cluster-scoped counterpart of the test above, for invalidateClusterSecurityExceptionCache.
func TestAPIServerStore_ListClusterSecurityExceptions_DoesNotRepopulateAfterRacingInvalidation(t *testing.T) {
	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		securityExceptionGVR:        "SecurityExceptionList",
		clusterSecurityExceptionGVR: "ClusterSecurityExceptionList",
	})
	wrapped := &ctxCapturingDynamicClient{Interface: dynClient}

	listInFlight := make(chan struct{})
	releaseList := make(chan struct{})
	wrapped.resources = map[schema.GroupVersionResource]*ctxCapturingResource{
		clusterSecurityExceptionGVR: {
			ResourceInterface: dynClient.Resource(clusterSecurityExceptionGVR),
			hook: func(context.Context) {
				close(listInFlight)
				<-releaseList
			},
		},
	}

	a := &APIServerStore{
		DynamicClient:              wrapped,
		Namespace:                  "kubescape",
		securityExceptionListCache: cache.New(time.Minute),
	}

	done := make(chan struct{})
	var listErr error
	go func() {
		defer close(done)
		_, _, listErr = a.GetSecurityExceptions(context.Background(), "")
	}()

	select {
	case <-listInFlight:
	case <-time.After(5 * time.Second):
		t.Fatal("List() never reached the point where it should be in flight")
	}

	a.invalidateClusterSecurityExceptionCache()

	close(releaseList)
	select {
	case <-done:
		assert.NoError(t, listErr)
	case <-time.After(5 * time.Second):
		t.Fatal("GetSecurityExceptions never returned")
	}

	_, ok := a.securityExceptionListCache.Get(clusterSecurityExceptionListCacheKey)
	assert.False(t, ok, "a List() that raced an invalidation must not repopulate the cache with its now-stale result")
}

// TestAPIServerStore_TrySetSecurityExceptionCache_GenerationMismatchSkipsWrite unit-tests the
// compare-and-swap primitive directly, without goroutines: the write must be skipped whenever an
// invalidation bumped the generation after the snapshot the caller took before its List() call.
func TestAPIServerStore_TrySetSecurityExceptionCache_GenerationMismatchSkipsWrite(t *testing.T) {
	a := &APIServerStore{securityExceptionListCache: cache.New(time.Minute)}

	seenGeneration := a.beginSecurityExceptionCacheRefresh("se/ns-a")
	a.invalidateSecurityExceptionCacheKey("se/ns-a") // simulates a CRD change landing mid-List()
	a.trySetSecurityExceptionCache("se/ns-a", seenGeneration, []sev1beta1.SecurityException{{}})

	_, ok := a.securityExceptionListCache.Get("se/ns-a")
	assert.False(t, ok, "a stale generation must prevent the write")
}

// TestAPIServerStore_TrySetSecurityExceptionCache_GenerationMatchWrites is the non-racing
// counterpart: with no invalidation in between, the write must still succeed exactly as before
// this fix, so #733's fix does not change GetSecurityExceptions' behavior on the common path.
func TestAPIServerStore_TrySetSecurityExceptionCache_GenerationMatchWrites(t *testing.T) {
	a := &APIServerStore{securityExceptionListCache: cache.New(time.Minute)}

	seenGeneration := a.beginSecurityExceptionCacheRefresh("se/ns-a")
	a.trySetSecurityExceptionCache("se/ns-a", seenGeneration, []sev1beta1.SecurityException{{}})

	cached, ok := a.securityExceptionListCache.Get("se/ns-a")
	require.True(t, ok, "an unraced write must still populate the cache")
	assert.Len(t, cached.([]sev1beta1.SecurityException), 1)
}

// TestAPIServerStore_InvalidateAllSecurityExceptionCaches_CoversInFlightKey is a regression test
// for the "unrecognized object" fallback path in invalidateSecurityExceptionCacheForObject: it
// must invalidate a namespace whose List() is in flight (and so has no value in
// securityExceptionListCache yet, only an entry in securityExceptionCacheEntries), not just
// namespaces that already have a cached value to range over.
func TestAPIServerStore_InvalidateAllSecurityExceptionCaches_CoversInFlightKey(t *testing.T) {
	a := &APIServerStore{securityExceptionListCache: cache.New(time.Minute)}

	seenGeneration := a.beginSecurityExceptionCacheRefresh("se/ns-a") // List() "in flight", no Set() yet

	a.invalidateSecurityExceptionCacheForObject(&unstructured.Unstructured{}) // unresolvable -> invalidate all

	a.trySetSecurityExceptionCache("se/ns-a", seenGeneration, []sev1beta1.SecurityException{{}})

	_, ok := a.securityExceptionListCache.Get("se/ns-a")
	assert.False(t, ok, "an in-flight key must be covered by the invalidate-all fallback, not just already-cached keys")
}

func TestAPIServerStore_InvalidateSecurityExceptionCacheForObject(t *testing.T) {
	a := &APIServerStore{securityExceptionListCache: cache.New(time.Minute)}
	a.securityExceptionListCache.Set("se/ns-a", []sev1beta1.SecurityException{{}}, time.Minute)
	a.securityExceptionListCache.Set("se/ns-b", []sev1beta1.SecurityException{{}}, time.Minute)
	a.securityExceptionListCache.Set(clusterSecurityExceptionListCacheKey, []sev1beta1.ClusterSecurityException{{}}, time.Minute)

	a.invalidateSecurityExceptionCacheForObject(&unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{
			"namespace": "ns-a",
		},
	}})

	_, ok := a.securityExceptionListCache.Get("se/ns-a")
	assert.False(t, ok, "the changed namespace must be evicted immediately")
	_, ok = a.securityExceptionListCache.Get("se/ns-b")
	assert.True(t, ok, "other namespaces must stay cached")
	_, ok = a.securityExceptionListCache.Get(clusterSecurityExceptionListCacheKey)
	assert.True(t, ok, "cluster-scoped exceptions must not be evicted by a namespaced change")
}

func TestAPIServerStore_InvalidateClusterSecurityExceptionCache(t *testing.T) {
	a := &APIServerStore{securityExceptionListCache: cache.New(time.Minute)}
	a.securityExceptionListCache.Set("se/ns-a", []sev1beta1.SecurityException{{}}, time.Minute)
	a.securityExceptionListCache.Set(clusterSecurityExceptionListCacheKey, []sev1beta1.ClusterSecurityException{{}}, time.Minute)

	a.invalidateClusterSecurityExceptionCache()

	_, ok := a.securityExceptionListCache.Get(clusterSecurityExceptionListCacheKey)
	assert.False(t, ok, "cluster-scoped cache must be evicted immediately")
	_, ok = a.securityExceptionListCache.Get("se/ns-a")
	assert.True(t, ok, "namespaced exceptions must stay cached")
}

// ctxCapturingResource wraps a dynamic.ResourceInterface, invoking a hook synchronously with
// the ctx passed into List/Get, before delegating to the real call. The hook lets a test cancel
// the caller's ctx *while the K8s API call is in flight* and assert the effect on the ctx the
// call actually received - the only way to distinguish a derived ctx (context.WithTimeout(ctx,
// ...), which is canceled immediately) from a context.WithoutCancel-detached one (which is not),
// since by the time the surrounding APIServerStore method returns, its own `defer cancel()`
// has already canceled the derived ctx either way.
type ctxCapturingResource struct {
	dynamic.ResourceInterface
	hook func(ctx context.Context)
}

func (r *ctxCapturingResource) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	if r.hook != nil {
		r.hook(ctx)
	}
	return r.ResourceInterface.List(ctx, opts)
}

func (r *ctxCapturingResource) Get(ctx context.Context, name string, opts metav1.GetOptions, subresources ...string) (*unstructured.Unstructured, error) {
	if r.hook != nil {
		r.hook(ctx)
	}
	return r.ResourceInterface.Get(ctx, name, opts, subresources...)
}

// Namespace mutates the receiver in place (rather than returning a fresh wrapper) so that a
// subsequent List/Get on the namespaced handle still runs through the same hook.
func (r *ctxCapturingResource) Namespace(ns string) dynamic.ResourceInterface {
	r.ResourceInterface = r.ResourceInterface.(dynamic.NamespaceableResourceInterface).Namespace(ns)
	return r
}

// ctxCapturingDynamicClient wraps a dynamic.Interface, returning the pre-registered
// ctxCapturingResource for a GVR (see resources) so a test's hook is preserved, or a
// pass-through one otherwise.
type ctxCapturingDynamicClient struct {
	dynamic.Interface
	resources map[schema.GroupVersionResource]*ctxCapturingResource
}

func (c *ctxCapturingDynamicClient) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	if c.resources == nil {
		c.resources = map[schema.GroupVersionResource]*ctxCapturingResource{}
	}
	if _, ok := c.resources[gvr]; !ok {
		c.resources[gvr] = &ctxCapturingResource{ResourceInterface: c.Interface.Resource(gvr)}
	}
	return c.resources[gvr]
}

// requireHookObservesCancellation builds a hook for ctxCapturingResource that, the first time
// it runs, cancels the caller's ctx and asserts the ctx received by the K8s API call is
// canceled too - proving it derives from the caller's ctx instead of detaching from it via
// context.WithoutCancel.
func requireHookObservesCancellation(t *testing.T, cancel func()) (hook func(ctx context.Context), called *bool) {
	t.Helper()
	calledFlag := false
	return func(ctx context.Context) {
		calledFlag = true
		select {
		case <-ctx.Done():
			t.Error("ctx passed to the K8s API call must not already be canceled before the caller's ctx is canceled")
		default:
		}
		cancel()
		assert.ErrorIs(t, ctx.Err(), context.Canceled, "canceling the caller's ctx must cancel the ctx passed to the K8s API call")
	}, &calledFlag
}

func TestAPIServerStore_GetSecurityExceptions_HonorsCallerCancellation(t *testing.T) {
	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		securityExceptionGVR:        "SecurityExceptionList",
		clusterSecurityExceptionGVR: "ClusterSecurityExceptionList",
	})
	wrapped := &ctxCapturingDynamicClient{Interface: dynClient}
	a := &APIServerStore{DynamicClient: wrapped, Namespace: "kubescape"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hook, called := requireHookObservesCancellation(t, cancel)
	wrapped.resources = map[schema.GroupVersionResource]*ctxCapturingResource{
		clusterSecurityExceptionGVR: {ResourceInterface: dynClient.Resource(clusterSecurityExceptionGVR), hook: hook},
	}

	_, _, err := a.GetSecurityExceptions(ctx, "kubescape")
	require.NoError(t, err)
	require.True(t, *called, "the List call the hook was attached to must have run")
}

func TestAPIServerStore_GetWorkloadLabels_HonorsCallerCancellation(t *testing.T) {
	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{})
	wrapped := &ctxCapturingDynamicClient{Interface: dynClient}
	a := &APIServerStore{DynamicClient: wrapped, Namespace: "kubescape"}

	podGVR, err := k8sinterface.GetGroupVersionResource("Pod")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hook, called := requireHookObservesCancellation(t, cancel)
	wrapped.resources = map[schema.GroupVersionResource]*ctxCapturingResource{
		podGVR: {ResourceInterface: dynClient.Resource(podGVR), hook: hook},
	}

	_, _ = a.GetWorkloadLabels(ctx, "kubescape", "Pod", "mypod")
	require.True(t, *called, "the Get call the hook was attached to must have run")
}

func TestAPIServerStore_GetNamespaceLabels_HonorsCallerCancellation(t *testing.T) {
	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{})
	wrapped := &ctxCapturingDynamicClient{Interface: dynClient}
	a := &APIServerStore{DynamicClient: wrapped, Namespace: "kubescape"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hook, called := requireHookObservesCancellation(t, cancel)
	wrapped.resources = map[schema.GroupVersionResource]*ctxCapturingResource{
		namespaceGVR: {ResourceInterface: dynClient.Resource(namespaceGVR), hook: hook},
	}

	_, _ = a.GetNamespaceLabels(ctx, "myns")
	require.True(t, *called, "the Get call the hook was attached to must have run")
}

func TestAPIServerStore_GetContainerProfile_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	_, _ = a.GetContainerProfile(canaryCtx(), "my-namespace", name)
	require.Contains(t, wrapped.containerProfiles, "my-namespace")
	requireCanaryCtx(t, wrapped.containerProfiles["my-namespace"].getCtx)
}

func TestAPIServerStore_StoreSBOMFiltered_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	require.NoError(t, a.StoreSBOM(canaryCtx(), domain.SBOM{Name: name}, true))
	require.Contains(t, wrapped.sbomSyftFiltereds, a.Namespace)
	requireCanaryCtx(t, wrapped.sbomSyftFiltereds[a.Namespace].createCtx)
}

func TestAPIServerStore_StoreCVESummary_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(canaryCtx(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
	cveManifest := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}
	require.NoError(t, a.StoreCVESummary(ctx, cveManifest, cveManifest, false))
	require.Contains(t, wrapped.vulnSummaries, "anyNamespaceJob")
	requireCanaryCtx(t, wrapped.vulnSummaries["anyNamespaceJob"].createCtx)
}

func TestAPIServerStore_StoreCVESummaryStub_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(canaryCtx(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
	require.NoError(t, a.StoreCVESummaryStub(ctx, helpersv1.Incomplete))
	require.Contains(t, wrapped.vulnSummaries, "anyNamespaceJob")
	requireCanaryCtx(t, wrapped.vulnSummaries["anyNamespaceJob"].createCtx)
}

func TestAPIServerStore_StoreVEX_RetryConflict_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-kubescape/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)
	cve := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}

	// First store (creates the object)
	require.NoError(t, a.StoreVEX(ctx, cve, cve, false))

	// Reset captured contexts
	require.Contains(t, wrapped.ovecs, a.Namespace)
	wrapped.ovecs[a.Namespace].getCtx = nil
	wrapped.ovecs[a.Namespace].createCtx = nil
	wrapped.ovecs[a.Namespace].updateCtx = nil

	conflicts := 0
	clientset.PrependReactor("update", "openvulnerabilityexchangecontainers", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if conflicts < 1 {
			conflicts++
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{Group: "spdx.softwarecomposition.kubescape.io", Resource: "openvulnerabilityexchangecontainers"}, name, nil)
		}
		return false, nil, nil
	})

	// Second store with canary context (triggers conflict retry)
	canary := context.WithValue(canaryCtx(), domain.WorkloadKey{}, workload)
	updated := cve
	updated.Annotations = map[string]string{"kubescape.io/test": "updated"}
	require.NoError(t, a.StoreVEX(canary, updated, updated, false))

	requireCanaryCtx(t, wrapped.ovecs[a.Namespace].getCtx)
	requireCanaryCtx(t, wrapped.ovecs[a.Namespace].updateCtx)
	require.Equal(t, 1, conflicts)
}

func TestAPIServerStore_StoreCVE_RetryConflict_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)

	// First store
	require.NoError(t, a.StoreCVE(context.Background(), domain.CVEManifest{Name: name}, false))

	// Reset
	require.Contains(t, wrapped.vulnManifests, a.Namespace)
	wrapped.vulnManifests[a.Namespace].getCtx = nil
	wrapped.vulnManifests[a.Namespace].createCtx = nil
	wrapped.vulnManifests[a.Namespace].updateCtx = nil

	conflicts := 0
	clientset.PrependReactor("update", "vulnerabilitymanifests", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if conflicts < 1 {
			conflicts++
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{Group: "spdx.softwarecomposition.kubescape.io", Resource: "vulnerabilitymanifests"}, name, nil)
		}
		return false, nil, nil
	})

	// Second store
	require.NoError(t, a.StoreCVE(canaryCtx(), domain.CVEManifest{Name: name}, false))

	requireCanaryCtx(t, wrapped.vulnManifests[a.Namespace].getCtx)
	requireCanaryCtx(t, wrapped.vulnManifests[a.Namespace].createCtx)
	requireCanaryCtx(t, wrapped.vulnManifests[a.Namespace].updateCtx)
	require.Equal(t, 1, conflicts)
}

func TestAPIServerStore_StoreSBOM_RetryConflict_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)

	// First store
	require.NoError(t, a.StoreSBOM(context.Background(), domain.SBOM{Name: name}, false))

	// Reset
	require.Contains(t, wrapped.sbomSyfts, a.Namespace)
	wrapped.sbomSyfts[a.Namespace].getCtx = nil
	wrapped.sbomSyfts[a.Namespace].createCtx = nil
	wrapped.sbomSyfts[a.Namespace].updateCtx = nil

	conflicts := 0
	clientset.PrependReactor("update", "sbomsyfts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if conflicts < 1 {
			conflicts++
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{Group: "spdx.softwarecomposition.kubescape.io", Resource: "sbomsyfts"}, name, nil)
		}
		return false, nil, nil
	})

	// Second store
	require.NoError(t, a.StoreSBOM(canaryCtx(), domain.SBOM{Name: name}, false))

	requireCanaryCtx(t, wrapped.sbomSyfts[a.Namespace].getCtx)
	requireCanaryCtx(t, wrapped.sbomSyfts[a.Namespace].createCtx)
	requireCanaryCtx(t, wrapped.sbomSyfts[a.Namespace].updateCtx)
	require.Equal(t, 1, conflicts)
}

func TestAPIServerStore_StoreSBOMFiltered_RetryConflict_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)

	// First store
	require.NoError(t, a.StoreSBOM(context.Background(), domain.SBOM{Name: name}, true))

	// Reset
	require.Contains(t, wrapped.sbomSyftFiltereds, a.Namespace)
	wrapped.sbomSyftFiltereds[a.Namespace].getCtx = nil
	wrapped.sbomSyftFiltereds[a.Namespace].createCtx = nil
	wrapped.sbomSyftFiltereds[a.Namespace].updateCtx = nil

	conflicts := 0
	clientset.PrependReactor("update", "sbomsyftfiltereds", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if conflicts < 1 {
			conflicts++
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{Group: "spdx.softwarecomposition.kubescape.io", Resource: "sbomsyftfiltereds"}, name, nil)
		}
		return false, nil, nil
	})

	// Second store
	require.NoError(t, a.StoreSBOM(canaryCtx(), domain.SBOM{Name: name}, true))

	requireCanaryCtx(t, wrapped.sbomSyftFiltereds[a.Namespace].getCtx)
	requireCanaryCtx(t, wrapped.sbomSyftFiltereds[a.Namespace].createCtx)
	requireCanaryCtx(t, wrapped.sbomSyftFiltereds[a.Namespace].updateCtx)
	require.Equal(t, 1, conflicts)
}

func TestAPIServerStore_StoreCVESummary_RetryConflict_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
	cveManifest := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}

	// First store
	require.NoError(t, a.StoreCVESummary(ctx, cveManifest, cveManifest, false))

	// Reset
	require.Contains(t, wrapped.vulnSummaries, "anyNamespaceJob")
	wrapped.vulnSummaries["anyNamespaceJob"].getCtx = nil
	wrapped.vulnSummaries["anyNamespaceJob"].createCtx = nil
	wrapped.vulnSummaries["anyNamespaceJob"].updateCtx = nil

	conflicts := 0
	clientset.PrependReactor("update", "vulnerabilitymanifestsummaries", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if conflicts < 1 {
			conflicts++
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{Group: "spdx.softwarecomposition.kubescape.io", Resource: "vulnerabilitymanifestsummaries"}, name, nil)
		}
		return false, nil, nil
	})

	// Second store
	canary := context.WithValue(canaryCtx(), domain.WorkloadKey{}, workload)
	canary = context.WithValue(canary, domain.TimestampKey{}, int64(1734957372))
	require.NoError(t, a.StoreCVESummary(canary, cveManifest, cveManifest, false))

	requireCanaryCtx(t, wrapped.vulnSummaries["anyNamespaceJob"].getCtx)
	requireCanaryCtx(t, wrapped.vulnSummaries["anyNamespaceJob"].createCtx)
	requireCanaryCtx(t, wrapped.vulnSummaries["anyNamespaceJob"].updateCtx)
	require.Equal(t, 1, conflicts)
}

func TestAPIServerStore_StoreCVESummaryStub_RetryConflict_ctxPropagated(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := newFakeAPIServerStore("kubescape", wrapped)
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))

	// First store
	require.NoError(t, a.StoreCVESummaryStub(ctx, helpersv1.Incomplete))

	// Reset
	require.Contains(t, wrapped.vulnSummaries, "anyNamespaceJob")
	wrapped.vulnSummaries["anyNamespaceJob"].getCtx = nil
	wrapped.vulnSummaries["anyNamespaceJob"].createCtx = nil
	wrapped.vulnSummaries["anyNamespaceJob"].updateCtx = nil

	conflicts := 0
	clientset.PrependReactor("update", "vulnerabilitymanifestsummaries", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if conflicts < 1 {
			conflicts++
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{Group: "spdx.softwarecomposition.kubescape.io", Resource: "vulnerabilitymanifestsummaries"}, name, nil)
		}
		return false, nil, nil
	})

	// Second store
	canary := context.WithValue(canaryCtx(), domain.WorkloadKey{}, workload)
	canary = context.WithValue(canary, domain.TimestampKey{}, int64(1734957372))
	require.NoError(t, a.StoreCVESummaryStub(canary, helpersv1.Incomplete))

	requireCanaryCtx(t, wrapped.vulnSummaries["anyNamespaceJob"].getCtx)
	requireCanaryCtx(t, wrapped.vulnSummaries["anyNamespaceJob"].createCtx)
	requireCanaryCtx(t, wrapped.vulnSummaries["anyNamespaceJob"].updateCtx)
	require.Equal(t, 1, conflicts)
}

func TestCtxCapturingClient_wrappersKeyedByNamespace(t *testing.T) {
	clientset := newFakeStorageClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}

	// VulnerabilityManifests: different namespaces must return different wrappers,
	// repeated access to one namespace must return the same wrapper.
	vm1 := wrapped.VulnerabilityManifests("ns-a")
	vm2 := wrapped.VulnerabilityManifests("ns-b")
	vm1Again := wrapped.VulnerabilityManifests("ns-a")
	require.NotSame(t, vm1, vm2, "different namespaces must return different wrappers")
	require.Same(t, vm1, vm1Again, "same namespace must return the memoized wrapper")

	// SBOMSyfts
	ss1 := wrapped.SBOMSyfts("ns-a")
	ss2 := wrapped.SBOMSyfts("ns-b")
	ss1Again := wrapped.SBOMSyfts("ns-a")
	require.NotSame(t, ss1, ss2)
	require.Same(t, ss1, ss1Again)

	// OpenVulnerabilityExchangeContainers
	ov1 := wrapped.OpenVulnerabilityExchangeContainers("ns-a")
	ov2 := wrapped.OpenVulnerabilityExchangeContainers("ns-b")
	ov1Again := wrapped.OpenVulnerabilityExchangeContainers("ns-a")
	require.NotSame(t, ov1, ov2)
	require.Same(t, ov1, ov1Again)

	// SBOMSyftFiltereds
	sf1 := wrapped.SBOMSyftFiltereds("ns-a")
	sf2 := wrapped.SBOMSyftFiltereds("ns-b")
	sf1Again := wrapped.SBOMSyftFiltereds("ns-a")
	require.NotSame(t, sf1, sf2)
	require.Same(t, sf1, sf1Again)

	// ContainerProfiles
	cp1 := wrapped.ContainerProfiles("ns-a")
	cp2 := wrapped.ContainerProfiles("ns-b")
	cp1Again := wrapped.ContainerProfiles("ns-a")
	require.NotSame(t, cp1, cp2)
	require.Same(t, cp1, cp1Again)
}

func TestAPIServerStore_storeVEX_ignoredMatches(t *testing.T) {
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	testMatch := v1beta1.Match{
		Vulnerability: v1beta1.Vulnerability{
			VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
				ID:         "CVE-TRANSITION-TEST",
				DataSource: "GHSA-TRANSITION-TEST",
			},
			Fix: v1beta1.Fix{
				State:    "fixed",
				Versions: []string{"2.0"},
			},
		},
		Artifact: v1beta1.GrypePackage{
			Name:    "transition-package",
			Version: "1.0",
			PURL:    "pkg:deb/debian/transition-package@1.0",
		},
	}

	// Initially, testMatch is in Matches for both cveManifest and cveManifestFiltered (so it starts as affected)
	cveManifest.Content.Matches = append(cveManifest.Content.Matches, testMatch)
	cveManifestFiltered.Content.Matches = append(cveManifestFiltered.Content.Matches, testMatch)

	a := NewFakeAPIServerStorage("kubescape")

	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	// First StoreVEX call: testMatch should be created with StatusAffected
	err := a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	require.NoError(t, err)

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, vexContainer)

	var foundInitial bool
	for _, stmt := range vexContainer.Spec.Statements {
		if stmt.Vulnerability.Name == "CVE-TRANSITION-TEST" {
			foundInitial = true
			assert.Equal(t, v1beta1.Status(vex.StatusAffected), stmt.Status)
			assert.NotEmpty(t, stmt.ActionStatement)
		}
	}
	assert.True(t, foundInitial, "Initial match should be recorded as affected in VEX document")

	// Now move testMatch from Matches to IgnoredMatches (simulating a SecurityException rule applied)
	var filteredMatches []v1beta1.Match
	for _, m := range cveManifestFiltered.Content.Matches {
		if m.Vulnerability.ID != "CVE-TRANSITION-TEST" {
			filteredMatches = append(filteredMatches, m)
		}
	}
	cveManifestFiltered.Content.Matches = filteredMatches
	cveManifestFiltered.Content.IgnoredMatches = append(cveManifestFiltered.Content.IgnoredMatches, v1beta1.IgnoredMatch{Match: testMatch})
	cveManifest.Content.IgnoredMatches = append(cveManifest.Content.IgnoredMatches, v1beta1.IgnoredMatch{Match: testMatch})

	// Second StoreVEX call: testMatch should transition from affected to not_affected
	err = a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	require.NoError(t, err)

	vexContainerUpdated, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	var foundTransitioned bool
	for _, stmt := range vexContainerUpdated.Spec.Statements {
		if stmt.Vulnerability.Name == "CVE-TRANSITION-TEST" {
			foundTransitioned = true
			assert.Equal(t, v1beta1.Status(vex.StatusNotAffected), stmt.Status)
			assert.Equal(t, v1beta1.Justification(vex.VulnerableCodeNotPresent), stmt.Justification)
			assert.Equal(t, "Vulnerability was ignored by an external VEX document or scanner configuration", stmt.ImpactStatement)
			assert.Empty(t, stmt.ActionStatement, "ActionStatement should be cleared on transition to not_affected")
		}
	}
	assert.True(t, foundTransitioned, "Transitioned match should be updated to not_affected with SecurityException impact statement")
}

// TestStatementHasPURL_MatchesAcrossMultipleProducts is a regression test for #665:
// the dedup/ignore matching in createVEX/updateVEX used to only check
// Products[0].Subcomponents[0], silently missing a match if the target package
// was listed under any other product. Local statements never trigger this today
// (createProductStructForImageAndPackage always builds exactly one product/
// subcomponent), but external VEX statements (Red Hat CSAF, Chainguard OpenVEX)
// can legitimately list several. This constructs a statement with the target
// package as the second subcomponent of the second product, proving the match
// is found regardless of position.
func TestStatementHasPURL_MatchesAcrossMultipleProducts(t *testing.T) {
	products := []v1beta1.Product{
		{
			Component: v1beta1.Component{ID: "pkg:oci/image-one"},
			Subcomponents: []v1beta1.Subcomponent{
				{Component: v1beta1.Component{ID: "pkg:deb/debian/openssl@1.0"}},
			},
		},
		{
			Component: v1beta1.Component{ID: "pkg:oci/image-two"},
			Subcomponents: []v1beta1.Subcomponent{
				{Component: v1beta1.Component{ID: "pkg:deb/debian/nginx@1.0"}},
				{Component: v1beta1.Component{ID: "pkg:deb/debian/curl@7.68"}},
			},
		},
	}

	assert.True(t, statementHasPURL(products, "pkg:deb/debian/curl@7.68"),
		"should find a package even when it is not the first subcomponent of the first product")
	assert.True(t, statementHasPURL(products, "pkg:deb/debian/openssl@1.0"),
		"should still find the first product package")
	assert.False(t, statementHasPURL(products, "pkg:deb/debian/not-present@1.0"),
		"should not match a package that is not present anywhere")
	assert.False(t, statementHasPURL(nil, "pkg:deb/debian/curl@7.68"),
		"should not panic or match on nil products")
}

// TestAPIServerStore_storeVEX_ignoredMatches_multiProductStatement is a regression
// test for #665: the ignored-vulnerability lookup in updateVEX used to only check
// Products[0].Subcomponents[0], so a statement whose target package sits under a
// later product/subcomponent would never be recognized as ignored. This manually
// expands an existing statement to carry an extra leading product before the real
// one, then runs it through the real StoreVEX/updateVEX path (not just the isolated
// helper) and asserts the ignore transition still happens correctly.
func TestAPIServerStore_storeVEX_ignoredMatches_multiProductStatement(t *testing.T) {
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	testMatch := v1beta1.Match{
		Vulnerability: v1beta1.Vulnerability{
			VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
				ID:         "CVE-MULTI-PRODUCT-TEST",
				DataSource: "GHSA-MULTI-PRODUCT-TEST",
			},
			Fix: v1beta1.Fix{
				State:    "fixed",
				Versions: []string{"2.0"},
			},
		},
		Artifact: v1beta1.GrypePackage{
			Name:    "multi-product-package",
			Version: "1.0",
			PURL:    "pkg:deb/debian/multi-product-package@1.0",
		},
	}

	cveManifest.Content.Matches = append(cveManifest.Content.Matches, testMatch)
	cveManifestFiltered.Content.Matches = append(cveManifestFiltered.Content.Matches, testMatch)

	a := NewFakeAPIServerStorage("kubescape")

	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	// First StoreVEX call creates the statement as affected, single-product
	// (this is how production code always creates it today).
	err := a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	require.NoError(t, err)

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	// Manually expand the statement to carry an extra leading product before the
	// real one, simulating what a multi-product external-style statement looks like.
	// This proves the fix works through the real storage round-trip, not just
	// against a hand-built struct in memory.
	for i := range vexContainer.Spec.Statements {
		if vexContainer.Spec.Statements[i].Vulnerability.Name == "CVE-MULTI-PRODUCT-TEST" {
			realProduct := vexContainer.Spec.Statements[i].Products[0]
			decoyProduct := v1beta1.Product{
				Component: v1beta1.Component{ID: "pkg:oci/decoy-image"},
				Subcomponents: []v1beta1.Subcomponent{
					{Component: v1beta1.Component{ID: "pkg:deb/debian/decoy-package@1.0"}},
				},
			}
			vexContainer.Spec.Statements[i].Products = []v1beta1.Product{decoyProduct, realProduct}
		}
	}
	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(context.Background(), vexContainer, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Now move testMatch to IgnoredMatches, simulating a SecurityException rule applied.
	var filteredMatches []v1beta1.Match
	for _, m := range cveManifestFiltered.Content.Matches {
		if m.Vulnerability.ID != "CVE-MULTI-PRODUCT-TEST" {
			filteredMatches = append(filteredMatches, m)
		}
	}
	cveManifestFiltered.Content.Matches = filteredMatches
	cveManifestFiltered.Content.IgnoredMatches = append(cveManifestFiltered.Content.IgnoredMatches, v1beta1.IgnoredMatch{Match: testMatch})
	cveManifest.Content.IgnoredMatches = append(cveManifest.Content.IgnoredMatches, v1beta1.IgnoredMatch{Match: testMatch})

	// Second StoreVEX call: the real updateVEX ignored-lookup must find the real
	// product even though it now sits second, not first.
	err = a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	require.NoError(t, err)

	vexContainerUpdated, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	var foundTransitioned bool
	for _, stmt := range vexContainerUpdated.Spec.Statements {
		if stmt.Vulnerability.Name == "CVE-MULTI-PRODUCT-TEST" {
			foundTransitioned = true
			assert.Equal(t, v1beta1.Status(vex.StatusNotAffected), stmt.Status,
				"statement should transition to not_affected even though its real product is second, not first")
			assert.Equal(t, "Vulnerability was ignored by an external VEX document or scanner configuration", stmt.ImpactStatement,
				"ignore lookup should find the package regardless of product position")
		}
	}
	assert.True(t, foundTransitioned, "multi-product statement should still be found and transitioned")
}

// TestAPIServerStore_storeVEX_dedup_multiProductStatement is a regression test for
// #665: the dedup check in updateVEX (deciding whether a vulnerability is already
// recorded) used to only check Products[0].Subcomponents[0]. This manually expands
// an existing statement to carry an extra leading product before the real one, then
// runs the same match through StoreVEX again and asserts no duplicate statement is
// appended - proving the dedup check finds the existing entry through the real
// updateVEX path, not just the isolated helper.
func TestAPIServerStore_storeVEX_dedup_multiProductStatement(t *testing.T) {
	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	testMatch := v1beta1.Match{
		Vulnerability: v1beta1.Vulnerability{
			VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
				ID:         "CVE-DEDUP-MULTI-PRODUCT-TEST",
				DataSource: "GHSA-DEDUP-MULTI-PRODUCT-TEST",
			},
			Fix: v1beta1.Fix{
				State:    "fixed",
				Versions: []string{"2.0"},
			},
		},
		Artifact: v1beta1.GrypePackage{
			Name:    "dedup-multi-product-package",
			Version: "1.0",
			PURL:    "pkg:deb/debian/dedup-multi-product-package@1.0",
		},
	}

	cveManifest.Content.Matches = append(cveManifest.Content.Matches, testMatch)
	cveManifestFiltered.Content.Matches = append(cveManifestFiltered.Content.Matches, testMatch)

	a := NewFakeAPIServerStorage("kubescape")

	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	// First StoreVEX call creates the statement, single-product (as production code
	// always does today).
	err := a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	require.NoError(t, err)

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	// Manually expand the statement to carry an extra leading decoy product before
	// the real one, simulating a genuine multi-product external-style statement.
	for i := range vexContainer.Spec.Statements {
		if vexContainer.Spec.Statements[i].Vulnerability.Name == "CVE-DEDUP-MULTI-PRODUCT-TEST" {
			realProduct := vexContainer.Spec.Statements[i].Products[0]
			decoyProduct := v1beta1.Product{
				Component: v1beta1.Component{ID: "pkg:oci/dedup-decoy-image"},
				Subcomponents: []v1beta1.Subcomponent{
					{Component: v1beta1.Component{ID: "pkg:deb/debian/dedup-decoy-package@1.0"}},
				},
			}
			vexContainer.Spec.Statements[i].Products = []v1beta1.Product{decoyProduct, realProduct}
		}
	}
	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(context.Background(), vexContainer, metav1.UpdateOptions{})
	require.NoError(t, err)

	countBefore := 0
	for _, s := range vexContainer.Spec.Statements {
		if s.Vulnerability.Name == "CVE-DEDUP-MULTI-PRODUCT-TEST" {
			countBefore++
		}
	}
	require.Equal(t, 1, countBefore, "sanity check: exactly one statement before the second StoreVEX call")

	// Second StoreVEX call: same match, still present (not ignored). The dedup check
	// must recognize the real product even though it now sits second, not first, and
	// must NOT append a duplicate statement.
	err = a.StoreVEX(ctx, cveManifest, cveManifestFiltered, false)
	require.NoError(t, err)

	vexContainerUpdated, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	countAfter := 0
	for _, s := range vexContainerUpdated.Spec.Statements {
		if s.Vulnerability.Name == "CVE-DEDUP-MULTI-PRODUCT-TEST" {
			countAfter++
		}
	}
	assert.Equal(t, 1, countAfter, "dedup check should recognize the existing multi-product statement and not append a duplicate")
}

// TestAPIServerStore_StoreVEX_NilContentDoesNotPanic is a regression test for #518:
// createVEX, updateVEX, and markRelevantVulnerabilitiesAsAffectedInVex used to guard
// CVEManifest.Content inconsistently - some reads were nil-checked, others weren't, within
// the very same function. None of the current callers ever pass a nil Content, but the
// functions themselves had no defense of their own. This exercises both the create path
// (first call, container doesn't exist yet) and the update path (second call, container
// already exists) with a completely empty CVEManifest{} - Content is nil - for both cve and
// cvep, and asserts neither call panics or errors.
func TestAPIServerStore_StoreVEX_NilContentDoesNotPanic(t *testing.T) {
	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.TODO()

	empty := domain.CVEManifest{Name: name}

	require.NotPanics(t, func() {
		err := a.StoreVEX(ctx, empty, empty, false)
		assert.NoError(t, err, "createVEX must handle a nil CVEManifest.Content without erroring")
	})

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Empty(t, vexContainer.Spec.Statements, "no matches were ever provided, so no statements should be generated")

	// Second call with the same (still nil-Content) manifests exercises updateVEX.
	require.NotPanics(t, func() {
		err := a.StoreVEX(ctx, empty, empty, false)
		assert.NoError(t, err, "updateVEX must handle a nil CVEManifest.Content without erroring")
	})

	vexContainerUpdated, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Empty(t, vexContainerUpdated.Spec.Statements, "updateVEX must not fabricate statements out of a nil CVEManifest.Content")
}

// TestAPIServerStore_StoreCVESummary_NilContentDoesNotPanic is a regression test for #524:
// parseSeverities dereferenced cve.Content.Matches unguarded, and cvep.Content.Matches guarded
// only by the caller-supplied withRelevancy bool rather than an actual nil check on
// cvep.Content. StoreCVESummary is part of the public ports.CVERepository interface, so
// nothing enforced that precondition on it. This calls StoreCVESummary directly (not just
// indirectly through scan.go) with a CVEManifest{} - Content is nil - for both cve and cvep,
// in both withRelevancy states, and asserts none of the four combinations panic or error.
func TestAPIServerStore_StoreCVESummary_NilContentDoesNotPanic(t *testing.T) {
	for _, withRelevancy := range []bool{false, true} {
		t.Run(fmt.Sprintf("withRelevancy=%v", withRelevancy), func(t *testing.T) {
			a := NewFakeAPIServerStorage("kubescape")
			ctx := context.TODO()
			workload := domain.ScanCommand{
				Wlid:          "wlid://cluster-x/namespace-y/deployment-z",
				ContainerName: "container",
			}
			ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)
			ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(123456))

			empty := domain.CVEManifest{Name: name}

			require.NotPanics(t, func() {
				err := a.StoreCVESummary(ctx, empty, empty, withRelevancy)
				assert.NoError(t, err, "StoreCVESummary must handle a nil CVEManifest.Content without erroring")
			})

			// Second call with the same (still nil-Content) manifests exercises the
			// RetryOnConflict update path, not just the initial Create.
			require.NotPanics(t, func() {
				err := a.StoreCVESummary(ctx, empty, empty, withRelevancy)
				assert.NoError(t, err, "the update path must also handle a nil CVEManifest.Content without erroring")
			})
		})
	}
}

// TestAPIServerStore_StoreCVESummary_MixedNilContentDoesNotPanic is a regression test for
// CodeRabbit's review on #525: the "both nil" cases above never actually reach the second
// (cvep) loop in parseSeverities when withRelevancy is true and cve.Content is non-nil, which
// is the exact combination that used to panic. This gives cve real match data and leaves
// cvep.Content nil with withRelevancy=true, then reads the stored summary back and asserts
// the real manifest's counts are recorded while the relevant counts stay zero.
func TestAPIServerStore_StoreCVESummary_MixedNilContentDoesNotPanic(t *testing.T) {
	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.TODO()
	workload := domain.ScanCommand{
		Wlid:          "wlid://cluster-x/namespace-y/deployment-z",
		ContainerName: "container",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(123456))

	cve := domain.CVEManifest{
		Name: name,
		Content: &v1beta1.GrypeDocument{
			Matches: []v1beta1.Match{
				{
					Vulnerability: v1beta1.Vulnerability{
						VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
							ID:       "CVE-MIXED-TEST",
							Severity: domain.CriticalSeverity,
						},
					},
				},
			},
		},
	}
	cvep := domain.CVEManifest{Name: name} // Content is nil

	require.NotPanics(t, func() {
		err := a.StoreCVESummary(ctx, cve, cvep, true)
		assert.NoError(t, err, "StoreCVESummary must handle a non-nil cve.Content with a nil cvep.Content under withRelevancy=true")
	})

	resourceName, err := GetCVESummaryK8sResourceNameWithCVEName(ctx, cve.Name)
	require.NoError(t, err)
	namespace, err := GetCVESummaryK8sResourceNamespace(ctx)
	require.NoError(t, err)

	summary, err := a.StorageClient.VulnerabilityManifestSummaries(namespace).Get(ctx, resourceName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), summary.Spec.Severities.Critical.All, "the real cve manifest's match must still be counted")
	assert.Equal(t, int64(0), summary.Spec.Severities.Critical.Relevant, "cvep.Content is nil, so no relevant count should be recorded")
}

// buildLargeCVEManifest synthesizes a CVEManifest with numMatches distinct vulnerability/package
// pairs, used to benchmark updateVEX/createVEX at a scale comparable to a large real-world image.
func buildLargeCVEManifest(numMatches int) domain.CVEManifest {
	matches := make([]v1beta1.Match, 0, numMatches)
	for i := 0; i < numMatches; i++ {
		matches = append(matches, v1beta1.Match{
			Vulnerability: v1beta1.Vulnerability{
				VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
					ID:         fmt.Sprintf("CVE-BENCH-%d", i),
					DataSource: fmt.Sprintf("GHSA-BENCH-%d", i),
				},
			},
			Artifact: v1beta1.GrypePackage{
				Name:    fmt.Sprintf("package-%d", i),
				Version: "1.0",
				PURL:    fmt.Sprintf("pkg:golang/package-%d@1.0", i),
			},
		})
	}
	return domain.CVEManifest{
		Name: name,
		Content: &v1beta1.GrypeDocument{
			Matches: matches,
		},
	}
}

// BenchmarkAPIServerStore_StoreVEX_LargeManifest measures StoreVEX cost on a large manifest
// across the create path (first call) and the update path (second call, which rescans
// existing statements for dedup, reset-to-baseline, and mark-affected/mark-ignored). Run with:
//
//	go test ./repositories/... -run '^$' -bench BenchmarkAPIServerStore_StoreVEX_LargeManifest -benchmem
func BenchmarkAPIServerStore_StoreVEX_LargeManifest(b *testing.B) {
	const numMatches = 5000
	cveManifest := buildLargeCVEManifest(numMatches)
	// Filter to half the matches as "relevant", exercising markRelevantVulnerabilitiesAsAffectedInVex.
	filtered := cveManifest
	filteredContent := *cveManifest.Content
	filteredContent.Matches = append([]v1beta1.Match(nil), cveManifest.Content.Matches[:numMatches/2]...)
	filtered.Content = &filteredContent

	ctx := context.TODO()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		a := NewFakeAPIServerStorage("kubescape")
		if err := a.StoreVEX(ctx, cveManifest, filtered, false); err != nil {
			b.Fatal(err)
		}
		// Second call exercises updateVEX against the already-populated statement set.
		if err := a.StoreVEX(ctx, cveManifest, filtered, false); err != nil {
			b.Fatal(err)
		}
	}
}

func TestStoreVEX_ExternalVEXMasking(t *testing.T) {
	ctx := context.Background()
	namespace := "default"
	store := NewFakeAPIServerStorage(namespace)

	// Simulate a CVE manifest with two ignored matches:
	// 1. Suppressed by a backend-delivered exception policy. Those never go through
	//    buildPolicy, so they carry no sourceKind and the rule buildIgnoreRule writes for
	//    them holds the vulnerability id and nothing else. It is not a Grype-native ignore:
	//    Grype states those against a package, which buildIgnoreRule never sets.
	// 2. Suppressed by a genuine SecurityException
	cveManifest := domain.CVEManifest{
		Name: "deployment-my-app",
		Content: &v1beta1.GrypeDocument{
			IgnoredMatches: []v1beta1.IgnoredMatch{
				{
					Match: v1beta1.Match{
						Vulnerability: v1beta1.Vulnerability{
							VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2023-1234"},
						},
						Artifact: v1beta1.GrypePackage{PURL: "pkg:apk/alpine/curl@8.1.2-r0"},
					},
					AppliedIgnoreRules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-2023-1234"}},
				},
				{
					Match: v1beta1.Match{
						Vulnerability: v1beta1.Vulnerability{
							VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2023-5678"},
						},
						Artifact: v1beta1.GrypePackage{PURL: "pkg:apk/alpine/wget@1.2.3"},
					},
					AppliedIgnoreRules: []v1beta1.IgnoreRule{{
						Vulnerability: "CVE-2023-5678",
						SourceKind:    "SecurityException",
					}},
				},
			},
		},
		Annotations: map[string]string{"kubescape.io/image-id": "docker://alpine@sha256:abcd"},
	}

	err := store.StoreVEX(ctx, cveManifest, cveManifest, false)
	require.NoError(t, err)

	vexContainer, err := store.StorageClient.OpenVulnerabilityExchangeContainers(namespace).Get(ctx, cveManifest.Name, metav1.GetOptions{})
	require.NoError(t, err)

	var foundPolicy, foundCRD bool
	for _, stmt := range vexContainer.Spec.Statements {
		if stmt.Vulnerability.Name == "CVE-2023-1234" {
			foundPolicy = true
			// Still the point of this test: a suppression with no CRD provenance must not
			// be attributed to a SecurityException. It is attributed to the policy that
			// actually made it rather than to an external document.
			assert.Equal(t, cloudExceptionImpactStatement, stmt.ImpactStatement)
			assert.NotEqual(t, securityExceptionImpactStatement, stmt.ImpactStatement)
		} else if stmt.Vulnerability.Name == "CVE-2023-5678" {
			foundCRD = true
			assert.Equal(t, securityExceptionImpactStatement, stmt.ImpactStatement)
		}
	}
	assert.True(t, foundPolicy, "Should have found the exception-policy statement")
	assert.True(t, foundCRD, "Should have found CRD SecurityException statement")
}

func TestCreateProductStructForImageAndPackage(t *testing.T) {
	tests := []struct {
		name          string
		imagePullable string
		packagePURL   string
		wantProductID string
	}{
		{
			name:          "multi-segment image reference with repository",
			imagePullable: "gcr.io/google-samples/microservices-demo/adservice@sha256:45fb8ed886902c0c49e044b1f8870fad61c1022fa23c4943098302a8f1c5b75f",
			packagePURL:   "pkg:golang/github.com/foo/bar@v1.0.0",
			wantProductID: "pkg:oci/adservice@sha256:45fb8ed886902c0c49e044b1f8870fad61c1022fa23c4943098302a8f1c5b75f?repository_url=gcr.io%2Fgoogle-samples%2Fmicroservices-demo",
		},
		{
			name:          "docker:// prefix with repository",
			imagePullable: "docker://docker.io/library/nginx:latest",
			packagePURL:   "pkg:deb/debian/nginx@1.18.0",
			wantProductID: "pkg:oci/nginx:latest?repository_url=docker.io%2Flibrary",
		},
		{
			name:          "single-component image reference without repository",
			imagePullable: "alpine:latest",
			packagePURL:   "pkg:apk/alpine/musl@1.2.2",
			wantProductID: "pkg:oci/alpine:latest",
		},
		{
			name:          "single-component bare name without tag",
			imagePullable: "redis",
			packagePURL:   "pkg:generic/redis@7.0.0",
			wantProductID: "pkg:oci/redis",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			product, err := createProductStructForImageAndPackage(tt.imagePullable, tt.packagePURL)
			require.NoError(t, err)
			require.NotNil(t, product)
			assert.Equal(t, tt.wantProductID, product.Component.ID)
			require.Len(t, product.Subcomponents, 1)
			assert.Equal(t, tt.packagePURL, product.Subcomponents[0].Component.ID)
		})
	}
}

// StoreCVESummary writes a VulnerabilityManifestSummary named for the workload, not for the
// CVE manifest it was built from, so cve.Name and the stored object's name are two different
// strings on any real scan. Three of that function's four log lines used to report cve.Name,
// which named nothing that exists in storage; only the success line reported the object.
// Passing the name once to createOrUpdate is what keeps those from disagreeing.
func TestAPIServerStore_StoreCVESummary_reportsTheSummaryName(t *testing.T) {
	workload := domain.ScanCommand{
		Wlid:          "wlid://cluster-kind/namespace-local-path-storage/deployment-local-path-provisioner",
		ContainerName: "local-path-provisioner",
	}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))

	cve := domain.CVEManifest{Name: "some-image-slug-cve-manifest"}

	summaryName, err := GetCVESummaryK8sResourceNameWithCVEName(ctx, cve.Name)
	require.NoError(t, err)
	// the premise: the two names are not the same string
	require.NotEqual(t, cve.Name, summaryName)

	a := NewFakeAPIServerStorage("kubescape")
	require.NoError(t, a.StoreCVESummary(ctx, cve, domain.CVEManifest{}, false))

	ns, err := GetCVESummaryK8sResourceNamespace(ctx)
	require.NoError(t, err)

	// the object exists under the summary name
	stored, err := a.StorageClient.VulnerabilityManifestSummaries(ns).Get(ctx, summaryName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, summaryName, stored.Name)

	// and nothing was written under the CVE manifest's name
	_, err = a.StorageClient.VulnerabilityManifestSummaries(ns).Get(ctx, cve.Name, metav1.GetOptions{})
	assert.True(t, apierrors.IsNotFound(err), "expected no summary stored under the CVE manifest name, got %v", err)
}

// calculateVexCanonicalHash becomes the document's Metadata.ID, so the same content has to
// render the same hash every time. cstringFromComponent walked Component.Hashes and
// Identifiers with a bare range, and Go randomizes map iteration, so a component carrying
// more than one of either hashed differently between runs and the document changed identity
// for no reason. Statements kubevuln writes itself carry only an ID, so both maps are empty
// today and it never showed; an ingested OpenVEX component routinely carries several.
func TestCalculateVexCanonicalHash_StableAcrossMapOrder(t *testing.T) {
	docFor := func(c v1beta1.Component) v1beta1.VEX {
		return v1beta1.VEX{
			Metadata: v1beta1.Metadata{Timestamp: "2026-08-19T10:00:00Z", Version: 1, Author: "kubescape"},
			Statements: []v1beta1.Statement{{
				Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2021-44228"},
				Status:        "not_affected",
				Products:      []v1beta1.Product{{Component: c}},
			}},
		}
	}
	distinctHashes := func(t *testing.T, c v1beta1.Component) int {
		t.Helper()
		seen := map[string]struct{}{}
		// enough iterations that a randomized order shows up: an unsorted three-entry map
		// produced nine distinct hashes over this many runs
		for i := 0; i < 200; i++ {
			h, err := calculateVexCanonicalHash(docFor(c))
			require.NoError(t, err)
			seen[h] = struct{}{}
		}
		return len(seen)
	}

	t.Run("component with several identifiers and hashes", func(t *testing.T) {
		c := v1beta1.Component{
			ID: "pkg:oci/nginx",
			Identifiers: map[v1beta1.IdentifierType]string{
				"purl":  "pkg:oci/nginx",
				"cpe22": "cpe:/a:nginx:nginx",
				"cpe23": "cpe:2.3:a:nginx:nginx",
			},
			Hashes: map[v1beta1.Algorithm]v1beta1.Hash{
				"sha256": "aaa",
				"sha512": "bbb",
				"md5":    "ccc",
			},
		}
		assert.Equal(t, 1, distinctHashes(t, c), "the same component must canonicalize to one hash")
	})

	t.Run("component carrying only an ID, as kubevuln writes today", func(t *testing.T) {
		assert.Equal(t, 1, distinctHashes(t, v1beta1.Component{ID: "pkg:oci/nginx"}),
			"the shape already in use must hash exactly as it did before")
	})
}

// The enrich helpers take the caller's own manifest maps. They used to alias them and write
// through, so a CVE manifest came back from StoreCVESummary carrying summary annotations and
// labels it never had: eight labels where it passed one. applyExceptionsToManifest already
// clones for this reason; these did not.
func TestEnrichSummaryManifestObject_DoesNotMutateCaller(t *testing.T) {
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:          "wlid://cluster-a/namespace-b/deployment-c",
		ContainerName: "app",
	})
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1))

	annotations := map[string]string{"mine": "keep"}
	labels := map[string]string{"mine": "keep"}

	gotAnnotations, err := enrichSummaryManifestObjectAnnotations(ctx, annotations)
	require.NoError(t, err)
	gotLabels, err := enrichSummaryManifestObjectLabels(ctx, labels, true)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"mine": "keep"}, annotations, "caller's annotations must be untouched")
	assert.Equal(t, map[string]string{"mine": "keep"}, labels, "caller's labels must be untouched")

	// and the returned maps still carry both the caller's entries and the added ones
	assert.Equal(t, "keep", gotAnnotations["mine"])
	assert.Equal(t, "keep", gotLabels["mine"])
	assert.Equal(t, helpersv1.ContextMetadataKeyFiltered, gotLabels[helpersv1.ContextMetadataKey])
	assert.Equal(t, "deployment", gotLabels[helpersv1.RelatedKindMetadataKey])
	assert.NotEmpty(t, gotAnnotations[helpersv1.WlidMetadataKey])
}

// A nil map in still gives a usable map out, which is what the nil checks used to provide.
func TestEnrichSummaryManifestObject_HandlesNilMaps(t *testing.T) {
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid: "wlid://cluster-a/namespace-b/deployment-c",
	})
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1))

	gotAnnotations, err := enrichSummaryManifestObjectAnnotations(ctx, nil)
	require.NoError(t, err)
	assert.NotNil(t, gotAnnotations)

	gotLabels, err := enrichSummaryManifestObjectLabels(ctx, nil, false)
	require.NoError(t, err)
	assert.NotNil(t, gotLabels)
	assert.Equal(t, helpersv1.ContextMetadataKeyNonFiltered, gotLabels[helpersv1.ContextMetadataKey])
}

func TestCalculateVexCanonicalHash_DeterministicWithMultipleHashesAndIdentifiers(t *testing.T) {
	doc := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "kubescape.io",
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{ID: "https://nvd.nist.gov", Name: "CVE-2023-1234"},
				Status:        v1beta1.Status("not_affected"),
				Products: []v1beta1.Product{
					{
						Component: v1beta1.Component{
							ID: "pkg:deb/debian/libssl3@3.0.11",
							Hashes: map[v1beta1.Algorithm]v1beta1.Hash{
								"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
								"sha1":   "1234567890abcdef1234567890abcdef12345678",
								"md5":    "0123456789abcdef0123456789abcdef",
							},
							Identifiers: map[v1beta1.IdentifierType]string{
								"purl":  "pkg:deb/debian/libssl3@3.0.11",
								"cpe23": "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*",
								"cpe22": "cpe:/a:openssl:openssl:3.0.11",
							},
						},
					},
				},
			},
		},
	}

	firstHash, err := calculateVexCanonicalHash(doc)
	require.NoError(t, err)
	require.NotEmpty(t, firstHash)

	for i := 0; i < 50; i++ {
		h, err := calculateVexCanonicalHash(doc)
		require.NoError(t, err)
		assert.Equal(t, firstHash, h, "run %d gave different hash", i)
	}
}

func TestCalculateVexCanonicalHash_AliasCollision(t *testing.T) {
	docWithAlias := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "kubescape.io",
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{
					ID:      "https://nvd.nist.gov",
					Name:    "CVE-2023-1",
					Aliases: []string{"000"},
				},
				Status: v1beta1.Status("not_affected"),
			},
		},
	}

	docWithoutAlias := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "kubescape.io",
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{
					ID:   "https://nvd.nist.gov",
					Name: "CVE-2023-1000",
				},
				Status: v1beta1.Status("not_affected"),
			},
		},
	}

	hashWithAlias, err := calculateVexCanonicalHash(docWithAlias)
	require.NoError(t, err)
	hashWithoutAlias, err := calculateVexCanonicalHash(docWithoutAlias)
	require.NoError(t, err)

	assert.NotEqual(t, hashWithAlias, hashWithoutAlias, "CVE-2023-1 with alias 000 should not collide with CVE-2023-1000")

	// Colon-containing alias should not collide with multiple split aliases
	docWithColonAlias := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "kubescape.io",
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{
					ID:      "https://nvd.nist.gov",
					Name:    "CVE-2023-1234",
					Aliases: []string{"A:B"},
				},
				Status: v1beta1.Status("not_affected"),
			},
		},
	}

	docWithSplitAliases := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "kubescape.io",
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{
					ID:      "https://nvd.nist.gov",
					Name:    "CVE-2023-1234",
					Aliases: []string{"A", "B"},
				},
				Status: v1beta1.Status("not_affected"),
			},
		},
	}

	hashWithColonAlias, err := calculateVexCanonicalHash(docWithColonAlias)
	require.NoError(t, err)
	hashWithSplitAliases, err := calculateVexCanonicalHash(docWithSplitAliases)
	require.NoError(t, err)

	assert.NotEqual(t, hashWithColonAlias, hashWithSplitAliases, "alias 'A:B' should not collide with aliases 'A' and 'B'")
}

func TestCalculateVexCanonicalHash_ComponentFieldCollision(t *testing.T) {
	docWithIDIncludingSuffix := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
			Author:    "kubescape.io",
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
				Status:        v1beta1.Status("not_affected"),
				Products: []v1beta1.Product{
					{
						Component: v1beta1.Component{
							ID: "pkg:oci/nginx:h:6:sha256:4:1234",
						},
					},
				},
			},
		},
	}

	docWithHashes := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
			Author:    "kubescape.io",
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
				Status:        v1beta1.Status("not_affected"),
				Products: []v1beta1.Product{
					{
						Component: v1beta1.Component{
							ID: "pkg:oci/nginx",
							Hashes: map[v1beta1.Algorithm]v1beta1.Hash{
								"sha256": "1234",
							},
						},
					},
				},
			},
		},
	}

	docWithIdentifiers := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
			Author:    "kubescape.io",
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
				Status:        v1beta1.Status("not_affected"),
				Products: []v1beta1.Product{
					{
						Component: v1beta1.Component{
							ID: "pkg:oci/nginx",
							Identifiers: map[v1beta1.IdentifierType]string{
								"sha256": "1234",
							},
						},
					},
				},
			},
		},
	}

	hID, err := calculateVexCanonicalHash(docWithIDIncludingSuffix)
	require.NoError(t, err)
	hHashes, err := calculateVexCanonicalHash(docWithHashes)
	require.NoError(t, err)
	hIdentifiers, err := calculateVexCanonicalHash(docWithIdentifiers)
	require.NoError(t, err)

	assert.NotEqual(t, hID, hHashes, "component ID containing hash-like suffix should not collide with component carrying Hashes")
	assert.NotEqual(t, hHashes, hIdentifiers, "component carrying Hashes should not collide with component carrying Identifiers with same key/value")
}

func TestCalculateVexCanonicalHash_AliasOrderIndependent(t *testing.T) {
	doc1 := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "kubescape.io",
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{
					ID:      "https://nvd.nist.gov",
					Name:    "CVE-2023-1234",
					Aliases: []string{"GHSA-1111", "RHSA-2222"},
				},
				Status: v1beta1.Status("not_affected"),
			},
		},
	}

	doc2 := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "kubescape.io",
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{
					ID:      "https://nvd.nist.gov",
					Name:    "CVE-2023-1234",
					Aliases: []string{"RHSA-2222", "GHSA-1111"},
				},
				Status: v1beta1.Status("not_affected"),
			},
		},
	}

	hash1, err := calculateVexCanonicalHash(doc1)
	require.NoError(t, err)
	hash2, err := calculateVexCanonicalHash(doc2)
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2, "different alias order should produce the same hash")
}

func TestCalculateVexCanonicalHash_StatementOrderIndependence(t *testing.T) {
	stmtA := v1beta1.Statement{
		ID:            "https://kubescape.io/vex/statement/CVE-2023-1234/pkg%3Adeb%2Fdebian%2Flibssl3%403.0.11",
		Vulnerability: v1beta1.VexVulnerability{ID: "https://nvd.nist.gov", Name: "CVE-2023-1234"},
		Status:        v1beta1.Status("not_affected"),
		Justification: v1beta1.Justification("vulnerable_code_not_present"),
		Products: []v1beta1.Product{
			{
				Component: v1beta1.Component{ID: "pkg:oci/test-image"},
				Subcomponents: []v1beta1.Subcomponent{
					{Component: v1beta1.Component{ID: "pkg:deb/debian/libssl3@3.0.11"}},
				},
			},
		},
	}

	stmtB := v1beta1.Statement{
		ID:            "https://kubescape.io/vex/statement/CVE-2023-1234/pkg%3Adeb%2Fdebian%2Fopenssl%403.0.11",
		Vulnerability: v1beta1.VexVulnerability{ID: "https://nvd.nist.gov", Name: "CVE-2023-1234"},
		Status:        v1beta1.Status("not_affected"),
		Justification: v1beta1.Justification("vulnerable_code_not_present"),
		Products: []v1beta1.Product{
			{
				Component: v1beta1.Component{ID: "pkg:oci/test-image"},
				Subcomponents: []v1beta1.Subcomponent{
					{Component: v1beta1.Component{ID: "pkg:deb/debian/openssl@3.0.11"}},
				},
			},
		},
	}

	stmtC := v1beta1.Statement{
		ID:            "https://kubescape.io/vex/statement/CVE-2023-9999/pkg%3Adeb%2Fdebian%2Fcurl%407.88.1",
		Vulnerability: v1beta1.VexVulnerability{ID: "https://nvd.nist.gov", Name: "CVE-2023-9999"},
		Status:        v1beta1.Status("affected"),
		Products: []v1beta1.Product{
			{
				Component: v1beta1.Component{ID: "pkg:oci/test-image"},
				Subcomponents: []v1beta1.Subcomponent{
					{Component: v1beta1.Component{ID: "pkg:deb/debian/curl@7.88.1"}},
				},
			},
		},
	}

	docOrder1 := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "kubescape.io",
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
		},
		Statements: []v1beta1.Statement{stmtA, stmtB, stmtC},
	}

	docOrder2 := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "kubescape.io",
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
		},
		Statements: []v1beta1.Statement{stmtC, stmtB, stmtA},
	}

	docOrder3 := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "kubescape.io",
			Timestamp: "2026-01-01T00:00:00Z",
			Version:   1,
		},
		Statements: []v1beta1.Statement{stmtB, stmtA, stmtC},
	}

	h1, err := calculateVexCanonicalHash(docOrder1)
	require.NoError(t, err)
	h2, err := calculateVexCanonicalHash(docOrder2)
	require.NoError(t, err)
	h3, err := calculateVexCanonicalHash(docOrder3)
	require.NoError(t, err)

	assert.Equal(t, h1, h2, "statement order should not affect canonical hash (order 1 vs order 2)")
	assert.Equal(t, h1, h3, "statement order should not affect canonical hash (order 1 vs order 3)")
}

func TestCalculateVexCanonicalHash_DoesNotMutateCallerSlice(t *testing.T) {
	stmtZ := v1beta1.Statement{
		Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-9999"},
		ID:            "stmt-z",
	}
	stmtA := v1beta1.Statement{
		Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-0001"},
		ID:            "stmt-a",
	}

	statements := []v1beta1.Statement{stmtZ, stmtA}
	doc := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Timestamp: "2026-01-01T00:00:00Z",
		},
		Statements: statements,
	}

	_, err := calculateVexCanonicalHash(doc)
	require.NoError(t, err)

	assert.Equal(t, "stmt-z", doc.Statements[0].ID, "calculateVexCanonicalHash must not mutate caller's slice order")
	assert.Equal(t, "stmt-a", doc.Statements[1].ID, "calculateVexCanonicalHash must not mutate caller's slice order")
}

func TestCstringFromComponent_SortedKeys(t *testing.T) {
	c := v1beta1.Component{
		ID: "pkg:deb/debian/libssl3@3.0.11",
		Hashes: map[v1beta1.Algorithm]v1beta1.Hash{
			"sha256": "hash256",
			"sha1":   "hash1",
			"md5":    "hashmd5",
		},
		Identifiers: map[v1beta1.IdentifierType]string{
			"purl":  "pkg:deb/debian/libssl3@3.0.11",
			"cpe23": "cpe23value",
			"cpe22": "cpe22value",
		},
	}

	expected := ":29:pkg:deb/debian/libssl3@3.0.11:h:3:md5:7:hashmd5:h:4:sha1:5:hash1:h:6:sha256:7:hash256:i:5:cpe22:10:cpe22value:i:5:cpe23:10:cpe23value:i:4:purl:29:pkg:deb/debian/libssl3@3.0.11"
	for i := 0; i < 20; i++ {
		got := cstringFromComponent(c)
		assert.Equal(t, expected, got)
	}
}

func TestCstringFromComponent_FieldCollision(t *testing.T) {
	c1 := v1beta1.Component{
		ID: "pkg:oci/nginx:h:6:sha256:4:1234",
	}
	c2 := v1beta1.Component{
		ID: "pkg:oci/nginx",
		Hashes: map[v1beta1.Algorithm]v1beta1.Hash{
			"sha256": "1234",
		},
	}
	c3 := v1beta1.Component{
		ID: "pkg:oci/nginx",
		Identifiers: map[v1beta1.IdentifierType]string{
			"sha256": "1234",
		},
	}

	assert.NotEqual(t, cstringFromComponent(c1), cstringFromComponent(c2), "ID with serialized suffix must not collide with Hashes")
	assert.NotEqual(t, cstringFromComponent(c2), cstringFromComponent(c3), "Hashes must not collide with Identifiers having same key/value")
}

func TestCstringFromVulnerability(t *testing.T) {
	tests := []struct {
		name     string
		vuln     v1beta1.VexVulnerability
		expected string
	}{
		{
			name: "no aliases",
			vuln: v1beta1.VexVulnerability{
				ID:   "https://nvd.nist.gov",
				Name: "CVE-2023-1234",
			},
			expected: ":20:https://nvd.nist.gov:13:CVE-2023-1234",
		},
		{
			name: "single alias",
			vuln: v1beta1.VexVulnerability{
				ID:      "https://nvd.nist.gov",
				Name:    "CVE-2023-1",
				Aliases: []string{"000"},
			},
			expected: ":20:https://nvd.nist.gov:10:CVE-2023-1:3:000",
		},
		{
			name: "multiple aliases sorted",
			vuln: v1beta1.VexVulnerability{
				ID:      "https://nvd.nist.gov",
				Name:    "CVE-2023-1234",
				Aliases: []string{"RHSA-2", "GHSA-1", "ALAS-3"},
			},
			expected: ":20:https://nvd.nist.gov:13:CVE-2023-1234:6:ALAS-3:6:GHSA-1:6:RHSA-2",
		},
		{
			name: "colon-containing alias",
			vuln: v1beta1.VexVulnerability{
				ID:      "https://nvd.nist.gov",
				Name:    "CVE-2023-1234",
				Aliases: []string{"A:B"},
			},
			expected: ":20:https://nvd.nist.gov:13:CVE-2023-1234:3:A:B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cstringFromVulnerability(tt.vuln)
			assert.Equal(t, tt.expected, got)
		})
	}

	// Distinct alias list test
	vSplit := v1beta1.VexVulnerability{
		ID:      "https://nvd.nist.gov",
		Name:    "CVE-2023-1234",
		Aliases: []string{"A", "B"},
	}
	vColon := v1beta1.VexVulnerability{
		ID:      "https://nvd.nist.gov",
		Name:    "CVE-2023-1234",
		Aliases: []string{"A:B"},
	}
	assert.NotEqual(t, cstringFromVulnerability(vSplit), cstringFromVulnerability(vColon))
}

func TestSortVexStatements_TieBreakers(t *testing.T) {
	docTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("tie breaker on status", func(t *testing.T) {
		stmtAffected := v1beta1.Statement{
			Vulnerability: v1beta1.VexVulnerability{ID: "src", Name: "CVE-2023-1000"},
			Status:        v1beta1.Status("affected"),
			ID:            "stmt-1",
		}
		stmtNotAffected := v1beta1.Statement{
			Vulnerability: v1beta1.VexVulnerability{ID: "src", Name: "CVE-2023-1000"},
			Status:        v1beta1.Status("not_affected"),
			ID:            "stmt-2",
		}

		stmts := []v1beta1.Statement{stmtNotAffected, stmtAffected}
		sortVexStatements(stmts, docTime)

		assert.Equal(t, "affected", string(stmts[0].Status))
		assert.Equal(t, "not_affected", string(stmts[1].Status))
	})

	t.Run("tie breaker on justification", func(t *testing.T) {
		stmtA := v1beta1.Statement{
			Vulnerability: v1beta1.VexVulnerability{ID: "src", Name: "CVE-2023-1000"},
			Status:        v1beta1.Status("not_affected"),
			Justification: v1beta1.Justification("component_not_present"),
			ID:            "stmt-1",
		}
		stmtB := v1beta1.Statement{
			Vulnerability: v1beta1.VexVulnerability{ID: "src", Name: "CVE-2023-1000"},
			Status:        v1beta1.Status("not_affected"),
			Justification: v1beta1.Justification("vulnerable_code_not_present"),
			ID:            "stmt-2",
		}

		stmts := []v1beta1.Statement{stmtB, stmtA}
		sortVexStatements(stmts, docTime)

		assert.Equal(t, "component_not_present", string(stmts[0].Justification))
		assert.Equal(t, "vulnerable_code_not_present", string(stmts[1].Justification))
	})

	t.Run("tie breaker on products", func(t *testing.T) {
		stmtA := v1beta1.Statement{
			Vulnerability: v1beta1.VexVulnerability{ID: "src", Name: "CVE-2023-1000"},
			Status:        v1beta1.Status("not_affected"),
			Products: []v1beta1.Product{
				{Component: v1beta1.Component{ID: "pkg:oci/image-alpha"}},
			},
		}
		stmtB := v1beta1.Statement{
			Vulnerability: v1beta1.VexVulnerability{ID: "src", Name: "CVE-2023-1000"},
			Status:        v1beta1.Status("not_affected"),
			Products: []v1beta1.Product{
				{Component: v1beta1.Component{ID: "pkg:oci/image-bravo"}},
			},
		}

		stmts := []v1beta1.Statement{stmtB, stmtA}
		sortVexStatements(stmts, docTime)

		assert.Equal(t, "pkg:oci/image-alpha", stmts[0].Products[0].Component.ID)
		assert.Equal(t, "pkg:oci/image-bravo", stmts[1].Products[0].Component.ID)
	})

	t.Run("tie breaker on statement ID", func(t *testing.T) {
		stmtA := v1beta1.Statement{
			Vulnerability: v1beta1.VexVulnerability{ID: "src", Name: "CVE-2023-1000"},
			Status:        v1beta1.Status("not_affected"),
			ID:            "https://kubescape.io/vex/statement/aaa",
		}
		stmtB := v1beta1.Statement{
			Vulnerability: v1beta1.VexVulnerability{ID: "src", Name: "CVE-2023-1000"},
			Status:        v1beta1.Status("not_affected"),
			ID:            "https://kubescape.io/vex/statement/bbb",
		}

		stmts := []v1beta1.Statement{stmtB, stmtA}
		sortVexStatements(stmts, docTime)

		assert.Equal(t, "https://kubescape.io/vex/statement/aaa", stmts[0].ID)
		assert.Equal(t, "https://kubescape.io/vex/statement/bbb", stmts[1].ID)
	})
}

func TestCalculateVexCanonicalHash_SubcomponentOrderIndependent(t *testing.T) {
	doc1 := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Timestamp: "2026-01-01T00:00:00Z",
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
				Products: []v1beta1.Product{
					{
						Component: v1beta1.Component{ID: "pkg:oci/image"},
						Subcomponents: []v1beta1.Subcomponent{
							{Component: v1beta1.Component{ID: "pkg:deb/debian/libssl3@3.0.11"}},
							{Component: v1beta1.Component{ID: "pkg:deb/debian/curl@7.88.1"}},
						},
					},
				},
			},
		},
	}

	doc2 := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Timestamp: "2026-01-01T00:00:00Z",
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
				Products: []v1beta1.Product{
					{
						Component: v1beta1.Component{ID: "pkg:oci/image"},
						Subcomponents: []v1beta1.Subcomponent{
							{Component: v1beta1.Component{ID: "pkg:deb/debian/curl@7.88.1"}},
							{Component: v1beta1.Component{ID: "pkg:deb/debian/libssl3@3.0.11"}},
						},
					},
				},
			},
		},
	}

	h1, err := calculateVexCanonicalHash(doc1)
	require.NoError(t, err)
	h2, err := calculateVexCanonicalHash(doc2)
	require.NoError(t, err)

	assert.Equal(t, h1, h2, "subcomponent order within a product should not affect the canonical hash")
}

func TestCalculateVexCanonicalHash_ZeroRFC3339StatementTimestamp(t *testing.T) {
	docWithZeroStmtTime := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Timestamp: "2026-01-01T00:00:00Z",
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
				Timestamp:     "0001-01-01T00:00:00Z",
			},
		},
	}

	docWithDocStmtTime := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Timestamp: "2026-01-01T00:00:00Z",
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
				Timestamp:     "2026-01-01T00:00:00Z",
			},
		},
	}

	docWithEmptyStmtTime := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Timestamp: "2026-01-01T00:00:00Z",
		},
		Statements: []v1beta1.Statement{
			{
				Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
				Timestamp:     "",
			},
		},
	}

	hZero, err := calculateVexCanonicalHash(docWithZeroStmtTime)
	require.NoError(t, err)

	hDocTime, err := calculateVexCanonicalHash(docWithDocStmtTime)
	require.NoError(t, err)

	hEmpty, err := calculateVexCanonicalHash(docWithEmptyStmtTime)
	require.NoError(t, err)

	assert.NotEqual(t, hDocTime, hZero, "zero RFC3339 timestamp should be preserved and not overwritten by document timestamp")
	assert.Equal(t, hDocTime, hEmpty, "empty statement timestamp should fall back to document timestamp")
}

func TestSortVexStatements_ZeroRFC3339Timestamp(t *testing.T) {
	docTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	stmtZero := v1beta1.Statement{
		Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1000"},
		Timestamp:     "0001-01-01T00:00:00Z",
		ID:            "stmt-zero",
	}

	stmtLater := v1beta1.Statement{
		Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1000"},
		Timestamp:     "2026-01-01T00:00:00Z",
		ID:            "stmt-later",
	}

	stmts := []v1beta1.Statement{stmtLater, stmtZero}
	sortVexStatements(stmts, docTime)

	assert.Equal(t, "stmt-zero", stmts[0].ID, "zero RFC3339 timestamp should sort before 2026 timestamp")
	assert.Equal(t, "stmt-later", stmts[1].ID)
}

func TestCalculateVexCanonicalHash_FractionalTimestamp(t *testing.T) {
	t.Run("differing fractional document timestamps produce distinct hashes", func(t *testing.T) {
		doc1 := v1beta1.VEX{
			Metadata: v1beta1.Metadata{
				Timestamp: "2026-01-01T00:00:00.100Z",
			},
			Statements: []v1beta1.Statement{
				{Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"}},
			},
		}
		doc2 := v1beta1.VEX{
			Metadata: v1beta1.Metadata{
				Timestamp: "2026-01-01T00:00:00.200Z",
			},
			Statements: []v1beta1.Statement{
				{Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"}},
			},
		}

		h1, err := calculateVexCanonicalHash(doc1)
		require.NoError(t, err)
		h2, err := calculateVexCanonicalHash(doc2)
		require.NoError(t, err)

		assert.NotEqual(t, h1, h2, "distinct fractional document timestamps must produce distinct canonical hashes")
	})

	t.Run("differing fractional statement timestamps produce distinct hashes", func(t *testing.T) {
		doc1 := v1beta1.VEX{
			Metadata: v1beta1.Metadata{
				Timestamp: "2026-01-01T00:00:00Z",
			},
			Statements: []v1beta1.Statement{
				{
					Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
					Timestamp:     "2026-01-01T00:00:00.123456Z",
				},
			},
		}
		doc2 := v1beta1.VEX{
			Metadata: v1beta1.Metadata{
				Timestamp: "2026-01-01T00:00:00Z",
			},
			Statements: []v1beta1.Statement{
				{
					Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
					Timestamp:     "2026-01-01T00:00:00.654321Z",
				},
			},
		}

		h1, err := calculateVexCanonicalHash(doc1)
		require.NoError(t, err)
		h2, err := calculateVexCanonicalHash(doc2)
		require.NoError(t, err)

		assert.NotEqual(t, h1, h2, "distinct fractional statement timestamps must produce distinct canonical hashes")
	})

	t.Run("equivalent UTC timestamps with different timezone offsets produce same hash", func(t *testing.T) {
		doc1 := v1beta1.VEX{
			Metadata: v1beta1.Metadata{
				Timestamp: "2026-01-01T01:00:00+01:00",
			},
			Statements: []v1beta1.Statement{
				{
					Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
					Timestamp:     "2026-01-01T02:30:00+02:30",
				},
			},
		}
		doc2 := v1beta1.VEX{
			Metadata: v1beta1.Metadata{
				Timestamp: "2026-01-01T00:00:00Z",
			},
			Statements: []v1beta1.Statement{
				{
					Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1234"},
					Timestamp:     "2026-01-01T00:00:00Z",
				},
			},
		}

		h1, err := calculateVexCanonicalHash(doc1)
		require.NoError(t, err)
		h2, err := calculateVexCanonicalHash(doc2)
		require.NoError(t, err)

		assert.Equal(t, h1, h2, "equivalent timestamps with different timezone offsets must produce the same canonical hash")
	})
}

func TestSortVexStatements_FractionalTimestamp(t *testing.T) {
	docTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	stmtEarlier := v1beta1.Statement{
		Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1000"},
		Timestamp:     "2026-01-01T00:00:00.100Z",
		ID:            "stmt-earlier",
	}

	stmtLater := v1beta1.Statement{
		Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-1000"},
		Timestamp:     "2026-01-01T00:00:00.200Z",
		ID:            "stmt-later",
	}

	stmts := []v1beta1.Statement{stmtLater, stmtEarlier}
	sortVexStatements(stmts, docTime)

	assert.Equal(t, "stmt-earlier", stmts[0].ID, "earlier fractional timestamp should sort first")
	assert.Equal(t, "stmt-later", stmts[1].ID)
}

// A SecurityException that fails to convert is dropped from the list. That leaves the set
// incomplete in exactly the way a failed List() does, and the caller decides whether a
// suppression that is missing means "deleted" from that flag alone: with the set reported
// complete, reconcileCachedCVE persists the removals and republishes VEX from a set quietly
// short an entry. Caching it would pin that for the TTL, against GetSecurityExceptions' own
// documented property that a failure is never cached.
func TestAPIServerStore_GetSecurityExceptions_ConversionFailureDegrades(t *testing.T) {
	good := map[string]interface{}{
		"apiVersion": "kubescape.io/v1beta1",
		"kind":       "SecurityException",
		"metadata":   map[string]interface{}{"name": "good", "namespace": "kubescape"},
		"spec":       map[string]interface{}{"vulnerabilities": []interface{}{}},
	}
	// spec.vulnerabilities is a list on the typed struct, so a string here fails conversion
	bad := map[string]interface{}{
		"apiVersion": "kubescape.io/v1beta1",
		"kind":       "SecurityException",
		"metadata":   map[string]interface{}{"name": "bad", "namespace": "kubescape"},
		"spec":       map[string]interface{}{"vulnerabilities": "not-a-list"},
	}

	var listCalls int32
	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		securityExceptionGVR:        "SecurityExceptionList",
		clusterSecurityExceptionGVR: "ClusterSecurityExceptionList",
	})
	dynClient.PrependReactor("list", "securityexceptions", func(k8stesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(&listCalls, 1)
		return true, &unstructured.UnstructuredList{
			Object: map[string]interface{}{"apiVersion": "kubescape.io/v1beta1", "kind": "SecurityExceptionList"},
			Items:  []unstructured.Unstructured{{Object: good}, {Object: bad}},
		}, nil
	})
	a := &APIServerStore{
		DynamicClient:              dynClient,
		Namespace:                  "kubescape",
		securityExceptionListCache: cache.New(securityExceptionListCacheCleaningInterval),
	}

	got, _, err := a.GetSecurityExceptions(context.TODO(), "kubescape")
	require.Error(t, err, "a dropped exception leaves the set incomplete and must be reported")

	// the ones that did convert are still applied, the same as a partial result from a
	// failed List(): losing them too would drop working suppressions as well
	require.Len(t, got, 1)
	assert.Equal(t, "good", got[0].Name)

	// and nothing was cached, so the next call re-lists rather than serving the short set
	_, _, err = a.GetSecurityExceptions(context.TODO(), "kubescape")
	require.Error(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&listCalls),
		"an incomplete list must not be cached; the second call has to go back to the apiserver")
}
