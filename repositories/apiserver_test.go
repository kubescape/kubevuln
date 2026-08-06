package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
		name          string
		args          args
		sbom          domain.SBOM
		wantErr       error
		wantEmptySBOM bool
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
		},
		{
			"SBOMCreatorVersion mismatch",
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

	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}

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
	}

	for i := range tests {
		ctx = context.WithValue(ctx, domain.WorkloadKey{}, tests[i].workload)
		enrichedLabels, err := enrichSummaryManifestObjectLabels(ctx, tests[i].labels, true)
		assert.Equal(t, err, nil)

		val, exist := enrichedLabels[helpersv1.ApiGroupMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].k8sResourceGroup)

		val, exist = enrichedLabels[helpersv1.ApiVersionMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].k8sResourceVersion)

		val, exist = enrichedLabels[helpersv1.RelatedKindMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].k8sResourceType)

		val, exist = enrichedLabels[helpersv1.RelatedNameMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].k8sResourceName)

		val, exist = enrichedLabels[helpersv1.RelatedNamespaceMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].k8sResourceNamespace)

		val, exist = enrichedLabels[helpersv1.ContainerNameMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].workload.ContainerName)
	}

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

		val, exist = enrichedAnnotations["kubescape.io/timestamp"]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, "1734957372")
	}

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
	clientset := fake.NewSimpleClientset(seeded)
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}

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
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("get", "vulnerabilitymanifests", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	_, err := a.GetCVE(context.TODO(), name, "", "", "")
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_GetSBOM_transientError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("get", "sbomsyfts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	_, err := a.GetSBOM(context.TODO(), name, "")
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreCVE_transientError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "vulnerabilitymanifests", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	err := a.StoreCVE(context.TODO(), domain.CVEManifest{Name: name}, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreSBOM_transientError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "sbomsyfts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	err := a.StoreSBOM(context.TODO(), domain.SBOM{Name: name}, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreSBOMFiltered_transientError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "sbomsyftfiltereds", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	err := a.StoreSBOM(context.TODO(), domain.SBOM{Name: name}, true)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreCVESummary_transientError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
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
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "vulnerabilitymanifests", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "vulnerabilitymanifests"}, name)
	})
	clientset.PrependReactor("get", "vulnerabilitymanifests", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	err := a.StoreCVE(context.TODO(), domain.CVEManifest{Name: name}, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreSBOM_updateGetFailure_transientError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "sbomsyfts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "sbomsyfts"}, name)
	})
	clientset.PrependReactor("get", "sbomsyfts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	err := a.StoreSBOM(context.TODO(), domain.SBOM{Name: name}, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreSBOMFiltered_updateGetFailure_transientError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "sbomsyftfiltereds", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "sbomsyftfiltereds"}, name)
	})
	clientset.PrependReactor("get", "sbomsyftfiltereds", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	err := a.StoreSBOM(context.TODO(), domain.SBOM{Name: name}, true)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreCVESummary_updateGetFailure_transientError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "vulnerabilitymanifestsummaries"}, name)
	})
	clientset.PrependReactor("get", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
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
	clientset := fake.NewSimpleClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "vulnerabilitymanifests", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "vulnerabilitymanifests"}, name, fmt.Errorf("conflict"))
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
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
	clientset := fake.NewSimpleClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "sbomsyfts", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "sbomsyfts"}, name, fmt.Errorf("conflict"))
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
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
	clientset := fake.NewSimpleClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "sbomsyftfiltereds", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "sbomsyftfiltereds"}, name, fmt.Errorf("conflict"))
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
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
	clientset := fake.NewSimpleClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "vulnerabilitymanifestsummaries"}, resourceName, fmt.Errorf("conflict"))
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
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

	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
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
	clientset := fake.NewSimpleClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "vulnerabilitymanifestsummaries"}, resourceName, fmt.Errorf("conflict"))
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	err = a.StoreCVESummaryStub(ctx, helpersv1.UnsupportedSchema)
	require.True(t, apierrors.IsConflict(err))
	require.Equal(t, retry.DefaultRetry.Steps, updateCalls)
}

func TestAPIServerStore_StoreVEX_transientError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("create", "openvulnerabilityexchangecontainers", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	cve := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}
	err := a.StoreVEX(context.TODO(), cve, cve, false)
	require.ErrorIs(t, err, injectedErr)
}

func TestAPIServerStore_StoreVEX_updateGetFailure_transientError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
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
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
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
	clientset := fake.NewSimpleClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "openvulnerabilityexchangecontainers", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "openvulnerabilityexchangecontainers"}, name, fmt.Errorf("conflict"))
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	cve := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}
	err := a.StoreVEX(context.TODO(), cve, cve, false)
	require.True(t, apierrors.IsConflict(err))
	require.Equal(t, retry.DefaultRetry.Steps, updateCalls)
}

// TestAPIServerStore_StoreVEX_concurrentCreateRace guards against a regression where a
// caller whose Create lost the race (another writer created the container between this
// caller's own NotFound-returning Get and its Create call) received the raw AlreadyExists
// error instead of falling back to an update, unlike every other Store* method in this file.
func TestAPIServerStore_StoreVEX_concurrentCreateRace(t *testing.T) {
	clientset := fake.NewSimpleClientset()
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
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	cve := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}
	err := a.StoreVEX(context.TODO(), cve, cve, false)
	require.NoError(t, err)
	require.Equal(t, 1, createCalls)

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, vexContainer)
	// updateVEX bumps Metadata.Version on every successful update, so a version > 0
	// confirms the fallback actually went through updateVEX rather than a no-op.
	require.Greater(t, vexContainer.Spec.Metadata.Version, int64(0))
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
	clientset := fake.NewSimpleClientset(seeded)
	var updateCalls int
	clientset.PrependReactor("update", "openvulnerabilityexchangecontainers", func(k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		if updateCalls == 1 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "openvulnerabilityexchangecontainers"}, name, fmt.Errorf("conflict"))
		}
		return false, nil, nil // fall through to the tracker's default update handling
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
	cve := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}
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
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
	_, _ = a.GetCVE(canaryCtx(), name, "", "", "")
	require.Contains(t, wrapped.vulnManifests, a.Namespace)
	requireCanaryCtx(t, wrapped.vulnManifests[a.Namespace].getCtx)
}

func TestAPIServerStore_GetSBOM_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
	_, _ = a.GetSBOM(canaryCtx(), name, "")
	require.Contains(t, wrapped.sbomSyfts, a.Namespace)
	requireCanaryCtx(t, wrapped.sbomSyfts[a.Namespace].getCtx)
}

func TestAPIServerStore_GetCVESummary_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
	workload := domain.ScanCommand{
		ImageHash:     "sha256:ead0a4a53df89fd173874b46093b6e62d8c72967bbf606d672c9e8c9b601a4fc",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx := context.WithValue(canaryCtx(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1734957372))
	_, _ = a.GetCVESummary(ctx)
	require.Contains(t, wrapped.vulnSummaries, a.Namespace)
	requireCanaryCtx(t, wrapped.vulnSummaries[a.Namespace].getCtx)
}

func TestAPIServerStore_GetCVESummary_returnsTransientError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	injectedErr := apierrors.NewInternalError(fmt.Errorf("etcd timeout"))
	clientset.PrependReactor("get", "vulnerabilitymanifestsummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injectedErr
	})
	a := &APIServerStore{StorageClient: clientset.SpdxV1beta1(), Namespace: "kubescape"}
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
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
	require.NoError(t, a.StoreCVE(canaryCtx(), domain.CVEManifest{Name: name}, false))
	require.Contains(t, wrapped.vulnManifests, a.Namespace)
	requireCanaryCtx(t, wrapped.vulnManifests[a.Namespace].createCtx)
}

func TestAPIServerStore_StoreSBOM_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
	require.NoError(t, a.StoreSBOM(canaryCtx(), domain.SBOM{Name: name}, false))
	require.Contains(t, wrapped.sbomSyfts, a.Namespace)
	requireCanaryCtx(t, wrapped.sbomSyfts[a.Namespace].createCtx)
}

func TestAPIServerStore_StoreVEX_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
	cve := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}
	require.NoError(t, a.StoreVEX(canaryCtx(), cve, cve, false))
	require.Contains(t, wrapped.ovecs, a.Namespace)
	requireCanaryCtx(t, wrapped.ovecs[a.Namespace].getCtx)
	requireCanaryCtx(t, wrapped.ovecs[a.Namespace].createCtx)
}

func TestAPIServerStore_GetContainerProfile_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
	_, _ = a.GetContainerProfile(canaryCtx(), "my-namespace", name)
	require.Contains(t, wrapped.containerProfiles, "my-namespace")
	requireCanaryCtx(t, wrapped.containerProfiles["my-namespace"].getCtx)
}

func TestAPIServerStore_StoreSBOMFiltered_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
	require.NoError(t, a.StoreSBOM(canaryCtx(), domain.SBOM{Name: name}, true))
	require.Contains(t, wrapped.sbomSyftFiltereds, a.Namespace)
	requireCanaryCtx(t, wrapped.sbomSyftFiltereds[a.Namespace].createCtx)
}

func TestAPIServerStore_StoreCVESummary_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
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
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
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
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
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
	require.NoError(t, a.StoreVEX(canary, cve, cve, false))

	requireCanaryCtx(t, wrapped.ovecs[a.Namespace].getCtx)
	requireCanaryCtx(t, wrapped.ovecs[a.Namespace].updateCtx)
}

func TestAPIServerStore_StoreCVE_RetryConflict_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}

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
}

func TestAPIServerStore_StoreSBOM_RetryConflict_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}

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
}

func TestAPIServerStore_StoreSBOMFiltered_RetryConflict_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}

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
}

func TestAPIServerStore_StoreCVESummary_RetryConflict_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
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
}

func TestAPIServerStore_StoreCVESummaryStub_RetryConflict_ctxPropagated(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	wrapped := &ctxCapturingClient{SpdxV1beta1Interface: clientset.SpdxV1beta1()}
	a := &APIServerStore{StorageClient: wrapped, Namespace: "kubescape"}
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
}

func TestCtxCapturingClient_wrappersKeyedByNamespace(t *testing.T) {
	clientset := fake.NewSimpleClientset()
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
