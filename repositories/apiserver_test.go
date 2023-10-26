package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	v1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const name = "k8s.gcr.io-kube-proxy-sha256-c1b13"

func (a *APIServerStore) storeSBOMp(ctx context.Context, sbom domain.SBOM, incomplete bool) error {
	manifest := v1beta1.SBOMSPDXv2p3Filtered{
		ObjectMeta: metav1.ObjectMeta{
			Name:        sbom.Name,
			Annotations: sbom.Annotations,
		},
		Spec: v1beta1.SBOMSPDXv2p3Spec{},
	}
	if sbom.Content != nil {
		manifest.Spec.SPDX = *sbom.Content
	}
	if manifest.Annotations == nil {
		manifest.Annotations = map[string]string{}
	}
	manifest.Annotations[instanceidhandler.StatusMetadataKey] = sbom.Status // for the moment stored as an annotation
	if incomplete {
		manifest.Annotations[instanceidhandler.StatusMetadataKey] = instanceidhandler.Incomplete
	}
	_, err := a.StorageClient.SBOMSPDXv2p3Filtereds(a.Namespace).Create(ctx, &manifest, metav1.CreateOptions{})
	return err
}

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
			tools.EnsureSetup(t, err == nil)
			tt.args.ctx = context.WithValue(tt.args.ctx, domain.WorkloadKey{}, workload)
			err = a.StoreCVE(tt.args.ctx, tt.cve, false)
			tools.EnsureSetup(t, err == nil)
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
			Descriptor: v1beta1.Descriptor{
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
	tools.EnsureSetup(t, err == nil)
	cvep.Content.Descriptor.Version = "v1.1.0"
	err = a.StoreCVE(ctx, cvep, true)
	assert.NoError(t, err)
	got, err := a.GetCVE(ctx, name, "", "", "")
	tools.EnsureSetup(t, err == nil)
	assert.Equal(t, got.Content.Descriptor.Version, "v1.1.0")
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
		wantEmptySBOM bool
	}{
		{
			"valid SBOM is retrieved",
			args{
				ctx:  context.TODO(),
				name: name,
			},
			domain.SBOM{
				Name: name,
				Content: &v1beta1.Document{
					CreationInfo: &v1beta1.CreationInfo{
						Created: time.Now().Format(time.RFC3339),
					},
				},
			},
			false,
		},
		{
			"invalid timestamp, SBOM is still retrieved",
			args{
				ctx:  context.TODO(),
				name: name,
			},
			domain.SBOM{
				Name: name,
				Content: &v1beta1.Document{
					CreationInfo: &v1beta1.CreationInfo{
						Created: "invalid timestamp",
					},
				},
			},
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
				Content: &v1beta1.Document{
					CreationInfo: &v1beta1.CreationInfo{
						Created: time.Now().Format(time.RFC3339),
					},
				},
			},
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
				Content: &v1beta1.Document{
					CreationInfo: &v1beta1.CreationInfo{
						Created: time.Now().Format(time.RFC3339),
					},
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewFakeAPIServerStorage("kubescape")
			_, err := a.GetSBOM(tt.args.ctx, tt.args.name, tt.args.SBOMCreatorVersion)
			tools.EnsureSetup(t, err == nil)
			err = a.StoreSBOM(tt.args.ctx, tt.sbom)
			tools.EnsureSetup(t, err == nil)
			gotSbom, _ := a.GetSBOM(tt.args.ctx, tt.args.name, tt.args.SBOMCreatorVersion)
			if (gotSbom.Content == nil) != tt.wantEmptySBOM {
				t.Errorf("GetSBOM() gotSbom.Content = %v, wantEmptySBOM %v", gotSbom.Content, tt.wantEmptySBOM)
				return
			}
		})
	}
}

func TestAPIServerStore_GetSBOMp(t *testing.T) {
	type args struct {
		ctx                context.Context
		name               string
		SBOMCreatorVersion string
	}
	tests := []struct {
		name          string
		args          args
		sbom          domain.SBOM
		incomplete    bool
		wantEmptySBOM bool
	}{
		{
			name: "valid SBOMp is retrieved",
			args: args{
				ctx:  context.TODO(),
				name: name,
			},
			sbom: domain.SBOM{
				Name: name,
				Annotations: map[string]string{
					"foo": "bar",
				},
				Content: &v1beta1.Document{
					CreationInfo: &v1beta1.CreationInfo{
						Created: time.Now().Format(time.RFC3339),
					},
				},
			},
		},
		{
			name: "invalid timestamp, SBOMp is still retrieved",
			args: args{
				ctx:  context.TODO(),
				name: name,
			},
			sbom: domain.SBOM{
				Name: name,
				Annotations: map[string]string{
					"foo": "bar",
				},
				Content: &v1beta1.Document{
					CreationInfo: &v1beta1.CreationInfo{
						Created: "invalid timestamp",
					},
				},
			},
		},
		{
			name: "SBOMCreatorVersion mismatch",
			args: args{
				ctx:                context.TODO(),
				name:               name,
				SBOMCreatorVersion: "v1.1.0",
			},
			sbom: domain.SBOM{
				Name: name,
				Annotations: map[string]string{
					"foo": "bar",
				},
				SBOMCreatorVersion: "v1.0.0",
				Content: &v1beta1.Document{
					CreationInfo: &v1beta1.CreationInfo{
						Created: time.Now().Format(time.RFC3339),
					},
				},
			},
			wantEmptySBOM: false, // SBOMp is not versioned
		},
		{
			name: "empty name",
			args: args{
				ctx:                context.TODO(),
				name:               "",
				SBOMCreatorVersion: "v1.1.0",
			},
			sbom: domain.SBOM{
				Name:               "",
				SBOMCreatorVersion: "v1.0.0",
				Content: &v1beta1.Document{
					CreationInfo: &v1beta1.CreationInfo{
						Created: time.Now().Format(time.RFC3339),
					},
				},
			},
			wantEmptySBOM: true,
		},
		{
			name: "incomplete SBOMp is retrieved",
			args: args{
				ctx:  context.TODO(),
				name: name,
			},
			sbom: domain.SBOM{
				Name: name,
				Content: &v1beta1.Document{
					CreationInfo: &v1beta1.CreationInfo{
						Created: time.Now().Format(time.RFC3339),
					},
				},
			},
			incomplete:    true,
			wantEmptySBOM: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewFakeAPIServerStorage("kubescape")
			_, err := a.GetSBOMp(tt.args.ctx, tt.args.name, tt.args.SBOMCreatorVersion)
			tools.EnsureSetup(t, err == nil)
			err = a.storeSBOMp(tt.args.ctx, tt.sbom, tt.incomplete)
			tools.EnsureSetup(t, err == nil)
			gotSbom, _ := a.GetSBOMp(tt.args.ctx, tt.args.name, tt.args.SBOMCreatorVersion)
			if !tt.wantEmptySBOM {
				assert.NotNil(t, gotSbom.Content)
				assert.Equal(t, "bar", gotSbom.Annotations["foo"])
			}
		})
	}
}

func TestAPIServerStore_parseSeverities(t *testing.T) {
	var nginxCVECriticalSeveritiesNumber = 72
	var nginxCVEHighSeveritiesNumber = 128
	var nginxCVEMediumSeveritiesNumber = 98
	var nginxCVELowSeveritiesNumber = 56
	var nginxCVENegligibleSeveritiesNumber = 102
	var nginxCVEUnknownSeveritiesNumber = 0

	cveManifest := tools.FileToCVEManifest("testdata/nginx-cve.json")
	severities := parseSeverities(cveManifest, cveManifest, false)
	assert.Equal(t, nginxCVECriticalSeveritiesNumber, severities.Critical.All)
	assert.Equal(t, nginxCVEHighSeveritiesNumber, severities.High.All)
	assert.Equal(t, nginxCVEMediumSeveritiesNumber, severities.Medium.All)
	assert.Equal(t, nginxCVELowSeveritiesNumber, severities.Low.All)
	assert.Equal(t, nginxCVENegligibleSeveritiesNumber, severities.Negligible.All)
	assert.Equal(t, nginxCVEUnknownSeveritiesNumber, severities.Unknown.All)

	assert.Equal(t, 0, severities.Critical.Relevant)
	assert.Equal(t, 0, severities.High.Relevant)
	assert.Equal(t, 0, severities.Medium.Relevant)
	assert.Equal(t, 0, severities.Low.Relevant)
	assert.Equal(t, 0, severities.Negligible.Relevant)
	assert.Equal(t, 0, severities.Unknown.Relevant)

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

func TestAPIServerStore_storeSBOMWithoutContent(t *testing.T) {
	SBOMData := tools.FileToSBOM("testdata/alpine-sbom.json")
	SBOM := domain.SBOM{
		Content: SBOMData,
	}
	a := NewFakeAPIServerStorage("kubescape")

	err := a.storeSBOMWithoutContent(context.TODO(), SBOM)
	assert.Equal(t, err, nil)
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

		val, exist := enrichedLabels[v1.ApiGroupMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].k8sResourceGroup)

		val, exist = enrichedLabels[v1.ApiVersionMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].k8sResourceVersion)

		val, exist = enrichedLabels[v1.KindMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].k8sResourceType)

		val, exist = enrichedLabels[v1.NameMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].k8sResourceName)

		val, exist = enrichedLabels[v1.NamespaceMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].k8sResourceNamespace)

		val, exist = enrichedLabels[v1.ContainerNameMetadataKey]
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
		ctx = context.WithValue(ctx, domain.WorkloadKey{}, tests[i].workload)
		enrichedAnnotations, err := enrichSummaryManifestObjectAnnotations(ctx, tests[i].annotations)
		assert.Equal(t, err, nil)

		val, exist := enrichedAnnotations[v1.WlidMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].workload.Wlid)

		val, exist = enrichedAnnotations[v1.ContainerNameMetadataKey]
		assert.Equal(t, exist, true)
		assert.Equal(t, val, tests[i].workload.ContainerName)
	}

}

func TestAPIServerStore_getCVESummaryK8sResourceName(t *testing.T) {
	tests := []struct {
		workload domain.ScanCommand
		expRes   string
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
		name, err := GetCVESummaryK8sResourceName(ctx)
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
