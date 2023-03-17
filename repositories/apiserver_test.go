package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"gotest.tools/v3/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const imageID = "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
const instanceID = "apiVersion-v1/namespace-default/kind-Deployment/name-nginx/resourceVersion-153294/containerName-nginx"

func (a *APIServerStore) storeSBOMp(ctx context.Context, sbom domain.SBOM) error {
	manifest := v1beta1.SBOMSPDXv2p3Filtered{
		ObjectMeta: metav1.ObjectMeta{
			Name:   hashFromInstanceID(sbom.ID),
			Labels: labelsFromInstanceID(sbom.ID),
		},
		Spec: v1beta1.SBOMSPDXv2p3Spec{
			SPDX: *sbom.Content,
		},
	}
	_, err := a.StorageClient.SBOMSPDXv2p3Filtereds(a.Namespace).Create(ctx, &manifest, metav1.CreateOptions{})
	return err
}

func TestAPIServerStore_GetCVE(t *testing.T) {
	m := NewFakeAPIServerStorage("kubescape")
	ctx := context.TODO()
	got, _ := m.GetCVE(ctx, imageID, "", "", "")
	assert.Assert(t, got.Content == nil)
	cve := domain.CVEManifest{
		ImageID:            imageID,
		SBOMCreatorVersion: "",
		CVEScannerVersion:  "",
		CVEDBVersion:       "",
		Content:            &v1beta1.GrypeDocument{},
	}
	_ = m.StoreCVE(ctx, cve, false)
	got, _ = m.GetCVE(ctx, imageID, "", "", "")
	assert.Assert(t, got.Content != nil)
}

func TestAPIServerStore_GetSBOM(t *testing.T) {
	m := NewFakeAPIServerStorage("kubescape")
	ctx := context.TODO()
	got, _ := m.GetSBOM(ctx, imageID, "")
	assert.Assert(t, got.Content == nil)
	got, _ = m.GetSBOMp(ctx, imageID, "")
	assert.Assert(t, got.Content == nil)
	sbom := domain.SBOM{
		ID:                 imageID,
		SBOMCreatorVersion: "",
		Status:             "",
		Content: &v1beta1.Document{
			CreationInfo: &v1beta1.CreationInfo{
				Created: time.Now().Format(time.RFC3339),
			},
		},
	}
	_ = m.StoreSBOM(ctx, sbom)
	sbomp := domain.SBOM{
		ID:                 instanceID,
		SBOMCreatorVersion: "",
		Status:             "",
		Content: &v1beta1.Document{
			CreationInfo: &v1beta1.CreationInfo{
				Created: time.Now().Format(time.RFC3339),
			},
		},
	}
	_ = m.storeSBOMp(ctx, sbomp)
	got, _ = m.GetSBOM(ctx, imageID, "")
	assert.Assert(t, got.Content != nil)
	got, _ = m.GetSBOMp(ctx, instanceID, "")
	assert.Assert(t, got.Content != nil)
}

func Test_extractHashFromImageID(t *testing.T) {
	tests := []struct {
		name    string
		imageID string
		want    string
	}{
		{
			name:    "no tag",
			imageID: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
			want:    "c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
		},
		{
			name:    "with tag",
			imageID: "library/nginx:v1.21.0@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
			want:    "c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hashFromImageID(tt.imageID); got != tt.want {
				t.Errorf("hashFromImageID() = %v, want %v", got, tt.want)
			}
		})
	}
}

//func TestForRazi(t *testing.T) {
//	ctx := context.TODO()
//	sbomAdapter := v1.NewSyftAdapter(1 * time.Hour)
//	cveAdapter := v1.NewGrypeAdapter()
//	cveAdapter.Ready(ctx)
//	repository, _ := newFakeAPIServerStorage("kubescape")
//	sbom, err := sbomAdapter.CreateSBOM(ctx, "requarks/wiki@sha256:dd83fff15e77843ff934b25c28c865ac000edf7653e5d11adad1dd51df87439d", domain.RegistryOptions{})
//	if err != nil {
//		panic(err)
//	}
//	cve, err := cveAdapter.ScanSBOM(ctx, sbom)
//	if err != nil {
//		panic(err)
//	}
//	repository.StoreCVE(ctx, cve, false)
//}
