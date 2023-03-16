package repositories

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"gotest.tools/v3/assert"
)

const imageID = "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
const instanceID = "apiVersion-v1/namespace-default/kind-Deployment/name-nginx/resourceVersion-153294/containerName-nginx"

func NewFakeAPIServerStorage(namespace string) (*APIServerStore, error) {
	return &APIServerStore{
		StorageClient: fake.NewSimpleClientset().SpdxV1beta1(),
		Namespace:     namespace,
	}, nil
}

func TestAPIServerStore_GetCVE(t *testing.T) {
	m, _ := NewFakeAPIServerStorage("kubescape")
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
	m, _ := NewFakeAPIServerStorage("kubescape")
	ctx := context.TODO()
	got, _ := m.GetSBOM(ctx, imageID, "")
	assert.Assert(t, got.Content == nil)
	got, _ = m.GetSBOMp(ctx, imageID, "")
	assert.Assert(t, got.Content == nil)
	sbom := domain.SBOM{
		ID:                 imageID,
		SBOMCreatorVersion: "",
		Status:             "",
		Content:            &v1beta1.Document{},
	}
	_ = m.StoreSBOM(ctx, sbom)
	sbomp := domain.SBOM{
		ID:                 instanceID,
		SBOMCreatorVersion: "",
		Status:             "",
		Content:            &v1beta1.Document{},
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
