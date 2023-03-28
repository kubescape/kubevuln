package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const imageID = "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
const instanceID = "ee9bdd0adec9ce004572faf3492f583aa82042a8b3a9d5c7d9179dc03c531eef"

func (a *APIServerStore) storeSBOMp(ctx context.Context, sbom domain.SBOM) error {
	manifest := v1beta1.SBOMSPDXv2p3Filtered{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sbom.ID,
			Annotations: map[string]string{
				domain.StatusKey: sbom.Status,
			},
		},
		Spec: v1beta1.SBOMSPDXv2p3Spec{
			SPDX: *sbom.Content,
		},
	}
	_, err := a.StorageClient.SBOMSPDXv2p3Filtereds(a.Namespace).Create(ctx, &manifest, metav1.CreateOptions{})
	return err
}

func TestAPIServerStore_GetCVE(t *testing.T) {
	type args struct {
		ctx                context.Context
		imageID            string
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
				ctx:     context.TODO(),
				imageID: imageID,
			},
			domain.CVEManifest{
				ID:      imageID,
				Content: &v1beta1.GrypeDocument{},
			},
			false,
		},
		{
			"CVEScannerVersion mismatch",
			args{
				ctx:               context.TODO(),
				imageID:           imageID,
				CVEScannerVersion: "v1.1.0",
			},
			domain.CVEManifest{
				ID:                imageID,
				CVEScannerVersion: "v1.0.0",
				Content:           &v1beta1.GrypeDocument{},
			},
			true,
		},
		{
			"CVEDBVersion mismatch",
			args{
				ctx:          context.TODO(),
				imageID:      imageID,
				CVEDBVersion: "v1.1.0",
			},
			domain.CVEManifest{
				ID:           imageID,
				CVEDBVersion: "v1.0.0",
				Content:      &v1beta1.GrypeDocument{},
			},
			true,
		},
		{
			"empty imageID",
			args{
				ctx:          context.TODO(),
				imageID:      "",
				CVEDBVersion: "v1.1.0",
			},
			domain.CVEManifest{
				ID:           "",
				CVEDBVersion: "v1.0.0",
				Content:      &v1beta1.GrypeDocument{},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewFakeAPIServerStorage("kubescape")
			_, err := a.GetCVE(tt.args.ctx, tt.args.imageID, tt.args.SBOMCreatorVersion, tt.args.CVEScannerVersion, tt.args.CVEDBVersion)
			tools.EnsureSetup(t, err == nil)
			err = a.StoreCVE(tt.args.ctx, tt.cve, false)
			tools.EnsureSetup(t, err == nil)
			gotCve, _ := a.GetCVE(tt.args.ctx, tt.args.imageID, tt.args.SBOMCreatorVersion, tt.args.CVEScannerVersion, tt.args.CVEDBVersion)
			if (gotCve.Content == nil) != tt.wantEmptyCVE {
				t.Errorf("GetCVE() gotCve.Content = %v, wantEmptyCVE %v", gotCve.Content, tt.wantEmptyCVE)
				return
			}
		})
	}
}

func TestAPIServerStore_GetSBOM(t *testing.T) {
	type args struct {
		ctx                context.Context
		imageID            string
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
				ctx:     context.TODO(),
				imageID: imageID,
			},
			domain.SBOM{
				ID: imageID,
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
				ctx:     context.TODO(),
				imageID: imageID,
			},
			domain.SBOM{
				ID: imageID,
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
				imageID:            imageID,
				SBOMCreatorVersion: "v1.1.0",
			},
			domain.SBOM{
				ID:                 imageID,
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
			"empty imageID",
			args{
				ctx:                context.TODO(),
				imageID:            "",
				SBOMCreatorVersion: "v1.1.0",
			},
			domain.SBOM{
				ID:                 "",
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
			_, err := a.GetSBOM(tt.args.ctx, tt.args.imageID, tt.args.SBOMCreatorVersion)
			tools.EnsureSetup(t, err == nil)
			err = a.StoreSBOM(tt.args.ctx, tt.sbom)
			tools.EnsureSetup(t, err == nil)
			gotSbom, _ := a.GetSBOM(tt.args.ctx, tt.args.imageID, tt.args.SBOMCreatorVersion)
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
		instanceID         string
		SBOMCreatorVersion string
	}
	tests := []struct {
		name          string
		args          args
		sbom          domain.SBOM
		wantEmptySBOM bool
	}{
		{
			"valid SBOMp is retrieved",
			args{
				ctx:        context.TODO(),
				instanceID: instanceID,
			},
			domain.SBOM{
				ID: instanceID,
				Content: &v1beta1.Document{
					CreationInfo: &v1beta1.CreationInfo{
						Created: time.Now().Format(time.RFC3339),
					},
				},
			},
			false,
		},
		{
			"invalid timestamp, SBOMp is still retrieved",
			args{
				ctx:        context.TODO(),
				instanceID: instanceID,
			},
			domain.SBOM{
				ID: instanceID,
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
				instanceID:         instanceID,
				SBOMCreatorVersion: "v1.1.0",
			},
			domain.SBOM{
				ID:                 instanceID,
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
			"empty imageID",
			args{
				ctx:                context.TODO(),
				instanceID:         "",
				SBOMCreatorVersion: "v1.1.0",
			},
			domain.SBOM{
				ID:                 "",
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
			_, err := a.GetSBOMp(tt.args.ctx, tt.args.instanceID, tt.args.SBOMCreatorVersion)
			tools.EnsureSetup(t, err == nil)
			err = a.storeSBOMp(tt.args.ctx, tt.sbom)
			tools.EnsureSetup(t, err == nil)
			gotSbom, _ := a.GetSBOMp(tt.args.ctx, tt.args.instanceID, tt.args.SBOMCreatorVersion)
			if (gotSbom.Content == nil) != tt.wantEmptySBOM {
				t.Errorf("GetSBOM() gotSbom.Content = %v, wantEmptySBOM %v", gotSbom.Content, tt.wantEmptySBOM)
				return
			}
		})
	}
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
		{
			name:    "only hash",
			imageID: "c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
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
