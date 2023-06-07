package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const name = "k8s.gcr.io-kube-proxy-sha256-c1b13"

func (a *APIServerStore) storeSBOMp(ctx context.Context, sbom domain.SBOM, incomplete bool) error {
	manifest := v1beta1.SBOMSPDXv2p3Filtered{
		ObjectMeta: metav1.ObjectMeta{
			Name: sbom.Name,
			Annotations: map[string]string{
				instanceidhandler.StatusMetadataKey: sbom.Status,
			},
		},
		Spec: v1beta1.SBOMSPDXv2p3Spec{},
	}
	if sbom.Content != nil {
		manifest.Spec.SPDX = *sbom.Content
	}
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
				Name:    name,
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewFakeAPIServerStorage("kubescape")
			_, err := a.GetCVE(tt.args.ctx, tt.args.name, tt.args.SBOMCreatorVersion, tt.args.CVEScannerVersion, tt.args.CVEDBVersion)
			tools.EnsureSetup(t, err == nil)
			err = a.StoreCVE(tt.args.ctx, tt.cve, false)
			tools.EnsureSetup(t, err == nil)
			gotCve, _ := a.GetCVE(tt.args.ctx, tt.args.name, tt.args.SBOMCreatorVersion, tt.args.CVEScannerVersion, tt.args.CVEDBVersion)
			if (gotCve.Content == nil) != tt.wantEmptyCVE {
				t.Errorf("GetCVE() gotCve.Content = %v, wantEmptyCVE %v", gotCve.Content, tt.wantEmptyCVE)
				return
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
				Name:               name,
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
			if (gotSbom.Content == nil) != tt.wantEmptySBOM {
				t.Errorf("GetSBOM() gotSbom.Content = %v, wantEmptySBOM %v", gotSbom.Content, tt.wantEmptySBOM)
				return
			}
		})
	}
}
