package repositories

import (
	"context"
	"reflect"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
)

func TestAPIServerStore_GetCVE(t *testing.T) {
	type fields struct {
		Clientset *versioned.Clientset
		Namespace string
	}
	type args struct {
		ctx                context.Context
		imageID            string
		SBOMCreatorVersion string
		CVEScannerVersion  string
		CVEDBVersion       string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantCve domain.CVEManifest
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &APIServerStore{
				Clientset: tt.fields.Clientset,
				Namespace: tt.fields.Namespace,
			}
			gotCve, err := a.GetCVE(tt.args.ctx, tt.args.imageID, tt.args.SBOMCreatorVersion, tt.args.CVEScannerVersion, tt.args.CVEDBVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCVE() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotCve, tt.wantCve) {
				t.Errorf("GetCVE() gotCve = %v, want %v", gotCve, tt.wantCve)
			}
		})
	}
}

func TestAPIServerStore_GetSBOM(t *testing.T) {
	type fields struct {
		Clientset *versioned.Clientset
		Namespace string
	}
	type args struct {
		ctx                context.Context
		imageID            string
		SBOMCreatorVersion string
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantSbom domain.SBOM
		wantErr  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &APIServerStore{
				Clientset: tt.fields.Clientset,
				Namespace: tt.fields.Namespace,
			}
			gotSbom, err := a.GetSBOM(tt.args.ctx, tt.args.imageID, tt.args.SBOMCreatorVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSbom, tt.wantSbom) {
				t.Errorf("GetSBOM() gotSbom = %v, want %v", gotSbom, tt.wantSbom)
			}
		})
	}
}

func TestAPIServerStore_GetSBOMp(t *testing.T) {
	type fields struct {
		Clientset *versioned.Clientset
		Namespace string
	}
	type args struct {
		ctx                context.Context
		instanceID         string
		SBOMCreatorVersion string
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantSbom domain.SBOM
		wantErr  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &APIServerStore{
				Clientset: tt.fields.Clientset,
				Namespace: tt.fields.Namespace,
			}
			gotSbom, err := a.GetSBOMp(tt.args.ctx, tt.args.instanceID, tt.args.SBOMCreatorVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSBOMp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSbom, tt.wantSbom) {
				t.Errorf("GetSBOMp() gotSbom = %v, want %v", gotSbom, tt.wantSbom)
			}
		})
	}
}

func TestAPIServerStore_StoreCVE(t *testing.T) {
	type fields struct {
		Clientset *versioned.Clientset
		Namespace string
	}
	type args struct {
		ctx           context.Context
		cve           domain.CVEManifest
		withRelevancy bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &APIServerStore{
				Clientset: tt.fields.Clientset,
				Namespace: tt.fields.Namespace,
			}
			if err := a.StoreCVE(tt.args.ctx, tt.args.cve, tt.args.withRelevancy); (err != nil) != tt.wantErr {
				t.Errorf("StoreCVE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAPIServerStore_StoreSBOM(t *testing.T) {
	type fields struct {
		Clientset *versioned.Clientset
		Namespace string
	}
	type args struct {
		ctx  context.Context
		sbom domain.SBOM
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &APIServerStore{
				Clientset: tt.fields.Clientset,
				Namespace: tt.fields.Namespace,
			}
			if err := a.StoreSBOM(tt.args.ctx, tt.args.sbom); (err != nil) != tt.wantErr {
				t.Errorf("StoreSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewAPIServerStorage(t *testing.T) {
	type args struct {
		namespace string
	}
	tests := []struct {
		name    string
		args    args
		want    *APIServerStore
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAPIServerStorage(tt.args.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAPIServerStorage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAPIServerStorage() got = %v, want %v", got, tt.want)
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hashFromImageID(tt.imageID); got != tt.want {
				t.Errorf("hashFromImageID() = %v, want %v", got, tt.want)
			}
		})
	}
}
