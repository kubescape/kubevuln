//go:build integration
// +build integration

package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
)

func TestArmoAdapter_GetCVEExceptions(t *testing.T) {
	tests := []struct {
		name     string
		yamlFile string
		wantErr  bool
	}{
		{
			"valid scan command send status",
			"../../api/v1/testdata/scan.yaml",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var workload domain.ScanCommand
			b, err := os.ReadFile(tt.yamlFile)
			tools.EnsureSetup(t, err == nil)
			err = json.Unmarshal(b, &workload)
			tools.EnsureSetup(t, err == nil)
			a := NewArmoAdapter("3fcd1e54-7871-49dc-8ebf-8d828d28c00b", "http://192.168.88.250:7555")
			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.WorkloadKey, workload)
			got, err := a.GetCVEExceptions(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCVEExceptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Println(got)
			//if !reflect.DeepEqual(got, tt.want) {
			//	t.Errorf("GetCVEExceptions() got = %v, want %v", got, tt.want)
			//}
		})
	}
}

func TestArmoAdapter_SendStatus(t *testing.T) {
	tests := []struct {
		name     string
		yamlFile string
		wantErr  bool
	}{
		{
			"valid scan command send status",
			"../../api/v1/testdata/scan.yaml",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var workload domain.ScanCommand
			b, err := os.ReadFile(tt.yamlFile)
			tools.EnsureSetup(t, err == nil)
			err = json.Unmarshal(b, &workload)
			tools.EnsureSetup(t, err == nil)
			a := NewArmoAdapter("3fcd1e54-7871-49dc-8ebf-8d828d28c00b", "http://192.168.88.250:7555")
			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.WorkloadKey, workload)
			if err := a.SendStatus(ctx, 0); (err != nil) != tt.wantErr {
				t.Errorf("SendStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestArmoAdapter_SubmitCVE(t *testing.T) {
	tests := []struct {
		name     string
		yamlFile string
		wantErr  bool
	}{
		{
			"valid cve submit",
			"../../api/v1/testdata/scan.yaml",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var workload domain.ScanCommand
			b, err := os.ReadFile(tt.yamlFile)
			tools.EnsureSetup(t, err == nil)
			err = json.Unmarshal(b, &workload)
			tools.EnsureSetup(t, err == nil)
			a := NewArmoAdapter("3fcd1e54-7871-49dc-8ebf-8d828d28c00b", "http://192.168.88.250:7555")
			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.TimestampKey, time.Now().Unix())
			ctx = context.WithValue(ctx, domain.ScanIDKey, uuid.New().String())
			ctx = context.WithValue(ctx, domain.WorkloadKey, workload)
			syft := NewSyftAdapter()
			sbom, err := syft.CreateSBOM(ctx, workload.ImageHash, domain.RegistryOptions{})
			tools.EnsureSetup(t, err == nil)
			grype, err := NewGrypeAdapter(ctx)
			tools.EnsureSetup(t, err == nil)
			cve, err := grype.ScanSBOM(ctx, sbom, domain.CVEExceptions{})
			tools.EnsureSetup(t, err == nil)
			if err := a.SubmitCVE(ctx, cve, false); (err != nil) != tt.wantErr {
				t.Errorf("SubmitCVE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
