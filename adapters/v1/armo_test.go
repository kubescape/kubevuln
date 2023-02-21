//go:build integration
// +build integration

package v1

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

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
			got, err := a.GetCVEExceptions(workload, "3fcd1e54-7871-49dc-8ebf-8d828d28c00b")
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
			if err := a.SendStatus(workload, 0); (err != nil) != tt.wantErr {
				t.Errorf("SendStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
