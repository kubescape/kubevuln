package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-go/httputils"
	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/go-test/deep"
	"github.com/google/uuid"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
)

func TestArmoAdapter_GetCVEExceptions(t *testing.T) {
	type fields struct {
		clusterConfig        armometadata.ClusterConfig
		getCVEExceptionsFunc func(string, string, *armotypes.PortalDesignator) ([]armotypes.VulnerabilityExceptionPolicy, error)
	}
	tests := []struct {
		name     string
		workload bool
		fields   fields
		want     domain.CVEExceptions
		wantErr  bool
	}{
		{
			name:     "no workload",
			workload: false,
			wantErr:  true,
		},
		{
			name:     "error get exceptions",
			workload: true,
			fields: fields{
				getCVEExceptionsFunc: func(s string, s2 string, designator *armotypes.PortalDesignator) ([]armotypes.VulnerabilityExceptionPolicy, error) {
					return nil, errors.New("error")
				},
			},
			wantErr: true,
		},
		{
			name:     "no exception",
			workload: true,
			fields: fields{
				getCVEExceptionsFunc: func(s string, s2 string, designator *armotypes.PortalDesignator) ([]armotypes.VulnerabilityExceptionPolicy, error) {
					return []armotypes.VulnerabilityExceptionPolicy{}, nil
				},
			},
			want: []armotypes.VulnerabilityExceptionPolicy{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ArmoAdapter{
				clusterConfig:        tt.fields.clusterConfig,
				getCVEExceptionsFunc: tt.fields.getCVEExceptionsFunc,
			}
			ctx := context.TODO()
			if tt.workload {
				ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})
			}
			got, err := a.GetCVEExceptions(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCVEExceptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			diff := deep.Equal(got, tt.want)
			if diff != nil {
				t.Errorf("compare failed: %v", diff)
			}
		})
	}
}

func TestArmoAdapter_SubmitCVE(t *testing.T) {
	type fields struct {
		clusterConfig        armometadata.ClusterConfig
		getCVEExceptionsFunc func(string, string, *armotypes.PortalDesignator) ([]armotypes.VulnerabilityExceptionPolicy, error)
		httpPostFunc         func(httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte) (*http.Response, error)
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "submit cve",
			fields: fields{
				getCVEExceptionsFunc: func(s string, s2 string, designator *armotypes.PortalDesignator) ([]armotypes.VulnerabilityExceptionPolicy, error) {
					return []armotypes.VulnerabilityExceptionPolicy{}, nil
				},
				httpPostFunc: func(httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte) (*http.Response, error) {
					return &http.Response{
						StatusCode: 200,
						Body:       io.NopCloser(bytes.NewBuffer([]byte{})),
					}, nil
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ArmoAdapter{
				clusterConfig:        tt.fields.clusterConfig,
				getCVEExceptionsFunc: tt.fields.getCVEExceptionsFunc,
				httpPostFunc:         tt.fields.httpPostFunc,
			}
			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
			ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
			ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})
			b, err := os.ReadFile("testdata/alpine-cve.json")
			tools.EnsureSetup(t, err == nil)
			var grypeCVE models.Document
			err = json.Unmarshal(b, &grypeCVE)
			tools.EnsureSetup(t, err == nil)
			domainCVE, err := grypeToDomain(grypeCVE)
			tools.EnsureSetup(t, err == nil)
			cve := domain.CVEManifest{
				Content: domainCVE,
			}
			cvep := domain.CVEManifest{
				Content: domainCVE,
			}
			if err := a.SubmitCVE(ctx, cve, cvep); (err != nil) != tt.wantErr {
				t.Errorf("SubmitCVE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewArmoAdapter(t *testing.T) {
	type args struct {
		accountID            string
		gatewayRestURL       string
		eventReceiverRestURL string
	}
	tests := []struct {
		name string
		args args
		want *ArmoAdapter
	}{
		{
			name: "new armo adapter",
			want: &ArmoAdapter{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewArmoAdapter(tt.args.accountID, tt.args.gatewayRestURL, tt.args.eventReceiverRestURL)
			// need to nil functions to compare
			got.httpPostFunc = nil
			got.getCVEExceptionsFunc = nil
			diff := deep.Equal(got, tt.want)
			if diff != nil {
				t.Errorf("compare failed: %v", diff)
			}
		})
	}
}
