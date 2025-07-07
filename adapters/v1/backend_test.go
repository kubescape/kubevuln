package v1

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/containerscan"
	v1 "github.com/armosec/armoapi-go/containerscan/v1"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/utils-go/httputils"
	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/google/uuid"
	"github.com/kinbiko/jsonassert"
	beClientV1 "github.com/kubescape/backend/pkg/client/v1"
	sysreport "github.com/kubescape/backend/pkg/server/v1/systemreports"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestBackendAdapter_GetCVEExceptions(t *testing.T) {
	type fields struct {
		getCVEExceptionsFunc func(string, string, *identifiers.PortalDesignator, map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error)
		clusterConfig        armometadata.ClusterConfig
	}
	tests := []struct {
		fields   fields
		name     string
		want     domain.CVEExceptions
		workload bool
		wantErr  bool
	}{
		{
			name:     "no workload",
			workload: false,
			wantErr:  true,
		},
		/*{
			name:     "error get exceptions",
			workload: true,
			fields: fields{
				getCVEExceptionsFunc: func(s string, designator *identifiers.PortalDesignator) ([]armotypes.VulnerabilityExceptionPolicy, error) {
					return nil, fmt.Errorf("error")
				},
			},
			wantErr: true,
		},
		{
			name:     "no exception",
			workload: true,
			fields: fields{
				getCVEExceptionsFunc: func(s string, designator *identifiers.PortalDesignator) ([]armotypes.VulnerabilityExceptionPolicy, error) {
					return []armotypes.VulnerabilityExceptionPolicy{}, nil
				},
			},
			want: []armotypes.VulnerabilityExceptionPolicy{},
		},*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &BackendAdapter{
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
			assert.Equal(t, tt.want, got)
		})
	}
}

func fileToType[T any](path string) *T {
	var t *T
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(b, &t)
	if err != nil {
		panic(err)
	}
	return t
}

func TestBackendAdapter_SubmitCVE(t *testing.T) {
	ja := jsonassert.New(t)
	tests := []struct {
		cve                        domain.CVEManifest
		cvep                       domain.CVEManifest
		name                       string
		exceptions                 []armotypes.VulnerabilityExceptionPolicy
		checkFullBody              bool
		checkFullBodyWithException bool
		wantErr                    bool
	}{
		{
			name:          "submit small cve",
			cve:           *fileToType[domain.CVEManifest]("testdata/nginx-cve-small.json"),
			checkFullBody: true,
		},
		{
			name: "submit big cve",
			cve:  *fileToType[domain.CVEManifest]("testdata/nginx-cve.json"),
		},
		{
			name: "submit big cve with relevancy",
			cve:  *fileToType[domain.CVEManifest]("testdata/nginx-cve.json"),
			cvep: *fileToType[domain.CVEManifest]("testdata/nginx-filtered-cve.json"),
		},
		{
			name:                       "submit small cve with exceptions",
			cve:                        *fileToType[domain.CVEManifest]("testdata/nginx-cve-small.json"),
			checkFullBodyWithException: true,
			exceptions: []armotypes.VulnerabilityExceptionPolicy{{
				PolicyType:            "vulnerabilityExceptionPolicy",
				Actions:               []armotypes.VulnerabilityExceptionPolicyActions{"ignore"},
				VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-2007-5686"}},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mu := &sync.Mutex{}
			seenCVE := map[string]struct{}{}
			httpPostFunc := func(httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte, timeOut time.Duration) (*http.Response, error) {
				var report v1.ScanResultReport
				err := json.Unmarshal(body, &report)
				if err != nil {
					t.Errorf("failed to unmarshal report: %v", err)
				}
				var expectedBody []byte
				vulns := "null"
				if report.Vulnerabilities != nil {
					vulns = "\"<<PRESENCE>>\""
				}
				var args []interface{}
				switch {
				case tt.checkFullBody:
					expectedBody, err = os.ReadFile("testdata/cve-body.json")
				case tt.checkFullBodyWithException:
					expectedBody, err = os.ReadFile("testdata/cve-body-with-exception.json")
				case report.Summary == nil:
					expectedBody, err = os.ReadFile("testdata/cve-chunk.json")
				case tt.cvep.Content != nil:
					args = append(args, vulns)
					expectedBody, err = os.ReadFile("testdata/cve-chunk-with-relevant-summary.json")
				default:
					args = append(args, vulns)
					expectedBody, err = os.ReadFile("testdata/cve-chunk-with-summary.json")
				}
				if err != nil {
					t.Errorf("failed to read expected body: %v", err)
				}
				ja.Assertf(string(body), string(expectedBody), args...)
				mu.Lock()
				for _, v := range report.Vulnerabilities {
					id := v.Name + "+" + v.RelatedPackageName
					if _, ok := seenCVE[id]; ok {
						t.Errorf("duplicate cve %s", id)
					}
					seenCVE[id] = struct{}{}
				}
				mu.Unlock()
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewBuffer([]byte{})),
				}, nil
			}
			a := &BackendAdapter{
				clusterConfig: armometadata.ClusterConfig{},
				getCVEExceptionsFunc: func(s, a string, designator *identifiers.PortalDesignator, headers map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
					return tt.exceptions, nil
				},
				httpPostFunc: httpPostFunc,
			}
			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
			ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
			ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})
			if err := a.SubmitCVE(ctx, tt.cve, tt.cvep); (err != nil) != tt.wantErr {
				t.Errorf("SubmitCVE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

//go:embed testdata/nginx-document-source.json
var nginxSBOMMetadata []byte

func TestParseImageManifest(t *testing.T) {
	tests := []struct {
		name     string
		document *v1beta1.GrypeDocument
		expected *containerscan.ImageManifest
		wantErr  bool
	}{
		{
			name:     "empty document",
			document: nil,
			wantErr:  true,
		},
		{
			name: "malformed metadata base64 config",
			document: &v1beta1.GrypeDocument{
				Source: &v1beta1.Source{
					Target: []byte(`{
									"config": "eyJhcmNoaXRlY3R1cmUiOiJhcm02NCIs"
									}`),
				},
			},
			wantErr: true,
		},
		{
			name: "valid document",
			document: &v1beta1.GrypeDocument{
				Source: &v1beta1.Source{
					Target: nginxSBOMMetadata,
				},
			},
			expected: fileToType[containerscan.ImageManifest]("testdata/nginx-image-manifest.json"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageManifest, err := ParseImageManifest(tt.document)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, imageManifest)
			}
		})
	}
}

func TestNewBackendAdapter(t *testing.T) {
	type args struct {
		accountID            string
		apiServerRestURL     string
		eventReceiverRestURL string
	}
	tests := []struct {
		name string
		args args
		want *BackendAdapter
	}{
		{
			name: "new backend adapter",
			want: &BackendAdapter{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewBackendAdapter(tt.args.accountID, tt.args.apiServerRestURL, tt.args.eventReceiverRestURL, "")
			// need to nil functions to compare
			got.httpPostFunc = nil
			got.getCVEExceptionsFunc = nil
			assert.NotEqual(t, got, tt.want)
		})
	}
}

func TestBackendAdapter_SendStatus(t *testing.T) {
	tests := []struct {
		name    string
		step    int
		report  sysreport.BaseReport
		wantErr bool
	}{
		{
			name: "send status",
			step: 1,
			report: sysreport.BaseReport{
				Reporter:   ReporterName,
				Target:     "vuln scan:: scanning wlid: wlid , container: container imageTag: imageTag imageHash: imageHash",
				Status:     "Dequeueing",
				ActionName: ActionName,
				ActionID:   "1",
				ActionIDN:  1,
				Details:    "started",
			},
		},
	}
	for _, tt := range tests { //nolint:govet
		t.Run(tt.name, func(t *testing.T) {
			a := &BackendAdapter{
				sendStatusFunc: func(sender *beClientV1.BaseReportSender, s string, b bool) {
					report := sender.GetBaseReport()
					assert.NotEqual(t, *report, tt.report) //nolint:govet
				},
			}
			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
			ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
			ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{
				Wlid:          "wlid",
				ContainerName: "container",
				ImageTag:      "imageTag",
				ImageHash:     "imageHash",
			})
			if err := a.SendStatus(ctx, tt.step); (err != nil) != tt.wantErr {
				t.Errorf("SendStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
