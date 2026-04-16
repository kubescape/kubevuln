package v1

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
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
	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/armosec/utils-go/httputils"
	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/stretchr/testify/require"
	"github.com/google/uuid"
	"github.com/kinbiko/jsonassert"
	beClientV1 "github.com/kubescape/backend/pkg/client/v1"
	sysreport "github.com/kubescape/backend/pkg/server/v1/systemreports"
	"github.com/kubescape/kubevuln/core/domain"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
				clusterConfig:         tt.fields.clusterConfig,
				getCVEExceptionsFunc:  tt.fields.getCVEExceptionsFunc,
				securityExceptionRepo: &repositories.NoOpSecurityExceptionRepository{},
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
				httpPostFunc:          httpPostFunc,
				securityExceptionRepo: &repositories.NoOpSecurityExceptionRepository{},
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
			got := NewBackendAdapter(tt.args.accountID, tt.args.apiServerRestURL, tt.args.eventReceiverRestURL, "", &repositories.NoOpSecurityExceptionRepository{})
			// need to nil functions to compare
			got.httpPostFunc = nil
			got.getCVEExceptionsFunc = nil
			got.securityExceptionRepo = nil
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

func TestBackendAdapter_ReportScanFailure_WorkloadScan(t *testing.T) {
	var capturedURL string
	var capturedReport scanfailure.ScanFailureReport

	mockHTTP := func(_ httputils.IHttpClient, fullURL string, _ map[string]string, body []byte, _ time.Duration) (*http.Response, error) {
		capturedURL = fullURL
		require.NoError(t, json.Unmarshal(body, &capturedReport))
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBuffer(nil)),
		}, nil
	}

	a := &BackendAdapter{
		eventReceiverRestURL: "http://localhost:8080",
		clusterConfig:        armometadata.ClusterConfig{AccountID: "test-account"},
		httpPostFunc:         mockHTTP,
		accessKey:            "test-key",
	}

	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:               "wlid://cluster-prod/namespace-default/deployment-nginx",
		ImageTagNormalized: "nginx:1.25.0",
		ImageHash:          "sha256:abc123",
		JobID:              "job-42",
		ContainerName:      "web",
	})

	scanErr := fmt.Errorf("syft: timeout after 300s")
	err := a.ReportScanFailure(ctx, scanfailure.ScanFailureSBOMGeneration, scanfailure.ReasonSBOMGenerationFailed, scanErr)

	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/k8s/v2/scanFailure", capturedURL)
	assert.Equal(t, "test-account", capturedReport.CustomerGUID)
	assert.Equal(t, "nginx:1.25.0", capturedReport.ImageTag)
	assert.Equal(t, "sha256:abc123", capturedReport.ImageHash)
	assert.Equal(t, "job-42", capturedReport.JobID)
	assert.Equal(t, scanfailure.ScanFailureSBOMGeneration, capturedReport.FailureCase)
	assert.Equal(t, scanfailure.ReasonSBOMGenerationFailed, capturedReport.FailureReason)
	assert.Equal(t, "syft: timeout after 300s", capturedReport.Error)
	assert.False(t, capturedReport.IsRegistryScan)
	require.Len(t, capturedReport.Workloads, 1)
	assert.Equal(t, "prod", capturedReport.Workloads[0].ClusterName)
	assert.Equal(t, "default", capturedReport.Workloads[0].Namespace)
	assert.Equal(t, "Deployment", capturedReport.Workloads[0].WorkloadKind)
	assert.Equal(t, "nginx", capturedReport.Workloads[0].WorkloadName)
	assert.Equal(t, "web", capturedReport.Workloads[0].ContainerName)
}

func TestBackendAdapter_ReportScanFailure_RegistryScan(t *testing.T) {
	var capturedReport scanfailure.ScanFailureReport

	mockHTTP := func(_ httputils.IHttpClient, _ string, _ map[string]string, body []byte, _ time.Duration) (*http.Response, error) {
		require.NoError(t, json.Unmarshal(body, &capturedReport))
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBuffer(nil)),
		}, nil
	}

	a := &BackendAdapter{
		eventReceiverRestURL: "http://localhost:8080",
		clusterConfig:        armometadata.ClusterConfig{AccountID: "test-account"},
		httpPostFunc:         mockHTTP,
	}

	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:               "wlid://cluster-prod/namespace-default/deployment-scanner",
		ImageTagNormalized: "registry.io/app:v1",
		ImageHash:          "sha256:def456",
		Args:               map[string]interface{}{identifiers.AttributeRegistryName: "my-registry"},
	})

	scanErr := fmt.Errorf("grype: CVE DB unavailable")
	err := a.ReportScanFailure(ctx, scanfailure.ScanFailureCVE, scanfailure.ReasonCVEMatchingFailed, scanErr)

	require.NoError(t, err)
	assert.True(t, capturedReport.IsRegistryScan)
	assert.Equal(t, "my-registry", capturedReport.RegistryName)
	assert.Nil(t, capturedReport.Workloads)
	assert.Equal(t, "registry.io/app:v1", capturedReport.ImageTag)
	assert.Equal(t, scanfailure.ReasonCVEMatchingFailed, capturedReport.FailureReason)
	assert.Equal(t, "grype: CVE DB unavailable", capturedReport.Error)
}

func TestBackendAdapter_ReportScanFailure_NoWorkloadInContext(t *testing.T) {
	a := &BackendAdapter{
		eventReceiverRestURL: "http://localhost:8080",
		clusterConfig:        armometadata.ClusterConfig{AccountID: "test-account"},
	}

	err := a.ReportScanFailure(context.Background(), scanfailure.ScanFailureCVE, "should fail", nil)

	assert.ErrorIs(t, err, domain.ErrCastingWorkload)
}

func TestBackendAdapter_ReportScanFailure_HTTPError(t *testing.T) {
	mockHTTP := func(_ httputils.IHttpClient, _ string, _ map[string]string, _ []byte, _ time.Duration) (*http.Response, error) {
		return nil, assert.AnError
	}

	a := &BackendAdapter{
		eventReceiverRestURL: "http://localhost:8080",
		clusterConfig:        armometadata.ClusterConfig{AccountID: "test-account"},
		httpPostFunc:         mockHTTP,
	}

	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:               "wlid://cluster-prod/namespace-default/deployment-nginx",
		ImageTagNormalized: "nginx:latest",
	})

	err := a.ReportScanFailure(ctx, scanfailure.ScanFailureBackendPost, scanfailure.ReasonResultUploadFailed, fmt.Errorf("connection refused"))

	assert.Error(t, err)
}

func TestBackendAdapter_ReportScanFailure_HTTPNon2xx(t *testing.T) {
	mockHTTP := func(_ httputils.IHttpClient, _ string, _ map[string]string, _ []byte, _ time.Duration) (*http.Response, error) {
		return &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(bytes.NewBufferString("internal server error")),
		}, nil
	}

	a := &BackendAdapter{
		eventReceiverRestURL: "http://localhost:8080",
		clusterConfig:        armometadata.ClusterConfig{AccountID: "test-account"},
		httpPostFunc:         mockHTTP,
	}

	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:               "wlid://cluster-prod/namespace-default/deployment-nginx",
		ImageTagNormalized: "nginx:latest",
	})

	err := a.ReportScanFailure(ctx, scanfailure.ScanFailureBackendPost, scanfailure.ReasonResultUploadFailed, fmt.Errorf("backend error"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestBackendAdapter_ReportScanFailure_NilError(t *testing.T) {
	var capturedReport scanfailure.ScanFailureReport

	mockHTTP := func(_ httputils.IHttpClient, _ string, _ map[string]string, body []byte, _ time.Duration) (*http.Response, error) {
		require.NoError(t, json.Unmarshal(body, &capturedReport))
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBuffer(nil)),
		}, nil
	}

	a := &BackendAdapter{
		eventReceiverRestURL: "http://localhost:8080",
		clusterConfig:        armometadata.ClusterConfig{AccountID: "test-account"},
		httpPostFunc:         mockHTTP,
	}

	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:               "wlid://cluster-prod/namespace-default/deployment-nginx",
		ImageTagNormalized: "nginx:1.25.0",
	})

	err := a.ReportScanFailure(ctx, scanfailure.ScanFailureSBOMGeneration, scanfailure.ReasonSBOMIncomplete, nil)

	require.NoError(t, err)
	assert.Equal(t, scanfailure.ReasonSBOMIncomplete, capturedReport.FailureReason)
	assert.Empty(t, capturedReport.Error, "Error field should be empty when scanErr is nil")
}

type mockSecurityExceptionRepo struct {
	exceptions        []sev1beta1.SecurityException
	clusterExceptions []sev1beta1.ClusterSecurityException
	err               error
}

func (m *mockSecurityExceptionRepo) GetSecurityExceptions(_ context.Context, _ string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error) {
	return m.exceptions, m.clusterExceptions, m.err
}

func TestGetCVEExceptions_MergesCRDExceptions(t *testing.T) {
	cloudPolicies := []armotypes.VulnerabilityExceptionPolicy{
		{
			PolicyType:            "vulnerabilityExceptionPolicy",
			VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-CLOUD-1"}},
		},
	}

	mockRepo := &mockSecurityExceptionRepo{
		exceptions: []sev1beta1.SecurityException{
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
				Spec: sev1beta1.SecurityExceptionSpec{
					Vulnerabilities: []sev1beta1.VulnerabilityException{
						{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-CRD-1"}},
					},
				},
			},
		},
	}

	a := &BackendAdapter{
		clusterConfig: armometadata.ClusterConfig{AccountID: "test-account"},
		getCVEExceptionsFunc: func(string, string, *identifiers.PortalDesignator, map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
			return cloudPolicies, nil
		},
		securityExceptionRepo: mockRepo,
	}

	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid: "wlid://cluster-test/namespace-default/deployment-myapp",
	})

	exceptions, err := a.GetCVEExceptions(ctx)
	require.NoError(t, err)
	assert.Len(t, exceptions, 2, "should merge cloud + CRD exceptions")
	assert.Equal(t, "CVE-CLOUD-1", exceptions[0].VulnerabilityPolicies[0].Name)
	assert.Equal(t, "CVE-CRD-1", exceptions[1].VulnerabilityPolicies[0].Name)
}
