package v1

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/containerscan"
	v1 "github.com/armosec/armoapi-go/containerscan/v1"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/armosec/utils-go/httputils"
	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/google/uuid"
	"github.com/kinbiko/jsonassert"
	beClientV1 "github.com/kubescape/backend/pkg/client/v1"
	sysreport "github.com/kubescape/backend/pkg/server/v1/systemreports"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubevuln/core/domain"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// securityExceptionGVR and clusterSecurityExceptionGVR mirror the unexported GVRs of the same
// names in package repositories (repositories/apiserver.go) — duplicated here because they're
// not exported across the package boundary, only used to register the fake dynamic client's
// list kinds for this test.
var (
	securityExceptionGVR = schema.GroupVersionResource{
		Group:    "kubescape.io",
		Version:  "v1beta1",
		Resource: "securityexceptions",
	}
	clusterSecurityExceptionGVR = schema.GroupVersionResource{
		Group:    "kubescape.io",
		Version:  "v1beta1",
		Resource: "clustersecurityexceptions",
	}
)

type testSecurityExceptionRepo struct {
	getSecurityExceptions func(context.Context, string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error)
	getWorkloadLabels     func(context.Context, string, string, string) (map[string]string, error)
	getNamespaceLabels    func(context.Context, string) (map[string]string, error)
}

func (r *testSecurityExceptionRepo) GetSecurityExceptions(ctx context.Context, namespace string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error) {
	if r != nil && r.getSecurityExceptions != nil {
		return r.getSecurityExceptions(ctx, namespace)
	}
	return nil, nil, nil
}

func (r *testSecurityExceptionRepo) GetWorkloadLabels(ctx context.Context, namespace, kind, name string) (map[string]string, error) {
	if r != nil && r.getWorkloadLabels != nil {
		return r.getWorkloadLabels(ctx, namespace, kind, name)
	}
	return nil, nil
}

func (r *testSecurityExceptionRepo) GetNamespaceLabels(ctx context.Context, name string) (map[string]string, error) {
	if r != nil && r.getNamespaceLabels != nil {
		return r.getNamespaceLabels(ctx, name)
	}
	return nil, nil
}

func scanContext(wlid, containerName, image string) context.Context {
	return context.WithValue(context.TODO(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:               wlid,
		ContainerName:      containerName,
		ImageTagNormalized: image,
	})
}

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
			got, _, err := a.GetCVEExceptions(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCVEExceptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBackendAdapter_GetCVEExceptions_Caches(t *testing.T) {
	calls := 0
	a := NewBackendAdapter("account", "apiServer", "eventReceiver", "", &repositories.NoOpSecurityExceptionRepository{})
	a.getCVEExceptionsFunc = func(_ string, _ string, _ *identifiers.PortalDesignator, _ map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
		calls++
		return []armotypes.VulnerabilityExceptionPolicy{{}}, nil
	}
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:          "wlid://cluster-c/namespace-ns/deployment-d",
		ContainerName: "container",
	})

	got1, _, err := a.GetCVEExceptions(ctx)
	assert.NoError(t, err)
	assert.Len(t, got1, 1)
	assert.Equal(t, 1, calls, "first call should hit the backend")

	got2, _, err := a.GetCVEExceptions(ctx)
	assert.NoError(t, err)
	assert.Equal(t, got1, got2)
	assert.Equal(t, 1, calls, "second call for the same workload should be served from cache")

	// a different workload must not be served from the other workload's cache entry
	otherCtx := context.WithValue(context.TODO(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:          "wlid://cluster-c/namespace-ns2/deployment-d2",
		ContainerName: "container2",
	})
	_, _, err = a.GetCVEExceptions(otherCtx)
	assert.NoError(t, err)
	assert.Equal(t, 2, calls, "a different workload should not hit the cache")
}

// TestBackendAdapter_GetCVEExceptions_CacheDoesNotOutliveCRDExpiry is a regression test:
// ConvertToVulnerabilityExceptionPolicies only checks an exception's expiresAt on a cache
// miss, so a cache entry that outlives the CRD exception it was built from would keep
// suppressing CVEs past that exception's own expiry until the fixed exceptionsCacheTTL
// elapsed. The cache entry's TTL must instead be bounded to the earliest expiresAt among
// its policies (see cacheTTLFor), so expiry forces a re-evaluation instead of a stale hit.
func TestBackendAdapter_GetCVEExceptions_CacheDoesNotOutliveCRDExpiry(t *testing.T) {
	expiresAt := metav1.NewTime(time.Now().Add(50 * time.Millisecond))
	crdCalls := 0
	a := NewBackendAdapter("account", "apiServer", "eventReceiver", "", &testSecurityExceptionRepo{
		getSecurityExceptions: func(context.Context, string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error) {
			crdCalls++
			return []sev1beta1.SecurityException{{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
				Spec: sev1beta1.SecurityExceptionSpec{
					ExpiresAt: &expiresAt,
					Vulnerabilities: []sev1beta1.VulnerabilityException{
						{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-SOON-EXPIRED"}, Status: sev1beta1.VulnerabilityStatusNotAffected},
					},
				},
			}}, nil, nil
		},
	})
	a.getCVEExceptionsFunc = func(_ string, _ string, _ *identifiers.PortalDesignator, _ map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
		return nil, nil
	}
	ctx := scanContext("wlid://cluster-c/namespace-ns/deployment-d", "container", "docker.io/library/nginx:1.25")

	exceptions, _, err := a.GetCVEExceptions(ctx)
	assert.NoError(t, err)
	assert.Len(t, exceptions, 1, "the not-yet-expired exception should suppress on the first call")
	assert.Equal(t, 1, crdCalls)

	time.Sleep(75 * time.Millisecond) // past expiresAt, well within exceptionsCacheTTL

	exceptions, _, err = a.GetCVEExceptions(ctx)
	assert.NoError(t, err)
	assert.Empty(t, exceptions, "an exception that expired mid-TTL must not keep being served from a stale cache entry")
	assert.Equal(t, 2, crdCalls, "expiry must force re-evaluation instead of a cache hit")
}

// TestBackendAdapter_GetCVEExceptions_DoesNotCacheAlreadyExpiredPolicy is a regression test:
// cacheTTLFor returns 0 (not negative) for a policy whose ExpirationDate has already passed
// by the time it's about to be cached (e.g. a cloud-sourced policy the backend API returned
// with a past expirationDate). akyoto/cache only reaps entries on its cleaning-interval
// sweep, not the instant a 0-second TTL elapses, so writing it at all would let it keep
// being served as a cache hit until that sweep ran. The write must be skipped outright.
func TestBackendAdapter_GetCVEExceptions_DoesNotCacheAlreadyExpiredPolicy(t *testing.T) {
	calls := 0
	past := time.Now().Add(-1 * time.Hour)
	a := NewBackendAdapter("account", "apiServer", "eventReceiver", "", &repositories.NoOpSecurityExceptionRepository{})
	a.getCVEExceptionsFunc = func(_ string, _ string, _ *identifiers.PortalDesignator, _ map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
		calls++
		return []armotypes.VulnerabilityExceptionPolicy{{ExpirationDate: &past}}, nil
	}
	ctx := scanContext("wlid://cluster-c/namespace-ns/deployment-d", "container", "docker.io/library/nginx:1.25")

	_, _, err := a.GetCVEExceptions(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 1, calls)

	_, _, err = a.GetCVEExceptions(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 2, calls, "an already-expired policy must not be cached, forcing a re-fetch on the next call")
}

func TestBackendAdapter_GetCVEExceptions_ImageScopedCRDPoliciesUseDistinctCacheEntries(t *testing.T) {
	a := NewBackendAdapter("account", "apiServer", "eventReceiver", "", &testSecurityExceptionRepo{
		getSecurityExceptions: func(context.Context, string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error) {
			return nil, []sev1beta1.ClusterSecurityException{{
				Spec: sev1beta1.SecurityExceptionSpec{
					Match: sev1beta1.ExceptionMatch{
						Images: []string{"docker.io/library/nginx:*"},
					},
					Vulnerabilities: []sev1beta1.VulnerabilityException{{
						Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2023-1"},
						Status:        sev1beta1.VulnerabilityStatusNotAffected,
					}},
				},
			}}, nil
		},
	})
	a.getCVEExceptionsFunc = func(_ string, _ string, _ *identifiers.PortalDesignator, _ map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
		return nil, nil
	}

	nginx, _, err := a.GetCVEExceptions(scanContext("wlid://cluster-c/namespace-ns/deployment-d", "container", "docker.io/library/nginx:1.25"))
	assert.NoError(t, err)
	assert.Len(t, nginx, 1)

	redis, _, err := a.GetCVEExceptions(scanContext("wlid://cluster-c/namespace-ns/deployment-d", "container", "docker.io/library/redis:7"))
	assert.NoError(t, err)
	assert.Empty(t, redis, "different images for the same workload must not share cached exception results")
}

func TestBackendAdapter_GetCVEExceptions_RegistryScansDoNotShareExceptionResults(t *testing.T) {
	a := NewBackendAdapter("account", "apiServer", "eventReceiver", "", &testSecurityExceptionRepo{
		getSecurityExceptions: func(context.Context, string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error) {
			return nil, []sev1beta1.ClusterSecurityException{{
				Spec: sev1beta1.SecurityExceptionSpec{
					Match: sev1beta1.ExceptionMatch{
						Images: []string{"docker.io/library/nginx:*"},
					},
					Vulnerabilities: []sev1beta1.VulnerabilityException{{
						Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2023-1"},
						Status:        sev1beta1.VulnerabilityStatusNotAffected,
					}},
				},
			}}, nil
		},
	})
	a.getCVEExceptionsFunc = func(_ string, _ string, _ *identifiers.PortalDesignator, _ map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
		return nil, nil
	}

	nginx, _, err := a.GetCVEExceptions(scanContext("", "", "docker.io/library/nginx:1.25"))
	assert.NoError(t, err)
	assert.Len(t, nginx, 1)

	redis, _, err := a.GetCVEExceptions(scanContext("", "", "docker.io/library/redis:7"))
	assert.NoError(t, err)
	assert.Empty(t, redis, "registry scans for different images must not share cached exception results")
}

func TestBackendAdapter_GetCVEExceptions_DoesNotCacheWhenCRDLookupFails(t *testing.T) {
	calls := 0
	a := NewBackendAdapter("account", "apiServer", "eventReceiver", "", &testSecurityExceptionRepo{
		getSecurityExceptions: func(context.Context, string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error) {
			return nil, nil, errors.New("boom")
		},
	})
	a.getCVEExceptionsFunc = func(_ string, _ string, _ *identifiers.PortalDesignator, _ map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
		calls++
		return []armotypes.VulnerabilityExceptionPolicy{{}}, nil
	}
	ctx := scanContext("wlid://cluster-c/namespace-ns/deployment-d", "container", "docker.io/library/nginx:1.25")

	_, _, err := a.GetCVEExceptions(ctx)
	assert.ErrorIs(t, err, domain.ErrExceptionsDegraded, "degraded CRD merges must be reported as incomplete")
	_, _, err = a.GetCVEExceptions(ctx)
	assert.ErrorIs(t, err, domain.ErrExceptionsDegraded, "degraded CRD merges must be reported as incomplete")
	assert.Equal(t, 2, calls, "degraded CRD merges should not be cached")
}

// TestBackendAdapter_GetCVEExceptions_DoesNotCacheWhenRealCRDListFails is an end-to-end
// regression test for #477. TestBackendAdapter_GetCVEExceptions_DoesNotCacheWhenCRDLookupFails
// above only proves GetCVEExceptions handles a non-nil error correctly — it injects that
// error directly via a fake securityExceptionRepo, so it never exercises the real
// repositories.APIServerStore.GetSecurityExceptions, which is the concrete implementation
// that actually talks to the Kubernetes API and is where the bug lived: it used to swallow
// List() failures and always return a nil error, so this exact "don't cache" guard could
// never fire against the real implementation despite passing against the fake. This test
// wires a real APIServerStore backed by a dynamic client that fails the CRD list, closing
// that gap.
func TestBackendAdapter_GetCVEExceptions_DoesNotCacheWhenRealCRDListFails(t *testing.T) {
	store := repositories.NewFakeAPIServerStorage("kubescape")
	store.DynamicClient.(*fakedynamic.FakeDynamicClient).PrependReactor("list", "securityexceptions", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("etcd timeout")
	})

	calls := 0
	a := NewBackendAdapter("account", "apiServer", "eventReceiver", "", store)
	a.getCVEExceptionsFunc = func(_ string, _ string, _ *identifiers.PortalDesignator, _ map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
		calls++
		return []armotypes.VulnerabilityExceptionPolicy{{}}, nil
	}
	ctx := scanContext("wlid://cluster-c/namespace-ns/deployment-d", "container", "docker.io/library/nginx:1.25")

	_, _, err := a.GetCVEExceptions(ctx)
	require.ErrorIs(t, err, domain.ErrExceptionsDegraded)
	_, _, err = a.GetCVEExceptions(ctx)
	require.ErrorIs(t, err, domain.ErrExceptionsDegraded)
	assert.Equal(t, 2, calls, "a real CRD list failure must disable caching, not just a faked one")
}

func TestBackendAdapter_GetCVEExceptions_DoesNotCacheUnresolvedSelectorLabels(t *testing.T) {
	calls := 0
	a := NewBackendAdapter("account", "apiServer", "eventReceiver", "", &testSecurityExceptionRepo{
		getSecurityExceptions: func(context.Context, string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error) {
			return []sev1beta1.SecurityException{{
				Spec: sev1beta1.SecurityExceptionSpec{
					Match: sev1beta1.ExceptionMatch{
						ObjectSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "nginx"},
						},
					},
					Vulnerabilities: []sev1beta1.VulnerabilityException{{
						Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2026-1"},
					}},
				},
			}}, nil, nil
		},
		getWorkloadLabels: func(context.Context, string, string, string) (map[string]string, error) {
			return nil, errors.New("lookup failed")
		},
	})
	a.getCVEExceptionsFunc = func(_ string, _ string, _ *identifiers.PortalDesignator, _ map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
		calls++
		return []armotypes.VulnerabilityExceptionPolicy{{}}, nil
	}
	ctx := scanContext("wlid://cluster-c/namespace-ns/deployment-d", "container", "docker.io/library/nginx:1.25")

	_, _, err := a.GetCVEExceptions(ctx)
	assert.ErrorIs(t, err, domain.ErrExceptionsDegraded, "selector-based degradation must be reported as incomplete")
	_, _, err = a.GetCVEExceptions(ctx)
	assert.ErrorIs(t, err, domain.ErrExceptionsDegraded, "selector-based degradation must be reported as incomplete")
	assert.Equal(t, 2, calls, "selector-based degradations should not be cached")
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
			httpPostFunc := func(ctx context.Context, httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte, timeOut time.Duration) (*http.Response, error) {
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

func TestBackendAdapter_SubmitCVE_RelevancySubset(t *testing.T) {
	// minimal valid image source so ParseImageManifest succeeds; the config is stored
	// base64-encoded (the []byte JSON field forces base64), matching real syft output
	config := base64.StdEncoding.EncodeToString([]byte(`{"architecture":"amd64","os":"linux","history":[],"rootfs":{"type":"layers","diff_ids":[]}}`))
	imageTarget := fmt.Sprintf(`{"userInput":"","imageID":"","manifestDigest":"","mediaType":"","tags":null,"imageSize":0,"layers":[{"mediaType":"","digest":"dummyLayer","size":0}],"manifest":null,"config":%q,"repoDigests":null,"architecture":"","os":""}`, config)

	match := func(id, pkg string) v1beta1.Match {
		return v1beta1.Match{
			Vulnerability: v1beta1.Vulnerability{
				VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: id},
			},
			Artifact: v1beta1.GrypePackage{Name: pkg},
		}
	}
	full := domain.CVEManifest{
		Content: &v1beta1.GrypeDocument{
			Source: &v1beta1.Source{Target: json.RawMessage(imageTarget)},
			Matches: []v1beta1.Match{
				match("CVE-2024-0001", "libssl1.1"),
				match("CVE-2024-0001", "openssl"),
				match("CVE-2024-0002", "zlib1g"),
			},
		},
	}
	cvep := domain.CVEManifest{
		Content: &v1beta1.GrypeDocument{
			Source: &v1beta1.Source{Target: json.RawMessage(imageTarget)},
			Matches: []v1beta1.Match{
				match("CVE-2024-0001", "libssl1.1"),
			},
		},
	}

	var gotReport v1.ScanResultReport
	httpPostFunc := func(ctx context.Context, httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte, timeOut time.Duration) (*http.Response, error) {
		var report v1.ScanResultReport
		if err := json.Unmarshal(body, &report); err != nil {
			t.Errorf("failed to unmarshal report: %v", err)
		}
		gotReport = report
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBuffer([]byte{})),
		}, nil
	}

	a := &BackendAdapter{
		getCVEExceptionsFunc: func(s, a string, designator *identifiers.PortalDesignator, headers map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
			return nil, nil
		},
		httpPostFunc:          httpPostFunc,
		securityExceptionRepo: &repositories.NoOpSecurityExceptionRepository{},
	}
	ctx := context.TODO()
	ctx = context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})

	require.NoError(t, a.SubmitCVE(ctx, full, cvep))

	require.Len(t, gotReport.Vulnerabilities, 3)
	wantRelevant := map[string]bool{
		"CVE-2024-0001+libssl1.1": true,
		"CVE-2024-0001+openssl":   false,
		"CVE-2024-0002+zlib1g":    false,
	}
	for _, v := range gotReport.Vulnerabilities {
		id := v.Name + "+" + v.RelatedPackageName
		want, ok := wantRelevant[id]
		require.True(t, ok, "unexpected vulnerability %s", id)
		require.NotNil(t, v.IsRelevant, "IsRelevant should be set for %s", id)
		assert.Equal(t, want, *v.IsRelevant, "IsRelevant mismatch for %s", id)
	}
	require.NotNil(t, gotReport.Summary)
	assert.Equal(t, int64(1), gotReport.Summary.RelevantCount)
}

func TestMarkRelevantVulnerabilities(t *testing.T) {
	vuln := func(name, pkg string) containerscan.CommonContainerVulnerabilityResult {
		return containerscan.CommonContainerVulnerabilityResult{
			Vulnerability: containerscan.Vulnerability{Name: name, RelatedPackageName: pkg},
		}
	}
	tests := []struct {
		name                string
		vulnerabilities     []containerscan.CommonContainerVulnerabilityResult
		relevantVulns       []containerscan.CommonContainerVulnerabilityResult
		wantRelevantVulnIDs map[string]bool // key: name+"+"+relatedPackageName
	}{
		{
			name: "same cve on multiple packages, only one executed",
			vulnerabilities: []containerscan.CommonContainerVulnerabilityResult{
				vuln("CVE-2024-0001", "libssl1.1"),
				vuln("CVE-2024-0001", "openssl"),
			},
			relevantVulns: []containerscan.CommonContainerVulnerabilityResult{
				vuln("CVE-2024-0001", "libssl1.1"),
			},
			wantRelevantVulnIDs: map[string]bool{
				"CVE-2024-0001+libssl1.1": true,
				"CVE-2024-0001+openssl":   false,
			},
		},
		{
			name: "single cve single package present in both scans",
			vulnerabilities: []containerscan.CommonContainerVulnerabilityResult{
				vuln("CVE-2024-0001", "libssl1.1"),
			},
			relevantVulns: []containerscan.CommonContainerVulnerabilityResult{
				vuln("CVE-2024-0001", "libssl1.1"),
			},
			wantRelevantVulnIDs: map[string]bool{
				"CVE-2024-0001+libssl1.1": true,
			},
		},
		{
			name: "disjoint cves",
			vulnerabilities: []containerscan.CommonContainerVulnerabilityResult{
				vuln("CVE-2024-0001", "libssl1.1"),
			},
			relevantVulns: []containerscan.CommonContainerVulnerabilityResult{
				vuln("CVE-2024-0002", "openssl"),
			},
			wantRelevantVulnIDs: map[string]bool{
				"CVE-2024-0001+libssl1.1": false,
			},
		},
		{
			name: "empty relevancy scan marks nothing relevant",
			vulnerabilities: []containerscan.CommonContainerVulnerabilityResult{
				vuln("CVE-2024-0001", "libssl1.1"),
			},
			wantRelevantVulnIDs: map[string]bool{
				"CVE-2024-0001+libssl1.1": false,
			},
		},
		{
			name: "mixed cves on multiple packages",
			vulnerabilities: []containerscan.CommonContainerVulnerabilityResult{
				vuln("CVE-2024-0001", "p1"),
				vuln("CVE-2024-0001", "p2"),
				vuln("CVE-2024-0002", "p3"),
			},
			relevantVulns: []containerscan.CommonContainerVulnerabilityResult{
				vuln("CVE-2024-0001", "p1"),
			},
			wantRelevantVulnIDs: map[string]bool{
				"CVE-2024-0001+p1": true,
				"CVE-2024-0001+p2": false,
				"CVE-2024-0002+p3": false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			markRelevantVulnerabilities(tt.vulnerabilities, tt.relevantVulns)
			for _, v := range tt.vulnerabilities {
				id := v.Name + "+" + v.RelatedPackageName
				want, ok := tt.wantRelevantVulnIDs[id]
				require.True(t, ok, "unexpected vulnerability %s", id)
				require.NotNil(t, v.IsRelevant, "IsRelevant should be set for %s", id)
				assert.Equal(t, want, *v.IsRelevant, "IsRelevant mismatch for %s", id)
			}
		})
	}
}

// A package name is not unique within an image: two versions of one library sitting side by
// side is ordinary in Java and Node images, and each produces its own vulnerability record
// under the same name. Keying relevancy on the CVE and the name alone marked the version that
// was never loaded relevant because the other one was, which is the opposite of what the
// relevancy scan is for.
func TestMarkRelevantVulnerabilities_DistinguishesPackageVersions(t *testing.T) {
	vuln := func(cve, pkg, version string) containerscan.CommonContainerVulnerabilityResult {
		return containerscan.CommonContainerVulnerabilityResult{
			Vulnerability: containerscan.Vulnerability{
				Name:               cve,
				RelatedPackageName: pkg,
				PackageVersion:     version,
			},
		}
	}

	vulnerabilities := []containerscan.CommonContainerVulnerabilityResult{
		vuln("CVE-2024-0001", "commons-collections", "3.2.1"),
		vuln("CVE-2024-0001", "commons-collections", "4.4"),
		vuln("CVE-2024-0002", "log4j-core", "2.14.1"),
	}
	// only the 4.4 copy is actually loaded
	relevant := []containerscan.CommonContainerVulnerabilityResult{
		vuln("CVE-2024-0001", "commons-collections", "4.4"),
	}

	markRelevantVulnerabilities(vulnerabilities, relevant)

	want := map[string]bool{
		"CVE-2024-0001+commons-collections@3.2.1": false,
		"CVE-2024-0001+commons-collections@4.4":   true,
		"CVE-2024-0002+log4j-core@2.14.1":         false,
	}
	for _, v := range vulnerabilities {
		id := v.Name + "+" + v.RelatedPackageName + "@" + v.PackageVersion
		expected, ok := want[id]
		require.True(t, ok, "unexpected vulnerability %s", id)
		require.NotNil(t, v.IsRelevant, "IsRelevant should be set for %s", id)
		assert.Equal(t, expected, *v.IsRelevant, "IsRelevant mismatch for %s", id)
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
		name       string
		step       int
		wantStatus string
		wantErr    bool
	}{
		{
			name:       "send status",
			step:       1,
			wantStatus: sysreport.JobStarted,
		},
		{
			name:       "inqueueing step reports started",
			step:       0,
			wantStatus: sysreport.JobStarted,
		},
		{
			name:       "second dequeueing step reports success",
			step:       2,
			wantStatus: sysreport.JobSuccess,
		},
		{
			name:       "final dequeueing step reports done",
			step:       3,
			wantStatus: sysreport.JobDone,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			a := &BackendAdapter{
				sendStatusFunc: func(sender *beClientV1.BaseReportSender, s string, b bool) {
					called = true
					assert.Equal(t, tt.wantStatus, s)
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
			assert.True(t, called, "sendStatusFunc was never invoked")
		})
	}
}

func TestBackendAdapter_ReportScanFailure_WorkloadScan(t *testing.T) {
	var capturedURL string
	var capturedReport scanfailure.ScanFailureReport

	mockHTTP := func(_ context.Context, _ httputils.IHttpClient, fullURL string, _ map[string]string, body []byte, _ time.Duration) (*http.Response, error) {
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

	mockHTTP := func(_ context.Context, _ httputils.IHttpClient, _ string, _ map[string]string, body []byte, _ time.Duration) (*http.Response, error) {
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
	mockHTTP := func(_ context.Context, _ httputils.IHttpClient, _ string, _ map[string]string, _ []byte, _ time.Duration) (*http.Response, error) {
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
	mockHTTP := func(_ context.Context, _ httputils.IHttpClient, _ string, _ map[string]string, _ []byte, _ time.Duration) (*http.Response, error) {
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

	mockHTTP := func(_ context.Context, _ httputils.IHttpClient, _ string, _ map[string]string, body []byte, _ time.Duration) (*http.Response, error) {
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
	exceptions         []sev1beta1.SecurityException
	clusterExceptions  []sev1beta1.ClusterSecurityException
	err                error
	workloadLabels     map[string]string
	namespaceLabels    map[string]string
	workloadLabelsErr  error
	namespaceLabelsErr error
}

func (m *mockSecurityExceptionRepo) GetSecurityExceptions(_ context.Context, _ string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error) {
	return m.exceptions, m.clusterExceptions, m.err
}

func (m *mockSecurityExceptionRepo) GetWorkloadLabels(_ context.Context, _, _, _ string) (map[string]string, error) {
	return m.workloadLabels, m.workloadLabelsErr
}

func (m *mockSecurityExceptionRepo) GetNamespaceLabels(_ context.Context, _ string) (map[string]string, error) {
	return m.namespaceLabels, m.namespaceLabelsErr
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
						{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-CRD-1"}, Status: sev1beta1.VulnerabilityStatusNotAffected},
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

	exceptions, stats, err := a.GetCVEExceptions(ctx)
	require.NoError(t, err)
	assert.Len(t, exceptions, 2, "should merge cloud + CRD exceptions")
	assert.Equal(t, "CVE-CLOUD-1", exceptions[0].VulnerabilityPolicies[0].Name)
	assert.Equal(t, "CVE-CRD-1", exceptions[1].VulnerabilityPolicies[0].Name)
	assert.Empty(t, stats.ExpiredBySource, "nothing expired in this scenario")
}

func TestGetCVEExceptions_ScopesCRDByMatch(t *testing.T) {
	// A cluster exception scoped to redis images must NOT be applied to an
	// nginx workload — this is the fail-open regression the match logic fixes.
	mockRepo := &mockSecurityExceptionRepo{
		clusterExceptions: []sev1beta1.ClusterSecurityException{
			{
				Spec: sev1beta1.SecurityExceptionSpec{
					Match: sev1beta1.ExceptionMatch{Images: []string{"docker.io/library/redis:*"}},
					Vulnerabilities: []sev1beta1.VulnerabilityException{
						{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-REDIS-ONLY"}, Status: sev1beta1.VulnerabilityStatusNotAffected},
					},
				},
			},
		},
	}

	a := &BackendAdapter{
		clusterConfig: armometadata.ClusterConfig{AccountID: "test-account"},
		getCVEExceptionsFunc: func(string, string, *identifiers.PortalDesignator, map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
			return nil, nil
		},
		securityExceptionRepo: mockRepo,
	}

	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:               "wlid://cluster-test/namespace-production/deployment-nginx",
		ImageTagNormalized: "docker.io/library/nginx:1.25",
	})

	exceptions, _, err := a.GetCVEExceptions(ctx)
	require.NoError(t, err)
	assert.Empty(t, exceptions, "redis-scoped exception must not apply to an nginx workload")
}

// recordingHTTPClient counts how many times it served a request, so tests can prove that the
// exact same client instance was reused across multiple call sites instead of merely asserting
// that a getter echoes back the field it was handed.
type recordingHTTPClient struct {
	mu    sync.Mutex
	calls int
}

func (c *recordingHTTPClient) Do(_ *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
}

func (c *recordingHTTPClient) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestBackendAdapter_HTTPClientReuse(t *testing.T) {
	stub := &recordingHTTPClient{}
	a := &BackendAdapter{
		clusterConfig:        armometadata.ClusterConfig{AccountID: "test-account"},
		eventReceiverRestURL: "http://example.invalid",
		httpClient:           stub,
		httpPostFunc:         httpPostWithContext,
		sendStatusFunc: func(sender *beClientV1.BaseReportSender, status string, sendReport bool) {
			sender.SendStatus(status, sendReport)
		},
	}

	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:          "wlid",
		ContainerName: "container",
		ImageTag:      "imageTag",
		ImageHash:     "imageHash",
	})
	require.NoError(t, a.ReportError(ctx, fmt.Errorf("boom")))
	assert.Equal(t, 1, stub.Calls(), "ReportError should use the shared httpClient")

	require.NoError(t, a.SendStatus(ctx, 0))
	assert.Equal(t, 2, stub.Calls(), "SendStatus should use the shared httpClient")

	require.NoError(t, a.postResults(ctx, v1.ScanResultReport{}, a.eventReceiverRestURL, "imageTag", "wlid"))
	assert.Equal(t, 3, stub.Calls(), "postResults should use the shared httpClient")

	require.NoError(t, a.ReportScanFailure(ctx, scanfailure.ScanFailureSBOMGeneration, scanfailure.ReasonSBOMGenerationFailed, nil))
	assert.Equal(t, 4, stub.Calls(), "ReportScanFailure should use the shared httpClient")

	assert.Same(t, stub, a.getHTTPClient(), "getHTTPClient should keep returning the exact configured instance")
}

func TestSendError_DeliversImmediatelyWhenChannelHasRoom(t *testing.T) {
	// Realistic shape from the reported bug: a buffered channel with free space, hit while ctx
	// is already cancelled. The send must still win deterministically instead of racing a
	// random select against ctx.Done().
	ch := make(chan error, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sendError(ctx, ch, fmt.Errorf("overflow error"))

	require.Len(t, ch, 1)
	assert.EqualError(t, <-ch, "overflow error")
}

func TestSendError_BlocksOnFullChannelUntilCtxCancelledThenDrops(t *testing.T) {
	// This is the scenario the PR description actually claims to guard: a full channel with a
	// live context. sendError must block until either the channel drains or ctx is cancelled,
	// only dropping the error once that happens.
	ch := make(chan error, 1)
	ch <- fmt.Errorf("first error")
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		sendError(ctx, ch, fmt.Errorf("second error"))
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("sendError returned before the channel had room or ctx was cancelled")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sendError did not return after context cancellation")
	}

	require.Len(t, ch, 1, "second error should have been dropped since the channel stayed full")
	assert.EqualError(t, <-ch, "first error")
}

// blockingHTTPClient's Do blocks until the request's own context is done, simulating how a real
// net/http.Transport aborts an in-flight request once its context is cancelled. It lets tests
// prove that cancelling the caller's ctx actually reaches the request (and the retry loop around
// it), instead of the call quietly running to completion regardless (#446).
type blockingHTTPClient struct {
	calls int32
}

func (c *blockingHTTPClient) Do(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&c.calls, 1)
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func (c *blockingHTTPClient) Calls() int32 {
	return atomic.LoadInt32(&c.calls)
}

func TestBackendAdapter_PostResultsAbortsPromptlyOnCtxCancellation(t *testing.T) {
	client := &blockingHTTPClient{}
	a := &BackendAdapter{
		eventReceiverRestURL: "http://example.invalid",
		httpClient:           client,
		httpPostFunc:         httpPostWithContext,
	}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- a.postResults(ctx, v1.ScanResultReport{}, a.eventReceiverRestURL, "imageTag", "wlid")
	}()

	// give postResults time to reach the (blocking) HTTP call before cancelling
	require.Eventually(t, func() bool { return client.Calls() > 0 }, time.Second, time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.Error(t, err, "postResults should return an error once the request is aborted by ctx cancellation")
	case <-time.After(2 * time.Second):
		t.Fatal("postResults did not return promptly after ctx was cancelled; the retry loop is not ctx-aware")
	}
}

func TestBackendAdapter_ReportScanFailureAbortsPromptlyOnCtxCancellation(t *testing.T) {
	client := &blockingHTTPClient{}
	a := &BackendAdapter{
		eventReceiverRestURL: "http://example.invalid",
		clusterConfig:        armometadata.ClusterConfig{AccountID: "test-account"},
		httpClient:           client,
		httpPostFunc:         httpPostWithContext,
	}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{
		Wlid:               "wlid://cluster-prod/namespace-default/deployment-nginx",
		ImageTagNormalized: "nginx:latest",
	}))

	done := make(chan error, 1)
	go func() {
		done <- a.ReportScanFailure(ctx, scanfailure.ScanFailureBackendPost, scanfailure.ReasonResultUploadFailed, fmt.Errorf("connection refused"))
	}()

	require.Eventually(t, func() bool { return client.Calls() > 0 }, time.Second, time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.Error(t, err, "ReportScanFailure should return an error once the request is aborted by ctx cancellation")
	case <-time.After(2 * time.Second):
		t.Fatal("ReportScanFailure did not return promptly after ctx was cancelled; the retry loop is not ctx-aware")
	}
}

func TestBackendAdapter_SubmitCVE_SkipsChunksWhenSummaryFails(t *testing.T) {
	var chunkPosts int32
	httpPostFunc := func(_ context.Context, _ httputils.IHttpClient, _ string, _ map[string]string, body []byte, _ time.Duration) (*http.Response, error) {
		var report v1.ScanResultReport
		require.NoError(t, json.Unmarshal(body, &report))
		if report.Summary != nil {
			// this is the summary report (possibly combined with the first chunk) - fail it
			return nil, fmt.Errorf("simulated summary post failure")
		}
		atomic.AddInt32(&chunkPosts, 1)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBuffer(nil)),
		}, nil
	}

	a := &BackendAdapter{
		clusterConfig: armometadata.ClusterConfig{},
		getCVEExceptionsFunc: func(string, string, *identifiers.PortalDesignator, map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
			return nil, nil
		},
		httpPostFunc:          httpPostFunc,
		securityExceptionRepo: &repositories.NoOpSecurityExceptionRepository{},
	}
	ctx := context.TODO()
	ctx = context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})

	cve := *fileToType[domain.CVEManifest]("testdata/nginx-cve.json")
	err := a.SubmitCVE(ctx, cve, domain.CVEManifest{})

	require.Error(t, err, "SubmitCVE should surface the summary post failure")
	assert.Equal(t, int32(0), atomic.LoadInt32(&chunkPosts), "no vulnerability chunk should be posted once the summary failed")
}

func TestShouldRetryReport(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   bool
	}{
		{http.StatusUnauthorized, false},
		{http.StatusForbidden, false},
		{http.StatusNotFound, false},
		{http.StatusInternalServerError, true}, // #486
		{http.StatusTooManyRequests, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			got := shouldRetryReport(&http.Response{StatusCode: tc.status})
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSubmitCVE_NoPanicOnNonStringArgs(t *testing.T) {
	backend := &BackendAdapter{
		clusterConfig:         armometadata.ClusterConfig{},
		securityExceptionRepo: &testSecurityExceptionRepo{},
		getCVEExceptionsFunc: func(string, string, *identifiers.PortalDesignator, map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
			return nil, nil
		},
		sendStatusFunc: func(*beClientV1.BaseReportSender, string, bool) {},
		httpPostFunc: func(context.Context, httputils.IHttpClient, string, map[string]string, []byte, time.Duration) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		},
	}
	ctx := context.WithValue(context.Background(), domain.TimestampKey{}, int64(123456))
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, "56275825-4c07-4e3f-9a4c-53f05b0d0c2e")

	// Create a scan command with non-string args
	workload := domain.ScanCommand{
		Wlid: "wlid://cluster-x/namespace-y/deployment-z",
		Args: map[string]interface{}{
			identifiers.AttributeRegistryName: 12345, // Not a string!
		},
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	cve := domain.CVEManifest{
		Content: &v1beta1.GrypeDocument{},
	}
	cvep := domain.CVEManifest{}

	// Ensure it does NOT panic
	assert.NotPanics(t, func() {
		_ = backend.SubmitCVE(ctx, cve, cvep)
	})
}

func TestBackendAdapter_ReportError_NilError(t *testing.T) {
	backend := &BackendAdapter{}
	err := backend.ReportError(context.Background(), nil)
	assert.NoError(t, err)
}

func TestBackendAdapter_ReportErrorAbortsPromptlyOnCtxCancellation(t *testing.T) {
	backend := &BackendAdapter{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := backend.ReportError(ctx, errors.New("boom"))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestBackendAdapter_SendStatusAbortsPromptlyOnCtxCancellation(t *testing.T) {
	backend := &BackendAdapter{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := backend.SendStatus(ctx, 0)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestHttpPostWithContext_IncludesResponseBodyInError verifies that httpPostWithContext captures non-200 response body snippets up to 512 bytes and truncates beyond that boundary.
func TestHttpPostWithContext_IncludesResponseBodyInError(t *testing.T) {
	// Marker 'B' is at byte index 512 (the 513th byte), proving truncation occurs at exactly 512 bytes.
	longBody := strings.Repeat("A", 512) + "B" + "EXCLUSIVE_TAIL_HEADER"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(longBody))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := httpPostWithContext(ctx, http.DefaultClient, ts.URL, nil, []byte("data"), 100*time.Millisecond)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "received status code: 429")
	assert.Contains(t, err.Error(), strings.Repeat("A", 512))
	assert.NotContains(t, err.Error(), "B")
	assert.NotContains(t, err.Error(), "EXCLUSIVE_TAIL_HEADER")
}

// TestHttpPostWithContext_EmptyResponseBody verifies the status-code-only error format when non-200 response body is empty.
func TestHttpPostWithContext_EmptyResponseBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := httpPostWithContext(ctx, http.DefaultClient, ts.URL, nil, []byte("data"), 100*time.Millisecond)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "received status code: 500", err.Error())
}

// TestBackendAdapter_PostResults_429RateLimitLogging verifies that postResults detects 429 rate-limiting errors and logs vendor guidance.
func TestBackendAdapter_PostResults_429RateLimitLogging(t *testing.T) {
	backend := &BackendAdapter{
		httpPostFunc: func(context.Context, httputils.IHttpClient, string, map[string]string, []byte, time.Duration) (*http.Response, error) {
			return nil, fmt.Errorf("received status code: 429, body: quota exceeded")
		},
	}

	report := v1.ScanResultReport{
		Designators: identifiers.PortalDesignator{
			Attributes: map[string]string{
				identifiers.AttributeCustomerGUID: "test-guid",
			},
		},
	}

	// Capture logger output to verify the rate-limit guidance log message
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	logger.InitLogger("pretty")

	err := backend.postResults(context.Background(), report, "http://localhost", "nginx:latest", "wlid://cluster-a/namespace-b/deployment-c")

	_ = w.Close()
	os.Stderr = oldStderr
	logger.InitLogger("pretty")

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	logOutput := buf.String()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "429")
	assert.Contains(t, err.Error(), "quota exceeded")
	assert.Contains(t, logOutput, "failed sending vulnerabilities report due to rate limiting (429 Too Many Requests)")
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantOK    bool
		wantAbout time.Duration
	}{
		{"absent header", "", false, 0},
		{"valid seconds", "120", true, 120 * time.Second},
		{"zero seconds", "0", true, 0},
		{"negative seconds rejected", "-5", false, 0},
		{"overflowing seconds rejected", "9223372037", false, 0},
		{"garbage value rejected", "not-a-valid-value", false, 0},
		{"valid future HTTP-date", time.Now().Add(2 * time.Hour).UTC().Format(http.TimeFormat), true, 2 * time.Hour},
		{"past HTTP-date clamped to zero, not negative", time.Now().Add(-2 * time.Hour).UTC().Format(http.TimeFormat), true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			if tt.header != "" {
				resp.Header.Set("Retry-After", tt.header)
			}
			wait, ok := parseRetryAfter(resp)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.InDelta(t, tt.wantAbout.Seconds(), wait.Seconds(), 5,
					"parsed wait should be close to the expected duration")
			}
		})
	}
}

// TestHttpPostWithContext_HonorsRetryAfter is the real end-to-end proof: a server that
// responds 429 with an explicit Retry-After, then 200 on the next attempt. The elapsed
// time should be close to the server's requested wait, not the default exponential
// backoff's much shorter initial interval (~500ms), proving the header is actually read
// and honored rather than ignored.
func TestHttpPostWithContext_HonorsRetryAfter(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	start := time.Now()
	resp, err := httpPostWithContext(context.Background(), server.Client(), server.URL, nil, nil, 10*time.Second)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(2), atomic.LoadInt32(&attempts))
	assert.GreaterOrEqual(t, elapsed, 900*time.Millisecond,
		"should have waited close to the requested 1s, not the default ~500ms backoff interval")
	assert.Less(t, elapsed, 5*time.Second, "should not have waited far longer than requested")
}
