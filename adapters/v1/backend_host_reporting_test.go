package v1

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	cs "github.com/armosec/armoapi-go/containerscan"
	csv1 "github.com/armosec/armoapi-go/containerscan/v1"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/utils-go/httputils"
	instanceidv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

func hostReportingFixture(t *testing.T) (context.Context, domain.ScanCommand, domain.CVEManifest, domain.CVEManifest) {
	t.Helper()
	instance, err := instanceidv1.GenerateInstanceIDFromString("apiVersion-v1/namespace-host/kind-Node/name-host-node.a/hostName-host")
	require.NoError(t, err)
	slug, err := instance.GetSlug(false)
	require.NoError(t, err)
	workload := domain.ScanCommand{Wlid: "wlid://cluster-unknown/namespace-host/host-node.a", ContainerName: "host", InstanceID: slug,
		Args: map[string]interface{}{domain.ArgsNamespace: "storage", identifiers.AttributeRegistryName: "contaminated", identifiers.AttributeVolumeId: "contaminated"}}
	full := domain.CVEManifest{Name: "host-inventory", SBOMCreatorName: "syft", SBOMCreatorVersion: "v1.42.3",
		Labels:      map[string]string{helpersv1.ArtifactTypeMetadataKey: helpersv1.HostArtifactType},
		Annotations: map[string]string{helpersv1.WlidMetadataKey: workload.Wlid, domain.HostInventoryUIDAnnotationKey: "inventory-uid", domain.HostInventoryResourceVersionAnnotationKey: "42"},
		Content:     &v1beta1.GrypeDocument{Source: &v1beta1.Source{Type: "directory", Target: json.RawMessage(`{"path":"/host"}`)}},
	}
	for _, id := range []string{"CVE-2026-1", "CVE-2026-2"} {
		full.Content.Matches = append(full.Content.Matches, v1beta1.Match{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: id, Severity: "High"}}, Artifact: v1beta1.GrypePackage{Name: "tool", Version: "1", Type: "rpm", PURL: "pkg:rpm/tool@1"}})
	}
	relevant := full
	relevant.Name = slug
	relevant.Annotations = maps.Clone(full.Annotations)
	relevant.Annotations[domain.HostProfilePathsHashAnnotationKey] = "profile-paths-hash"
	relevant.Content = full.Content.DeepCopy()
	relevant.Content.Matches = relevant.Content.Matches[:1]
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, "source-scan-id")
	ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1791470000))
	return ctx, workload, full, relevant
}

func captureHostReports(t *testing.T, cluster string, captured *[]csv1.ScanResultReport) *BackendAdapter {
	t.Helper()
	var mu sync.Mutex
	return NewBackendAdapter("customer", "api", "https://report.example", "", &repositories.NoOpSecurityExceptionRepository{}).WithClusterName(cluster).WithBackendClient(&MockBackendClient{
		GetCVEExceptionsFunc: func(_ context.Context, _, _ string, designator *identifiers.PortalDesignator, _ map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
			require.Equal(t, cluster, designator.Attributes["scope.cluster"])
			require.Equal(t, "node", designator.Attributes["scope.kind"])
			require.Empty(t, designator.Attributes["scope.namespace"])
			return nil, nil
		},
		HttpPostFunc: func(_ context.Context, _ httputils.IHttpClient, _ string, _ map[string]string, body []byte, _ time.Duration) (*http.Response, error) {
			var report csv1.ScanResultReport
			require.NoError(t, json.Unmarshal(body, &report))
			mu.Lock()
			*captured = append(*captured, report)
			mu.Unlock()
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
		},
	})
}

func TestHostUploadIdentityBoundToSnapshotAndExecution(t *testing.T) {
	_, workload, full, relevant := hostReportingFixture(t)
	adapter := NewBackendAdapter("customer", "api", "report", "", nil).WithClusterName("cluster")
	image, _, first, err := adapter.hostReportWorkload(workload, full, relevant, "scan", "execution")
	require.NoError(t, err)
	_, _, retry, err := adapter.hostReportWorkload(workload, full, relevant, "scan", "execution")
	require.NoError(t, err)
	require.Equal(t, first, retry)
	_, _, fresh, err := adapter.hostReportWorkload(workload, full, relevant, "scan", "new-execution")
	require.NoError(t, err)
	require.NotEqual(t, first, fresh)
	relevant.Annotations[domain.HostProfilePathsHashAnnotationKey] = "changed"
	sameInventory, _, changedProfile, err := adapter.hostReportWorkload(workload, full, relevant, "scan", "execution")
	require.NoError(t, err)
	require.NotEqual(t, first, changedProfile)
	require.Equal(t, image.ImageHash, sameInventory.ImageHash)
	full.Annotations[domain.HostInventoryResourceVersionAnnotationKey], relevant.Annotations[domain.HostInventoryResourceVersionAnnotationKey] = "43", "43"
	newInventory, _, changedInventory, err := adapter.hostReportWorkload(workload, full, relevant, "scan", "execution")
	require.NoError(t, err)
	require.NotEqual(t, changedProfile, changedInventory)
	require.NotEqual(t, image.ImageHash, newInventory.ImageHash)
}

func TestSubmitHostCVERetriesAndChunksShareExecutionIdentity(t *testing.T) {
	ctx, _, full, relevant := hostReportingFixture(t)
	for i := 0; i < 20; i++ {
		match := full.Content.Matches[0]
		match.Vulnerability.Description = strings.Repeat("description ", 250)
		full.Content.Matches = append(full.Content.Matches, match)
	}
	var mu sync.Mutex
	var received []csv1.ScanResultReport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report csv1.ScanResultReport
		require.NoError(t, json.NewDecoder(r.Body).Decode(&report))
		mu.Lock()
		received = append(received, report)
		firstAttempt := len(received) == 1
		mu.Unlock()
		if firstAttempt {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	adapter := NewBackendAdapter("customer", "api", server.URL, "", &repositories.NoOpSecurityExceptionRepository{}).WithClusterName("cluster").WithBackendClient(&MockBackendClient{
		GetCVEExceptionsFunc: func(context.Context, string, string, *identifiers.PortalDesignator, map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
			return nil, nil
		},
		HttpPostFunc: httpPostWithContext,
	})
	require.NoError(t, adapter.SubmitCVE(ctx, full, relevant))
	mu.Lock()
	defer mu.Unlock()
	require.Greater(t, len(received), 3, "must exercise both retry and multiple reports")
	require.Equal(t, received[0].PaginationInfo.ReportNumber, received[1].PaginationInfo.ReportNumber)
	lastReports := 0
	for _, report := range received {
		require.Equal(t, received[0].ContainerScanID, report.ContainerScanID)
		for _, finding := range report.Vulnerabilities {
			require.Equal(t, report.ContainerScanID, finding.ContainerScanID)
		}
		if report.Summary != nil {
			require.Equal(t, report.ContainerScanID, report.Summary.ContainerScanID)
		}
		if report.PaginationInfo.IsLastReport {
			lastReports++
		}
	}
	require.Equal(t, 1, lastReports)
}

func TestSubmitHostCVECanonicalSerializedReport(t *testing.T) {
	ctx, workload, full, relevant := hostReportingFixture(t)
	before, err := json.Marshal([]interface{}{workload, full, relevant})
	require.NoError(t, err)
	var reports []csv1.ScanResultReport
	adapter := captureHostReports(t, "armo-dev-stage", &reports)
	require.NoError(t, adapter.SubmitCVE(ctx, full, relevant))
	require.Len(t, reports, 1)
	report := reports[0]
	serialized, err := json.Marshal(report)
	require.NoError(t, err)
	t.Logf("serialized host report: %s", serialized)
	require.True(t, report.PaginationInfo.IsLastReport)
	require.True(t, armotypes.ValidateContainerScanID(report.ContainerScanID))
	require.NotEqual(t, "source-scan-id", report.ContainerScanID)
	attrs := report.Designators.Attributes
	for key, value := range map[string]string{identifiers.AttributeKind: "Node", identifiers.AttributeApiVersion: "v1", identifiers.AttributeNamespace: "", identifiers.AttributeCluster: "armo-dev-stage", identifiers.AttributeName: "node.a", identifiers.AttributeContainerName: "host", identifiers.AttributeCustomerGUID: "customer", helpersv1.WlidMetadataKey: workload.Wlid, domain.HostInventoryUIDAnnotationKey: "inventory-uid", domain.HostInventoryResourceVersionAnnotationKey: "42", helpersv1.ScanIdMetadataKey: "source-scan-id"} {
		require.Contains(t, attrs, key)
		require.Equal(t, value, attrs[key])
	}
	require.NotContains(t, attrs, identifiers.AttributeRegistryName)
	require.NotContains(t, attrs, identifiers.AttributeVolumeId)
	require.Equal(t, cs.GenerateWorkloadHash(attrs), attrs[identifiers.AttributeWorkloadHash])
	require.NotNil(t, report.Summary)
	require.True(t, report.Summary.HasRelevancyData)
	require.Equal(t, "wlid://cluster-armo-dev-stage/namespace-*/node-node.a", report.Summary.WLID)
	require.Equal(t, attrs, report.Summary.Designators.Attributes)
	require.Empty(t, report.Summary.Namespace)
	require.Equal(t, "v1", report.Summary.ApiVersion)
	require.Nil(t, report.Summary.ImageManifest)
	require.True(t, strings.HasPrefix(report.Summary.ImageID, "directory-inventory:"))
	require.Equal(t, report.ContainerScanID, report.Summary.ContainerScanID)
	require.Len(t, report.Vulnerabilities, 2)
	for i, finding := range report.Vulnerabilities {
		require.Equal(t, attrs, finding.Designators.Attributes)
		require.Equal(t, report.Summary.WLID, finding.WLID)
		require.Equal(t, report.Summary.ImageID, finding.ImageID)
		require.Equal(t, report.ContainerScanID, finding.ContainerScanID)
		require.NotNil(t, finding.IsRelevant)
		require.Equal(t, i == 0, *finding.IsRelevant)
		require.Equal(t, report.Summary.Context, finding.Context)
	}
	after, err := json.Marshal([]interface{}{workload, full, relevant})
	require.NoError(t, err)
	require.JSONEq(t, string(before), string(after), "reporting must not mutate storage inputs")
}

func TestSubmitHostCVERevisionAndRelevanceIdentity(t *testing.T) {
	ctx, _, full, relevant := hostReportingFixture(t)
	var reports []csv1.ScanResultReport
	adapter := captureHostReports(t, "cluster", &reports)
	require.NoError(t, adapter.SubmitCVE(ctx, full, relevant))
	require.NoError(t, adapter.SubmitCVE(ctx, full, relevant))
	require.NotEqual(t, reports[0].ContainerScanID, reports[1].ContainerScanID, "fresh execution may observe changed DB or exception policies")
	require.Equal(t, reports[0].Summary.ImageID, reports[1].Summary.ImageID)
	relevant.Annotations[domain.HostProfilePathsHashAnnotationKey] = "changed-profile-paths"
	relevant.Content.Matches = nil
	require.NoError(t, adapter.SubmitCVE(ctx, full, relevant))
	require.NotEqual(t, reports[0].ContainerScanID, reports[2].ContainerScanID)
	require.Equal(t, reports[0].Summary.ImageID, reports[2].Summary.ImageID)
	for _, finding := range reports[2].Vulnerabilities {
		require.NotNil(t, finding.IsRelevant)
		require.False(t, *finding.IsRelevant)
	}
	full.Annotations[domain.HostInventoryResourceVersionAnnotationKey] = "43"
	relevant.Annotations[domain.HostInventoryResourceVersionAnnotationKey] = "43"
	full.Content.Matches = nil
	require.NoError(t, adapter.SubmitCVE(ctx, full, relevant))
	require.NotEqual(t, reports[2].ContainerScanID, reports[3].ContainerScanID)
	require.NotEqual(t, reports[2].Summary.ImageID, reports[3].Summary.ImageID)
	require.Empty(t, reports[3].Vulnerabilities)
	require.NotEmpty(t, reports[3].Summary.ImageID)
	require.True(t, reports[3].Summary.HasRelevancyData)
	require.True(t, reports[3].PaginationInfo.IsLastReport)
}

func TestSubmitHostCVEInvalidConfigurationAndIdentity(t *testing.T) {
	for _, cluster := range []string{"", "unknown", "bad/cluster"} {
		t.Run(cluster, func(t *testing.T) {
			ctx, _, full, relevant := hostReportingFixture(t)
			var reports []csv1.ScanResultReport
			require.Error(t, captureHostReports(t, cluster, &reports).SubmitCVE(ctx, full, relevant))
			require.Empty(t, reports)
		})
	}
	for _, mutation := range []func(*domain.ScanCommand, *domain.CVEManifest, *domain.CVEManifest){
		func(w *domain.ScanCommand, _, _ *domain.CVEManifest) { w.InstanceID = "unrelated" },
		func(w *domain.ScanCommand, _, _ *domain.CVEManifest) { w.Wlid += "/extra" },
		func(_ *domain.ScanCommand, f, _ *domain.CVEManifest) { f.Content.Source.Type = "image" },
		func(_ *domain.ScanCommand, f, _ *domain.CVEManifest) {
			delete(f.Annotations, domain.HostInventoryUIDAnnotationKey)
		},
		func(_ *domain.ScanCommand, _, r *domain.CVEManifest) {
			r.Annotations[domain.HostInventoryResourceVersionAnnotationKey] = "mismatch"
		},
		func(_ *domain.ScanCommand, _, r *domain.CVEManifest) {
			delete(r.Annotations, domain.HostProfilePathsHashAnnotationKey)
		},
	} {
		ctx, workload, full, relevant := hostReportingFixture(t)
		mutation(&workload, &full, &relevant)
		ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)
		var reports []csv1.ScanResultReport
		require.Error(t, captureHostReports(t, "cluster", &reports).SubmitCVE(ctx, full, relevant))
		require.Empty(t, reports)
	}
}
