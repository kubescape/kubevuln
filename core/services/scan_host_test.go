package services

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/scanfailure"
	mapset "github.com/deckarep/golang-set/v2"
	instanceidv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/adapters"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const hostFixtureName = "host-node-a-981e6a0debbb274ebadfb55c1047b758"
const hostFixtureWLID = "wlid://cluster-test/namespace-host/host-node.a"
const hostFixtureInstance = "apiVersion-v1/namespace-host/kind-Node/name-host-node.a/hostName-host"

func hostFixture(t *testing.T) (domain.SBOM, ports.ContainerRelevancyScan) {
	t.Helper()
	id, err := instanceidv1.GenerateInstanceIDFromString(hostFixtureInstance)
	require.NoError(t, err)
	var doc v1beta1.SyftDocument
	require.NoError(t, json.Unmarshal([]byte(`{
 "source":{"type":"directory","metadata":{"path":"/host"}},
 "schema":{"version":"16.0.39"},"distro":{"id":"alpine","versionID":"3.20"},
 "artifacts":[{"id":"selected","name":"selected","version":"1.0","type":"apk"},{"id":"ancestor","name":"ancestor","version":"2.0","type":"apk"},{"id":"excluded","name":"excluded","version":"3.0","type":"apk"}],
 "files":[{"id":"f1","location":{"path":"usr/bin/tool"}},{"id":"f2","location":{"path":"/opt/cache/abc/file"}},{"id":"f3","location":{"path":"usr/bin/unused"}}],
 "artifactRelationships":[{"parent":"ancestor","child":"selected","type":"contains"},{"parent":"selected","child":"f1","type":"contains"},{"parent":"selected","child":"f2","type":"contains"},{"parent":"excluded","child":"f3","type":"contains"}]
 }`), &doc))
	return domain.SBOM{Name: hostFixtureName, Content: &doc, Status: helpersv1.Learning, SBOMCreatorName: "syft", SBOMCreatorVersion: "v1.99.0",
			Labels:      map[string]string{"kubescape.io/host": "node-a-981e6a0debbb274ebadfb55c1047b758", "kubescape.io/node-name": "node-a-981e6a0debbb274ebadfb55c1047b758"},
			Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Learning, domain.HostInventoryUIDAnnotationKey: "host-uid", domain.HostInventoryResourceVersionAnnotationKey: "10"}},
		ports.ContainerRelevancyScan{HostNodeName: "node.a", ContainerName: "host", InstanceID: id, InstanceIDString: hostFixtureInstance, Wlid: hostFixtureWLID, Completion: helpersv1.Full, RelevantFiles: mapset.NewSet("/usr/bin/tool"), Labels: map[string]string{helpersv1.ContainerNameMetadataKey: "host"}}
}
func TestFilterHostSBOM(t *testing.T) {
	sbom, scan := hostFixture(t)
	scan.Labels["kubescape.io/host"] = "misleading-profile-host"
	scan.Labels["kubescape.io/node-name"] = "misleading-profile-node"
	scan.Labels["profile-only"] = "retained"
	sbom.Labels["inventory-only"] = "retained"
	before := cloneHostSBOM(sbom)
	scan.RelevantFiles.Add("opt/cache/⋯/file")
	filtered, err := filterHostSBOM(sbom, scan)
	require.NoError(t, err)
	require.Len(t, filtered.Content.Artifacts, 2)
	require.Equal(t, "selected", filtered.Content.Artifacts[0].ID)
	require.Equal(t, "ancestor", filtered.Content.Artifacts[1].ID)
	require.Len(t, filtered.Content.Files, 2)
	require.Equal(t, "usr/bin/tool", filtered.Content.Files[0].Location.RealPath)
	require.Len(t, filtered.Content.ArtifactRelationships, 3)
	require.Equal(t, helpersv1.HostArtifactType, filtered.Labels[helpersv1.ArtifactTypeMetadataKey])
	require.Equal(t, sbom.Labels["kubescape.io/host"], filtered.Labels["kubescape.io/host"])
	require.Equal(t, sbom.Labels["kubescape.io/node-name"], filtered.Labels["kubescape.io/node-name"])
	require.Equal(t, "retained", filtered.Labels["profile-only"])
	require.Equal(t, "retained", filtered.Labels["inventory-only"])
	require.Equal(t, "10", filtered.Annotations[domain.HostInventoryResourceVersionAnnotationKey])
	filtered.Labels["mutated"] = "yes"
	filtered.Annotations["mutated"] = "yes"
	filtered.Content.SyftSource.Metadata[0] = 'x'
	require.Equal(t, before, sbom)
	require.Empty(t, scan.Labels["mutated"])
	require.Equal(t, "misleading-profile-host", scan.Labels["kubescape.io/host"])
	require.Equal(t, "misleading-profile-node", scan.Labels["kubescape.io/node-name"])
}
func TestFilterHostSBOMPOSIXBackslashes(t *testing.T) {
	sbom, scan := hostFixture(t)
	const escapedPath = `usr/lib/systemd/system/system-systemd\x2dcryptsetup.slice`
	sbom.Content.Files[0].Location.RealPath = escapedPath
	scan.RelevantFiles = mapset.NewSet("/" + escapedPath)
	before := cloneHostSBOM(sbom)

	filtered, err := filterHostSBOM(sbom, scan)
	require.NoError(t, err)
	require.Len(t, filtered.Content.Files, 1)
	require.Equal(t, escapedPath, filtered.Content.Files[0].Location.RealPath)
	require.Len(t, filtered.Content.Artifacts, 2)
	require.Equal(t, "selected", filtered.Content.Artifacts[0].ID)
	require.Equal(t, "ancestor", filtered.Content.Artifacts[1].ID)
	require.Equal(t, before, sbom)
}

func TestFilterHostSBOMUnsafePathsRejected(t *testing.T) {
	for _, tc := range []struct {
		name, inventoryPath, profilePath string
	}{
		{"inventory NUL", "usr/bin/bad\x00name", "/usr/bin/tool"},
		{"profile root escape", "usr/bin/tool", "/../../tool"},
		{"profile ambiguous traversal", "usr/bin/tool", "/usr/*/../tool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sbom, scan := hostFixture(t)
			sbom.Content.Files[0].Location.RealPath = tc.inventoryPath
			scan.RelevantFiles = mapset.NewSet(tc.profilePath)
			before := cloneHostSBOM(sbom)
			filtered, err := filterHostSBOM(sbom, scan)
			require.Error(t, err)
			require.Nil(t, filtered.Content)
			require.Equal(t, before, sbom)
		})
	}
}

func TestNormalizeHostPath(t *testing.T) {
	for _, p := range []string{"usr/bin/tool", "/usr/bin/tool", "/usr/./bin/x/../tool"} {
		got, err := normalizeHostPath(p)
		require.NoError(t, err)
		require.Equal(t, "/usr/bin/tool", got)
	}
	for _, p := range []string{"../tool", "/../../tool", "/a/*/../tool", "/usr/../*/x", "/usr/../⋯/x", "/usr/.././*/x", "/usr/..//⋯/x", "/a/⋯/../tool", "/bad\x00path", "//host/bin/tool", ""} {
		_, err := normalizeHostPath(p)
		require.Error(t, err, p)
	}
	for _, p := range []string{"/bin/tool", "/usr/bin/tool", "/host/usr/bin/tool", "/a/*/file", "/a/⋯/file"} {
		got, err := normalizeHostPath(p)
		require.NoError(t, err)
		require.Equal(t, p, got)
	}
	for _, p := range []string{`C:\bin`, `usr/lib/systemd/system/system-systemd\x2dcryptsetup.slice`} {
		got, err := normalizeHostPath(p)
		require.NoError(t, err)
		require.Equal(t, "/"+p, got)
	}
}

type hostTestScanner struct {
	fakeCVEScanner
	calls []domain.SBOM
}

func (s *hostTestScanner) ScanSBOM(ctx context.Context, b domain.SBOM) (domain.CVEManifest, error) {
	s.calls = append(s.calls, cloneHostSBOM(b))
	matches := make([]v1beta1.Match, 0, len(b.Content.Artifacts))
	for _, p := range b.Content.Artifacts {
		m := matchForTest("CVE-" + p.ID)
		m.Vulnerability.Severity = "High"
		m.Artifact.Name = p.Name
		m.Artifact.Version = p.Version
		m.Artifact.Type = v1beta1.SyftType(p.Type)
		matches = append(matches, m)
	}
	b.Annotations["scanner-mutation"] = "yes"
	return domain.CVEManifest{Name: b.Name, Labels: b.Labels, Annotations: b.Annotations, CVEScannerVersion: "test", CVEDBVersion: "db", Content: &v1beta1.GrypeDocument{Matches: matches, Source: &v1beta1.Source{Type: "directory", Target: b.Content.SyftSource.Metadata}}}, nil
}

type hostTestPlatform struct {
	recordingPlatform
	t        *testing.T
	relevant []domain.CVEManifest
	failures []context.Context
}

func (p *hostTestPlatform) ReportScanFailure(ctx context.Context, failureCase scanfailure.ScanFailureCase, reason string, err error) error {
	p.failures = append(p.failures, ctx)
	require.NoError(p.t, ctx.Err())
	id, _ := ctx.Value(domain.ScanIDKey{}).(string)
	require.True(p.t, armotypes.ValidateContainerScanID(id), id)
	workload := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	require.Equal(p.t, hostFixtureWLID, workload.Wlid)
	require.Empty(p.t, workload.ImageHash)
	require.NotEmpty(p.t, workload.InstanceID)
	return nil
}
func (p *hostTestPlatform) SubmitCVE(ctx context.Context, cve, cvep domain.CVEManifest) error {
	id, _ := ctx.Value(domain.ScanIDKey{}).(string)
	require.True(p.t, armotypes.ValidateContainerScanID(id), id)
	workload := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	require.Empty(p.t, workload.ImageHash)
	require.Empty(p.t, workload.ImageTag)
	require.Empty(p.t, workload.ImageSlug)
	_, err := v1.DomainToArmo(ctx, *cve.Content, p.exceptions)
	require.NoError(p.t, err)
	_, err = v1.DomainToArmo(ctx, *cvep.Content, p.exceptions)
	require.NoError(p.t, err)
	image, err := v1.ParseImageManifest(cve.Content)
	require.NoError(p.t, err)
	require.Nil(p.t, image)
	p.submitted = append(p.submitted, cve)
	p.relevant = append(p.relevant, cvep)
	return nil
}
func TestScanHostCPStoredResultsAndRefresh(t *testing.T) {
	for _, generation := range []bool{false, true} {
		t.Run(map[bool]string{false: "generation disabled", true: "generation enabled"}[generation], func(t *testing.T) {
			b, scan := hostFixture(t)
			cr := &v1beta1.SBOMSyft{ObjectMeta: metav1.ObjectMeta{Name: b.Name, Namespace: "storage", UID: "host-uid", ResourceVersion: "10", Labels: b.Labels, Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Learning}}, Spec: v1beta1.SBOMSyftSpec{Metadata: v1beta1.SPDXMeta{Tool: v1beta1.ToolMeta{Name: b.SBOMCreatorName, Version: b.SBOMCreatorVersion}}, Syft: *b.Content}}
			cp := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "storage", Annotations: map[string]string{helpersv1.InstanceIDMetadataKey: hostFixtureInstance, helpersv1.WlidMetadataKey: hostFixtureWLID, helpersv1.StatusMetadataKey: helpersv1.Learning, helpersv1.CompletionMetadataKey: helpersv1.Full}}, Spec: v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/usr/bin/tool"}}}}
			repo := repositories.NewFakeAPIServerStorage("storage", cr, cp)
			scanner := &hostTestScanner{}
			platform := &hostTestPlatform{t: t, recordingPlatform: recordingPlatform{exceptions: exceptionPolicyForTest("CVE-selected")}}
			service := NewScanService(adapters.NewMockSBOMAdapter(true, false, false), repo, scanner, repo, platform, v1.NewContainerProfileAdapter(repo), true, true, generation, true, false)
			ctx, err := service.ValidateScanCP(context.Background(), domain.ScanCommand{JobID: "host-job", Args: map[string]interface{}{domain.ArgsName: "cp", domain.ArgsNamespace: "storage"}})
			require.NoError(t, err)
			accepted := 0
			ctx = domain.WithHostInventoryReady(ctx, func() error { accepted++; return nil })
			require.NoError(t, service.ScanCP(ctx))
			require.Equal(t, 1, accepted)
			require.Len(t, scanner.calls, 2)
			require.Contains(t, matchIDs(platform.submitted[0].Content.Matches), "CVE-selected")
			require.Contains(t, matchIDs(platform.relevant[0].Content.Matches), "CVE-selected")
			relevantName, err := scan.InstanceID.GetSlug(false)
			require.NoError(t, err)
			for _, name := range []string{b.Name, relevantName} {
				got, err := repo.StorageClient.VulnerabilityManifests("storage").Get(ctx, name, metav1.GetOptions{})
				require.NoError(t, err)
				require.Equal(t, helpersv1.HostArtifactType, got.Labels[helpersv1.ArtifactTypeMetadataKey])
				require.Equal(t, b.Labels["kubescape.io/host"], got.Labels["kubescape.io/host"])
				require.Equal(t, b.Labels["kubescape.io/node-name"], got.Labels["kubescape.io/node-name"])
				require.Equal(t, "10", got.Annotations[domain.HostInventoryResourceVersionAnnotationKey])
				require.Equal(t, b.SBOMCreatorVersion, got.Annotations[helpersv1.ToolVersionMetadataKey])
				require.Equal(t, b.SBOMCreatorName, got.Annotations[domain.HostInventoryToolNameAnnotationKey])
				require.NotContains(t, matchIDs(got.Spec.Payload.Matches), "CVE-selected")
				require.Len(t, got.Spec.Payload.IgnoredMatches, 1)
			}
			summaries, err := repo.StorageClient.VulnerabilityManifestSummaries("host").List(ctx, metav1.ListOptions{})
			require.NoError(t, err)
			require.Len(t, summaries.Items, 1)
			summary := summaries.Items[0]
			require.Equal(t, b.SBOMCreatorVersion, summary.Annotations[helpersv1.ToolVersionMetadataKey])
			require.Equal(t, b.SBOMCreatorName, summary.Annotations[domain.HostInventoryToolNameAnnotationKey])
			require.Equal(t, helpersv1.HostArtifactType, summary.Labels[helpersv1.ArtifactTypeMetadataKey])
			require.Equal(t, b.Name, summary.Spec.Vulnerabilities.ImageVulnerabilitiesObj.Name)
			require.Equal(t, "storage", summary.Spec.Vulnerabilities.ImageVulnerabilitiesObj.Namespace)
			require.Equal(t, relevantName, summary.Spec.Vulnerabilities.WorkloadVulnerabilitiesObj.Name)
			require.Equal(t, "storage", summary.Spec.Vulnerabilities.WorkloadVulnerabilitiesObj.Namespace)
			filteredInventory, err := repo.StorageClient.SBOMSyftFiltereds("storage").Get(ctx, relevantName, metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, b.Labels["kubescape.io/host"], filteredInventory.Labels["kubescape.io/host"])
			require.Equal(t, b.Labels["kubescape.io/node-name"], filteredInventory.Labels["kubescape.io/node-name"])
			stored, err := repo.StorageClient.SBOMSyfts("storage").Get(ctx, b.Name, metav1.GetOptions{})
			require.NoError(t, err)
			require.Empty(t, stored.Annotations["scanner-mutation"])
			require.Equal(t, "usr/bin/tool", stored.Spec.Syft.Files[0].Location.RealPath)
			stored.ResourceVersion = "11"
			stored.Spec.Syft.Artifacts[0].Version = "1.1"
			_, err = repo.StorageClient.SBOMSyfts("storage").Update(ctx, stored, metav1.UpdateOptions{})
			require.NoError(t, err)
			require.NoError(t, service.ScanCP(ctx))
			require.Len(t, scanner.calls, 4)
			require.Equal(t, "1.1", scanner.calls[2].Content.Artifacts[0].Version)
			require.Equal(t, "11", platform.submitted[1].Annotations[domain.HostInventoryResourceVersionAnnotationKey])
		})
	}
}

type hostTestInventory struct {
	ports.SBOMRepository
	sbom         domain.SBOM
	err          error
	calls        int
	beforeReturn func()
}

func (r *hostTestInventory) GetHostSBOM(context.Context, string) (domain.SBOM, error) {
	r.calls++
	if r.beforeReturn != nil {
		r.beforeReturn()
	}
	return r.sbom, r.err
}
func TestScanHostCPPendingAndRejectedReadiness(t *testing.T) {
	b, scan := hostFixture(t)
	for _, tc := range []struct {
		name           string
		lookup, accept error
		storage        bool
	}{
		{"pending", domain.ErrHostInventoryPending, nil, true},
		{"expired", nil, domain.ErrHostInventoryUnavailable, true},
		{"cancelled", nil, context.Canceled, true},
		{"storage disabled", nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &hostTestInventory{sbom: b, err: tc.lookup}
			scanner := &hostTestScanner{}
			platform := &hostTestPlatform{t: t}
			service := NewScanService(adapters.NewMockSBOMAdapter(true, false, false), repo, scanner, nil, platform, nil, tc.storage, false, false, false, false)
			// Host inventory errors carry a validated host scan context even before readiness.
			ctx := domain.WithHostInventoryReady(context.Background(), func() error { return tc.accept })
			err := service.scanHostCP(ctx, domain.ScanCommand{}, scan)
			require.Error(t, err)
			require.Empty(t, scanner.calls)
			require.Empty(t, platform.submitted)
			if tc.storage {
				require.Empty(t, platform.failures)
			}
			if tc.lookup != nil {
				require.True(t, errors.Is(err, tc.lookup))
			}
			if tc.accept != nil {
				require.ErrorIs(t, err, tc.accept)
			}
			if !tc.storage {
				require.Zero(t, repo.calls)
				require.Len(t, platform.failures, 1)
			}
		})
	}
}

func TestScanHostCPInventoryFailureReporting(t *testing.T) {
	b, scan := hostFixture(t)
	for _, tc := range []struct {
		name   string
		lookup error
		bad    bool
	}{{"forbidden", errors.New("forbidden inventory"), false}, {"invalid source", nil, true}, {"pending", domain.ErrHostInventoryPending, false}, {"canceled", context.Canceled, false}} {
		t.Run(tc.name, func(t *testing.T) {
			inventory := cloneHostSBOM(b)
			if tc.bad {
				inventory.Content.SyftSource.Type = "image"
			}
			repo := &hostTestInventory{sbom: inventory, err: tc.lookup}
			platform := &hostTestPlatform{t: t}
			scanner := &hostTestScanner{}
			service := NewScanService(adapters.NewMockSBOMAdapter(true, false, false), repo, scanner, nil, platform, nil, true, false, false, false, false)
			var reporter func(context.Context, error)
			ctx, cancel := context.WithCancel(context.Background())
			ctx = domain.WithHostInventoryFailureReporter(ctx, func(report func(context.Context, error)) { reporter = report })
			err := service.scanHostCP(ctx, domain.ScanCommand{JobID: "host-job"}, scan)
			require.Error(t, err)
			require.NotNil(t, reporter)
			require.Empty(t, scanner.calls)
			if tc.name == "pending" || tc.name == "canceled" {
				require.Empty(t, platform.failures)
			} else {
				require.Len(t, platform.failures, 1)
			}
			if tc.name == "pending" {
				cancel()
				reporter(context.Background(), domain.ErrHostInventoryUnavailable)
				require.Len(t, platform.failures, 1)
				workload := platform.failures[0].Value(domain.WorkloadKey{}).(domain.ScanCommand)
				require.Equal(t, "host-job", workload.JobID)
			}
			cancel()
		})
	}
}

func TestScanHostCPCanceledLookupCannotReportLateFailure(t *testing.T) {
	for _, invalidSnapshot := range []bool{false, true} {
		t.Run(map[bool]string{false: "late error", true: "late malformed snapshot"}[invalidSnapshot], func(t *testing.T) {
			b, scan := hostFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			repo := &hostTestInventory{sbom: b, err: errors.New("late invalid inventory"), beforeReturn: cancel}
			if invalidSnapshot {
				repo.err = nil
				repo.sbom.Content = nil
			}
			platform := &hostTestPlatform{t: t}
			scanner := &hostTestScanner{}
			service := NewScanService(adapters.NewMockSBOMAdapter(true, false, false), repo, scanner, nil, platform, nil, true, false, false, false, false)
			var reporter func(context.Context, error)
			ctx = domain.WithHostInventoryFailureReporter(ctx, func(report func(context.Context, error)) { reporter = report })
			require.ErrorIs(t, service.scanHostCP(ctx, domain.ScanCommand{}, scan), context.Canceled)
			require.Empty(t, platform.failures)
			require.Empty(t, scanner.calls)
			reporter(context.Background(), domain.ErrHostInventoryUnavailable)
			require.Len(t, platform.failures, 1)
		})
	}
}

func TestScanHostCPInventoryFailureArbitration(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure wins", true: "expiry wins"}[expired], func(t *testing.T) {
			b, scan := hostFixture(t)
			repo := &hostTestInventory{sbom: b, err: errors.New("invalid inventory")}
			platform := &hostTestPlatform{t: t}
			service := NewScanService(adapters.NewMockSBOMAdapter(true, false, false), repo, &hostTestScanner{}, nil, platform, nil, true, false, false, false, false)
			var reporter func(context.Context, error)
			claimed := 0
			ctx := domain.WithHostInventoryFailureReporter(context.Background(), func(report func(context.Context, error)) { reporter = report })
			ctx = domain.WithHostInventoryReady(ctx, func() error {
				claimed++
				if expired {
					return domain.ErrHostInventoryUnavailable
				}
				return nil
			})
			require.Error(t, service.scanHostCP(ctx, domain.ScanCommand{}, scan))
			require.Equal(t, 1, claimed)
			if expired {
				require.Empty(t, platform.failures)
				reporter(context.Background(), domain.ErrHostInventoryUnavailable)
			}
			require.Len(t, platform.failures, 1)
		})
	}
}
