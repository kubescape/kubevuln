package services

import (
	"context"
	"sort"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/armoapi-go/scanfailure"
	wlidpkg "github.com/armosec/utils-k8s-go/wlid"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/kubevuln/adapters"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The image-level CVE manifest is keyed by image slug and shared by every workload that runs
// the image, in every namespace. SecurityExceptions are selected per scanned workload, so they
// must only shape that workload's results (its summary, its relevancy manifest), never the
// shared image record. These tests pin that invariant across namespaces and scan orders.

const (
	sharedImageSlug = "imageSlug"
	sharedImageHash = "docker.io/library/nginx@sha256:b997b0db9c2bc0a2fb803ced5fb9ff3a757e54903a28ada3e50412cc3ab7822f"
)

// namespaceExceptionsPlatform returns the exceptions of the scanned workload's namespace, the
// way BackendAdapter.GetCVEExceptions selects namespaced SecurityExceptions.
type namespaceExceptionsPlatform struct {
	byNamespace map[string]domain.CVEExceptions
	err         error
	submitted   []domain.CVEManifest
}

var _ ports.Platform = (*namespaceExceptionsPlatform)(nil)

func (p *namespaceExceptionsPlatform) GetCVEExceptions(ctx context.Context) (domain.CVEExceptions, domain.ExceptionStats, error) {
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return nil, domain.ExceptionStats{}, domain.ErrCastingWorkload
	}
	return p.byNamespace[wlidpkg.GetNamespaceFromWlid(workload.Wlid)], domain.ExceptionStats{}, p.err
}

func (p *namespaceExceptionsPlatform) SubmitCVE(_ context.Context, cve domain.CVEManifest, _ domain.CVEManifest) error {
	p.submitted = append(p.submitted, cve)
	return nil
}

func (p *namespaceExceptionsPlatform) ReportError(context.Context, error) error { return nil }
func (p *namespaceExceptionsPlatform) ReportScanFailure(context.Context, scanfailure.ScanFailureCase, string, error) error {
	return nil
}
func (p *namespaceExceptionsPlatform) SendStatus(context.Context, int) error { return nil }

// namespacedExceptionPolicy mirrors what ConvertToVulnerabilityExceptionPolicies produces for
// a namespaced SecurityException ignoring the given CVEs.
func namespacedExceptionPolicy(namespace string, ids ...string) domain.CVEExceptions {
	var policies []armotypes.VulnerabilityPolicy
	for _, id := range ids {
		policies = append(policies, armotypes.VulnerabilityPolicy{Name: id})
	}
	p := armotypes.VulnerabilityExceptionPolicy{
		PolicyType:            "vulnerabilityExceptionPolicy",
		Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
		VulnerabilityPolicies: policies,
	}
	p.Attributes = map[string]interface{}{
		"sourceKind":      "SecurityException",
		"sourceNamespace": namespace,
		"ruleId":          "SecurityException/" + namespace + "/accepted",
	}
	return domain.CVEExceptions{p}
}

// clusterExceptionPolicy mirrors what ConvertToVulnerabilityExceptionPolicies produces for a
// ClusterSecurityException ignoring the given CVEs; selectsWorkloads is true when its match
// uses a namespace or object selector or resources.
func clusterExceptionPolicy(selectsWorkloads bool, ids ...string) domain.CVEExceptions {
	var policies []armotypes.VulnerabilityPolicy
	for _, id := range ids {
		policies = append(policies, armotypes.VulnerabilityPolicy{Name: id})
	}
	p := armotypes.VulnerabilityExceptionPolicy{
		PolicyType:            "vulnerabilityExceptionPolicy",
		Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
		VulnerabilityPolicies: policies,
	}
	p.Attributes = map[string]interface{}{
		"sourceKind": "ClusterSecurityException",
		"ruleId":     "ClusterSecurityException/accepted",
	}
	if selectsWorkloads {
		p.Attributes["workloadScoped"] = true
	}
	return domain.CVEExceptions{p}
}

func joinExceptions(sets ...domain.CVEExceptions) domain.CVEExceptions {
	var out domain.CVEExceptions
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// severityScanner returns a fixed set of findings with severities, for every SBOM it scans.
type severityScanner struct {
	fakeCVEScanner
	findings map[string]string // CVE ID -> severity
}

func (s severityScanner) ScanSBOM(_ context.Context, sbom domain.SBOM) (domain.CVEManifest, error) {
	ids := make([]string, 0, len(s.findings))
	for id := range s.findings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	matches := make([]v1beta1.Match, 0, len(ids))
	for _, id := range ids {
		m := matchForTest(id)
		m.Vulnerability.Severity = s.findings[id]
		m.Artifact = v1beta1.GrypePackage{Name: "pkg-" + id, Version: "1.0"}
		matches = append(matches, m)
	}
	// Like a real scan result, carry the SBOM creator version annotation, so the stored manifest
	// is a valid cache entry for later scans of the same image.
	annotations := map[string]string{helpersv1.ToolVersionMetadataKey: sbom.SBOMCreatorVersion}
	for k, v := range sbom.Annotations {
		annotations[k] = v
	}
	return domain.CVEManifest{
		Name:               sbom.Name,
		ReportCreatedAt:    reportTimeForTest(),
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		CVEScannerVersion:  "fake-cve",
		CVEDBVersion:       "fake-db",
		Annotations:        annotations,
		Labels:             sbom.Labels,
		Content:            &v1beta1.GrypeDocument{Matches: matches},
	}, nil
}

var sharedImageFindings = map[string]string{
	"CVE-A": domain.CriticalSeverity,
	"CVE-B": domain.HighSeverity,
}

type sharedImageFixture struct {
	t        *testing.T
	s        *ScanService
	repo     *repositories.APIServerStore
	platform *namespaceExceptionsPlatform
	versions [3]string // sbom creator, cve scanner, cve db
}

func newSharedImageFixture(t *testing.T, findings map[string]string, byNamespace map[string]domain.CVEExceptions) *sharedImageFixture {
	platform := &namespaceExceptionsPlatform{byNamespace: byNamespace}
	repo := repositories.NewFakeAPIServerStorage("kubescape")
	scanner := severityScanner{findings: findings}
	s, sbomVer, cveVer, dbVer, _ := newScanCVETestService(t, platform, repo, scanner)
	return &sharedImageFixture{t: t, s: s, repo: repo, platform: platform, versions: [3]string{sbomVer, cveVer, dbVer}}
}

// ctxFor returns a validated ScanCVE context for deployment "web" in namespace, running the
// shared image.
func (f *sharedImageFixture) ctxFor(namespace string) context.Context {
	ctx, err := f.s.ValidateScanCVE(context.TODO(), domain.ScanCommand{
		ImageSlug:     sharedImageSlug,
		ContainerName: "nginx",
		ImageHash:     sharedImageHash,
		Wlid:          "wlid://cluster-test/namespace-" + namespace + "/deployment-web",
	})
	require.NoError(f.t, err)
	return ctx
}

func (f *sharedImageFixture) scan(namespace string) {
	require.NoError(f.t, f.s.ScanCVE(f.ctxFor(namespace)), "scanning %s", namespace)
}

// sharedImage returns the stored image-level manifest's (matched, ignored) CVE IDs.
func (f *sharedImageFixture) sharedImage() (matched, ignored []string) {
	stored, err := f.repo.GetCVE(context.TODO(), sharedImageSlug, f.versions[0], f.versions[1], f.versions[2])
	require.NoError(f.t, err)
	require.NotNil(f.t, stored.Content, "the shared image manifest must be stored")
	matched = matchIDs(stored.Content.Matches)
	for _, im := range stored.Content.IgnoredMatches {
		ignored = append(ignored, im.Match.Vulnerability.ID)
	}
	sort.Strings(matched)
	sort.Strings(ignored)
	return matched, ignored
}

// assertSharedImageCanonical asserts the shared image record holds exactly the scanner's
// findings, with no suppression from any namespace's exceptions.
func (f *sharedImageFixture) assertSharedImageCanonical(findings map[string]string, step string) {
	want := make([]string, 0, len(findings))
	for id := range findings {
		want = append(want, id)
	}
	sort.Strings(want)
	matched, ignored := f.sharedImage()
	assert.Equal(f.t, want, matched, "%s: shared image manifest must keep every scanner finding", step)
	assert.Empty(f.t, ignored, "%s: shared image manifest must not carry namespace-scoped suppression", step)
}

func (f *sharedImageFixture) summary(namespace string) *v1beta1.VulnerabilityManifestSummary {
	summary, err := f.repo.GetCVESummary(f.ctxFor(namespace))
	require.NoError(f.t, err)
	require.NotNil(f.t, summary, "summary for %s", namespace)
	return summary
}

func TestScanService_SharedImageManifest_IndependentOfScanOrder(t *testing.T) {
	exceptions := map[string]domain.CVEExceptions{"team-a": namespacedExceptionPolicy("team-a", "CVE-A")}
	for _, order := range [][]string{
		{"team-a", "team-b"},
		{"team-b", "team-a"},
		{"team-a", "team-b", "team-a"},
		{"team-b", "team-a", "team-b"},
		{"team-a", "team-a", "team-b", "team-b"},
	} {
		t.Run(joinNamespaces(order), func(t *testing.T) {
			f := newSharedImageFixture(t, sharedImageFindings, exceptions)
			scanned := map[string]bool{}
			for i, ns := range order {
				f.scan(ns)
				scanned[ns] = true
				step := joinNamespaces(order[:i+1])
				f.assertSharedImageCanonical(sharedImageFindings, step)
				if scanned["team-a"] {
					s := f.summary("team-a")
					assert.Zero(t, s.Spec.Severities.Critical.All, "%s: team-a's own exception must suppress CVE-A in its summary", step)
					assert.Equal(t, int64(1), s.Spec.Severities.High.All, step)
					assert.Equal(t, sharedImageSlug, s.Spec.Vulnerabilities.ImageVulnerabilitiesObj.Name, step)
				}
				if scanned["team-b"] {
					s := f.summary("team-b")
					assert.Equal(t, int64(1), s.Spec.Severities.Critical.All, "%s: team-a's exception must never suppress CVE-A for team-b", step)
					assert.Equal(t, int64(1), s.Spec.Severities.High.All, step)
					assert.Equal(t, sharedImageSlug, s.Spec.Vulnerabilities.ImageVulnerabilitiesObj.Name, step)
				}
			}
			for _, submitted := range f.platform.submitted {
				assert.ElementsMatch(t, []string{"CVE-A", "CVE-B"}, matchIDs(submitted.Content.Matches), "the backend keeps receiving unfiltered findings")
			}
		})
	}
}

func joinNamespaces(order []string) string {
	out := ""
	for i, ns := range order {
		if i > 0 {
			out += "->"
		}
		out += ns
	}
	return out
}

func TestScanService_SharedImageManifest_ExceptionLifecycleStaysScoped(t *testing.T) {
	exceptions := map[string]domain.CVEExceptions{}
	f := newSharedImageFixture(t, sharedImageFindings, exceptions)

	f.scan("team-b") // team-b scanned once, with no exceptions: both findings count
	f.scan("team-a")
	f.assertSharedImageCanonical(sharedImageFindings, "no exceptions")

	for _, step := range []struct {
		name         string
		exceptions   domain.CVEExceptions
		wantCritical int64
		wantHigh     int64
	}{
		{name: "create CVE-A exception", exceptions: namespacedExceptionPolicy("team-a", "CVE-A"), wantCritical: 0, wantHigh: 1},
		{name: "modify to CVE-B", exceptions: namespacedExceptionPolicy("team-a", "CVE-B"), wantCritical: 1, wantHigh: 0},
		{name: "widen to both", exceptions: namespacedExceptionPolicy("team-a", "CVE-A", "CVE-B"), wantCritical: 0, wantHigh: 0},
		{name: "exception no longer matches", exceptions: namespacedExceptionPolicy("team-a", "CVE-Z"), wantCritical: 1, wantHigh: 1},
		{name: "remove exception", exceptions: nil, wantCritical: 1, wantHigh: 1},
	} {
		exceptions["team-a"] = step.exceptions
		f.scan("team-a")
		f.assertSharedImageCanonical(sharedImageFindings, step.name)
		a := f.summary("team-a")
		assert.Equal(t, step.wantCritical, a.Spec.Severities.Critical.All, step.name)
		assert.Equal(t, step.wantHigh, a.Spec.Severities.High.All, step.name)
		b := f.summary("team-b")
		assert.Equal(t, int64(1), b.Spec.Severities.Critical.All, "%s: team-b is unaffected", step.name)
		assert.Equal(t, int64(1), b.Spec.Severities.High.All, "%s: team-b is unaffected", step.name)
	}
}

func TestScanService_SharedImageManifest_IndependentExceptionSets(t *testing.T) {
	findings := map[string]string{
		"CVE-A": domain.CriticalSeverity, // suppressed only in team-a
		"CVE-B": domain.HighSeverity,     // suppressed only in team-b
		"CVE-C": domain.MediumSeverity,   // suppressed in both
		"CVE-D": domain.LowSeverity,      // suppressed in neither
	}
	exceptions := map[string]domain.CVEExceptions{
		"team-a": namespacedExceptionPolicy("team-a", "CVE-A", "CVE-C"),
		"team-b": namespacedExceptionPolicy("team-b", "CVE-B", "CVE-C"),
	}
	for _, order := range [][]string{{"team-a", "team-b"}, {"team-b", "team-a"}, {"team-a", "team-b", "team-a"}} {
		t.Run(joinNamespaces(order), func(t *testing.T) {
			f := newSharedImageFixture(t, findings, exceptions)
			for _, ns := range order {
				f.scan(ns)
				f.assertSharedImageCanonical(findings, ns)
			}
			a := f.summary("team-a").Spec.Severities
			assert.Equal(t, [4]int64{0, 1, 0, 1}, [4]int64{a.Critical.All, a.High.All, a.Medium.All, a.Low.All}, "team-a: A and C suppressed")
			b := f.summary("team-b").Spec.Severities
			assert.Equal(t, [4]int64{1, 0, 0, 1}, [4]int64{b.Critical.All, b.High.All, b.Medium.All, b.Low.All}, "team-b: B and C suppressed")
		})
	}
}

// A manifest stored before this fix carries the suppression of whichever workload stored it.
// The next cache hit, from any namespace, must restore it to the canonical scanner result.
func TestScanService_SharedImageManifest_LegacyFilteredManifestIsRestored(t *testing.T) {
	exceptions := map[string]domain.CVEExceptions{"team-a": namespacedExceptionPolicy("team-a", "CVE-A")}
	f := newSharedImageFixture(t, sharedImageFindings, exceptions)

	legacy := domain.CVEManifest{
		Name:               sharedImageSlug,
		ReportCreatedAt:    reportTimeForTest(),
		SBOMCreatorVersion: f.versions[0],
		CVEScannerVersion:  f.versions[1],
		CVEDBVersion:       f.versions[2],
		Annotations:        map[string]string{helpersv1.ToolVersionMetadataKey: f.versions[0]},
	}
	scanned, err := severityScanner{findings: sharedImageFindings}.ScanSBOM(context.TODO(), domain.SBOM{Name: sharedImageSlug})
	require.NoError(t, err)
	legacy.Content = scanned.Content
	ctxA := f.ctxFor("team-a")
	filtered, _ := f.s.applyExceptionsToManifest(ctxA, legacy)
	require.Len(t, filtered.Content.IgnoredMatches, 1, "fixture: a legacy manifest filtered by team-a")
	require.NoError(t, f.repo.StoreCVE(context.TODO(), filtered, false))

	f.scan("team-a") // cache hit, same exceptions as the ones baked into the legacy manifest
	f.assertSharedImageCanonical(sharedImageFindings, "after team-a cache hit")
	assert.Zero(t, f.summary("team-a").Spec.Severities.Critical.All)
}

// The canonical scanner result must not be mutated while deriving a workload's filtered view.
func TestScanService_ApplyExceptionsDoesNotMutateCanonicalManifest(t *testing.T) {
	exceptions := map[string]domain.CVEExceptions{"team-a": namespacedExceptionPolicy("team-a", "CVE-A")}
	f := newSharedImageFixture(t, sharedImageFindings, exceptions)
	canonical, err := severityScanner{findings: sharedImageFindings}.ScanSBOM(context.TODO(), domain.SBOM{Name: sharedImageSlug})
	require.NoError(t, err)
	canonical.Labels = map[string]string{"l": "v"}
	canonical.Annotations = map[string]string{"a": "v"}
	before := canonical.Content.DeepCopy()

	filtered, complete := f.s.applyExceptionsToManifest(f.ctxFor("team-a"), canonical)
	require.True(t, complete)
	require.Len(t, filtered.Content.IgnoredMatches, 1)

	filtered.Content.Matches[0].Vulnerability.ID = "MUTATED"
	filtered.Content.IgnoredMatches[0].AppliedIgnoreRules[0].SourceNamespace = "MUTATED"
	filtered.Labels["l"] = "MUTATED"
	filtered.Annotations["a"] = "MUTATED"
	assert.Equal(t, before, canonical.Content, "the canonical findings must be independent of the filtered copy")
	assert.Equal(t, "v", canonical.Labels["l"])
	assert.Equal(t, "v", canonical.Annotations["a"])
}

// ScanCP is the flow the operator uses for running workloads. Two workloads in different
// namespaces running the same image share its image-level manifest, whether that manifest is
// produced on a cache miss or served from the cache.
func TestScanService_ScanCP_SharedImageManifest_IndependentOfNamespaceExceptions(t *testing.T) {
	imageID := "sha256:b997b0db9c2bc0a2fb803ced5fb9ff3a757e54903a28ada3e50412cc3ab7822f"
	imageTag := "docker.io/library/nginx:1.25.0"
	slug, err := names.ImageInfoToSlug(tools.NormalizeReference(imageTag), imageID)
	require.NoError(t, err)

	for _, order := range [][]string{{"team-a", "team-b", "team-a"}, {"team-b", "team-a", "team-b"}} {
		t.Run(joinNamespaces(order), func(t *testing.T) {
			platform := &namespaceExceptionsPlatform{byNamespace: map[string]domain.CVEExceptions{
				"team-a": namespacedExceptionPolicy("team-a", "CVE-A"),
			}}
			sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
			scanner := severityScanner{findings: sharedImageFindings}
			storageCP := repositories.NewMemoryStorage(false, false)
			storageSBOM := repositories.NewMemoryStorage(false, false)
			storageCVE := repositories.NewMemoryStorage(false, false)
			s := NewScanService(sbomAdapter, storageSBOM, scanner, storageCVE, platform, v1.NewContainerProfileAdapter(storageCP), true, false, true, false, false)
			s.Ready(context.TODO())

			ctxFor := map[string]context.Context{}
			for _, ns := range []string{"team-a", "team-b"} {
				wlid := "wlid://cluster-test/namespace-" + ns + "/deployment-web"
				ctx, err := s.ValidateScanCP(context.TODO(), domain.ScanCommand{
					Args: map[string]interface{}{domain.ArgsName: "deployment-web", domain.ArgsNamespace: ns},
					Wlid: wlid,
				})
				require.NoError(t, err)
				require.NoError(t, storageCP.StoreContainerProfile(ctx, v1beta1.ContainerProfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "deployment-web",
						Namespace: ns,
						Annotations: map[string]string{
							helpersv1.CompletionMetadataKey: helpersv1.Full,
							helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-" + ns + "/kind-Deployment/name-web/containerName-nginx",
							helpersv1.StatusMetadataKey:     helpersv1.Learning,
							helpersv1.WlidMetadataKey:       wlid,
						},
					},
					Spec: v1beta1.ContainerProfileSpec{ImageID: imageID, ImageTag: imageTag},
				}))
				ctxFor[ns] = ctx
			}

			for i, ns := range order {
				require.NoError(t, s.ScanCP(ctxFor[ns]), "ScanCP %s", ns)
				stored, err := storageCVE.GetCVE(context.TODO(), slug, sbomAdapter.Version(), scanner.Version(), scanner.DBVersion(context.TODO()))
				require.NoError(t, err)
				require.NotNil(t, stored.Content)
				step := joinNamespaces(order[:i+1])
				assert.ElementsMatch(t, []string{"CVE-A", "CVE-B"}, matchIDs(stored.Content.Matches), "%s: shared image manifest keeps every finding", step)
				assert.Empty(t, stored.Content.IgnoredMatches, "%s: shared image manifest carries no namespace-scoped suppression", step)
			}
		})
	}
}

// sharedImageManifestCVEs returns the stored image manifest's (matched, ignored) CVE IDs and
// the namespaces any of its ignore rules came from.
func (f *sharedImageFixture) sharedImageSourceNamespaces() []string {
	stored, err := f.repo.GetCVE(context.TODO(), sharedImageSlug, f.versions[0], f.versions[1], f.versions[2])
	require.NoError(f.t, err)
	require.NotNil(f.t, stored.Content)
	seen := map[string]bool{}
	for _, im := range stored.Content.IgnoredMatches {
		for _, r := range im.AppliedIgnoreRules {
			if r.SourceNamespace != "" {
				seen[r.SourceNamespace] = true
			}
		}
	}
	var out []string
	for ns := range seen {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// Exceptions that hold for every workload running the image (a ClusterSecurityException
// without selectors) keep shaping the shared image manifest exactly as before; only the
// workload-scoped ones are kept out of it.
func TestScanService_SharedImageManifest_ImageWideExceptionsStillApply(t *testing.T) {
	exceptions := map[string]domain.CVEExceptions{
		"team-a": joinExceptions(clusterExceptionPolicy(false, "CVE-B"), namespacedExceptionPolicy("team-a", "CVE-A")),
		"team-b": clusterExceptionPolicy(false, "CVE-B"),
	}
	for _, order := range [][]string{{"team-a", "team-b"}, {"team-b", "team-a"}, {"team-a", "team-b", "team-a"}} {
		t.Run(joinNamespaces(order), func(t *testing.T) {
			f := newSharedImageFixture(t, sharedImageFindings, exceptions)
			for i, ns := range order {
				f.scan(ns)
				step := joinNamespaces(order[:i+1])
				matched, ignored := f.sharedImage()
				assert.Equal(t, []string{"CVE-A"}, matched, "%s: the namespaced exception never reaches the shared manifest", step)
				assert.Equal(t, []string{"CVE-B"}, ignored, "%s: the image-wide exception is stored as before", step)
				assert.Empty(t, f.sharedImageSourceNamespaces(), step)
			}
			a := f.summary("team-a").Spec.Severities
			assert.Equal(t, [2]int64{0, 0}, [2]int64{a.Critical.All, a.High.All}, "team-a: both exceptions apply")
			b := f.summary("team-b").Spec.Severities
			assert.Equal(t, [2]int64{1, 0}, [2]int64{b.Critical.All, b.High.All}, "team-b: only the image-wide exception applies")
		})
	}
}

// A ClusterSecurityException that selects workloads (namespace/object selector, resources) is
// as workload-specific as a namespaced one.
func TestScanService_SharedImageManifest_SelectingClusterExceptionIsWorkloadScoped(t *testing.T) {
	exceptions := map[string]domain.CVEExceptions{"team-a": clusterExceptionPolicy(true, "CVE-A")}
	for _, order := range [][]string{{"team-a", "team-b"}, {"team-b", "team-a", "team-b"}} {
		t.Run(joinNamespaces(order), func(t *testing.T) {
			f := newSharedImageFixture(t, sharedImageFindings, exceptions)
			for _, ns := range order {
				f.scan(ns)
				f.assertSharedImageCanonical(sharedImageFindings, ns)
			}
			assert.Zero(t, f.summary("team-a").Spec.Severities.Critical.All)
			assert.Equal(t, int64(1), f.summary("team-b").Spec.Severities.Critical.All)
		})
	}
}

// The image-level VEX document describes the stored image manifest, so it must carry the
// image-wide decisions only, never one namespace's.
func TestScanService_SharedImageManifest_ImageLevelVEXExcludesWorkloadScopedExceptions(t *testing.T) {
	exceptions := map[string]domain.CVEExceptions{
		"team-a": joinExceptions(clusterExceptionPolicy(false, "CVE-B"), namespacedExceptionPolicy("team-a", "CVE-A")),
		"team-b": clusterExceptionPolicy(false, "CVE-B"),
	}
	for _, order := range [][]string{{"team-a", "team-b"}, {"team-b", "team-a"}} {
		t.Run(joinNamespaces(order), func(t *testing.T) {
			platform := &namespaceExceptionsPlatform{byNamespace: exceptions}
			repo := &vexRecordingCVERepository{CVERepository: repositories.NewFakeAPIServerStorage("kubescape")}
			s, sbomVer, cveVer, dbVer, _ := newScanCVETestServiceVEX(t, platform, repo, severityScanner{findings: sharedImageFindings}, true)
			f := &sharedImageFixture{t: t, s: s, platform: platform, versions: [3]string{sbomVer, cveVer, dbVer}}
			for _, ns := range order {
				f.scan(ns)
			}
			require.NotEmpty(t, repo.vexCalls, "the fresh scan publishes the image-level VEX document")
			stored, err := repo.GetCVE(context.TODO(), sharedImageSlug, sbomVer, cveVer, dbVer)
			require.NoError(t, err)
			for i, call := range repo.vexCalls {
				require.NotNil(t, call.Content)
				assert.Equal(t, []string{"CVE-A"}, matchIDs(call.Content.Matches), "VEX call %d: no namespaced suppression", i)
				require.Len(t, call.Content.IgnoredMatches, 1, "VEX call %d", i)
				assert.Equal(t, "CVE-B", call.Content.IgnoredMatches[0].Vulnerability.ID, "VEX call %d: the image-wide suppression", i)
			}
			assert.Equal(t, stored.Content, repo.vexCalls[len(repo.vexCalls)-1].Content, "the VEX document describes the stored manifest")
		})
	}
}

// A registry scan of the same image shares its image manifest with the workloads running it.
func TestScanService_SharedImageManifest_RegistryScanSharesCanonicalManifest(t *testing.T) {
	exceptions := map[string]domain.CVEExceptions{"team-a": namespacedExceptionPolicy("team-a", "CVE-A")}
	f := newSharedImageFixture(t, sharedImageFindings, exceptions)
	registryCtx, err := f.s.ValidateScanRegistry(context.TODO(), domain.ScanCommand{
		ImageSlug:          sharedImageSlug,
		ImageTagNormalized: "docker.io/library/nginx:1.25.0",
		JobID:              "job-1",
	})
	require.NoError(t, err)

	f.scan("team-a")
	require.NoError(t, f.s.ScanRegistry(registryCtx))
	f.assertSharedImageCanonical(sharedImageFindings, "team-a then registry")
	require.NoError(t, f.s.ScanRegistry(registryCtx))
	f.scan("team-a")
	f.assertSharedImageCanonical(sharedImageFindings, "registry then team-a")
	assert.Zero(t, f.summary("team-a").Spec.Severities.Critical.All, "team-a keeps its own suppression")
}

// A change limited to a workload-scoped exception leaves the shared manifest unchanged, so a
// cache hit must not reuse the workload's relevancy manifest filtered by its old exceptions.
func TestScanService_SharedImageManifest_ScopedExceptionChangeInvalidatesRelevancy(t *testing.T) {
	for _, tc := range []struct {
		name          string
		exceptionNow  bool
		wantRelevancy bool
	}{
		{name: "exception unchanged keeps relevancy", exceptionNow: true, wantRelevancy: true},
		{name: "exception removed drops stale relevancy", exceptionNow: false, wantRelevancy: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exceptions := map[string]domain.CVEExceptions{}
			if tc.exceptionNow {
				exceptions["team-a"] = namespacedExceptionPolicy("team-a", "CVE-A")
			}
			f := newSharedImageFixture(t, sharedImageFindings, exceptions)
			ctx := addTimestamp(f.ctxFor("team-a"))
			image, err := severityScanner{findings: sharedImageFindings}.ScanSBOM(context.TODO(), domain.SBOM{Name: sharedImageSlug, SBOMCreatorVersion: f.versions[0]})
			require.NoError(t, err)
			image.CVEScannerVersion, image.CVEDBVersion = f.versions[1], f.versions[2]
			require.NoError(t, f.repo.StoreCVE(ctx, image, false))

			// The relevancy manifest and summary team-a's last ScanCP stored, while its
			// exception for CVE-A existed.
			oldExceptions := namespacedExceptionPolicy("team-a", "CVE-A")
			relevant := copyManifest(image)
			relevant.Name = "runtime-findings"
			v1.ApplySecurityExceptions(relevant.Content, oldExceptions, nil)
			filteredImage := copyManifest(image)
			v1.ApplySecurityExceptions(filteredImage.Content, oldExceptions, nil)
			require.NoError(t, f.repo.StoreCVE(ctx, relevant, true))
			require.NoError(t, f.repo.StoreCVESummary(ctx, filteredImage, relevant, true))

			f.scan("team-a") // image-only cache hit
			summary := f.summary("team-a")
			if tc.wantRelevancy {
				assert.Equal(t, "runtime-findings", summary.Spec.Vulnerabilities.WorkloadVulnerabilitiesObj.Name)
				assert.Equal(t, int64(1), summary.Spec.Severities.High.Relevant)
				assert.Zero(t, summary.Spec.Severities.Critical.Relevant)
			} else {
				assert.Empty(t, summary.Spec.Vulnerabilities.WorkloadVulnerabilitiesObj.Name, "stale relevancy must not be reused")
				assert.Zero(t, summary.Spec.Severities.Critical.Relevant)
				assert.Equal(t, int64(1), summary.Spec.Severities.Critical.All, "CVE-A is no longer suppressed for team-a")
			}
			f.assertSharedImageCanonical(sharedImageFindings, tc.name)
		})
	}
}

// ScanCP's per-instance VEX document belongs to the workload, so it carries the workload's own
// exceptions, while the image manifest it shares with other namespaces does not.
func TestScanService_ScanCP_PerInstanceVEXKeepsWorkloadExceptions(t *testing.T) {
	imageID := "sha256:b997b0db9c2bc0a2fb803ced5fb9ff3a757e54903a28ada3e50412cc3ab7822f"
	imageTag := "docker.io/library/nginx:1.25.0"
	slug, err := names.ImageInfoToSlug(tools.NormalizeReference(imageTag), imageID)
	require.NoError(t, err)
	platform := &namespaceExceptionsPlatform{byNamespace: map[string]domain.CVEExceptions{
		"team-a": namespacedExceptionPolicy("team-a", "CVE-A"),
	}}
	sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
	scanner := severityScanner{findings: sharedImageFindings}
	storageCP := repositories.NewMemoryStorage(false, false)
	storageCVE := &vexRecordingCVERepository{CVERepository: repositories.NewMemoryStorage(false, false)}
	s := NewScanService(sbomAdapter, repositories.NewMemoryStorage(false, false), scanner, storageCVE, platform, v1.NewContainerProfileAdapter(storageCP), true, true, true, false, false)
	s.Ready(context.TODO())
	wlid := "wlid://cluster-test/namespace-team-a/deployment-web"
	ctx, err := s.ValidateScanCP(context.TODO(), domain.ScanCommand{
		Args: map[string]interface{}{domain.ArgsName: "deployment-web", domain.ArgsNamespace: "team-a"},
		Wlid: wlid,
	})
	require.NoError(t, err)
	require.NoError(t, storageCP.StoreContainerProfile(ctx, v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment-web",
			Namespace: "team-a",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-team-a/kind-Deployment/name-web/containerName-nginx",
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.WlidMetadataKey:       wlid,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{ImageID: imageID, ImageTag: imageTag},
	}))

	require.NoError(t, s.ScanCP(ctx))

	require.Len(t, storageCVE.vexCalls, 1, "ScanCP publishes one per-instance VEX document")
	assert.Equal(t, []string{"CVE-B"}, matchIDs(storageCVE.vexCalls[0].Content.Matches))
	require.Len(t, storageCVE.vexCalls[0].Content.IgnoredMatches, 1, "the workload's own exception is in its VEX document")
	assert.Equal(t, "CVE-A", storageCVE.vexCalls[0].Content.IgnoredMatches[0].Vulnerability.ID)
	stored, err := storageCVE.GetCVE(context.TODO(), slug, sbomAdapter.Version(), scanner.Version(), scanner.DBVersion(context.TODO()))
	require.NoError(t, err)
	require.NotNil(t, stored.Content)
	assert.ElementsMatch(t, []string{"CVE-A", "CVE-B"}, matchIDs(stored.Content.Matches), "the shared image manifest stays free of it")
}

// cloudExceptionPolicy mirrors a backend-delivered exception policy: no CRD sourceKind, with
// the scope the backend recorded on it as designators.
func cloudExceptionPolicy(designators []identifiers.PortalDesignator, ids ...string) domain.CVEExceptions {
	var policies []armotypes.VulnerabilityPolicy
	for _, id := range ids {
		policies = append(policies, armotypes.VulnerabilityPolicy{Name: id})
	}
	p := armotypes.VulnerabilityExceptionPolicy{
		PolicyType:            "vulnerabilityExceptionPolicy",
		Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
		VulnerabilityPolicies: policies,
	}
	p.Designatores = designators
	return domain.CVEExceptions{p}
}

// The backend is queried per workload (namespace, kind, name, container), so a cloud exception
// scoped to team-a's workload is only returned for team-a's scans. It must not reach the
// shared image manifest either; a cluster-wide one still does.
func TestScanService_SharedImageManifest_CloudExceptionScope(t *testing.T) {
	attrs := func(kv ...string) []identifiers.PortalDesignator {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return []identifiers.PortalDesignator{{DesignatorType: identifiers.DesignatorAttributes, Attributes: m}}
	}
	for _, tc := range []struct {
		name        string
		designators []identifiers.PortalDesignator
		imageWide   bool
	}{
		{name: "namespace", designators: attrs("cluster", "test", "namespace", "team-a")},
		{name: "workload", designators: attrs("cluster", "test", "namespace", "team-a", "kind", "deployment", "name", "web")},
		{name: "container", designators: attrs("cluster", "test", "namespace", "team-a", "kind", "deployment", "name", "web", "containerName", "nginx")},
		{name: "workload labels", designators: attrs("cluster", "test", "app", "web")},
		{name: "wlid", designators: []identifiers.PortalDesignator{{DesignatorType: identifiers.DesignatorWlid, WLID: "wlid://cluster-test/namespace-team-a/deployment-web"}}},
		{name: "cluster-wide", designators: attrs("customerGUID", "guid", "cluster", "test"), imageWide: true},
		{name: "no designators", imageWide: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exceptions := map[string]domain.CVEExceptions{"team-a": cloudExceptionPolicy(tc.designators, "CVE-A")}
			if tc.imageWide {
				// a policy that holds everywhere is returned for every workload's query
				exceptions["team-b"] = exceptions["team-a"]
			}
			for _, order := range [][]string{{"team-a", "team-b", "team-a"}, {"team-b", "team-a", "team-b"}} {
				f := newSharedImageFixture(t, sharedImageFindings, exceptions)
				for _, ns := range order {
					f.scan(ns)
					matched, ignored := f.sharedImage()
					if tc.imageWide {
						assert.Equal(t, []string{"CVE-B"}, matched, "%v: an image-wide cloud exception is stored as before", order)
						assert.Equal(t, []string{"CVE-A"}, ignored, "%v", order)
					} else {
						assert.Equal(t, []string{"CVE-A", "CVE-B"}, matched, "%v: a workload-scoped cloud exception must not reach the shared manifest", order)
						assert.Empty(t, ignored, "%v", order)
					}
				}
				assert.Zero(t, f.summary("team-a").Spec.Severities.Critical.All, "%v: team-a's summary applies its exception", order)
				wantB := int64(1)
				if tc.imageWide {
					wantB = 0
				}
				assert.Equal(t, wantB, f.summary("team-b").Spec.Severities.Critical.All, "%v: team-b", order)
			}
		})
	}
}
