package repositories

import (
	"context"
	"fmt"
	"maps"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
)

const migrateDigest = "sha256:45fb8ed886902c0c49e044b1f8870fad61c1022fa23c4943098302a8f1c5b75f"

func imageProduct(id, packagePURL string) v1beta1.Product {
	return v1beta1.Product{
		Component:     v1beta1.Component{ID: id},
		Subcomponents: []v1beta1.Subcomponent{{Component: v1beta1.Component{ID: packagePURL}}},
	}
}

func cloneStatements(statements []v1beta1.Statement) []v1beta1.Statement {
	out := make([]v1beta1.Statement, len(statements))
	for i := range statements {
		statements[i].DeepCopyInto(&out[i])
	}
	return out
}

// VEX documents stored before the image product ID followed the oci purl type keep the old
// ID, because updateVEX keys statements on vulnerability and package purl. Each of kubevuln's
// own products that carries exactly what the old code wrote for the image is given today's ID,
// for every shape of reference kubevuln stores, and nothing else in the document changes.
func TestMigrateLegacyImageProducts(t *testing.T) {
	const packagePURL = "pkg:apk/alpine/libcrypto3@3.0.8-r3?arch=x86_64&distro=alpine-3.17.3"

	tests := []struct {
		name  string
		image string
	}{
		{name: "registry with a nested repository, by digest", image: "gcr.io/google-samples/microservices-demo/adservice@" + migrateDigest},
		{name: "registry with a port, by tag", image: "registry.example.com:5000/team/app:1.0"},
		{name: "docker hub official image, by digest", image: "index.docker.io/library/nginx@" + migrateDigest},
		{name: "docker hub bare name, by tag", image: "nginx:1.25"},
		{name: "docker hub library name, by tag", image: "library/nginx:latest"},
		{name: "docker hub user repository, by tag and digest", image: "docker.io/bitnami/redis:7.2@" + migrateDigest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			legacy, current := legacyImageProductID(tc.image), imageProductID(tc.image)
			require.NotEqual(t, legacy, current, "the reference must be one whose product ID changed")
			another := legacyImageProductID("quay.io/prometheus/node-exporter:v1.8.2")

			statements := []v1beta1.Statement{
				{
					// ours, with an assessment an earlier scan recorded
					ID:              localStatementID("CVE-2023-0001", packagePURL),
					Vulnerability:   v1beta1.VexVulnerability{ID: "https://nvd.nist.gov/vuln/detail/CVE-2023-0001", Name: "CVE-2023-0001"},
					Products:        []v1beta1.Product{imageProduct(legacy, packagePURL), imageProduct(another, packagePURL)},
					Status:          v1beta1.Status(vex.StatusAffected),
					ActionStatement: "upgrade",
					StatusNotes:     "response: will fix",
				},
				{
					// another author's, naming the image the same way
					ID:            "https://vendor.example/vex/statement/1",
					Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2023-0002"},
					Products:      []v1beta1.Product{imageProduct(legacy, packagePURL)},
					Status:        v1beta1.Status(vex.StatusNotAffected),
					Justification: v1beta1.Justification(vex.ComponentNotPresent),
				},
			}
			want := cloneStatements(statements)
			want[0].Products[0].ID = current

			migrateLegacyImageProducts(statements, tc.image, "")
			assert.Equal(t, want, statements, "only our product for this image is renamed")

			migrateLegacyImageProducts(statements, tc.image, "")
			assert.Equal(t, want, statements, "a second run changes nothing")
		})
	}
}

// A reference that does not parse as an image reference has no repository to name, so its
// product keeps the legacy ID, which is also what imageProductID still gives it.
func TestMigrateLegacyImageProductsKeepsAnUnparseableReference(t *testing.T) {
	const packagePURL = "pkg:deb/debian/openssl@3.0.11-1"
	for _, image := range []string{
		"Registry.Example.com/Team/App:1.0", // upper case in the repository path
		"docker-pullable://docker.io/library/nginx@" + migrateDigest,
		"",
	} {
		statements := []v1beta1.Statement{{
			ID:       localStatementID("CVE-2023-0001", packagePURL),
			Products: []v1beta1.Product{imageProduct(legacyImageProductID(image), packagePURL)},
			Status:   v1beta1.Status(vex.StatusAffected),
		}}
		want := cloneStatements(statements)

		migrateLegacyImageProducts(statements, image, "")
		assert.Equal(t, want, statements, "%q", image)
	}

	// Before #719 it had an empty repository_url qualifier as well. That stays too.
	const bare = "App:1.0" // upper case: not a reference
	statements := []v1beta1.Statement{{
		ID:       localStatementID("CVE-2023-0001", packagePURL),
		Products: []v1beta1.Product{imageProduct("pkg:oci/App:1.0?repository_url=", packagePURL)},
	}}
	migrateLegacyImageProducts(statements, bare, "")
	assert.Equal(t, "pkg:oci/App:1.0?repository_url=", statements[0].Products[0].ID, "an unparseable reference keeps its ID")
}

// Every Docker Hub spelling of the image wrote its own old ID, and the document may carry any
// of them: each is rewritten, whichever spelling is rescanned.
func TestMigrateLegacyImageProductsCoversEveryDockerHubSpelling(t *testing.T) {
	const packagePURL = "pkg:deb/debian/openssl@3.0.11-1"
	const current = "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25"
	old := []string{
		"pkg:oci/nginx:1.25",                                    // nginx:1.25
		"pkg:oci/nginx:1.25?repository_url=",                    // nginx:1.25, before #719
		"pkg:oci/nginx:1.25?repository_url=library",             // library/nginx:1.25
		"pkg:oci/nginx:1.25?repository_url=docker.io",           // docker.io/nginx:1.25
		"pkg:oci/nginx:1.25?repository_url=docker.io%2Flibrary", // docker.io/library/nginx:1.25
		"pkg:oci/nginx:1.25?repository_url=index.docker.io",
		"pkg:oci/nginx:1.25?repository_url=index.docker.io%2Flibrary",
	}
	for _, image := range []string{"nginx:1.25", "docker.io/library/nginx:1.25", "index.docker.io/nginx:1.25"} {
		statements := make([]v1beta1.Statement, len(old))
		for i, id := range old {
			statements[i] = v1beta1.Statement{
				ID:       localStatementID(fmt.Sprintf("CVE-2023-%04d", i), packagePURL),
				Products: []v1beta1.Product{imageProduct(id, packagePURL)},
			}
		}
		require.Equal(t, current, imageProductID(image))

		migrateLegacyImageProducts(statements, image, "")
		for i, s := range statements {
			assert.Equal(t, current, s.Products[0].ID, "%s rescanned as %s", old[i], image)
		}
	}

	assert.Equal(t, []string{"quay.io/prometheus/node-exporter:v1.8.2"}, imageSpellings("quay.io/prometheus/node-exporter:v1.8.2"),
		"another registry has one spelling")
}

// The stored annotation is merged over by every scan, so it may already hold the spelling being
// rescanned while the products still carry another spelling's old ID.
func TestAPIServerStore_updateVEX_migratesADockerHubSpellingTheAnnotationLost(t *testing.T) {
	const image = "docker.io/library/nginx:1.25"
	a, ctx := storeWithLegacyProducts(t, image, "pkg:oci/nginx:1.25?repository_url=index.docker.io%2Flibrary")

	full, filtered := manifestsForImage(image)
	require.NoError(t, a.StoreVEX(ctx, full, filtered, false))

	requireProducts(t, a, ctx, full.Name, "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25")
}

// storeWithLegacyProducts stores the VEX document for the testdata manifests with the image
// annotation set to storedImage, then rewrites each of kubevuln's products to the literal
// legacyID, as an older kubevuln left it. It returns the store and the context to rescan with.
func storeWithLegacyProducts(t *testing.T, storedImage, legacyID string) (*APIServerStore, context.Context) {
	t.Helper()
	full, filtered := manifestsForImage(storedImage)
	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "nginx:latest",
		ContainerName: "anyJobContName",
	})
	vexClient := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace)

	require.NoError(t, a.StoreVEX(ctx, full, filtered, false))
	stored, err := vexClient.Get(ctx, full.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, storedImage, stored.Annotations[helpersv1.ImageIDMetadataKey])
	ours := 0
	for i := range stored.Spec.Statements {
		if !isLocalStatement(stored.Spec.Statements[i].ID) {
			continue
		}
		for j := range stored.Spec.Statements[i].Products {
			stored.Spec.Statements[i].Products[j].ID = legacyID
			ours++
		}
	}
	require.NotZero(t, ours)
	_, err = vexClient.Update(ctx, stored, metav1.UpdateOptions{})
	require.NoError(t, err)
	return a, ctx
}

func manifestsForImage(image string) (domain.CVEManifest, domain.CVEManifest) {
	full := tools.FileToCVEManifest("testdata/nginx-cve.json")
	filtered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")
	for _, m := range []*domain.CVEManifest{&full, &filtered} {
		m.Annotations = maps.Clone(m.Annotations)
		m.Annotations[helpersv1.ImageIDMetadataKey] = image
	}
	return full, filtered
}

// requireProducts checks that every one of kubevuln's products in the stored document is want.
func requireProducts(t *testing.T, a *APIServerStore, ctx context.Context, name, want string) {
	t.Helper()
	got, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	for _, s := range got.Spec.Statements {
		if !isLocalStatement(s.ID) {
			continue
		}
		for _, p := range s.Products {
			require.Equal(t, want, p.ID, "statement %s", s.ID)
		}
	}
}

// Before #719 the repository_url qualifier was written even when it was empty, so a bare
// image name got "pkg:oci/nginx:1.25?repository_url=". That form is migrated as well.
func TestAPIServerStore_updateVEX_migratesThePre719BareImageForm(t *testing.T) {
	const image = "nginx:1.25"
	a, ctx := storeWithLegacyProducts(t, image, "pkg:oci/nginx:1.25?repository_url=")

	full, filtered := manifestsForImage(image)
	require.NoError(t, a.StoreVEX(ctx, full, filtered, false))

	requireProducts(t, a, ctx, full.Name, "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25")
}

// The document was stored for one spelling of the image and is rescanned under another that
// names the same image. The legacy IDs differ with the spelling, so the stored image annotation
// is what tells the migration which one the document was written for.
func TestAPIServerStore_updateVEX_migratesAProductStoredUnderAnotherSpelling(t *testing.T) {
	const digest = "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228"
	a, ctx := storeWithLegacyProducts(t, "index.docker.io/library/nginx@"+digest,
		"pkg:oci/nginx@"+digest+"?repository_url=index.docker.io%2Flibrary")

	full, filtered := manifestsForImage("docker.io/library/nginx@" + digest)
	require.NoError(t, a.StoreVEX(ctx, full, filtered, false))

	requireProducts(t, a, ctx, full.Name, "pkg:oci/nginx@"+digest+"?repository_url=docker.io%2Flibrary%2Fnginx")
}

// A stored annotation for another image does not make its legacy IDs ours to rewrite: the
// statements written for that image are not relabelled as this one's, they are replaced by
// the ones this scan writes for it.
func TestAPIServerStore_updateVEX_leavesAnotherImagesLegacyProduct(t *testing.T) {
	const digest = "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228"
	legacy := "pkg:oci/redis@" + digest + "?repository_url=docker.io%2Flibrary"
	a, ctx := storeWithLegacyProducts(t, "docker.io/library/redis@"+digest, legacy)

	full, filtered := manifestsForImage("docker.io/library/nginx@" + digest)
	require.NoError(t, a.StoreVEX(ctx, full, filtered, false))

	requireProducts(t, a, ctx, full.Name, imageProductID("docker.io/library/nginx@"+digest))
}

// The container is named after the workload instance, which keeps its name when a bare pod's
// image is changed in place or a mutable tag resolves to another digest. After a rescan on the
// new digest, every finding has a statement naming that digest with this scan's verdict, a
// finding only the old image had is no longer asserted, and another author's statement stays.
func TestAPIServerStore_updateVEX_imageChangedUnderTheSameName(t *testing.T) {
	const (
		imageA = "docker.io/library/nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		imageB = "docker.io/library/nginx@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	match := func(cve, purl string) v1beta1.Match {
		return v1beta1.Match{
			Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: cve, DataSource: "https://example.com/" + cve}},
			Artifact:      v1beta1.GrypePackage{PURL: purl},
		}
	}
	manifests := func(image string, matches ...v1beta1.Match) (domain.CVEManifest, domain.CVEManifest) {
		m := domain.CVEManifest{
			Name:        "pod-web-0-nginx-5cf6-a1fd",
			Annotations: map[string]string{helpersv1.ImageIDMetadataKey: image},
			Content:     &v1beta1.GrypeDocument{Matches: matches},
		}
		return m, m // every finding is relevant
	}
	openssl := match("CVE-2024-1", "pkg:deb/debian/openssl@3.0.1")
	zlib := match("CVE-2024-2", "pkg:deb/debian/zlib@1.2")
	curl := match("CVE-2024-3", "pkg:deb/debian/curl@8.0")

	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.TODO()
	vexClient := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace)

	full, filtered := manifests(imageA, openssl, zlib)
	require.NoError(t, a.StoreVEX(ctx, full, filtered, false))
	stored, err := vexClient.Get(ctx, full.Name, metav1.GetOptions{})
	require.NoError(t, err)
	external := v1beta1.Statement{
		ID:            "https://vendor.example/vex/statement/1",
		Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2099-0001"},
		Products:      []v1beta1.Product{imageProduct(imageProductID(imageA), "pkg:deb/debian/zlib@1.2")},
		Status:        v1beta1.Status(vex.StatusNotAffected),
		Justification: v1beta1.Justification(vex.ComponentNotPresent),
	}
	stored.Spec.Statements = append(stored.Spec.Statements, external)
	_, err = vexClient.Update(ctx, stored, metav1.UpdateOptions{})
	require.NoError(t, err)

	full, filtered = manifests(imageB, openssl, curl)
	require.NoError(t, a.StoreVEX(ctx, full, filtered, false))
	got, err := vexClient.Get(ctx, full.Name, metav1.GetOptions{})
	require.NoError(t, err)

	want := imageProductID(imageB)
	local := map[string]v1beta1.Statement{}
	for _, s := range got.Spec.Statements {
		if !isLocalStatement(s.ID) {
			assert.Equal(t, external, s, "another author's statement is left as it was")
			continue
		}
		require.Len(t, s.Products, 1)
		assert.Equal(t, want, s.Products[0].ID, "statement %s names another image", s.ID)
		local[s.Vulnerability.Name] = s
	}
	assert.Len(t, local, 2)
	assert.NotContains(t, local, "CVE-2024-2", "a finding only the previous image had is not asserted")
	for _, cve := range []string{"CVE-2024-1", "CVE-2024-3"} {
		assert.Equal(t, v1beta1.Status(vex.StatusAffected), local[cve].Status, cve)
	}
	assert.Equal(t, imageB, got.Annotations[helpersv1.ImageIDMetadataKey])
}

// End to end through StoreVEX: a document an older kubevuln stored is rewritten on the next
// scan of the image, without a statement added beside the migrated ones, and the scan after
// that leaves it alone.
func TestAPIServerStore_updateVEX_migratesLegacyImageProducts(t *testing.T) {
	const image = "index.docker.io/library/nginx@sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228"
	cveManifestFull := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")
	for _, m := range []*domain.CVEManifest{&cveManifestFull, &cveManifestFiltered} {
		m.Annotations = maps.Clone(m.Annotations)
		m.Annotations[helpersv1.ImageIDMetadataKey] = image
	}
	legacy, current := legacyImageProductID(image), imageProductID(image)
	require.NotEqual(t, legacy, current)

	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "nginx:latest",
		ContainerName: "anyJobContName",
	})
	vexClient := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace)

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))
	stored, err := vexClient.Get(ctx, cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)

	// Make it the document an older kubevuln stored: each of our products names the image the
	// old way. Another author's statement names it the same way.
	ours := 0
	for i := range stored.Spec.Statements {
		if !isLocalStatement(stored.Spec.Statements[i].ID) {
			continue
		}
		for j := range stored.Spec.Statements[i].Products {
			require.Equal(t, current, stored.Spec.Statements[i].Products[j].ID)
			stored.Spec.Statements[i].Products[j].ID = legacy
			ours++
		}
	}
	require.NotZero(t, ours)
	external := v1beta1.Statement{
		ID:            "https://vendor.example/vex/statement/1",
		Vulnerability: v1beta1.VexVulnerability{Name: "CVE-2099-0001"},
		Products:      []v1beta1.Product{imageProduct(legacy, "pkg:deb/debian/zlib1g@1.2.13")},
		Status:        v1beta1.Status(vex.StatusNotAffected),
		Justification: v1beta1.Justification(vex.ComponentNotPresent),
	}
	stored.Spec.Statements = append(stored.Spec.Statements, external)
	statementCount := len(stored.Spec.Statements)
	_, err = vexClient.Update(ctx, stored, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))
	migrated, err := vexClient.Get(ctx, cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)

	assert.Len(t, migrated.Spec.Statements, statementCount, "no statement is added beside the migrated ones")
	var sawExternal bool
	for _, s := range migrated.Spec.Statements {
		if !isLocalStatement(s.ID) {
			assert.Equal(t, external, s, "another author's statement is left as it was")
			sawExternal = true
			continue
		}
		for _, p := range s.Products {
			assert.Equal(t, current, p.ID, "statement %s still names the image the old way", s.ID)
		}
	}
	assert.True(t, sawExternal)

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))
	again, err := vexClient.Get(ctx, cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, migrated.Spec.Version, again.Spec.Version, "a migrated document is not written again")
}
