package repositories

import (
	"context"
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

			migrateLegacyImageProducts(statements, tc.image)
			assert.Equal(t, want, statements, "only our product for this image is renamed")

			migrateLegacyImageProducts(statements, tc.image)
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

		migrateLegacyImageProducts(statements, image)
		assert.Equal(t, want, statements, "%q", image)
	}
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
