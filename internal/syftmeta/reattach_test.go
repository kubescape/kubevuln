package syftmeta

import (
	"fmt"
	"testing"

	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func storedPackages(ids ...string) []v1beta1.SyftPackage {
	out := make([]v1beta1.SyftPackage, 0, len(ids))
	for _, id := range ids {
		out = append(out, v1beta1.SyftPackage{PackageBasicData: v1beta1.PackageBasicData{ID: id}})
	}
	return out
}

func docPackage(id, metadataType string, metadata any) model.Package {
	return model.Package{
		PackageBasicData:  model.PackageBasicData{ID: id},
		PackageCustomData: model.PackageCustomData{MetadataType: metadataType, Metadata: metadata},
	}
}

func TestReattach(t *testing.T) {
	stored := storedPackages("a", "b", "c")
	doc := []model.Package{
		docPackage("a", "JavaMetadata", map[string]string{"virtualPath": "/a.jar"}),
		docPackage("b", "ApkMetadata", map[string]string{"package": "b"}),
		docPackage("c", "", nil),
	}

	Reattach(stored, doc)

	assert.Equal(t, "JavaMetadata", stored[0].MetadataType)
	assert.JSONEq(t, `{"virtualPath":"/a.jar"}`, string(stored[0].Metadata))
	assert.Equal(t, "ApkMetadata", stored[1].MetadataType)
	assert.JSONEq(t, `{"package":"b"}`, string(stored[1].Metadata))
	assert.Equal(t, "", stored[2].MetadataType)
	assert.JSONEq(t, `null`, string(stored[2].Metadata))
}

// The stored list comes from marshalling the same document, so the two are normally aligned,
// but the pairing is by ID rather than by position and must stay that way: nothing in the
// round-trip promises an order.
func TestReattach_PairsByIDNotPosition(t *testing.T) {
	stored := storedPackages("c", "a", "b")
	doc := []model.Package{
		docPackage("a", "JavaMetadata", nil),
		docPackage("b", "ApkMetadata", nil),
		docPackage("c", "RpmMetadata", nil),
	}

	Reattach(stored, doc)

	assert.Equal(t, "RpmMetadata", stored[0].MetadataType)
	assert.Equal(t, "JavaMetadata", stored[1].MetadataType)
	assert.Equal(t, "ApkMetadata", stored[2].MetadataType)
}

// A stored package with no counterpart keeps what it already had rather than being cleared.
func TestReattach_LeavesUnmatchedAlone(t *testing.T) {
	stored := storedPackages("a", "orphan")
	stored[1].MetadataType = "existing"
	stored[1].Metadata = []byte(`{"kept":true}`)

	Reattach(stored, []model.Package{docPackage("a", "JavaMetadata", nil)})

	assert.Equal(t, "JavaMetadata", stored[0].MetadataType)
	assert.Equal(t, "existing", stored[1].MetadataType)
	assert.JSONEq(t, `{"kept":true}`, string(stored[1].Metadata))
}

// Syft keys its package collection by ID so duplicates should not occur, but the search this
// replaced stopped at the first match and this keeps that resolution rather than the last.
func TestReattach_FirstWinsOnDuplicateID(t *testing.T) {
	stored := storedPackages("dup")
	doc := []model.Package{
		docPackage("dup", "first", nil),
		docPackage("dup", "second", nil),
	}

	Reattach(stored, doc)

	assert.Equal(t, "first", stored[0].MetadataType)
}

func TestReattach_EmptyInputs(t *testing.T) {
	require.NotPanics(t, func() {
		Reattach(nil, nil)
		Reattach(storedPackages("a"), nil)
		Reattach(nil, []model.Package{docPackage("a", "t", nil)})
	})
}

// Metadata that cannot be marshalled leaves the package's existing value alone instead of
// replacing it with a broken one.
func TestReattach_UnmarshalableMetadataIsSkipped(t *testing.T) {
	stored := storedPackages("a")
	stored[0].Metadata = []byte(`{"kept":true}`)

	Reattach(stored, []model.Package{docPackage("a", "JavaMetadata", make(chan int))})

	assert.Equal(t, "JavaMetadata", stored[0].MetadataType)
	assert.JSONEq(t, `{"kept":true}`, string(stored[0].Metadata))
}

func benchmarkInputs(n int) ([]v1beta1.SyftPackage, []model.Package) {
	ids := make([]string, n)
	doc := make([]model.Package, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%016x-package-id", i)
		ids[i] = id
		doc[i] = docPackage(id, "JavaMetadata", map[string]string{"virtualPath": id})
	}
	return storedPackages(ids...), doc
}

func BenchmarkReattach(b *testing.B) {
	for _, n := range []int{500, 2000, 8000} {
		stored, doc := benchmarkInputs(n)
		b.Run(fmt.Sprintf("packages-%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				Reattach(stored, doc)
			}
		})
	}
}
