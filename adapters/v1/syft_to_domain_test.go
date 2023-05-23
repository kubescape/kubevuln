package v1

import (
	"testing"
	"time"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"
)

func TestSyftAdapter_spdxToDomain(t *testing.T) {
	tests := []struct {
		name    string
		spdxDoc *v2_3.Document
		want    *v1beta1.Document
		wantErr bool
	}{
		{
			name: "Test spdxToDomain",
			spdxDoc: &v2_3.Document{
				Annotations: []*v2_3.Annotation{{}},
				CreationInfo: &v2_3.CreationInfo{
					Creators: []common.Creator{{
						Creator: "syft-",
					}},
				},
				ExternalDocumentReferences: []v2_3.ExternalDocumentRef{{}},
				Files:                      []*v2_3.File{{}},
				OtherLicenses:              []*v2_3.OtherLicense{{}},
				Packages: []*v2_3.Package{{
					Annotations: []v2_3.Annotation{{}},
					Files: []*v2_3.File{{
						Annotations:        []v2_3.Annotation{{}},
						ArtifactOfProjects: []*v2_3.ArtifactOfProject{{}},
						Checksums:          []common.Checksum{{}},
						Snippets:           map[common.ElementID]*v2_3.Snippet{"": {}},
					}},
					PackageChecksums:          []common.Checksum{{}},
					PackageExternalReferences: []*v2_3.PackageExternalReference{{}},
					PackageOriginator:         &common.Originator{},
					PackageSupplier:           &common.Supplier{},
					PackageVerificationCode:   &common.PackageVerificationCode{},
				}},
				Relationships: []*v2_3.Relationship{{}},
				Reviews:       []*v2_3.Review{{}},
				Snippets: []v2_3.Snippet{{
					Ranges: []common.SnippetRange{{}},
				}},
			},
			want: &v1beta1.Document{
				Annotations: []v1beta1.Annotation{{}},
				CreationInfo: &v1beta1.CreationInfo{
					Creators: []v1beta1.Creator{{
						Creator: "syft-unknown",
					}},
				},
				ExternalDocumentReferences: []v1beta1.ExternalDocumentRef{{}},
				Files:                      []*v1beta1.File{{}},
				OtherLicenses:              []*v1beta1.OtherLicense{{}},
				Packages: []*v1beta1.Package{{
					Annotations: []v1beta1.Annotation{{}},
					Files: []*v1beta1.File{{
						Annotations:        []v1beta1.Annotation{{}},
						ArtifactOfProjects: []*v1beta1.ArtifactOfProject{{}},
						Checksums:          []v1beta1.Checksum{{}},
						Snippets:           map[v1beta1.ElementID]*v1beta1.Snippet{"": {}},
					}},
					PackageChecksums:          []v1beta1.Checksum{{}},
					PackageExternalReferences: []*v1beta1.PackageExternalReference{{}},
					PackageOriginator:         &v1beta1.Originator{},
					PackageSupplier:           &v1beta1.Supplier{},
					PackageVerificationCode:   &v1beta1.PackageVerificationCode{},
				}},
				Relationships: []*v1beta1.Relationship{{}},
				Reviews:       []*v1beta1.Review{{}},
				Snippets: []v1beta1.Snippet{{
					Ranges: []v1beta1.SnippetRange{{}},
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SyftAdapter{
				scanTimeout: 5 * time.Minute,
			}
			got, err := s.spdxToDomain(tt.spdxDoc)
			if (err != nil) != tt.wantErr {
				t.Errorf("spdxToDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, got, tt.want)
		})
	}
}
