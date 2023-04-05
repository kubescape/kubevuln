package v1

import (
	"testing"

	"github.com/go-test/deep"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func Test_domainToSpdx(t *testing.T) {
	tests := []struct {
		name    string
		doc     v1beta1.Document
		want    *v2_3.Document
		wantErr bool
	}{
		{
			name: "Test domainToSpdx",
			doc: v1beta1.Document{
				Annotations: []v1beta1.Annotation{{}},
				CreationInfo: &v1beta1.CreationInfo{
					Creators: []v1beta1.Creator{{}},
				},
				ExternalDocumentReferences: []v1beta1.ExternalDocumentRef{{}},
				OtherLicenses:              []*v1beta1.OtherLicense{{}},
				Packages: []*v1beta1.Package{{
					Annotations: []v1beta1.Annotation{{}},
					Files: []*v1beta1.File{{
						ArtifactOfProjects: []*v1beta1.ArtifactOfProject{{}},
						Snippets: map[v1beta1.ElementID]*v1beta1.Snippet{"": {
							Ranges: []v1beta1.SnippetRange{{}},
						}},
					}},
					PackageChecksums:          []v1beta1.Checksum{{}},
					PackageExternalReferences: []*v1beta1.PackageExternalReference{{}},
					PackageSupplier:           &v1beta1.Supplier{},
					PackageOriginator:         &v1beta1.Originator{},
					PackageVerificationCode:   &v1beta1.PackageVerificationCode{},
				}},
				Relationships: []*v1beta1.Relationship{{}},
				Reviews:       []*v1beta1.Review{{}},
				Snippets:      []v1beta1.Snippet{{}},
			},
			want: &v2_3.Document{
				Annotations: []*v2_3.Annotation{{}},
				CreationInfo: &v2_3.CreationInfo{
					Creators: []common.Creator{{}},
				},
				ExternalDocumentReferences: []v2_3.ExternalDocumentRef{{}},
				OtherLicenses:              []*v2_3.OtherLicense{{}},
				Packages: []*v2_3.Package{{
					Annotations: []v2_3.Annotation{{}},
					Files: []*v2_3.File{{
						ArtifactOfProjects: []*v2_3.ArtifactOfProject{{}},
						Snippets: map[common.ElementID]*v2_3.Snippet{"": {
							Ranges: []common.SnippetRange{{}},
						}},
					}},
					PackageChecksums:          []common.Checksum{{}},
					PackageExternalReferences: []*v2_3.PackageExternalReference{{}},
					PackageSupplier:           &common.Supplier{},
					PackageOriginator:         &common.Originator{},
					PackageVerificationCode:   &common.PackageVerificationCode{},
				}},
				Relationships: []*v2_3.Relationship{{}},
				Reviews:       []*v2_3.Review{{}},
				Snippets:      []v2_3.Snippet{{}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := domainToSpdx(tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("domainToSpdx() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			diff := deep.Equal(got, tt.want)
			if diff != nil {
				t.Errorf("compare failed: %v", diff)
			}
		})
	}
}
