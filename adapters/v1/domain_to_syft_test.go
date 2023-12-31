package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_domainJSONToSyft(t *testing.T) {
	type args struct {
		data []byte
	}
	type source struct {
		id   string
		name string
	}

	type want struct {
		source                source
		artifacts             int // number of artifacts
		artifactRelationships int // number of artifact relationships
		files                 int // number of files
	}
	tests := []struct {
		name    string
		args    args
		want    want
		wantErr bool
	}{
		{
			name: "valid alpine SBOM",
			args: args{
				data: fileContent("testdata/alpine-sbom.json"),
			},
			want: want{
				artifacts:             15,
				artifactRelationships: 129,
				files:                 78,
				source: source{
					id:   "e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
					name: "alpine",
				},
			},
		}, {
			name: "valid nginx SBOM",
			args: args{
				data: fileContent("testdata/nginx-sbom.json"),
			},
			want: want{
				artifacts:             110,
				artifactRelationships: 3450,
				files:                 2940,
				source: source{
					id:   "6db649d8a1f720b6c59469c1c61c95fc3d332e437d457106a66b975515e75128",
					name: "nginx",
				},
			},
		}, {
			name: "valid hello-world SBOM",
			args: args{
				data: fileContent("testdata/hello-world-sbom.json"),
			},
			want: want{
				artifacts:             0,
				artifactRelationships: 0,
				files:                 0,
				source: source{
					id:   "432f982638b3aefab73cc58ab28f5c16e96fdb504e8c134fc58dff4bae8bf338",
					name: "library/hello-world",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := domainJSONToSyft(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("syftJSONToDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want.artifacts, got.Artifacts.Packages.PackageCount())
			assert.Equal(t, tt.want.artifactRelationships, len(got.Relationships))
			assert.Equal(t, tt.want.files, len(got.AllCoordinates()))
			assert.Equal(t, tt.want.source.id, got.Source.ID)
			assert.Equal(t, tt.want.source.name, got.Source.Name)
		})
	}
}
