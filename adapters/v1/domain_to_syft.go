package v1

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/google/go-cmp/cmp"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func domainJSONToSyft(data []byte) (*sbom.SBOM, error) {
	var d model.Document

	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	return toSyftModel(d), nil
}

func domainToSyft(doc v1beta1.SyftDocument) (*sbom.SBOM, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return domainJSONToSyft(b)

}

// ========================= copied code ================================
// code below is copied from https://github.com/anchore/syft/blob/v0.98.0/syft/format/syftjson/to_syft_model.go
func toSyftModel(doc model.Document) *sbom.SBOM {
	idAliases := make(map[string]string)

	catalog := toSyftCatalog(doc.Artifacts, idAliases)

	fileArtifacts := toSyftFiles(doc.Files)

	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          catalog,
			FileMetadata:      fileArtifacts.FileMetadata,
			FileDigests:       fileArtifacts.FileDigests,
			FileContents:      fileArtifacts.FileContents,
			FileLicenses:      fileArtifacts.FileLicenses,
			LinuxDistribution: toSyftLinuxRelease(doc.Distro),
		},
		Source:        *toSyftSourceData(doc.Source),
		Descriptor:    toSyftDescriptor(doc.Descriptor),
		Relationships: toSyftRelationships(&doc, catalog, doc.ArtifactRelationships, idAliases),
	}
}

func toSyftFiles(files []model.File) sbom.Artifacts {
	ret := sbom.Artifacts{
		FileMetadata: make(map[file.Coordinates]file.Metadata),
		FileDigests:  make(map[file.Coordinates][]file.Digest),
		FileContents: make(map[file.Coordinates]string),
		FileLicenses: make(map[file.Coordinates][]file.License),
	}

	for _, f := range files {
		coord := f.Location
		if f.Metadata != nil {
			mode, err := strconv.ParseInt(strconv.Itoa(f.Metadata.Mode), 8, 64)
			if err != nil {
				// todo: handle error
				mode = 0
			}

			fm := os.FileMode(mode)

			ret.FileMetadata[coord] = file.Metadata{
				FileInfo: stereoscopeFile.ManualInfo{
					NameValue: path.Base(coord.RealPath),
					SizeValue: f.Metadata.Size,
					ModeValue: fm,
				},
				Path:            coord.RealPath,
				LinkDestination: f.Metadata.LinkDestination,
				UserID:          f.Metadata.UserID,
				GroupID:         f.Metadata.GroupID,
				Type:            toSyftFileType(f.Metadata.Type),
				MIMEType:        f.Metadata.MIMEType,
			}
		}

		for _, d := range f.Digests {
			ret.FileDigests[coord] = append(ret.FileDigests[coord], file.Digest{
				Algorithm: d.Algorithm,
				Value:     d.Value,
			})
		}

		if f.Contents != "" {
			ret.FileContents[coord] = f.Contents
		}

		for _, l := range f.Licenses {
			var evidence *file.LicenseEvidence
			if e := l.Evidence; e != nil {
				evidence = &file.LicenseEvidence{
					Confidence: e.Confidence,
					Offset:     e.Offset,
					Extent:     e.Extent,
				}
			}
			ret.FileLicenses[coord] = append(ret.FileLicenses[coord], file.License{
				Value:           l.Value,
				SPDXExpression:  l.SPDXExpression,
				Type:            l.Type,
				LicenseEvidence: evidence,
			})
		}
	}

	return ret
}

func toSyftLicenses(m []model.License) (p []pkg.License) {
	for _, l := range m {
		p = append(p, pkg.License{
			Value:          l.Value,
			SPDXExpression: l.SPDXExpression,
			Type:           l.Type,
			URLs:           l.URLs,
			Locations:      file.NewLocationSet(l.Locations...),
		})
	}
	return
}

func toSyftFileType(ty string) stereoscopeFile.Type {
	switch ty {
	case "SymbolicLink":
		return stereoscopeFile.TypeSymLink
	case "HardLink":
		return stereoscopeFile.TypeHardLink
	case "Directory":
		return stereoscopeFile.TypeDirectory
	case "Socket":
		return stereoscopeFile.TypeSocket
	case "BlockDevice":
		return stereoscopeFile.TypeBlockDevice
	case "CharacterDevice":
		return stereoscopeFile.TypeCharacterDevice
	case "FIFONode":
		return stereoscopeFile.TypeFIFO
	case "RegularFile":
		return stereoscopeFile.TypeRegular
	case "IrregularFile":
		return stereoscopeFile.TypeIrregular
	default:
		return stereoscopeFile.TypeIrregular
	}
}

func toSyftLinuxRelease(d model.LinuxRelease) *linux.Release {
	if cmp.Equal(d, model.LinuxRelease{}) {
		return nil
	}
	return &linux.Release{
		PrettyName:       d.PrettyName,
		Name:             d.Name,
		ID:               d.ID,
		IDLike:           d.IDLike,
		Version:          d.Version,
		VersionID:        d.VersionID,
		VersionCodename:  d.VersionCodename,
		BuildID:          d.BuildID,
		ImageID:          d.ImageID,
		ImageVersion:     d.ImageVersion,
		Variant:          d.Variant,
		VariantID:        d.VariantID,
		HomeURL:          d.HomeURL,
		SupportURL:       d.SupportURL,
		BugReportURL:     d.BugReportURL,
		PrivacyPolicyURL: d.PrivacyPolicyURL,
		CPEName:          d.CPEName,
		SupportEnd:       d.SupportEnd,
	}
}

func toSyftRelationships(doc *model.Document, catalog *pkg.Collection, relationships []model.Relationship, idAliases map[string]string) []artifact.Relationship {
	idMap := make(map[string]interface{})

	for _, p := range catalog.Sorted() {
		idMap[string(p.ID())] = p
		locations := p.Locations.ToSlice()
		for _, l := range locations {
			idMap[string(l.Coordinates.ID())] = l.Coordinates
		}
	}

	// set source metadata in identifier map
	idMap[doc.Source.ID] = toSyftSource(doc.Source)

	for _, f := range doc.Files {
		idMap[f.ID] = f.Location
	}

	var out []artifact.Relationship
	for _, r := range relationships {
		syftRelationship, err := toSyftRelationship(idMap, r, idAliases)
		if err != nil {
			// TODO handle error
			continue
		}
		if syftRelationship != nil {
			out = append(out, *syftRelationship)
		}
	}

	return out
}

func toSyftSource(s model.Source) source.Source {
	description := toSyftSourceData(s)
	if description == nil {
		return nil
	}
	return source.FromDescription(*description)
}

func toSyftRelationship(idMap map[string]interface{}, relationship model.Relationship, idAliases map[string]string) (*artifact.Relationship, error) {
	id := func(id string) string {
		aliased, ok := idAliases[id]
		if ok {
			return aliased
		}
		return id
	}

	from, ok := idMap[id(relationship.Parent)].(artifact.Identifiable)
	if !ok {
		return nil, fmt.Errorf("relationship mapping from key %s is not a valid artifact.Identifiable type: %+v", relationship.Parent, idMap[relationship.Parent])
	}

	to, ok := idMap[id(relationship.Child)].(artifact.Identifiable)
	if !ok {
		return nil, fmt.Errorf("relationship mapping to key %s is not a valid artifact.Identifiable type: %+v", relationship.Child, idMap[relationship.Child])
	}

	typ := artifact.RelationshipType(relationship.Type)

	switch typ {
	case artifact.OwnershipByFileOverlapRelationship, artifact.ContainsRelationship, artifact.DependencyOfRelationship, artifact.EvidentByRelationship:
	default:
		if !strings.Contains(string(typ), "dependency-of") {
			return nil, fmt.Errorf("unknown relationship type: %s", string(typ))
		}
		// lets try to stay as compatible as possible with similar relationship types without dropping the relationship
		typ = artifact.DependencyOfRelationship
	}
	return &artifact.Relationship{
		From: from,
		To:   to,
		Type: typ,
		Data: relationship.Metadata,
	}, nil
}

func toSyftDescriptor(d model.Descriptor) sbom.Descriptor {
	return sbom.Descriptor{
		Name:          d.Name,
		Version:       d.Version,
		Configuration: d.Configuration,
	}
}

func toSyftSourceData(s model.Source) *source.Description {
	return &source.Description{
		ID:       s.ID,
		Name:     s.Name,
		Version:  s.Version,
		Metadata: s.Metadata,
	}
}

func toSyftCatalog(pkgs []model.Package, idAliases map[string]string) *pkg.Collection {
	catalog := pkg.NewCollection()
	for _, p := range pkgs {
		catalog.Add(toSyftPackage(p, idAliases))
	}
	return catalog
}

func toSyftPackage(p model.Package, idAliases map[string]string) pkg.Package {
	var cpes []cpe.CPE
	for _, c := range p.CPEs {
		value, err := cpe.New(c)
		if err != nil {
			continue
		}

		cpes = append(cpes, value)
	}

	out := pkg.Package{
		Name:      p.Name,
		Version:   p.Version,
		FoundBy:   p.FoundBy,
		Locations: file.NewLocationSet(p.Locations...),
		Licenses:  pkg.NewLicenseSet(toSyftLicenses(p.Licenses)...),
		Language:  p.Language,
		Type:      p.Type,
		CPEs:      cpes,
		PURL:      p.PURL,
		Metadata:  p.Metadata,
	}

	// we don't know if this package ID is truly unique, however, we need to trust the user input in case there are
	// external references to it. That is, we can't derive our own ID (using pkg.SetID()) since consumers won't
	// be able to historically interact with data that references the IDs from the original SBOM document being decoded now.
	out.OverrideID(artifact.ID(p.ID))

	// this alias mapping is currently defunct, but could be useful in the future.
	id := string(out.ID())
	if id != p.ID {
		idAliases[p.ID] = id
	}

	return out
}

// ========================= end of copied code ================================
