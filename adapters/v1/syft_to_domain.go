package v1

import (
	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func (s *SyftAdapter) syftToDomain(syftSBOM sbom.SBOM) (*v1beta1.Document, error) {
	spdxDoc := spdxhelpers.ToFormatModel(syftSBOM)
	return s.spdxToDomain(spdxDoc)
}

func (s *SyftAdapter) spdxToDomain(spdxDoc *v2_3.Document) (*v1beta1.Document, error) {
	doc := v1beta1.Document{
		SPDXVersion:                spdxDoc.SPDXVersion,
		DataLicense:                spdxDoc.DataLicense,
		SPDXIdentifier:             v1beta1.ElementID(spdxDoc.SPDXIdentifier),
		DocumentName:               spdxDoc.DocumentName,
		DocumentNamespace:          spdxDoc.DocumentNamespace,
		ExternalDocumentReferences: syftToDomainExternalDocumentReferences(spdxDoc.ExternalDocumentReferences),
		DocumentComment:            spdxDoc.DocumentComment,
		Packages:                   syftToDomainPackages(spdxDoc.Packages),
		Files:                      syftToDomainFiles(spdxDoc.Files),
		OtherLicenses:              syftToDomainOtherLicenses(spdxDoc.OtherLicenses),
		Relationships:              syftToDomainRelationships(spdxDoc.Relationships),
		Annotations:                syftToDomainAnnotations(spdxDoc.Annotations),
		Snippets:                   syftToDomainSnippets(spdxDoc.Snippets),
		Reviews:                    syftToDomainReviews(spdxDoc.Reviews),
	}
	if spdxDoc.CreationInfo != nil {
		doc.CreationInfo = &v1beta1.CreationInfo{
			LicenseListVersion: spdxDoc.CreationInfo.LicenseListVersion,
			Creators:           s.syftToDomainCreators(spdxDoc.CreationInfo.Creators),
			Created:            spdxDoc.CreationInfo.Created,
			CreatorComment:     spdxDoc.CreationInfo.CreatorComment,
		}
	}
	return &doc, nil
}

func syftToDomainExternalDocumentReferences(externalDocumentReferences []v2_3.ExternalDocumentRef) []v1beta1.ExternalDocumentRef {
	var result []v1beta1.ExternalDocumentRef
	for _, e := range externalDocumentReferences {
		result = append(result, v1beta1.ExternalDocumentRef{
			DocumentRefID: e.DocumentRefID,
			URI:           e.URI,
			Checksum: v1beta1.Checksum{
				Algorithm: v1beta1.ChecksumAlgorithm(e.Checksum.Algorithm),
				Value:     e.Checksum.Value,
			},
		})
	}
	return result
}

func (s *SyftAdapter) syftToDomainCreators(creators []common.Creator) []v1beta1.Creator {
	var result []v1beta1.Creator
	for _, c := range creators {
		creator := c.Creator
		if creator == "syft-" {
			creator += s.Version()
		}
		result = append(result, v1beta1.Creator{
			Creator:     creator,
			CreatorType: c.CreatorType,
		})
	}
	return result
}

func syftToDomainPackages(packages []*v2_3.Package) []*v1beta1.Package {
	var result []*v1beta1.Package
	for _, p := range packages {
		newP := v1beta1.Package{
			HasFiles:                    nil, // TODO check with Vlad
			IsUnpackaged:                p.IsUnpackaged,
			PackageName:                 p.PackageName,
			PackageSPDXIdentifier:       v1beta1.ElementID(p.PackageSPDXIdentifier),
			PackageVersion:              p.PackageVersion,
			PackageFileName:             p.PackageFileName,
			PackageDownloadLocation:     p.PackageDownloadLocation,
			FilesAnalyzed:               p.FilesAnalyzed,
			IsFilesAnalyzedTagPresent:   p.IsFilesAnalyzedTagPresent,
			PackageChecksums:            syftToDomainPackagesPackageChecksums(p.PackageChecksums),
			PackageHomePage:             p.PackageHomePage,
			PackageSourceInfo:           p.PackageSourceInfo,
			PackageLicenseConcluded:     p.PackageLicenseConcluded,
			PackageLicenseInfoFromFiles: p.PackageLicenseInfoFromFiles,
			PackageLicenseDeclared:      p.PackageLicenseDeclared,
			PackageLicenseComments:      p.PackageLicenseComments,
			PackageCopyrightText:        p.PackageCopyrightText,
			PackageSummary:              p.PackageSummary,
			PackageDescription:          p.PackageDescription,
			PackageComment:              p.PackageComment,
			PackageExternalReferences:   syftToDomainPackagesPackageExternalReferences(p.PackageExternalReferences),
			PackageAttributionTexts:     p.PackageAttributionTexts,
			PrimaryPackagePurpose:       p.PrimaryPackagePurpose,
			ReleaseDate:                 p.ReleaseDate,
			BuiltDate:                   p.BuiltDate,
			ValidUntilDate:              p.ValidUntilDate,
			Files:                       syftToDomainFiles(p.Files),
			Annotations:                 syftToDomainPackagesAnnotations(p.Annotations),
		}
		if p.PackageSupplier != nil {
			newP.PackageSupplier = &v1beta1.Supplier{
				Supplier:     p.PackageSupplier.Supplier,
				SupplierType: p.PackageSupplier.SupplierType,
			}
		}
		if p.PackageOriginator != nil {
			newP.PackageOriginator = &v1beta1.Originator{
				Originator:     p.PackageOriginator.Originator,
				OriginatorType: p.PackageOriginator.OriginatorType,
			}
		}
		if p.PackageVerificationCode != nil {
			newP.PackageVerificationCode = &v1beta1.PackageVerificationCode{
				Value:         p.PackageVerificationCode.Value,
				ExcludedFiles: p.PackageVerificationCode.ExcludedFiles,
			}
		}
		result = append(result, &newP)
	}
	return result
}

func syftToDomainPackagesPackageChecksums(packageChecksums []common.Checksum) []v1beta1.Checksum {
	var result []v1beta1.Checksum
	for _, p := range packageChecksums {
		result = append(result, v1beta1.Checksum{
			Algorithm: v1beta1.ChecksumAlgorithm(p.Algorithm),
			Value:     p.Value,
		})
	}
	return result
}

func syftToDomainPackagesPackageExternalReferences(packageExternalReferences []*v2_3.PackageExternalReference) []*v1beta1.PackageExternalReference {
	var result []*v1beta1.PackageExternalReference
	for _, p := range packageExternalReferences {
		result = append(result, &v1beta1.PackageExternalReference{
			Category:           p.Category,
			RefType:            p.RefType,
			Locator:            p.Locator,
			ExternalRefComment: p.ExternalRefComment,
		})
	}
	return result
}

func syftToDomainPackagesAnnotations(annotations []v2_3.Annotation) []v1beta1.Annotation {
	var result []v1beta1.Annotation
	for _, a := range annotations {
		result = append(result, v1beta1.Annotation{
			Annotator: v1beta1.Annotator{
				Annotator:     a.Annotator.Annotator,
				AnnotatorType: a.Annotator.AnnotatorType,
			},
			AnnotationDate: a.AnnotationDate,
			AnnotationType: a.AnnotationType,
			AnnotationSPDXIdentifier: v1beta1.DocElementID{
				DocumentRefID: a.AnnotationSPDXIdentifier.DocumentRefID,
				ElementRefID:  v1beta1.ElementID(a.AnnotationSPDXIdentifier.ElementRefID),
				SpecialID:     a.AnnotationSPDXIdentifier.SpecialID,
			},
			AnnotationComment: a.AnnotationComment,
		})
	}
	return result
}

func syftToDomainPackagesFilesArtifactOfProjects(artifactOfProjects []*v2_3.ArtifactOfProject) []*v1beta1.ArtifactOfProject {
	var result []*v1beta1.ArtifactOfProject
	for _, a := range artifactOfProjects {
		result = append(result, &v1beta1.ArtifactOfProject{
			Name:     a.Name,
			HomePage: a.HomePage,
			URI:      a.URI,
		})
	}
	return result
}

func syftToDomainPackagesFilesSnippets(snippets map[common.ElementID]*v2_3.Snippet) map[v1beta1.ElementID]*v1beta1.Snippet {
	if len(snippets) == 0 {
		return nil
	}
	result := make(map[v1beta1.ElementID]*v1beta1.Snippet)
	for k, s := range snippets {
		result[v1beta1.ElementID(k)] = &v1beta1.Snippet{
			SnippetSPDXIdentifier:         v1beta1.ElementID(s.SnippetSPDXIdentifier),
			SnippetFromFileSPDXIdentifier: v1beta1.ElementID(s.SnippetFromFileSPDXIdentifier),
			Ranges:                        syftToDomainPackagesFilesSnippetsRanges(s.Ranges),
			SnippetLicenseConcluded:       s.SnippetLicenseConcluded,
			LicenseInfoInSnippet:          s.LicenseInfoInSnippet,
			SnippetLicenseComments:        s.SnippetLicenseComments,
			SnippetCopyrightText:          s.SnippetCopyrightText,
			SnippetComment:                s.SnippetComment,
			SnippetName:                   s.SnippetName,
			SnippetAttributionTexts:       s.SnippetAttributionTexts,
		}
	}
	return result
}

func syftToDomainPackagesFilesSnippetsRanges(ranges []common.SnippetRange) []v1beta1.SnippetRange {
	var result []v1beta1.SnippetRange
	for _, r := range ranges {
		result = append(result, v1beta1.SnippetRange{
			StartPointer: v1beta1.SnippetRangePointer{
				Offset:             r.StartPointer.Offset,
				LineNumber:         r.StartPointer.LineNumber,
				FileSPDXIdentifier: v1beta1.ElementID(r.StartPointer.FileSPDXIdentifier),
			},
			EndPointer: v1beta1.SnippetRangePointer{
				Offset:             r.EndPointer.Offset,
				LineNumber:         r.EndPointer.LineNumber,
				FileSPDXIdentifier: v1beta1.ElementID(r.EndPointer.FileSPDXIdentifier),
			},
		})
	}
	return result
}

func syftToDomainFiles(files []*v2_3.File) []*v1beta1.File {
	var result []*v1beta1.File
	for _, f := range files {
		result = append(result, &v1beta1.File{
			FileName:             f.FileName,
			FileSPDXIdentifier:   v1beta1.ElementID(f.FileSPDXIdentifier),
			FileTypes:            f.FileTypes,
			Checksums:            syftToDomainPackagesPackageChecksums(f.Checksums),
			LicenseConcluded:     f.LicenseConcluded,
			LicenseInfoInFiles:   f.LicenseInfoInFiles,
			LicenseComments:      f.LicenseComments,
			FileCopyrightText:    f.FileCopyrightText,
			ArtifactOfProjects:   syftToDomainPackagesFilesArtifactOfProjects(f.ArtifactOfProjects),
			FileComment:          f.FileComment,
			FileNotice:           f.FileNotice,
			FileContributors:     f.FileContributors,
			FileAttributionTexts: f.FileAttributionTexts,
			FileDependencies:     f.FileDependencies,
			Snippets:             syftToDomainPackagesFilesSnippets(f.Snippets),
			Annotations:          syftToDomainPackagesAnnotations(f.Annotations),
		})
	}
	return result
}

func syftToDomainOtherLicenses(otherLicenses []*v2_3.OtherLicense) []*v1beta1.OtherLicense {
	var result []*v1beta1.OtherLicense
	for _, o := range otherLicenses {
		result = append(result, &v1beta1.OtherLicense{
			LicenseIdentifier:      o.LicenseIdentifier,
			ExtractedText:          o.ExtractedText,
			LicenseName:            o.LicenseName,
			LicenseCrossReferences: o.LicenseCrossReferences,
			LicenseComment:         o.LicenseComment,
		})
	}
	return result
}

func syftToDomainRelationships(relationships []*v2_3.Relationship) []*v1beta1.Relationship {
	var result []*v1beta1.Relationship
	for _, r := range relationships {
		result = append(result, &v1beta1.Relationship{
			RefA: v1beta1.DocElementID{
				DocumentRefID: r.RefA.DocumentRefID,
				ElementRefID:  v1beta1.ElementID(r.RefA.ElementRefID),
				SpecialID:     r.RefA.SpecialID,
			},
			RefB: v1beta1.DocElementID{
				DocumentRefID: r.RefB.DocumentRefID,
				ElementRefID:  v1beta1.ElementID(r.RefB.ElementRefID),
				SpecialID:     r.RefB.SpecialID,
			},
			Relationship:        r.Relationship,
			RelationshipComment: r.RelationshipComment,
		})
	}
	return result
}

func syftToDomainAnnotations(annotations []*v2_3.Annotation) []v1beta1.Annotation {
	var result []v1beta1.Annotation
	for _, a := range annotations {
		result = append(result, v1beta1.Annotation{
			Annotator: v1beta1.Annotator{
				Annotator:     a.Annotator.Annotator,
				AnnotatorType: a.Annotator.AnnotatorType,
			},
			AnnotationDate: a.AnnotationDate,
			AnnotationType: a.AnnotationType,
			AnnotationSPDXIdentifier: v1beta1.DocElementID{
				DocumentRefID: a.AnnotationSPDXIdentifier.DocumentRefID,
				ElementRefID:  v1beta1.ElementID(a.AnnotationSPDXIdentifier.ElementRefID),
				SpecialID:     a.AnnotationSPDXIdentifier.SpecialID,
			},
			AnnotationComment: a.AnnotationComment,
		})
	}
	return result
}

func syftToDomainSnippets(snippets []v2_3.Snippet) []v1beta1.Snippet {
	var result []v1beta1.Snippet
	for _, s := range snippets {
		result = append(result, v1beta1.Snippet{
			SnippetSPDXIdentifier:         v1beta1.ElementID(s.SnippetSPDXIdentifier),
			SnippetFromFileSPDXIdentifier: v1beta1.ElementID(s.SnippetFromFileSPDXIdentifier),
			Ranges:                        syftToDomainPackagesFilesSnippetsRanges(s.Ranges),
			SnippetLicenseConcluded:       s.SnippetLicenseConcluded,
			LicenseInfoInSnippet:          s.LicenseInfoInSnippet,
			SnippetLicenseComments:        s.SnippetLicenseComments,
			SnippetCopyrightText:          s.SnippetCopyrightText,
			SnippetComment:                s.SnippetComment,
			SnippetName:                   s.SnippetName,
			SnippetAttributionTexts:       s.SnippetAttributionTexts,
		})
	}
	return result
}

func syftToDomainReviews(reviews []*v2_3.Review) []*v1beta1.Review {
	var result []*v1beta1.Review
	for _, r := range reviews {
		result = append(result, &v1beta1.Review{
			Reviewer:      r.Reviewer,
			ReviewerType:  r.ReviewerType,
			ReviewDate:    r.ReviewDate,
			ReviewComment: r.ReviewComment,
		})
	}
	return result
}
