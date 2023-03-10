package v1

import (
	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func syftToDomain(syftSBOM sbom.SBOM) (*softwarecomposition.Document, error) {
	spdxDoc := spdxhelpers.ToFormatModel(syftSBOM)
	return spdxToDomain(spdxDoc)
}

func spdxToDomain(spdxDoc *v2_3.Document) (*softwarecomposition.Document, error) {
	doc := softwarecomposition.Document{
		SPDXVersion:                spdxDoc.SPDXVersion,
		DataLicense:                spdxDoc.DataLicense,
		SPDXIdentifier:             softwarecomposition.ElementID(spdxDoc.SPDXIdentifier),
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
		doc.CreationInfo = &softwarecomposition.CreationInfo{
			LicenseListVersion: spdxDoc.CreationInfo.LicenseListVersion,
			Creators:           syftToDomainCreators(spdxDoc.CreationInfo.Creators),
			Created:            spdxDoc.CreationInfo.Created,
			CreatorComment:     spdxDoc.CreationInfo.CreatorComment,
		}
	}
	return &doc, nil
}

func syftToDomainExternalDocumentReferences(externalDocumentReferences []v2_3.ExternalDocumentRef) []softwarecomposition.ExternalDocumentRef {
	var result []softwarecomposition.ExternalDocumentRef
	for _, e := range externalDocumentReferences {
		result = append(result, softwarecomposition.ExternalDocumentRef{
			DocumentRefID: e.DocumentRefID,
			URI:           e.URI,
			Checksum: softwarecomposition.Checksum{
				Algorithm: softwarecomposition.ChecksumAlgorithm(e.Checksum.Algorithm),
				Value:     e.Checksum.Value,
			},
		})
	}
	return result
}

func syftToDomainCreators(creators []common.Creator) []softwarecomposition.Creator {
	var result []softwarecomposition.Creator
	for _, c := range creators {
		result = append(result, softwarecomposition.Creator{
			Creator:     c.Creator,
			CreatorType: c.CreatorType,
		})
	}
	return result
}

func syftToDomainPackages(packages []*v2_3.Package) []*softwarecomposition.Package {
	var result []*softwarecomposition.Package
	for _, p := range packages {
		newP := softwarecomposition.Package{
			HasFiles:                    nil, // TODO check with Vlad
			IsUnpackaged:                p.IsUnpackaged,
			PackageName:                 p.PackageName,
			PackageSPDXIdentifier:       softwarecomposition.ElementID(p.PackageSPDXIdentifier),
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
			newP.PackageSupplier = &softwarecomposition.Supplier{
				Supplier:     p.PackageSupplier.Supplier,
				SupplierType: p.PackageSupplier.SupplierType,
			}
		}
		if p.PackageOriginator != nil {
			newP.PackageOriginator = &softwarecomposition.Originator{
				Originator:     p.PackageOriginator.Originator,
				OriginatorType: p.PackageOriginator.OriginatorType,
			}
		}
		if p.PackageVerificationCode != nil {
			newP.PackageVerificationCode = &softwarecomposition.PackageVerificationCode{
				Value:         p.PackageVerificationCode.Value,
				ExcludedFiles: p.PackageVerificationCode.ExcludedFiles,
			}
		}
		result = append(result, &newP)
	}
	return result
}

func syftToDomainPackagesPackageChecksums(packageChecksums []common.Checksum) []softwarecomposition.Checksum {
	var result []softwarecomposition.Checksum
	for _, p := range packageChecksums {
		result = append(result, softwarecomposition.Checksum{
			Algorithm: softwarecomposition.ChecksumAlgorithm(p.Algorithm),
			Value:     p.Value,
		})
	}
	return result
}

func syftToDomainPackagesPackageExternalReferences(packageExternalReferences []*v2_3.PackageExternalReference) []*softwarecomposition.PackageExternalReference {
	var result []*softwarecomposition.PackageExternalReference
	for _, p := range packageExternalReferences {
		result = append(result, &softwarecomposition.PackageExternalReference{
			Category:           p.Category,
			RefType:            p.RefType,
			Locator:            p.Locator,
			ExternalRefComment: p.ExternalRefComment,
		})
	}
	return result
}

func syftToDomainPackagesAnnotations(annotations []v2_3.Annotation) []softwarecomposition.Annotation {
	var result []softwarecomposition.Annotation
	for _, a := range annotations {
		result = append(result, softwarecomposition.Annotation{
			Annotator: softwarecomposition.Annotator{
				Annotator:     a.Annotator.Annotator,
				AnnotatorType: a.Annotator.AnnotatorType,
			},
			AnnotationDate: a.AnnotationDate,
			AnnotationType: a.AnnotationType,
			AnnotationSPDXIdentifier: softwarecomposition.DocElementID{
				DocumentRefID: a.AnnotationSPDXIdentifier.DocumentRefID,
				ElementRefID:  softwarecomposition.ElementID(a.AnnotationSPDXIdentifier.ElementRefID),
				SpecialID:     a.AnnotationSPDXIdentifier.SpecialID,
			},
			AnnotationComment: a.AnnotationComment,
		})
	}
	return result
}

func syftToDomainPackagesFilesArtifactOfProjects(artifactOfProjects []*v2_3.ArtifactOfProject) []*softwarecomposition.ArtifactOfProject {
	var result []*softwarecomposition.ArtifactOfProject
	for _, a := range artifactOfProjects {
		result = append(result, &softwarecomposition.ArtifactOfProject{
			Name:     a.Name,
			HomePage: a.HomePage,
			URI:      a.URI,
		})
	}
	return result
}

func syftToDomainPackagesFilesSnippets(snippets map[common.ElementID]*v2_3.Snippet) map[softwarecomposition.ElementID]*softwarecomposition.Snippet {
	result := make(map[softwarecomposition.ElementID]*softwarecomposition.Snippet)
	for k, s := range snippets {
		result[softwarecomposition.ElementID(k)] = &softwarecomposition.Snippet{
			SnippetSPDXIdentifier:         softwarecomposition.ElementID(s.SnippetSPDXIdentifier),
			SnippetFromFileSPDXIdentifier: softwarecomposition.ElementID(s.SnippetFromFileSPDXIdentifier),
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

func syftToDomainPackagesFilesSnippetsRanges(ranges []common.SnippetRange) []softwarecomposition.SnippetRange {
	var result []softwarecomposition.SnippetRange
	for _, r := range ranges {
		result = append(result, softwarecomposition.SnippetRange{
			StartPointer: softwarecomposition.SnippetRangePointer{
				Offset:             r.StartPointer.Offset,
				LineNumber:         r.StartPointer.LineNumber,
				FileSPDXIdentifier: softwarecomposition.ElementID(r.StartPointer.FileSPDXIdentifier),
			},
			EndPointer: softwarecomposition.SnippetRangePointer{
				Offset:             r.EndPointer.Offset,
				LineNumber:         r.EndPointer.LineNumber,
				FileSPDXIdentifier: softwarecomposition.ElementID(r.EndPointer.FileSPDXIdentifier),
			},
		})
	}
	return result
}

func syftToDomainFiles(files []*v2_3.File) []*softwarecomposition.File {
	var result []*softwarecomposition.File
	for _, f := range files {
		result = append(result, &softwarecomposition.File{
			FileName:             f.FileName,
			FileSPDXIdentifier:   softwarecomposition.ElementID(f.FileSPDXIdentifier),
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

func syftToDomainOtherLicenses(otherLicenses []*v2_3.OtherLicense) []*softwarecomposition.OtherLicense {
	var result []*softwarecomposition.OtherLicense
	for _, o := range otherLicenses {
		result = append(result, &softwarecomposition.OtherLicense{
			LicenseIdentifier:      o.LicenseIdentifier,
			ExtractedText:          o.ExtractedText,
			LicenseName:            o.LicenseName,
			LicenseCrossReferences: o.LicenseCrossReferences,
			LicenseComment:         o.LicenseComment,
		})
	}
	return result
}

func syftToDomainRelationships(relationships []*v2_3.Relationship) []*softwarecomposition.Relationship {
	var result []*softwarecomposition.Relationship
	for _, r := range relationships {
		result = append(result, &softwarecomposition.Relationship{
			RefA: softwarecomposition.DocElementID{
				DocumentRefID: r.RefA.DocumentRefID,
				ElementRefID:  softwarecomposition.ElementID(r.RefA.ElementRefID),
				SpecialID:     r.RefA.SpecialID,
			},
			RefB: softwarecomposition.DocElementID{
				DocumentRefID: r.RefB.DocumentRefID,
				ElementRefID:  softwarecomposition.ElementID(r.RefB.ElementRefID),
				SpecialID:     r.RefB.SpecialID,
			},
			Relationship:        r.Relationship,
			RelationshipComment: r.RelationshipComment,
		})
	}
	return result
}

func syftToDomainAnnotations(annotations []*v2_3.Annotation) []softwarecomposition.Annotation {
	var result []softwarecomposition.Annotation
	for _, a := range annotations {
		result = append(result, softwarecomposition.Annotation{
			Annotator: softwarecomposition.Annotator{
				Annotator:     a.Annotator.Annotator,
				AnnotatorType: a.Annotator.AnnotatorType,
			},
			AnnotationDate: a.AnnotationDate,
			AnnotationType: a.AnnotationType,
			AnnotationSPDXIdentifier: softwarecomposition.DocElementID{
				DocumentRefID: a.AnnotationSPDXIdentifier.DocumentRefID,
				ElementRefID:  softwarecomposition.ElementID(a.AnnotationSPDXIdentifier.ElementRefID),
				SpecialID:     a.AnnotationSPDXIdentifier.SpecialID,
			},
			AnnotationComment: a.AnnotationComment,
		})
	}
	return result
}

func syftToDomainSnippets(snippets []v2_3.Snippet) []softwarecomposition.Snippet {
	var result []softwarecomposition.Snippet
	for _, s := range snippets {
		result = append(result, softwarecomposition.Snippet{
			SnippetSPDXIdentifier:         softwarecomposition.ElementID(s.SnippetSPDXIdentifier),
			SnippetFromFileSPDXIdentifier: softwarecomposition.ElementID(s.SnippetFromFileSPDXIdentifier),
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

func syftToDomainReviews(reviews []*v2_3.Review) []*softwarecomposition.Review {
	var result []*softwarecomposition.Review
	for _, r := range reviews {
		result = append(result, &softwarecomposition.Review{
			Reviewer:      r.Reviewer,
			ReviewerType:  r.ReviewerType,
			ReviewDate:    r.ReviewDate,
			ReviewComment: r.ReviewComment,
		})
	}
	return result
}
