package v1

import (
	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func domainToSyft(doc v1beta1.Document) (*sbom.SBOM, error) {
	spdxDoc, err := domainToSpdx(doc)
	if err != nil {
		return nil, err
	}
	return spdxhelpers.ToSyftModel(spdxDoc)
}

func domainToSpdx(doc v1beta1.Document) (*v2_3.Document, error) {
	spdxDoc := v2_3.Document{
		SPDXVersion:                doc.SPDXVersion,
		DataLicense:                doc.DataLicense,
		SPDXIdentifier:             common.ElementID(doc.SPDXIdentifier),
		DocumentName:               doc.DocumentName,
		DocumentNamespace:          doc.DocumentNamespace,
		ExternalDocumentReferences: domainToSyftExternalDocumentReferences(doc.ExternalDocumentReferences),
		DocumentComment:            doc.DocumentComment,
		Packages:                   domainToSyftPackages(doc.Packages),
		Files:                      domainToSyftFiles(doc.Files),
		OtherLicenses:              domainToSyftOtherLicenses(doc.OtherLicenses),
		Relationships:              domainToSyftRelationships(doc.Relationships),
		Annotations:                domainToSyftAnnotations(doc.Annotations),
		Snippets:                   domainToSyftSnippets(doc.Snippets),
		Reviews:                    domainToSyftReviews(doc.Reviews),
	}
	if doc.CreationInfo != nil {
		spdxDoc.CreationInfo = &v2_3.CreationInfo{
			LicenseListVersion: doc.CreationInfo.LicenseListVersion,
			Creators:           domainToSyftCreators(doc.CreationInfo.Creators),
			Created:            doc.CreationInfo.Created,
			CreatorComment:     doc.CreationInfo.CreatorComment,
		}
	}
	return &spdxDoc, nil
}

func domainToSyftExternalDocumentReferences(externalDocumentReferences []v1beta1.ExternalDocumentRef) []v2_3.ExternalDocumentRef {
	var result []v2_3.ExternalDocumentRef
	for _, e := range externalDocumentReferences {
		result = append(result, v2_3.ExternalDocumentRef{
			DocumentRefID: e.DocumentRefID,
			URI:           e.URI,
			Checksum: common.Checksum{
				Algorithm: common.ChecksumAlgorithm(e.Checksum.Algorithm),
				Value:     e.Checksum.Value,
			},
		})
	}
	return result
}

func domainToSyftCreators(creators []v1beta1.Creator) []common.Creator {
	var result []common.Creator
	for _, c := range creators {
		result = append(result, common.Creator{
			Creator:     c.Creator,
			CreatorType: c.CreatorType,
		})
	}
	return result
}

func domainToSyftPackages(packages []*v1beta1.Package) []*v2_3.Package {
	var result []*v2_3.Package
	for _, p := range packages {
		newP := v2_3.Package{
			IsUnpackaged:                p.IsUnpackaged,
			PackageName:                 p.PackageName,
			PackageSPDXIdentifier:       common.ElementID(p.PackageSPDXIdentifier),
			PackageVersion:              p.PackageVersion,
			PackageFileName:             p.PackageFileName,
			PackageDownloadLocation:     p.PackageDownloadLocation,
			FilesAnalyzed:               p.FilesAnalyzed,
			IsFilesAnalyzedTagPresent:   p.IsFilesAnalyzedTagPresent,
			PackageChecksums:            domainToSyftPackagesPackageChecksums(p.PackageChecksums),
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
			PackageExternalReferences:   domainToSyftPackagesPackageExternalReferences(p.PackageExternalReferences),
			PackageAttributionTexts:     p.PackageAttributionTexts,
			PrimaryPackagePurpose:       p.PrimaryPackagePurpose,
			ReleaseDate:                 p.ReleaseDate,
			BuiltDate:                   p.BuiltDate,
			ValidUntilDate:              p.ValidUntilDate,
			Files:                       domainToSyftFiles(p.Files),
			Annotations:                 domainToSyftPackagesAnnotations(p.Annotations),
		}
		if p.PackageSupplier != nil {
			newP.PackageSupplier = &common.Supplier{
				Supplier:     p.PackageSupplier.Supplier,
				SupplierType: p.PackageSupplier.SupplierType,
			}
		}
		if p.PackageOriginator != nil {
			newP.PackageOriginator = &common.Originator{
				Originator:     p.PackageOriginator.Originator,
				OriginatorType: p.PackageOriginator.OriginatorType,
			}
		}
		if p.PackageVerificationCode != nil {
			newP.PackageVerificationCode = &common.PackageVerificationCode{
				Value:         p.PackageVerificationCode.Value,
				ExcludedFiles: p.PackageVerificationCode.ExcludedFiles,
			}
		}
		result = append(result, &newP)
	}
	return result
}

func domainToSyftPackagesPackageChecksums(packageChecksums []v1beta1.Checksum) []common.Checksum {
	var result []common.Checksum
	for _, p := range packageChecksums {
		result = append(result, common.Checksum{
			Algorithm: common.ChecksumAlgorithm(p.Algorithm),
			Value:     p.Value,
		})
	}
	return result
}

func domainToSyftPackagesPackageExternalReferences(packageExternalReferences []*v1beta1.PackageExternalReference) []*v2_3.PackageExternalReference {
	var result []*v2_3.PackageExternalReference
	for _, p := range packageExternalReferences {
		result = append(result, &v2_3.PackageExternalReference{
			Category:           p.Category,
			RefType:            p.RefType,
			Locator:            p.Locator,
			ExternalRefComment: p.ExternalRefComment,
		})
	}
	return result
}

func domainToSyftPackagesAnnotations(annotations []v1beta1.Annotation) []v2_3.Annotation {
	var result []v2_3.Annotation
	for _, a := range annotations {
		result = append(result, v2_3.Annotation{
			Annotator: common.Annotator{
				Annotator:     a.Annotator.Annotator,
				AnnotatorType: a.Annotator.AnnotatorType,
			},
			AnnotationDate: a.AnnotationDate,
			AnnotationType: a.AnnotationType,
			AnnotationSPDXIdentifier: common.DocElementID{
				DocumentRefID: a.AnnotationSPDXIdentifier.DocumentRefID,
				ElementRefID:  common.ElementID(a.AnnotationSPDXIdentifier.ElementRefID),
				SpecialID:     a.AnnotationSPDXIdentifier.SpecialID,
			},
			AnnotationComment: a.AnnotationComment,
		})
	}
	return result
}

func domainToSyftPackagesFilesArtifactOfProjects(artifactOfProjects []*v1beta1.ArtifactOfProject) []*v2_3.ArtifactOfProject {
	var result []*v2_3.ArtifactOfProject
	for _, a := range artifactOfProjects {
		result = append(result, &v2_3.ArtifactOfProject{
			Name:     a.Name,
			HomePage: a.HomePage,
			URI:      a.URI,
		})
	}
	return result
}

func domainToSyftPackagesFilesSnippets(snippets map[v1beta1.ElementID]*v1beta1.Snippet) map[common.ElementID]*v2_3.Snippet {
	if len(snippets) == 0 {
		return nil
	}
	result := make(map[common.ElementID]*v2_3.Snippet)
	for k, s := range snippets {
		result[common.ElementID(k)] = &v2_3.Snippet{
			SnippetSPDXIdentifier:         common.ElementID(s.SnippetSPDXIdentifier),
			SnippetFromFileSPDXIdentifier: common.ElementID(s.SnippetFromFileSPDXIdentifier),
			Ranges:                        domainToSyftPackagesFilesSnippetsRanges(s.Ranges),
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

func domainToSyftPackagesFilesSnippetsRanges(ranges []v1beta1.SnippetRange) []common.SnippetRange {
	var result []common.SnippetRange
	for _, r := range ranges {
		result = append(result, common.SnippetRange{
			StartPointer: common.SnippetRangePointer{
				Offset:             r.StartPointer.Offset,
				LineNumber:         r.StartPointer.LineNumber,
				FileSPDXIdentifier: common.ElementID(r.StartPointer.FileSPDXIdentifier),
			},
			EndPointer: common.SnippetRangePointer{
				Offset:             r.EndPointer.Offset,
				LineNumber:         r.EndPointer.LineNumber,
				FileSPDXIdentifier: common.ElementID(r.EndPointer.FileSPDXIdentifier),
			},
		})
	}
	return result
}

func domainToSyftFiles(files []*v1beta1.File) []*v2_3.File {
	var result []*v2_3.File
	for _, f := range files {
		result = append(result, &v2_3.File{
			FileName:             f.FileName,
			FileSPDXIdentifier:   common.ElementID(f.FileSPDXIdentifier),
			FileTypes:            f.FileTypes,
			Checksums:            domainToSyftPackagesPackageChecksums(f.Checksums),
			LicenseConcluded:     f.LicenseConcluded,
			LicenseInfoInFiles:   f.LicenseInfoInFiles,
			LicenseComments:      f.LicenseComments,
			FileCopyrightText:    f.FileCopyrightText,
			ArtifactOfProjects:   domainToSyftPackagesFilesArtifactOfProjects(f.ArtifactOfProjects),
			FileComment:          f.FileComment,
			FileNotice:           f.FileNotice,
			FileContributors:     f.FileContributors,
			FileAttributionTexts: f.FileAttributionTexts,
			FileDependencies:     f.FileDependencies,
			Snippets:             domainToSyftPackagesFilesSnippets(f.Snippets),
			Annotations:          domainToSyftPackagesAnnotations(f.Annotations),
		})
	}
	return result
}

func domainToSyftOtherLicenses(otherLicenses []*v1beta1.OtherLicense) []*v2_3.OtherLicense {
	var result []*v2_3.OtherLicense
	for _, o := range otherLicenses {
		result = append(result, &v2_3.OtherLicense{
			LicenseIdentifier:      o.LicenseIdentifier,
			ExtractedText:          o.ExtractedText,
			LicenseName:            o.LicenseName,
			LicenseCrossReferences: o.LicenseCrossReferences,
			LicenseComment:         o.LicenseComment,
		})
	}
	return result
}

func domainToSyftRelationships(relationships []*v1beta1.Relationship) []*v2_3.Relationship {
	var result []*v2_3.Relationship
	for _, r := range relationships {
		result = append(result, &v2_3.Relationship{
			RefA: common.DocElementID{
				DocumentRefID: r.RefA.DocumentRefID,
				ElementRefID:  common.ElementID(r.RefA.ElementRefID),
				SpecialID:     r.RefA.SpecialID,
			},
			RefB: common.DocElementID{
				DocumentRefID: r.RefB.DocumentRefID,
				ElementRefID:  common.ElementID(r.RefB.ElementRefID),
				SpecialID:     r.RefB.SpecialID,
			},
			Relationship:        r.Relationship,
			RelationshipComment: r.RelationshipComment,
		})
	}
	return result
}

func domainToSyftAnnotations(annotations []v1beta1.Annotation) []*v2_3.Annotation {
	var result []*v2_3.Annotation
	for _, a := range annotations {
		result = append(result, &v2_3.Annotation{
			Annotator: common.Annotator{
				Annotator:     a.Annotator.Annotator,
				AnnotatorType: a.Annotator.AnnotatorType,
			},
			AnnotationDate: a.AnnotationDate,
			AnnotationType: a.AnnotationType,
			AnnotationSPDXIdentifier: common.DocElementID{
				DocumentRefID: a.AnnotationSPDXIdentifier.DocumentRefID,
				ElementRefID:  common.ElementID(a.AnnotationSPDXIdentifier.ElementRefID),
				SpecialID:     a.AnnotationSPDXIdentifier.SpecialID,
			},
			AnnotationComment: a.AnnotationComment,
		})
	}
	return result
}

func domainToSyftSnippets(snippets []v1beta1.Snippet) []v2_3.Snippet {
	var result []v2_3.Snippet
	for _, s := range snippets {
		result = append(result, v2_3.Snippet{
			SnippetSPDXIdentifier:         common.ElementID(s.SnippetSPDXIdentifier),
			SnippetFromFileSPDXIdentifier: common.ElementID(s.SnippetFromFileSPDXIdentifier),
			Ranges:                        domainToSyftPackagesFilesSnippetsRanges(s.Ranges),
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

func domainToSyftReviews(reviews []*v1beta1.Review) []*v2_3.Review {
	var result []*v2_3.Review
	for _, r := range reviews {
		result = append(result, &v2_3.Review{
			Reviewer:      r.Reviewer,
			ReviewerType:  r.ReviewerType,
			ReviewDate:    r.ReviewDate,
			ReviewComment: r.ReviewComment,
		})
	}
	return result
}
