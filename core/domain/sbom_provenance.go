package domain

const (
	SBOMImportPrefix     = "kubescape.io/sbom-import-"
	SBOMImportSource     = SBOMImportPrefix + "source"
	SBOMImportPolicy     = SBOMImportPrefix + "policy"
	SBOMImportSigner     = SBOMImportPrefix + "signer"
	SBOMImportArtifact   = SBOMImportPrefix + "artifact"
	SBOMImportSubject    = SBOMImportPrefix + "subject"
	SBOMImportRequest    = SBOMImportPrefix + "request"
	SBOMImportContent    = SBOMImportPrefix + "content"
	SBOMImportVerifiedAt = SBOMImportPrefix + "verified-at"
	SBOMImportSchema     = SBOMImportPrefix + "schema"
)

func (s SBOM) Imported() bool { return s.Annotations[SBOMImportSource] != "" }
