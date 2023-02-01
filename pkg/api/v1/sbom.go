package v1

// SBOMService contains the methods of the sbom service
type SBOMService interface {
	New(NewSBOMRequest) error
}

// SBOMRepository is what lets our service do db operations without knowing anything about the implementation
type SBOMRepository interface {
	StoreSBOM(SBOM) error
}

type sbomService struct {
	storage SBOMRepository
}

func NewSBOMService(sbomRepo SBOMRepository) SBOMService {
	return &sbomService{storage: sbomRepo}
}

func (c *sbomService) New(sbom NewSBOMRequest) error {
	return nil
}
