package repository

import api "github.com/kubescape/kubevuln/pkg/api/v1"

type Storage interface {
	RetrieveRelevantSBOM() (api.SBOM, error)
	RetrieveSBOM() (api.SBOM, error)
	StoreCVE(api.CVE) error
	StoreSBOM(api.SBOM) error
}

type storage struct{}

func (s storage) RetrieveRelevantSBOM() (api.SBOM, error) {
	return api.SBOM{}, nil
}

func (s storage) RetrieveSBOM() (api.SBOM, error) {
	return api.SBOM{}, nil
}

func (s storage) StoreCVE(cve api.CVE) error {
	return nil
}

func (s storage) StoreSBOM(sbom api.SBOM) error {
	return nil
}

func NewStorage() Storage {
	return &storage{}
}
