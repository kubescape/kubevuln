package v1

import (
	"encoding/json"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func syftJSONToDomain(data []byte) (*v1beta1.SyftDocument, error) {
	var syftSBOM *v1beta1.SyftDocument
	err := json.Unmarshal(data, &syftSBOM)
	if err != nil {
		return nil, err
	}

	return syftSBOM, nil
}

func (s *SyftAdapter) syftToDomain(syftSBOM sbom.SBOM) (*v1beta1.SyftDocument, error) {
	encoder := syftjson.NewFormatEncoder()

	syftJSON, err := format.Encode(syftSBOM, encoder)
	if err != nil {
		return nil, err
	}

	return syftJSONToDomain(syftJSON)
}
