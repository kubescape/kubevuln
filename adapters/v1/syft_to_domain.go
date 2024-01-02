package v1

import (
	"encoding/json"

	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func (s *SyftAdapter) syftToDomain(sbomSBOM sbom.SBOM) (*v1beta1.SyftDocument, error) {
	doc := syftjson.ToFormatModel(sbomSBOM, syftjson.EncoderConfig{
		Pretty: false,
		Legacy: false,
	})

	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	var syftSBOM *v1beta1.SyftDocument
	if err := json.Unmarshal(b, &syftSBOM); err != nil {
		return nil, err
	}
	for i := range syftSBOM.Artifacts {
		for j := range doc.Artifacts {
			if syftSBOM.Artifacts[i].ID == doc.Artifacts[j].ID {
				syftSBOM.Artifacts[i].MetadataType = doc.Artifacts[j].MetadataType
				if b, err := json.Marshal(doc.Artifacts[j].Metadata); err == nil {
					syftSBOM.Artifacts[i].Metadata = b
				} else {
					logger.L().Warning("failed to marshal Artifacts[j].Metadata", helpers.Error(err))
				}
				break
			}
		}
	}

	return syftSBOM, nil
}
