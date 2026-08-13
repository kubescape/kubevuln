package v1

import (
	"encoding/json"

	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/kubescape/kubevuln/internal/syftmeta"
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
	syftmeta.Reattach(syftSBOM.Artifacts, doc.Artifacts)

	return syftSBOM, nil
}
