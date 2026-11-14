package main

import (
	"fmt"

	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/config"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/sbomreuse"
)

func configureSBOMReuse(c config.Config, fallback ports.SBOMCreator) (ports.SBOMCreator, error) {
	if c.SBOMReusePolicyFile == "" {
		return fallback, nil
	}
	if c.NodeSbomGeneration {
		return nil, fmt.Errorf("SBOM reuse requires kubevuln-owned generation")
	}
	if len(c.ProxyRegistryMap) > 0 {
		return nil, fmt.Errorf("SBOM reuse does not yet support proxyRegistryMap; HTTP(S)_PROXY remains supported")
	}
	p, err := sbomreuse.LoadPolicy(c.SBOMReusePolicyFile)
	if err != nil {
		return nil, err
	}
	return v1.NewRegistrySBOMAdapter(fallback, sbomreuse.NewProvider(p)), nil
}
