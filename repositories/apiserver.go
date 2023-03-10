package repositories

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// APIServerStore implements both CVERepository and SBOMRepository with in-cluster storage (apiserver) to be used for production
type APIServerStore struct {
	Clientset *versioned.Clientset
}

var _ ports.CVERepository = (*APIServerStore)(nil)

//var _ ports.SBOMRepository = (*APIServerStore)(nil)

// NewAPIServerStorage initializes the APIServerStore struct
func NewAPIServerStorage() (*APIServerStore, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &APIServerStore{
		Clientset: clientset,
	}, nil
}

func (a *APIServerStore) GetCVE(ctx context.Context, imageID, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (cve domain.CVEManifest, err error) {
	manifest, err := a.Clientset.SpdxV1beta1().VulnerabilityManifests("kubescape").Get(ctx, imageID, metav1.GetOptions{})
	logger.L().Info(manifest.Name)
	return domain.CVEManifest{}, err
}

func (a *APIServerStore) StoreCVE(ctx context.Context, cve domain.CVEManifest) error {
	//TODO implement me
	panic("implement me")
}
