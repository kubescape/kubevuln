package repositories

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoOpSecurityExceptionRepository_GetSecurityExceptions(t *testing.T) {
	repo := &NoOpSecurityExceptionRepository{}

	exceptions, clusterExceptions, err := repo.GetSecurityExceptions(context.Background(), "some-namespace")

	assert.NoError(t, err)
	assert.Nil(t, exceptions)
	assert.Nil(t, clusterExceptions)
}

func TestNoOpSecurityExceptionRepository_GetWorkloadLabels(t *testing.T) {
	repo := &NoOpSecurityExceptionRepository{}

	labels, err := repo.GetWorkloadLabels(context.Background(), "namespace", "kind", "name")

	assert.ErrorIs(t, err, errNoClusterConnection)
	assert.Nil(t, labels)
}

func TestNoOpSecurityExceptionRepository_GetNamespaceLabels(t *testing.T) {
	repo := &NoOpSecurityExceptionRepository{}

	labels, err := repo.GetNamespaceLabels(context.Background(), "namespace")

	assert.ErrorIs(t, err, errNoClusterConnection)
	assert.Nil(t, labels)
}
