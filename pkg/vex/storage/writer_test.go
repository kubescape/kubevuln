package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestPersistVEXStatements_ConflictRetry(t *testing.T) {
	ctx := context.Background()
	attempts := 0

	// Mock function that fails with Conflict error twice before succeeding
	mockUpdate := func(ctx context.Context) error {
		attempts++
		if attempts < 3 {
			return k8serrors.NewConflict(schema.GroupResource{Group: "softwarecomposition.kubescape.io", Resource: "openvulnerabilityexchangecontainers"}, "test-vex", errors.New("conflict"))
		}
		return nil
	}

	err := PersistVEXStatements(ctx, mockUpdate)

	require.NoError(t, err)
	assert.Equal(t, 3, attempts)
}

func TestPersistVEXStatements_SentinelError(t *testing.T) {
	ctx := context.Background()
	attempts := 0
	expectedErr := errors.New("sentinel error")

	// Mock function that fails with a regular (non-conflict) error immediately
	mockUpdate := func(ctx context.Context) error {
		attempts++
		return expectedErr
	}

	err := PersistVEXStatements(ctx, mockUpdate)

	require.ErrorIs(t, err, expectedErr)
	assert.Equal(t, 1, attempts)
}

func TestPersistVEXStatements_ConflictExhaustion(t *testing.T) {
	ctx := context.Background()
	attempts := 0

	// Mock function that fails with Conflict error permanently
	mockUpdate := func(ctx context.Context) error {
		attempts++
		return k8serrors.NewConflict(schema.GroupResource{Group: "softwarecomposition.kubescape.io", Resource: "openvulnerabilityexchangecontainers"}, "test-vex", errors.New("conflict"))
	}

	err := PersistVEXStatements(ctx, mockUpdate)

	require.Error(t, err)
	assert.True(t, k8serrors.IsConflict(err))
	assert.Greater(t, attempts, 3) // DefaultRetry has multiple attempts (usually 5)
}
