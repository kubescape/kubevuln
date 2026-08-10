package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/kubevuln/pkg/vex/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestPersistVEXStatements_ConflictRetry(t *testing.T) {
	ctx := context.Background()
	attempts := 0

	// Mock function that fails with Conflict error twice before succeeding
	mockUpdate := func(ctx context.Context, name, namespace string, statements []parser.VEXStatement) error {
		attempts++
		if attempts < 3 {
			return k8serrors.NewConflict(schema.GroupResource{Group: "softwarecomposition.kubescape.io", Resource: "openvulnerabilityexchangecontainers"}, name, errors.New("conflict"))
		}
		return nil
	}

	err := PersistVEXStatements(ctx, "test-vex", "default", []parser.VEXStatement{}, mockUpdate)

	require.NoError(t, err)
	assert.Equal(t, 3, attempts)
}
