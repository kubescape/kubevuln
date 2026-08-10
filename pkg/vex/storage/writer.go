package storage

import (
	"context"

	"github.com/kubescape/kubevuln/pkg/vex/parser"
	"k8s.io/client-go/util/retry"
)

// PersistVEXStatements executes an update operation with exponential backoff on conflict errors.
// This directly resolves Issue #410 by preventing HTTP 409 concurrency update failures.
func PersistVEXStatements(ctx context.Context, name, namespace string, statements []parser.VEXStatement, updateFn func(ctx context.Context, name, namespace string, statements []parser.VEXStatement) error) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return updateFn(ctx, name, namespace, statements)
	})
}
