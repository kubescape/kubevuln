package storage

import (
	"context"

	"k8s.io/client-go/util/retry"
)

// PersistVEXStatements executes an update operation with default retry backoff on conflict errors.
// This directly resolves Issue #410 by preventing HTTP 409 concurrency update failures.
func PersistVEXStatements(ctx context.Context, updateFn func(ctx context.Context) error) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return updateFn(ctx)
	})
}
