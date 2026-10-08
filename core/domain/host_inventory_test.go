package domain

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAcceptHostInventory(t *testing.T) {
	require.NoError(t, AcceptHostInventory(context.Background()))
	calls := 0
	ctx := WithHostInventoryReady(context.Background(), func() error { calls++; return ErrHostInventoryUnavailable })
	require.ErrorIs(t, AcceptHostInventory(ctx), ErrHostInventoryUnavailable)
	require.Equal(t, 1, calls)
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	require.ErrorIs(t, AcceptHostInventory(ctx), context.Canceled)
	require.Equal(t, 1, calls)
}
