package controller

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCooldownQueue_Debounce(t *testing.T) {
	cq := NewCooldownQueue(50 * time.Millisecond)
	defer cq.Stop()

	var counter int32

	// Push 5 events in rapid succession for the same key
	for i := 0; i < 5; i++ {
		cq.Push("feed-1", func() {
			atomic.AddInt32(&counter, 1)
		})
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for the cooldown window to elapse
	time.Sleep(100 * time.Millisecond)

	// Verify the action fired exactly once due to debouncing
	assert.Equal(t, int32(1), atomic.LoadInt32(&counter))
}

func TestCooldownQueue_Stop(t *testing.T) {
	cq := NewCooldownQueue(100 * time.Millisecond)

	var counter int32
	cq.Push("feed-2", func() {
		atomic.AddInt32(&counter, 1)
	})

	// Cancel queue before timer fires
	cq.Stop()
	time.Sleep(150 * time.Millisecond)

	// Verify action never fired
	assert.Equal(t, int32(0), atomic.LoadInt32(&counter))
}
