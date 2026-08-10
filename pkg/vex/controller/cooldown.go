package controller

import (
	"sync"
	"time"
)

// CooldownQueue provides event debouncing by ensuring actions on a given resource key
// only fire after a specified cooldown period of inactivity has elapsed.
type CooldownQueue struct {
	mu       sync.Mutex
	timers   map[string]*time.Timer
	cooldown time.Duration
}

// NewCooldownQueue creates a CooldownQueue with the given debouncing duration.
func NewCooldownQueue(cooldown time.Duration) *CooldownQueue {
	return &CooldownQueue{
		timers:   make(map[string]*time.Timer),
		cooldown: cooldown,
	}
}

// Push schedules or resets an action for the specified key.
func (cq *CooldownQueue) Push(key string, action func()) {
	cq.mu.Lock()
	defer cq.mu.Unlock()

	if timer, ok := cq.timers[key]; ok {
		timer.Stop()
	}

	cq.timers[key] = time.AfterFunc(cq.cooldown, func() {
		cq.mu.Lock()
		delete(cq.timers, key)
		cq.mu.Unlock()
		action()
	})
}

// Stop cancels all active timers in the queue.
func (cq *CooldownQueue) Stop() {
	cq.mu.Lock()
	defer cq.mu.Unlock()

	for key, timer := range cq.timers {
		timer.Stop()
		delete(cq.timers, key)
	}
}
