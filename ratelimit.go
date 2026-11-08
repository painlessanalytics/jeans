package main

import (
	"sync"
	"time"
)

// failureLimiter counts failed attempts per key in a fixed window that starts
// at the first failure. Once max failures are recorded, the key is blocked
// until the window ends. State is in memory only, so it resets on restart.
type failureLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	max     int
	window  time.Duration
	entries map[string]*failureEntry
}

type failureEntry struct {
	count int
	start time.Time
}

// maxLimiterEntries bounds memory use; when exceeded, expired entries are purged.
const maxLimiterEntries = 10000

func newFailureLimiter(max int, window time.Duration) *failureLimiter {
	return &failureLimiter{
		now:     time.Now,
		max:     max,
		window:  window,
		entries: make(map[string]*failureEntry),
	}
}

// blocked reports whether key is locked out and, if so, for how much longer.
func (l *failureLimiter) blocked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[key]
	if !ok {
		return false, 0
	}
	remaining := e.start.Add(l.window).Sub(l.now())
	if remaining <= 0 {
		delete(l.entries, key)
		return false, 0
	}
	return e.count >= l.max, remaining
}

// fail records a failed attempt for key.
func (l *failureLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if len(l.entries) >= maxLimiterEntries {
		for k, e := range l.entries {
			if !e.start.Add(l.window).After(now) {
				delete(l.entries, k)
			}
		}
	}
	e, ok := l.entries[key]
	if !ok || !e.start.Add(l.window).After(now) {
		l.entries[key] = &failureEntry{count: 1, start: now}
		return
	}
	e.count++
}

// reset clears the failure count for key (after a successful login).
func (l *failureLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
