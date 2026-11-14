// Package ratelimit provides an in-memory per-key token bucket limiter.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter limits events per key (for example per client IP).
//
// State is kept in memory, so limits apply per service instance. A shared
// store (Redis) is needed once the service runs with several replicas.
type Limiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	idleTTL time.Duration
	now     func() time.Time
	entries map[string]*entry
	lastGC  time.Time
}

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// New returns a limiter that allows perMinute events per key with bursts of
// up to burst events.
func New(perMinute, burst int) *Limiter {
	return &Limiter{
		limit:   rate.Limit(float64(perMinute) / 60),
		burst:   burst,
		idleTTL: 10 * time.Minute,
		now:     time.Now,
		entries: make(map[string]*entry),
	}
}

// Allow reports whether an event for key may happen now and consumes a token
// if so.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.gc(now)

	e, ok := l.entries[key]
	if !ok {
		e = &entry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[key] = e
	}
	e.lastSeen = now
	return e.limiter.AllowN(now, 1)
}

// gc drops keys that have been idle longer than idleTTL. It runs at most once
// per idleTTL, so memory stays bounded by the number of active keys.
func (l *Limiter) gc(now time.Time) {
	if now.Sub(l.lastGC) < l.idleTTL {
		return
	}
	for k, e := range l.entries {
		if now.Sub(e.lastSeen) > l.idleTTL {
			delete(l.entries, k)
		}
	}
	l.lastGC = now
}
