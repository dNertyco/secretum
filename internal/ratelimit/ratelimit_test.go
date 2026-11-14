package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterPerKey(t *testing.T) {
	l := New(60, 2) // 1 per second, burst 2
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }

	for i := range 2 {
		if !l.Allow("a") {
			t.Fatalf("event %d of burst 2 must be allowed", i+1)
		}
	}
	if l.Allow("a") {
		t.Fatal("third event in the same instant must be denied")
	}
	if !l.Allow("b") {
		t.Fatal("other keys must not be affected")
	}

	now = now.Add(time.Second)
	if !l.Allow("a") {
		t.Fatal("a token must be refilled after one second")
	}
}

func TestLimiterEvictsIdleKeys(t *testing.T) {
	l := New(60, 1)
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }

	l.Allow("a")
	now = now.Add(time.Hour)
	l.Allow("b")

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.entries["a"]; ok {
		t.Error("idle key was not evicted")
	}
	if _, ok := l.entries["b"]; !ok {
		t.Error("active key was evicted")
	}
}
