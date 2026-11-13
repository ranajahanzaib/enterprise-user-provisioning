package ratelimit

import (
	"sync"
	"time"
)

type entry struct {
	start time.Time
	count int
}
type Limiter struct {
	mu      sync.Mutex
	entries map[string]entry
}

func (l *Limiter) Allow(key string, limit int, window time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = make(map[string]entry)
	}
	e := l.entries[key]
	if e.start.IsZero() || now.Sub(e.start) >= window {
		e = entry{start: now}
	}
	if e.count >= limit {
		l.entries[key] = e
		return false
	}
	e.count++
	l.entries[key] = e
	if len(l.entries) > 4096 {
		for k, v := range l.entries {
			if now.Sub(v.start) >= window {
				delete(l.entries, k)
			}
		}
	}
	return true
}
