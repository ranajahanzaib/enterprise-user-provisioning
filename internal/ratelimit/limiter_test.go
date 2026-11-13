package ratelimit

import (
	"testing"
	"time"
)

func TestWindowLimitAndReset(t *testing.T) {
	var l Limiter
	now := time.Now()
	if !l.Allow("client", 2, time.Minute, now) || !l.Allow("client", 2, time.Minute, now.Add(time.Second)) {
		t.Fatal("allowed requests were denied")
	}
	if l.Allow("client", 2, time.Minute, now.Add(2*time.Second)) {
		t.Fatal("request exceeded limit was allowed")
	}
	if !l.Allow("client", 2, time.Minute, now.Add(time.Minute)) {
		t.Fatal("new window did not reset")
	}
}
