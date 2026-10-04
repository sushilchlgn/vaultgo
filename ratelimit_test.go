package main

import (
	"testing"
	"time"
)

func TestRateLimiterBurstAndRefill(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewRateLimiter(1, 3) // 1 token per second, burst of 3
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("request %d within the burst should be allowed", i+1)
		}
	}
	if l.Allow("a") {
		t.Fatal("request beyond the burst should be denied")
	}
	if !l.Allow("b") {
		t.Fatal("a different key has its own bucket")
	}

	now = now.Add(2 * time.Second) // earns 2 tokens
	for i := 0; i < 2; i++ {
		if !l.Allow("a") {
			t.Fatalf("refilled token %d should be allowed", i+1)
		}
	}
	if l.Allow("a") {
		t.Fatal("only two tokens should have refilled")
	}
}

func TestFailureTrackerBlocksAndUnblocks(t *testing.T) {
	now := time.Unix(1000, 0)
	f := NewFailureTracker(3, time.Minute, 5*time.Minute)
	f.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		if f.RecordFailure("ip") {
			t.Fatalf("failure %d must not trigger a lockout", i+1)
		}
	}
	if blocked, _ := f.Blocked("ip"); blocked {
		t.Fatal("should not be blocked yet")
	}
	if !f.RecordFailure("ip") {
		t.Fatal("third failure should trigger the lockout")
	}
	if blocked, wait := f.Blocked("ip"); !blocked || wait <= 0 {
		t.Fatal("should now be blocked with time remaining")
	}

	now = now.Add(6 * time.Minute)
	if blocked, _ := f.Blocked("ip"); blocked {
		t.Fatal("lockout should have expired")
	}
}

func TestFailuresOutsideWindowDoNotAccumulate(t *testing.T) {
	now := time.Unix(1000, 0)
	f := NewFailureTracker(3, time.Minute, 5*time.Minute)
	f.now = func() time.Time { return now }

	f.RecordFailure("ip")
	f.RecordFailure("ip")

	now = now.Add(2 * time.Minute) // window has passed
	if f.RecordFailure("ip") {
		t.Fatal("old failures should not count toward a lockout")
	}
}

func TestBlockingIsPerKey(t *testing.T) {
	f := NewFailureTracker(1, time.Minute, time.Minute)
	f.RecordFailure("attacker")

	if blocked, _ := f.Blocked("attacker"); !blocked {
		t.Fatal("attacker should be blocked")
	}
	if blocked, _ := f.Blocked("innocent"); blocked {
		t.Fatal("other keys must not be affected")
	}
}