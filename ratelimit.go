package main

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ---------- Token bucket: caps the overall request rate ----------

type bucket struct {
	tokens float64
	last   time.Time
}

// RateLimiter is a token bucket per key. Each key gets `burst` tokens up
// front and earns `rate` more per second, up to the burst size.
type RateLimiter struct {
	mu        sync.Mutex
	rate      float64
	burst     float64
	buckets   map[string]*bucket
	lastSweep time.Time
	now       func() time.Time
}

func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		rate:    rate,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// Allow reports whether the key may make one more request right now.
func (l *RateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweep(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep forgets keys idle for ten minutes so the map can't grow forever.
func (l *RateLimiter) sweep(now time.Time) {
	if l.lastSweep.IsZero() {
		l.lastSweep = now
		return
	}
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	for k, b := range l.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
	l.lastSweep = now
}

// ---------- Failure tracker: locks out repeated failed logins ----------

type failEntry struct {
	count        int
	windowStart  time.Time
	blockedUntil time.Time
}

type FailureTracker struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	block   time.Duration
	entries map[string]*failEntry
	now     func() time.Time
}

// NewFailureTracker blocks a key for `block` after `max` failures
// within `window`.
func NewFailureTracker(max int, window, block time.Duration) *FailureTracker {
	return &FailureTracker{
		max:     max,
		window:  window,
		block:   block,
		entries: make(map[string]*failEntry),
		now:     time.Now,
	}
}

// Blocked reports whether the key is locked out, and for how much longer.
func (f *FailureTracker) Blocked(key string) (bool, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	e, ok := f.entries[key]
	if !ok {
		return false, 0
	}
	now := f.now()
	if now.Before(e.blockedUntil) {
		return true, e.blockedUntil.Sub(now)
	}
	return false, 0
}

// RecordFailure counts one failed attempt. It returns true if this
// failure is the one that triggered the lockout.
func (f *FailureTracker) RecordFailure(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()

	// Drop stale entries when the map gets large.
	if len(f.entries) > 1000 {
		for k, e := range f.entries {
			if now.After(e.blockedUntil) && now.Sub(e.windowStart) > f.window {
				delete(f.entries, k)
			}
		}
	}

	e, ok := f.entries[key]
	if !ok {
		e = &failEntry{windowStart: now}
		f.entries[key] = e
	}

	if now.Sub(e.windowStart) > f.window {
		e.count = 0
		e.windowStart = now
	}

	e.count++
	if e.count >= f.max {
		e.blockedUntil = now.Add(f.block)
		e.count = 0
		e.windowStart = now
		return true
	}
	return false
}

// ---------- Middleware ----------

// Limits bundles the protections that sit in front of the whole router.
type Limits struct {
	requests *RateLimiter
	failures *FailureTracker
}

func NewLimits() *Limits {
	return &Limits{
		requests: NewRateLimiter(20, 40),                         // 20 req/s, burst of 40
		failures: NewFailureTracker(5, time.Minute, 5*time.Minute), // 5 failures/min -> 5 min lockout
	}
}

func tooMany(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int(math.Ceil(retryAfter.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, "too many requests")
}

// rateLimit wraps the whole router. Blocked requests are rejected before
// any database work happens, and are deliberately NOT written to the audit
// log one by one: that would let an attacker fill the table. Only the
// moment a lockout starts is recorded.
func rateLimit(store *Store, lim *Limits, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		if blocked, wait := lim.failures.Blocked(ip); blocked {
			tooMany(w, wait)
			return
		}

		if !lim.requests.Allow(ip) {
			tooMany(w, time.Second)
			return
		}

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		if rec.status == http.StatusUnauthorized {
			if lim.failures.RecordFailure(ip) {
				// Log one row for the lockout itself.
				_ = store.WriteAudit(0, "", "lockout", "", 0,
					http.StatusTooManyRequests, "rate_limited", ip)
			}
		}
	})
}