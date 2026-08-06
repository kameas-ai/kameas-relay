package relay

import (
	"sync"
	"time"
)

// limiter implements the token buckets of relay-api.md §7.1.
//
// Counters are IN-MEMORY ONLY and are not part of the Store: §8 says
// "Rate-limit counters are in-memory and MUST NOT be durable per-operator
// state." A rate limit is backpressure, not a revocation, and it MUST NOT
// destroy E2E session state a well-behaved retry could reuse.
type limiter struct {
	clock Clock

	mu      sync.Mutex
	buckets map[string]*bucket
	// lastSweep bounds memory: idle buckets are dropped periodically so a
	// churn of one-shot keys cannot grow the map without limit.
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

const bucketSweepInterval = 10 * time.Minute

func newLimiter(clock Clock) *limiter {
	return &limiter{clock: clock, buckets: make(map[string]*bucket)}
}

// allow consumes one token from the bucket identified by key, refilling at
// rate tokens/second up to burst. rate <= 0 disables the limit.
func (l *limiter) allow(key string, rate, burst float64) bool {
	if rate <= 0 {
		return true
	}
	if burst < 1 {
		burst = 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	l.sweepLocked(now, burst, rate)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: burst, last: now}
		l.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * rate
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// sweepLocked drops buckets that have been idle long enough to have
// refilled completely — they carry no information and re-creating one is
// free. Caller holds l.mu.
func (l *limiter) sweepLocked(now time.Time, burst, rate float64) {
	if l.lastSweep.IsZero() {
		l.lastSweep = now
		return
	}
	if now.Sub(l.lastSweep) < bucketSweepInterval {
		return
	}
	l.lastSweep = now
	refill := time.Duration(burst/rate) * time.Second
	if refill < bucketSweepInterval {
		refill = bucketSweepInterval
	}
	for k, b := range l.buckets {
		if now.Sub(b.last) > refill {
			delete(l.buckets, k)
		}
	}
}

// perHour converts an n-per-hour §7.1 limit into (rate, burst).
func perHour(n int) (rate, burst float64) {
	if n <= 0 {
		return 0, 0
	}
	return float64(n) / 3600.0, float64(n)
}

// perMinute converts an n-per-minute §7.1 limit into (rate, burst).
func perMinute(n int) (rate, burst float64) {
	if n <= 0 {
		return 0, 0
	}
	return float64(n) / 60.0, float64(n)
}
