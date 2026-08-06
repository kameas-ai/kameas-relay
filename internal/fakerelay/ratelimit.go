package fakerelay

import (
	"sync"
	"time"
)

// limiter implements the simple token buckets of relay-api.md §7.1.
// Counters are in-memory only — the contract forbids durable per-operator
// rate-limit state (§8).
type limiter struct {
	mu      sync.Mutex
	clock   Clock
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(clock Clock) *limiter {
	return &limiter{clock: clock, buckets: make(map[string]*bucket)}
}

// allow consumes one token from the bucket identified by key, refilling
// at rate tokens/second up to burst. rate <= 0 disables the limit.
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
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
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
