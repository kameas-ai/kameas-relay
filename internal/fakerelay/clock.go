package fakerelay

import (
	"sort"
	"sync"
	"time"
)

// Clock abstracts time so tests never sleep on the wall clock. Presence
// (15 s heartbeat / 30 s offline flip, relay-api.md §6), mailbox TTL
// (§4), pairing-window expiry (§3.1) and rate-limit refill all read time
// exclusively through this interface.
type Clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer mirrors the subset of *time.Timer the relay needs.
type Timer interface {
	Stop() bool
	Reset(d time.Duration) bool
}

// realClock is the production clock (used by cmd/fakerelay).
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

// FakeClock is a deterministic clock for tests. Advance moves time
// forward and fires due timers synchronously, in deadline order.
type FakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

// NewFakeClock returns a FakeClock starting at start.
func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{now: start}
}

func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *FakeClock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{clock: c, deadline: c.now.Add(d), f: f, active: true}
	c.timers = append(c.timers, t)
	return t
}

// Advance moves the clock forward by d, firing every timer whose deadline
// falls inside the window, in order. Callbacks run synchronously on the
// calling goroutine with the clock unlocked, so they may schedule or
// reset timers.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.now.Add(d)
	for {
		var next *fakeTimer
		for _, t := range c.timers {
			if t.active && !t.deadline.After(target) && (next == nil || t.deadline.Before(next.deadline)) {
				next = t
			}
		}
		if next == nil {
			break
		}
		next.active = false
		if next.deadline.After(c.now) {
			c.now = next.deadline
		}
		f := next.f
		c.mu.Unlock()
		f()
		c.mu.Lock()
		c.compact()
	}
	c.now = target
	c.mu.Unlock()
}

// compact drops dead timers; caller holds c.mu.
func (c *FakeClock) compact() {
	live := c.timers[:0]
	for _, t := range c.timers {
		if t.active {
			live = append(live, t)
		}
	}
	c.timers = live
	sort.Slice(c.timers, func(i, j int) bool { return c.timers[i].deadline.Before(c.timers[j].deadline) })
}

type fakeTimer struct {
	clock    *FakeClock
	deadline time.Time
	f        func()
	active   bool
}

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := t.active
	t.active = false
	return was
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := t.active
	t.deadline = t.clock.now.Add(d)
	t.active = true
	if !was {
		// Re-arming a fired timer: make sure it is back in the list.
		found := false
		for _, x := range t.clock.timers {
			if x == t {
				found = true
				break
			}
		}
		if !found {
			t.clock.timers = append(t.clock.timers, t)
		}
	}
	return was
}
