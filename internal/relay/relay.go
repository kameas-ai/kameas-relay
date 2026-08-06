package relay

import (
	"context"
	"sync"
)

// Relay is the production relay service. Construct with New and mount
// Handler() on an http.Server.
//
// The Store holds every persisted record (relay-api.md §8). Everything
// tracked here is live connection state and timers — inherently
// process-local, never persisted, and correctly lost on restart.
type Relay struct {
	cfg     Config
	limiter *limiter

	mu        sync.Mutex
	hostConns map[string]map[*wsConn]bool // host_id  -> attached host connections
	devConns  map[string]map[*wsConn]bool // channel  -> durable device attaches
	pairConns map[string]map[*wsConn]bool // window   -> pairing attaches
	presTimer map[string]Timer            // host_id  -> §6 offline deadline
	winTimer  map[string]Timer            // window   -> §3.1 expiry
	closed    bool
}

// New validates cfg and returns a Relay.
func New(cfg Config) (*Relay, error) {
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Relay{
		cfg:       cfg,
		limiter:   newLimiter(cfg.Clock),
		hostConns: make(map[string]map[*wsConn]bool),
		devConns:  make(map[string]map[*wsConn]bool),
		pairConns: make(map[string]map[*wsConn]bool),
		presTimer: make(map[string]Timer),
		winTimer:  make(map[string]Timer),
	}, nil
}

// Close stops the relay's timers. It does not close attached sockets: the
// http.Server's shutdown owns those, and a relay that closed them itself
// would race the graceful-shutdown path.
func (r *Relay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	for _, t := range r.presTimer {
		t.Stop()
	}
	for _, t := range r.winTimer {
		t.Stop()
	}
	clear(r.presTimer)
	clear(r.winTimer)
	return nil
}

// Config exposes the effective configuration (post-defaults) for tests and
// for cmd/relayd's startup log.
func (r *Relay) Config() Config { return r.cfg }

// HostOnline reports the relay's presence view of a host. Test/inspection
// affordance; deliberately not reachable over HTTP (§7.3 forbids the health
// endpoints from enumerating anything).
func (r *Relay) HostOnline(ctx context.Context, hostID string) (bool, error) {
	p, ok, err := r.cfg.Store.LookupHostPresence(ctx, hostID)
	if err != nil || !ok {
		return false, err
	}
	return p.Online, nil
}
