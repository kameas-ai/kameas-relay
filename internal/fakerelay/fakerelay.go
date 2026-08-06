// Package fakerelay is the contract-faithful, in-memory test double for
// the kameas-relay service (specs/074-kenaz-ios-remote/contracts/
// relay-api.md, NORMATIVE DRAFT 2026-08-05). Every spec-074 lane —
// kenaz host-agent tests, iOS integration tests, the remotectl CLI —
// consumes this package instead of real infrastructure.
//
// The relay is a dumb pipe BY CONSTRUCTION (§XII condition 2): it parses
// only the three-field plaintext frame header {channel, seq, push_class}
// and treats every body as opaque bytes. This package imports no crypto
// of any kind; denylist_test.go is the structural proof.
package fakerelay

import (
	"log/slog"
	"sync"
	"time"
)

// Defaults from relay-api.md §2.2, §4, §6, §7.1.
const (
	DefaultMailboxTTL        = 15 * time.Minute
	DefaultMailboxMaxFrames  = 128
	DefaultMailboxMaxBytes   = 4 << 20 // 4 MiB
	DefaultWindowTTL         = 5 * time.Minute
	DefaultOfflineAfter      = 30 * time.Second
	DefaultHeartbeatInterval = 15 * time.Second
	DefaultMaxFrameSize      = 128 << 10 // 128 KiB
	DefaultMaxHeaderLen      = 512
	DefaultBindingIdleReap   = 30 * 24 * time.Hour // §2.2 binding reaper
)

// Limits carries the tunable §7.1 rate limits. Zero values take the
// contract defaults; set a field negative to disable that limit.
type Limits struct {
	DeviceFramesPerSec       float64 // default 60
	DeviceFramesBurst        float64 // default 120
	HostFramesPerSec         float64 // default 200
	HostFramesBurst          float64 // default 400
	MailboxGetPerMin         int     // default 30
	PairingsPerHour          int     // default 10
	PairingWindowsPerHour    int     // default 20
	PairingAttachesPerWindow int     // default 10
	APNSRegsPerHour          int     // default 10
	DeviceAttachPerChannel   int     // default 4
}

func (l *Limits) applyDefaults() {
	def := func(v *float64, d float64) {
		if *v == 0 {
			*v = d
		} else if *v < 0 {
			*v = 0 // 0 means unlimited in the limiter
		}
	}
	defi := func(v *int, d int) {
		if *v == 0 {
			*v = d
		} else if *v < 0 {
			*v = 0
		}
	}
	def(&l.DeviceFramesPerSec, 60)
	def(&l.DeviceFramesBurst, 120)
	def(&l.HostFramesPerSec, 200)
	def(&l.HostFramesBurst, 400)
	defi(&l.MailboxGetPerMin, 30)
	defi(&l.PairingsPerHour, 10)
	defi(&l.PairingWindowsPerHour, 20)
	defi(&l.PairingAttachesPerWindow, 10)
	defi(&l.APNSRegsPerHour, 10)
	defi(&l.DeviceAttachPerChannel, 4)
}

// Config configures a fake relay. The zero value is usable: real clock,
// FakeValidator, contract defaults.
type Config struct {
	Clock     Clock
	Validator TokenValidator
	Logger    *slog.Logger // connection metadata only; never frame bytes or tokens

	MailboxTTL       time.Duration
	MailboxMaxFrames int
	MailboxMaxBytes  int64
	WindowTTL        time.Duration
	OfflineAfter     time.Duration
	MaxFrameSize     int
	MaxHeaderLen     int
	// BindingIdleReap is the §2.2 reaper horizon: a host account binding
	// with zero pairings and no attach for this long is deleted, so a
	// regenerated or mistyped host_id cannot squat forever.
	BindingIdleReap time.Duration
	Limits          Limits
}

func (c *Config) applyDefaults() {
	if c.Clock == nil {
		c.Clock = realClock{}
	}
	if c.Validator == nil {
		c.Validator = FakeValidator{}
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.MailboxTTL == 0 {
		c.MailboxTTL = DefaultMailboxTTL
	}
	if c.MailboxMaxFrames == 0 {
		c.MailboxMaxFrames = DefaultMailboxMaxFrames
	}
	if c.MailboxMaxBytes == 0 {
		c.MailboxMaxBytes = DefaultMailboxMaxBytes
	}
	if c.WindowTTL == 0 {
		c.WindowTTL = DefaultWindowTTL
	}
	if c.OfflineAfter == 0 {
		c.OfflineAfter = DefaultOfflineAfter
	}
	if c.MaxFrameSize == 0 {
		c.MaxFrameSize = DefaultMaxFrameSize
	}
	if c.MaxHeaderLen == 0 {
		c.MaxHeaderLen = DefaultMaxHeaderLen
	}
	if c.BindingIdleReap == 0 {
		c.BindingIdleReap = DefaultBindingIdleReap
	}
	c.Limits.applyDefaults()
}

// pairing is one routing registration — the §8 persistence-budget row
// {pairing_id, channel_id, host_id, device_id, account_sub, host_label?,
// created_at}. Nothing else about a pairing is ever stored.
type pairing struct {
	id         string
	channelID  string
	hostID     string
	deviceID   string
	accountSub string
	hostLabel  *string
	createdAt  time.Time
}

// window is one ephemeral pairing window (§8 row 5).
type window struct {
	id                 string
	hostID             string
	provisionalChannel string
	expiresAt          time.Time
	timer              Timer
	closed             bool
	attaches           int
}

// apnsReg is one APNs token registration (§8 row 3). There is no
// categories field: the relay does not know a frame's category and
// cannot enforce a subscription it has no category for (§5.1).
type apnsReg struct {
	deviceID string
	token    string
	env      string
}

// hostPresence is half the §8 presence row: live + last-seen only.
type hostPresence struct {
	online   bool
	lastSeen time.Time
	timer    Timer
}

// devPresence is the other half of the §8 presence row:
// {channel_id, device_attached, last_seen} (§6.1).
type devPresence struct {
	attached bool
	lastSeen time.Time
}

// hostBinding is the §2.2 host-account binding row:
// {host_id, account_sub, bound_at, last_attach_at}. Created only on a
// successful /v1/host attach, immutable, reaped after BindingIdleReap
// idle with zero pairings.
type hostBinding struct {
	sub        string
	boundAt    time.Time
	lastAttach time.Time
}

// Relay is the in-memory fake relay. Construct with New, mount
// Handler() on an httptest.Server (or any http.Server), and drive the
// control surface (Recorder, HostOnline, FakeClock.Advance) from tests.
type Relay struct {
	cfg      Config
	limiter  *limiter
	recorder *APNSRecorder

	mu        sync.Mutex
	bindings  map[string]*hostBinding     // host_id -> §2.2 account binding
	chanPres  map[string]*devPresence     // channel_id -> device presence (§6.1)
	pairings  map[string]*pairing         // pairing_id -> pairing
	channels  map[string]*pairing         // channel_id -> pairing
	windows   map[string]*window          // window_id -> window
	provChans map[string]*window          // provisional_channel -> window
	mailboxes map[string]*mailbox         // channel_id -> mailbox
	apnsTok   map[string]*apnsReg         // device_id -> registration
	presence  map[string]*hostPresence    // host_id -> presence
	hostConns map[string]map[*wsConn]bool // host_id -> conns
	devConns  map[string]map[*wsConn]bool // channel_id -> conns (durable attach)
	pairConns map[string]map[*wsConn]bool // window_id -> conns (pairing attach)
}

// New builds a fake relay from cfg (zero value ok).
func New(cfg Config) *Relay {
	cfg.applyDefaults()
	return &Relay{
		cfg:       cfg,
		limiter:   newLimiter(cfg.Clock),
		recorder:  &APNSRecorder{},
		bindings:  make(map[string]*hostBinding),
		pairings:  make(map[string]*pairing),
		channels:  make(map[string]*pairing),
		windows:   make(map[string]*window),
		provChans: make(map[string]*window),
		mailboxes: make(map[string]*mailbox),
		apnsTok:   make(map[string]*apnsReg),
		presence:  make(map[string]*hostPresence),
		chanPres:  make(map[string]*devPresence),
		hostConns: make(map[string]map[*wsConn]bool),
		devConns:  make(map[string]map[*wsConn]bool),
		pairConns: make(map[string]map[*wsConn]bool),
	}
}

// Recorder exposes the mock APNs recorder for test inspection.
func (r *Relay) Recorder() *APNSRecorder { return r.recorder }

// HostOnline reports the relay's presence view of a host (control
// surface for tests).
func (r *Relay) HostOnline(hostID string) (online bool, lastSeen time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.presence[hostID]
	if !ok {
		return false, time.Time{}
	}
	return p.online, p.lastSeen
}

// bindingFor returns the §2.2 account binding for hostID, applying the
// reaper lazily first: a binding with zero pairings and no attach for
// BindingIdleReap is deleted, so a regenerated host_id cannot squat
// forever. Caller holds r.mu.
func (r *Relay) bindingFor(hostID string) (*hostBinding, bool) {
	b, ok := r.bindings[hostID]
	if !ok {
		return nil, false
	}
	if !r.hostHasPairings(hostID) && r.cfg.Clock.Now().Sub(b.lastAttach) >= r.cfg.BindingIdleReap {
		delete(r.bindings, hostID)
		return nil, false
	}
	return b, true
}

// hostHasPairings reports whether any routing registration references
// hostID. Caller holds r.mu.
func (r *Relay) hostHasPairings(hostID string) bool {
	for _, pr := range r.pairings {
		if pr.hostID == hostID {
			return true
		}
	}
	return false
}

// bindHost creates the immutable §2.2 binding on a successful /v1/host
// attach (ONLY there — device attaches MUST NOT bind, §3.2). Returns
// false when hostID is already bound to a different sub. Caller holds
// r.mu.
func (r *Relay) bindHost(hostID, sub string) bool {
	now := r.cfg.Clock.Now()
	if b, ok := r.bindingFor(hostID); ok {
		if b.sub != sub {
			return false
		}
		b.lastAttach = now
		return true
	}
	r.bindings[hostID] = &hostBinding{sub: sub, boundAt: now, lastAttach: now}
	return true
}

// windowForHost returns the (at most one, §3.1) open window for hostID.
// Caller holds r.mu.
func (r *Relay) windowForHost(hostID string) (*window, bool) {
	for _, win := range r.windows {
		if win.hostID == hostID && !win.closed {
			return win, true
		}
	}
	return nil, false
}
