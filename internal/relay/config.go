package relay

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Contract defaults and HARD CEILINGS from relay-api.md §2.2, §3.1, §4, §6,
// §7.1.
//
// The ceilings are enforced at boot, not merely documented. §4 says the
// mailbox TTL and caps "are defaults the relay lane MAY tune downward;
// neither may be raised without a CONTRACTS.md revision, because the
// budget's 'short TTL, bounded' is the constitutional constraint, not the
// specific number." Config.Validate therefore refuses to start a relay
// configured above them — a ratchet a misconfigured deploy cannot cross.
const (
	DefaultMailboxTTL        = 15 * time.Minute
	DefaultMailboxMaxFrames  = 128
	DefaultMailboxMaxBytes   = 4 << 20 // 4 MiB
	DefaultWindowTTL         = 5 * time.Minute
	DefaultOfflineAfter      = 30 * time.Second
	DefaultHeartbeatInterval = 15 * time.Second
	DefaultMaxFrameSize      = 128 << 10 // 128 KiB
	DefaultMaxHeaderLen      = 512
	DefaultBindingIdleReap   = 30 * 24 * time.Hour
)

// Limits carries the tunable §7.1 rate limits. Zero takes the contract
// default; negative disables that limit (test affordance only — a
// production deploy that disables a limit is a defect, not a tuning).
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
		switch {
		case *v == 0:
			*v = d
		case *v < 0:
			*v = 0 // 0 means unlimited in the limiter
		}
	}
	defi := func(v *int, d int) {
		switch {
		case *v == 0:
			*v = d
		case *v < 0:
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

// Config configures a Relay.
//
// Store and Validator are REQUIRED and have no defaults: a relay with an
// implicit auth validator is exactly the kind of accident that turns a
// fail-closed design into a fail-open one, so New refuses rather than
// guessing.
type Config struct {
	Store     Store
	Validator TokenValidator

	// Clock defaults to SystemClock.
	Clock Clock
	// Logger defaults to a discarding logger. §9: connection metadata only
	// — never frame bytes, token bytes, or any claim other than sub.
	Logger *slog.Logger
	// Pusher defaults to NopPusher.
	Pusher Pusher
	// Ready is the optional readiness dependency behind GET /readyz —
	// typically the JWT validator's JWKS reachability check. nil means
	// readiness reduces to liveness.
	Ready func(context.Context) error

	MailboxTTL        time.Duration
	MailboxMaxFrames  int
	MailboxMaxBytes   int64
	WindowTTL         time.Duration
	OfflineAfter      time.Duration
	HeartbeatInterval time.Duration
	MaxFrameSize      int
	MaxHeaderLen      int
	BindingIdleReap   time.Duration
	Limits            Limits
}

func (c *Config) applyDefaults() {
	if c.Clock == nil {
		c.Clock = SystemClock{}
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Pusher == nil {
		c.Pusher = NopPusher{}
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
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = DefaultHeartbeatInterval
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

// Validate enforces the contract's bounds. Every violation is fatal at
// boot: a relay that silently clamps a misconfiguration is a relay whose
// running behaviour does not match its configuration file.
func (c *Config) Validate() error {
	if c.Store == nil {
		return fmt.Errorf("relay: Store is required")
	}
	if c.Validator == nil {
		return fmt.Errorf("relay: Validator is required — there is no default, and no unauthenticated mode")
	}
	ceiling := func(name string, got, max time.Duration) error {
		if got <= 0 {
			return fmt.Errorf("relay: %s must be positive, got %s", name, got)
		}
		if got > max {
			return fmt.Errorf("relay: %s = %s exceeds the contract ceiling %s; it may be tuned downward only "+
				"(relay-api.md; raising it needs a CONTRACTS.md revision)", name, got, max)
		}
		return nil
	}
	if err := ceiling("mailbox TTL", c.MailboxTTL, DefaultMailboxTTL); err != nil {
		return err
	}
	if err := ceiling("pairing window TTL", c.WindowTTL, DefaultWindowTTL); err != nil {
		return err
	}
	if err := ceiling("presence offline-after", c.OfflineAfter, DefaultOfflineAfter); err != nil {
		return err
	}
	if c.HeartbeatInterval <= 0 || c.HeartbeatInterval >= c.OfflineAfter {
		return fmt.Errorf("relay: heartbeat interval %s must be positive and shorter than offline-after %s",
			c.HeartbeatInterval, c.OfflineAfter)
	}
	if c.MailboxMaxFrames <= 0 || c.MailboxMaxFrames > DefaultMailboxMaxFrames {
		return fmt.Errorf("relay: mailbox frame cap %d is outside (0, %d]", c.MailboxMaxFrames, DefaultMailboxMaxFrames)
	}
	if c.MailboxMaxBytes <= 0 || c.MailboxMaxBytes > DefaultMailboxMaxBytes {
		return fmt.Errorf("relay: mailbox byte cap %d is outside (0, %d]", c.MailboxMaxBytes, DefaultMailboxMaxBytes)
	}
	// §7.1 marks the frame and header caps Hard: they are not tunable in
	// either direction, because both endpoints and the AD encoding depend
	// on them.
	if c.MaxFrameSize != DefaultMaxFrameSize {
		return fmt.Errorf("relay: max frame size is hard at %d bytes (§7.1), got %d", DefaultMaxFrameSize, c.MaxFrameSize)
	}
	if c.MaxHeaderLen != DefaultMaxHeaderLen {
		return fmt.Errorf("relay: max header length is hard at %d bytes (§7.1), got %d", DefaultMaxHeaderLen, c.MaxHeaderLen)
	}
	if c.BindingIdleReap <= 0 {
		return fmt.Errorf("relay: binding idle reap must be positive (§2.2 requires a reaper)")
	}
	return nil
}

// mailboxPolicy projects the §4 TTL/caps for the Store.
func (c *Config) mailboxPolicy() MailboxPolicy {
	return MailboxPolicy{TTL: c.MailboxTTL, MaxFrames: c.MailboxMaxFrames, MaxBytes: c.MailboxMaxBytes}
}
