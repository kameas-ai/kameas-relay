package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// Environment configuration for cmd/relayd.
//
// Every value is validated at BOOT and a bad one is fatal. A relay that
// starts with a silently-clamped mailbox TTL, or with authentication
// half-configured, is worse than a relay that refuses to start: the first
// is a privacy posture nobody reviewed, the second is a page.
//
//	RELAY_ADDR                     listen address                  (default :8080)
//	RELAY_READ_HEADER_TIMEOUT      slowloris guard                 (default 10s)
//	RELAY_IDLE_TIMEOUT             idle keep-alive timeout         (default 120s)
//	RELAY_SHUTDOWN_GRACE           graceful drain on SIGTERM       (default 20s)
//	RELAY_LOG_LEVEL                debug|info|warn|error           (default info)
//	RELAY_LOG_FORMAT               json|text                       (default json)
//
//	RELAY_OIDC_ISSUER              REQUIRED  Zitadel issuer URL
//	RELAY_JWKS_URL                 JWKS document (default <issuer>/oauth/v2/keys)
//	RELAY_AUDIENCE                 required audience               (default kameas-api)
//	RELAY_JWKS_CACHE_TTL           5m..24h                         (default 15m)
//	RELAY_JWT_LEEWAY               clock skew allowance, 0..5m     (default 60s)
//
//	RELAY_MAILBOX_TTL              <= 15m                          (default 15m)
//	RELAY_MAILBOX_MAX_FRAMES       <= 128                          (default 128)
//	RELAY_MAILBOX_MAX_BYTES        <= 4194304                      (default 4 MiB)
//	RELAY_WINDOW_TTL               <= 5m                           (default 5m)
//	RELAY_OFFLINE_AFTER            <= 30s                          (default 30s)
//	RELAY_HEARTBEAT_INTERVAL       < offline-after                 (default 15s)
//	RELAY_BINDING_IDLE_REAP        §2.2 reaper horizon             (default 720h)
//
//	RELAY_LIMIT_DEVICE_FRAMES_PER_SEC     (default 60)
//	RELAY_LIMIT_DEVICE_FRAMES_BURST       (default 120)
//	RELAY_LIMIT_HOST_FRAMES_PER_SEC       (default 200)
//	RELAY_LIMIT_HOST_FRAMES_BURST         (default 400)
//	RELAY_LIMIT_MAILBOX_GET_PER_MIN       (default 30)
//	RELAY_LIMIT_PAIRINGS_PER_HOUR         (default 10)
//	RELAY_LIMIT_WINDOWS_PER_HOUR          (default 20)
//	RELAY_LIMIT_ATTACHES_PER_WINDOW       (default 10)
//	RELAY_LIMIT_APNS_REGS_PER_HOUR        (default 10)
//	RELAY_LIMIT_DEVICE_ATTACH_PER_CHANNEL (default 4)
//
// There is deliberately NO variable that disables authentication, relaxes
// the frame/header caps, or raises a mailbox bound.

// ServerConfig is everything cmd/relayd needs.
type ServerConfig struct {
	Addr              string
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	ShutdownGrace     time.Duration
	LogLevel          slog.Level
	LogJSON           bool

	Issuer        string
	Audience      string
	JWKSURL       string
	JWKSCacheTTL  time.Duration
	JWTLeeway     time.Duration
	BindingReaper time.Duration

	// Relay carries the tunables; Store, Validator, Logger, Pusher, and
	// Ready are filled in by relayd.
	Relay Config
}

type envReader struct {
	get  func(string) string
	errs []error
}

func (e *envReader) fail(format string, args ...any) {
	e.errs = append(e.errs, fmt.Errorf(format, args...))
}

func (e *envReader) str(key, def string) string {
	if v := strings.TrimSpace(e.get(key)); v != "" {
		return v
	}
	return def
}

func (e *envReader) dur(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(e.get(key))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		e.fail("%s: %q is not a duration (e.g. 15m, 30s)", key, raw)
		return def
	}
	return d
}

func (e *envReader) intv(key string, def int) int {
	raw := strings.TrimSpace(e.get(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		e.fail("%s: %q is not an integer", key, raw)
		return def
	}
	return n
}

func (e *envReader) int64v(key string, def int64) int64 {
	raw := strings.TrimSpace(e.get(key))
	if raw == "" {
		return def
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		e.fail("%s: %q is not an integer", key, raw)
		return def
	}
	return n
}

func (e *envReader) float(key string, def float64) float64 {
	raw := strings.TrimSpace(e.get(key))
	if raw == "" {
		return def
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		e.fail("%s: %q is not a number", key, raw)
		return def
	}
	return f
}

// LoadServerConfig reads and validates the environment. getenv is injected
// so the loader is testable without mutating process state.
func LoadServerConfig(getenv func(string) string) (ServerConfig, error) {
	e := &envReader{get: getenv}

	cfg := ServerConfig{
		Addr:              e.str("RELAY_ADDR", ":8080"),
		ReadHeaderTimeout: e.dur("RELAY_READ_HEADER_TIMEOUT", 10*time.Second),
		IdleTimeout:       e.dur("RELAY_IDLE_TIMEOUT", 120*time.Second),
		ShutdownGrace:     e.dur("RELAY_SHUTDOWN_GRACE", 20*time.Second),

		Issuer:        e.str("RELAY_OIDC_ISSUER", ""),
		Audience:      e.str("RELAY_AUDIENCE", "kameas-api"),
		JWKSURL:       e.str("RELAY_JWKS_URL", ""),
		JWKSCacheTTL:  e.dur("RELAY_JWKS_CACHE_TTL", 15*time.Minute),
		JWTLeeway:     e.dur("RELAY_JWT_LEEWAY", 60*time.Second),
		BindingReaper: e.dur("RELAY_BINDING_IDLE_REAP", DefaultBindingIdleReap),
	}

	switch strings.ToLower(e.str("RELAY_LOG_LEVEL", "info")) {
	case "debug":
		cfg.LogLevel = slog.LevelDebug
	case "info":
		cfg.LogLevel = slog.LevelInfo
	case "warn", "warning":
		cfg.LogLevel = slog.LevelWarn
	case "error":
		cfg.LogLevel = slog.LevelError
	default:
		e.fail("RELAY_LOG_LEVEL: want debug|info|warn|error")
	}
	switch strings.ToLower(e.str("RELAY_LOG_FORMAT", "json")) {
	case "json":
		cfg.LogJSON = true
	case "text":
		cfg.LogJSON = false
	default:
		e.fail("RELAY_LOG_FORMAT: want json|text")
	}

	// AuthN is not optional and has no default issuer: a relay that boots
	// without an identity provider would have to either refuse everyone
	// (a confusing outage) or accept everyone (a constitutional failure).
	if cfg.Issuer == "" {
		e.fail("RELAY_OIDC_ISSUER is required — the relay has no unauthenticated mode")
	}
	if cfg.JWKSURL == "" && cfg.Issuer != "" {
		// Zitadel's discovery path. Set RELAY_JWKS_URL explicitly for any
		// other provider.
		cfg.JWKSURL = strings.TrimRight(cfg.Issuer, "/") + "/oauth/v2/keys"
	}
	if cfg.Audience == "" {
		e.fail("RELAY_AUDIENCE must not be empty")
	}

	cfg.Relay = Config{
		MailboxTTL:        e.dur("RELAY_MAILBOX_TTL", DefaultMailboxTTL),
		MailboxMaxFrames:  e.intv("RELAY_MAILBOX_MAX_FRAMES", DefaultMailboxMaxFrames),
		MailboxMaxBytes:   e.int64v("RELAY_MAILBOX_MAX_BYTES", DefaultMailboxMaxBytes),
		WindowTTL:         e.dur("RELAY_WINDOW_TTL", DefaultWindowTTL),
		OfflineAfter:      e.dur("RELAY_OFFLINE_AFTER", DefaultOfflineAfter),
		HeartbeatInterval: e.dur("RELAY_HEARTBEAT_INTERVAL", DefaultHeartbeatInterval),
		MaxFrameSize:      DefaultMaxFrameSize, // §7.1 Hard — not configurable
		MaxHeaderLen:      DefaultMaxHeaderLen, // §7.1 Hard — not configurable
		BindingIdleReap:   cfg.BindingReaper,
		Limits: Limits{
			DeviceFramesPerSec:       e.float("RELAY_LIMIT_DEVICE_FRAMES_PER_SEC", 60),
			DeviceFramesBurst:        e.float("RELAY_LIMIT_DEVICE_FRAMES_BURST", 120),
			HostFramesPerSec:         e.float("RELAY_LIMIT_HOST_FRAMES_PER_SEC", 200),
			HostFramesBurst:          e.float("RELAY_LIMIT_HOST_FRAMES_BURST", 400),
			MailboxGetPerMin:         e.intv("RELAY_LIMIT_MAILBOX_GET_PER_MIN", 30),
			PairingsPerHour:          e.intv("RELAY_LIMIT_PAIRINGS_PER_HOUR", 10),
			PairingWindowsPerHour:    e.intv("RELAY_LIMIT_WINDOWS_PER_HOUR", 20),
			PairingAttachesPerWindow: e.intv("RELAY_LIMIT_ATTACHES_PER_WINDOW", 10),
			APNSRegsPerHour:          e.intv("RELAY_LIMIT_APNS_REGS_PER_HOUR", 10),
			DeviceAttachPerChannel:   e.intv("RELAY_LIMIT_DEVICE_ATTACH_PER_CHANNEL", 4),
		},
	}

	if cfg.ShutdownGrace <= 0 {
		e.fail("RELAY_SHUTDOWN_GRACE must be positive")
	}
	if len(e.errs) > 0 {
		return ServerConfig{}, errors.Join(e.errs...)
	}
	// Apply relay defaults for anything left zero, then run the contract
	// bound checks so a bad env fails here rather than at first request.
	cfg.Relay.applyDefaults()
	// Validate() also requires Store and Validator; relayd supplies those,
	// so check the tunables with placeholders that Validate only nil-checks.
	probe := cfg.Relay
	probe.Store = noopStoreProbe{}
	probe.Validator = noopValidatorProbe{}
	if err := probe.Validate(); err != nil {
		return ServerConfig{}, err
	}
	return cfg, nil
}

// The two probe types below exist only so LoadServerConfig can run the same
// Validate() the runtime does, without pretending to own a Store or a
// Validator. They are unexported and unreachable from any constructor.
type noopStoreProbe struct{ Store }

type noopValidatorProbe struct{ TokenValidator }
