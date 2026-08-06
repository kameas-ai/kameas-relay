package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The end-to-end contract behaviours (routing, mailbox, presence, pairing
// windows, binding, limits, close codes) are exercised by
// internal/relayparity, which runs one scripted table against BOTH this
// package and internal/fakerelay so the double cannot drift from the
// service. This file covers what is specific to the production
// implementation: configuration, the Store seam, the authN/authZ seam, and
// the logging discipline of §9.

func tid(b byte) string { return b64.EncodeToString(bytes.Repeat([]byte{b}, 16)) }

var (
	hostA    = tid(0x01)
	deviceA  = tid(0x02)
	channelA = tid(0x03)
)

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Store:     NewMemStore(DefaultBindingIdleReap),
		Validator: TestOnlySubjectValidator{},
		Clock:     NewFakeClock(time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)),
	}
}

func newTestRelay(t *testing.T, cfg Config) (*Relay, *httptest.Server) {
	t.Helper()
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)
	return r, srv
}

// ---------------------------------------------------------------------
// Config — the contract's bounds are enforced at BOOT
// ---------------------------------------------------------------------

func TestConfigRequiresStoreAndValidator(t *testing.T) {
	if _, err := New(Config{Validator: TestOnlySubjectValidator{}}); err == nil {
		t.Error("a relay without a Store must not start")
	}
	// The important half: there is no default validator, so a relay cannot
	// come up accidentally unauthenticated.
	_, err := New(Config{Store: NewMemStore(0)})
	if err == nil {
		t.Fatal("a relay without a Validator must not start — there is no unauthenticated mode")
	}
	if !strings.Contains(err.Error(), "Validator") {
		t.Errorf("error should name the missing Validator, got %v", err)
	}
}

func TestConfigRefusesRaisedContractBounds(t *testing.T) {
	// §4: the mailbox TTL and caps "may be tuned downward; neither may be
	// raised without a CONTRACTS.md revision". §7.1 marks the frame and
	// header caps Hard in both directions. Both are enforced here rather
	// than clamped, so a running relay always matches its configuration.
	cases := []struct {
		name string
		mut  func(*Config)
		want bool // true => must be rejected
	}{
		{"mailbox TTL raised", func(c *Config) { c.MailboxTTL = 30 * time.Minute }, true},
		{"mailbox TTL lowered", func(c *Config) { c.MailboxTTL = 5 * time.Minute }, false},
		{"mailbox frame cap raised", func(c *Config) { c.MailboxMaxFrames = 1024 }, true},
		{"mailbox frame cap lowered", func(c *Config) { c.MailboxMaxFrames = 16 }, false},
		{"mailbox byte cap raised", func(c *Config) { c.MailboxMaxBytes = 64 << 20 }, true},
		{"window TTL raised past 5m", func(c *Config) { c.WindowTTL = 10 * time.Minute }, true},
		{"window TTL lowered", func(c *Config) { c.WindowTTL = time.Minute }, false},
		{"offline-after raised past 30s", func(c *Config) { c.OfflineAfter = time.Minute }, true},
		{"heartbeat not shorter than offline-after", func(c *Config) { c.HeartbeatInterval = 30 * time.Second }, true},
		{"max frame size changed", func(c *Config) { c.MaxFrameSize = 256 << 10 }, true},
		{"max header len changed", func(c *Config) { c.MaxHeaderLen = 1024 }, true},
		{"binding reaper disabled", func(c *Config) { c.BindingIdleReap = -1 }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			tc.mut(&cfg)
			_, err := New(cfg)
			if tc.want && err == nil {
				t.Fatal("configuration should have been rejected at boot")
			}
			if !tc.want && err != nil {
				t.Fatalf("configuration should have been accepted: %v", err)
			}
		})
	}
}

func TestLoadServerConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	t.Run("issuer is required", func(t *testing.T) {
		if _, err := LoadServerConfig(env(map[string]string{})); err == nil {
			t.Fatal("a relay must not boot without an identity provider")
		}
	})

	t.Run("defaults", func(t *testing.T) {
		cfg, err := LoadServerConfig(env(map[string]string{
			"RELAY_OIDC_ISSUER": "https://lle.zitadel.example",
		}))
		if err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if cfg.Addr != ":8080" {
			t.Errorf("addr = %q", cfg.Addr)
		}
		if cfg.Audience != "kameas-api" {
			t.Errorf("audience = %q; the contract pins kameas-api", cfg.Audience)
		}
		if want := "https://lle.zitadel.example/oauth/v2/keys"; cfg.JWKSURL != want {
			t.Errorf("JWKS URL = %q; want the derived %q", cfg.JWKSURL, want)
		}
		if cfg.Relay.MailboxTTL != DefaultMailboxTTL || cfg.Relay.OfflineAfter != DefaultOfflineAfter {
			t.Errorf("contract defaults not applied: %+v", cfg.Relay)
		}
		if cfg.Relay.MaxFrameSize != DefaultMaxFrameSize || cfg.Relay.MaxHeaderLen != DefaultMaxHeaderLen {
			t.Error("the hard §7.1 caps must not be reachable from the environment")
		}
	})

	t.Run("bad values fail fast", func(t *testing.T) {
		cases := []map[string]string{
			{"RELAY_OIDC_ISSUER": "https://i", "RELAY_MAILBOX_TTL": "1h"},
			{"RELAY_OIDC_ISSUER": "https://i", "RELAY_MAILBOX_TTL": "not-a-duration"},
			{"RELAY_OIDC_ISSUER": "https://i", "RELAY_WINDOW_TTL": "10m"},
			{"RELAY_OIDC_ISSUER": "https://i", "RELAY_OFFLINE_AFTER": "5m"},
			{"RELAY_OIDC_ISSUER": "https://i", "RELAY_MAILBOX_MAX_FRAMES": "9999"},
			{"RELAY_OIDC_ISSUER": "https://i", "RELAY_LOG_LEVEL": "chatty"},
			{"RELAY_OIDC_ISSUER": "https://i", "RELAY_LOG_FORMAT": "yaml"},
			{"RELAY_OIDC_ISSUER": "https://i", "RELAY_HEARTBEAT_INTERVAL": "45s"},
			{"RELAY_OIDC_ISSUER": "https://i", "RELAY_LIMIT_MAILBOX_GET_PER_MIN": "many"},
		}
		for _, m := range cases {
			if _, err := LoadServerConfig(env(m)); err == nil {
				t.Errorf("env %v should have been rejected", m)
			}
		}
	})

	t.Run("no variable can disable authentication", func(t *testing.T) {
		// A regression guard with teeth: if someone adds an "insecure" or
		// "dev" auth mode, this fails and they have to justify it.
		for _, k := range []string{
			"RELAY_AUTH_MODE", "RELAY_INSECURE", "RELAY_DISABLE_AUTH",
			"RELAY_SKIP_JWT", "RELAY_DEV_MODE", "RELAY_ALLOW_ANONYMOUS",
		} {
			cfg, err := LoadServerConfig(env(map[string]string{k: "1"}))
			if err == nil {
				t.Errorf("%s=1 produced a valid config %+v; there must be no unauthenticated mode", k, cfg)
			}
		}
	})
}

// ---------------------------------------------------------------------
// AuthN seam — §2.1 bearer placement, §2 fail-closed
// ---------------------------------------------------------------------

func TestBearerMustNotRideTheQueryString(t *testing.T) {
	_, srv := newTestRelay(t, testConfig(t))

	// §2.1: "The relay MUST reject a token supplied as a query parameter,
	// EVEN A VALID ONE — query strings are logged by load balancers and
	// proxies outside our control."
	for _, param := range tokenQueryParams {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/pairing-windows?"+param+"=fake-alice", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer fake-alice") // valid header too
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("?%s= alongside a valid header returned %d; want 401", param, resp.StatusCode)
		}
	}
}

// failClosedValidator simulates the JWKS-unreachable path.
type failClosedValidator struct{}

func (failClosedValidator) Validate(context.Context, string) (string, error) {
	return "", ErrTokenUnavailable
}

func TestJWKSUnavailableFailsClosedWith503(t *testing.T) {
	cfg := testConfig(t)
	cfg.Validator = failClosedValidator{}
	_, srv := newTestRelay(t, cfg)

	req, _ := http.NewRequest("POST", srv.URL+"/v1/pairings", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer anything")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503 auth_unavailable (§7.2) — never a fallback to accepting", resp.StatusCode)
	}
	var body struct{ Code string }
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Code != string(CodeAuthUnavailable) {
		t.Fatalf("code = %q; want %q", body.Code, CodeAuthUnavailable)
	}
}

func TestReadyzReflectsDependencyAndEnumeratesNothing(t *testing.T) {
	cfg := testConfig(t)
	down := errors.New("jwks unreachable at https://internal-idp.svc.cluster.local")
	var fail bool
	cfg.Ready = func(context.Context) error {
		if fail {
			return down
		}
		return nil
	}
	_, srv := newTestRelay(t, cfg)

	get := func(path string) (int, string) {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.String()
	}

	if code, _ := get("/healthz"); code != 200 {
		t.Errorf("/healthz = %d", code)
	}
	if code, _ := get("/readyz"); code != 200 {
		t.Errorf("/readyz = %d while the dependency is healthy", code)
	}
	fail = true
	code, body := get("/readyz")
	if code != http.StatusServiceUnavailable {
		t.Errorf("/readyz = %d while the dependency is down; want 503", code)
	}
	// §7.3: health endpoints return no operator data. The dependency's
	// error text names an internal hostname, so it must not be echoed.
	if strings.Contains(body, "internal-idp") || strings.Contains(body, "jwks") {
		t.Errorf("/readyz body leaked dependency detail: %q", body)
	}
}

func TestHealthEndpointsEnumerateNothing(t *testing.T) {
	cfg := testConfig(t)
	r, srv := newTestRelay(t, cfg)
	ctx := context.Background()

	// Populate every persistence class, then confirm the unauthenticated
	// health surfaces still say nothing about any of it (§7.3).
	if _, err := cfg.Store.BindHost(ctx, hostA, "alice", r.cfg.Clock.Now()); err != nil {
		t.Fatalf("BindHost: %v", err)
	}
	label := "daily-driver"
	if err := cfg.Store.CreatePairing(ctx, Pairing{
		PairingID: "p1", ChannelID: channelA, HostID: hostA, DeviceID: deviceA,
		AccountSub: "alice", HostLabel: &label,
	}); err != nil {
		t.Fatalf("CreatePairing: %v", err)
	}

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		_ = resp.Body.Close()
		body := buf.String()
		for _, secret := range []string{hostA, deviceA, channelA, "alice", "daily-driver", "1"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s body %q leaks %q — §7.3 forbids enumerating channels, devices, hosts, or counts", path, body, secret)
			}
		}
	}
}

// ---------------------------------------------------------------------
// AuthZ — channel rule and the §2.2 binding
// ---------------------------------------------------------------------

func TestAuthorizeChannelTable(t *testing.T) {
	cfg := testConfig(t)
	r, _ := newTestRelay(t, cfg)
	ctx := context.Background()
	if _, err := cfg.Store.BindHost(ctx, hostA, "alice", r.cfg.Clock.Now()); err != nil {
		t.Fatalf("BindHost: %v", err)
	}
	if err := cfg.Store.CreatePairing(ctx, Pairing{
		PairingID: "p1", ChannelID: channelA, HostID: hostA, DeviceID: deviceA, AccountSub: "alice",
	}); err != nil {
		t.Fatalf("CreatePairing: %v", err)
	}

	cases := []struct {
		name    string
		channel string
		sub     string
		want    ErrCode
	}{
		{"registered channel, owning account", channelA, "alice", ""},
		{"registered channel, other account", channelA, "mallory", CodeForbidden},
		{"unregistered channel", tid(0x09), "alice", CodeNotFound},
		{"unregistered channel, other account", tid(0x09), "mallory", CodeNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := r.authorizeChannel(ctx, tc.channel, tc.sub); got != tc.want {
				t.Fatalf("code = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestBindingIsImmutableAndReaped(t *testing.T) {
	cfg := testConfig(t)
	clock := cfg.Clock.(*FakeClock)
	store := cfg.Store
	ctx := context.Background()

	if _, err := store.BindHost(ctx, hostA, "alice", clock.Now()); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	// §2.2: immutable. A later attach presenting a different sub is
	// refused; the relay MUST NOT rebind, merge, or prompt.
	if _, err := store.BindHost(ctx, hostA, "mallory", clock.Now()); !errors.Is(err, ErrBoundToOtherAccount) {
		t.Fatalf("rebind attempt returned %v; want ErrBoundToOtherAccount", err)
	}
	if b, ok, _ := store.LookupBinding(ctx, hostA, clock.Now()); !ok || b.AccountSub != "alice" {
		t.Fatalf("binding changed under a rebind attempt: %+v", b)
	}

	// §2.2 reaper: zero pairings + idle horizon ⇒ deleted, so a
	// regenerated or mistyped host_id cannot squat forever.
	clock.Advance(DefaultBindingIdleReap + time.Hour)
	if _, ok, _ := store.LookupBinding(ctx, hostA, clock.Now()); ok {
		t.Fatal("idle binding with zero pairings was not reaped")
	}

	// With a pairing present, the binding survives the same idle period:
	// the reaper's condition is "no pairings AND idle", not "idle".
	if _, err := store.BindHost(ctx, hostA, "alice", clock.Now()); err != nil {
		t.Fatalf("rebind after reap: %v", err)
	}
	if err := store.CreatePairing(ctx, Pairing{
		PairingID: "p1", ChannelID: channelA, HostID: hostA, DeviceID: deviceA, AccountSub: "alice",
	}); err != nil {
		t.Fatalf("CreatePairing: %v", err)
	}
	clock.Advance(DefaultBindingIdleReap + time.Hour)
	if _, ok, _ := store.LookupBinding(ctx, hostA, clock.Now()); !ok {
		t.Fatal("binding with a live pairing must not be reaped")
	}
}

// ---------------------------------------------------------------------
// Store — the §8 budget
// ---------------------------------------------------------------------

func TestMailboxIsNonDestructiveAndCapped(t *testing.T) {
	store := NewMemStore(0)
	ctx := context.Background()
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	pol := MailboxPolicy{TTL: DefaultMailboxTTL, MaxFrames: 4, MaxBytes: DefaultMailboxMaxBytes}

	for i := uint64(1); i <= 3; i++ {
		if err := store.AppendMailbox(ctx, channelA, MailboxItem{
			Seq: i, PushClass: PushNone, Body: []byte{byte(i)}, StoredAt: now,
		}, pol); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// Non-destructive: the NSE and the app both fetch the same item, so a
	// second read must return the same three frames.
	for attempt := range 2 {
		items, next, trunc, err := store.FetchMailbox(ctx, channelA, 0, 64, now, pol.TTL)
		if err != nil || len(items) != 3 || next != 3 || trunc {
			t.Fatalf("attempt %d: items=%d next=%d trunc=%v err=%v — reads must be non-destructive",
				attempt, len(items), next, trunc, err)
		}
	}

	// Cap eviction drops OLDEST and produces a seq gap, which is expected
	// and correct: the device's forward-only drain plus the snapshot.full
	// reconcile handle it, and the relay never gap-repairs.
	for i := uint64(4); i <= 8; i++ {
		_ = store.AppendMailbox(ctx, channelA, MailboxItem{
			Seq: i, PushClass: PushNone, Body: []byte{byte(i)}, StoredAt: now,
		}, pol)
	}
	items, _, _, _ := store.FetchMailbox(ctx, channelA, 0, 64, now, pol.TTL)
	if len(items) != 4 || items[0].Seq != 5 {
		t.Fatalf("after eviction got %d items starting at seq %d; want 4 starting at 5", len(items), items[0].Seq)
	}

	// TTL expiry.
	if items, _, _, _ := store.FetchMailbox(ctx, channelA, 0, 64, now.Add(pol.TTL+time.Second), pol.TTL); len(items) != 0 {
		t.Fatalf("%d items survived the TTL", len(items))
	}
}

func TestMailboxBodyIsStoredWhole(t *testing.T) {
	// §4/§10: the class-M body is ONE opaque blob; the nonce ‖ ciphertext
	// split is the RECEIVER's. A store that decomposed it would have taken
	// a dependency on the AEAD layout.
	store := NewMemStore(0)
	ctx := context.Background()
	now := time.Now()
	body := bytes.Repeat([]byte{0xAB}, 24+64) // looks like nonce ‖ ct
	pol := MailboxPolicy{TTL: time.Minute, MaxFrames: 8, MaxBytes: 1 << 20}
	_ = store.AppendMailbox(ctx, channelA, MailboxItem{Seq: 1, PushClass: PushNone, Body: body, StoredAt: now}, pol)

	items, _, _, _ := store.FetchMailbox(ctx, channelA, 0, 8, now, pol.TTL)
	if len(items) != 1 || !bytes.Equal(items[0].Body, body) {
		t.Fatal("mailbox body did not round-trip byte-for-byte")
	}
}

func TestDeletePairingCascades(t *testing.T) {
	store := NewMemStore(0)
	ctx := context.Background()
	now := time.Now()
	if err := store.CreatePairing(ctx, Pairing{
		PairingID: "p1", ChannelID: channelA, HostID: hostA, DeviceID: deviceA, AccountSub: "alice",
	}); err != nil {
		t.Fatalf("CreatePairing: %v", err)
	}
	_ = store.PutAPNSToken(ctx, APNSToken{DeviceID: deviceA, Token: "deadbeef", Env: "sandbox"})
	_ = store.AppendMailbox(ctx, channelA, MailboxItem{Seq: 1, Body: []byte("x"), PushClass: PushNone, StoredAt: now},
		MailboxPolicy{TTL: time.Minute, MaxFrames: 8, MaxBytes: 1 << 20})

	if _, ok, _ := store.DeletePairing(ctx, "p1"); !ok {
		t.Fatal("DeletePairing reported nothing deleted")
	}
	if _, ok, _ := store.PairingByChannel(ctx, channelA); ok {
		t.Error("channel index survived deletion")
	}
	if items, _, _, _ := store.FetchMailbox(ctx, channelA, 0, 8, now, time.Minute); len(items) != 0 {
		t.Error("mailbox survived pairing deletion")
	}
	// §8: an APNs token is retained "until re-registration or pairing
	// deletion".
	if _, ok, _ := store.LookupAPNSToken(ctx, deviceA); ok {
		t.Error("APNs token survived deletion of the device's only pairing")
	}
}

func TestCreatePairingRejectsChannelReuse(t *testing.T) {
	store := NewMemStore(0)
	ctx := context.Background()
	p := Pairing{PairingID: "p1", ChannelID: channelA, HostID: hostA, DeviceID: deviceA, AccountSub: "alice"}
	if err := store.CreatePairing(ctx, p); err != nil {
		t.Fatalf("first: %v", err)
	}
	p.PairingID = "p2"
	if err := store.CreatePairing(ctx, p); !errors.Is(err, ErrChannelRegistered) {
		t.Fatalf("second registration returned %v; want ErrChannelRegistered (§7.2 conflict)", err)
	}
}

func TestOpenWindowDisplacesThePriorOne(t *testing.T) {
	// §3.1: at most one open window per host_id. Two live windows would
	// mean two provisional channels and an ambiguous AD.
	store := NewMemStore(0)
	ctx := context.Background()
	now := time.Now()
	w1 := Window{WindowID: "w1", HostID: hostA, ProvisionalChannel: tid(0x11), ExpiresAt: now.Add(time.Minute)}
	w2 := Window{WindowID: "w2", HostID: hostA, ProvisionalChannel: tid(0x12), ExpiresAt: now.Add(time.Minute)}

	if displaced, _ := store.OpenWindow(ctx, w1); displaced != nil {
		t.Fatal("the first window displaced something")
	}
	displaced, _ := store.OpenWindow(ctx, w2)
	if displaced == nil || displaced.WindowID != "w1" {
		t.Fatalf("second POST displaced %v; want w1", displaced)
	}
	if _, ok, _ := store.LookupWindow(ctx, "w1"); ok {
		t.Error("the displaced window is still usable")
	}
	got, ok, _ := store.WindowForHost(ctx, hostA, now)
	if !ok || got.WindowID != "w2" {
		t.Fatalf("WindowForHost = %v, %v; want w2", got, ok)
	}

	// Server-side expiry; never extended on activity.
	if _, ok, _ := store.WindowForHost(ctx, hostA, now.Add(2*time.Minute)); ok {
		t.Error("an expired window is still open")
	}
}

// ---------------------------------------------------------------------
// §5.3 — the closed APNs payload schema
// ---------------------------------------------------------------------

func TestAPNSPayloadsAreClosedAndCategoryFree(t *testing.T) {
	label := "daily-driver"

	attention := attentionPayload(&label, channelA, 7)
	aps, _ := attention["aps"].(map[string]any)
	if aps == nil {
		t.Fatal("no aps dictionary")
	}
	// The relay ships NO display text and NO category: the NSE decrypts
	// over the E2E path and rewrites title/body/categoryIdentifier locally.
	for _, forbidden := range []string{"title", "body", "category", "subtitle"} {
		if _, present := aps[forbidden]; present {
			t.Errorf("aps carries %q; the relay MUST NOT author categorized or text-bearing pushes (§5.3)", forbidden)
		}
	}
	alert, _ := aps["alert"].(map[string]any)
	if alert["loc-key"] != LocKeyGeneric {
		t.Errorf("loc-key = %v; want the fixed %q", alert["loc-key"], LocKeyGeneric)
	}
	if args, _ := alert["loc-args"].([]any); len(args) != 1 || args[0] != label {
		t.Errorf("loc-args = %v; want exactly [host_label]", alert["loc-args"])
	}
	assertKeys(t, "attention alert", alert, "loc-key", "loc-args")
	assertKeys(t, "attention aps", aps, "alert", "mutable-content", "sound", "thread-id")
	assertKeys(t, "attention payload", attention, "aps", "ch", "sq")

	// §XII condition-5 reduction: clearing host_label removes loc-args
	// entirely, leaving a fixed non-operator-derived string. That is
	// STRONGER than the condition's category-only floor.
	reduced := attentionPayload(nil, channelA, 7)
	ralert := reduced["aps"].(map[string]any)["alert"].(map[string]any)
	if _, present := ralert["loc-args"]; present {
		t.Error("clearing host_label must remove loc-args entirely")
	}
	assertKeys(t, "reduced alert", ralert, "loc-key")

	wake := wakePayload(channelA, 7)
	waps := wake["aps"].(map[string]any)
	assertKeys(t, "wake aps", waps, "content-available")
	assertKeys(t, "wake payload", wake, "aps", "ch", "sq")
}

func assertKeys(t *testing.T, what string, m map[string]any, want ...string) {
	t.Helper()
	set := make(map[string]bool, len(want))
	for _, k := range want {
		set[k] = true
		if _, ok := m[k]; !ok {
			t.Errorf("%s: missing key %q", what, k)
		}
	}
	for k := range m {
		if !set[k] {
			t.Errorf("%s: unexpected key %q — the §5.3 schema is CLOSED and an unknown field fails the SC-2 audit", what, k)
		}
	}
}

// ---------------------------------------------------------------------
// §9 — logging discipline
// ---------------------------------------------------------------------

func TestLoggingCarriesMetadataOnly(t *testing.T) {
	var buf lockedBuffer
	cfg := testConfig(t)
	cfg.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r, srv := newTestRelay(t, cfg)
	ctx := context.Background()

	// Register an APNs token whose bytes must never reach a log line.
	if _, err := cfg.Store.BindHost(ctx, hostA, "alice", r.cfg.Clock.Now()); err != nil {
		t.Fatalf("BindHost: %v", err)
	}
	if err := cfg.Store.CreatePairing(ctx, Pairing{
		PairingID: "p1", ChannelID: channelA, HostID: hostA, DeviceID: deviceA, AccountSub: "alice",
	}); err != nil {
		t.Fatalf("CreatePairing: %v", err)
	}
	const secretToken = "d3adb33fcafebabe0123456789abcdef"
	req, _ := http.NewRequest("PUT", srv.URL+"/v1/devices/"+deviceA+"/apns",
		strings.NewReader(`{"token":"`+secretToken+`","env":"sandbox"}`))
	req.Header.Set("Authorization", "Bearer fake-alice")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("PUT apns: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT apns: status %d", resp.StatusCode)
	}

	logs := buf.String()
	if !strings.Contains(logs, deviceA) {
		t.Error("expected the device id in the log — §9 permits ids and they are what makes a line useful")
	}
	// §9 MUST NOT: token bytes, JWT bytes, any claim other than sub.
	for _, forbidden := range []string{secretToken, "fake-alice", "Bearer"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("log leaked %q:\n%s", forbidden, logs)
		}
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
