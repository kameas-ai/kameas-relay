package sc2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kameas-ai/kameas-relay/devclient"
	"github.com/kameas-ai/kameas-relay/fakehost"
	"github.com/kameas-ai/kameas-relay/internal/relay"
	"github.com/kameas-ai/kameas-relay/wire"
)

// ---------------------------------------------------------------------
// The canaries
// ---------------------------------------------------------------------
//
// Every string below is known plaintext that travels END TO END between
// the fake host and the device client, through the real relay, over the
// real construction. None of it may be observable to the relay in any
// form: §XII condition 4 (no content persistence or logging of any kind)
// and condition 3 (anything observable and not enumerated is a defect).

const (
	// Content inside encrypted `event` envelopes.
	canaryEventAttr   = "CANARY-EVENT-ATTR-a3f19c7e"
	canaryWorkbenchID = "CANARY-WORKBENCH-5d2b81af"
	canaryTaskID      = "CANARY-TASK-91c40de6"

	// The operator-authored device name, carried inside the encrypted
	// pair.init.
	canaryDeviceName = "CANARY-DEVICE-NAME-7fe0a234"

	// approval.request.summary. §XII condition 5 names this one
	// explicitly: it "MUST NOT appear" in a push payload, and §8 forbids
	// persisting it anywhere. The fake host hard-codes this string.
	canaryApprovalSummary = "run make check"

	// A prompt-shaped string riding an event attr, standing in for the
	// class of content §XII condition 5 forbids in a push: "Nothing
	// derived from prompts, tool calls, agent output, file paths, or
	// command text."
	canaryPromptish = "rm -rf /home/operator/secret-project"
)

func allCanaries() []string {
	return []string{
		canaryEventAttr, canaryWorkbenchID, canaryTaskID,
		canaryDeviceName, canaryApprovalSummary, canaryPromptish,
	}
}

// hostLabelControl is the POSITIVE control. It is the operator-authored
// push label, which the relay legitimately holds (§8 folds host_label into
// the routing registration, and the NFR-3 threat model names it as
// operator plaintext the relay stores). Finding it in the store is what
// proves the audit is walking real records rather than an empty set — an
// all-negative assertion over nothing at all passes vacuously.
const hostLabelControl = "SC2-POSITIVE-CONTROL-HOST-LABEL"

// ---------------------------------------------------------------------
// Surfaces and the detector
// ---------------------------------------------------------------------

// surface is one place the relay could observe or emit something.
type surface struct {
	what string
	data []byte
}

type finding struct {
	canary  string
	surface string
	context string
}

// scan is the detector. It is a plain substring search over raw bytes on
// purpose: anything cleverer could be argued around, and a substring search
// cannot be defeated by an encoding as long as the raw bytes are what is
// searched (which is why relay.AuditRecord carries Raw alongside JSON).
func scan(surfaces []surface, canaries []string) []finding {
	var out []finding
	for _, s := range surfaces {
		for _, c := range canaries {
			if i := bytes.Index(s.data, []byte(c)); i >= 0 {
				lo := max(i-60, 0)
				hi := min(i+len(c)+60, len(s.data))
				out = append(out, finding{canary: c, surface: s.what, context: string(s.data[lo:hi])})
			}
		}
	}
	return out
}

// TestCanaryDetectorDetects is the DELIBERATE-FAILURE check.
//
// Without it, a scan() that silently stopped matching — a bad refactor, an
// encoding change, a typo in a canary constant — would turn the whole SC-2
// suite green while proving nothing. This test plants each canary in a
// fabricated surface of the same shape as the real ones and asserts the
// detector fires on every single one.
func TestCanaryDetectorDetects(t *testing.T) {
	for _, c := range allCanaries() {
		t.Run(c, func(t *testing.T) {
			planted := []surface{
				{what: "fabricated log line", data: []byte(
					`{"time":"2026-08-06T12:00:00Z","level":"INFO","msg":"frame","body":"` + c + `"}`)},
				{what: "fabricated store record", data: []byte(`{"Class":"ciphertext_mailbox","Body":"` + c + `"}`)},
				{what: "fabricated raw body", data: append([]byte{0x00, 0xFF}, append([]byte(c), 0x00)...)},
			}
			hits := scan(planted, []string{c})
			if len(hits) != len(planted) {
				t.Fatalf("detector found %d of %d planted canaries — the SC-2 assertion is not actually detecting",
					len(hits), len(planted))
			}
		})
	}
	// And the converse: a clean surface must not produce a finding, or
	// every run would fail for the wrong reason.
	clean := []surface{{what: "clean", data: []byte("nothing to see, just ciphertext-looking bytes")}}
	if hits := scan(clean, allCanaries()); len(hits) != 0 {
		t.Fatalf("detector fired on a clean surface: %+v", hits)
	}
}

// ---------------------------------------------------------------------
// The property test
// ---------------------------------------------------------------------

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.b.Bytes()...)
}

// TestNoPlaintextReachesTheRelay drives complete E2E sessions — pairing,
// live stream, an approval round-trip, an offline mailbox cycle, and the
// drain — through the REAL relay, then asserts every canary is absent from
// every surface the relay can observe.
func TestNoPlaintextReachesTheRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// --- the real relay, fully instrumented -------------------------
	logs := &lockedBuf{}
	store := relay.NewMemStore(relay.DefaultBindingIdleReap)
	pusher := &relay.RecordingPusher{}
	r, err := relay.New(relay.Config{
		Store:     store,
		Validator: relay.TestOnlySubjectValidator{},
		Pusher:    pusher,
		// Debug level: the audit must cover the CHATTIEST configuration
		// the relay can be run in, not the quietest.
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	defer func() { _ = r.Close() }()
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	// --- the fake host, carrying canaries in its content ------------
	out := &lockedBuf{}
	host, err := fakehost.New(fakehost.Config{
		RelayOrigin: srv.URL,
		Sub:         "sc2-user",
		// Becomes host_label — the positive control, legitimately visible.
		HostName:        hostLabelControl,
		AutoConfirm:     true,
		ApprovalAfter:   150 * time.Millisecond,
		ApprovalTimeout: 30 * time.Second,
		EventInterval:   40 * time.Millisecond,
		Out:             out,
		Script: []fakehost.ScriptEvent{
			// push_class "none" (source "agent").
			{AfterMS: 20, Source: "agent", Kind: "task.progress",
				WorkbenchID: canaryWorkbenchID, TaskID: canaryTaskID,
				Attrs: map[string]any{"detail": canaryEventAttr, "command": canaryPromptish}},
			// push_class "wake" (source "workbench").
			{AfterMS: 60, Source: "workbench", Kind: "workbench.started",
				WorkbenchID: canaryWorkbenchID,
				Attrs:       map[string]any{"detail": canaryEventAttr}},
			// push_class "attention" (source "security") — the alert form,
			// so the §5.3 payload audit has something to inspect.
			{AfterMS: 100, Source: "security", Kind: "security.egress_denied",
				WorkbenchID: canaryWorkbenchID,
				Attrs:       map[string]any{"detail": canaryEventAttr, "command": canaryPromptish}},
		},
	})
	if err != nil {
		t.Fatalf("fakehost.New: %v", err)
	}
	hostErr := make(chan error, 1)
	go func() { hostErr <- host.Run(ctx) }()
	if err := host.WaitAttached(ctx); err != nil {
		t.Fatalf("host attach: %v", err)
	}
	qr, _, err := host.OpenPairingWindow(ctx)
	if err != nil {
		t.Fatalf("OpenPairingWindow: %v", err)
	}

	// --- pair, with a canary device name ----------------------------
	st, err := devclient.Pair(ctx, devclient.PairConfig{
		QRURI:       qr,
		Sub:         "sc2-user",
		DeviceName:  canaryDeviceName,
		DeviceModel: "iPhone15,2",
	})
	if err != nil {
		t.Fatalf("pairing: %v", err)
	}

	// Register an APNs token so the §5.2 trigger fires while the device is
	// detached and the audit has real push payloads to inspect.
	registerAPNS(t, srv, st.DeviceID, "sc2-user")

	// --- live session: snapshot, events, approval round-trip --------
	decrypted := &lockedBuf{}
	sess, err := devclient.Connect(ctx, st)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	var sawSnapshot, sawCanaryEvent, sawApproval, sawResolved bool
	var rpcID string
	for !(sawSnapshot && sawCanaryEvent && sawApproval && sawResolved) {
		env, err := sess.Recv(ctx)
		if err != nil {
			t.Fatalf("recv: %v (host err: %v)", err, drainErr(hostErr))
		}
		record(decrypted, env)
		switch env.Kind {
		case "snapshot.full":
			sawSnapshot = true
		case "event":
			if bytes.Contains(env.Body, []byte(canaryEventAttr)) {
				sawCanaryEvent = true
			}
		case "approval.request":
			var a wire.ApprovalRequest
			if err := env.DecodeBody(&a); err != nil {
				t.Fatalf("approval decode: %v", err)
			}
			if a.Summary != canaryApprovalSummary {
				t.Fatalf("approval summary = %q; the canary constant is stale", a.Summary)
			}
			sawApproval = true
			// Device→host over the live socket.
			rpcID, err = sess.SendRPC(ctx, "approval.decide", map[string]string{
				"approval_id": a.ApprovalID, "decision": "allow",
			})
			if err != nil {
				t.Fatalf("approval.decide: %v", err)
			}
		case "approval.resolved":
			sawResolved = true
		case "rpc.response":
			if env.ID == rpcID {
				sawResolved = sawResolved || false
			}
		}
	}

	// --- offline cycle: detach, let frames spool, drain -------------
	_ = sess.Close()
	// Wait for the host to observe the §6.1 detach, then for it to spool
	// class-M frames into the mailbox.
	waitFor(t, 10*time.Second, func() bool { return !host.DeviceAttached() })

	// With the device detached the host seals class M under K_mbx and the
	// relay buffers it (§4.1 arm 2) — regardless of push_class, and with a
	// push for the two non-"none" classes. Both shapes are emitted so the
	// §5.3 payload audit has an alert AND a silent wake to inspect.
	host.EmitEvent(fakehost.ScriptEvent{
		Source: "workbench", Kind: "workbench.stopped", WorkbenchID: canaryWorkbenchID,
		Attrs: map[string]any{"detail": canaryEventAttr, "command": canaryPromptish},
	})
	host.EmitEvent(fakehost.ScriptEvent{
		Source: "security", Kind: "security.egress_denied", WorkbenchID: canaryWorkbenchID,
		TaskID: canaryTaskID,
		Attrs:  map[string]any{"detail": canaryEventAttr, "command": canaryPromptish},
	})
	waitFor(t, 10*time.Second, func() bool { return mailboxDepth(t, srv, st.ChannelID, "sc2-user") >= 2 })
	waitFor(t, 10*time.Second, func() bool { return len(pusher.Pushes()) >= 2 })

	// Reconnect: devclient.Connect drains the mailbox before the
	// handshake, so this both exercises the drain and proves the spooled
	// ciphertext really did carry the canaries.
	sess2, err := devclient.Connect(ctx, st)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	var sawPostReconnect bool
	for !sawPostReconnect && time.Now().Before(deadline) {
		rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
		env, err := sess2.Recv(rctx)
		rcancel()
		if err != nil {
			continue
		}
		record(decrypted, env)
		if bytes.Contains(env.Body, []byte(canaryEventAttr)) {
			sawPostReconnect = true
		}
	}
	_ = sess2.Close()

	// --- NON-VACUITY ------------------------------------------------
	//
	// Before asserting the canaries are absent from the relay, prove they
	// were actually present in the traffic. Otherwise a harness that
	// silently never sent them would pass this test while proving nothing.
	// Evidence is what the two ENDPOINTS decrypted, from both directions:
	// `decrypted` is every envelope the device received, and `out` is the
	// fake host's operator output — which prints the device name only
	// after decrypting the device→host pair.identity, and is therefore the
	// proof that the device-name canary crossed the relay too.
	plaintext := append(decrypted.Bytes(), out.Bytes()...)
	for _, c := range allCanaries() {
		if !bytes.Contains(plaintext, []byte(c)) {
			t.Fatalf("canary %q was never decrypted at either endpoint — "+
				"it did not traverse the relay, so the no-plaintext assertion would be vacuous", c)
		}
	}
	if !sawPostReconnect {
		t.Fatal("the mailbox drain never returned a canary-bearing frame; the class-M path was not exercised")
	}

	// --- gather every surface the relay can observe -----------------
	surfaces := gatherSurfaces(t, srv, store, pusher, logs)

	// The audit must not be walking an empty set: the positive control is
	// operator plaintext the relay LEGITIMATELY holds (host_label), so it
	// must be findable in the store.
	if hits := scan(surfaces, []string{hostLabelControl}); len(hits) == 0 {
		t.Fatal("positive control absent: the audit walked no real records, so its negative result means nothing")
	}

	// --- THE ASSERTION ----------------------------------------------
	if hits := scan(surfaces, allCanaries()); len(hits) > 0 {
		for _, h := range hits {
			t.Errorf("SC-2 FAILURE: canary %q observable in %s\n  context: %q",
				h.canary, h.surface, h.context)
		}
		t.Fatal("plaintext reached the relay — this is a §XII condition-2 / condition-4 constitutional failure, not a bug")
	}

	// --- §5.3: the APNs payload schema is CLOSED --------------------
	auditPushPayloads(t, pusher)
}

// gatherSurfaces collects every place the relay could have retained or
// emitted something: stored records (including RAW mailbox bytes), log
// output, the health endpoints, the mailbox REST body, and error messages.
func gatherSurfaces(t *testing.T, srv *httptest.Server, store *relay.MemStore,
	pusher *relay.RecordingPusher, logs *lockedBuf) []surface {
	t.Helper()
	var surfaces []surface

	// 1. Every stored record, in both encoded and raw form.
	records := store.AuditRecords()
	if len(records) == 0 {
		t.Fatal("the store holds nothing after a full session; the walk cannot be meaningful")
	}
	for i, rec := range records {
		surfaces = append(surfaces, surface{
			what: fmt.Sprintf("store record %d (%s), JSON", i, rec.Class), data: rec.JSON,
		})
		for j, raw := range rec.Raw {
			surfaces = append(surfaces, surface{
				what: fmt.Sprintf("store record %d (%s), raw field %d", i, rec.Class, j), data: raw,
			})
		}
	}

	// 2. Every log line the relay emitted, at debug level.
	surfaces = append(surfaces, surface{what: "relay log output", data: logs.Bytes()})

	// 3. Health and readiness bodies.
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		surfaces = append(surfaces, surface{what: "GET " + path, data: body})
	}

	// 4. Every APNs payload the relay would have sent.
	for i, p := range pusher.Pushes() {
		blob, _ := json.Marshal(p.Payload)
		surfaces = append(surfaces, surface{what: fmt.Sprintf("APNs payload %d", i), data: blob})
	}

	// 5. Error bodies. §7.2: "message MUST NOT include token bytes, claim
	//    values, emails, channel content, or any frame body." Provoke one
	//    of every reachable code and read what comes back.
	for _, probe := range []struct {
		method, path, token string
		body                string
	}{
		{"GET", "/v1/channels/" + strings.Repeat("A", 22) + "/frames", "fake-sc2-user", ""},
		{"GET", "/v1/channels/not-a-channel/frames", "fake-sc2-user", ""},
		{"POST", "/v1/pairings", "fake-sc2-user", `{"channel_id":"bad"}`},
		{"POST", "/v1/pairing-windows", "fake-sc2-user", `{"host_id":"` + canaryEventAttr + `"}`},
		{"PATCH", "/v1/pairings/nope", "fake-sc2-user", `{"host_label":"` + canaryPromptish + `"}`},
		{"DELETE", "/v1/pairings/nope", "fake-sc2-user", ""},
		{"POST", "/v1/pairings", "", ""},
		{"POST", "/v1/pairings", "not-a-valid-token", ""},
	} {
		var rd io.Reader
		if probe.body != "" {
			rd = strings.NewReader(probe.body)
		}
		req, err := http.NewRequest(probe.method, srv.URL+probe.path, rd)
		if err != nil {
			t.Fatalf("probe request: %v", err)
		}
		if probe.token != "" {
			req.Header.Set("Authorization", "Bearer "+probe.token)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("probe %s %s: %v", probe.method, probe.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		surfaces = append(surfaces, surface{
			what: fmt.Sprintf("error body for %s %s", probe.method, probe.path), data: body,
		})
	}

	// 6. The log output again, AFTER the error probes — several of those
	//    probes carried a canary in their request, so this catches a relay
	//    that echoes a rejected input into a log line.
	surfaces = append(surfaces, surface{what: "relay log output (post-probe)", data: logs.Bytes()})

	return surfaces
}

// auditPushPayloads enforces the CLOSED §5.3 schema: "A payload containing
// any field not listed here MUST fail the SC-2 APNs audit test."
func auditPushPayloads(t *testing.T, pusher *relay.RecordingPusher) {
	t.Helper()
	pushes := pusher.Pushes()
	if len(pushes) == 0 {
		t.Fatal("no pushes recorded; the §5.3 payload audit has nothing to check")
	}
	var sawAlert, sawSilent bool
	for i, p := range pushes {
		keys(t, fmt.Sprintf("push %d payload", i), p.Payload, "aps", "ch", "sq")
		aps, ok := p.Payload["aps"].(map[string]any)
		if !ok {
			t.Fatalf("push %d has no aps dictionary", i)
		}
		if _, silent := aps["content-available"]; silent {
			sawSilent = true
			keys(t, fmt.Sprintf("push %d aps (wake)", i), aps, "content-available")
			continue
		}
		sawAlert = true
		keys(t, fmt.Sprintf("push %d aps (attention)", i), aps, "alert", "mutable-content", "sound", "thread-id")
		alert, ok := aps["alert"].(map[string]any)
		if !ok {
			t.Fatalf("push %d alert is not a dictionary", i)
		}
		// The relay ships NO display text and NO category: the NSE
		// decrypts over the E2E path and rewrites locally.
		keys(t, fmt.Sprintf("push %d alert", i), alert, "loc-key", "loc-args")
		if alert["loc-key"] != relay.LocKeyGeneric {
			t.Errorf("push %d loc-key = %v; want the fixed %q", i, alert["loc-key"], relay.LocKeyGeneric)
		}
		// loc-args carries AT MOST the host_label and nothing else.
		args, _ := alert["loc-args"].([]any)
		if len(args) != 1 || args[0] != hostLabelControl {
			t.Errorf("push %d loc-args = %v; want exactly [host_label]", i, alert["loc-args"])
		}
	}
	if !sawAlert || !sawSilent {
		t.Errorf("audit saw alert=%v silent=%v; the script should have produced both push shapes", sawAlert, sawSilent)
	}
}

func keys(t *testing.T, what string, m map[string]any, want ...string) {
	t.Helper()
	set := make(map[string]bool, len(want))
	for _, k := range want {
		set[k] = true
	}
	for k := range m {
		if !set[k] {
			t.Errorf("%s: unexpected key %q — the §5.3 schema is CLOSED", what, k)
		}
	}
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------

func record(buf *lockedBuf, env wire.Envelope) {
	blob, err := json.Marshal(env)
	if err != nil {
		return
	}
	_, _ = buf.Write(blob)
	_, _ = buf.Write([]byte("\n"))
}

func registerAPNS(t *testing.T, srv *httptest.Server, deviceID, sub string) {
	t.Helper()
	req, err := http.NewRequest("PUT", srv.URL+"/v1/devices/"+deviceID+"/apns",
		strings.NewReader(`{"token":"00112233445566778899aabbccddeeff","env":"sandbox"}`))
	if err != nil {
		t.Fatalf("apns request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer fake-"+sub)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("apns register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("apns register: %d %s", resp.StatusCode, body)
	}
}

func mailboxDepth(t *testing.T, srv *httptest.Server, channel, sub string) int {
	t.Helper()
	req, err := http.NewRequest("GET", srv.URL+"/v1/channels/"+channel+"/frames", nil)
	if err != nil {
		t.Fatalf("mailbox request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer fake-"+sub)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("mailbox GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0
	}
	var out struct {
		Frames []json.RawMessage `json:"frames"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0
	}
	return len(out.Frames)
}

func waitFor(t *testing.T, limit time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", limit)
}

func drainErr(ch chan error) error {
	select {
	case err := <-ch:
		return err
	default:
		return nil
	}
}
