package fakehost_test

// Task 1.3 verify line: fakehost + fakerelay in-process, driven by
// remotectl-equivalent client code (devclient) — watch renders the live
// snapshot/event stream, approve round-trips a scripted approval, and a
// reconnect exercises the session-start seq regime + snapshot.full
// reconcile. Wall-clock discipline: scripted timings are tens of
// milliseconds and every wait is an event-driven Recv under a deadline;
// no sleep exceeds 200ms.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kameas-ai/kameas-relay/devclient"
	"github.com/kameas-ai/kameas-relay/fakehost"
	"github.com/kameas-ai/kameas-relay/internal/fakerelay"
	"github.com/kameas-ai/kameas-relay/wire"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type harness struct {
	origin   string
	relay    *fakerelay.Relay
	host     *fakehost.Host
	out      *lockedBuf
	qr       string
	windowID string
	hostErr  chan error
}

func startHarness(t *testing.T, ctx context.Context, mutate func(*fakehost.Config)) *harness {
	t.Helper()
	return startHarnessRelay(t, ctx, fakerelay.Config{}, mutate)
}

func startHarnessRelay(t *testing.T, ctx context.Context, relayCfg fakerelay.Config, mutate func(*fakehost.Config)) *harness {
	t.Helper()
	relay := fakerelay.New(relayCfg)
	srv := httptest.NewServer(relay.Handler())
	t.Cleanup(srv.Close)

	out := &lockedBuf{}
	cfg := fakehost.Config{
		RelayOrigin:     srv.URL,
		Sub:             "itest-user",
		HostName:        "Itest Host",
		AutoConfirm:     true,
		ApprovalAfter:   80 * time.Millisecond,
		ApprovalTimeout: 30 * time.Second,
		EventInterval:   40 * time.Millisecond,
		Out:             out,
		// No t.Logf here: host goroutines outlive the test body by a
		// moment (ctx cancellation is asynchronous) and logging to a
		// finished testing.T panics.
	}
	if mutate != nil {
		mutate(&cfg)
	}
	host, err := fakehost.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{origin: srv.URL, relay: relay, host: host, out: out, hostErr: make(chan error, 1)}
	// Attach FIRST: the §2.2 account binding is created only by a
	// successful /v1/host attach, and opening a pairing window requires
	// the binding to exist.
	go func() { h.hostErr <- host.Run(ctx) }()
	if err := host.WaitAttached(ctx); err != nil {
		t.Fatalf("host never attached to the relay: %v", err)
	}
	qr, windowID, err := host.OpenPairingWindow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h.qr, h.windowID = qr, windowID
	// The relay's presence view converges with the attach (belt and
	// braces for tests that read it).
	deadline := time.Now().Add(5 * time.Second)
	for {
		if online, _ := relay.HostOnline(host.HostIDWire()); online {
			return h
		}
		if time.Now().After(deadline) {
			t.Fatal("relay presence never went online")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func pairDevice(t *testing.T, ctx context.Context, h *harness) *devclient.State {
	t.Helper()
	// The QR alone suffices: the pairing attach is addressed by the QR's
	// host_id (§3.2); window_id never appears on a device path.
	st, err := devclient.Pair(ctx, devclient.PairConfig{
		QRURI:       h.qr,
		Sub:         "itest-user",
		DeviceName:  "Itest iPhone",
		DeviceModel: "iPhone15,2",
	})
	if err != nil {
		t.Fatalf("pairing: %v", err)
	}
	return st
}

// waitDeviceAttached polls the host's §6.1 view of the device.
func waitDeviceAttached(t *testing.T, h *harness, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.host.DeviceAttached() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("host never saw device attached=%v via §6.1 presence", want)
}

func recvUntil(t *testing.T, ctx context.Context, sess *devclient.Session, want func(wire.Envelope) bool) wire.Envelope {
	t.Helper()
	for {
		env, err := sess.Recv(ctx)
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		if want(env) {
			return env
		}
	}
}

func TestEndToEndWatchAndApprove(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h := startHarness(t, ctx, nil)
	st := pairDevice(t, ctx, h)
	if err := st.Save(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	sess, err := devclient.Connect(ctx, st)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sess.Close()

	// The host's first post-handshake envelope MUST be snapshot.full.
	env, err := sess.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if env.Kind != "snapshot.full" {
		t.Fatalf("first envelope: got %s, want snapshot.full", env.Kind)
	}
	var snap wire.SnapshotFull
	if err := env.DecodeBody(&snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Workbenches) == 0 || !snap.ApprovalsBrokered {
		t.Fatalf("snapshot content: %+v", snap)
	}

	// Live event stream renders.
	evEnv := recvUntil(t, ctx, sess, func(e wire.Envelope) bool { return e.Kind == "event" })
	var ev wire.Event
	if err := evEnv.DecodeBody(&ev); err != nil {
		t.Fatal(err)
	}
	if ev.Source != "workbench" {
		t.Fatalf("event source: %s", ev.Source)
	}

	// The scripted approval arrives; approve it over the two-valued
	// remote surface.
	reqEnv := recvUntil(t, ctx, sess, func(e wire.Envelope) bool { return e.Kind == "approval.request" })
	var req wire.ApprovalRequest
	if err := reqEnv.DecodeBody(&req); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(req.ApprovalID, "rid-") || len(req.ApprovalID) != 4+24 {
		t.Fatalf("approval_id shape: %q", req.ApprovalID)
	}
	rpcID, err := sess.SendRPC(ctx, "approval.decide", map[string]string{
		"approval_id": req.ApprovalID, "decision": "allow",
	})
	if err != nil {
		t.Fatal(err)
	}

	var gotApplied, gotResolved bool
	for !gotApplied || !gotResolved {
		env, err := sess.Recv(ctx)
		if err != nil {
			t.Fatal(err)
		}
		switch env.Kind {
		case "rpc.response":
			if env.ID != rpcID {
				continue
			}
			var res struct {
				Status   string `json:"status"`
				Decision string `json:"decision"`
				Source   string `json:"source"`
			}
			if err := env.DecodeBody(&res); err != nil {
				t.Fatal(err)
			}
			// Remote allow maps to allow_once, never allow_always.
			if res.Status != "applied" || res.Decision != "allow_once" || res.Source != "remote" {
				t.Fatalf("decide result: %+v", res)
			}
			gotApplied = true
		case "approval.resolved":
			var res wire.ApprovalResolved
			if err := env.DecodeBody(&res); err != nil {
				t.Fatal(err)
			}
			if res.ApprovalID != req.ApprovalID {
				continue
			}
			if res.Decision != "allow_once" || res.Source != "remote" {
				t.Fatalf("resolution: %+v", res)
			}
			gotResolved = true
		}
	}

	// Ledger obligations (approval-events.md §6): remote.command before
	// the reply, approval.granted with device_id, summary NEVER written.
	ledger := h.out.String()
	if !strings.Contains(ledger, `"kind":"remote.command"`) || !strings.Contains(ledger, `"method":"approval.decide"`) {
		t.Errorf("ledger missing remote.command: %s", ledger)
	}
	if !strings.Contains(ledger, `"kind":"approval.granted"`) || !strings.Contains(ledger, `"device_id":"`+st.DeviceID+`"`) {
		t.Errorf("ledger missing approval.granted with device identity: %s", ledger)
	}
	if strings.Contains(ledger, "run make check") {
		t.Errorf("ledger contains the approval summary — content must never be ledgered: %s", ledger)
	}

	// invalid decision values are refused (allow_always must not be
	// accepted from a device).
	badID, err := sess.SendRPC(ctx, "approval.decide", map[string]string{
		"approval_id": req.ApprovalID, "decision": "allow_always",
	})
	if err != nil {
		t.Fatal(err)
	}
	env = recvUntil(t, ctx, sess, func(e wire.Envelope) bool { return e.Kind == "rpc.response" && e.ID == badID })
	var eb wire.RPCErrorBody
	if err := env.DecodeBody(&eb); err != nil || eb.Error.Code != "invalid_params" {
		t.Fatalf("allow_always must fail with invalid_params, got %s / %v", env.Body, err)
	}

	// snapshot.request answers with a snapshot.full carrying the id.
	snapID, err := sess.SendRPC(ctx, "snapshot.request", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	env = recvUntil(t, ctx, sess, func(e wire.Envelope) bool { return e.Kind == "snapshot.full" && e.ID == snapID })
	if env.ID != snapID {
		t.Fatalf("snapshot.request response id: %s", env.ID)
	}

	// Unknown methods are rejected: absent = forbidden.
	unkID, err := sess.SendRPC(ctx, "workbench.open", map[string]string{"profile_id": "p"})
	if err != nil {
		t.Fatal(err)
	}
	env = recvUntil(t, ctx, sess, func(e wire.Envelope) bool { return e.Kind == "rpc.response" && e.ID == unkID })
	if err := env.DecodeBody(&eb); err != nil || eb.Error.Code != "unknown_method" {
		t.Fatalf("unknown method must fail with unknown_method, got %s", env.Body)
	}

	// Transcript pages arrive with the request id and ascending pages.
	trID, err := sess.SendRPC(ctx, "task.transcript", map[string]any{"task_id": "task-1"})
	if err != nil {
		t.Fatal(err)
	}
	var pages []wire.TranscriptPage
	for len(pages) < 2 {
		env := recvUntil(t, ctx, sess, func(e wire.Envelope) bool { return e.Kind == "transcript.page" })
		var p wire.TranscriptPage
		if err := env.DecodeBody(&p); err != nil {
			t.Fatal(err)
		}
		if p.RequestID != trID {
			t.Fatalf("transcript request_id: %s want %s", p.RequestID, trID)
		}
		pages = append(pages, p)
	}
	if pages[0].Page != 1 || pages[1].Page != 2 || pages[0].HasMore == false || pages[1].HasMore == true {
		t.Fatalf("transcript pagination: %+v", pages)
	}
}

// mailboxCount polls the relay mailbox over REST (device credentials)
// until it holds want frames past `after`, returning the observed seqs.
// Doubling as an integration check that reads are non-destructive.
func mailboxCount(t *testing.T, ctx context.Context, h *harness, st *devclient.State, after uint64, want int) []uint64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			h.origin+"/v1/channels/"+st.ChannelID+"/frames?after="+strconv.FormatUint(after, 10), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer fake-"+st.Sub)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			Frames []struct {
				Seq uint64 `json:"seq"`
			} `json:"frames"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Frames) >= want {
			seqs := make([]uint64, len(out.Frames))
			for i, f := range out.Frames {
				seqs[i] = f.Seq
			}
			return seqs
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("mailbox never reached %d frames past seq %d", want, after)
	return nil
}

// TestMailboxOfflineDeliveryAndDrain is the end-to-end class-M path the
// pre-ruling stack could not exercise: the host consumes the relay's
// §6.1 device-presence signal, selects the CLASS-M construction while
// the device is detached, the relay mailboxes those frames (regardless
// of push_class), and the reconnecting device drains ?after=<seq>,
// decrypts through the real e2ekit mailbox path, observes the
// eviction-induced forward seq gap, and gets the mandated snapshot.full
// reconcile.
func TestMailboxOfflineDeliveryAndDrain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h := startHarnessRelay(t, ctx,
		fakerelay.Config{MailboxMaxFrames: 2}, // force eviction ⇒ a drain gap
		func(c *fakehost.Config) {
			c.ApprovalAfter = time.Hour // quiet stream: the test drives events explicitly
			c.EventInterval = time.Hour
		})
	st := pairDevice(t, ctx, h)
	if err := st.Save(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	// Session 1 establishes, host sees the device attached via §6.1.
	sess1, err := devclient.Connect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if env, err := sess1.Recv(ctx); err != nil || env.Kind != "snapshot.full" {
		t.Fatalf("session 1 first envelope: %v %v", env.Kind, err)
	}
	waitDeviceAttached(t, h, true)
	seenBefore := st.H2DLastSeen
	sess1.Close()

	// Detach propagates to the host (§6.1) — from here the host's
	// emissions are class M by construction choice.
	waitDeviceAttached(t, h, false)
	for i := 0; i < 4; i++ {
		h.host.EmitEvent(fakehost.ScriptEvent{Source: "task", Kind: "completed", TaskID: "task-1",
			Attrs: map[string]any{"n": i}})
	}
	// Cap 2 evicted the first two: the mailbox holds the last two seqs.
	seqs := mailboxCount(t, ctx, h, st, seenBefore, 2)
	if len(seqs) != 2 || seqs[0] != seenBefore+3 || seqs[1] != seenBefore+4 {
		t.Fatalf("mailbox seqs = %v, want [%d %d] (oldest evicted)", seqs, seenBefore+3, seenBefore+4)
	}

	// Reconnect: drain decrypts the surviving class-M frames via the
	// real e2ekit path; the eviction gap mandates the reconcile.
	sess2, err := devclient.Connect(ctx, st)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer sess2.Close()
	if len(sess2.DrainedEnvelopes) != 2 {
		t.Fatalf("drained %d envelopes, want 2 decrypted class-M events", len(sess2.DrainedEnvelopes))
	}
	for _, env := range sess2.DrainedEnvelopes {
		if env.Kind != "event" {
			t.Fatalf("drained envelope kind %s, want event", env.Kind)
		}
		var ev wire.Event
		if err := env.DecodeBody(&ev); err != nil || ev.Source != "task" || ev.Kind != "completed" {
			t.Fatalf("drained event decode: %+v %v", ev, err)
		}
	}
	if !sess2.ReconcileExpected {
		t.Error("drain saw an eviction gap: ReconcileExpected must be set")
	}
	if st.H2DLastSeen <= seenBefore {
		t.Errorf("h2d high-water mark did not advance: %d -> %d", seenBefore, st.H2DLastSeen)
	}
	env, err := sess2.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if env.Kind != "snapshot.full" {
		t.Fatalf("reconnect first envelope: got %s, want snapshot.full (the mandated reconcile)", env.Kind)
	}
	// And the live stream continues class L afterwards.
	h.host.EmitEvent(fakehost.ScriptEvent{Source: "workbench", Kind: "resumed", WorkbenchID: "wb-042"})
	recvUntil(t, ctx, sess2, func(e wire.Envelope) bool { return e.Kind == "event" })
}

// TestPresenceRaceClassLInMailboxRecovery pins the e2e-envelope §1.2
// recovery rule end-to-end: a class-L frame that lost the presence race
// lands in the mailbox, cannot authenticate there, and the device
// DISCARDS it, ABANDONS the rest of the drain (a later class-M item is
// deliberately left unconsumed — skip-and-continue would let a relay
// steer acceptance), and recovers through the session-start forward
// jump + snapshot.full reconcile.
func TestPresenceRaceClassLInMailboxRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h := startHarness(t, ctx, func(c *fakehost.Config) {
		c.ApprovalAfter = time.Hour
		c.EventInterval = time.Hour
	})
	st := pairDevice(t, ctx, h)
	if err := st.Save(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	sess1, err := devclient.Connect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if env, err := sess1.Recv(ctx); err != nil || env.Kind != "snapshot.full" {
		t.Fatalf("session 1 first envelope: %v %v", env.Kind, err)
	}
	waitDeviceAttached(t, h, true)
	seenBefore := st.H2DLastSeen
	sess1.Close()
	waitDeviceAttached(t, h, false)

	// The race, made deterministic: one class-L frame emitted against
	// the dead session (test instrument), then one legitimate class-M.
	if !h.host.EmitEventClassL(fakehost.ScriptEvent{Source: "task", Kind: "errored", TaskID: "task-1"}) {
		t.Fatal("EmitEventClassL found no session stream")
	}
	h.host.EmitEvent(fakehost.ScriptEvent{Source: "task", Kind: "completed", TaskID: "task-1"})
	mailboxCount(t, ctx, h, st, seenBefore, 2)

	sess2, err := devclient.Connect(ctx, st)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer sess2.Close()
	// The class-L item is first in the drain: discarded, drain
	// abandoned — NOTHING drained, not even the decryptable class-M
	// item behind it.
	if len(sess2.DrainedEnvelopes) != 0 {
		t.Fatalf("drained %d envelopes after an unauthenticatable item, want 0 (abandon, not skip)", len(sess2.DrainedEnvelopes))
	}
	if !sess2.ReconcileExpected {
		t.Error("abandoned drain must set ReconcileExpected")
	}
	// last_seen stayed put, so the host's sess.confirm presented a
	// forward jump — and the reconnect still advanced the mark.
	if st.H2DLastSeen <= seenBefore {
		t.Errorf("h2d high-water mark did not advance across the reconnect: %d -> %d", seenBefore, st.H2DLastSeen)
	}
	env, err := sess2.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if env.Kind != "snapshot.full" {
		t.Fatalf("reconnect first envelope: got %s, want snapshot.full", env.Kind)
	}
}

func TestApprovalTimeoutIsFailClosedDeny(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h := startHarness(t, ctx, func(c *fakehost.Config) {
		c.ApprovalAfter = 50 * time.Millisecond
		c.ApprovalTimeout = 150 * time.Millisecond
	})
	st := pairDevice(t, ctx, h)

	sess, err := devclient.Connect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	reqEnv := recvUntil(t, ctx, sess, func(e wire.Envelope) bool { return e.Kind == "approval.request" })
	var req wire.ApprovalRequest
	if err := reqEnv.DecodeBody(&req); err != nil {
		t.Fatal(err)
	}
	// Decide nothing: absence of consent is denial.
	resEnv := recvUntil(t, ctx, sess, func(e wire.Envelope) bool { return e.Kind == "approval.resolved" })
	var res wire.ApprovalResolved
	if err := resEnv.DecodeBody(&res); err != nil {
		t.Fatal(err)
	}
	if res.ApprovalID != req.ApprovalID || res.Decision != "deny" || res.Source != "timeout" {
		t.Fatalf("timeout resolution: %+v", res)
	}
	// A late decision gets already_resolved as a RESULT, not an error.
	lateID, err := sess.SendRPC(ctx, "approval.decide", map[string]string{
		"approval_id": req.ApprovalID, "decision": "allow",
	})
	if err != nil {
		t.Fatal(err)
	}
	env := recvUntil(t, ctx, sess, func(e wire.Envelope) bool { return e.Kind == "rpc.response" && e.ID == lateID })
	var late struct {
		Status   string `json:"status"`
		Decision string `json:"decision"`
		Source   string `json:"source"`
	}
	if err := env.DecodeBody(&late); err != nil {
		t.Fatal(err)
	}
	if late.Status != "already_resolved" || late.Decision != "deny" || late.Source != "timeout" {
		t.Fatalf("late decision: %+v", late)
	}
	if !strings.Contains(h.out.String(), `"kind":"approval.denied"`) {
		t.Errorf("ledger missing approval.denied: %s", h.out.String())
	}
}

func TestPairingDeclinedByOperator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h := startHarness(t, ctx, func(c *fakehost.Config) {
		c.AutoConfirm = false
		c.ConfirmIn = strings.NewReader("n\n")
	})
	_, err := devclient.Pair(ctx, devclient.PairConfig{
		QRURI:       h.qr,
		Sub:         "itest-user",
		DeviceName:  "Declined iPhone",
		DeviceModel: "iPhone15,2",
	})
	if err == nil {
		t.Fatal("pairing succeeded despite operator decline")
	}
	if !errors.Is(err, devclient.ErrPairDenied) || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("expected ErrPairDenied(declined), got: %v", err)
	}
}

func TestPairingWrongAccountRejectedDeviceSide(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h := startHarness(t, ctx, nil)
	// The device recomputes account_bind from its own sub and refuses
	// before sending anything.
	_, err := devclient.Pair(ctx, devclient.PairConfig{
		QRURI:       h.qr,
		Sub:         "someone-else",
		DeviceName:  "Wrong iPhone",
		DeviceModel: "iPhone15,2",
	})
	if err == nil || !strings.Contains(err.Error(), "account_bind") {
		t.Fatalf("expected account_bind mismatch, got: %v", err)
	}
}
