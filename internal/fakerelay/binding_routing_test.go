package fakerelay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// ---------------------------------------------------------------------
// §2.2 — account binding: immutable, host-attach-only, reaped
// ---------------------------------------------------------------------

// TestAccountBindingNoRebind: the binding is immutable — a differing sub
// is refused with forbidden, never rebound, and idle time alone does not
// reap a binding that still has pairings.
func TestAccountBindingNoRebind(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil) // binds hostA -> alice, registers a pairing

	_, resp, err := e.dialWSRaw("/v1/host?host_id="+hostA, tokBob)
	if err == nil {
		t.Fatal("cross-account host attach succeeded")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-account attach: %+v, want 403 forbidden", resp)
	}

	// 31 days idle, but a pairing still exists ⇒ NOT reaped, still 403.
	e.clock.Advance(31 * 24 * time.Hour)
	_, resp, err = e.dialWSRaw("/v1/host?host_id="+hostA, tokBob)
	if err == nil {
		t.Fatal("cross-account host attach succeeded after idle with live pairing")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("idle-with-pairing attach: %+v, want 403 (binding not reaped)", resp)
	}
}

// TestAccountBindingReap: zero pairings + 30 days idle ⇒ the binding is
// reaped and the host_id is bindable again (a regenerated host_id must
// not squat forever).
func TestAccountBindingReap(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.bindHost() // binds hostA -> alice; no pairings exist

	// Before the horizon: bob is still refused.
	e.clock.Advance(29 * 24 * time.Hour)
	if _, resp, err := e.dialWSRaw("/v1/host?host_id="+hostA, tokBob); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("pre-horizon attach: err=%v resp=%+v, want 403", err, resp)
	}

	// Past the horizon with zero pairings: reaped ⇒ bob binds.
	e.clock.Advance(2 * 24 * time.Hour)
	c := e.dialWS("/v1/host?host_id="+hostA, tokBob)
	_ = c.CloseNow()
	e.relay.mu.Lock()
	b, ok := e.relay.bindings[hostA]
	e.relay.mu.Unlock()
	if !ok || b.sub != "bob" {
		t.Fatalf("post-reap binding = %+v ok=%v, want a fresh bob binding", b, ok)
	}
}

// ---------------------------------------------------------------------
// §4.1 — routing when the peer is absent (the three-way split)
// ---------------------------------------------------------------------

// readControlErr reads TEXT control messages until a §4.1 routing error
// arrives, skipping presence traffic (both kinds share the TEXT channel).
func readControlErr(t *testing.T, c *websocket.Conn) (code, channel string) {
	t.Helper()
	deadline := time.Now().Add(readTimeout)
	for time.Now().Before(deadline) {
		var m struct {
			Error   string `json:"error"`
			Channel string `json:"channel"`
		}
		if err := json.Unmarshal(readMessage(t, c, websocket.MessageText), &m); err == nil && m.Error != "" {
			return m.Error, m.Channel
		}
	}
	t.Fatal("no routing-error control message arrived")
	return "", ""
}

// TestDeviceFrameHostDetachedPeerUnavailable: device→host with no host
// attached ⇒ frame dropped + peer_unavailable TEXT control message; the
// connection stays up and works once the host returns. No device→host
// mailbox, ever.
func TestDeviceFrameHostDetachedPeerUnavailable(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)
	e.waitHostConns(0) // binding attach torn down: host is detached

	device := e.dialDevice(channelA, tokAlice)
	readPresence(t, device) // initial host presence

	writeFrame(t, device, frame(t, channelA, 1, PushNone, nil))
	code, ch := readControlErr(t, device)
	if code != "peer_unavailable" || ch != channelA {
		t.Fatalf("control = %s/%s, want peer_unavailable on %s", code, ch, channelA)
	}

	// The connection survived; with the host back, frames flow.
	host := e.dialHost(hostA, tokAlice)
	sent := frame(t, channelA, 2, PushNone, []byte("after-reattach"))
	writeFrame(t, device, sent)
	if got := readMessage(t, host, websocket.MessageBinary); !bytes.Equal(got, sent) {
		t.Fatal("frame did not flow after host reattach — peer_unavailable must not wedge the connection")
	}
}

// TestHostFrameThreeWaySplit exercises all three §4.1 host→device arms
// on one relay: live forward, mailbox-on-detach (regardless of
// push_class), drop+not_found for an unregistered channel.
func TestHostFrameThreeWaySplit(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)
	host := e.dialHost(hostA, tokAlice)

	// Arm 1: device attached ⇒ forwarded live, nothing mailboxed.
	device := e.dialDevice(channelA, tokAlice)
	readPresence(t, device)
	live := frame(t, channelA, 1, PushNone, nil)
	writeFrame(t, host, live)
	if got := readMessage(t, device, websocket.MessageBinary); !bytes.Equal(got, live) {
		t.Fatal("arm 1: live frame not forwarded verbatim")
	}

	// Arm 2: device detached ⇒ mailboxed REGARDLESS of push_class —
	// plain snapshot/rpc traffic (push_class none) must reach a
	// reconnecting device too.
	_ = device.CloseNow()
	waitDevConns(t, e, channelA, 0)
	writeFrame(t, host, frame(t, channelA, 2, PushNone, bytes.Repeat([]byte{0xAA}, 30)))
	waitMailboxSeq(t, e, 2)
	if got := e.mailboxGet(t, "?after=0"); len(got.Frames) != 1 || got.Frames[0].Seq != 2 || got.Frames[0].PushClass != PushNone {
		t.Fatalf("arm 2: %+v, want seq 2 push_class none mailboxed", got)
	}

	// Arm 3: unregistered channel ⇒ dropped + not_found TEXT to the
	// host; nothing mailboxed anywhere; connection stays up.
	ghost := tid(0x5A)
	writeFrame(t, host, frame(t, ghost, 3, PushNone, nil))
	code, ch := readControlErr(t, host)
	if code != "not_found" || ch != ghost {
		t.Fatalf("arm 3: control = %s/%s, want not_found on %s", code, ch, ghost)
	}
	e.relay.mu.Lock()
	_, ghostMbx := e.relay.mailboxes[ghost]
	e.relay.mu.Unlock()
	if ghostMbx {
		t.Fatal("arm 3: a mailbox was created for an unregistered channel")
	}
	// Still routable after the not_found: arm-2 delivery continues.
	writeFrame(t, host, frame(t, channelA, 4, PushNone, nil))
	waitMailboxSeq(t, e, 4)
}

func waitDevConns(t *testing.T, e *testEnv, channel string, n int) {
	t.Helper()
	deadline := time.Now().Add(readTimeout)
	for time.Now().Before(deadline) {
		e.relay.mu.Lock()
		got := len(e.relay.devConns[channel])
		e.relay.mu.Unlock()
		if got == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("channel %s never reached %d device attachments", channel, n)
}

// ---------------------------------------------------------------------
// §6.1 — device presence to the host
// ---------------------------------------------------------------------

func readDevPresence(t *testing.T, c *websocket.Conn) devPresenceMsg {
	t.Helper()
	deadline := time.Now().Add(readTimeout)
	for time.Now().Before(deadline) {
		var p devPresenceMsg
		if err := json.Unmarshal(readMessage(t, c, websocket.MessageText), &p); err == nil && p.Presence == "device" {
			return p
		}
	}
	t.Fatal("no device-presence control message arrived")
	return devPresenceMsg{}
}

// TestDevicePresenceToHost: the relay publishes device attach/detach on
// the host's TEXT channel — the signal that lets the host choose class L
// vs class M — including the current state once on host attach.
func TestDevicePresenceToHost(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)

	// Initial state on host attach: the channel exists, no device yet.
	host := e.dialHost(hostA, tokAlice)
	p := readDevPresence(t, host)
	if p.Channel != channelA || p.Attached {
		t.Fatalf("initial device presence = %+v, want detached on %s", p, channelA)
	}

	// Attach transition.
	device := e.dialDevice(channelA, tokAlice)
	readPresence(t, device)
	p = readDevPresence(t, host)
	if p.Channel != channelA || !p.Attached || p.LastSeen == "" {
		t.Fatalf("attach transition = %+v, want attached with last_seen", p)
	}

	// Detach transition.
	_ = device.CloseNow()
	p = readDevPresence(t, host)
	if p.Channel != channelA || p.Attached {
		t.Fatalf("detach transition = %+v, want detached", p)
	}
}
