package fakerelay

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestScriptedSession is the Task 1.2 verify scenario: host attach →
// device attach → frames both ways → presence flip when heartbeats stop.
// The clock is injected; no wall-clock sleeps.
func TestScriptedSession(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)

	// Host attaches: attach counts as liveness, so the host is online.
	host := e.dialHost(hostA, tokAlice)

	// Device attaches and immediately receives the current presence.
	device := e.dialDevice(channelA, tokAlice)
	p := readPresence(t, device)
	if p.HostID != hostA || !p.Online {
		t.Fatalf("initial presence = %+v, want online for %s", p, hostA)
	}

	// Host→device frame: forwarded verbatim, body untouched.
	h2d := frame(t, channelA, 1, PushNone, []byte("h2d-opaque-bytes"))
	writeFrame(t, host, h2d)
	if got := readMessage(t, device, websocket.MessageBinary); !bytes.Equal(got, h2d) {
		t.Fatalf("device received %q, want the exact wire bytes %q", got, h2d)
	}

	// Device→host frame (push_class MUST be none for device frames).
	d2h := frame(t, channelA, 1, PushNone, []byte("d2h-opaque-bytes"))
	writeFrame(t, device, d2h)
	if got := readMessage(t, host, websocket.MessageBinary); !bytes.Equal(got, d2h) {
		t.Fatalf("host received %q, want the exact wire bytes %q", got, d2h)
	}

	// Explicit heartbeat at t0+10s resets the silence window (§6: 15 s
	// cadence). Advancing first makes the reset observable via last_seen,
	// so the test can deterministically wait for the relay to process it.
	e.clock.Advance(10 * time.Second)
	beat := e.clock.Now()
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	if err := host.Write(ctx, websocket.MessageText, []byte(`{"type":"heartbeat"}`)); err != nil {
		t.Fatalf("heartbeat write: %v", err)
	}
	waitLastSeen(t, e, hostA, beat)

	// Heartbeats stop. 30 s of silence flips the host offline (§6) and
	// the flip is published to the attached device. (The flip lands at
	// beat+30s, proving the heartbeat extended the window.)
	e.clock.Advance(31 * time.Second)
	p = readPresence(t, device)
	if p.Online {
		t.Fatalf("presence after 31s silence = online, want offline")
	}
	if online, _ := e.relay.HostOnline(hostA); online {
		t.Fatal("relay control surface still reports host online")
	}

	// Host liveness resumes ⇒ presence flips back online (§6 reconnect).
	ctx2, cancel2 := context.WithTimeout(context.Background(), readTimeout)
	defer cancel2()
	if err := host.Write(ctx2, websocket.MessageText, []byte(`{"type":"heartbeat"}`)); err != nil {
		t.Fatalf("heartbeat write: %v", err)
	}
	p = readPresence(t, device)
	if !p.Online {
		t.Fatal("presence after heartbeat resume = offline, want online")
	}
}

// waitLastSeen polls the control surface with 1 ms naps (bounded well
// under the no->100ms-sleep rule per check) until the relay has recorded
// liveness at or after want.
func waitLastSeen(t *testing.T, e *testEnv, hostID string, want time.Time) {
	t.Helper()
	deadline := time.Now().Add(readTimeout)
	for time.Now().Before(deadline) {
		if _, last := e.relay.HostOnline(hostID); !last.Before(want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("relay never recorded liveness at %v for %s", want, hostID)
}

// TestDeviceSetPushClassRejected pins the §5.2 rule: the relay MUST
// reject any device-originated frame with push_class != "none" and close
// with protocol_violation (4400).
func TestDeviceSetPushClassRejected(t *testing.T) {
	for _, pc := range []string{PushWake, PushAttention} {
		t.Run(pc, func(t *testing.T) {
			e := newTestEnv(t, Config{})
			e.createPairing(nil)
			device := e.dialDevice(channelA, tokAlice)
			readPresence(t, device) // drain initial presence
			writeFrame(t, device, frame(t, channelA, 1, pc, nil))
			expectClose(t, device, 4400)
		})
	}
}

// TestHostFrameForwardedToAllAttachedDevices covers multi-attach fan-out
// within the §7.1 concurrent-attachment limit.
func TestHostFrameForwardedToAllAttachedDevices(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)
	host := e.dialHost(hostA, tokAlice)
	d1 := e.dialDevice(channelA, tokAlice)
	d2 := e.dialDevice(channelA, tokAlice)
	readPresence(t, d1)
	readPresence(t, d2)

	msg := frame(t, channelA, 7, PushNone, nil)
	writeFrame(t, host, msg)
	for _, d := range []*websocket.Conn{d1, d2} {
		if got := readMessage(t, d, websocket.MessageBinary); !bytes.Equal(got, msg) {
			t.Fatal("attached device did not receive the forwarded frame verbatim")
		}
	}
}

// TestDeviceFrameOnForeignChannelClosed: a device may only send on the
// channel its attachment is bound to (channel-level authZ, §2).
func TestDeviceFrameOnForeignChannelClosed(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)
	device := e.dialDevice(channelA, tokAlice)
	readPresence(t, device)
	writeFrame(t, device, frame(t, tid(0x99), 1, PushNone, nil))
	expectClose(t, device, 4403)
}
