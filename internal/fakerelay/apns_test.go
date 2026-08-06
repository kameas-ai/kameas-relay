package fakerelay

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func (e *testEnv) registerAPNS(t *testing.T) {
	t.Helper()
	status, body := e.rest("PUT", "/v1/devices/"+deviceA+"/apns", tokAlice, map[string]any{
		"token": "aabbccdd", "env": "sandbox",
	})
	if status != http.StatusNoContent {
		t.Fatalf("APNs registration: status %d body %s", status, body)
	}
}

// waitPushes blocks until the recorder holds n pushes (or fails).
func waitPushes(t *testing.T, e *testEnv, n int) []Push {
	t.Helper()
	deadline := time.Now().Add(readTimeout)
	for time.Now().Before(deadline) {
		if p := e.relay.Recorder().Pushes(); len(p) >= n {
			return p
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("recorder never reached %d pushes (have %d)", n, len(e.relay.Recorder().Pushes()))
	return nil
}

// TestAPNSAttentionGenericAlertClosedSchema: offline device + attention
// frame ⇒ exactly one alert push whose payload is EXACTLY the §5.3
// closed schema — the generic NSE-wake form: loc-key + loc-args +
// mutable-content, and NO title, NO body, NO category anywhere.
func TestAPNSAttentionGenericAlertClosedSchema(t *testing.T) {
	label := "daily driver"
	e := newTestEnv(t, Config{})
	e.createPairing(&label)
	e.registerAPNS(t)

	e.sendMailboxFrames(t, []uint64{9}, PushAttention)
	pushes := waitPushes(t, e, 1)
	if len(pushes) != 1 {
		t.Fatalf("recorded %d pushes, want 1", len(pushes))
	}
	p := pushes[0]
	if p.DeviceID != deviceA || p.Env != "sandbox" || p.Token != "aabbccdd" {
		t.Fatalf("push routing = %+v", p)
	}
	want := map[string]any{
		"aps": map[string]any{
			"alert":           map[string]any{"loc-key": LocKeyGeneric, "loc-args": []any{label}},
			"mutable-content": 1,
			"sound":           "default",
			"thread-id":       channelA,
		},
		"ch": channelA,
		"sq": uint64(9),
	}
	if !reflect.DeepEqual(p.Payload, want) {
		t.Fatalf("payload = %#v\nwant closed schema %#v", p.Payload, want)
	}
	// Belt and braces on the §5.3 prohibitions: no display text, no
	// category, in any spelling.
	aps := p.Payload["aps"].(map[string]any)
	if _, has := aps["category"]; has {
		t.Fatal("payload carries aps.category — the relay must never author a categorized push")
	}
	alert := aps["alert"].(map[string]any)
	for _, banned := range []string{"title", "body"} {
		if _, has := alert[banned]; has {
			t.Fatalf("payload carries alert.%s — the relay ships no display text", banned)
		}
	}
}

// TestAPNSSuppressedWhenDeviceAttached: a push fires only when the
// target device has NO live WSS attachment (§5.2).
func TestAPNSSuppressedWhenDeviceAttached(t *testing.T) {
	label := "lab"
	e := newTestEnv(t, Config{})
	e.createPairing(&label)
	e.registerAPNS(t)

	host := e.dialHost(hostA, tokAlice)
	device := e.dialDevice(channelA, tokAlice)
	readPresence(t, device)

	writeFrame(t, host, frame(t, channelA, 1, PushAttention, nil))
	readMessage(t, device, websocket.MessageBinary) // frame arrives live…
	if got := e.relay.Recorder().Pushes(); len(got) != 0 {
		t.Fatalf("push recorded despite live attachment: %+v", got)
	}
}

// TestAPNSWakeSilent: wake ⇒ silent background push, no alert, no
// sound, no category (§5.2, §5.3).
func TestAPNSWakeSilent(t *testing.T) {
	label := "lab"
	e := newTestEnv(t, Config{})
	e.createPairing(&label)
	e.registerAPNS(t)

	e.sendMailboxFrames(t, []uint64{4}, PushWake)
	p := waitPushes(t, e, 1)[0]
	want := map[string]any{
		"aps": map[string]any{"content-available": 1},
		"ch":  channelA,
		"sq":  uint64(4),
	}
	if !reflect.DeepEqual(p.Payload, want) {
		t.Fatalf("wake payload = %#v, want silent shape %#v", p.Payload, want)
	}
}

// TestAPNSLabelClearedReduction: clearing host_label via PATCH
// (host_label: null) is the §XII condition-5 reduction — loc-args is
// removed ENTIRELY, leaving only the fixed non-operator loc-key.
func TestAPNSLabelClearedReduction(t *testing.T) {
	label := "revealing operator label"
	e := newTestEnv(t, Config{})
	pairingID := e.createPairing(&label)
	e.registerAPNS(t)

	status, body := e.rest("PATCH", "/v1/pairings/"+pairingID, tokAlice, map[string]any{"host_label": nil})
	if status != http.StatusNoContent {
		t.Fatalf("PATCH clear host_label: status %d body %s", status, body)
	}

	e.sendMailboxFrames(t, []uint64{2}, PushAttention)
	p := waitPushes(t, e, 1)[0]
	want := map[string]any{
		"aps": map[string]any{
			"alert":           map[string]any{"loc-key": LocKeyGeneric}, // no loc-args key at all
			"mutable-content": 1,
			"sound":           "default",
			"thread-id":       channelA,
		},
		"ch": channelA,
		"sq": uint64(2),
	}
	if !reflect.DeepEqual(p.Payload, want) {
		t.Fatalf("reduced payload = %#v\nwant %#v", p.Payload, want)
	}
}

// TestAPNSNoneNeverPushes: push_class none ⇒ no push, ever (§5.2) —
// but the frame is still mailboxed (§4.1: buffering is independent of
// push_class).
func TestAPNSNoneNeverPushes(t *testing.T) {
	label := "lab"
	e := newTestEnv(t, Config{})
	e.createPairing(&label)
	e.registerAPNS(t)

	e.sendMailboxFrames(t, []uint64{1, 2, 3}, PushNone)
	if got := e.relay.Recorder().Pushes(); len(got) != 0 {
		t.Fatalf("push recorded for push_class none: %+v", got)
	}
	if got := e.mailboxGet(t, "?after=0"); len(got.Frames) != 3 {
		t.Fatalf("push_class none frames were not mailboxed: %d, want 3", len(got.Frames))
	}
}

// TestAPNSRegistrationRejectsCategories: §5.1 — there is no categories
// field; a stale registration that still sends one is refused.
func TestAPNSRegistrationRejectsCategories(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)
	status, body := e.rest("PUT", "/v1/devices/"+deviceA+"/apns", tokAlice, map[string]any{
		"token": "aabbccdd", "env": "sandbox", "categories": []string{"approval"},
	})
	if status != http.StatusBadRequest || errBody(t, body) != "protocol_violation" {
		t.Fatalf("categories registration: status %d body %s, want 400 protocol_violation", status, body)
	}
}
