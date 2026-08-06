package fakerelay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type windowResp struct {
	WindowID           string `json:"window_id"`
	ProvisionalChannel string `json:"provisional_channel"`
	ExpiresAt          string `json:"expires_at"`
}

// openWindow binds hostA (windows require an existing §2.2 binding) and
// opens a pairing window.
func (e *testEnv) openWindow(t *testing.T) windowResp {
	t.Helper()
	e.bindHost()
	status, body := e.rest("POST", "/v1/pairing-windows", tokAlice, map[string]string{"host_id": hostA})
	if status != http.StatusCreated {
		t.Fatalf("open window: status %d body %s", status, body)
	}
	var out windowResp
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("window decode: %v", err)
	}
	return out
}

// pairingAttachPath is the §3.2 attach form: addressed by host_id (from
// the QR), never by window_id.
func pairingAttachPath(hostWire string) string { return "/v1/device?host=" + hostWire }

// TestProvisionalChannelSameOnBothSides pins the normative ADR-B2 rule
// (§3.1/§3.2): the relay conveys the SAME provisional channel to the
// host (window response) and the device (first pairing-attach message).
func TestProvisionalChannelSameOnBothSides(t *testing.T) {
	e := newTestEnv(t, Config{})
	win := e.openWindow(t)
	if !validChannelID(win.ProvisionalChannel) {
		t.Fatalf("provisional_channel %q is not 22-char canonical base64url over 16 bytes", win.ProvisionalChannel)
	}

	device := e.dialWS(pairingAttachPath(hostA), tokAlice)
	var first struct {
		ProvisionalChannel string `json:"provisional_channel"`
	}
	if err := json.Unmarshal(readMessage(t, device, websocket.MessageText), &first); err != nil {
		t.Fatalf("first server message decode: %v", err)
	}
	if first.ProvisionalChannel != win.ProvisionalChannel {
		t.Fatalf("device saw provisional channel %q, host saw %q — MUST be identical (ADR B2)",
			first.ProvisionalChannel, win.ProvisionalChannel)
	}

	// Pairing frames flow both ways on the provisional channel.
	host := e.dialHost(hostA, tokAlice)
	pairInit := frame(t, win.ProvisionalChannel, 0, PushNone, []byte(`{"v":1,"kind":"pair.init","body":{}}`))
	writeFrame(t, device, pairInit)
	if got := readMessage(t, host, websocket.MessageBinary); !bytes.Equal(got, pairInit) {
		t.Fatal("host did not receive the pairing frame verbatim")
	}
	pairAccept := frame(t, win.ProvisionalChannel, 0, PushNone, []byte(`{"v":1,"kind":"pair.accept","body":{}}`))
	writeFrame(t, host, pairAccept)
	if got := readMessage(t, device, websocket.MessageBinary); !bytes.Equal(got, pairAccept) {
		t.Fatal("device did not receive the pairing frame verbatim")
	}
}

// pairingRefusal performs one pairing attach expected to be refused and
// returns (HTTP status, raw response body) for byte-identity checks.
func pairingRefusal(t *testing.T, e *testEnv, hostWire, token string) (int, string) {
	t.Helper()
	_, resp, err := e.dialWSRaw(pairingAttachPath(hostWire), token)
	if err == nil {
		t.Fatal("pairing attach unexpectedly succeeded")
	}
	if resp == nil {
		t.Fatal("no HTTP response for refused pairing attach")
	}
	body := readAll(t, resp)
	return resp.StatusCode, body
}

// TestPairingAttachOracleCollapse pins §3.2's two-outcome rule: EVERY
// refusal on the pairing-attach path — unknown host_id, unbound
// host_id, account mismatch, no open window, expired window, attach
// rate excess, even a malformed host id — is one byte-identical
// window_closed response. Anything distinguishable is a
// window-existence oracle.
func TestPairingAttachOracleCollapse(t *testing.T) {
	e := newTestEnv(t, Config{Limits: Limits{PairingAttachesPerWindow: 1}})

	// Cause 1: completely unknown host_id (nothing bound, no window).
	unknownStatus, unknownBody := pairingRefusal(t, e, tid(0x66), tokAlice)

	// Cause 2: bound host, NO window open.
	e.bindHost()
	noWinStatus, noWinBody := pairingRefusal(t, e, hostA, tokAlice)

	// Cause 3: window open, account mismatch.
	e.openWindow(t)
	mismatchStatus, mismatchBody := pairingRefusal(t, e, hostA, tokBob)

	// Cause 4: attach-rate excess (limit 1; first attach consumes it).
	c := e.dialWS(pairingAttachPath(hostA), tokAlice)
	readMessage(t, c, websocket.MessageText)
	rateStatus, rateBody := pairingRefusal(t, e, hostA, tokAlice)

	// Cause 5: expired window.
	e.clock.Advance(5*time.Minute + time.Second)
	expiredStatus, expiredBody := pairingRefusal(t, e, hostA, tokAlice)

	// Cause 6: malformed host id.
	malStatus, malBody := pairingRefusal(t, e, "not-a-channel-id", tokAlice)

	wantStatus, wantBody := unknownStatus, unknownBody
	if wantStatus != http.StatusGone {
		t.Fatalf("pairing refusal status = %d, want 410 window_closed", wantStatus)
	}
	for name, got := range map[string][2]any{
		"no-window":        {noWinStatus, noWinBody},
		"account-mismatch": {mismatchStatus, mismatchBody},
		"rate-excess":      {rateStatus, rateBody},
		"expired-window":   {expiredStatus, expiredBody},
		"malformed-host":   {malStatus, malBody},
	} {
		if got[0].(int) != wantStatus || got[1].(string) != wantBody {
			t.Errorf("%s refusal differs from unknown-host refusal: %d %q vs %d %q — oracle reopened",
				name, got[0], got[1], wantStatus, wantBody)
		}
	}
}

// TestPairingAttachDoesNotBind: §3.2 — a device attach MUST NOT create
// or modify an account binding; without this rule a stranger could
// TOFU-bind an unknown host_id and lock the real host out.
func TestPairingAttachDoesNotBind(t *testing.T) {
	e := newTestEnv(t, Config{})
	unknown := tid(0x66)
	status, _ := pairingRefusal(t, e, unknown, tokBob) // valid token, unbound host
	if status != http.StatusGone {
		t.Fatalf("refusal status = %d, want 410", status)
	}
	e.relay.mu.Lock()
	_, bound := e.relay.bindings[unknown]
	e.relay.mu.Unlock()
	if bound {
		t.Fatal("a pairing attach created an account binding — only /v1/host may bind")
	}
	// And the real host can still bind it afterwards.
	c := e.dialWS("/v1/host?host_id="+unknown, tokAlice)
	_ = c.CloseNow()
}

// TestSingleOpenWindowPerHost: §3.1 — a second POST invalidates the
// first: its pairing attaches are closed 4410 and the old window_id
// 410s on DELETE-side lookups; the new window works.
func TestSingleOpenWindowPerHost(t *testing.T) {
	e := newTestEnv(t, Config{})
	win1 := e.openWindow(t)

	// Attach a pairing device to window 1.
	d1 := e.dialWS(pairingAttachPath(hostA), tokAlice)
	readMessage(t, d1, websocket.MessageText)

	// Second POST displaces window 1.
	win2 := e.openWindow(t)
	if win2.WindowID == win1.WindowID || win2.ProvisionalChannel == win1.ProvisionalChannel {
		t.Fatal("second window reused the first window's identifiers")
	}
	expectClose(t, d1, 4410) // displaced attaches get the 4410 treatment

	// The old provisional channel is dead: host frames on it are
	// unroutable now.
	e.relay.mu.Lock()
	_, oldLive := e.relay.provChans[win1.ProvisionalChannel]
	e.relay.mu.Unlock()
	if oldLive {
		t.Fatal("displaced window's provisional channel still routable")
	}

	// The new window admits attaches and conveys ITS provisional channel.
	d2 := e.dialWS(pairingAttachPath(hostA), tokAlice)
	var first struct {
		ProvisionalChannel string `json:"provisional_channel"`
	}
	if err := json.Unmarshal(readMessage(t, d2, websocket.MessageText), &first); err != nil ||
		first.ProvisionalChannel != win2.ProvisionalChannel {
		t.Fatalf("new-window attach conveyed %q, want %q", first.ProvisionalChannel, win2.ProvisionalChannel)
	}
}

// TestWindowExpiry: attach after the ≤5 min TTL fails with the uniform
// window_closed refusal, and already-attached pairing connections are
// closed with 4410. Provisional channels are never mailboxed.
func TestWindowExpiry(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.openWindow(t)
	device := e.dialWS(pairingAttachPath(hostA), tokAlice)
	readMessage(t, device, websocket.MessageText) // provisional_channel

	e.clock.Advance(5*time.Minute + time.Second)

	// The attached pairing connection is closed with 4410.
	expectClose(t, device, 4410)

	// A fresh attach is refused pre-upgrade with the uniform 410.
	if status, _ := pairingRefusal(t, e, hostA, tokAlice); status != http.StatusGone {
		t.Fatalf("expired-window attach status = %d, want 410", status)
	}
}

// TestWindowExplicitClose: DELETE closes the window (host closes it when
// the pairing sheet closes, §3.1). window_id remains a host-facing
// handle — it never appears on a device path.
func TestWindowExplicitClose(t *testing.T) {
	e := newTestEnv(t, Config{})
	win := e.openWindow(t)
	status, _ := e.rest("DELETE", "/v1/pairing-windows/"+win.WindowID, tokAlice, nil)
	if status != http.StatusNoContent {
		t.Fatalf("close window: status %d", status)
	}
	if status, _ := pairingRefusal(t, e, hostA, tokAlice); status != http.StatusGone {
		t.Fatalf("closed-window attach status = %d, want 410", status)
	}
}

// TestCreatePairingHostGeneratedChannelID: §3.4 — channel_id comes from
// the host, the relay assigns pairing_id, and a duplicate channel_id is
// a 409 conflict.
func TestCreatePairingHostGeneratedChannelID(t *testing.T) {
	e := newTestEnv(t, Config{})
	pid := e.createPairing(nil)
	if pid == "" {
		t.Fatal("no pairing_id returned")
	}

	// Same host-generated channel_id again ⇒ conflict.
	status, body := e.rest("POST", "/v1/pairings", tokAlice, map[string]any{
		"channel_id": channelA, "host_id": hostA, "device_id": tid(0x42), "host_label": nil,
	})
	if status != http.StatusConflict || errBody(t, body) != "conflict" {
		t.Fatalf("duplicate channel_id: status %d code %s, want 409 conflict", status, errBody(t, body))
	}
}

// TestDeletePairingRevokesAttachAndMailbox: FR-8 metadata deregistration.
func TestDeletePairingRevokesAttachAndMailbox(t *testing.T) {
	e := newTestEnv(t, Config{})
	pid := e.createPairing(nil)
	e.sendMailboxFrames(t, []uint64{1}, PushNone)

	status, _ := e.rest("DELETE", "/v1/pairings/"+pid, tokAlice, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete pairing: status %d", status)
	}
	// Channel is gone: device attach now 404s.
	_, resp, err := e.dialWSRaw("/v1/device?channel="+channelA, tokAlice)
	if err == nil {
		t.Fatal("attach to deregistered channel succeeded")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("deregistered attach: %+v, want 404", resp)
	}
	// Mailbox is gone too.
	status, body := e.rest("GET", "/v1/channels/"+channelA+"/frames?after=0", tokAlice, nil)
	if status != http.StatusNotFound || errBody(t, body) != "not_found" {
		t.Fatalf("mailbox after deregistration: status %d body %s, want 404 not_found", status, body)
	}
}

// TestPatchPairingLabelValidation: host_label is capped at 64 UTF-8
// bytes (§3.4) and the PATCH body must carry the key.
func TestPatchPairingLabelValidation(t *testing.T) {
	e := newTestEnv(t, Config{})
	pid := e.createPairing(nil)

	long := string(bytes.Repeat([]byte("x"), 65))
	status, body := e.rest("PATCH", "/v1/pairings/"+pid, tokAlice, map[string]any{"host_label": long})
	if status != http.StatusBadRequest || errBody(t, body) != "protocol_violation" {
		t.Fatalf("oversize label: status %d code %s", status, errBody(t, body))
	}
	status, _ = e.rest("PATCH", "/v1/pairings/"+pid, tokAlice, map[string]any{})
	if status != http.StatusBadRequest {
		t.Fatalf("missing host_label key: status %d, want 400", status)
	}
	status, _ = e.rest("PATCH", "/v1/pairings/"+pid, tokAlice, map[string]any{"host_label": "ok"})
	if status != http.StatusNoContent {
		t.Fatalf("valid label: status %d, want 204", status)
	}
}
