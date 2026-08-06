package fakerelay

import (
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestMailboxGetRateLimited: §7.1 mailbox GET per device, token bucket;
// exceeding yields 429 rate_limited with Retry-After set (§7.1/§7.2).
func TestMailboxGetRateLimited(t *testing.T) {
	e := newTestEnv(t, Config{Limits: Limits{MailboxGetPerMin: 2}})
	e.createPairing(nil)

	for i := 0; i < 2; i++ {
		if status, body := e.rest("GET", "/v1/channels/"+channelA+"/frames?after=0", tokAlice, nil); status != http.StatusOK {
			t.Fatalf("GET %d: status %d body %s", i, status, body)
		}
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/v1/channels/"+channelA+"/frames?after=0", nil)
	req.Header.Set("Authorization", "Bearer "+tokAlice)
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("third GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third GET status = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("rate_limited response missing Retry-After (§7.2)")
	}

	// A rate limit is backpressure, not revocation: after refill the same
	// device fetches again with all relay-side state intact (§7.1).
	e.clock.Advance(time.Minute)
	if status, _ := e.rest("GET", "/v1/channels/"+channelA+"/frames?after=0", tokAlice, nil); status != http.StatusOK {
		t.Fatalf("post-refill GET status = %d, want 200 (backpressure must not destroy state)", status)
	}
}

// TestDeviceFrameRateLimitClose: frames/s per device connection; the
// WSS surface closes with 4429 (§7.2).
func TestDeviceFrameRateLimitClose(t *testing.T) {
	e := newTestEnv(t, Config{Limits: Limits{DeviceFramesPerSec: 1, DeviceFramesBurst: 2}})
	e.createPairing(nil)
	_ = e.dialHost(hostA, tokAlice)
	device := e.dialDevice(channelA, tokAlice)
	readPresence(t, device)

	for seq := uint64(1); seq <= 3; seq++ { // burst is 2; the third frame trips the bucket
		writeFrame(t, device, frame(t, channelA, seq, PushNone, nil))
	}
	expectClose(t, device, 4429)
}

// TestPairingWindowRateLimited: §7.1 pairing windows per host.
func TestPairingWindowRateLimited(t *testing.T) {
	e := newTestEnv(t, Config{Limits: Limits{PairingWindowsPerHour: 2}})
	e.openWindow(t)
	e.openWindow(t)
	status, body := e.rest("POST", "/v1/pairing-windows", tokAlice, map[string]string{"host_id": hostA})
	if status != http.StatusTooManyRequests || errBody(t, body) != "rate_limited" {
		t.Fatalf("third window: status %d code %s, want 429 rate_limited", status, errBody(t, body))
	}
}

// TestPairingAttachPerWindowLimit: §3.3/§7.1 — pairing attaches per
// window are capped as a flood guard; exceeding yields the uniform
// window_closed refusal, NOT rate_limited — a distinguishable
// rate-limit response would re-open the window-existence oracle §3.2
// closes.
func TestPairingAttachPerWindowLimit(t *testing.T) {
	e := newTestEnv(t, Config{Limits: Limits{PairingAttachesPerWindow: 2}})
	e.openWindow(t)
	for i := 0; i < 2; i++ {
		c := e.dialWS(pairingAttachPath(hostA), tokAlice)
		readMessage(t, c, websocket.MessageText)
	}
	_, resp, err := e.dialWSRaw(pairingAttachPath(hostA), tokAlice)
	if err == nil {
		t.Fatal("third pairing attach succeeded past the window cap")
	}
	if resp == nil || resp.StatusCode != http.StatusGone {
		t.Fatalf("third pairing attach: %+v, want the uniform 410 window_closed", resp)
	}
}

// TestConcurrentDeviceAttachLimit: §7.1 concurrent device attachments
// per channel.
func TestConcurrentDeviceAttachLimit(t *testing.T) {
	e := newTestEnv(t, Config{Limits: Limits{DeviceAttachPerChannel: 2}})
	e.createPairing(nil)
	d1 := e.dialDevice(channelA, tokAlice)
	d2 := e.dialDevice(channelA, tokAlice)
	readPresence(t, d1)
	readPresence(t, d2)
	_, resp, err := e.dialWSRaw("/v1/device?channel="+channelA, tokAlice)
	if err == nil {
		t.Fatal("attach past the concurrent-attachment cap succeeded")
	}
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over-cap attach: %+v, want 429", resp)
	}
}
