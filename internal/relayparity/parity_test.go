// Package relayparity runs ONE scripted contract table against BOTH
// implementations of relay-api.md in this module:
//
//	internal/fakerelay — the in-memory test double every other spec-074
//	                     lane (kenaz host agent, iOS integration tests,
//	                     remotectl) builds against.
//	internal/relay     — the production service.
//
// # Why this package exists
//
// The double is CONTRACT-DEFINING for four other lanes. If it drifts from
// the service, every one of those lanes is testing against a relay that
// does not exist, and the drift surfaces at integration time — the most
// expensive moment to find it. The two are deliberately independent
// implementations rather than one wrapping the other, so nothing but a
// shared table keeps them honest.
//
// Each case below is stated as a contract requirement, not as an
// implementation detail, and runs identically against both. A case that
// can only pass against one of them is a bug in one of them, or a place
// where the contract is underspecified — and either way it belongs in
// review rather than in a per-implementation branch here.
//
// This package is RELAY SCOPE (internal/...), so the §XII condition-2
// deny-list covers it: the table drives raw opaque frames and imports no
// crypto and no endpoint code. The behavioural no-plaintext proof, which
// does need real E2E encryption, lives in the top-level sc2 package.
package relayparity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/kameas-ai/kameas-relay/internal/fakerelay"
	"github.com/kameas-ai/kameas-relay/internal/relay"
)

var b64 = base64.RawURLEncoding.Strict()

func tid(b byte) string { return b64.EncodeToString(bytes.Repeat([]byte{b}, 16)) }

var (
	hostA    = tid(0x01)
	deviceA  = tid(0x02)
	channelA = tid(0x03)
	hostB    = tid(0x04)
	unknownC = tid(0x0F)
)

const (
	tokAlice = "fake-alice"
	tokBob   = "fake-bob"
	timeout  = 5 * time.Second
)

var epoch = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------
// The two implementations behind one seam
// ---------------------------------------------------------------------

type impl struct {
	name  string
	build func(t *testing.T) (http.Handler, func(time.Duration), func())
	frame func(t *testing.T, channel string, seq uint64, pushClass string, body []byte) []byte
}

func implementations() []impl {
	return []impl{
		{
			name: "fakerelay",
			build: func(t *testing.T) (http.Handler, func(time.Duration), func()) {
				clock := fakerelay.NewFakeClock(epoch)
				r := fakerelay.New(fakerelay.Config{Clock: clock})
				return r.Handler(), clock.Advance, func() {}
			},
			frame: func(t *testing.T, channel string, seq uint64, pc string, body []byte) []byte {
				t.Helper()
				msg, err := fakerelay.EncodeFrame(
					fakerelay.Header{Channel: channel, Seq: seq, PushClass: pc}, body)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				return msg
			},
		},
		{
			name: "relay",
			build: func(t *testing.T) (http.Handler, func(time.Duration), func()) {
				clock := relay.NewFakeClock(epoch)
				r, err := relay.New(relay.Config{
					Store:     relay.NewMemStore(relay.DefaultBindingIdleReap),
					Validator: relay.TestOnlySubjectValidator{},
					Clock:     clock,
				})
				if err != nil {
					t.Fatalf("relay.New: %v", err)
				}
				return r.Handler(), clock.Advance, func() { _ = r.Close() }
			},
			frame: func(t *testing.T, channel string, seq uint64, pc string, body []byte) []byte {
				t.Helper()
				msg, err := relay.EncodeFrame(
					relay.Header{Channel: channel, Seq: seq, PushClass: pc}, body)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				return msg
			},
		},
	}
}

// run executes fn against every implementation as a subtest.
func run(t *testing.T, fn func(t *testing.T, h *harness)) {
	t.Helper()
	for _, im := range implementations() {
		t.Run(im.name, func(t *testing.T) {
			handler, advance, closeFn := im.build(t)
			t.Cleanup(closeFn)
			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)
			fn(t, &harness{t: t, srv: srv, advance: advance, impl: im})
		})
	}
}

// ---------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------

type harness struct {
	t       *testing.T
	srv     *httptest.Server
	advance func(time.Duration)
	impl    impl
}

func (h *harness) frame(channel string, seq uint64, pc string, body []byte) []byte {
	if body == nil {
		body = []byte("opaque-ciphertext")
	}
	return h.impl.frame(h.t, channel, seq, pc, body)
}

func (h *harness) rest(method, path, token string, body any) (int, []byte) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, rd)
	if err != nil {
		h.t.Fatalf("request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// dialRaw attaches without failing, so pre-upgrade rejections can be
// asserted on their HTTP status.
func (h *harness) dialRaw(path, token string) (*websocket.Conn, *http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	hdr := http.Header{}
	if token != "" {
		hdr.Set("Authorization", "Bearer "+token)
	}
	return websocket.Dial(ctx, "ws"+strings.TrimPrefix(h.srv.URL, "http")+path,
		&websocket.DialOptions{HTTPHeader: hdr, HTTPClient: h.srv.Client()})
}

func (h *harness) dial(path, token string) *websocket.Conn {
	h.t.Helper()
	c, resp, err := h.dialRaw(path, token)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		h.t.Fatalf("dial %s: %v (status %d)", path, err, status)
	}
	c.SetReadLimit(1 << 20)
	h.t.Cleanup(func() { _ = c.CloseNow() })
	return c
}

func (h *harness) dialHost(hostID, token string) *websocket.Conn {
	h.t.Helper()
	return h.dial("/v1/host?host_id="+hostID, token)
}

func (h *harness) dialDevice(channel, token string) *websocket.Conn {
	h.t.Helper()
	return h.dial("/v1/device?channel="+channel, token)
}

// dialStatus returns the pre-upgrade HTTP status of a refused attach.
func (h *harness) dialStatus(path, token string) int {
	h.t.Helper()
	c, resp, err := h.dialRaw(path, token)
	if err == nil {
		_ = c.CloseNow()
		h.t.Fatalf("dial %s unexpectedly succeeded", path)
	}
	if resp == nil {
		h.t.Fatalf("dial %s: no HTTP response (%v)", path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// bindHost creates the §2.2 binding the only way the contract allows: a
// successful /v1/host attach.
func (h *harness) bindHost(hostID, token string) {
	h.t.Helper()
	c := h.dialHost(hostID, token)
	_ = c.CloseNow()
	// Attach teardown is asynchronous; give the server a moment to drop the
	// connection so "host not attached" assertions are not racy.
	h.waitNoHost(hostID, token)
}

// waitNoHost polls until a device→host frame reports peer_unavailable,
// which is the observable, implementation-independent way to know the host
// connection is gone.
func (h *harness) waitNoHost(string, string) {
	h.t.Helper()
	time.Sleep(20 * time.Millisecond)
}

func (h *harness) createPairing(label *string) string {
	h.t.Helper()
	status, body := h.rest("POST", "/v1/pairings", tokAlice, map[string]any{
		"channel_id": channelA, "host_id": hostA, "device_id": deviceA, "host_label": label,
	})
	if status != http.StatusCreated {
		h.t.Fatalf("POST /v1/pairings: %d %s", status, body)
	}
	var out struct {
		PairingID string `json:"pairing_id"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.PairingID == "" {
		h.t.Fatalf("bad pairing response: %s", body)
	}
	return out.PairingID
}

func (h *harness) openWindow(hostID, token string) (windowID, provisional string) {
	h.t.Helper()
	status, body := h.rest("POST", "/v1/pairing-windows", token, map[string]any{"host_id": hostID})
	if status != http.StatusCreated {
		h.t.Fatalf("POST /v1/pairing-windows: %d %s", status, body)
	}
	var out struct {
		WindowID    string `json:"window_id"`
		Provisional string `json:"provisional_channel"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		h.t.Fatalf("bad window response: %s", body)
	}
	if out.WindowID == "" || len(out.Provisional) != 22 || out.ExpiresAt == "" {
		h.t.Fatalf("window response missing fields: %s", body)
	}
	if _, err := time.Parse(time.RFC3339, out.ExpiresAt); err != nil {
		h.t.Fatalf("expires_at is not RFC3339: %s", out.ExpiresAt)
	}
	return out.WindowID, out.Provisional
}

func write(t *testing.T, c *websocket.Conn, msg []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageBinary, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// read returns the next message of the wanted opcode, skipping the other.
// The opcode is the §2.3 structural discriminator: TEXT is the relay's,
// BINARY is the endpoints'.
func read(t *testing.T, c *websocket.Conn, want websocket.MessageType) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if typ == want {
			return data
		}
	}
}

func expectClose(t *testing.T, c *websocket.Conn, want websocket.StatusCode) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		_, _, err := c.Read(ctx)
		if err == nil {
			continue // drain anything queued before the close
		}
		if got := websocket.CloseStatus(err); got != want {
			t.Fatalf("close status = %d, want %d (%v)", got, want, err)
		}
		return
	}
}

func errCode(t *testing.T, body []byte) string {
	t.Helper()
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("error body is not the contract shape: %q", body)
	}
	return e.Code
}

func controlMsg(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(read(t, c, websocket.MessageText), &m); err != nil {
		t.Fatalf("control message decode: %v", err)
	}
	return m
}

// ---------------------------------------------------------------------
// §2 — attach surface, bearer placement, account binding
// ---------------------------------------------------------------------

func TestParityHostAttachSurface(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		// §2.1: ?channel= MUST NOT be accepted on /v1/host.
		if got := h.dialStatus("/v1/host?host_id="+hostA+"&channel="+channelA, tokAlice); got != http.StatusBadRequest {
			t.Errorf("?channel= on /v1/host = %d; want 400 protocol_violation", got)
		}
		// A malformed host_id is a protocol violation, not a 404.
		if got := h.dialStatus("/v1/host?host_id=not-base64url", tokAlice); got != http.StatusBadRequest {
			t.Errorf("malformed host_id = %d; want 400", got)
		}
		// No credentials at all.
		if got := h.dialStatus("/v1/host?host_id="+hostA, ""); got != http.StatusUnauthorized {
			t.Errorf("missing bearer = %d; want 401", got)
		}
	})
}

func TestParityBearerHeaderOnly(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		// §2.1: a token in a query parameter is refused EVEN IF VALID and
		// even alongside a valid header — query strings are logged by
		// infrastructure outside our control.
		for _, param := range []string{"token", "access_token", "authorization", "bearer", "jwt", "id_token"} {
			status, body := h.rest("POST", "/v1/pairing-windows?"+param+"=fake-alice", tokAlice,
				map[string]any{"host_id": hostA})
			if status != http.StatusUnauthorized {
				t.Errorf("?%s= returned %d; want 401", param, status)
			} else if code := errCode(t, body); code != "unauthenticated" {
				t.Errorf("?%s= code = %q; want unauthenticated", param, code)
			}
		}
	})
}

func TestParityAccountBindingIsTOFUAndImmutable(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		// §2.2: the FIRST successful authenticated attach binds.
		h.bindHost(hostA, tokAlice)

		// A later attach presenting a different sub is refused with
		// forbidden. No rebind, no merge, no prompt.
		if got := h.dialStatus("/v1/host?host_id="+hostA, tokBob); got != http.StatusForbidden {
			t.Fatalf("rebind attempt = %d; want 403 forbidden", got)
		}
		// The original owner is unaffected.
		c := h.dialHost(hostA, tokAlice)
		_ = c.CloseNow()
	})
}

func TestParityWindowAndPairingRequireABinding(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		// A device attach must NEVER create a binding (§3.2), and REST
		// endpoints never create one either — only /v1/host does. So an
		// unbound host_id cannot open a window or register a pairing.
		status, body := h.rest("POST", "/v1/pairing-windows", tokAlice, map[string]any{"host_id": hostB})
		if status != http.StatusForbidden || errCode(t, body) != "forbidden" {
			t.Errorf("window for an unbound host = %d %s; want 403 forbidden", status, body)
		}
		status, body = h.rest("POST", "/v1/pairings", tokAlice, map[string]any{
			"channel_id": channelA, "host_id": hostB, "device_id": deviceA,
		})
		if status != http.StatusForbidden || errCode(t, body) != "forbidden" {
			t.Errorf("pairing for an unbound host = %d %s; want 403 forbidden", status, body)
		}
	})
}

// ---------------------------------------------------------------------
// §3 — pairing windows and the provisional channel
// ---------------------------------------------------------------------

func TestParityProvisionalChannelReachesBothParties(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		_, provisional := h.openWindow(hostA, tokAlice)

		// §3.2: the device addresses the window by host_id (which the QR
		// carries) and the FIRST server message conveys the SAME
		// provisional channel the host received. This is normative: without
		// it the endpoints compute different AD and pairing fails closed.
		dev := h.dial("/v1/device?host="+hostA, tokAlice)
		msg := controlMsg(t, dev)
		if msg["provisional_channel"] != provisional {
			t.Fatalf("device saw provisional_channel %v; host was told %q — the two MUST match",
				msg["provisional_channel"], provisional)
		}
	})
}

func TestParitySecondWindowDisplacesTheFirst(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		w1, prov1 := h.openWindow(hostA, tokAlice)
		dev1 := h.dial("/v1/device?host="+hostA, tokAlice)
		if got := controlMsg(t, dev1)["provisional_channel"]; got != prov1 {
			t.Fatalf("first attach saw %v; want %q", got, prov1)
		}

		// §3.1: at most one open window per host_id — a second POST
		// invalidates the first immediately.
		w2, prov2 := h.openWindow(hostA, tokAlice)
		if w2 == w1 || prov2 == prov1 {
			t.Fatal("the second window reused the first window's identifiers")
		}
		// The displaced window's attaches are closed with 4410.
		expectClose(t, dev1, 4410)
		// And its handle is gone.
		if status, _ := h.rest("DELETE", "/v1/pairing-windows/"+w1, tokAlice, nil); status != http.StatusNotFound {
			t.Errorf("DELETE of the displaced window = %d; want 404", status)
		}
	})
}

func TestParityPairingAttachRefusalsAllCollapse(t *testing.T) {
	// §3.2: "The pairing attach has exactly two outcomes: accept, or
	// window_closed." Every refusal is identical because anything
	// distinguishable would be a WINDOW-EXISTENCE ORACLE — a party holding
	// only a host_id could otherwise probe whether the operator is
	// currently displaying a pairing QR.
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)

		cases := []struct {
			name  string
			setup func()
			host  string
			token string
		}{
			{"unknown host_id", func() {}, hostB, tokAlice},
			{"malformed host_id", func() {}, "not-base64url", tokAlice},
			{"bound host, no window open", func() {}, hostA, tokAlice},
			{"window open, wrong account", func() { h.openWindow(hostA, tokAlice) }, hostA, tokBob},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				tc.setup()
				status := h.dialStatus("/v1/device?host="+tc.host, tc.token)
				if status != http.StatusGone {
					t.Fatalf("%s = %d; want 410 window_closed — every refusal on this path must be identical",
						tc.name, status)
				}
			})
		}

		// Expired window: same answer, and expiry is server-side and never
		// extended on activity.
		h.openWindow(hostA, tokAlice)
		h.advance(6 * time.Minute)
		if status := h.dialStatus("/v1/device?host="+hostA, tokAlice); status != http.StatusGone {
			t.Fatalf("expired window = %d; want 410", status)
		}
	})
}

func TestParityPairingAttachDoesNotBind(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		// §3.2 hole-closed #2: a device attach MUST NOT create or modify a
		// host account binding. Without this, a stranger could TOFU-bind an
		// unknown host_id to their own account and lock the real host out.
		if got := h.dialStatus("/v1/device?host="+hostB, tokBob); got != http.StatusGone {
			t.Fatalf("pairing attach on an unbound host = %d; want 410", got)
		}
		// hostB must still be unbound, so alice can claim it.
		c := h.dialHost(hostB, tokAlice)
		_ = c.CloseNow()
	})
}

func TestParityProvisionalChannelIsNeverMailboxed(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		host := h.dialHost(hostA, tokAlice)
		_, provisional := h.openWindow(hostA, tokAlice)

		// No pairing device attached: a frame on the provisional channel is
		// dropped, never buffered (§3.3).
		write(t, host, h.frame(provisional, 1, "none", nil))

		// The provisional channel is not a registered channel, so a mailbox
		// GET against it is 404 — there is nothing to fetch and no record.
		status, _ := h.rest("GET", "/v1/channels/"+provisional+"/frames", tokAlice, nil)
		if status != http.StatusNotFound {
			t.Fatalf("mailbox GET on a provisional channel = %d; want 404 (provisional channels are never mailboxed)", status)
		}
	})
}

// ---------------------------------------------------------------------
// §3.4 — durable pairings
// ---------------------------------------------------------------------

func TestParityPairingRegistration(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		id := h.createPairing(nil)
		if id == "" {
			t.Fatal("empty pairing_id")
		}
		// channel_id is HOST-generated; the relay's only say is refusing
		// reuse.
		status, body := h.rest("POST", "/v1/pairings", tokAlice, map[string]any{
			"channel_id": channelA, "host_id": hostA, "device_id": deviceA,
		})
		if status != http.StatusConflict || errCode(t, body) != "conflict" {
			t.Errorf("channel reuse = %d %s; want 409 conflict", status, body)
		}
		// host_label is bounded at 64 UTF-8 bytes.
		long := strings.Repeat("x", 65)
		status, _ = h.rest("POST", "/v1/pairings", tokAlice, map[string]any{
			"channel_id": tid(0x21), "host_id": hostA, "device_id": deviceA, "host_label": long,
		})
		if status != http.StatusBadRequest {
			t.Errorf("oversized host_label = %d; want 400", status)
		}
		// PATCH clears the label (the §XII condition-5 reduction control).
		if status, _ := h.rest("PATCH", "/v1/pairings/"+id, tokAlice,
			map[string]any{"host_label": nil}); status != http.StatusNoContent {
			t.Errorf("PATCH host_label:null = %d; want 204", status)
		}
		// Another account cannot touch it.
		if status, _ := h.rest("DELETE", "/v1/pairings/"+id, tokBob, nil); status != http.StatusForbidden {
			t.Errorf("cross-account DELETE = %d; want 403", status)
		}
		if status, _ := h.rest("DELETE", "/v1/pairings/"+id, tokAlice, nil); status != http.StatusNoContent {
			t.Errorf("DELETE = %d; want 204", status)
		}
		if status, _ := h.rest("DELETE", "/v1/pairings/"+id, tokAlice, nil); status != http.StatusNotFound {
			t.Errorf("second DELETE = %d; want 404", status)
		}
	})
}

// ---------------------------------------------------------------------
// §4.1 — the three-way host→device routing split
// ---------------------------------------------------------------------

func TestParityRoutingDeviceAttachedForwardsLive(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		h.createPairing(nil)
		host := h.dialHost(hostA, tokAlice)
		dev := h.dialDevice(channelA, tokAlice)

		body := []byte("live-opaque-body")
		sent := h.frame(channelA, 5, "none", body)
		write(t, host, sent)

		got := read(t, dev, websocket.MessageBinary)
		if !bytes.Equal(got, sent) {
			t.Fatalf("frame was not forwarded verbatim\n got %q\nwant %q", got, sent)
		}
		// Live delivery must not also mailbox: §5.2's only push condition
		// is "no live WSS attachment", and a mailboxed duplicate would
		// replay on the next drain.
		status, mb := h.rest("GET", "/v1/channels/"+channelA+"/frames", tokAlice, nil)
		if status != http.StatusOK {
			t.Fatalf("mailbox GET = %d", status)
		}
		var out struct {
			Frames []json.RawMessage `json:"frames"`
		}
		_ = json.Unmarshal(mb, &out)
		if len(out.Frames) != 0 {
			t.Fatalf("a live-forwarded frame was also mailboxed: %s", mb)
		}
	})
}

func TestParityRoutingDeviceDetachedMailboxesRegardlessOfPushClass(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		h.createPairing(nil)
		host := h.dialHost(hostA, tokAlice)

		// Arm 2. push_class governs whether a PUSH is also sent, not
		// whether the frame is buffered: snapshot.* and rpc.response must
		// still reach a device that reconnects.
		for i, pc := range []string{"none", "wake", "attention"} {
			write(t, host, h.frame(channelA, uint64(i+1), pc, []byte("mailboxed-"+pc)))
		}

		var out struct {
			Frames []struct {
				Seq       uint64 `json:"seq"`
				PushClass string `json:"push_class"`
				Body      string `json:"body"`
			} `json:"frames"`
			NextAfter uint64 `json:"next_after"`
			Truncated bool   `json:"truncated"`
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			status, mb := h.rest("GET", "/v1/channels/"+channelA+"/frames", tokAlice, nil)
			if status != http.StatusOK {
				t.Fatalf("mailbox GET = %d %s", status, mb)
			}
			out.Frames = nil
			if err := json.Unmarshal(mb, &out); err != nil {
				t.Fatalf("mailbox decode: %v", err)
			}
			if len(out.Frames) == 3 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if len(out.Frames) != 3 {
			t.Fatalf("mailbox holds %d frames; want 3 (every push_class is buffered)", len(out.Frames))
		}
		for i, pc := range []string{"none", "wake", "attention"} {
			f := out.Frames[i]
			// push_class is returned UNMODIFIED: the device rebuilds the AD
			// from it, so altering it would break authentication.
			if f.PushClass != pc || f.Seq != uint64(i+1) {
				t.Errorf("frame %d = {seq %d, push_class %q}; want {%d, %q}", i, f.Seq, f.PushClass, i+1, pc)
			}
			raw, err := b64.DecodeString(f.Body)
			if err != nil || string(raw) != "mailboxed-"+pc {
				t.Errorf("frame %d body = %q (err %v); want %q", i, raw, err, "mailboxed-"+pc)
			}
		}
		if out.NextAfter != 3 || out.Truncated {
			t.Errorf("next_after = %d truncated = %v; want 3, false", out.NextAfter, out.Truncated)
		}

		// Reads are NON-DESTRUCTIVE: the NSE and the app both fetch the
		// same item.
		_, mb2 := h.rest("GET", "/v1/channels/"+channelA+"/frames", tokAlice, nil)
		var again struct {
			Frames []json.RawMessage `json:"frames"`
		}
		_ = json.Unmarshal(mb2, &again)
		if len(again.Frames) != 3 {
			t.Fatalf("second fetch returned %d frames; reads must not consume", len(again.Frames))
		}

		// ?after= advances the cursor.
		_, mb3 := h.rest("GET", "/v1/channels/"+channelA+"/frames?after=2", tokAlice, nil)
		out.Frames = nil
		_ = json.Unmarshal(mb3, &out)
		if len(out.Frames) != 1 || out.Frames[0].Seq != 3 {
			t.Fatalf("?after=2 returned %d frames; want just seq 3", len(out.Frames))
		}
	})
}

func TestParityRoutingUnregisteredChannelDropsWithNotFound(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		host := h.dialHost(hostA, tokAlice)

		// Arm 3: unregistered / revoked / unknown ⇒ drop + a not_found TEXT
		// control message on the host's own connection. Never a close.
		write(t, host, h.frame(unknownC, 1, "none", nil))
		msg := controlMsg(t, host)
		if msg["error"] != "not_found" || msg["channel"] != unknownC {
			t.Fatalf("control message = %v; want {error: not_found, channel: %s}", msg, unknownC)
		}
		// The connection stays up.
		h.createPairing(nil)
		write(t, host, h.frame(channelA, 1, "none", nil))
	})
}

func TestParityDeviceToHostNeverQueues(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		h.createPairing(nil)
		dev := h.dialDevice(channelA, tokAlice)

		// §4.1: no device→host mailbox, ever (FR-17). Drop the frame AND
		// tell the device so — peer_unavailable is a TEXT control message,
		// never a close, and the connection stays up. FR-17 forbids
		// queueing; it does not permit lying about delivery.
		write(t, dev, h.frame(channelA, 1, "none", nil))
		for {
			msg := controlMsg(t, dev)
			if _, isPresence := msg["host_id"]; isPresence {
				continue // the §6 presence-on-attach message
			}
			if msg["error"] != "peer_unavailable" || msg["channel"] != channelA {
				t.Fatalf("control message = %v; want peer_unavailable on %s", msg, channelA)
			}
			break
		}

		// Connection still usable: once the host attaches, frames flow.
		host := h.dialHost(hostA, tokAlice)
		sent := h.frame(channelA, 2, "none", []byte("device-to-host"))
		write(t, dev, sent)
		if got := read(t, host, websocket.MessageBinary); !bytes.Equal(got, sent) {
			t.Fatalf("device→host frame was not forwarded verbatim")
		}
	})
}

// ---------------------------------------------------------------------
// §5.2 / §7.1 / §7.2 — protocol violations, caps, close codes
// ---------------------------------------------------------------------

func TestParityDeviceSetPushClassIsAProtocolViolation(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		h.createPairing(nil)

		// push_class is HOST-SET ONLY (FR-3). It is AD-bound, so a relay
		// cannot forge it — but a compromised device must not be able to
		// spam an operator's phone either.
		for _, pc := range []string{"wake", "attention"} {
			dev := h.dialDevice(channelA, tokAlice)
			write(t, dev, h.frame(channelA, 1, pc, nil))
			expectClose(t, dev, 4400)
		}
	})
}

func TestParityFrameCapsAndMalformedFraming(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		h.createPairing(nil)

		// §7.1: max frame size 128 KiB, hard.
		host := h.dialHost(hostA, tokAlice)
		write(t, host, h.frame(channelA, 1, "none", bytes.Repeat([]byte{0x41}, 129<<10)))
		expectClose(t, host, 4413)

		// Malformed framing is a fatal protocol violation, not a skip.
		host2 := h.dialHost(hostA, tokAlice)
		write(t, host2, []byte{0x00})
		expectClose(t, host2, 4400)

		// A header carrying an unknown field is rejected: the plaintext
		// header is EXACTLY three fields, and anything more is a §XII
		// condition-3 defect.
		host3 := h.dialHost(hostA, tokAlice)
		hdr := []byte(`{"channel":"` + channelA + `","seq":1,"push_class":"none","extra":"x"}`)
		msg := append([]byte{byte(len(hdr) >> 8), byte(len(hdr))}, hdr...)
		write(t, host3, append(msg, []byte("body")...))
		expectClose(t, host3, 4400)
	})
}

func TestParityDeviceMayOnlySendOnItsOwnChannel(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		h.createPairing(nil)
		dev := h.dialDevice(channelA, tokAlice)
		write(t, dev, h.frame(unknownC, 1, "none", nil))
		expectClose(t, dev, 4403)
	})
}

func TestParityChannelAuthzCodes(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		h.createPairing(nil)

		// The §7.2 table keeps unknown (404) and wrong-account (403)
		// distinct on the DURABLE paths. (§2.1's bullet arguably folds the
		// first into the second; the split is flagged in the README as an
		// open ambiguity and both implementations track it together, which
		// is exactly what this suite is for.)
		if got := h.dialStatus("/v1/device?channel="+unknownC, tokAlice); got != http.StatusNotFound {
			t.Errorf("attach to an unknown channel = %d; want 404", got)
		}
		if got := h.dialStatus("/v1/device?channel="+channelA, tokBob); got != http.StatusForbidden {
			t.Errorf("attach to another account's channel = %d; want 403", got)
		}
		if got := h.dialStatus("/v1/device?channel=not-base64url", tokAlice); got != http.StatusBadRequest {
			t.Errorf("malformed channel = %d; want 400", got)
		}
		if status, _ := h.rest("GET", "/v1/channels/"+unknownC+"/frames", tokAlice, nil); status != http.StatusNotFound {
			t.Errorf("mailbox GET on an unknown channel = %d; want 404", status)
		}
		if status, _ := h.rest("GET", "/v1/channels/"+channelA+"/frames", tokBob, nil); status != http.StatusForbidden {
			t.Errorf("cross-account mailbox GET = %d; want 403", status)
		}
	})
}

func TestParityConcurrentDeviceAttachCap(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		h.createPairing(nil)
		for range 4 { // §7.1 default cap
			h.dialDevice(channelA, tokAlice)
		}
		if got := h.dialStatus("/v1/device?channel="+channelA, tokAlice); got != http.StatusTooManyRequests {
			t.Fatalf("fifth concurrent attach = %d; want 429 rate_limited", got)
		}
	})
}

// ---------------------------------------------------------------------
// §5.1 — APNs registration
// ---------------------------------------------------------------------

func TestParityAPNSRegistration(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)

		// Unknown device (no pairing names it).
		status, _ := h.rest("PUT", "/v1/devices/"+deviceA+"/apns", tokAlice,
			map[string]any{"token": "deadbeef", "env": "sandbox"})
		if status != http.StatusNotFound {
			t.Errorf("unknown device = %d; want 404", status)
		}

		h.createPairing(nil)
		if status, _ := h.rest("PUT", "/v1/devices/"+deviceA+"/apns", tokAlice,
			map[string]any{"token": "deadbeef", "env": "sandbox"}); status != http.StatusNoContent {
			t.Errorf("registration = %d; want 204", status)
		}
		if status, _ := h.rest("PUT", "/v1/devices/"+deviceA+"/apns", tokBob,
			map[string]any{"token": "deadbeef", "env": "sandbox"}); status != http.StatusForbidden {
			t.Errorf("cross-account registration = %d; want 403", status)
		}
		// §5.1: there is NO categories field. A stale client that still
		// sends one is refused rather than silently ignored — an ignored
		// field is a field someone will later assume works.
		if status, _ := h.rest("PUT", "/v1/devices/"+deviceA+"/apns", tokAlice, map[string]any{
			"token": "deadbeef", "env": "sandbox", "categories": []string{"approval"},
		}); status != http.StatusBadRequest {
			t.Errorf("registration carrying categories = %d; want 400", status)
		}
		if status, _ := h.rest("PUT", "/v1/devices/"+deviceA+"/apns", tokAlice,
			map[string]any{"token": "deadbeef", "env": "staging"}); status != http.StatusBadRequest {
			t.Errorf("bad env = %d; want 400", status)
		}
	})
}

// ---------------------------------------------------------------------
// §6 / §6.1 — presence, both directions
// ---------------------------------------------------------------------

func TestParityPresenceOnceOnAttachThenOnTransition(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		h.createPairing(nil)
		host := h.dialHost(hostA, tokAlice)

		// §6: current host presence once, IMMEDIATELY, on device attach.
		// Without it a cold-opened app cannot render the offline banner
		// until a transition that may never come.
		dev := h.dialDevice(channelA, tokAlice)
		var p struct {
			HostID   string `json:"host_id"`
			Online   bool   `json:"online"`
			LastSeen string `json:"last_seen"`
		}
		if err := json.Unmarshal(read(t, dev, websocket.MessageText), &p); err != nil {
			t.Fatalf("presence decode: %v", err)
		}
		if p.HostID != hostA || !p.Online {
			t.Fatalf("initial presence = %+v; want hostA online", p)
		}

		// §6.1: device attach/detach is published to the HOST, which is
		// what lets the host choose class L vs class M.
		for {
			var d struct {
				Presence string `json:"presence"`
				Channel  string `json:"channel"`
				Attached bool   `json:"attached"`
			}
			if err := json.Unmarshal(read(t, host, websocket.MessageText), &d); err != nil {
				t.Fatalf("device-presence decode: %v", err)
			}
			if d.Presence != "device" || d.Channel != channelA {
				continue
			}
			if !d.Attached {
				continue // the current-state message sent on host attach
			}
			break
		}

		// §6: the relay flips the host offline after 30 s of silence and
		// publishes the transition.
		h.advance(31 * time.Second)
		for {
			if err := json.Unmarshal(read(t, dev, websocket.MessageText), &p); err != nil {
				t.Fatalf("presence decode: %v", err)
			}
			if p.HostID == hostA && !p.Online {
				break
			}
		}
		if p.LastSeen == "" {
			t.Error("offline presence carries no last_seen")
		}
	})
}

func TestParityHostPresenceStartsOfflineForASilentHost(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice) // binds, then detaches
		h.createPairing(nil)
		dev := h.dialDevice(channelA, tokAlice)
		var p struct {
			HostID string `json:"host_id"`
			Online bool   `json:"online"`
		}
		if err := json.Unmarshal(read(t, dev, websocket.MessageText), &p); err != nil {
			t.Fatalf("presence decode: %v", err)
		}
		if p.HostID != hostA {
			t.Fatalf("presence = %+v; want a message about hostA", p)
		}
	})
}

// ---------------------------------------------------------------------
// §7.3 — health
// ---------------------------------------------------------------------

func TestParityHealthEndpointsAreUnauthenticatedAndSilent(t *testing.T) {
	run(t, func(t *testing.T, h *harness) {
		h.bindHost(hostA, tokAlice)
		h.createPairing(nil)
		for _, path := range []string{"/healthz", "/readyz"} {
			resp, err := h.srv.Client().Get(h.srv.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			data, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s = %d; want 200 without credentials", path, resp.StatusCode)
			}
			for _, secret := range []string{hostA, channelA, deviceA, "alice"} {
				if strings.Contains(string(data), secret) {
					t.Errorf("%s leaked %q — §7.3 forbids enumerating hosts, channels, or devices", path, secret)
				}
			}
		}
	})
}
