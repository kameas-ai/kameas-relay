package fakerelay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// Wall-clock ceiling for reads that are expected to complete immediately
// (the event has already been triggered); generous only to absorb
// scheduler noise, never used as a sleep.
const readTimeout = 5 * time.Second

// tid builds a deterministic canonical 22-char id from a fill byte.
func tid(b byte) string { return b64.EncodeToString(bytes.Repeat([]byte{b}, 16)) }

// Common test identities.
var (
	hostA    = tid(0x01)
	deviceA  = tid(0x02)
	channelA = tid(0x03)
)

const (
	tokAlice = "fake-alice" // sub "alice"
	tokBob   = "fake-bob"   // sub "bob"
)

type testEnv struct {
	t     *testing.T
	relay *Relay
	clock *FakeClock
	srv   *httptest.Server
}

func newTestEnv(t *testing.T, cfg Config) *testEnv {
	t.Helper()
	clock := NewFakeClock(time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC))
	cfg.Clock = clock
	relay := New(cfg)
	srv := httptest.NewServer(relay.Handler())
	t.Cleanup(srv.Close)
	return &testEnv{t: t, relay: relay, clock: clock, srv: srv}
}

func (e *testEnv) wsURL(path string) string {
	return "ws" + strings.TrimPrefix(e.srv.URL, "http") + path
}

// dialWS attaches a WebSocket; fatal on failure.
func (e *testEnv) dialWS(path, token string) *websocket.Conn {
	e.t.Helper()
	c, resp, err := e.dialWSRaw(path, token)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		e.t.Fatalf("dial %s: %v (http status %d)", path, err, status)
	}
	e.t.Cleanup(func() { _ = c.CloseNow() })
	c.SetReadLimit(1 << 20)
	return c
}

// dialWSRaw attaches without failing the test, returning the HTTP
// response for pre-upgrade rejection assertions.
func (e *testEnv) dialWSRaw(path, token string) (*websocket.Conn, *http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	hdr := http.Header{}
	if token != "" {
		hdr.Set("Authorization", "Bearer "+token)
	}
	return websocket.Dial(ctx, e.wsURL(path), &websocket.DialOptions{
		HTTPHeader: hdr,
		HTTPClient: e.srv.Client(),
	})
}

func (e *testEnv) dialHost(hostID, token string) *websocket.Conn {
	e.t.Helper()
	return e.dialWS("/v1/host?host_id="+hostID, token)
}

func (e *testEnv) dialDevice(channel, token string) *websocket.Conn {
	e.t.Helper()
	return e.dialWS("/v1/device?channel="+channel, token)
}

// rest performs an authenticated REST call and returns status + body.
func (e *testEnv) rest(method, path, token string, body any) (int, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatalf("marshal body: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatalf("build request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// bindHost creates the §2.2 account binding for hostA↔alice the only
// way the contract allows: a successful /v1/host attach. The attach is
// closed immediately; the binding persists.
func (e *testEnv) bindHost() {
	e.t.Helper()
	c := e.dialHost(hostA, tokAlice) // dial success ⇒ binding committed
	_ = c.CloseNow()
	e.waitHostConns(0)
}

// waitHostConns polls until hostA has exactly n live attachments (conn
// teardown is asynchronous).
func (e *testEnv) waitHostConns(n int) {
	e.t.Helper()
	deadline := time.Now().Add(readTimeout)
	for time.Now().Before(deadline) {
		e.relay.mu.Lock()
		got := len(e.relay.hostConns[hostA])
		e.relay.mu.Unlock()
		if got == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	e.t.Fatalf("hostA never reached %d attachments", n)
}

// createPairing binds hostA to alice (if needed) and registers the
// standard pairing, returning pairing_id.
func (e *testEnv) createPairing(label *string) string {
	e.t.Helper()
	e.bindHost()
	status, body := e.rest("POST", "/v1/pairings", tokAlice, map[string]any{
		"channel_id": channelA, "host_id": hostA, "device_id": deviceA, "host_label": label,
	})
	if status != http.StatusCreated {
		e.t.Fatalf("POST /v1/pairings: status %d body %s", status, body)
	}
	var out struct {
		PairingID string `json:"pairing_id"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.PairingID == "" {
		e.t.Fatalf("bad pairing response: %s", body)
	}
	return out.PairingID
}

// frame builds a wire frame; body defaults to opaque filler.
func frame(t *testing.T, channel string, seq uint64, pushClass string, body []byte) []byte {
	t.Helper()
	if body == nil {
		body = []byte(fmt.Sprintf("opaque-ciphertext-%d", seq))
	}
	msg, err := EncodeFrame(Header{Channel: channel, Seq: seq, PushClass: pushClass}, body)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	return msg
}

func writeFrame(t *testing.T, c *websocket.Conn, msg []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageBinary, msg); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

// readMessage reads the next message of the wanted type, skipping the
// other type (frames are BINARY, relay control messages are TEXT).
func readMessage(t *testing.T, c *websocket.Conn, want websocket.MessageType) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
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

func readPresence(t *testing.T, c *websocket.Conn) presenceMsg {
	t.Helper()
	var p presenceMsg
	if err := json.Unmarshal(readMessage(t, c, websocket.MessageText), &p); err != nil {
		t.Fatalf("presence decode: %v", err)
	}
	return p
}

// expectClose asserts the next read fails with the given WSS close code.
func expectClose(t *testing.T, c *websocket.Conn, want websocket.StatusCode) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	for {
		_, _, err := c.Read(ctx)
		if err == nil {
			continue // drain messages queued before the close
		}
		if got := websocket.CloseStatus(err); got != want {
			t.Fatalf("close status = %d, want %d (err: %v)", got, want, err)
		}
		return
	}
}

// readAll drains an HTTP response body (pre-upgrade WSS rejections).
func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.Body == nil {
		return ""
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading rejection body: %v", err)
	}
	return string(data)
}

// errBody decodes the closed-set error body.
func errBody(t *testing.T, data []byte) string {
	t.Helper()
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatalf("error body not per contract: %q", data)
	}
	return e.Code
}
