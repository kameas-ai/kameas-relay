package fakerelay

import (
	"net/http"
	"testing"
)

// TestErrorTableREST is the table-driven §7.2 conformance check for the
// REST/pre-upgrade surface: every case must produce the contract's HTTP
// status and closed-set code.
func TestErrorTableREST(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(e *testEnv)
		method     string
		path       string
		token      string
		body       any
		wantStatus int
		wantCode   string
	}{
		{
			name:   "unauthenticated: missing token",
			method: "GET", path: "/v1/channels/" + channelA + "/frames?after=0",
			wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated",
		},
		{
			name:   "unauthenticated: token not accepted by the validator",
			method: "POST", path: "/v1/pairings", token: "not-a-fake-token", body: map[string]string{},
			wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated",
		},
		{
			name:   "forbidden: channel paired to a different account",
			setup:  func(e *testEnv) { e.createPairing(nil) },
			method: "GET", path: "/v1/channels/" + channelA + "/frames?after=0", token: tokBob,
			wantStatus: http.StatusForbidden, wantCode: "forbidden",
		},
		{
			name:   "not_found: unknown channel",
			method: "GET", path: "/v1/channels/" + tid(0x77) + "/frames?after=0", token: tokAlice,
			wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
		{
			name:   "not_found: unknown pairing on PATCH",
			method: "PATCH", path: "/v1/pairings/nonexistent", token: tokAlice,
			body:       map[string]any{"host_label": nil},
			wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
		{
			name:   "conflict: duplicate channel_id",
			setup:  func(e *testEnv) { e.createPairing(nil) },
			method: "POST", path: "/v1/pairings", token: tokAlice,
			body:       map[string]any{"channel_id": channelA, "host_id": hostA, "device_id": deviceA},
			wantStatus: http.StatusConflict, wantCode: "conflict",
		},
		{
			name:   "protocol_violation: malformed pairing body",
			method: "POST", path: "/v1/pairings", token: tokAlice,
			body:       map[string]any{"channel_id": "not-22-chars"},
			wantStatus: http.StatusBadRequest, wantCode: "protocol_violation",
		},
		{
			name:   "forbidden: host_id bound to another account",
			setup:  func(e *testEnv) { e.createPairing(nil) }, // binds hostA -> alice
			method: "POST", path: "/v1/pairing-windows", token: tokBob,
			body:       map[string]string{"host_id": hostA},
			wantStatus: http.StatusForbidden, wantCode: "forbidden",
		},
		{
			name:   "not_found: APNs registration for unknown device",
			method: "PUT", path: "/v1/devices/" + tid(0x55) + "/apns", token: tokAlice,
			body:       map[string]any{"token": "aa", "env": "sandbox"},
			wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
		{
			name:   "protocol_violation: bad APNs env",
			setup:  func(e *testEnv) { e.createPairing(nil) },
			method: "PUT", path: "/v1/devices/" + deviceA + "/apns", token: tokAlice,
			body:       map[string]any{"token": "aa", "env": "staging"},
			wantStatus: http.StatusBadRequest, wantCode: "protocol_violation",
		},
		{
			name:   "forbidden: pairing window for an unbound host_id",
			method: "POST", path: "/v1/pairing-windows", token: tokAlice,
			body:       map[string]string{"host_id": tid(0x71)},
			wantStatus: http.StatusForbidden, wantCode: "forbidden",
		},
		{
			name:   "forbidden: pairing registration for an unbound host_id",
			method: "POST", path: "/v1/pairings", token: tokAlice,
			body:       map[string]any{"channel_id": tid(0x72), "host_id": tid(0x73), "device_id": tid(0x74)},
			wantStatus: http.StatusForbidden, wantCode: "forbidden",
		},
		{
			name:   "unauthenticated: bearer token in a query parameter (REST)",
			method: "GET", path: "/v1/channels/" + channelA + "/frames?after=0&access_token=fake-alice", token: tokAlice,
			wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, Config{})
			if tc.setup != nil {
				tc.setup(e)
			}
			status, body := e.rest(tc.method, tc.path, tc.token, tc.body)
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", status, tc.wantStatus, body)
			}
			if code := errBody(t, body); code != tc.wantCode {
				t.Fatalf("code = %q, want %q", code, tc.wantCode)
			}
		})
	}
}

// TestWSSPreUpgradeRejections: authN/authZ failures reject BEFORE the
// upgrade completes (§2), with the contract HTTP statuses.
func TestWSSPreUpgradeRejections(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(e *testEnv)
		path       string
		token      string
		wantStatus int
	}{
		{"host attach without token", nil, "/v1/host?host_id=" + hostA, "", http.StatusUnauthorized},
		{"host attach on foreign host_id", func(e *testEnv) { e.createPairing(nil) }, "/v1/host?host_id=" + hostA, tokBob, http.StatusForbidden},
		{"device attach unknown channel", nil, "/v1/device?channel=" + channelA, tokAlice, http.StatusNotFound},
		{"device attach foreign channel", func(e *testEnv) { e.createPairing(nil) }, "/v1/device?channel=" + channelA, tokBob, http.StatusForbidden},
		{"malformed host_id", nil, "/v1/host?host_id=short", tokAlice, http.StatusBadRequest},
		// §2.1: ?channel= MUST NOT be accepted on /v1/host.
		{"channel param refused on host attach", func(e *testEnv) { e.createPairing(nil) },
			"/v1/host?host_id=" + hostA + "&channel=" + channelA, tokAlice, http.StatusBadRequest},
		// §2.1: a bearer token in the query string is refused EVEN WITH a
		// valid Authorization header — query strings leak into
		// infrastructure logs.
		{"query-string token refused on host attach", nil,
			"/v1/host?host_id=" + hostA + "&access_token=fake-alice", tokAlice, http.StatusUnauthorized},
		{"query-string token refused on device attach", func(e *testEnv) { e.createPairing(nil) },
			"/v1/device?channel=" + channelA + "&token=fake-alice", tokAlice, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, Config{})
			if tc.setup != nil {
				tc.setup(e)
			}
			_, resp, err := e.dialWSRaw(tc.path, tc.token)
			if err == nil {
				t.Fatal("upgrade unexpectedly succeeded")
			}
			if resp == nil || resp.StatusCode != tc.wantStatus {
				got := 0
				if resp != nil {
					got = resp.StatusCode
				}
				t.Fatalf("status = %d, want %d", got, tc.wantStatus)
			}
		})
	}
}

// TestWSSCloseCodes: post-upgrade violations close with the §7.2 WSS
// close codes.
func TestWSSCloseCodes(t *testing.T) {
	t.Run("frame_too_large 4413", func(t *testing.T) {
		e := newTestEnv(t, Config{MaxFrameSize: 256})
		e.createPairing(nil)
		host := e.dialHost(hostA, tokAlice)
		writeFrame(t, host, frame(t, channelA, 1, PushNone, make([]byte, 512)))
		expectClose(t, host, 4413)
	})
	t.Run("protocol_violation 4400 on malformed framing", func(t *testing.T) {
		e := newTestEnv(t, Config{})
		e.createPairing(nil)
		host := e.dialHost(hostA, tokAlice)
		writeFrame(t, host, []byte{0xFF}) // truncated header_len
		expectClose(t, host, 4400)
	})
	t.Run("protocol_violation 4400 on oversize header", func(t *testing.T) {
		e := newTestEnv(t, Config{})
		e.createPairing(nil)
		host := e.dialHost(hostA, tokAlice)
		// header_len declares 600 > 512 cap
		msg := append([]byte{0x02, 0x58}, make([]byte, 600)...)
		writeFrame(t, host, msg)
		expectClose(t, host, 4400)
	})
	t.Run("protocol_violation 4400 on extra plaintext header field", func(t *testing.T) {
		e := newTestEnv(t, Config{})
		e.createPairing(nil)
		host := e.dialHost(hostA, tokAlice)
		// A fourth plaintext field is a §XII condition-3 defect; the
		// header decoder rejects unknown fields.
		hdr := []byte(`{"channel":"` + channelA + `","seq":1,"push_class":"none","extra":"leak"}`)
		msg := append([]byte{byte(len(hdr) >> 8), byte(len(hdr))}, hdr...)
		writeFrame(t, host, msg)
		expectClose(t, host, 4400)
	})
}

// TestFrameCodecCanonicality: table-driven DecodeFrame validation —
// non-canonical channel encodings and bad push classes are rejected.
func TestFrameCodecCanonicality(t *testing.T) {
	valid := frame(t, channelA, 1, PushNone, []byte("x"))
	if _, _, err := DecodeFrame(valid, 512); err != nil {
		t.Fatalf("valid frame rejected: %v", err)
	}
	cases := []struct {
		name    string
		channel string
		pc      string
	}{
		{"padded channel", "AAAAAAAAAAAAAAAAAAAAA=", PushNone},
		{"short channel", "AAAA", PushNone},
		{"wrong alphabet", "AAAAAAAAAAAAAAAAAAAA+/", PushNone},
		{"non-canonical trailing bits", "AAAAAAAAAAAAAAAAAAAAAB", PushNone}, // low bits of final char nonzero
		{"unknown push_class", channelA, "urgent"},
		{"empty push_class", channelA, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdr := []byte(`{"channel":"` + tc.channel + `","seq":1,"push_class":"` + tc.pc + `"}`)
			msg := append([]byte{byte(len(hdr) >> 8), byte(len(hdr))}, hdr...)
			msg = append(msg, 'x')
			if _, _, err := DecodeFrame(msg, 512); err == nil {
				t.Fatalf("frame with %s accepted", tc.name)
			}
		})
	}
}

// TestHealthEndpoints: §7.3 — unauthenticated, no enumeration.
func TestHealthEndpoints(t *testing.T) {
	e := newTestEnv(t, Config{})
	for _, path := range []string{"/healthz", "/readyz"} {
		status, body := e.rest("GET", path, "", nil)
		if status != http.StatusOK || string(body) != "ok" {
			t.Fatalf("%s = %d %q, want 200 ok with no operator data", path, status, body)
		}
	}
}
