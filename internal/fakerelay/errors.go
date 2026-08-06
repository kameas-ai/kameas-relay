package fakerelay

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/coder/websocket"
)

// errCode is the closed error set of relay-api.md §7.2. No other code may
// ever appear on the wire.
type errCode string

const (
	codeUnauthenticated   errCode = "unauthenticated"
	codeForbidden         errCode = "forbidden"
	codeAuthUnavailable   errCode = "auth_unavailable"
	codeNotFound          errCode = "not_found"
	codeConflict          errCode = "conflict"
	codeFrameTooLarge     errCode = "frame_too_large"
	codeProtocolViolation errCode = "protocol_violation"
	codeRateLimited       errCode = "rate_limited"
	codeWindowClosed      errCode = "window_closed"
	codeInternal          errCode = "internal"
	// codePeerUnavailable is a TEXT control message ONLY (§4.1, §7.2):
	// it has no HTTP status and no WSS close code, and the connection
	// stays up. It must never appear in httpStatus or wssClose.
	codePeerUnavailable errCode = "peer_unavailable"
)

// httpStatus maps each code to its HTTP status (relay-api.md §7.2).
var httpStatus = map[errCode]int{
	codeUnauthenticated:   http.StatusUnauthorized,
	codeForbidden:         http.StatusForbidden,
	codeAuthUnavailable:   http.StatusServiceUnavailable,
	codeNotFound:          http.StatusNotFound,
	codeConflict:          http.StatusConflict,
	codeFrameTooLarge:     http.StatusRequestEntityTooLarge,
	codeProtocolViolation: http.StatusBadRequest,
	codeRateLimited:       http.StatusTooManyRequests,
	codeWindowClosed:      http.StatusGone,
	codeInternal:          http.StatusInternalServerError,
}

// wssClose maps each code to its WSS close code (relay-api.md §7.2).
// not_found and conflict have no close code in the contract; they only
// occur pre-upgrade / on REST.
var wssClose = map[errCode]websocket.StatusCode{
	codeUnauthenticated:   4401,
	codeForbidden:         4403,
	codeAuthUnavailable:   4503,
	codeFrameTooLarge:     4413,
	codeProtocolViolation: 4400,
	codeRateLimited:       4429,
	codeWindowClosed:      4410,
	codeInternal:          4500,
}

// writeError emits the contract error body {"code","message"}. message
// MUST be non-content: no token bytes, claims, emails, or frame bodies
// (relay-api.md §7.2) — callers pass only fixed strings.
func writeError(w http.ResponseWriter, code errCode, msg string) {
	writeErrorRetry(w, code, msg, 0)
}

// controlError builds a §4.1 routing-error TEXT control message
// {"error":"<code>","channel":"<22ch>"}. Sent on the sender's own
// connection; never a close.
func controlError(code errCode, channel string) []byte {
	b, _ := json.Marshal(map[string]string{"error": string(code), "channel": channel})
	return b
}

func writeErrorRetry(w http.ResponseWriter, code errCode, msg string, retryAfterSecs int) {
	w.Header().Set("Content-Type", "application/json")
	if code == codeRateLimited {
		if retryAfterSecs <= 0 {
			retryAfterSecs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecs))
	}
	w.WriteHeader(httpStatus[code])
	_ = json.NewEncoder(w).Encode(map[string]string{"code": string(code), "message": msg})
}
