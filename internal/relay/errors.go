package relay

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/coder/websocket"
)

// ErrCode is the CLOSED error set of relay-api.md §7.2. No other code may
// ever appear on the wire.
type ErrCode string

const (
	CodeUnauthenticated   ErrCode = "unauthenticated"
	CodeForbidden         ErrCode = "forbidden"
	CodeAuthUnavailable   ErrCode = "auth_unavailable"
	CodeNotFound          ErrCode = "not_found"
	CodeConflict          ErrCode = "conflict"
	CodeFrameTooLarge     ErrCode = "frame_too_large"
	CodeProtocolViolation ErrCode = "protocol_violation"
	CodeRateLimited       ErrCode = "rate_limited"
	CodeWindowClosed      ErrCode = "window_closed"
	CodeInternal          ErrCode = "internal"
	// CodePeerUnavailable is a TEXT control message ONLY (§4.1, §7.2). It
	// has no HTTP status and no WSS close code, and the connection stays
	// up: FR-17 forbids queueing, it does not permit lying about delivery.
	// It must never appear in httpStatus or wssClose.
	CodePeerUnavailable ErrCode = "peer_unavailable"
)

var httpStatus = map[ErrCode]int{
	CodeUnauthenticated:   http.StatusUnauthorized,
	CodeForbidden:         http.StatusForbidden,
	CodeAuthUnavailable:   http.StatusServiceUnavailable,
	CodeNotFound:          http.StatusNotFound,
	CodeConflict:          http.StatusConflict,
	CodeFrameTooLarge:     http.StatusRequestEntityTooLarge,
	CodeProtocolViolation: http.StatusBadRequest,
	CodeRateLimited:       http.StatusTooManyRequests,
	CodeWindowClosed:      http.StatusGone,
	CodeInternal:          http.StatusInternalServerError,
}

// wssClose maps a code to its WSS close code. not_found and conflict have
// none in the contract: they only occur pre-upgrade or on REST.
var wssClose = map[ErrCode]websocket.StatusCode{
	CodeUnauthenticated:   4401,
	CodeForbidden:         4403,
	CodeAuthUnavailable:   4503,
	CodeFrameTooLarge:     4413,
	CodeProtocolViolation: 4400,
	CodeRateLimited:       4429,
	CodeWindowClosed:      4410,
	CodeInternal:          4500,
}

// writeError emits the contract error body {"code","message"}.
//
// `message` MUST NOT include token bytes, claim values, emails, channel
// content, or any frame body (§7.2), so every caller in this package passes
// a FIXED string literal. That is the enforcement: there is no code path
// where a runtime value reaches this parameter, which is what the SC-2
// error-surface assertion depends on.
func writeError(w http.ResponseWriter, code ErrCode, msg string) {
	writeErrorRetry(w, code, msg, 0)
}

func writeErrorRetry(w http.ResponseWriter, code ErrCode, msg string, retryAfterSecs int) {
	w.Header().Set("Content-Type", "application/json")
	if code == CodeRateLimited {
		if retryAfterSecs <= 0 {
			retryAfterSecs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecs))
	}
	status, ok := httpStatus[code]
	if !ok {
		status = http.StatusInternalServerError
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": string(code), "message": msg})
}

// controlError builds a §4.1 routing-error TEXT control message
// {"error":"<code>","channel":"<22ch>"}, sent on the sender's own
// connection. Never a close.
func controlError(code ErrCode, channel string) []byte {
	b, _ := json.Marshal(map[string]string{"error": string(code), "channel": channel})
	return b
}
