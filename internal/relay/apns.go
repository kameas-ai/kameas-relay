package relay

import (
	"context"
	"log/slog"
	"sync"
)

// The relay does not know a frame's notification category — and MUST NOT
// learn it (relay-api.md §5.3, ruled 2026-08-06, candidate (d)).
//
// Alert pushes are generic, text-free, and category-free: a fixed loc-key
// names a string in the app bundle, `mutable-content: 1` wakes the device's
// Notification Service Extension, and the NSE fetches the frame over the
// E2E path, decrypts it, and rewrites title / body / categoryIdentifier
// locally. The relay MUST NOT send alert.title, alert.body, or aps.category
// in any form, and nothing derived from prompts, tool calls, agent output,
// file paths, or command text may enter a payload — the relay could not
// obtain any of it if it tried, and this rule exists so no future
// "convenience" path is built to give it one.

// LocKeyGeneric is the fixed loc-key of the §5.3 closed alert payload. The
// visible fallback text is authored by the app bundle, never by the relay.
const LocKeyGeneric = "KENAZ_NOTIF_GENERIC"

// Push is one APNs delivery: the token to send to and the closed §5.3
// payload.
type Push struct {
	DeviceID string
	Token    string
	Env      string
	// Payload is exactly the closed schema of §5.3. A payload containing
	// any field not in that schema MUST fail the SC-2 APNs audit test.
	Payload map[string]any
}

// Pusher delivers a Push. It is an interface for two reasons: the LLE relay
// runs without Apple credentials, and the SC-2 audit needs to inspect every
// payload the relay would have sent.
//
// # Why no real APNs client ships in this lane
//
// Sending to Apple needs a provider authentication token — an ES256-signed
// JWT over the team's `.p8` key — and that key is operator item [OP] 0.7,
// which tasks.md gates Phase 4 on rather than Phase 2. Two notes for
// whoever implements it, because the choice interacts with the deny-list:
//
//   - Provider-token auth requires SIGNING, which is a private key in relay
//     scope. That is a new, narrower allow-list entry than internal/jwtverify
//     (which only ever holds public keys) and needs its own review: the key
//     is an Apple credential, never E2E material, so it does not weaken the
//     condition-2 claim — but the deny-list must say so explicitly rather
//     than by omission.
//   - Certificate-based APNs auth avoids the new crypto surface entirely,
//     because a TLS client certificate lives in the one cryptographic
//     surface §1 already grants the relay. It is the more conservative
//     option and should be priced before the provider-token one is chosen.
type Pusher interface {
	// Push delivers p. Errors are logged as connection metadata and never
	// propagate to an endpoint: a push failure must not change routing.
	Push(ctx context.Context, p Push) error
}

// NopPusher discards pushes. It is the default so a relay booted without
// APNs configuration behaves correctly (mailboxing still happens; only the
// notification is absent) rather than failing at the wrong layer.
type NopPusher struct{}

func (NopPusher) Push(context.Context, Push) error { return nil }

// LogPusher records that a push WOULD have been sent, at metadata level
// only: device id, environment, and whether the payload was an alert or a
// silent wake. It never logs the token bytes (§9) and there is no text in a
// §5.3 payload to log even if it wanted to.
type LogPusher struct{ Logger *slog.Logger }

func (l LogPusher) Push(_ context.Context, p Push) error {
	if l.Logger == nil {
		return nil
	}
	kind := "wake"
	if aps, ok := p.Payload["aps"].(map[string]any); ok {
		if _, alert := aps["alert"]; alert {
			kind = "attention"
		}
	}
	l.Logger.Info("apns push suppressed (no provider configured)",
		"device_id", p.DeviceID, "env", p.Env, "kind", kind)
	return nil
}

// RecordingPusher captures pushes in memory for tests and for the SC-2
// APNs audit.
type RecordingPusher struct {
	mu     sync.Mutex
	pushes []Push
}

func (r *RecordingPusher) Push(_ context.Context, p Push) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pushes = append(r.pushes, p)
	return nil
}

// Pushes returns a snapshot of everything recorded.
func (r *RecordingPusher) Pushes() []Push {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Push, len(r.pushes))
	copy(out, r.pushes)
	return out
}

// Reset clears the recording.
func (r *RecordingPusher) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pushes = nil
}

// attentionPayload builds the closed §5.3 alert shape — the ONLY alert
// form. loc-args carries AT MOST the operator-authored host_label and
// nothing else; clearing the label (the §XII condition-5 reduction control)
// removes loc-args entirely, leaving a fixed, non-operator-derived string.
func attentionPayload(hostLabel *string, channel string, seq uint64) map[string]any {
	alert := map[string]any{"loc-key": LocKeyGeneric}
	if hostLabel != nil {
		alert["loc-args"] = []any{*hostLabel}
	}
	return map[string]any{
		"aps": map[string]any{
			"alert":           alert,
			"mutable-content": 1,
			"sound":           "default",
			"thread-id":       channel,
		},
		"ch": channel,
		"sq": seq,
	}
}

// wakePayload builds the closed §5.3 silent shape: no alert, no sound, no
// category.
func wakePayload(channel string, seq uint64) map[string]any {
	return map[string]any{
		"aps": map[string]any{"content-available": 1},
		"ch":  channel,
		"sq":  seq,
	}
}
