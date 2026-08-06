package fakerelay

import "sync"

// The relay does not know a frame's notification category — and MUST
// NOT learn it (relay-api.md §5.3, ruled 2026-08-06, candidate (d)).
// Alert pushes are generic, text-free, and category-free: a fixed
// loc-key names an app-bundle string, mutable-content wakes the
// device's Notification Service Extension, and the NSE decrypts over
// the E2E path and rewrites title/body/categoryIdentifier locally.
// The relay MUST NOT send alert.title, alert.body, or aps.category.

// LocKeyGeneric is the fixed loc-key of the §5.3 closed alert payload.
// The visible fallback text is authored by the app bundle, never by the
// relay.
const LocKeyGeneric = "KENAZ_NOTIF_GENERIC"

// Push is one recorded would-be APNs delivery.
type Push struct {
	DeviceID string
	Token    string
	Env      string
	// Payload is exactly the closed schema of relay-api.md §5.3. Tests
	// assert the full key set — any extra field is an SC-2 audit failure.
	Payload map[string]any
}

// APNSRecorder is the mock APNs sender: an in-memory, test-inspectable
// list of every push the relay would have sent. The fake never talks to
// Apple.
type APNSRecorder struct {
	mu     sync.Mutex
	pushes []Push
}

// Pushes returns a snapshot of all recorded pushes.
func (r *APNSRecorder) Pushes() []Push {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Push, len(r.pushes))
	copy(out, r.pushes)
	return out
}

// Reset clears the recorded pushes.
func (r *APNSRecorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pushes = nil
}

func (r *APNSRecorder) record(p Push) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pushes = append(r.pushes, p)
}

// attentionPayload builds the closed §5.3 alert shape — the ONLY alert
// form. loc-args carries at most the operator-authored host_label
// (lock-screen fallback only); clearing the label (§XII condition-5
// reduction) removes loc-args entirely, leaving a fixed non-operator
// string.
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

// wakePayload builds the closed §5.3 silent shape: no alert, no sound,
// no category.
func wakePayload(channel string, seq uint64) map[string]any {
	return map[string]any{
		"aps": map[string]any{"content-available": 1},
		"ch":  channel,
		"sq":  seq,
	}
}
