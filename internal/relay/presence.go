package relay

import (
	"context"
	"encoding/json"
	"time"
)

// Presence — relay-api.md §6 and §6.1.
//
// Presence is the ONLY plaintext state the phone consumes (FR-2). It is
// published as a relay CONTROL message on the TEXT channel (§2.3),
// structurally outside the frame stream, and endpoints MUST NOT treat it as
// authenticated state: it drives the offline banner and control disabling,
// never a security decision.

// presenceMsg is the §6 host-presence control message.
type presenceMsg struct {
	HostID   string `json:"host_id"`
	Online   bool   `json:"online"`
	LastSeen string `json:"last_seen"`
}

// devPresenceMsg is the §6.1 device-presence control message published to
// the host.
//
// This is not symmetry for its own sake: the host cannot choose a frame's
// construction without it. Host→device frames are class L while the device
// is attached and class M once it is not, and that choice is the SENDER's —
// the relay MUST NOT make it (§4.1).
type devPresenceMsg struct {
	Presence string `json:"presence"` // always "device"
	Channel  string `json:"channel"`
	Attached bool   `json:"attached"`
	LastSeen string `json:"last_seen"`
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func hostPresenceJSON(p HostPresence) []byte {
	b, _ := json.Marshal(presenceMsg{HostID: p.HostID, Online: p.Online, LastSeen: rfc3339(p.LastSeen)})
	return b
}

func devPresenceJSON(p DevicePresence) []byte {
	b, _ := json.Marshal(devPresenceMsg{
		Presence: "device", Channel: p.ChannelID, Attached: p.Attached, LastSeen: rfc3339(p.LastSeen),
	})
	return b
}

// touchHost records host liveness: flips the host online if needed
// (broadcasting the transition) and re-arms the §6 offline deadline.
//
// Any inbound traffic counts as liveness — the contract mandates a 15 s
// heartbeat, but a host that is actively forwarding frames is self-evidently
// alive and must not be flipped offline for not also heartbeating.
func (r *Relay) touchHost(ctx context.Context, hostID string) {
	now := r.cfg.Clock.Now()
	p, ok, err := r.cfg.Store.LookupHostPresence(ctx, hostID)
	if err != nil {
		return
	}
	if !ok {
		p = HostPresence{HostID: hostID}
	}
	p.LastSeen = now
	flipped := !p.Online
	p.Online = true
	if err := r.cfg.Store.PutHostPresence(ctx, p); err != nil {
		return
	}
	if flipped {
		r.broadcastHostPresence(ctx, p)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if t, ok := r.presTimer[hostID]; ok {
		t.Reset(r.cfg.OfflineAfter)
		return
	}
	r.presTimer[hostID] = r.cfg.Clock.AfterFunc(r.cfg.OfflineAfter, func() { r.presenceDeadline(hostID) })
}

// presenceDeadline fires when a host has been silent for OfflineAfter
// (contract: 30 s, satisfying US5's ≤30 s bound).
func (r *Relay) presenceDeadline(hostID string) {
	ctx := context.Background()
	p, ok, err := r.cfg.Store.LookupHostPresence(ctx, hostID)
	if err != nil || !ok {
		return
	}
	silent := r.cfg.Clock.Now().Sub(p.LastSeen)
	if silent < r.cfg.OfflineAfter {
		// A heartbeat raced the timer; re-arm for the remainder rather than
		// flipping a live host offline.
		r.mu.Lock()
		if t, ok := r.presTimer[hostID]; ok && !r.closed {
			t.Reset(r.cfg.OfflineAfter - silent)
		}
		r.mu.Unlock()
		return
	}
	if !p.Online {
		return
	}
	p.Online = false
	if err := r.cfg.Store.PutHostPresence(ctx, p); err != nil {
		return
	}
	r.broadcastHostPresence(ctx, p)
	r.cfg.Logger.Info("host presence offline", "host_id", hostID)
}

// broadcastHostPresence sends the §6 message to every device durably
// attached to a channel of this host.
func (r *Relay) broadcastHostPresence(ctx context.Context, p HostPresence) {
	pairings, err := r.cfg.Store.PairingsForHost(ctx, p.HostID)
	if err != nil {
		return
	}
	msg := hostPresenceJSON(p)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pr := range pairings {
		for c := range r.devConns[pr.ChannelID] {
			c.sendText(msg)
		}
	}
}

// setDeviceAttached records a §6.1 attachment transition and publishes it to
// every attached host connection for that channel's host. Only 0↔1
// transitions publish.
func (r *Relay) setDeviceAttached(ctx context.Context, channelID string, attached bool) {
	p, ok, err := r.cfg.Store.LookupDevicePresence(ctx, channelID)
	if err != nil {
		return
	}
	if !ok {
		p = DevicePresence{ChannelID: channelID}
	}
	changed := p.Attached != attached
	p.Attached = attached
	p.LastSeen = r.cfg.Clock.Now()
	if err := r.cfg.Store.PutDevicePresence(ctx, p); err != nil || !changed {
		return
	}
	pr, ok, err := r.cfg.Store.PairingByChannel(ctx, channelID)
	if err != nil || !ok {
		return
	}
	msg := devPresenceJSON(p)
	r.mu.Lock()
	defer r.mu.Unlock()
	for hc := range r.hostConns[pr.HostID] {
		hc.sendText(msg)
	}
}

// deviceAttachedNow reports the live attachment state used by the §4.1
// router. It reads CONNECTIONS, not the presence record, because a routing
// decision must reflect the socket table at this instant rather than the
// last published transition.
func (r *Relay) deviceAttachedNow(channelID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.devConns[channelID]) > 0
}
