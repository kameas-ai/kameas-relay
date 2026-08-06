package fakerelay

import (
	"encoding/json"
	"time"
)

// presenceMsg is the relay control message of relay-api.md §6, published
// on every attached device connection for the host. It is structurally
// outside the frame stream: control messages ride WebSocket TEXT
// messages, frames ride BINARY messages (see README "Interpretations").
type presenceMsg struct {
	HostID   string `json:"host_id"`
	Online   bool   `json:"online"`
	LastSeen string `json:"last_seen"`
}

// touchHost records host liveness: flips online if needed (broadcasting
// the flip) and re-arms the 30 s offline timer. Caller holds r.mu.
func (r *Relay) touchHost(hostID string) {
	now := r.cfg.Clock.Now()
	p, ok := r.presence[hostID]
	if !ok {
		p = &hostPresence{}
		r.presence[hostID] = p
	}
	p.lastSeen = now
	if !p.online {
		p.online = true
		r.broadcastPresence(hostID, p)
	}
	if p.timer == nil {
		p.timer = r.cfg.Clock.AfterFunc(r.cfg.OfflineAfter, func() { r.presenceDeadline(hostID) })
	} else {
		p.timer.Reset(r.cfg.OfflineAfter)
	}
}

// presenceDeadline fires when a host has been silent for OfflineAfter.
func (r *Relay) presenceDeadline(hostID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.presence[hostID]
	if !ok {
		return
	}
	now := r.cfg.Clock.Now()
	silent := now.Sub(p.lastSeen)
	if silent < r.cfg.OfflineAfter {
		// A heartbeat raced the timer; re-arm for the remainder.
		p.timer.Reset(r.cfg.OfflineAfter - silent)
		return
	}
	if p.online {
		p.online = false
		r.broadcastPresence(hostID, p)
	}
}

// broadcastPresence sends the presence control message to every device
// connection attached (durably) to a channel of this host. Caller holds
// r.mu.
func (r *Relay) broadcastPresence(hostID string, p *hostPresence) {
	msg := r.presenceJSON(hostID, p)
	for channelID, conns := range r.devConns {
		pr, ok := r.channels[channelID]
		if !ok || pr.hostID != hostID {
			continue
		}
		for c := range conns {
			c.sendText(msg)
		}
	}
}

func (r *Relay) presenceJSON(hostID string, p *hostPresence) []byte {
	var last string
	if !p.lastSeen.IsZero() {
		last = p.lastSeen.UTC().Format(time.RFC3339)
	}
	b, _ := json.Marshal(presenceMsg{HostID: hostID, Online: p.online, LastSeen: last})
	return b
}

// devPresenceMsg is the §6.1 device-presence control message published
// to the host on its TEXT channel. It is what lets the host choose
// class L (device attached) vs class M (device detached) — the relay
// MUST NOT make that choice itself (§4.1).
type devPresenceMsg struct {
	Presence string `json:"presence"` // always "device"
	Channel  string `json:"channel"`
	Attached bool   `json:"attached"`
	LastSeen string `json:"last_seen"`
}

func (r *Relay) devPresenceJSON(channelID string, p *devPresence) []byte {
	var last string
	if !p.lastSeen.IsZero() {
		last = p.lastSeen.UTC().Format(time.RFC3339)
	}
	b, _ := json.Marshal(devPresenceMsg{Presence: "device", Channel: channelID, Attached: p.attached, LastSeen: last})
	return b
}

// setDevAttached records a §6.1 attachment transition for a durable
// channel and publishes it to every attached host connection for that
// channel's host. Only 0↔1 transitions publish. Caller holds r.mu.
func (r *Relay) setDevAttached(channelID string, attached bool) {
	p, ok := r.chanPres[channelID]
	if !ok {
		p = &devPresence{}
		r.chanPres[channelID] = p
	}
	changed := p.attached != attached
	p.attached = attached
	p.lastSeen = r.cfg.Clock.Now()
	if !changed {
		return
	}
	pr, ok := r.channels[channelID]
	if !ok {
		return
	}
	msg := r.devPresenceJSON(channelID, p)
	for hc := range r.hostConns[pr.hostID] {
		hc.sendText(msg)
	}
}
