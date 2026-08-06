package fakerelay

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/coder/websocket"
)

// wsConn wraps one attached WebSocket. All outbound traffic goes through
// the send queue and a single writer goroutine, so broadcasts under r.mu
// never block on the network.
type wsConn struct {
	c    *websocket.Conn
	send chan outMsg

	role    string // "host" | "device" | "pairing-device"
	sub     string
	hostID  string // host attach
	channel string // durable device attach
	winID   string // pairing attach

	closeOnce sync.Once
	closed    chan struct{}
}

type outMsg struct {
	typ  websocket.MessageType
	data []byte
}

func newWSConn(c *websocket.Conn) *wsConn {
	return &wsConn{c: c, send: make(chan outMsg, 256), closed: make(chan struct{})}
}

// sendText enqueues a relay control message. Control messages ride the
// TEXT channel only (§2.3); frames ride BINARY.
func (w *wsConn) sendText(data []byte) { w.enqueue(outMsg{websocket.MessageText, data}) }

// sendBinary enqueues a forwarded frame verbatim. The relay MUST NOT
// synthesize, rewrite, or default any header field (relay-api.md §10),
// so the original wire bytes are forwarded untouched.
func (w *wsConn) sendBinary(data []byte) { w.enqueue(outMsg{websocket.MessageBinary, data}) }

func (w *wsConn) enqueue(m outMsg) {
	select {
	case w.send <- m:
	case <-w.closed:
	default:
		// Queue full: drop. The fake favors liveness; a real relay would
		// apply backpressure here.
	}
}

// close closes the connection with a contract WSS close code.
func (w *wsConn) close(code websocket.StatusCode, reason string) {
	w.closeOnce.Do(func() {
		close(w.closed)
		_ = w.c.Close(code, reason)
	})
}

// writer drains the send queue onto the socket.
func (w *wsConn) writer(ctx context.Context) {
	for {
		select {
		case m := <-w.send:
			if err := w.c.Write(ctx, m.typ, m.data); err != nil {
				return
			}
		case <-w.closed:
			return
		case <-ctx.Done():
			return
		}
	}
}

// ---------------------------------------------------------------------
// WSS /v1/host  (relay-api.md §2.1, §2.2)
// ---------------------------------------------------------------------

// handleHostWS authenticates and attaches a host connection
// (?host_id=<22ch>; one connection multiplexes every channel). The §2.2
// account binding is created here and ONLY here — device attaches never
// bind. AuthN failures reject before the upgrade completes (§2).
func (r *Relay) handleHostWS(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	q := req.URL.Query()
	if q.Has("channel") {
		// §2.1: ?channel= MUST NOT be accepted on /v1/host.
		writeError(w, codeProtocolViolation, "channel is not a host attach parameter")
		return
	}
	hostID := q.Get("host_id")
	if !validChannelID(hostID) {
		writeError(w, codeProtocolViolation, "host_id must be 22-char canonical base64url")
		return
	}
	r.mu.Lock()
	// §2.2: bind on successful attach; immutable thereafter — a
	// differing sub is refused with forbidden, never rebound. (The bind
	// is committed here, after authN/authZ succeed and the upgrade is
	// about to complete, so a caller whose Dial returns can rely on the
	// binding existing.)
	if !r.bindHost(hostID, sub) {
		r.mu.Unlock()
		writeError(w, codeForbidden, "host_id is registered to a different account")
		return
	}
	r.mu.Unlock()

	c, err := websocket.Accept(w, req, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	// Slack above MaxFrameSize so the relay's own frame_too_large (4413)
	// check fires rather than the library's generic 1009 close.
	c.SetReadLimit(int64(r.cfg.MaxFrameSize) + 4096)
	conn := newWSConn(c)
	conn.role, conn.sub, conn.hostID = "host", sub, hostID

	r.mu.Lock()
	if r.hostConns[hostID] == nil {
		r.hostConns[hostID] = make(map[*wsConn]bool)
	}
	r.hostConns[hostID][conn] = true
	r.touchHost(hostID) // attach counts as liveness
	// §6.1: current device-presence state, once, on host attach — the
	// host cannot choose class L vs class M without it.
	for channelID, pr := range r.channels {
		if pr.hostID != hostID {
			continue
		}
		p, ok := r.chanPres[channelID]
		if !ok {
			p = &devPresence{}
		}
		conn.sendText(r.devPresenceJSON(channelID, p))
	}
	r.mu.Unlock()
	r.cfg.Logger.Info("host attached", "host_id", hostID)

	ctx := req.Context()
	go conn.writer(ctx)
	defer func() {
		r.mu.Lock()
		delete(r.hostConns[hostID], conn)
		if b, ok := r.bindings[hostID]; ok {
			b.lastAttach = r.cfg.Clock.Now() // idle horizon runs from last activity
		}
		r.mu.Unlock()
		conn.close(websocket.StatusNormalClosure, "")
		r.cfg.Logger.Info("host detached", "host_id", hostID)
	}()

	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.touchHost(hostID) // any inbound traffic is liveness; heartbeat is a TEXT message
		r.mu.Unlock()
		if typ != websocket.MessageBinary {
			continue // TEXT from a host = heartbeat / control; nothing else defined
		}
		if !r.hostFrame(conn, data) {
			return
		}
	}
}

// hostFrame routes one host-originated frame per the §4.1 three-way
// split. Returns false when the connection was closed. Caller does not
// hold r.mu.
func (r *Relay) hostFrame(conn *wsConn, raw []byte) bool {
	if len(raw) > r.cfg.MaxFrameSize {
		conn.close(wssClose[codeFrameTooLarge], string(codeFrameTooLarge))
		return false
	}
	h, body, err := DecodeFrame(raw, r.cfg.MaxHeaderLen)
	if err != nil {
		conn.close(wssClose[codeProtocolViolation], string(codeProtocolViolation))
		return false
	}
	if !r.limiter.allow("hostframes:"+conn.hostID, r.cfg.Limits.HostFramesPerSec, r.cfg.Limits.HostFramesBurst) {
		conn.close(wssClose[codeRateLimited], string(codeRateLimited))
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Provisional (pairing) channel: forward to pairing attaches only.
	// Provisional channels are NEVER mailboxed (relay-api.md §3.3).
	if win, ok := r.provChans[h.Channel]; ok {
		if win.hostID != conn.hostID || win.closed {
			conn.sendText(controlError(codeNotFound, h.Channel))
			return true
		}
		for dc := range r.pairConns[win.id] {
			dc.sendBinary(raw)
		}
		return true
	}

	pr, ok := r.channels[h.Channel]
	if !ok || pr.hostID != conn.hostID {
		// §4.1 arm 3: unregistered, revoked, or another host's channel —
		// drop + not_found TEXT control message. (not_found for both, so
		// a host cannot probe whether a foreign channel id exists.)
		conn.sendText(controlError(codeNotFound, h.Channel))
		r.cfg.Logger.Info("dropped host frame on unroutable channel", "host_id", conn.hostID, "channel", h.Channel)
		return true
	}

	if conns := r.devConns[h.Channel]; len(conns) > 0 {
		// §4.1 arm 1: device attached — forward verbatim; push
		// suppressed (§5.2 "no live WSS attachment" is the only push
		// condition).
		for dc := range conns {
			dc.sendBinary(raw)
		}
		return true
	}

	// §4.1 arm 2: registered channel, device detached — mailbox
	// REGARDLESS of push_class (snapshot.* and rpc.response must reach a
	// reconnecting device too); push_class governs only whether a push
	// is ALSO sent.
	mb := r.mailboxes[h.Channel]
	if mb == nil {
		mb = &mailbox{}
		r.mailboxes[h.Channel] = mb
	}
	bodyCopy := make([]byte, len(body))
	copy(bodyCopy, body)
	mb.append(mbxItem{seq: h.Seq, pushClass: h.PushClass, body: bodyCopy, at: r.cfg.Clock.Now()},
		r.cfg.Clock.Now(), r.cfg.MailboxTTL, r.cfg.MailboxMaxFrames, r.cfg.MailboxMaxBytes)
	r.maybePush(pr, h)
	return true
}

// maybePush records a would-be APNs delivery per the §5.2 trigger rule.
// Caller holds r.mu; caller has already established the device has no
// live attachment.
func (r *Relay) maybePush(pr *pairing, h Header) {
	if h.PushClass == PushNone {
		return
	}
	reg, ok := r.apnsTok[pr.deviceID]
	if !ok {
		return // no token registered — nowhere to push
	}
	var payload map[string]any
	switch h.PushClass {
	case PushWake:
		payload = wakePayload(h.Channel, h.Seq)
	case PushAttention:
		// Generic, category-free NSE-wake alert (§5.3): the device
		// rewrites it locally after decrypting over the E2E path.
		payload = attentionPayload(pr.hostLabel, h.Channel, h.Seq)
	default:
		return
	}
	r.recorder.record(Push{DeviceID: pr.deviceID, Token: reg.token, Env: reg.env, Payload: payload})
}

// ---------------------------------------------------------------------
// WSS /v1/device  (relay-api.md §2.1, §3.2)
// ---------------------------------------------------------------------

// handleDeviceWS handles both attach modes of §2.1:
//
//	?host=<22ch>     — pairing attach, addressed by host_id (§3.2); the
//	                   relay resolves the single open window; first
//	                   server message is {"provisional_channel"}.
//	?channel=<22ch>  — durable attach to a paired channel.
func (r *Relay) handleDeviceWS(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	if hostWire := req.URL.Query().Get("host"); hostWire != "" {
		r.devicePairingAttach(w, req, sub, hostWire)
		return
	}
	r.deviceChannelAttach(w, req, sub)
}

// devicePairingAttach admits a §3.2 pairing attach. The path has exactly
// two outcomes: accept, or one byte-identical `window_closed` refusal —
// for unknown host_id, unbound host_id, account mismatch, no open
// window, expired window, malformed host id, AND attach-rate excess.
// Anything distinguishable would be a window-existence oracle: a party
// without the QR must learn nothing, not even that the host_id exists.
// A pairing attach also MUST NOT create or modify an account binding —
// only /v1/host binds (§3.2).
func (r *Relay) devicePairingAttach(w http.ResponseWriter, req *http.Request, sub, hostWire string) {
	refuse := func() { writeError(w, codeWindowClosed, "no open pairing window") }
	if !validChannelID(hostWire) {
		refuse()
		return
	}
	r.mu.Lock()
	b, bound := r.bindingFor(hostWire)
	if !bound || b.sub != sub {
		r.mu.Unlock()
		refuse()
		return
	}
	win, open := r.windowForHost(hostWire)
	if !open || !r.cfg.Clock.Now().Before(win.expiresAt) {
		r.mu.Unlock()
		refuse()
		return
	}
	if r.cfg.Limits.PairingAttachesPerWindow > 0 && win.attaches >= r.cfg.Limits.PairingAttachesPerWindow {
		// §3.3: rate excess yields window_closed like every other
		// refusal here — a distinguishable rate_limited would re-open
		// the oracle.
		r.mu.Unlock()
		refuse()
		return
	}
	win.attaches++
	winID := win.id
	provisional := win.provisionalChannel
	r.mu.Unlock()

	c, err := websocket.Accept(w, req, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	// Slack above MaxFrameSize so the relay's own frame_too_large (4413)
	// check fires rather than the library's generic 1009 close.
	c.SetReadLimit(int64(r.cfg.MaxFrameSize) + 4096)
	conn := newWSConn(c)
	conn.role, conn.sub, conn.winID = "pairing-device", sub, winID

	// §3.2: on accept, first server message conveys the SAME provisional
	// channel the host received at window creation (normative — ADR B2).
	first, _ := json.Marshal(map[string]string{"provisional_channel": provisional})
	conn.sendText(first)

	r.mu.Lock()
	if r.pairConns[winID] == nil {
		r.pairConns[winID] = make(map[*wsConn]bool)
	}
	r.pairConns[winID][conn] = true
	r.mu.Unlock()
	r.cfg.Logger.Info("device pairing-attached", "host_id", hostWire)

	r.deviceReadLoop(req.Context(), conn, provisional, func() {
		r.mu.Lock()
		if m := r.pairConns[winID]; m != nil {
			delete(m, conn)
		}
		r.mu.Unlock()
	})
}

func (r *Relay) deviceChannelAttach(w http.ResponseWriter, req *http.Request, sub string) {
	channel := req.URL.Query().Get("channel")
	if !validChannelID(channel) {
		writeError(w, codeProtocolViolation, "channel must be 22-char canonical base64url")
		return
	}
	r.mu.Lock()
	pr, ok := r.channels[channel]
	switch {
	case !ok:
		r.mu.Unlock()
		writeError(w, codeNotFound, "unknown channel")
		return
	case pr.accountSub != sub:
		r.mu.Unlock()
		writeError(w, codeForbidden, "channel is not paired to this account")
		return
	case r.cfg.Limits.DeviceAttachPerChannel > 0 && len(r.devConns[channel]) >= r.cfg.Limits.DeviceAttachPerChannel:
		r.mu.Unlock()
		writeErrorRetry(w, codeRateLimited, "concurrent attachment limit for this channel", 60)
		return
	}
	hostID := pr.hostID
	r.mu.Unlock()

	c, err := websocket.Accept(w, req, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	// Slack above MaxFrameSize so the relay's own frame_too_large (4413)
	// check fires rather than the library's generic 1009 close.
	c.SetReadLimit(int64(r.cfg.MaxFrameSize) + 4096)
	conn := newWSConn(c)
	conn.role, conn.sub, conn.channel = "device", sub, channel

	r.mu.Lock()
	if r.devConns[channel] == nil {
		r.devConns[channel] = make(map[*wsConn]bool)
	}
	r.devConns[channel][conn] = true
	// §6: current host presence, once, immediately on device attach.
	p, ok := r.presence[hostID]
	if !ok {
		p = &hostPresence{}
	}
	conn.sendText(r.presenceJSON(hostID, p))
	// §6.1: publish the attach transition to the host.
	if len(r.devConns[channel]) == 1 {
		r.setDevAttached(channel, true)
	}
	r.mu.Unlock()
	r.cfg.Logger.Info("device attached", "channel", channel)

	r.deviceReadLoop(req.Context(), conn, channel, func() {
		r.mu.Lock()
		if m := r.devConns[channel]; m != nil {
			delete(m, conn)
			if len(m) == 0 {
				r.setDevAttached(channel, false)
			}
		}
		r.mu.Unlock()
		r.cfg.Logger.Info("device detached", "channel", channel)
	})
}

// deviceReadLoop runs the shared device frame loop. boundChannel is the
// only channel this connection may send on (durable channel or the
// window's provisional channel).
func (r *Relay) deviceReadLoop(ctx context.Context, conn *wsConn, boundChannel string, cleanup func()) {
	go conn.writer(ctx)
	defer func() {
		cleanup()
		conn.close(websocket.StatusNormalClosure, "")
	}()
	for {
		typ, data, err := conn.c.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			continue // no device-originated control messages are defined
		}
		if !r.deviceFrame(conn, boundChannel, data) {
			return
		}
	}
}

// deviceFrame routes one device-originated frame. Returns false when the
// connection was closed.
func (r *Relay) deviceFrame(conn *wsConn, boundChannel string, raw []byte) bool {
	if len(raw) > r.cfg.MaxFrameSize {
		conn.close(wssClose[codeFrameTooLarge], string(codeFrameTooLarge))
		return false
	}
	h, _, err := DecodeFrame(raw, r.cfg.MaxHeaderLen)
	if err != nil {
		conn.close(wssClose[codeProtocolViolation], string(codeProtocolViolation))
		return false
	}
	// §5.2 / e2e-envelope §2: push_class is host-set ONLY. A device
	// frame with any other value is a protocol violation and the
	// connection MUST be closed.
	if h.PushClass != PushNone {
		conn.close(wssClose[codeProtocolViolation], "device-set push_class")
		return false
	}
	if h.Channel != boundChannel {
		conn.close(wssClose[codeForbidden], "frame channel does not match attachment")
		return false
	}
	if !r.limiter.allow("devframes:"+conn.sub+":"+boundChannel, r.cfg.Limits.DeviceFramesPerSec, r.cfg.Limits.DeviceFramesBurst) {
		conn.close(wssClose[codeRateLimited], string(codeRateLimited))
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	var hostID string
	if conn.role == "pairing-device" {
		win, ok := r.windows[conn.winID]
		if !ok || win.closed {
			r.mu.Unlock()
			conn.close(wssClose[codeWindowClosed], string(codeWindowClosed))
			r.mu.Lock()
			return false
		}
		hostID = win.hostID
	} else {
		pr, ok := r.channels[boundChannel]
		if !ok {
			// Pairing deleted while attached: channel no longer authorized.
			r.mu.Unlock()
			conn.close(wssClose[codeForbidden], string(codeForbidden))
			r.mu.Lock()
			return false
		}
		hostID = pr.hostID
	}
	// §4.1: there is NO device→host mailbox (FR-17 forbids command
	// queueing). Host not attached ⇒ drop the frame AND tell the device
	// so — peer_unavailable is a TEXT control message, never a close,
	// and the connection stays up. FR-17 forbids queueing; it does not
	// permit lying about delivery.
	if len(r.hostConns[hostID]) == 0 {
		conn.sendText(controlError(codePeerUnavailable, h.Channel))
		return true
	}
	for hc := range r.hostConns[hostID] {
		hc.sendBinary(raw)
	}
	return true
}
