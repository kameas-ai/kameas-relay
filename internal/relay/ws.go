package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/coder/websocket"
)

// Two structurally disjoint message channels share each WebSocket (§2.3):
//
//	TEXT   — relay control messages (presence, the provisional-channel
//	         notification, routing errors), authored by the relay.
//	BINARY — E2E frames, authored by the host and device endpoints and
//	         forwarded byte-for-byte.
//
// The relay MUST NOT author a TEXT message whose content is derived from
// any BINARY frame's body. It cannot read one; the rule exists so that no
// future "helpful" summarization path is built that could.

// sendQueueDepth bounds per-connection buffering so a broadcast under the
// relay lock never blocks on a slow socket.
const sendQueueDepth = 256

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
	return &wsConn{c: c, send: make(chan outMsg, sendQueueDepth), closed: make(chan struct{})}
}

func (w *wsConn) sendText(data []byte) { w.enqueue(outMsg{websocket.MessageText, data}) }

// sendBinary enqueues a forwarded frame VERBATIM. The relay MUST NOT
// synthesize, rewrite, or default any header field (§10) — rewriting
// push_class or seq would break AD authentication by design — so the
// original wire bytes go out untouched.
func (w *wsConn) sendBinary(data []byte) { w.enqueue(outMsg{websocket.MessageBinary, data}) }

func (w *wsConn) enqueue(m outMsg) {
	select {
	case w.send <- m:
	case <-w.closed:
	default:
		// The peer is not draining. Dropping is the honest failure: the
		// relay MUST NOT retransmit or reorder (§10), and a device that
		// misses a live frame recovers through the seq-gap reconcile that
		// eviction already makes routine.
	}
}

func (w *wsConn) close(code websocket.StatusCode, reason string) {
	w.closeOnce.Do(func() {
		close(w.closed)
		_ = w.c.Close(code, reason)
	})
}

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

// accept upgrades the connection with the relay's read limit.
func (r *Relay) accept(w http.ResponseWriter, req *http.Request) (*websocket.Conn, error) {
	c, err := websocket.Accept(w, req, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return nil, err
	}
	// Slack above MaxFrameSize so the relay's own frame_too_large (4413)
	// check fires rather than the library's generic 1009 close: the
	// contract's close codes are part of the surface endpoints test against.
	c.SetReadLimit(int64(r.cfg.MaxFrameSize) + 4096)
	return c, nil
}

// ---------------------------------------------------------------------
// WSS /v1/host  (§2.1, §2.2)
// ---------------------------------------------------------------------

// handleHostWS authenticates and attaches a host.
//
// The host attaches ONCE and multiplexes every channel it is paired on over
// that single connection; frames are routed by the `channel` field in their
// header. `?host_id=` is the routing key and `?channel=` MUST NOT be
// accepted here.
//
// This is also the only place a §2.2 account binding is created. A device
// attach must never bind: without that rule, addressing a pairing window by
// host_id would let a stranger TOFU-bind an unknown host_id to their own
// account and lock the real host out of its own identifier.
func (r *Relay) handleHostWS(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	q := req.URL.Query()
	if q.Has("channel") {
		writeError(w, CodeProtocolViolation, "channel is not a host attach parameter")
		return
	}
	hostID := q.Get("host_id")
	if !validID(hostID) {
		writeError(w, CodeProtocolViolation, "host_id must be 22-char canonical base64url")
		return
	}
	ctx := req.Context()
	// §2.2: bind on successful attach; immutable thereafter — a differing
	// sub is refused with forbidden, never rebound, merged, or prompted.
	// Committed here, after authN succeeds and before the upgrade
	// completes, so a caller whose Dial returns can rely on the binding.
	if _, err := r.cfg.Store.BindHost(ctx, hostID, sub, r.cfg.Clock.Now()); err != nil {
		writeError(w, CodeForbidden, "host_id is registered to a different account")
		return
	}

	c, err := r.accept(w, req)
	if err != nil {
		return
	}
	conn := newWSConn(c)
	conn.role, conn.sub, conn.hostID = "host", sub, hostID

	r.mu.Lock()
	if r.hostConns[hostID] == nil {
		r.hostConns[hostID] = make(map[*wsConn]bool)
	}
	r.hostConns[hostID][conn] = true
	r.mu.Unlock()

	// Attach counts as liveness (§6).
	r.touchHost(ctx, hostID)

	// §6.1: current device-presence state, once, on host attach — the host
	// cannot choose class L vs class M without it, and a state that only
	// arrives on the next transition may never arrive at all.
	if pairings, err := r.cfg.Store.PairingsForHost(ctx, hostID); err == nil {
		for _, pr := range pairings {
			p, ok, err := r.cfg.Store.LookupDevicePresence(ctx, pr.ChannelID)
			if err != nil {
				continue
			}
			if !ok {
				p = DevicePresence{ChannelID: pr.ChannelID}
			}
			conn.sendText(devPresenceJSON(p))
		}
	}
	r.cfg.Logger.Info("host attached", "host_id", hostID)

	go conn.writer(ctx)
	defer func() {
		r.mu.Lock()
		delete(r.hostConns[hostID], conn)
		if len(r.hostConns[hostID]) == 0 {
			delete(r.hostConns, hostID)
		}
		r.mu.Unlock()
		// The idle horizon runs from last activity, not from first bind.
		_ = r.cfg.Store.TouchBinding(context.WithoutCancel(ctx), hostID, r.cfg.Clock.Now())
		conn.close(websocket.StatusNormalClosure, "")
		r.cfg.Logger.Info("host detached", "host_id", hostID)
	}()

	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		r.touchHost(ctx, hostID)
		if typ != websocket.MessageBinary {
			// TEXT from a host is a heartbeat; nothing else is defined, and
			// the relay does not parse it.
			continue
		}
		if !r.routeHostFrame(ctx, conn, data) {
			return
		}
	}
}

// routeHostFrame implements the §4.1 THREE-WAY host→device split. Returns
// false when the connection was closed.
//
//	device attached                    ⇒ forward live, verbatim
//	registered channel, device absent  ⇒ mailbox, REGARDLESS of push_class
//	unregistered / revoked / unknown   ⇒ drop + not_found TEXT to the host
//
// The middle arm is the one that is easy to get wrong: push_class governs
// whether a PUSH is also sent, not whether the frame is buffered.
// snapshot.* and rpc.response frames must still reach a device that
// reconnects, so a push_class of "none" is still mailboxed.
func (r *Relay) routeHostFrame(ctx context.Context, conn *wsConn, raw []byte) bool {
	if len(raw) > r.cfg.MaxFrameSize {
		conn.close(wssClose[CodeFrameTooLarge], string(CodeFrameTooLarge))
		return false
	}
	h, body, err := DecodeFrame(raw, r.cfg.MaxHeaderLen)
	if err != nil {
		conn.close(wssClose[CodeProtocolViolation], string(CodeProtocolViolation))
		return false
	}
	if !r.limiter.allow("hostframes:"+conn.hostID, r.cfg.Limits.HostFramesPerSec, r.cfg.Limits.HostFramesBurst) {
		conn.close(wssClose[CodeRateLimited], string(CodeRateLimited))
		return false
	}

	// Provisional (pairing) channel: forward to the window's pairing
	// attaches only. Provisional channels are NEVER mailboxed (§3.3).
	if win, ok, err := r.cfg.Store.WindowForHost(ctx, conn.hostID, r.cfg.Clock.Now()); err == nil && ok &&
		win.ProvisionalChannel == h.Channel {
		r.mu.Lock()
		conns := make([]*wsConn, 0, len(r.pairConns[win.WindowID]))
		for dc := range r.pairConns[win.WindowID] {
			conns = append(conns, dc)
		}
		r.mu.Unlock()
		for _, dc := range conns {
			dc.sendBinary(raw)
		}
		return true
	}

	pr, ok, err := r.cfg.Store.PairingByChannel(ctx, h.Channel)
	if err != nil || !ok || pr.HostID != conn.hostID {
		// Arm 3. not_found for a foreign host's channel too, so a host
		// cannot probe whether some other channel id exists.
		conn.sendText(controlError(CodeNotFound, h.Channel))
		r.cfg.Logger.Info("dropped host frame on unroutable channel",
			"host_id", conn.hostID, "channel", h.Channel)
		return true
	}

	if r.deviceAttachedNow(h.Channel) {
		// Arm 1. Push is suppressed: §5.2's only trigger condition is "the
		// target device has no live WSS attachment".
		r.mu.Lock()
		conns := make([]*wsConn, 0, len(r.devConns[h.Channel]))
		for dc := range r.devConns[h.Channel] {
			conns = append(conns, dc)
		}
		r.mu.Unlock()
		for _, dc := range conns {
			dc.sendBinary(raw)
		}
		return true
	}

	// Arm 2. The body is copied because raw aliases the read buffer; it is
	// copied WHOLE and stored WHOLE — never split, not even at the class-M
	// nonce boundary (§4, §10).
	bodyCopy := make([]byte, len(body))
	copy(bodyCopy, body)
	if err := r.cfg.Store.AppendMailbox(ctx, h.Channel, MailboxItem{
		Seq:       h.Seq,
		PushClass: h.PushClass,
		Body:      bodyCopy,
		StoredAt:  r.cfg.Clock.Now(),
	}, r.cfg.mailboxPolicy()); err != nil {
		r.cfg.Logger.Error("mailbox append failed", "channel", h.Channel)
		return true
	}
	r.maybePush(ctx, pr, h)
	return true
}

// maybePush applies the §5.2 trigger rule. The caller has established that
// the device has no live attachment.
//
// The relay MUST NOT infer a class: it reads the header field, which is
// AD-bound and therefore unforgeable by the relay.
func (r *Relay) maybePush(ctx context.Context, pr Pairing, h Header) {
	if h.PushClass == PushNone {
		return
	}
	tok, ok, err := r.cfg.Store.LookupAPNSToken(ctx, pr.DeviceID)
	if err != nil || !ok {
		return // no token registered — nowhere to push
	}
	var payload map[string]any
	switch h.PushClass {
	case PushWake:
		payload = wakePayload(h.Channel, h.Seq)
	case PushAttention:
		payload = attentionPayload(pr.HostLabel, h.Channel, h.Seq)
	default:
		return
	}
	if err := r.cfg.Pusher.Push(ctx, Push{
		DeviceID: pr.DeviceID, Token: tok.Token, Env: tok.Env, Payload: payload,
	}); err != nil {
		// A push failure must not change routing: the frame is already
		// mailboxed and the device will find it on reconnect.
		r.cfg.Logger.Warn("apns push failed", "device_id", pr.DeviceID, "channel", h.Channel)
	}
}

// ---------------------------------------------------------------------
// WSS /v1/device  (§2.1, §3.2)
// ---------------------------------------------------------------------

// handleDeviceWS dispatches the two device attach modes of §2.1:
//
//	?host=<22ch>     pairing attach, addressed by host_id (§3.2)
//	?channel=<22ch>  durable attach, exactly one channel per connection
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

// devicePairingAttach admits a §3.2 pairing attach.
//
// THE PATH HAS EXACTLY TWO OUTCOMES: accept, or one identical
// `window_closed` refusal — for unknown host_id, host_id known but unbound,
// account mismatch, no window open, window expired, malformed host id, AND
// attach-rate excess.
//
// Anything distinguishable would be a WINDOW-EXISTENCE ORACLE: because the
// device addresses the window by host_id (which the QR carries), a party
// holding only a host_id could otherwise probe whether the operator is
// currently displaying a pairing QR. Collapsing every refusal means a party
// without the QR learns nothing — not even that the host_id exists. Same
// discipline as the host's coarse pair_failed, one layer out.
//
// Note what is NOT here: this path never creates or modifies an account
// binding. Only /v1/host binds.
func (r *Relay) devicePairingAttach(w http.ResponseWriter, req *http.Request, sub, hostWire string) {
	// One refusal, one message, for every cause.
	refuse := func() { writeError(w, CodeWindowClosed, "no open pairing window") }

	if !validID(hostWire) {
		refuse()
		return
	}
	ctx := req.Context()
	now := r.cfg.Clock.Now()
	b, bound, err := r.cfg.Store.LookupBinding(ctx, hostWire, now)
	if err != nil || !bound || b.AccountSub != sub {
		refuse()
		return
	}
	win, open, err := r.cfg.Store.WindowForHost(ctx, hostWire, now)
	if err != nil || !open {
		refuse()
		return
	}
	// §3.3 flood guard. Excess yields window_closed like everything else
	// here; a distinguishable rate_limited would re-open the oracle.
	ok, err := r.cfg.Store.CountWindowAttach(ctx, win.WindowID, r.cfg.Limits.PairingAttachesPerWindow)
	if err != nil || !ok {
		refuse()
		return
	}

	c, err := r.accept(w, req)
	if err != nil {
		return
	}
	conn := newWSConn(c)
	conn.role, conn.sub, conn.winID = "pairing-device", sub, win.WindowID

	// §3.2: on accept, the first server message conveys the SAME
	// provisional channel the host received at window creation. This is
	// normative (ADR Decision 4 / review finding B2): without it the two
	// endpoints compute different AD for pairing frames 4–5 and pairing
	// fails closed for no reason.
	first, _ := json.Marshal(map[string]string{"provisional_channel": win.ProvisionalChannel})
	conn.sendText(first)

	r.mu.Lock()
	if r.pairConns[win.WindowID] == nil {
		r.pairConns[win.WindowID] = make(map[*wsConn]bool)
	}
	r.pairConns[win.WindowID][conn] = true
	r.mu.Unlock()
	r.cfg.Logger.Info("device pairing-attached", "host_id", hostWire, "window_id", win.WindowID)

	r.deviceReadLoop(ctx, conn, win.ProvisionalChannel, func() {
		r.mu.Lock()
		if m := r.pairConns[win.WindowID]; m != nil {
			delete(m, conn)
			if len(m) == 0 {
				delete(r.pairConns, win.WindowID)
			}
		}
		r.mu.Unlock()
	})
}

// deviceChannelAttach admits a durable attach: exactly one channel per
// connection, so a device paired to N hosts opens N connections.
func (r *Relay) deviceChannelAttach(w http.ResponseWriter, req *http.Request, sub string) {
	channel := req.URL.Query().Get("channel")
	if !validID(channel) {
		writeError(w, CodeProtocolViolation, "channel must be 22-char canonical base64url")
		return
	}
	ctx := req.Context()
	pr, ec := r.authorizeChannel(ctx, channel, sub)
	if ec != "" {
		writeError(w, ec, "channel is not available to this account")
		return
	}
	r.mu.Lock()
	overCap := r.cfg.Limits.DeviceAttachPerChannel > 0 &&
		len(r.devConns[channel]) >= r.cfg.Limits.DeviceAttachPerChannel
	r.mu.Unlock()
	if overCap {
		writeErrorRetry(w, CodeRateLimited, "concurrent attachment limit for this channel", 60)
		return
	}

	c, err := r.accept(w, req)
	if err != nil {
		return
	}
	conn := newWSConn(c)
	conn.role, conn.sub, conn.channel = "device", sub, channel

	r.mu.Lock()
	if r.devConns[channel] == nil {
		r.devConns[channel] = make(map[*wsConn]bool)
	}
	r.devConns[channel][conn] = true
	first := len(r.devConns[channel]) == 1
	r.mu.Unlock()

	// §6: current host presence, once, immediately on device attach.
	// Without it a cold-opened app cannot render US5's banner until the
	// first transition, which may never come.
	hp, ok, err := r.cfg.Store.LookupHostPresence(ctx, pr.HostID)
	if err == nil {
		if !ok {
			hp = HostPresence{HostID: pr.HostID}
		}
		conn.sendText(hostPresenceJSON(hp))
	}
	if first {
		r.setDeviceAttached(ctx, channel, true)
	}
	r.cfg.Logger.Info("device attached", "channel", channel)

	r.deviceReadLoop(ctx, conn, channel, func() {
		r.mu.Lock()
		empty := false
		if m := r.devConns[channel]; m != nil {
			delete(m, conn)
			if len(m) == 0 {
				delete(r.devConns, channel)
				empty = true
			}
		}
		r.mu.Unlock()
		if empty {
			r.setDeviceAttached(context.WithoutCancel(ctx), channel, false)
		}
		r.cfg.Logger.Info("device detached", "channel", channel)
	})
}

// deviceReadLoop runs the shared device frame loop. boundChannel is the only
// channel this connection may send on — the durable channel, or the window's
// provisional channel.
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
		if !r.routeDeviceFrame(ctx, conn, boundChannel, data) {
			return
		}
	}
}

// routeDeviceFrame routes one device-originated frame. Returns false when
// the connection was closed.
func (r *Relay) routeDeviceFrame(ctx context.Context, conn *wsConn, boundChannel string, raw []byte) bool {
	if len(raw) > r.cfg.MaxFrameSize {
		conn.close(wssClose[CodeFrameTooLarge], string(CodeFrameTooLarge))
		return false
	}
	h, _, err := DecodeFrame(raw, r.cfg.MaxHeaderLen)
	if err != nil {
		conn.close(wssClose[CodeProtocolViolation], string(CodeProtocolViolation))
		return false
	}
	// §5.2 / e2e-envelope §2: push_class is HOST-SET ONLY. A device frame
	// carrying any other value is a protocol violation and the connection
	// MUST be closed — otherwise a compromised device could spam an
	// operator's phone.
	if h.PushClass != PushNone {
		conn.close(wssClose[CodeProtocolViolation], "device-set push_class")
		return false
	}
	if h.Channel != boundChannel {
		conn.close(wssClose[CodeForbidden], "frame channel does not match attachment")
		return false
	}
	if !r.limiter.allow("devframes:"+conn.sub+":"+boundChannel,
		r.cfg.Limits.DeviceFramesPerSec, r.cfg.Limits.DeviceFramesBurst) {
		conn.close(wssClose[CodeRateLimited], string(CodeRateLimited))
		return false
	}

	var hostID string
	if conn.role == "pairing-device" {
		win, ok, err := r.cfg.Store.LookupWindow(ctx, conn.winID)
		if err != nil || !ok {
			conn.close(wssClose[CodeWindowClosed], string(CodeWindowClosed))
			return false
		}
		hostID = win.HostID
	} else {
		pr, ok, err := r.cfg.Store.PairingByChannel(ctx, boundChannel)
		if err != nil || !ok {
			// Pairing deleted while attached: the channel is no longer
			// authorized for anyone.
			conn.close(wssClose[CodeForbidden], string(CodeForbidden))
			return false
		}
		hostID = pr.HostID
	}

	r.mu.Lock()
	conns := make([]*wsConn, 0, len(r.hostConns[hostID]))
	for hc := range r.hostConns[hostID] {
		conns = append(conns, hc)
	}
	r.mu.Unlock()

	// §4.1: there is NO device→host mailbox — FR-17 forbids command
	// queueing. Host not attached ⇒ drop the frame AND tell the device so.
	// peer_unavailable is a TEXT control message, never a close, and the
	// connection stays up: FR-17 forbids queueing, it does not permit lying
	// about delivery.
	if len(conns) == 0 {
		conn.sendText(controlError(CodePeerUnavailable, h.Channel))
		return true
	}
	for _, hc := range conns {
		hc.sendBinary(raw)
	}
	return true
}
