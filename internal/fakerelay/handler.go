package fakerelay

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// Handler returns the full relay-api.md surface as an http.Handler,
// mountable on an httptest.Server or any http.Server.
func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	// §7.3 — unauthenticated, no operator data, no enumeration.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		// The fake's TokenValidator needs no JWKS, so readiness == liveness.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /v1/host", r.handleHostWS)
	mux.HandleFunc("GET /v1/device", r.handleDeviceWS)
	mux.HandleFunc("POST /v1/pairing-windows", r.handleOpenWindow)
	mux.HandleFunc("DELETE /v1/pairing-windows/{id}", r.handleCloseWindow)
	mux.HandleFunc("POST /v1/pairings", r.handleCreatePairing)
	mux.HandleFunc("PATCH /v1/pairings/{id}", r.handlePatchPairing)
	mux.HandleFunc("DELETE /v1/pairings/{id}", r.handleDeletePairing)
	mux.HandleFunc("GET /v1/channels/{id}/frames", r.handleMailboxGet)
	mux.HandleFunc("PUT /v1/devices/{id}/apns", r.handleAPNSRegister)
	return mux
}

// ---------------------------------------------------------------------
// §3.1 / §3.3 — pairing windows
// ---------------------------------------------------------------------

// handleOpenWindow opens a pairing window (§3.1): body {"host_id"}, the
// host_id MUST already be bound to the caller (§2.2 — binding happens
// only on /v1/host attach), and at most one window may be open per
// host_id — a second POST invalidates the first.
func (r *Relay) handleOpenWindow(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	var body struct {
		HostID string `json:"host_id"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil || !validChannelID(body.HostID) {
		writeError(w, codeProtocolViolation, "body must be {\"host_id\":\"<22ch base64url>\"}")
		return
	}
	rate, burst := perHour(r.cfg.Limits.PairingWindowsPerHour)
	if !r.limiter.allow("windows:"+body.HostID, rate, burst) {
		writeErrorRetry(w, codeRateLimited, "pairing-window limit", 3600)
		return
	}
	r.mu.Lock()
	if b, ok := r.bindingFor(body.HostID); !ok || b.sub != sub {
		r.mu.Unlock()
		writeError(w, codeForbidden, "host_id is not bound to this account")
		return
	}
	// §3.1: at most one open window per host_id — invalidate the prior
	// one; its window_id and provisional channel become unusable
	// immediately and its pairing attaches get the 4410 treatment.
	var displaced map[*wsConn]bool
	if old, ok := r.windowForHost(body.HostID); ok {
		displaced = r.expireWindowLocked(old)
	}
	win := &window{
		id:                 NewID(),
		hostID:             body.HostID,
		provisionalChannel: NewID(), // 16 relay-generated random bytes, 22ch base64url (§3.1)
		expiresAt:          r.cfg.Clock.Now().Add(r.cfg.WindowTTL),
	}
	winID := win.id
	win.timer = r.cfg.Clock.AfterFunc(r.cfg.WindowTTL, func() { r.expireWindow(winID) })
	r.windows[win.id] = win
	r.provChans[win.provisionalChannel] = win
	resp := map[string]string{
		"window_id":           win.id,
		"provisional_channel": win.provisionalChannel,
		"expires_at":          win.expiresAt.UTC().Format(time.RFC3339),
	}
	r.mu.Unlock()
	for c := range displaced {
		c.close(wssClose[codeWindowClosed], string(codeWindowClosed))
	}
	r.cfg.Logger.Info("pairing window opened", "window_id", winID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (r *Relay) handleCloseWindow(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	id := req.PathValue("id")
	r.mu.Lock()
	win, ok := r.windows[id]
	if !ok {
		r.mu.Unlock()
		writeError(w, codeNotFound, "unknown pairing window")
		return
	}
	if b, bound := r.bindingFor(win.hostID); !bound || b.sub != sub {
		r.mu.Unlock()
		writeError(w, codeForbidden, "window belongs to a different account")
		return
	}
	r.mu.Unlock()
	r.expireWindow(id)
	w.WriteHeader(http.StatusNoContent)
}

// expireWindow closes a window: drops the provisional channel, closes
// pairing attaches (4410), and discards any state. Provisional channels
// are never mailboxed, so there is nothing buffered to drop (§3.3).
func (r *Relay) expireWindow(id string) {
	r.mu.Lock()
	win, ok := r.windows[id]
	if !ok {
		r.mu.Unlock()
		return
	}
	conns := r.expireWindowLocked(win)
	r.mu.Unlock()
	for c := range conns {
		c.close(wssClose[codeWindowClosed], string(codeWindowClosed))
	}
	r.cfg.Logger.Info("pairing window closed", "window_id", id)
}

// expireWindowLocked marks a window closed and unindexes it, returning
// the pairing attaches for the caller to close outside the lock. Caller
// holds r.mu.
func (r *Relay) expireWindowLocked(win *window) map[*wsConn]bool {
	if win.closed {
		return nil
	}
	win.closed = true
	if win.timer != nil {
		win.timer.Stop()
	}
	delete(r.provChans, win.provisionalChannel)
	delete(r.windows, win.id)
	conns := r.pairConns[win.id]
	delete(r.pairConns, win.id)
	return conns
}

// ---------------------------------------------------------------------
// §3.4 — durable pairings
// ---------------------------------------------------------------------

func (r *Relay) handleCreatePairing(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	rate, burst := perHour(r.cfg.Limits.PairingsPerHour)
	if !r.limiter.allow("pairings:"+sub, rate, burst) {
		writeErrorRetry(w, codeRateLimited, "pairing registration limit", 3600)
		return
	}
	var body struct {
		ChannelID string  `json:"channel_id"`
		HostID    string  `json:"host_id"`
		DeviceID  string  `json:"device_id"`
		HostLabel *string `json:"host_label"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil ||
		!validChannelID(body.ChannelID) || !validChannelID(body.HostID) || !validChannelID(body.DeviceID) {
		writeError(w, codeProtocolViolation, "channel_id, host_id, device_id must be 22-char canonical base64url")
		return
	}
	if body.HostLabel != nil && len(*body.HostLabel) > 64 {
		writeError(w, codeProtocolViolation, "host_label exceeds 64 UTF-8 bytes")
		return
	}
	r.mu.Lock()
	if b, ok := r.bindingFor(body.HostID); !ok || b.sub != sub {
		r.mu.Unlock()
		writeError(w, codeForbidden, "host_id is not bound to this account")
		return
	}
	// channel_id is HOST-generated (§3.4); the relay only refuses reuse.
	if _, exists := r.channels[body.ChannelID]; exists {
		r.mu.Unlock()
		writeError(w, codeConflict, "channel_id already registered")
		return
	}
	pr := &pairing{
		id:         NewID(),
		channelID:  body.ChannelID,
		hostID:     body.HostID,
		deviceID:   body.DeviceID,
		accountSub: sub,
		hostLabel:  body.HostLabel,
		createdAt:  r.cfg.Clock.Now(),
	}
	r.pairings[pr.id] = pr
	r.channels[pr.channelID] = pr
	pid := pr.id
	r.mu.Unlock()
	r.cfg.Logger.Info("pairing registered", "pairing_id", pid, "channel", body.ChannelID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"pairing_id": pid})
}

// handlePatchPairing updates or clears host_label. Clearing it
// ({"host_label": null}) is the §XII condition-5 category-only toggle.
func (r *Relay) handlePatchPairing(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(req.Body).Decode(&raw); err != nil {
		writeError(w, codeProtocolViolation, "malformed body")
		return
	}
	labelRaw, has := raw["host_label"]
	if !has {
		writeError(w, codeProtocolViolation, "body must carry host_label (string or null)")
		return
	}
	var label *string
	if string(labelRaw) != "null" {
		var s string
		if err := json.Unmarshal(labelRaw, &s); err != nil || len(s) > 64 {
			writeError(w, codeProtocolViolation, "host_label must be a string of at most 64 UTF-8 bytes, or null")
			return
		}
		label = &s
	}
	r.mu.Lock()
	pr, ok := r.pairings[req.PathValue("id")]
	switch {
	case !ok:
		r.mu.Unlock()
		writeError(w, codeNotFound, "unknown pairing")
		return
	case pr.accountSub != sub:
		r.mu.Unlock()
		writeError(w, codeForbidden, "pairing belongs to a different account")
		return
	}
	pr.hostLabel = label
	r.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (r *Relay) handleDeletePairing(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	r.mu.Lock()
	pr, ok := r.pairings[req.PathValue("id")]
	switch {
	case !ok:
		r.mu.Unlock()
		writeError(w, codeNotFound, "unknown pairing")
		return
	case pr.accountSub != sub:
		r.mu.Unlock()
		writeError(w, codeForbidden, "pairing belongs to a different account")
		return
	}
	delete(r.pairings, pr.id)
	delete(r.channels, pr.channelID)
	delete(r.mailboxes, pr.channelID)
	delete(r.chanPres, pr.channelID)
	// APNs tokens are retained "until re-registration or pairing
	// deletion" (§8): drop the token unless another pairing still
	// references the device.
	stillPaired := false
	for _, other := range r.pairings {
		if other.deviceID == pr.deviceID {
			stillPaired = true
			break
		}
	}
	if !stillPaired {
		delete(r.apnsTok, pr.deviceID)
	}
	conns := r.devConns[pr.channelID]
	delete(r.devConns, pr.channelID)
	r.mu.Unlock()
	for c := range conns {
		c.close(wssClose[codeForbidden], "pairing deleted")
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------
// §4 — mailbox
// ---------------------------------------------------------------------

func (r *Relay) handleMailboxGet(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	channel := req.PathValue("id")
	r.mu.Lock()
	pr, ok := r.channels[channel]
	if !ok {
		r.mu.Unlock()
		writeError(w, codeNotFound, "unknown channel")
		return
	}
	if pr.accountSub != sub {
		r.mu.Unlock()
		writeError(w, codeForbidden, "channel is not paired to this account")
		return
	}
	r.mu.Unlock()

	rate, burst := perMinute(r.cfg.Limits.MailboxGetPerMin)
	if !r.limiter.allow("mbxget:"+pr.deviceID, rate, burst) {
		writeErrorRetry(w, codeRateLimited, "mailbox fetch limit", 60)
		return
	}

	var after uint64
	if s := req.URL.Query().Get("after"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			writeError(w, codeProtocolViolation, "after must be a uint64")
			return
		}
		after = v
	}
	limit := 64
	if s := req.URL.Query().Get("limit"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			writeError(w, codeProtocolViolation, "limit must be a positive integer")
			return
		}
		if v > 256 {
			v = 256
		}
		limit = v
	}

	type frameOut struct {
		Seq       uint64 `json:"seq"`
		PushClass string `json:"push_class"`
		Body      string `json:"body"`
	}
	resp := struct {
		Frames    []frameOut `json:"frames"`
		NextAfter uint64     `json:"next_after"`
		Truncated bool       `json:"truncated"`
	}{Frames: []frameOut{}}

	r.mu.Lock()
	if mb := r.mailboxes[channel]; mb != nil {
		items, nextAfter, truncated := mb.get(after, limit, r.cfg.Clock.Now(), r.cfg.MailboxTTL)
		resp.NextAfter, resp.Truncated = nextAfter, truncated
		for _, it := range items {
			// The class-M body is ONE opaque blob (§4): the relay MUST
			// NOT split, offset into, or otherwise structure it — the
			// nonce ‖ ciphertext layout is the RECEIVER's business
			// (e2e-envelope.md §1.2). Reads are non-destructive: the NSE
			// and the app may both fetch the same item.
			resp.Frames = append(resp.Frames, frameOut{
				Seq:       it.seq,
				PushClass: it.pushClass,
				Body:      b64.EncodeToString(it.body),
			})
		}
	} else {
		resp.NextAfter = after
	}
	r.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------
// §5.1 — APNs token registration
// ---------------------------------------------------------------------

func (r *Relay) handleAPNSRegister(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	deviceID := req.PathValue("id")
	rate, burst := perHour(r.cfg.Limits.APNSRegsPerHour)
	if !r.limiter.allow("apns:"+deviceID, rate, burst) {
		writeErrorRetry(w, codeRateLimited, "APNs registration limit", 3600)
		return
	}
	// §5.1: body is {token, env} and NOTHING else. There is no
	// categories field — the relay has no category to enforce a
	// subscription against, and storing unenforceable state is the worst
	// of both. Strict decoding refuses stale registrations that still
	// send one.
	var body struct {
		Token string `json:"token"`
		Env   string `json:"env"`
	}
	dec := json.NewDecoder(req.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil ||
		body.Token == "" || (body.Env != "sandbox" && body.Env != "production") {
		writeError(w, codeProtocolViolation, "body must be exactly {token, env: sandbox|production}")
		return
	}
	r.mu.Lock()
	// AuthZ per path parameter (§2): the device must appear in a pairing
	// record for this account.
	var owned, exists bool
	for _, pr := range r.pairings {
		if pr.deviceID == deviceID {
			exists = true
			if pr.accountSub == sub {
				owned = true
				break
			}
		}
	}
	if !exists {
		r.mu.Unlock()
		writeError(w, codeNotFound, "unknown device")
		return
	}
	if !owned {
		r.mu.Unlock()
		writeError(w, codeForbidden, "device is paired to a different account")
		return
	}
	r.apnsTok[deviceID] = &apnsReg{deviceID: deviceID, token: body.Token, env: body.Env}
	r.mu.Unlock()
	r.cfg.Logger.Info("apns token registered", "device_id", deviceID) // token bytes never logged (§9)
	w.WriteHeader(http.StatusNoContent)
}
