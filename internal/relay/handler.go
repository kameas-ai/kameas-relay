package relay

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

// maxRequestBody caps every JSON body we will read. The largest legitimate
// body is a pairing registration with a 64-byte label.
const maxRequestBody = 8 << 10

// Handler returns the full relay-api.md surface as an http.Handler.
func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()

	// §7.3 — unauthenticated, no operator data, and MUST NOT enumerate
	// channels, devices, hosts, or counts thereof. Both endpoints answer a
	// fixed string for exactly that reason: a health endpoint that reports
	// "3 hosts attached" is an unauthenticated observable about operator
	// activity, which §XII condition 3 makes a defect.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("GET /readyz", r.handleReadyz)

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

// handleReadyz reports readiness including JWKS reachability (§7.3). It
// answers ready/not-ready and nothing else — no dependency names, no error
// text, no counts.
func (r *Relay) handleReadyz(w http.ResponseWriter, req *http.Request) {
	if r.cfg.Ready != nil {
		ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
		defer cancel()
		if err := r.cfg.Ready(ctx); err != nil {
			r.cfg.Logger.Warn("readiness probe failed") // no error text: it could name an internal host
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "not ready")
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}

// decodeJSON reads a bounded, strictly-typed JSON body.
func decodeJSON(req *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(req.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing content after JSON body")
	}
	return nil
}

// ---------------------------------------------------------------------
// §3.1 / §3.3 — pairing windows
// ---------------------------------------------------------------------

// handleOpenWindow opens a pairing window (§3.1).
//
// Three rules make this endpoint what it is: the host_id must already be
// bound to the caller (§2.2 — binding happens only on a /v1/host attach);
// at most ONE window may be open per host_id, so a second POST invalidates
// the first (two live windows mean two provisional channels and an
// ambiguous AD); and the provisional channel the caller receives here is
// the SAME value the device receives at pairing attach, which is normative
// (ADR-remote-pairing-crypto Decision 4 / review finding B2) because the
// two endpoints otherwise compute different AD and pairing fails closed for
// no reason.
func (r *Relay) handleOpenWindow(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	var body struct {
		HostID string `json:"host_id"`
	}
	if err := decodeJSON(req, &body); err != nil || !validID(body.HostID) {
		writeError(w, CodeProtocolViolation, "body must be {\"host_id\":\"<22ch base64url>\"}")
		return
	}
	rate, burst := perHour(r.cfg.Limits.PairingWindowsPerHour)
	if !r.limiter.allow("windows:"+body.HostID, rate, burst) {
		writeErrorRetry(w, CodeRateLimited, "pairing-window limit", 3600)
		return
	}
	ctx := req.Context()
	if ec := r.authorizeHostID(ctx, body.HostID, sub); ec != "" {
		writeError(w, ec, "host_id is not bound to this account")
		return
	}

	win := Window{
		WindowID: NewID(),
		HostID:   body.HostID,
		// 16 relay-generated random bytes, 22ch base64url (§3.1). Metadata
		// only: no key material is involved and the relay learns nothing by
		// choosing it.
		ProvisionalChannel: NewID(),
		ExpiresAt:          r.cfg.Clock.Now().Add(r.cfg.WindowTTL),
	}
	displaced, err := r.cfg.Store.OpenWindow(ctx, win)
	if err != nil {
		writeError(w, CodeInternal, "could not open pairing window")
		return
	}
	if displaced != nil {
		r.tearDownWindow(displaced.WindowID)
	}

	r.mu.Lock()
	if !r.closed {
		id := win.WindowID
		r.winTimer[id] = r.cfg.Clock.AfterFunc(r.cfg.WindowTTL, func() { r.expireWindow(id) })
	}
	r.mu.Unlock()
	r.cfg.Logger.Info("pairing window opened", "window_id", win.WindowID, "host_id", win.HostID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"window_id":           win.WindowID,
		"provisional_channel": win.ProvisionalChannel,
		"expires_at":          win.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// handleCloseWindow is the host-facing DELETE. window_id is a host-facing
// handle for exactly this and for invalidation; it never appears on a
// device path (§2.1).
func (r *Relay) handleCloseWindow(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	ctx := req.Context()
	id := req.PathValue("id")
	win, ok, err := r.cfg.Store.LookupWindow(ctx, id)
	switch {
	case err != nil:
		writeError(w, CodeInternal, "could not read pairing window")
		return
	case !ok:
		writeError(w, CodeNotFound, "unknown pairing window")
		return
	}
	if ec := r.authorizeHostID(ctx, win.HostID, sub); ec != "" {
		writeError(w, ec, "window belongs to a different account")
		return
	}
	r.expireWindow(id)
	w.WriteHeader(http.StatusNoContent)
}

// expireWindow deletes a window and closes its pairing attaches with 4410.
// Provisional channels are NEVER mailboxed, so there is nothing buffered to
// drop (§3.3).
func (r *Relay) expireWindow(id string) {
	_, ok, err := r.cfg.Store.DeleteWindow(context.Background(), id)
	if err != nil || !ok {
		return
	}
	r.tearDownWindow(id)
	r.cfg.Logger.Info("pairing window closed", "window_id", id)
}

// tearDownWindow stops a window's expiry timer and closes every pairing
// attach riding it.
func (r *Relay) tearDownWindow(id string) {
	r.mu.Lock()
	if t, ok := r.winTimer[id]; ok {
		t.Stop()
		delete(r.winTimer, id)
	}
	conns := r.pairConns[id]
	delete(r.pairConns, id)
	r.mu.Unlock()
	for c := range conns {
		c.close(wssClose[CodeWindowClosed], string(CodeWindowClosed))
	}
}

// ---------------------------------------------------------------------
// §3.4 — durable pairings
// ---------------------------------------------------------------------

// handleCreatePairing registers a durable pairing.
//
// channel_id is HOST-generated, not relay-assigned: the host delivers the
// same value to the device inside the encrypted pair.complete, which is what
// makes every post-pairing AD `channel` value host-authenticated rather than
// relay-chosen. The relay's only say is refusing reuse.
func (r *Relay) handleCreatePairing(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	rate, burst := perHour(r.cfg.Limits.PairingsPerHour)
	if !r.limiter.allow("pairings:"+sub, rate, burst) {
		writeErrorRetry(w, CodeRateLimited, "pairing registration limit", 3600)
		return
	}
	var body struct {
		ChannelID string  `json:"channel_id"`
		HostID    string  `json:"host_id"`
		DeviceID  string  `json:"device_id"`
		HostLabel *string `json:"host_label"`
	}
	if err := decodeJSON(req, &body); err != nil ||
		!validID(body.ChannelID) || !validID(body.HostID) || !validID(body.DeviceID) {
		writeError(w, CodeProtocolViolation, "channel_id, host_id, device_id must be 22-char canonical base64url")
		return
	}
	if body.HostLabel != nil && len(*body.HostLabel) > 64 {
		writeError(w, CodeProtocolViolation, "host_label exceeds 64 UTF-8 bytes")
		return
	}
	ctx := req.Context()
	if ec := r.authorizeHostID(ctx, body.HostID, sub); ec != "" {
		writeError(w, ec, "host_id is not bound to this account")
		return
	}
	pr := Pairing{
		PairingID:  NewID(),
		ChannelID:  body.ChannelID,
		HostID:     body.HostID,
		DeviceID:   body.DeviceID,
		AccountSub: sub,
		HostLabel:  body.HostLabel,
		CreatedAt:  r.cfg.Clock.Now(),
	}
	switch err := r.cfg.Store.CreatePairing(ctx, pr); {
	case errors.Is(err, ErrChannelRegistered):
		writeError(w, CodeConflict, "channel_id already registered")
		return
	case err != nil:
		writeError(w, CodeInternal, "could not register pairing")
		return
	}
	r.cfg.Logger.Info("pairing registered", "pairing_id", pr.PairingID, "channel", pr.ChannelID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"pairing_id": pr.PairingID})
}

// handlePatchPairing updates or clears host_label.
//
// Clearing it ({"host_label": null}) removes loc-args from every subsequent
// push, leaving a fixed non-operator-derived string. That is the §XII
// condition-5 reduction control, and it is STRONGER than the condition's
// "category-only" floor because the reduced payload carries no category
// either — the relay never had one.
func (r *Relay) handlePatchPairing(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	var raw map[string]json.RawMessage
	if err := decodeJSON(req, &raw); err != nil {
		writeError(w, CodeProtocolViolation, "malformed body")
		return
	}
	labelRaw, has := raw["host_label"]
	if !has || len(raw) != 1 {
		writeError(w, CodeProtocolViolation, "body must carry exactly host_label (string or null)")
		return
	}
	var label *string
	if string(labelRaw) != "null" {
		var s string
		if err := json.Unmarshal(labelRaw, &s); err != nil || len(s) > 64 {
			writeError(w, CodeProtocolViolation, "host_label must be a string of at most 64 UTF-8 bytes, or null")
			return
		}
		label = &s
	}
	ctx := req.Context()
	pr, ok, err := r.cfg.Store.LookupPairing(ctx, req.PathValue("id"))
	switch {
	case err != nil:
		writeError(w, CodeInternal, "could not read pairing")
		return
	case !ok:
		writeError(w, CodeNotFound, "unknown pairing")
		return
	case pr.AccountSub != sub:
		writeError(w, CodeForbidden, "pairing belongs to a different account")
		return
	}
	if err := r.cfg.Store.SetHostLabel(ctx, pr.PairingID, label); err != nil {
		writeError(w, CodeInternal, "could not update pairing")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleDeletePairing is FR-8 revocation at the metadata layer.
//
// Deregistration here is defense in depth ONLY. Actual revocation is the
// host deleting the device record, after which the pairing root is not
// computable and any frames still in the mailbox become permanently
// undecryptable. The relay MUST NOT be treated as an enforcement point.
func (r *Relay) handleDeletePairing(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	ctx := req.Context()
	pr, ok, err := r.cfg.Store.LookupPairing(ctx, req.PathValue("id"))
	switch {
	case err != nil:
		writeError(w, CodeInternal, "could not read pairing")
		return
	case !ok:
		writeError(w, CodeNotFound, "unknown pairing")
		return
	case pr.AccountSub != sub:
		writeError(w, CodeForbidden, "pairing belongs to a different account")
		return
	}
	if _, _, err := r.cfg.Store.DeletePairing(ctx, pr.PairingID); err != nil {
		writeError(w, CodeInternal, "could not delete pairing")
		return
	}
	r.mu.Lock()
	conns := r.devConns[pr.ChannelID]
	delete(r.devConns, pr.ChannelID)
	r.mu.Unlock()
	for c := range conns {
		c.close(wssClose[CodeForbidden], "pairing deleted")
	}
	r.cfg.Logger.Info("pairing deleted", "pairing_id", pr.PairingID, "channel", pr.ChannelID)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------
// §4 — mailbox
// ---------------------------------------------------------------------

// handleMailboxGet serves the host→device ciphertext mailbox.
//
// Reads are NON-DESTRUCTIVE (§4): items expire by TTL or cap eviction only,
// never by having been fetched, because the app and its Notification
// Service Extension both fetch the same item.
//
// There is no device→host mailbox and there never will be: FR-17 forbids
// command queueing.
func (r *Relay) handleMailboxGet(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	ctx := req.Context()
	channel := req.PathValue("id")
	pr, ec := r.authorizeChannel(ctx, channel, sub)
	if ec != "" {
		writeError(w, ec, "channel is not available to this account")
		return
	}
	rate, burst := perMinute(r.cfg.Limits.MailboxGetPerMin)
	if !r.limiter.allow("mbxget:"+pr.DeviceID, rate, burst) {
		writeErrorRetry(w, CodeRateLimited, "mailbox fetch limit", 60)
		return
	}

	var after uint64
	if s := req.URL.Query().Get("after"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			writeError(w, CodeProtocolViolation, "after must be a uint64")
			return
		}
		after = v
	}
	limit := 64
	if s := req.URL.Query().Get("limit"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			writeError(w, CodeProtocolViolation, "limit must be a positive integer")
			return
		}
		limit = min(v, 256)
	}

	items, nextAfter, truncated, err := r.cfg.Store.FetchMailbox(ctx, channel, after, limit, r.cfg.Clock.Now(), r.cfg.MailboxTTL)
	if err != nil {
		writeError(w, CodeInternal, "could not read mailbox")
		return
	}

	type frameOut struct {
		Seq uint64 `json:"seq"`
		// PushClass is returned UNMODIFIED from the frame that was
		// buffered: the device rebuilds the AD from {channel, seq,
		// push_class}, so altering it breaks authentication — which is the
		// intended failure mode, not a bug to work around.
		PushClass string `json:"push_class"`
		// Body is the class-M body as ONE opaque blob. The nonce ‖
		// ciphertext split is the receiver's (e2e-envelope.md §1.2).
		Body string `json:"body"`
	}
	resp := struct {
		Frames    []frameOut `json:"frames"`
		NextAfter uint64     `json:"next_after"`
		Truncated bool       `json:"truncated"`
	}{Frames: make([]frameOut, 0, len(items)), NextAfter: nextAfter, Truncated: truncated}
	for _, it := range items {
		resp.Frames = append(resp.Frames, frameOut{
			Seq:       it.Seq,
			PushClass: it.PushClass,
			Body:      b64.EncodeToString(it.Body),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------
// §5.1 — APNs token registration
// ---------------------------------------------------------------------

// handleAPNSRegister stores a device's APNs token.
//
// The body is {token, env} and NOTHING else. There is no `categories`
// field: the relay has no category to enforce a subscription against, and
// storing unenforceable state is the worst of both. Strict decoding refuses
// a stale client that still sends one, rather than accepting and ignoring
// it — an ignored field is a field someone will later assume works.
func (r *Relay) handleAPNSRegister(w http.ResponseWriter, req *http.Request) {
	sub, ec := r.bearerSub(req)
	if ec != "" {
		writeError(w, ec, "invalid or missing bearer token")
		return
	}
	deviceID := req.PathValue("id")
	rate, burst := perHour(r.cfg.Limits.APNSRegsPerHour)
	if !r.limiter.allow("apns:"+deviceID, rate, burst) {
		writeErrorRetry(w, CodeRateLimited, "APNs registration limit", 3600)
		return
	}
	var body struct {
		Token string `json:"token"`
		Env   string `json:"env"`
	}
	if err := decodeJSON(req, &body); err != nil ||
		body.Token == "" || (body.Env != "sandbox" && body.Env != "production") {
		writeError(w, CodeProtocolViolation, "body must be exactly {token, env: sandbox|production}")
		return
	}
	ctx := req.Context()
	pairings, err := r.cfg.Store.PairingsForDevice(ctx, deviceID)
	if err != nil {
		writeError(w, CodeInternal, "could not read pairings")
		return
	}
	if len(pairings) == 0 {
		writeError(w, CodeNotFound, "unknown device")
		return
	}
	owned := false
	for _, p := range pairings {
		if p.AccountSub == sub {
			owned = true
			break
		}
	}
	if !owned {
		writeError(w, CodeForbidden, "device is paired to a different account")
		return
	}
	if err := r.cfg.Store.PutAPNSToken(ctx, APNSToken{DeviceID: deviceID, Token: body.Token, Env: body.Env}); err != nil {
		writeError(w, CodeInternal, "could not store APNs token")
		return
	}
	// Token bytes are never logged (§9).
	r.cfg.Logger.Info("apns token registered", "device_id", deviceID, "env", body.Env)
	w.WriteHeader(http.StatusNoContent)
}
