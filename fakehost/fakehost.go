// Package fakehost is the scripted host-side responder for spec-074
// tooling (Task 1.3): it opens a pairing window against a relay, prints
// the QR payload URI, completes pairing per ADR-remote-pairing-crypto
// Decision 8, establishes sessions, and then serves a scripted loop —
// snapshot.full on session start and on snapshot.request, scripted
// event envelopes, a scripted approval.request with first-decision-wins
// resolution and a fail-closed timeout deny, and canned transcript
// pages. Ledger lines (approval.granted|denied, remote.command per
// approval-events.md §6) are emitted as JSON on the configured writer.
//
// It is a host-side test instrument: it holds keys by design and is
// forbidden to relay code by the deny-list.
package fakehost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/kameas-ai/kameas-relay/e2ekit"
	"github.com/kameas-ai/kameas-relay/wire"
)

// ScriptEvent is one scripted `event` envelope, fired after AfterMS
// milliseconds from session establishment.
type ScriptEvent struct {
	AfterMS     int            `json:"after_ms"`
	Source      string         `json:"source"`
	Kind        string         `json:"kind"`
	WorkbenchID string         `json:"workbench_id,omitempty"`
	TaskID      string         `json:"task_id,omitempty"`
	Attrs       map[string]any `json:"attrs,omitempty"`
}

// LoadScript reads a JSON script file: an array of ScriptEvent.
func LoadScript(path string) ([]ScriptEvent, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var evs []ScriptEvent
	if err := json.Unmarshal(raw, &evs); err != nil {
		return nil, fmt.Errorf("fakehost: script %s: %w", path, err)
	}
	return evs, nil
}

// Config configures the fake host.
type Config struct {
	RelayOrigin string // e.g. http://127.0.0.1:7900
	Sub         string // fake account subject (Bearer fake-<sub>)
	HostName    string
	AutoConfirm bool
	ConfirmIn   io.Reader // pairing confirmation prompt input when !AutoConfirm (default os.Stdin)

	ApprovalAfter   time.Duration // scripted approval.request delay after session start (default 5s)
	ApprovalTimeout time.Duration // fail-closed deny (default 60s for demo)
	Script          []ScriptEvent // nil => built-in default status-flip loop
	EventInterval   time.Duration // built-in loop period (default 2s)
	WindowTTL       time.Duration // pairing window / QR TTL (default 5m)

	Out  io.Writer // QR, prompts, ledger JSON lines (default os.Stdout)
	Logf func(format string, args ...any)
}

func (c *Config) applyDefaults() {
	if c.Sub == "" {
		c.Sub = "demo-user"
	}
	if c.HostName == "" {
		c.HostName = "Fake Host"
	}
	if c.ConfirmIn == nil {
		c.ConfirmIn = os.Stdin
	}
	if c.ApprovalAfter == 0 {
		c.ApprovalAfter = 5 * time.Second
	}
	if c.ApprovalTimeout == 0 {
		c.ApprovalTimeout = 60 * time.Second
	}
	if c.EventInterval == 0 {
		c.EventInterval = 2 * time.Second
	}
	if c.WindowTTL == 0 {
		c.WindowTTL = 5 * time.Minute
	}
	if c.Out == nil {
		c.Out = os.Stdout
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

type pendingApproval struct {
	req   wire.ApprovalRequest
	timer *time.Timer
}

// deviceRecord is the single paired device (the fake pairs one device).
type deviceRecord struct {
	deviceID    [16]byte
	devPK       [32]byte
	channel     [16]byte
	channelWire string
	name        string
	roots       e2ekit.Roots
	kMbx        [32]byte
	h2dSent     uint64 // pairing-lifetime send counter, host→device
	d2h         *e2ekit.SeqTracker
	// attached mirrors the relay's §6.1 device-presence signal — the
	// input to the host's class-L vs class-M construction choice
	// (relay-api.md §4.1: that choice is the SENDER's). Default false:
	// until the relay says otherwise, spooled traffic goes class M.
	attached bool
}

// pairingState is the in-flight pairing handshake on the provisional
// channel.
type pairingState struct {
	step     int // 1 await pair.init done->2 await sess.header ->3 await pair.identity
	deviceID [16]byte
	devPK    [32]byte
	keys     e2ekit.SessionKeys
	push     *e2ekit.Stream // h2d
	pull     *e2ekit.Stream // d2h
	tracker  *e2ekit.SeqTracker
	h2dSent  uint64 // h2d pairing-lifetime counter while the record does not exist yet
}

// session is one established (or in-handshake) durable-channel session.
type session struct {
	keys        e2ekit.SessionKeys
	push        *e2ekit.Stream
	pull        *e2ekit.Stream
	step        int // 1 sent sess.accept, 2 got sess.header (sent confirm), 3 established
	cancelLoops context.CancelFunc
}

// Host is the scripted fake host.
type Host struct {
	cfg   Config
	httpc *http.Client

	hostID [16]byte
	hostPK [32]byte
	hostSK [32]byte

	attachedOnce sync.Once
	attachedCh   chan struct{} // closed once the host WSS attach succeeds

	mu              sync.Mutex
	conn            *websocket.Conn
	runCtx          context.Context
	windowID        string
	provChannelWire string
	token           [32]byte
	tokenLive       bool
	macFailures     int
	pairing         *pairingState
	device          *deviceRecord
	sess            *session
	pending         map[string]*pendingApproval
	resolved        map[string]wire.ApprovalResolved // TTL cache stand-in (bounded by demo lifetime)
	approvalSeq     int
	wbSuspended     bool
	started         time.Time
}

// New creates a fake host with a fresh CSPRNG identity.
func New(cfg Config) (*Host, error) {
	cfg.applyDefaults()
	pk, sk, err := e2ekit.NewKXKeypair()
	if err != nil {
		return nil, err
	}
	h := &Host{
		cfg:        cfg,
		httpc:      &http.Client{Timeout: 10 * time.Second},
		hostPK:     pk,
		hostSK:     sk,
		attachedCh: make(chan struct{}),
		pending:    make(map[string]*pendingApproval),
		resolved:   make(map[string]wire.ApprovalResolved),
		started:    time.Now(),
	}
	if _, err := rand.Read(h.hostID[:]); err != nil {
		return nil, err
	}
	return h, nil
}

// HostIDWire returns the host's routing id in wire form.
func (h *Host) HostIDWire() string { return e2ekit.EncodeChannelID(h.hostID) }

func (h *Host) bearer() string { return "Bearer fake-" + h.cfg.Sub }

func (h *Host) post(ctx context.Context, path string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.cfg.RelayOrigin+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", h.bearer())
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("fakehost: POST %s: %s: %s", path, resp.Status, msg)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// OpenPairingWindow opens a relay pairing window, mints the single-use
// token, and returns the QR URI plus the window id (the window id is
// NOT part of the QR — see the README note on the attach gap).
func (h *Host) OpenPairingWindow(ctx context.Context) (qrURI, windowID string, err error) {
	var resp struct {
		WindowID           string `json:"window_id"`
		ProvisionalChannel string `json:"provisional_channel"`
		ExpiresAt          string `json:"expires_at"`
	}
	if err := h.post(ctx, "/v1/pairing-windows", map[string]string{"host_id": h.HostIDWire()}, &resp); err != nil {
		return "", "", err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.windowID = resp.WindowID
	h.provChannelWire = resp.ProvisionalChannel
	if _, err := rand.Read(h.token[:]); err != nil {
		return "", "", err
	}
	h.tokenLive = true
	h.macFailures = 0
	qr := &e2ekit.QRPayload{
		Version:     1,
		RelayOrigin: h.cfg.RelayOrigin,
		HostID:      h.hostID,
		HostPK:      h.hostPK,
		Token:       h.token,
		AccountBind: e2ekit.V1.AccountBind(h.hostPK, h.cfg.Sub),
		ExpiresUnix: time.Now().Add(h.cfg.WindowTTL).Unix(),
	}
	return qr.Encode(), resp.WindowID, nil
}

// Run attaches to the relay and serves until ctx is cancelled or the
// connection drops.
func (h *Host) Run(ctx context.Context) error {
	wsURL := strings.Replace(h.cfg.RelayOrigin, "http", "ws", 1) + "/v1/host?host_id=" + h.HostIDWire()
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{h.bearer()}},
	})
	if err != nil {
		return fmt.Errorf("fakehost: host attach: %w", err)
	}
	h.mu.Lock()
	h.conn = conn
	h.runCtx = ctx
	h.mu.Unlock()
	h.attachedOnce.Do(func() { close(h.attachedCh) })
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Heartbeat (relay-api.md §6): TEXT, every 5s for demo liveness.
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				h.mu.Lock()
				_ = conn.Write(hbCtx, websocket.MessageText, []byte(`{"hb":1}`))
				h.mu.Unlock()
			}
		}
	}()

	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if typ != websocket.MessageText {
			h.handleBinary(data)
			continue
		}
		h.handleControl(data)
	}
}

// WaitAttached blocks until the host's relay attach has succeeded (which
// also means the §2.2 account binding exists — windows and pairings
// require it).
func (h *Host) WaitAttached(ctx context.Context) error {
	select {
	case <-h.attachedCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DeviceAttached reports the relay's §6.1 view of the paired device.
func (h *Host) DeviceAttached() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.device != nil && h.device.attached
}

// handleControl consumes relay TEXT control messages: §6.1 device
// presence (the class-L/class-M selector) and §4.1 routing errors.
// Relay TEXT is never authenticated state — it only steers construction
// choice, where a wrong steer degrades to a snapshot.full reconcile.
func (h *Host) handleControl(data []byte) {
	var msg struct {
		Presence string `json:"presence"`
		Channel  string `json:"channel"`
		Attached bool   `json:"attached"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		h.cfg.Logf("relay control (unparsed): %s", data)
		return
	}
	switch {
	case msg.Presence == "device":
		h.mu.Lock()
		if h.device != nil && msg.Channel == h.device.channelWire {
			h.device.attached = msg.Attached
		}
		h.mu.Unlock()
		h.cfg.Logf("device presence: channel=%s attached=%v", msg.Channel, msg.Attached)
	case msg.Error != "":
		h.cfg.Logf("relay routing error %s on channel %s", msg.Error, msg.Channel)
	default:
		h.cfg.Logf("relay control: %s", data)
	}
}

// ---------------------------------------------------------------------
// frame routing
// ---------------------------------------------------------------------

func (h *Host) handleBinary(data []byte) {
	hdr, body, err := wire.DecodeFrame(data)
	if err != nil {
		h.cfg.Logf("dropping malformed frame: %v", err)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case hdr.Channel == h.provChannelWire && h.provChannelWire != "":
		h.handlePairingFrame(hdr, body)
	case h.device != nil && hdr.Channel == h.device.channelWire:
		h.handleSessionFrame(hdr, body)
	default:
		h.cfg.Logf("frame on unknown channel %s dropped", hdr.Channel)
	}
}

// sendFrame writes one wire frame. Caller holds h.mu.
func (h *Host) sendFrame(channel string, seq uint64, pushClass string, body []byte) {
	frame, err := wire.EncodeFrame(wire.Header{Channel: channel, Seq: seq, PushClass: pushClass}, body)
	if err != nil {
		h.cfg.Logf("encode frame: %v", err)
		return
	}
	if h.conn == nil {
		return
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(h.runCtx), 5*time.Second)
	defer cancel()
	if err := h.conn.Write(wctx, websocket.MessageBinary, frame); err != nil {
		h.cfg.Logf("frame write: %v", err)
	}
}

// sendControl sends a class-P control envelope (seq 0). Caller holds h.mu.
func (h *Host) sendControl(channel, kind string, body any) {
	env, err := wire.NewControl(kind, body)
	if err != nil {
		h.cfg.Logf("control %s: %v", kind, err)
		return
	}
	raw, _ := env.Marshal()
	h.sendFrame(channel, 0, "none", raw)
}

// ---------------------------------------------------------------------
// pairing (ADR Decision 8)
// ---------------------------------------------------------------------

func (h *Host) handlePairingFrame(hdr wire.Header, body []byte) {
	if hdr.Seq == 0 {
		env, err := wire.ParseEnvelope(body)
		if err != nil {
			h.cfg.Logf("pairing: bad control envelope: %v", err)
			return
		}
		switch env.Kind {
		case "pair.init":
			h.handlePairInit(env)
		case "sess.header":
			h.handlePairSessHeader(env)
		default:
			h.cfg.Logf("pairing: unexpected control kind %s", env.Kind)
		}
		return
	}
	// Class L: pair.identity.
	h.handlePairIdentity(hdr, body)
}

// pairFail is the single non-distinguishing response path for every
// pre-key pairing failure (B4): plaintext sess.denied {pair_failed}.
func (h *Host) pairFail() {
	h.pairing = nil
	h.sendControl(h.provChannelWire, "sess.denied", wire.SessDenied{Reason: wire.DeniedPairFailed})
}

func (h *Host) handlePairInit(env wire.Envelope) {
	var pi wire.PairInit
	if err := env.DecodeBody(&pi); err != nil {
		h.pairFail()
		return
	}
	deviceIDRaw, err1 := e2ekit.DecodeBin(pi.DeviceID, 16)
	devPKRaw, err2 := e2ekit.DecodeBin(pi.DevPK, 32)
	nDRaw, err3 := e2ekit.DecodeBin(pi.ND, 32)
	macRaw, err4 := e2ekit.DecodeBin(pi.MacPair, 32)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || pi.Proto != 1 {
		h.pairFail()
		return
	}
	var deviceID [16]byte
	var devPK, nD, mac [32]byte
	copy(deviceID[:], deviceIDRaw)
	copy(devPK[:], devPKRaw)
	copy(nD[:], nDRaw)
	copy(mac[:], macRaw)

	// Constant-time MAC verification on the SAME path whether or not a
	// live token exists (the dummy-key rule from the 2026-08-05 security
	// review — an early return on "no token" is a timing oracle).
	key := h.token
	live := h.tokenLive
	if !live {
		key = [32]byte{} // dummy key of the correct length
	}
	bind := e2ekit.V1.AccountBind(h.hostPK, h.cfg.Sub)
	want := e2ekit.V1.MacPair(key, h.hostID, h.hostPK, deviceID, devPK, nD, bind)
	ok := subtle.ConstantTimeCompare(want[:], mac[:]) == 1
	if !live || !ok {
		if live {
			h.macFailures++
			if h.macFailures >= 5 {
				h.tokenLive = false // five-strike early invalidation
			}
		}
		h.pairFail()
		return
	}
	// Token is consumed at the moment the MAC verifies (fail-closed).
	h.tokenLive = false

	if h.device != nil && h.device.deviceID == deviceID {
		// device_id must be unused (N2). The encrypted pair.denied
		// {device_id_in_use} needs a session key, which needs the rest of
		// the handshake; the fake keeps a single device and simply
		// refuses here.
		h.pairFail()
		return
	}

	roots, err := e2ekit.HostRoots(h.hostPK, h.hostSK, devPK)
	if err != nil {
		h.pairFail()
		return
	}
	var nH [32]byte
	if _, err := rand.Read(nH[:]); err != nil {
		h.pairFail()
		return
	}
	tr := e2ekit.V1.Transcript(h.hostID, deviceID, nD, nH)
	keys := e2ekit.V1.SessionKeys(roots, tr)
	push, hdrH2D, err := e2ekit.NewPushStream(keys.H2D)
	if err != nil {
		h.pairFail()
		return
	}
	h.pairing = &pairingState{
		step:     2,
		deviceID: deviceID,
		devPK:    devPK,
		keys:     keys,
		push:     push,
		tracker:  e2ekit.NewSeqTracker(0),
	}
	h.sendControl(h.provChannelWire, "pair.accept", wire.SessAccept{
		HostID: h.HostIDWire(),
		NH:     e2ekit.EncodeBin(nH[:]),
		HdrH2D: e2ekit.EncodeBin(hdrH2D[:]),
	})
}

func (h *Host) handlePairSessHeader(env wire.Envelope) {
	p := h.pairing
	if p == nil || p.step != 2 {
		return
	}
	var sh wire.SessHeader
	if err := env.DecodeBody(&sh); err != nil {
		h.pairFail()
		return
	}
	raw, err := e2ekit.DecodeBin(sh.HdrD2H, 24)
	if err != nil {
		h.pairFail()
		return
	}
	var hd [24]byte
	copy(hd[:], raw)
	p.pull = e2ekit.NewPullStream(p.keys.D2H, hd)
	p.step = 3
}

func (h *Host) handlePairIdentity(hdr wire.Header, body []byte) {
	p := h.pairing
	if p == nil || p.step != 3 {
		return
	}
	if err := e2ekit.CheckFrameClass(hdr.Seq, false); err != nil {
		h.cfg.Logf("pairing: %v", err)
		h.pairing = nil
		return
	}
	if _, err := p.tracker.Accept(hdr.Seq); err != nil {
		h.cfg.Logf("pairing: %v", err)
		h.pairing = nil
		return
	}
	ad, err := hdr.AD()
	if err != nil {
		h.pairing = nil
		return
	}
	pt, _, err := p.pull.Pull(body, ad)
	if err != nil {
		h.cfg.Logf("pairing: pair.identity failed to decrypt (fatal): %v", err)
		h.pairing = nil
		return
	}
	env, err := wire.ParseEnvelope(pt)
	if err != nil || env.Kind != "pair.identity" {
		h.pairing = nil
		return
	}
	var pid wire.PairIdentity
	if err := env.DecodeBody(&pid); err != nil {
		h.pairing = nil
		return
	}
	confD, err := e2ekit.DecodeBin(pid.ConfD, 32)
	if err != nil || !e2ekit.VerifyMAC(p.keys.ConfD[:], confD) {
		h.cfg.Logf("pairing: conf_d mismatch (fatal session abort)")
		h.pairing = nil
		return
	}
	// (JWT id_token validation is out of scope for the fake — the vector
	// fixtures carry a placeholder, and the real host validates against
	// Zitadel JWKS.)

	// Operator confirmation is NORMATIVE (OQ-2 ruling): nothing persists
	// and no routing registers until the operator accepts.
	fmt.Fprintf(h.cfg.Out, "would prompt: Pair %q (%s)?\n", pid.DeviceName, pid.DeviceModel)
	confirmed := h.cfg.AutoConfirm
	if confirmed {
		fmt.Fprintln(h.cfg.Out, "auto-confirmed (--auto-confirm)")
	} else {
		fmt.Fprint(h.cfg.Out, "confirm pairing? [y/N]: ")
		sc := bufio.NewScanner(h.cfg.ConfirmIn)
		if sc.Scan() {
			ans := strings.ToLower(strings.TrimSpace(sc.Text()))
			confirmed = ans == "y" || ans == "yes"
		}
	}
	if !confirmed {
		// Encrypted, specific denial (post-key failures may be specific —
		// §5.3). Token stays consumed, nothing persisted.
		h.sendEncryptedOn(p.push, &p.h2dSent, h.provChannelWire, "pair.denied",
			wire.PairDenied{Reason: "declined"}, "none", e2ekit.TagMessage, "")
		h.pairing = nil
		return
	}

	// Persist + register routing, then pair.complete.
	var channel [16]byte
	if _, err := rand.Read(channel[:]); err != nil {
		h.pairing = nil
		return
	}
	channelWire := e2ekit.EncodeChannelID(channel)
	label := h.cfg.HostName
	regCtx, cancel := context.WithTimeout(context.WithoutCancel(h.runCtx), 5*time.Second)
	err = h.post(regCtx, "/v1/pairings", map[string]any{
		"channel_id": channelWire,
		"host_id":    h.HostIDWire(),
		"device_id":  e2ekit.EncodeChannelID(p.deviceID),
		"host_label": label,
	}, nil)
	cancel()
	if err != nil {
		h.cfg.Logf("pairing: routing registration failed: %v", err)
		h.pairing = nil
		return
	}

	roots, _ := e2ekit.HostRoots(h.hostPK, h.hostSK, p.devPK)
	dev := &deviceRecord{
		deviceID:    p.deviceID,
		devPK:       p.devPK,
		channel:     channel,
		channelWire: channelWire,
		name:        pid.DeviceName,
		roots:       roots,
		kMbx:        e2ekit.V1.MailboxKey(roots, h.hostID, p.deviceID),
		d2h:         p.tracker,
		h2dSent:     p.h2dSent,
	}
	h.device = dev

	h.sendEncryptedOn(p.push, &dev.h2dSent, h.provChannelWire, "pair.complete", wire.PairComplete{
		ConfH:       e2ekit.EncodeBin(p.keys.ConfH[:]),
		HostID:      h.HostIDWire(),
		HostName:    h.cfg.HostName,
		AccountBind: e2ekit.EncodeBin(mustBind(h)),
		ChannelID:   channelWire,
	}, "none", e2ekit.TagMessage, "")
	h.pairing = nil
	fmt.Fprintf(h.cfg.Out, "paired: device %s on channel %s\n", e2ekit.EncodeChannelID(dev.deviceID), channelWire)

	// The pairing sheet closes on success: close the window (best-effort,
	// slightly deferred so the pair.complete frame drains first).
	winID := h.windowID
	go func() {
		time.Sleep(200 * time.Millisecond)
		req, err := http.NewRequest(http.MethodDelete, h.cfg.RelayOrigin+"/v1/pairing-windows/"+winID, nil)
		if err != nil {
			return
		}
		req.Header.Set("Authorization", h.bearer())
		if resp, err := h.httpc.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
}

func mustBind(h *Host) []byte {
	b := e2ekit.V1.AccountBind(h.hostPK, h.cfg.Sub)
	return b[:]
}

// sendEncryptedOn seals one envelope on the given push stream, consuming
// the next pairing-lifetime seq from *counter, and sends it on channel.
// id is the optional envelope id. Caller holds h.mu.
func (h *Host) sendEncryptedOn(push *e2ekit.Stream, counter *uint64, channel, kind string, body any, pushClass string, tag byte, id string) {
	var env wire.Envelope
	var err error
	switch kind {
	case "sess.confirm", "pair.complete", "pair.denied", "session.revoked":
		env, err = wire.NewControl(kind, body)
	default:
		env, err = wire.NewPayload(kind, id, time.Now(), body)
	}
	if err != nil {
		h.cfg.Logf("envelope %s: %v", kind, err)
		return
	}
	raw, err := env.Marshal()
	if err != nil {
		h.cfg.Logf("envelope %s: %v", kind, err)
		return
	}
	*counter++
	seq := *counter
	chID, err := e2ekit.DecodeChannelID(channel)
	if err != nil {
		return
	}
	pc, err := e2ekit.ParsePushClass(pushClass)
	if err != nil {
		return
	}
	ad := e2ekit.BuildAD(chID, seq, pc)
	ct, err := push.Push(raw, ad[:], tag)
	if err != nil {
		h.cfg.Logf("push %s: %v", kind, err)
		return
	}
	h.sendFrame(channel, seq, pushClass, ct)
}
