package devclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/kameas-ai/kameas-relay/e2ekit"
	"github.com/kameas-ai/kameas-relay/wire"
)

// Presence is the relay's plaintext host-presence control message — the
// only plaintext state the device consumes, and never a security signal.
type Presence struct {
	HostID   string `json:"host_id"`
	Online   bool   `json:"online"`
	LastSeen string `json:"last_seen"`
}

// ErrSessionDenied wraps a plaintext sess.denied. It is UNAUTHENTICATED
// (a malicious relay can forge it): pairing material is deliberately NOT
// deleted on this error — the operator resolves the ambiguity.
type ErrSessionDenied struct{ Reason string }

func (e *ErrSessionDenied) Error() string {
	return fmt.Sprintf("devclient: session denied (%s) — unauthenticated; keeping pairing material (host may have revoked this device; re-pair from the host if so)", e.Reason)
}

// ErrRevoked is returned when the authenticated session.revoked envelope
// (TAG_FINAL) arrives — the ONLY revocation signal acted on
// destructively.
var ErrRevoked = errors.New("devclient: session revoked by host (authenticated)")

// Session is one established device session.
type Session struct {
	State *State

	// ReconcileExpected is set when the mailbox drain saw a gap or the
	// session-start seq jumped forward: cached state is stale and the
	// next snapshot.full is authoritative.
	ReconcileExpected bool
	// DrainedEnvelopes are mailbox envelopes decrypted during the
	// pre-handshake drain, in seq order.
	DrainedEnvelopes []wire.Envelope

	conn    *websocket.Conn
	keys    e2ekit.SessionKeys
	push    *e2ekit.Stream
	pull    *e2ekit.Stream
	tracker *e2ekit.SeqTracker

	mu       sync.Mutex
	presence *Presence
	revoked  bool

	OnPresence func(Presence)
}

// Connect drains the mailbox, runs the session handshake, and returns an
// established session. Every connect derives fresh nonces, keys, and
// stream states (ADR Decision 6).
func Connect(ctx context.Context, st *State) (*Session, error) {
	hostID, deviceID, channel, hostPK, devPK, devSK, err := st.keys()
	if err != nil {
		return nil, err
	}
	roots, err := e2ekit.DeviceRoots(devPK, devSK, hostPK)
	if err != nil {
		return nil, err
	}
	kMbx := e2ekit.V1.MailboxKey(roots, hostID, deviceID)

	s := &Session{State: st, tracker: e2ekit.NewSeqTracker(st.H2DLastSeen)}

	// 1. Mailbox drain BEFORE the handshake (e2e-envelope.md §1). Gaps
	// are expected; class-L frames that lost the presence race fail to
	// authenticate and are skipped — recovery is the snapshot.full
	// reconcile, not an error.
	if err := s.drainMailbox(ctx, channel, kMbx); err != nil {
		return nil, err
	}

	// 2. Attach.
	conn, _, err := websocket.Dial(ctx, wsOrigin(st.RelayOrigin)+"/v1/device?channel="+st.ChannelID,
		&websocket.DialOptions{HTTPHeader: bearer(st.Sub)})
	if err != nil {
		return nil, fmt.Errorf("devclient: attach: %w", err)
	}
	s.conn = conn
	ok := false
	defer func() {
		if !ok {
			conn.Close(websocket.StatusNormalClosure, "")
		}
	}()

	// 3. Handshake.
	var nD [32]byte
	if _, err := rand.Read(nD[:]); err != nil {
		return nil, err
	}
	if err := sendControl(ctx, conn, st.ChannelID, "sess.hello", wire.SessHello{
		Proto:    1,
		DeviceID: st.DeviceID,
		ND:       e2ekit.EncodeBin(nD[:]),
	}); err != nil {
		return nil, err
	}
	hdr, body, err := readBinary(ctx, conn, s.textHandler())
	if err != nil {
		return nil, err
	}
	if err := e2ekit.CheckFrameClass(hdr.Seq, true); err != nil {
		return nil, err
	}
	env, err := wire.ParseEnvelope(body)
	if err != nil {
		return nil, err
	}
	if env.Kind == "sess.denied" {
		var d wire.SessDenied
		_ = env.DecodeBody(&d)
		return nil, &ErrSessionDenied{Reason: d.Reason}
	}
	if env.Kind != "sess.accept" {
		return nil, fmt.Errorf("devclient: expected sess.accept, got %s", env.Kind)
	}
	var sa wire.SessAccept
	if err := env.DecodeBody(&sa); err != nil {
		return nil, err
	}
	if sa.HostID != st.HostID {
		return nil, errors.New("devclient: sess.accept host_id mismatch")
	}
	nHRaw, err := e2ekit.DecodeBin(sa.NH, 32)
	if err != nil {
		return nil, err
	}
	hdrH2DRaw, err := e2ekit.DecodeBin(sa.HdrH2D, 24)
	if err != nil {
		return nil, err
	}
	var nH [32]byte
	var hdrH2D [24]byte
	copy(nH[:], nHRaw)
	copy(hdrH2D[:], hdrH2DRaw)

	tr := e2ekit.V1.Transcript(hostID, deviceID, nD, nH)
	s.keys = e2ekit.V1.SessionKeys(roots, tr)
	s.pull = e2ekit.NewPullStream(s.keys.H2D, hdrH2D)
	push, hdrD2H, err := e2ekit.NewPushStream(s.keys.D2H)
	if err != nil {
		return nil, err
	}
	s.push = push
	if err := sendControl(ctx, conn, st.ChannelID, "sess.header", wire.SessHeader{
		HdrD2H: e2ekit.EncodeBin(hdrD2H[:]),
	}); err != nil {
		return nil, err
	}

	// Device sess.confirm: next pairing-lifetime counter value.
	if err := s.sendEncrypted(ctx, "sess.confirm", "",
		wire.SessConfirm{TranscriptMAC: e2ekit.EncodeBin(s.keys.ConfD[:])}, true); err != nil {
		return nil, err
	}

	// Host sess.confirm: session-start regime — a forward jump is normal
	// and mandates the snapshot.full reconcile.
	s.tracker.StartSession()
	hdr, body, err = readBinary(ctx, conn, s.textHandler())
	if err != nil {
		return nil, err
	}
	if err := e2ekit.CheckFrameClass(hdr.Seq, false); err != nil {
		return nil, err
	}
	reconcile, err := s.tracker.Accept(hdr.Seq)
	if err != nil {
		return nil, fmt.Errorf("devclient: host sess.confirm: %w (fatal abort)", err)
	}
	if reconcile {
		s.ReconcileExpected = true
	}
	ad, err := hdr.AD()
	if err != nil {
		return nil, err
	}
	pt, _, err := s.pull.Pull(body, ad)
	if err != nil {
		return nil, errors.New("devclient: host sess.confirm failed to authenticate — fatal abort, reconnect with fresh nonces")
	}
	env, err = wire.ParseEnvelope(pt)
	if err != nil || env.Kind != "sess.confirm" {
		return nil, errors.New("devclient: expected host sess.confirm")
	}
	var sc wire.SessConfirm
	if err := env.DecodeBody(&sc); err != nil {
		return nil, err
	}
	confH, err := e2ekit.DecodeBin(sc.TranscriptMAC, 32)
	if err != nil || !e2ekit.VerifyMAC(s.keys.ConfH[:], confH) {
		return nil, errors.New("devclient: transcript confirmation mismatch — fatal abort")
	}

	st.H2DLastSeen = s.tracker.LastSeen()
	_ = st.Save("")
	ok = true
	return s, nil
}

func (s *Session) textHandler() func([]byte) {
	return func(data []byte) {
		var p Presence
		if json.Unmarshal(data, &p) == nil && p.HostID != "" {
			s.mu.Lock()
			s.presence = &p
			cb := s.OnPresence
			s.mu.Unlock()
			if cb != nil {
				cb(p)
			}
		}
	}
}

// LastPresence returns the most recent relay presence message, if any.
func (s *Session) LastPresence() *Presence {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.presence
}

// drainMailbox fetches and decrypts spooled class-M frames.
func (s *Session) drainMailbox(ctx context.Context, channel [16]byte, kMbx [32]byte) error {
	httpc := &http.Client{Timeout: 10 * time.Second}
	after := s.State.H2DLastSeen
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s/v1/channels/%s/frames?after=%d", s.State.RelayOrigin, s.State.ChannelID, after), nil)
		if err != nil {
			return err
		}
		req.Header = bearer(s.State.Sub)
		resp, err := httpc.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			return fmt.Errorf("devclient: mailbox fetch: %s: %s", resp.Status, msg)
		}
		var out struct {
			Frames []struct {
				Seq       uint64 `json:"seq"`
				PushClass string `json:"push_class"`
				Body      string `json:"body"` // ONE opaque blob; the receiver splits nonce ‖ ct (e2e-envelope §1.2)
			} `json:"frames"`
			NextAfter uint64 `json:"next_after"`
			Truncated bool   `json:"truncated"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			return err
		}
		// abandon implements the §1.2 recovery rule: on ANY item that
		// cannot be authenticated, discard it, abandon the REST of the
		// drain, and proceed to the handshake. Skip-and-continue would
		// let a relay steer which frames the device accepts. last_seen
		// stays where it was, so the handshake's sess.confirm presents a
		// forward seq jump, which mandates the snapshot.full reconcile.
		// The common cause is benign: a class-L frame that lost the
		// device-presence race — never a security event.
		abandon := func() error {
			s.ReconcileExpected = true
			s.saveDrainMark()
			return nil
		}
		for _, f := range out.Frames {
			pc, err := e2ekit.ParsePushClass(f.PushClass)
			if err != nil {
				return abandon()
			}
			body, err := base64.RawURLEncoding.DecodeString(f.Body)
			if err != nil {
				return abandon()
			}
			ad := e2ekit.BuildAD(channel, f.Seq, pc)
			pt, err := e2ekit.OpenMailboxFrame(kMbx, body, ad[:])
			if err != nil {
				return abandon()
			}
			gap, err := s.tracker.AcceptMailbox(f.Seq)
			if err != nil {
				return fmt.Errorf("devclient: mailbox drain: %w", err)
			}
			if gap {
				s.ReconcileExpected = true
			}
			env, err := wire.ParseEnvelope(pt)
			if err != nil {
				return abandon()
			}
			s.DrainedEnvelopes = append(s.DrainedEnvelopes, env)
		}
		s.saveDrainMark()
		if !out.Truncated {
			return nil
		}
		after = out.NextAfter
	}
}

// saveDrainMark persists the high-water mark advanced by successfully
// authenticated drain items.
func (s *Session) saveDrainMark() {
	if s.tracker.LastSeen() > s.State.H2DLastSeen {
		s.State.H2DLastSeen = s.tracker.LastSeen()
		_ = s.State.Save("")
	}
}

// sendEncrypted seals and sends one d2h envelope, consuming the next
// pairing-lifetime seq (persisted before the frame leaves, so a crashed
// process cannot reuse a seq — reuse would wedge the pairing, N5).
func (s *Session) sendEncrypted(ctx context.Context, kind, id string, body any, control bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var env wire.Envelope
	var err error
	if control {
		env, err = wire.NewControl(kind, body)
	} else {
		env, err = wire.NewPayload(kind, id, time.Now(), body)
	}
	if err != nil {
		return err
	}
	raw, err := env.Marshal()
	if err != nil {
		return err
	}
	s.State.D2HLastSent++
	seq := s.State.D2HLastSent
	if err := s.State.Save(""); err != nil {
		return err
	}
	channel := deviceChannelOf(s.State)
	ad := e2ekit.BuildAD(channel, seq, e2ekit.PushClassNone) // devices MUST NOT set push_class
	ct, err := s.push.Push(raw, ad[:], e2ekit.TagMessage)
	if err != nil {
		return err
	}
	frame, err := wire.EncodeFrame(wire.Header{Channel: s.State.ChannelID, Seq: seq, PushClass: "none"}, ct)
	if err != nil {
		return err
	}
	return s.conn.Write(ctx, websocket.MessageBinary, frame)
}

func deviceChannelOf(st *State) [16]byte {
	id, _ := e2ekit.DecodeChannelID(st.ChannelID)
	return id
}

// SendRPC sends one rpc.request and returns its envelope id.
func (s *Session) SendRPC(ctx context.Context, method string, params any) (string, error) {
	var idBytes [8]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return "", err
	}
	id := "req-" + hex.EncodeToString(idBytes[:])
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return "", err
		}
		raw = b
	}
	return id, s.sendEncrypted(ctx, "rpc.request", id, wire.RPCRequest{Method: method, Params: raw}, false)
}

// Recv returns the next h2d envelope. Mid-session gaps, authentication
// failures, and unknown envelope versions are fatal (the caller
// reconnects with fresh state). After the authenticated session.revoked
// (TAG_FINAL) it returns ErrRevoked forever.
func (s *Session) Recv(ctx context.Context) (wire.Envelope, error) {
	if s.revoked {
		return wire.Envelope{}, ErrRevoked
	}
	for {
		hdr, body, err := readBinary(ctx, s.conn, s.textHandler())
		if err != nil {
			return wire.Envelope{}, err
		}
		if hdr.Seq == 0 {
			// Plaintext control mid-session: only sess.denied is defined,
			// and it is unauthenticated — surface without destroying state.
			env, err := wire.ParseEnvelope(body)
			if err != nil {
				return wire.Envelope{}, err
			}
			if env.Kind == "sess.denied" {
				var d wire.SessDenied
				_ = env.DecodeBody(&d)
				return wire.Envelope{}, &ErrSessionDenied{Reason: d.Reason}
			}
			continue
		}
		if _, err := s.tracker.Accept(hdr.Seq); err != nil {
			return wire.Envelope{}, fmt.Errorf("devclient: %w (fatal abort)", err)
		}
		ad, err := hdr.AD()
		if err != nil {
			return wire.Envelope{}, err
		}
		pt, tag, err := s.pull.Pull(body, ad)
		if err != nil {
			return wire.Envelope{}, fmt.Errorf("devclient: frame authentication failed (fatal abort): %w", err)
		}
		s.State.H2DLastSeen = s.tracker.LastSeen()
		_ = s.State.Save("")
		env, err := wire.ParseEnvelope(pt)
		if err != nil {
			return wire.Envelope{}, err
		}
		if tag == e2ekit.TagFinal || env.Kind == "session.revoked" {
			s.revoked = true
			if env.Kind == "session.revoked" {
				return env, nil // caller sees the envelope, then ErrRevoked
			}
		}
		return env, nil
	}
}

// Close closes the transport.
func (s *Session) Close() error {
	_ = s.State.Save("")
	return s.conn.Close(websocket.StatusNormalClosure, "")
}
