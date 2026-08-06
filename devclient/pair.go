package devclient

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/kameas-ai/kameas-relay/e2ekit"
	"github.com/kameas-ai/kameas-relay/wire"
)

// PairConfig drives one pairing attempt. The QR alone is sufficient:
// the pairing attach is addressed by the QR's host_id (relay-api.md
// §3.2, ruled 2026-08-06) — window_id is a host-facing handle and never
// appears on a device path.
type PairConfig struct {
	QRURI       string
	Sub         string
	DeviceName  string
	DeviceModel string
	NowUnix     int64 // 0 => time.Now()
}

// ErrPairDenied is returned when the host denies pairing.
var ErrPairDenied = errors.New("devclient: pairing denied")

func bearer(sub string) http.Header {
	return http.Header{"Authorization": []string{"Bearer fake-" + sub}}
}

func wsOrigin(origin string) string { return strings.Replace(origin, "http", "ws", 1) }

// readBinary reads WSS messages until a binary frame arrives, skipping
// relay TEXT control messages (presence etc.). Returns the decoded frame.
func readBinary(ctx context.Context, conn *websocket.Conn, onText func([]byte)) (wire.Header, []byte, error) {
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return wire.Header{}, nil, err
		}
		if typ == websocket.MessageText {
			if onText != nil {
				onText(data)
			}
			continue
		}
		return wire.DecodeFrame(data)
	}
}

func sendControl(ctx context.Context, conn *websocket.Conn, channel, kind string, body any) error {
	env, err := wire.NewControl(kind, body)
	if err != nil {
		return err
	}
	raw, err := env.Marshal()
	if err != nil {
		return err
	}
	frame, err := wire.EncodeFrame(wire.Header{Channel: channel, Seq: 0, PushClass: "none"}, raw)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageBinary, frame)
}

// Pair runs the full Decision-8 pairing flow against the relay named in
// the QR and returns a persistable device state. The QR is parsed with
// the strict Decision-8 rules and validated against the device clock
// (UX pre-check) and the signed-in subject (account_bind, constant time).
func Pair(ctx context.Context, cfg PairConfig) (*State, error) {
	qr, err := e2ekit.ParseQR(cfg.QRURI)
	if err != nil {
		return nil, err
	}
	// The `e` expiry pre-check (§3.2: SHOULD, device-side) catches a
	// stale or photographed QR without a wire round-trip — and without
	// burning a strike against a live token on the host.
	now := cfg.NowUnix
	if now == 0 {
		now = time.Now().Unix()
	}
	if err := qr.Validate(now, cfg.Sub); err != nil {
		return nil, err
	}

	devPK, devSK, err := e2ekit.NewKXKeypair()
	if err != nil {
		return nil, err
	}
	var deviceID [16]byte
	if _, err := rand.Read(deviceID[:]); err != nil {
		return nil, err
	}
	var nD [32]byte
	if _, err := rand.Read(nD[:]); err != nil {
		return nil, err
	}

	// Pairing attach, addressed by the QR's host_id (§3.2); the relay
	// resolves the single open window or refuses with the uniform
	// window_closed. First server TEXT message conveys the provisional
	// channel.
	conn, _, err := websocket.Dial(ctx, wsOrigin(qr.RelayOrigin)+"/v1/device?host="+e2ekit.EncodeChannelID(qr.HostID),
		&websocket.DialOptions{HTTPHeader: bearer(cfg.Sub)})
	if err != nil {
		return nil, fmt.Errorf("devclient: pairing attach: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	var provisional string
	for provisional == "" {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return nil, fmt.Errorf("devclient: awaiting provisional channel: %w", err)
		}
		if typ != websocket.MessageText {
			continue
		}
		var msg struct {
			ProvisionalChannel string `json:"provisional_channel"`
		}
		if json.Unmarshal(data, &msg) == nil && msg.ProvisionalChannel != "" {
			provisional = msg.ProvisionalChannel
		}
	}
	if _, err := e2ekit.DecodeChannelID(provisional); err != nil {
		return nil, fmt.Errorf("devclient: relay sent a non-canonical provisional channel: %w", err)
	}

	// Frame 1: pair.init (plaintext, seq 0, provisional channel).
	bind := e2ekit.V1.AccountBind(qr.HostPK, cfg.Sub) // == qr.AccountBind, already verified
	mac := e2ekit.V1.MacPair(qr.Token, qr.HostID, qr.HostPK, deviceID, devPK, nD, bind)
	if err := sendControl(ctx, conn, provisional, "pair.init", wire.PairInit{
		Proto:    1,
		DeviceID: e2ekit.EncodeChannelID(deviceID),
		DevPK:    e2ekit.EncodeBin(devPK[:]),
		ND:       e2ekit.EncodeBin(nD[:]),
		MacPair:  e2ekit.EncodeBin(mac[:]),
	}); err != nil {
		return nil, err
	}

	// Frame 2: pair.accept — or plaintext sess.denied.
	hdr, body, err := readBinary(ctx, conn, nil)
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
		// The device MUST NOT auto-retry: the token may be consumed.
		return nil, fmt.Errorf("%w: %s (recovery is a fresh QR)", ErrPairDenied, d.Reason)
	}
	if env.Kind != "pair.accept" {
		return nil, fmt.Errorf("devclient: expected pair.accept, got %s", env.Kind)
	}
	var pa wire.SessAccept
	if err := env.DecodeBody(&pa); err != nil {
		return nil, err
	}
	if pa.HostID != e2ekit.EncodeChannelID(qr.HostID) {
		return nil, errors.New("devclient: pair.accept host_id does not match the QR")
	}
	nHRaw, err := e2ekit.DecodeBin(pa.NH, 32)
	if err != nil {
		return nil, err
	}
	hdrH2DRaw, err := e2ekit.DecodeBin(pa.HdrH2D, 24)
	if err != nil {
		return nil, err
	}
	var nH [32]byte
	var hdrH2D [24]byte
	copy(nH[:], nHRaw)
	copy(hdrH2D[:], hdrH2DRaw)

	// Derive the session (device = kx client; roots recomputed, never stored).
	roots, err := e2ekit.DeviceRoots(devPK, devSK, qr.HostPK)
	if err != nil {
		return nil, err
	}
	tr := e2ekit.V1.Transcript(qr.HostID, deviceID, nD, nH)
	keys := e2ekit.V1.SessionKeys(roots, tr)
	pull := e2ekit.NewPullStream(keys.H2D, hdrH2D)
	push, hdrD2H, err := e2ekit.NewPushStream(keys.D2H)
	if err != nil {
		return nil, err
	}

	// Frame 3: sess.header.
	if err := sendControl(ctx, conn, provisional, "sess.header", wire.SessHeader{
		HdrD2H: e2ekit.EncodeBin(hdrD2H[:]),
	}); err != nil {
		return nil, err
	}

	// Frame 4: pair.identity (encrypted; first AEAD frame ever d2h => seq 1).
	provID, _ := e2ekit.DecodeChannelID(provisional)
	var d2hSent uint64
	identEnv, err := wire.NewControl("pair.identity", wire.PairIdentity{
		ConfD:       e2ekit.EncodeBin(keys.ConfD[:]),
		IDToken:     "fake.id.token", // JWT validation is out of scope for the tooling
		DeviceName:  cfg.DeviceName,
		DeviceModel: cfg.DeviceModel,
	})
	if err != nil {
		return nil, err
	}
	identRaw, _ := identEnv.Marshal()
	d2hSent++
	ad := e2ekit.BuildAD(provID, d2hSent, e2ekit.PushClassNone)
	ct, err := push.Push(identRaw, ad[:], e2ekit.TagMessage)
	if err != nil {
		return nil, err
	}
	frame, err := wire.EncodeFrame(wire.Header{Channel: provisional, Seq: d2hSent, PushClass: "none"}, ct)
	if err != nil {
		return nil, err
	}
	if err := conn.Write(ctx, websocket.MessageBinary, frame); err != nil {
		return nil, err
	}

	// Frame 5: pair.complete or pair.denied (encrypted).
	tracker := e2ekit.NewSeqTracker(0)
	hdr, body, err = readBinary(ctx, conn, nil)
	if err != nil {
		return nil, err
	}
	if err := e2ekit.CheckFrameClass(hdr.Seq, false); err != nil {
		return nil, err
	}
	if _, err := tracker.Accept(hdr.Seq); err != nil {
		return nil, err
	}
	adBytes, err := hdr.AD()
	if err != nil {
		return nil, err
	}
	pt, _, err := pull.Pull(body, adBytes)
	if err != nil {
		return nil, fmt.Errorf("devclient: pair.complete failed to authenticate (fatal): %w", err)
	}
	env, err = wire.ParseEnvelope(pt)
	if err != nil {
		return nil, err
	}
	if env.Kind == "pair.denied" {
		var d wire.PairDenied
		_ = env.DecodeBody(&d)
		return nil, fmt.Errorf("%w: %s", ErrPairDenied, d.Reason)
	}
	if env.Kind != "pair.complete" {
		return nil, fmt.Errorf("devclient: expected pair.complete, got %s", env.Kind)
	}
	var pc wire.PairComplete
	if err := env.DecodeBody(&pc); err != nil {
		return nil, err
	}
	confH, err := e2ekit.DecodeBin(pc.ConfH, 32)
	if err != nil || !e2ekit.VerifyMAC(keys.ConfH[:], confH) {
		return nil, errors.New("devclient: conf_h mismatch — fatal, nothing persisted")
	}
	bindGot, err := e2ekit.DecodeBin(pc.AccountBind, 16)
	if err != nil || !e2ekit.VerifyMAC(bind[:], bindGot) {
		return nil, errors.New("devclient: pair.complete account_bind mismatch")
	}
	if pc.HostID != e2ekit.EncodeChannelID(qr.HostID) {
		return nil, errors.New("devclient: pair.complete host_id mismatch")
	}
	if _, err := e2ekit.DecodeChannelID(pc.ChannelID); err != nil {
		return nil, fmt.Errorf("devclient: non-canonical durable channel_id: %w", err)
	}

	// Only now does the device persist host material (§5.2).
	return &State{
		RelayOrigin: qr.RelayOrigin,
		Sub:         cfg.Sub,
		HostID:      pc.HostID,
		HostPK:      e2ekit.EncodeBin(qr.HostPK[:]),
		HostName:    pc.HostName,
		DeviceID:    e2ekit.EncodeChannelID(deviceID),
		DevPK:       e2ekit.EncodeBin(devPK[:]),
		DevSK:       e2ekit.EncodeBin(devSK[:]),
		ChannelID:   pc.ChannelID,
		DeviceName:  cfg.DeviceName,
		D2HLastSent: d2hSent,            // pair.identity consumed 1
		H2DLastSeen: tracker.LastSeen(), // pair.complete consumed 1
	}, nil
}
