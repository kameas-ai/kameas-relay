package fakerelay

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
)

// Header is the plaintext frame header — the relay's ENTIRE visibility
// into a frame (e2e-envelope.md §2). Exactly three fields; anything more
// in plaintext framing is a §XII condition-3 defect, so decoding rejects
// unknown fields.
type Header struct {
	Channel   string `json:"channel"`
	Seq       uint64 `json:"seq"`
	PushClass string `json:"push_class"`
}

// Push classes (e2e-envelope.md §2). Host-set only; the relay rejects any
// device-originated frame whose push_class != "none".
const (
	PushNone      = "none"
	PushWake      = "wake"
	PushAttention = "attention"
)

func validPushClass(pc string) bool {
	return pc == PushNone || pc == PushWake || pc == PushAttention
}

// b64 is the only frame-id / channel-id encoding on this wire: base64url,
// unpadded, canonical. Strict() rejects non-canonical trailing bits.
var b64 = base64.RawURLEncoding.Strict()

// validChannelID reports whether s is a canonical 22-char base64url
// encoding of exactly 16 bytes (e2e-envelope.md §2).
func validChannelID(s string) bool {
	if len(s) != 22 {
		return false
	}
	raw, err := b64.DecodeString(s)
	return err == nil && len(raw) == 16
}

var (
	errFraming   = errors.New("malformed frame framing")
	errHeaderLen = errors.New("header length exceeds cap")
	errHeader    = errors.New("malformed frame header")
)

// DecodeFrame parses the WSS binary wire format (e2e-envelope.md §1.1):
//
//	[0..2)    uint16 big-endian header_len H (H <= maxHeader)
//	[2..2+H)  header JSON (exactly the three §2 fields)
//	[2+H..)   body — OPAQUE BYTES. The relay MUST NOT parse, interpret,
//	          or depend on anything in it (relay-api.md preamble); the
//	          returned body slice is forwarded or buffered verbatim.
func DecodeFrame(msg []byte, maxHeader int) (Header, []byte, error) {
	var h Header
	if len(msg) < 2 {
		return h, nil, errFraming
	}
	hl := int(binary.BigEndian.Uint16(msg[:2]))
	if hl > maxHeader {
		return h, nil, errHeaderLen
	}
	if len(msg) < 2+hl {
		return h, nil, errFraming
	}
	dec := json.NewDecoder(bytes.NewReader(msg[2 : 2+hl]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return h, nil, errHeader
	}
	if dec.More() {
		return h, nil, errHeader
	}
	if !validChannelID(h.Channel) || !validPushClass(h.PushClass) {
		return h, nil, errHeader
	}
	return h, msg[2+hl:], nil
}

// EncodeFrame builds a wire frame from a header and an opaque body.
// Exported for consumers of the fake (kenaz-agent tests, iOS integration
// harnesses) so every lane shares one framing implementation.
func EncodeFrame(h Header, body []byte) ([]byte, error) {
	hdr, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if len(hdr) > 512 {
		return nil, fmt.Errorf("header JSON is %d bytes; cap is 512", len(hdr))
	}
	msg := make([]byte, 2+len(hdr)+len(body))
	binary.BigEndian.PutUint16(msg[:2], uint16(len(hdr)))
	copy(msg[2:], hdr)
	copy(msg[2+len(hdr):], body)
	return msg, nil
}

// idRNG generates opaque ids (provisional channels, window ids, pairing
// ids). Deliberately math/rand/v2, NOT crypto/rand: the deny-list
// (denylist_test.go) is absolute, and nothing here is key material — the
// contract's ids are routing metadata only (relay-api.md §3.1 "It is
// metadata only. No key material is involved").
var (
	idMu  sync.Mutex
	idRNG = rand.New(rand.NewPCG(0x6b616d656173, 0x72656c6179)) // deterministic seed; fine for a fake
)

// NewID returns a canonical 22-char base64url id over 16 fresh bytes.
func NewID() string {
	idMu.Lock()
	defer idMu.Unlock()
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[:8], idRNG.Uint64())
	binary.BigEndian.PutUint64(raw[8:], idRNG.Uint64())
	return b64.EncodeToString(raw[:])
}
