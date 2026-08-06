package relay

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

// Header is the plaintext frame header — the relay's ENTIRE visibility into
// a frame (e2e-envelope.md §2). Exactly three fields; anything more in
// plaintext framing is a §XII condition-3 defect, so decoding rejects
// unknown fields rather than ignoring them.
type Header struct {
	Channel   string `json:"channel"`
	Seq       uint64 `json:"seq"`
	PushClass string `json:"push_class"`
}

// Push classes (e2e-envelope.md §2). Host-set only; the enum is closed and
// MUST NOT be widened — a richer enum would tell the relay which subsystem
// produced each event, which is a new observable and an amendment question.
const (
	PushNone      = "none"
	PushWake      = "wake"
	PushAttention = "attention"
)

func validPushClass(pc string) bool {
	return pc == PushNone || pc == PushWake || pc == PushAttention
}

// b64 is the only id encoding on this wire: base64url, unpadded, canonical.
// Strict() rejects non-canonical trailing bits, so two implementations
// cannot agree on the header and disagree on the AD.
var b64 = base64.RawURLEncoding.Strict()

// validID reports whether s is a canonical 22-char base64url encoding of
// exactly 16 bytes (e2e-envelope.md §2).
func validID(s string) bool {
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
//	[2..2+H)  header JSON — exactly the three §2 fields
//	[2+H..)   body — OPAQUE BYTES
//
// The returned body is a subslice of msg and is forwarded or buffered
// VERBATIM. The relay MUST NOT parse, interpret, or depend on anything in
// it, and MUST NOT split it (not even at the class-M nonce boundary).
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
	if !validID(h.Channel) || !validPushClass(h.PushClass) {
		return h, nil, errHeader
	}
	return h, msg[2+hl:], nil
}

// EncodeFrame builds a wire frame from a header and an opaque body.
// Exported so parity and conformance harnesses share one framing
// implementation with the router that consumes it.
func EncodeFrame(h Header, body []byte) ([]byte, error) {
	hdr, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if len(hdr) > DefaultMaxHeaderLen {
		return nil, fmt.Errorf("header JSON is %d bytes; cap is %d", len(hdr), DefaultMaxHeaderLen)
	}
	msg := make([]byte, 2+len(hdr)+len(body))
	binary.BigEndian.PutUint16(msg[:2], uint16(len(hdr)))
	copy(msg[2:], hdr)
	copy(msg[2+len(hdr):], body)
	return msg, nil
}

// ---------------------------------------------------------------------
// Relay-generated identifiers
// ---------------------------------------------------------------------

// idRNG generates opaque relay ids: provisional channels, window ids,
// pairing ids.
//
// Deliberately math/rand/v2 and NOT crypto/rand. The §XII condition-2
// deny-list is absolute in relay scope, and nothing here is key material:
// relay-api.md §3.1 says of the provisional channel, "It is metadata only.
// No key material is involved, and the relay learns nothing by choosing
// it." The same holds for window and pairing ids, which are opaque handles
// the contract never binds into any authenticated construction.
//
// The seeding below is what makes that safe in production. math/rand/v2's
// top-level functions are already randomly seeded by the runtime, so a
// generator seeded from rand.Uint64 inherits that entropy rather than the
// fixed seed a test double can afford. These ids still must not be treated
// as unguessable secrets by any other component — and nothing does: the
// only thing a guessed provisional channel buys is arrival at a pairing
// ceremony that fails closed without the QR's token (§3.2).
var (
	idMu  sync.Mutex
	idRNG = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
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
