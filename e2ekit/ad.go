package e2ekit

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// Canonical associated data and the wire-string ↔ AD-bytes mapping
// (e2e-envelope.md §2/§3, ADR Decision 5 / N7).

// AD push_class byte values.
const (
	PushClassNone      byte = 0x00
	PushClassWake      byte = 0x01
	PushClassAttention byte = 0x02
)

// ADLen is the fixed canonical AD width:
// channel_id(16) ‖ seq(8 BE) ‖ push_class(1).
const ADLen = 25

// b64 is the single binary wire encoding: base64url, unpadded,
// canonical (Strict rejects non-canonical trailing bits).
var b64 = base64.RawURLEncoding.Strict()

// ParsePushClass maps the wire string enum to the AD byte.
func ParsePushClass(s string) (byte, error) {
	switch s {
	case "none":
		return PushClassNone, nil
	case "wake":
		return PushClassWake, nil
	case "attention":
		return PushClassAttention, nil
	}
	return 0, fmt.Errorf("e2ekit: unknown push_class %q", s)
}

// PushClassString maps the AD byte back to the wire string.
func PushClassString(b byte) string {
	switch b {
	case PushClassNone:
		return "none"
	case PushClassWake:
		return "wake"
	case PushClassAttention:
		return "attention"
	}
	return "none"
}

// BuildAD builds the canonical 25-byte associated data. Senders compute
// it from the values they put in the header; receivers MUST recompute it
// from the received header's DECODED bytes, never from the JSON string.
func BuildAD(channelID [16]byte, seq uint64, pushClass byte) [ADLen]byte {
	var ad [ADLen]byte
	copy(ad[:16], channelID[:])
	binary.BigEndian.PutUint64(ad[16:24], seq)
	ad[24] = pushClass
	return ad
}

// EncodeBin encodes raw bytes as unpadded base64url (the only binary
// wire encoding on this surface).
func EncodeBin(raw []byte) string { return b64.EncodeToString(raw) }

// DecodeBin strictly decodes an unpadded canonical base64url string that
// must yield exactly n raw bytes. Padding, alternate alphabets,
// non-canonical trailing bits, and any other length are rejected.
func DecodeBin(s string, n int) ([]byte, error) {
	if len(s) != b64.EncodedLen(n) {
		return nil, fmt.Errorf("e2ekit: base64url field must be %d chars for %d bytes, got %d", b64.EncodedLen(n), n, len(s))
	}
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("e2ekit: non-canonical base64url: %w", err)
	}
	if len(raw) != n {
		return nil, fmt.Errorf("e2ekit: base64url field decoded to %d bytes, want %d", len(raw), n)
	}
	return raw, nil
}

// EncodeChannelID encodes a 16-byte channel id as its 22-char wire form.
func EncodeChannelID(id [16]byte) string { return b64.EncodeToString(id[:]) }

// DecodeChannelID strictly decodes a 22-char canonical channel id.
func DecodeChannelID(s string) ([16]byte, error) {
	var id [16]byte
	raw, err := DecodeBin(s, 16)
	if err != nil {
		return id, err
	}
	copy(id[:], raw)
	return id, nil
}
