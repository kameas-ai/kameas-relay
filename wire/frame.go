// Package wire implements the ENDPOINT side of the spec-074 wire
// surface: the WSS binary frame layout (e2e-envelope.md §1.1) and the
// envelope JSON (§5/§6) as consumed by the host and device instruments
// (fakehost, remotectl) — never by the relay.
//
// The ~60 lines of frame framing deliberately DUPLICATE
// internal/fakerelay/frames.go rather than share it: relay code and
// endpoint code must not share implementation (relay-api.md §1 forbids
// the relay sharing code with the E2E endpoints, and the deny-list in
// internal/fakerelay/denylist_test.go makes the direction structural).
package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kameas-ai/kameas-relay/e2ekit"
)

// MaxHeaderLen is the wire header cap (e2e-envelope.md §1.1).
const MaxHeaderLen = 512

// Header is the three-field plaintext frame header — the relay's entire
// visibility into a frame.
type Header struct {
	Channel   string `json:"channel"`
	Seq       uint64 `json:"seq"`
	PushClass string `json:"push_class"`
}

// ChannelID returns the header channel decoded per the strict 22-char
// canonical rule; the AD is built from these bytes, never the string.
func (h Header) ChannelID() ([16]byte, error) {
	return e2ekit.DecodeChannelID(h.Channel)
}

// AD builds the canonical 25-byte associated data for this header.
func (h Header) AD() ([]byte, error) {
	id, err := h.ChannelID()
	if err != nil {
		return nil, err
	}
	pc, err := e2ekit.ParsePushClass(h.PushClass)
	if err != nil {
		return nil, err
	}
	ad := e2ekit.BuildAD(id, h.Seq, pc)
	return ad[:], nil
}

var (
	// ErrFraming covers malformed length framing.
	ErrFraming = errors.New("wire: malformed frame framing")
	// ErrHeader covers a malformed or non-canonical frame header. Both
	// are fatal session aborts for an endpoint (§1.1).
	ErrHeader = errors.New("wire: malformed frame header")
)

// EncodeFrame builds one WSS binary frame:
// uint16-BE header length ‖ header JSON ‖ body.
func EncodeFrame(h Header, body []byte) ([]byte, error) {
	hdr, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if len(hdr) > MaxHeaderLen {
		return nil, fmt.Errorf("wire: header JSON is %d bytes; cap is %d", len(hdr), MaxHeaderLen)
	}
	msg := make([]byte, 2+len(hdr)+len(body))
	binary.BigEndian.PutUint16(msg[:2], uint16(len(hdr)))
	copy(msg[2:], hdr)
	copy(msg[2+len(hdr):], body)
	return msg, nil
}

// DecodeFrame parses one WSS binary frame with strict header validation
// (unknown fields, bad channel encoding, and bad push_class all reject).
func DecodeFrame(msg []byte) (Header, []byte, error) {
	var h Header
	if len(msg) < 2 {
		return h, nil, ErrFraming
	}
	hl := int(binary.BigEndian.Uint16(msg[:2]))
	if hl > MaxHeaderLen || len(msg) < 2+hl {
		return h, nil, ErrFraming
	}
	dec := json.NewDecoder(bytes.NewReader(msg[2 : 2+hl]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil || dec.More() {
		return h, nil, ErrHeader
	}
	if _, err := h.ChannelID(); err != nil {
		return h, nil, ErrHeader
	}
	if _, err := e2ekit.ParsePushClass(h.PushClass); err != nil {
		return h, nil, ErrHeader
	}
	return h, msg[2+hl:], nil
}
