package e2ekit

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

// Hand-rolled crypto_secretstream_xchacha20poly1305, byte-compatible
// with libsodium 1.0.22 (proven by vectors V5/V10/V11/V12; ADR
// Decision 7 names this the one genuine hand-roll and its §Golden-vector
// obligation the gate).
//
// libsodium state semantics reproduced here:
//
//   - init: subkey = HChaCha20(key, header[0:16]); 12-byte IETF nonce =
//     counter(4 LE, reset to 1) ‖ inonce(8) = header[16:24].
//   - each frame: Poly1305 is keyed from ChaCha20 keystream block 0; a
//     64-byte block whose first byte is the tag is encrypted at
//     counter 1; the message at counter 2. The MAC covers
//     ad ‖ pad16(ad) ‖ block(64) ‖ ct(mlen) ‖ PAD ‖ le64(adlen) ‖
//     le64(64+mlen), where PAD is libsodium's
//     `(0x10 - (sizeof block) + mlen) & 0xf` — an acknowledged
//     misalignment ("should have been (0x10 - (sizeof block + mlen))",
//     the source's own comment) kept forever for wire compatibility. It
//     reduces to mlen & 0xf, and it is WHY this construction is not
//     expressible through a standard RFC 8439 AEAD seal: the standard
//     pad is (16 - (64+mlen)%16) & 15, which differs for most lengths.
//     Poly1305 is therefore driven explicitly here.
//   - after each frame: inonce ^= mac[0:8]; counter++; rekey when the
//     tag has the REKEY bit (TAG_REKEY and TAG_FINAL both do) or the
//     counter wraps to 0.
//   - rekey: (k ‖ inonce) ^= ChaCha20-IETF keystream(k, nonce); counter
//     reset to 1.
//
// Post-TAG_FINAL refusal is a PROTOCOL-layer obligation, not a
// cryptographic one: TAG_FINAL rekeys both sides, so a frame pushed
// after the final frame decrypts successfully (verified against
// libsodium at vector freeze — V10's reject_post_final case). Stream
// tracks "finished" itself and Push/Pull refuse on that basis.

// Secretstream tag bytes (libsodium values).
const (
	TagMessage byte = 0x00
	TagPush    byte = 0x01 // unused in v1 (ADR Decision 5)
	TagRekey   byte = 0x02
	TagFinal   byte = TagPush | TagRekey // 0x03
)

const (
	// StreamKeyLen is crypto_secretstream_..._KEYBYTES.
	StreamKeyLen = 32
	// StreamHeaderLen is crypto_secretstream_..._HEADERBYTES.
	StreamHeaderLen = 24
	// StreamOverhead is crypto_secretstream_..._ABYTES: 1 tag byte + 16 MAC.
	StreamOverhead = 17
)

var (
	// ErrStreamFinished is the protocol-layer post-TAG_FINAL refusal: the
	// stream has seen TAG_FINAL and every subsequent frame is refused
	// WITHOUT a decrypt attempt (ADR Decision 5). Distinct from
	// ErrDecryptFailed on purpose — consuming tests assert which one.
	ErrStreamFinished = errors.New("e2ekit: stream finished (TAG_FINAL seen); frame refused at the protocol layer")
	// ErrDecryptFailed is a cryptographic authentication failure.
	ErrDecryptFailed = errors.New("e2ekit: secretstream frame failed authentication")
)

// Stream is one directional secretstream state (push or pull — the state
// is identical; libsodium's init_push and init_pull differ only in who
// draws the header).
type Stream struct {
	k        [32]byte
	nonce    [12]byte // counter(4, little-endian) ‖ inonce(8)
	finished bool
}

func newStream(key [32]byte, header [24]byte) *Stream {
	sub, err := chacha20.HChaCha20(key[:], header[:16])
	if err != nil {
		panic("e2ekit: HChaCha20: " + err.Error()) // unreachable: fixed-size inputs
	}
	s := &Stream{}
	copy(s.k[:], sub)
	s.nonce[0] = 1 // counter reset
	copy(s.nonce[4:], header[16:24])
	return s
}

// NewPushStream initializes a sender stream, drawing the 24-byte header
// from the CSPRNG. Production MUST use this path: headers are random,
// never derived — the vectors treat headers as INPUTS purely so the
// fixtures are deterministic (ADR §How to read the vectors).
func NewPushStream(key [32]byte) (*Stream, [24]byte, error) {
	var header [24]byte
	if _, err := rand.Read(header[:]); err != nil {
		return nil, header, err
	}
	return newStream(key, header), header, nil
}

// NewPullStream initializes a receiver stream from the peer's header.
// (State-identical to an init_push that had drawn this header, which is
// how the vector suite seeds deterministic push states.)
func NewPullStream(key [32]byte, header [24]byte) *Stream {
	return newStream(key, header)
}

// Finished reports whether the stream has seen TAG_FINAL.
func (s *Stream) Finished() bool { return s.finished }

// Push seals one frame: plaintext ‖ ad ‖ tag → frame of
// len(plaintext)+17 bytes. After TAG_FINAL the stream refuses further
// pushes (the sender-side half of the protocol close).
func (s *Stream) Push(plaintext, ad []byte, tag byte) ([]byte, error) {
	if s.finished {
		return nil, ErrStreamFinished
	}
	return s.pushRaw(plaintext, ad, tag), nil
}

// cipher returns the frame's ChaCha20 stream (counter 0) and the
// Poly1305 state keyed from keystream block 0. After the call the
// cipher sits at counter 1 (the tag block), then counter 2 (the
// message) — consumption is contiguous, matching libsodium's
// xor_ic(…, 1) / xor_ic(…, 2) calls exactly.
func (s *Stream) cipher() (*chacha20.Cipher, *poly1305.MAC) {
	c, err := chacha20.NewUnauthenticatedCipher(s.k[:], s.nonce[:])
	if err != nil {
		panic("e2ekit: chacha20: " + err.Error()) // unreachable: fixed sizes
	}
	var block0 [64]byte
	c.XORKeyStream(block0[:], block0[:])
	var polyKey [32]byte
	copy(polyKey[:], block0[:32])
	return c, poly1305.New(&polyKey)
}

var pad0 [16]byte

// macTail feeds the trailing pad and length words into the MAC:
// libsodium's kept-for-compat ciphertext pad (mlen & 0xf — see the
// package comment) then le64(adlen) ‖ le64(64+mlen).
func macTail(poly *poly1305.MAC, adlen, mlen int) {
	poly.Write(pad0[:mlen&0xf])
	var slen [8]byte
	binary.LittleEndian.PutUint64(slen[:], uint64(adlen))
	poly.Write(slen[:])
	binary.LittleEndian.PutUint64(slen[:], uint64(64+mlen))
	poly.Write(slen[:])
}

// pushRaw is the cryptographic push without the protocol-layer finished
// check. Kept unexported: only the vector suite uses it, to prove that a
// post-TAG_FINAL frame is cryptographically producible/decryptable and
// therefore that the refusal must live at the protocol layer.
func (s *Stream) pushRaw(plaintext, ad []byte, tag byte) []byte {
	c, poly := s.cipher()
	poly.Write(ad)
	poly.Write(pad0[:(16-len(ad)&0xf)&0xf])

	var block [64]byte
	block[0] = tag
	c.XORKeyStream(block[:], block[:]) // counter 1
	poly.Write(block[:])

	frame := make([]byte, 1+len(plaintext)+16)
	frame[0] = block[0]
	c.XORKeyStream(frame[1:1+len(plaintext)], plaintext) // counter 2
	poly.Write(frame[1 : 1+len(plaintext)])
	macTail(poly, len(ad), len(plaintext))

	mac := poly.Sum(nil)
	copy(frame[1+len(plaintext):], mac)
	s.advance(mac, tag)
	return frame
}

// Pull opens one frame, returning the plaintext and the frame's tag. A
// stream that has seen TAG_FINAL refuses every subsequent frame with
// ErrStreamFinished — the frame is not even decrypted (ADR Decision 5).
func (s *Stream) Pull(frame, ad []byte) ([]byte, byte, error) {
	if s.finished {
		return nil, 0, ErrStreamFinished
	}
	return s.pullRaw(frame, ad)
}

// pullRaw is the cryptographic pull without the protocol-layer finished
// check (see pushRaw). MAC verification precedes decryption, and the
// state does NOT advance on failure (libsodium semantics).
func (s *Stream) pullRaw(frame, ad []byte) ([]byte, byte, error) {
	if len(frame) < StreamOverhead {
		return nil, 0, ErrDecryptFailed
	}
	mlen := len(frame) - StreamOverhead
	c, poly := s.cipher()
	poly.Write(ad)
	poly.Write(pad0[:(16-len(ad)&0xf)&0xf])

	// Decrypt the tag byte; the block's remaining 63 bytes become raw
	// keystream, which is exactly what the push side MAC'd (its
	// encryption of 63 zero bytes). Restore the wire byte before MACing.
	var block [64]byte
	block[0] = frame[0]
	c.XORKeyStream(block[:], block[:]) // counter 1
	tag := block[0]
	block[0] = frame[0]
	poly.Write(block[:])

	ct := frame[1 : 1+mlen]
	poly.Write(ct)
	macTail(poly, len(ad), mlen)

	mac := poly.Sum(nil)
	if subtle.ConstantTimeCompare(mac, frame[1+mlen:]) != 1 {
		return nil, 0, ErrDecryptFailed
	}
	msg := make([]byte, mlen)
	c.XORKeyStream(msg, ct) // counter 2
	s.advance(mac, tag)
	return msg, tag, nil
}

// advance applies the post-frame state transition.
func (s *Stream) advance(mac []byte, tag byte) {
	for i := 0; i < 8; i++ {
		s.nonce[4+i] ^= mac[i]
	}
	ctr := binary.LittleEndian.Uint32(s.nonce[:4]) + 1
	binary.LittleEndian.PutUint32(s.nonce[:4], ctr)
	if tag&TagRekey != 0 || ctr == 0 {
		s.rekey()
	}
	if tag == TagFinal {
		s.finished = true
	}
}

// rekey is crypto_secretstream_xchacha20poly1305_rekey.
func (s *Stream) rekey() {
	var buf [40]byte
	copy(buf[:32], s.k[:])
	copy(buf[32:], s.nonce[4:12])
	c, err := chacha20.NewUnauthenticatedCipher(s.k[:], s.nonce[:])
	if err != nil {
		panic("e2ekit: chacha20: " + err.Error()) // unreachable
	}
	c.XORKeyStream(buf[:], buf[:])
	copy(s.k[:], buf[:32])
	copy(s.nonce[4:], buf[32:])
	s.nonce[0], s.nonce[1], s.nonce[2], s.nonce[3] = 1, 0, 0, 0
}
