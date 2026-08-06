package e2ekit

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Mailbox frames are a DIFFERENT construction, on purpose (ADR
// Decision 5): a stateless crypto_aead_xchacha20poly1305_ietf under the
// session-independent K_mbx with a random 24-byte nonce, because
// secretstream cannot span a session boundary. Which key applies is
// determined by transport (REST mailbox vs live WSS), never by a wire
// flag — vectors V12 pin both misuse directions as decrypt failures.

// MailboxNonceLen is the XChaCha20-Poly1305 nonce length.
const MailboxNonceLen = 24

// ErrMailboxDecryptFailed is a mailbox-frame authentication failure.
var ErrMailboxDecryptFailed = errors.New("e2ekit: mailbox frame failed authentication")

// SealMailbox encrypts one mailbox envelope under kMbx with the given
// nonce and canonical AD, returning ciphertext only (no nonce prefix).
// Production callers use SealMailboxFrame, which draws the nonce.
func SealMailbox(kMbx [32]byte, nonce [24]byte, plaintext, ad []byte) []byte {
	aead, err := chacha20poly1305.NewX(kMbx[:])
	if err != nil {
		panic("e2ekit: xchacha20poly1305: " + err.Error()) // unreachable: fixed key size
	}
	return aead.Seal(nil, nonce[:], plaintext, ad)
}

// SealMailboxFrame seals a mailbox envelope with a fresh random nonce
// and returns the class-M wire body: nonce(24) ‖ ciphertext.
func SealMailboxFrame(kMbx [32]byte, plaintext, ad []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	ct := SealMailbox(kMbx, nonce, plaintext, ad)
	body := make([]byte, 24+len(ct))
	copy(body[:24], nonce[:])
	copy(body[24:], ct)
	return body, nil
}

// OpenMailbox decrypts one mailbox ciphertext under kMbx.
func OpenMailbox(kMbx [32]byte, nonce [24]byte, ciphertext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kMbx[:])
	if err != nil {
		panic("e2ekit: xchacha20poly1305: " + err.Error()) // unreachable
	}
	pt, err := aead.Open(nil, nonce[:], ciphertext, ad)
	if err != nil {
		return nil, ErrMailboxDecryptFailed
	}
	return pt, nil
}

// OpenMailboxFrame splits a class-M wire body (nonce ‖ ct) at the fixed
// 24-byte boundary and decrypts it.
func OpenMailboxFrame(kMbx [32]byte, body, ad []byte) ([]byte, error) {
	if len(body) < MailboxNonceLen {
		return nil, ErrMailboxDecryptFailed
	}
	var nonce [24]byte
	copy(nonce[:], body[:24])
	return OpenMailbox(kMbx, nonce, body[24:], ad)
}
