package e2ekit

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// Suite pins the protocol version. The domain-separation strings are
// version-locked (ADR Decision 3: "Bumping the protocol version bumps
// every string"), so a Suite derives every DS string from its Proto
// byte; a v1 peer and a v2 peer derive different keys everywhere and
// fail closed at the first decrypt. Vector V14 pins the separation.
type Suite struct {
	Proto byte
}

// V1 is the shipping protocol version.
var V1 = Suite{Proto: 1}

func (s Suite) ds(tail string) []byte {
	return []byte(fmt.Sprintf("KENAZ-REMOTE-v%d:%s", s.Proto, tail))
}

func (s Suite) dsPair() []byte    { return s.ds("pair-mac") }
func (s Suite) dsH2D() []byte     { return s.ds("session:h2d") }
func (s Suite) dsD2H() []byte     { return s.ds("session:d2h") }
func (s Suite) dsMbx() []byte     { return s.ds("mailbox:h2d") }
func (s Suite) dsConfirm() []byte { return s.ds("confirm") }
func (s Suite) dsAcct() []byte    { return s.ds("account-bind") }

// keyedHash32 is crypto_generichash(32, msg..., key): keyed BLAKE2b with
// a 32-byte digest and no salt/personal parameters (ADR Decision 3).
func keyedHash32(key []byte, parts ...[]byte) (out [32]byte) {
	h, err := blake2b.New256(key)
	if err != nil {
		// Only reachable with a key > 64 bytes; every caller passes 32.
		panic("e2ekit: keyed BLAKE2b init: " + err.Error())
	}
	for _, p := range parts {
		h.Write(p)
	}
	h.Sum(out[:0])
	return out
}

// TranscriptLen is the fixed session-transcript width:
// proto(1) ‖ host_id(16) ‖ device_id(16) ‖ n_d(32) ‖ n_h(32).
const TranscriptLen = 97

// Transcript builds the fixed-width 97-byte session transcript T.
func (s Suite) Transcript(hostID, deviceID [16]byte, nD, nH [32]byte) [TranscriptLen]byte {
	var t [TranscriptLen]byte
	t[0] = s.Proto
	copy(t[1:17], hostID[:])
	copy(t[17:33], deviceID[:])
	copy(t[33:65], nD[:])
	copy(t[65:97], nH[:])
	return t
}

// SessionKeys is the per-session derivation output (ADR Decision 3).
type SessionKeys struct {
	H2D   [32]byte // Ksess_h2d
	D2H   [32]byte // Ksess_d2h
	ConfH [32]byte // host's transcript confirmation MAC (keyed by R_h2d)
	ConfD [32]byte // device's transcript confirmation MAC (keyed by R_d2h)
}

// SessionKeys derives the full session schedule from the roots and the
// transcript. Both nonces enter both keys via T — that is the whole
// point (whole-session replay resistance).
func (s Suite) SessionKeys(r Roots, t [TranscriptLen]byte) SessionKeys {
	return SessionKeys{
		H2D:   keyedHash32(r.H2D[:], s.dsH2D(), t[:]),
		D2H:   keyedHash32(r.D2H[:], s.dsD2H(), t[:]),
		ConfH: keyedHash32(r.H2D[:], s.dsConfirm(), t[:]),
		ConfD: keyedHash32(r.D2H[:], s.dsConfirm(), t[:]),
	}
}

// MailboxKey derives K_mbx. It deliberately omits the session nonces —
// the mailbox must survive session boundaries (ADR Decision 3/5).
func (s Suite) MailboxKey(r Roots, hostID, deviceID [16]byte) [32]byte {
	return keyedHash32(r.H2D[:], s.dsMbx(), []byte{s.Proto}, hostID[:], deviceID[:])
}

// MacPair computes the pairing MAC over the full B3-widened 145-byte
// field set, keyed by the one-time pairing token (ADR Decision 8):
//
//	mac_pair = crypto_generichash(32,
//	    DS_PAIR ‖ proto ‖ host_id ‖ host_pk ‖ device_id ‖ dev_pk
//	            ‖ n_d ‖ account_bind, key = token)
func (s Suite) MacPair(token [32]byte, hostID [16]byte, hostPK [32]byte,
	deviceID [16]byte, devPK [32]byte, nD [32]byte, accountBind [16]byte) [32]byte {
	return keyedHash32(token[:], s.dsPair(), []byte{s.Proto},
		hostID[:], hostPK[:], deviceID[:], devPK[:], nD[:], accountBind[:])
}

// AccountBind computes the QR account binding: the first 16 bytes of the
// unkeyed BLAKE2b-256 of DS_ACCT ‖ host_pk ‖ sub. It is a truncation of
// the 32-byte digest, NOT a 16-byte-output BLAKE2b (the digest length is
// part of the parameter block, so those differ). It is a confirmation
// oracle, not a secret (ADR N1); compare in constant time.
func (s Suite) AccountBind(hostPK [32]byte, sub string) (out [16]byte) {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic("e2ekit: BLAKE2b init: " + err.Error())
	}
	h.Write(s.dsAcct())
	h.Write(hostPK[:])
	h.Write([]byte(sub))
	full := h.Sum(nil)
	copy(out[:], full[:16])
	return out
}

// VerifyMAC compares two MAC values in constant time. It is the only
// sanctioned comparison for mac_pair, conf_h/conf_d, and account_bind.
func VerifyMAC(want, got []byte) bool {
	if len(want) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare(want, got) == 1
}
