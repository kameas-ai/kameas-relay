package e2ekit

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

// crypto_kx per libsodium: keypairs are X25519; session keys are the two
// halves of BLAKE2b-512(q ‖ client_pk ‖ server_pk) where
// q = X25519(sk, peer_pk). Host = server, device = client (ADR
// Decision 1); the halves are named by direction, never mixed (Decision 2):
//
//	R_h2d = keys[0:32]  = client.rx = server.tx   (host→device root)
//	R_d2h = keys[32:64] = client.tx = server.rx   (device→host root)

// KXSeedKeypair derives an X25519 keypair from a 32-byte seed exactly as
// libsodium's crypto_kx_seed_keypair: sk = BLAKE2b-256(seed) (unkeyed),
// pk = scalarmult_base(sk). Vector V1 pins both roles.
func KXSeedKeypair(seed []byte) (pk, sk [32]byte, err error) {
	if len(seed) != 32 {
		return pk, sk, errors.New("e2ekit: kx seed must be 32 bytes")
	}
	sk = blake2b.Sum256(seed)
	p, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return pk, sk, err
	}
	copy(pk[:], p)
	return pk, sk, nil
}

// NewKXKeypair draws a fresh keypair from the CSPRNG (production path).
func NewKXKeypair() (pk, sk [32]byte, err error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return pk, sk, err
	}
	return KXSeedKeypair(seed[:])
}

// kxSessionHash computes BLAKE2b-512(q ‖ client_pk ‖ server_pk).
func kxSessionHash(q []byte, clientPK, serverPK [32]byte) ([]byte, error) {
	h, err := blake2b.New512(nil)
	if err != nil {
		return nil, err
	}
	h.Write(q)
	h.Write(clientPK[:])
	h.Write(serverPK[:])
	return h.Sum(nil), nil
}

// KXClientSessionKeys is crypto_kx_client_session_keys: the device side.
// rx = keys[0:32], tx = keys[32:64].
func KXClientSessionKeys(clientPK, clientSK, serverPK [32]byte) (rx, tx [32]byte, err error) {
	q, err := curve25519.X25519(clientSK[:], serverPK[:])
	if err != nil {
		return rx, tx, err
	}
	keys, err := kxSessionHash(q, clientPK, serverPK)
	if err != nil {
		return rx, tx, err
	}
	copy(rx[:], keys[0:32])
	copy(tx[:], keys[32:64])
	return rx, tx, nil
}

// KXServerSessionKeys is crypto_kx_server_session_keys: the host side.
// tx = keys[0:32], rx = keys[32:64] (the mirror split).
func KXServerSessionKeys(serverPK, serverSK, clientPK [32]byte) (rx, tx [32]byte, err error) {
	q, err := curve25519.X25519(serverSK[:], clientPK[:])
	if err != nil {
		return rx, tx, err
	}
	keys, err := kxSessionHash(q, clientPK, serverPK)
	if err != nil {
		return rx, tx, err
	}
	copy(tx[:], keys[0:32])
	copy(rx[:], keys[32:64])
	return rx, tx, nil
}

// Roots holds the two directional pairing roots.
type Roots struct {
	H2D [32]byte // host→device root (host tx, device rx)
	D2H [32]byte // device→host root (device tx, host rx)
}

// DeviceRoots recomputes the pairing roots on the device (kx client).
func DeviceRoots(devPK, devSK, hostPK [32]byte) (Roots, error) {
	rx, tx, err := KXClientSessionKeys(devPK, devSK, hostPK)
	if err != nil {
		return Roots{}, err
	}
	return Roots{H2D: rx, D2H: tx}, nil
}

// HostRoots recomputes the pairing roots on the host (kx server).
func HostRoots(hostPK, hostSK, devPK [32]byte) (Roots, error) {
	rx, tx, err := KXServerSessionKeys(hostPK, hostSK, devPK)
	if err != nil {
		return Roots{}, err
	}
	return Roots{H2D: tx, D2H: rx}, nil
}
