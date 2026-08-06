// Package e2ekit is the pure-Go reference implementation of the spec-074
// end-to-end crypto construction defined by ADR-remote-pairing-crypto
// (Accepted 2026-08-05) and contracts/e2e-envelope.md: crypto_kx pairing
// roots, the keyed-BLAKE2b session-key schedule, a hand-rolled
// libsodium-compatible secretstream (XChaCha20-Poly1305) state machine,
// the stateless mailbox AEAD under K_mbx, the pairing MAC, the QR
// payload codec, and the two-regime sequence-acceptance logic.
//
// Every byte-level claim in this package is validated against the frozen
// golden vectors in specs/074-kenaz-ios-remote/contracts/vectors/
// (generated against real libsodium 1.0.22 — see vectors_test.go). The
// vectors are IMMUTABLE: a mismatch means this code is wrong, never the
// vectors.
//
// Dependencies are golang.org/x/crypto primitives only (curve25519,
// blake2b, chacha20, chacha20poly1305) per ADR Decision 7 — no CGo, no
// libsodium binding.
//
// This package is a host/device-side instrument: it holds and derives
// keys BY DESIGN. It must never be imported by relay code
// (internal/..., cmd/fakerelay) — the deny-list in
// internal/fakerelay/denylist_test.go enforces that structurally
// (§XII condition 2).
package e2ekit
