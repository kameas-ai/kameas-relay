// Package jwtverify is the relay's ONLY cryptographic package, and the
// single exception carved into the §XII condition-2 import deny-list
// (internal/fakerelay/denylist_test.go, which allow-lists this package by
// exact import path and nothing else).
//
// # Why an exception exists at all
//
// relay-api.md §1 states the relay's entire cryptographic surface as "TLS
// (Go stdlib) and JWT/JWKS validation". TLS is the runtime's; JWT/JWKS
// validation is this package's. Everything else in the relay — routing,
// mailbox, presence, pairing windows, APNs triggering — is deny-listed and
// reaches no crypto primitive at all.
//
// # Why the exception does not weaken the condition-2 claim
//
// §XII condition 2 asks for a relay that PROVABLY CANNOT DECRYPT. What this
// package does is strictly disjoint from decryption:
//
//   - It performs PUBLIC-KEY SIGNATURE VERIFICATION ONLY. It holds no
//     private key, no symmetric key, and no shared secret. Every key it ever
//     loads is a public key fetched from the identity provider's published
//     JWKS document — material anyone on the internet can fetch.
//   - It never decrypts anything. There is no AEAD open, no stream cipher,
//     no key-agreement, and no KDF in this package. Verification consumes a
//     signature and produces a boolean; it cannot produce plaintext because
//     it is never given ciphertext.
//   - It touches no E2E material. It cannot: it is forbidden to import the
//     pairing/session crypto set (x/crypto AEADs, curve25519, blake2b as a
//     KDF, any libsodium binding) and the endpoint instruments (e2ekit,
//     wire, fakehost, devclient) — the deny-list asserts that separately for
//     this package, so the allow-list is a hole for stdlib signature
//     verification and not a hole for E2E crypto.
//   - It reads exactly one claim. Only `sub` leaves this package (§2: "The
//     JWT sub is in the enumerated plaintext budget. Nothing else from the
//     token — email, name, or any other claim — may be read, stored, or
//     logged."). Claims is a one-field struct on purpose; there is nowhere
//     for a second claim to go.
//
// The negative property the deny-list protects is therefore intact: adding
// an AEAD import to the router still fails the build, and adding one HERE
// fails the build too.
//
// # What this package is NOT
//
// It is not a security boundary. Per §XII condition 6 and relay-api.md §2,
// relay-side authorization is METADATA-LEVEL DEFENSE IN DEPTH. Compromise of
// everything in this package yields routing capability and nothing else: no
// content, no command authority, no key material. No feature in any repo may
// be designed on the assumption that the relay enforces anything.
//
// # Implementation posture
//
// Standard library only — no third-party JWT library. A JWT verifier is
// roughly two hundred lines of parsing plus one call to crypto/rsa or
// crypto/ecdsa, and the audit cost of one small readable file is far below
// the audit cost of a dependency tree in the one package where a reader is
// looking hardest.
package jwtverify
