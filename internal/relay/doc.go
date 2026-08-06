// Package relay is the PRODUCTION implementation of
// specs/074-kenaz-ios-remote/contracts/relay-api.md — the WSS attach
// surface, the channel router, the ciphertext mailbox, presence, pairing
// windows, account binding, rate limits, and the APNs trigger.
//
// # The relay is a dumb pipe by construction, not by policy
//
// Per ADR-remote-access-amendment §XII (constitution v2.1.0), this service
// never decrypts, never derives a key, never verifies an AEAD tag, never
// sees a pairing token, and never handles key material of any kind.
//
// Its ENTIRE visibility into a frame is the three-field plaintext header
// {channel, seq, push_class} (e2e-envelope.md §2). Bodies are opaque bytes
// from the moment they arrive to the moment they are forwarded or handed
// back from the mailbox — never parsed, never interpreted, never split (not
// even at the fixed 24-byte nonce boundary: that layout is the receiver's
// business, and depending on it would couple the relay to the AEAD
// construction, which §1 forbids).
//
// Two proofs back that claim and both run in `make check`:
//
//   - STRUCTURAL — internal/fakerelay/denylist_test.go walks the import
//     graph of every relay package, including this one and cmd/relayd, and
//     fails the build if any of them imports a crypto primitive or any
//     endpoint code. The single allow-listed exception is
//     internal/jwtverify (public-key signature verification for JWTs; see
//     that package's doc for why it does not weaken the claim).
//   - BEHAVIOURAL — sc2/noplaintext_test.go drives complete E2E sessions
//     through THIS package with known-plaintext canaries and asserts the
//     canary appears in no stored record, no log line, no health surface,
//     and no error message.
//
// # Authorization here is not a security boundary
//
// §XII condition 6: everything this package enforces — account binding,
// channel authorization, pairing-window admission, revocation — is
// METADATA-LEVEL DEFENSE IN DEPTH. Compromising all of it yields routing
// capability and nothing else: no content, no command authority, no key
// material. Nothing in any repo may be designed on the assumption that the
// relay enforces anything.
//
// # Relationship to internal/fakerelay
//
// internal/fakerelay is the contract-faithful in-memory test double every
// other spec-074 lane builds against. It is NOT this package's ancestor and
// this package is not its wrapper: they are independent implementations of
// one contract, and internal/relayparity runs a shared scripted table
// against both so the double cannot silently drift from the service.
//
// # Persistence
//
// State lives behind the Store interface, whose method set is exactly the
// six persistence classes of relay-api.md §8 and nothing else. MemStore is
// the only implementation today; see store.go for the restart semantics and
// why they are safe.
package relay
