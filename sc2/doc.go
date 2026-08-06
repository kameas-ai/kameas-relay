// Package sc2 holds the BEHAVIOURAL half of the §XII condition-2 proof:
// the SC-2 adversarial no-plaintext property test (tasks.md Task 2.A4,
// spec NFR-3).
//
// A red test here is a SHIP-BLOCKING CONSTITUTIONAL FAILURE, not a flake.
// It is wired into `make check` and therefore into CI, so it cannot rot.
//
// # Why this lives here and not in internal/relay
//
// tasks.md names the file `internal/relay/noplaintext_test.go`. It is here
// instead, and the reason is the deny-list rather than convenience.
//
// The test only means something if the canary it hunts for was genuinely
// end-to-end encrypted on its way through the relay. Planting a canary in a
// plaintext body and then asserting the relay did not store it would assert
// nothing — the relay stores bodies verbatim, and it SHOULD, because they
// are ciphertext. So the test must drive REAL sessions with the real
// construction, which means importing e2ekit, fakehost, and devclient: the
// key-holding endpoint instruments.
//
// Those imports are exactly what the §XII condition-2 deny-list forbids in
// relay scope, and `go list` attributes a package's test imports to the
// package itself — so putting this file under internal/relay would have
// meant carving a second hole in the deny-list, in the router, for the
// benefit of a test. That trade is backwards: the structural proof's whole
// value is that internal/relay's import graph is clean, and weakening it to
// host the behavioural proof would damage the stronger of the two.
//
// Placing the file in a top-level package instead costs nothing and keeps
// both properties whole:
//
//   - `sc2` is an ENDPOINT-side instrument, like e2ekit / fakehost /
//     devclient. It holds keys by design and is outside relay scope, which
//     is where key-holding code belongs.
//   - It imports internal/relay as a CONSUMER. The deny-list constrains
//     what relay packages import, not who imports them, so nothing about
//     the structural proof changes.
//   - internal/relay's import graph — production AND test — stays free of
//     crypto and endpoint code, which is the property an auditor checks
//     first.
//
// Flagged rather than silently adapted: the deviation from tasks.md is the
// file's location only. The obligation, the coverage, and the CI wiring are
// as specified.
package sc2
