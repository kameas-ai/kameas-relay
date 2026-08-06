# kameas-relay

The Kameas-operated ciphertext rendezvous for **Kenaz iOS Remote** (spec 074):
WSS attach for one host and its paired devices, opaque frame forwarding,
presence, a short-TTL ciphertext mailbox, and an opaque APNs trigger. Deployed
to AWS (LLE first) via `kameas-infra`.

Normative surface: `specs/074-kenaz-ios-remote/contracts/relay-api.md`
(workspace repo), with `contracts/e2e-envelope.md` defining the only thing the
relay may parse — the three-field plaintext frame header
`{channel, seq, push_class}`. Contract entry: `kameas.relay.protocol` in the
workspace `CONTRACTS.md`.

## Constitutional posture (§XII)

Per **ADR-remote-access-amendment §XII** (ratified 2026-08-05, constitution
v2.1.0): the relay is a dumb pipe **by construction, not by policy**. It never
decrypts, never derives a key, never verifies an AEAD tag, never sees a pairing
token, and never handles key material. Every frame body is end-to-end
ciphertext between the phone and the host; the relay **provably cannot**
decrypt it:

- **Structural proof** (§XII condition 2): `internal/fakerelay/denylist_test.go`
  walks the import graph of every **relay package** and fails the build if any
  of them imports `crypto/*`, `golang.org/x/crypto/...`, any libsodium
  binding, anything under `kenaz/internal/remote`, **or any first-party
  package outside the relay scope**. The deny-list is absolute within that
  scope — even `crypto/rand` is banned (ids here are routing metadata, not
  key material, and are generated from `math/rand/v2`). The real relay's only
  permitted cryptographic surface is TLS (Go stdlib) and JWT/JWKS validation,
  both outside first-party code.

  **Deny-list scope (rescoped at Task 1.3, deliberately).** Relay scope is
  `internal/...` (the whole tree is reserved for relay code — today
  `internal/fakerelay`, later `internal/relay*`) plus `cmd/fakerelay` (and the
  future `cmd/relay` / `cmd/relayd`). The top-level packages — `e2ekit`,
  `wire`, `fakehost`, `devclient`, `cmd/fakehost`, `cmd/remotectl` — are
  **host/device-side test instruments that hold and derive keys BY DESIGN**:
  they are the two E2E endpoints in miniature. §XII condition 2's property is
  that the *relay* cannot decrypt, not that no code anywhere can; a
  module-wide crypto ban would make the endpoint instruments unimplementable
  while proving nothing extra. The inverse guard is enforced too: relay
  packages may import **no** first-party package outside relay scope, so
  `e2ekit` (and every other key-holding package) is structurally unreachable
  from relay code, and — because relay packages can only import relay
  packages first-party-wise — no import chain can smuggle crypto in
  transitively. A classifier self-test (`TestDenyListClassifier`) keeps the
  negative verification property honest: the walk still fails the build the
  moment `internal/fakerelay` imports `crypto/rand`.
- **Behavioural proof**: the SC-2 adversarial no-plaintext property test is a
  standing CI obligation of the real relay lane (not yet in this bootstrap).
- **Public source** (§XII condition 7): this repository **MUST be public at
  first push**. Auditability of the relay's inability to see content is a
  ratified condition, not a preference.

## Repo map

| Path | What it is | Holds keys? |
|---|---|---|
| `internal/fakerelay/` | In-memory relay test double (Task 1.2) | **never** (deny-listed) |
| `cmd/fakerelay/` | The fake relay as a runnable binary | **never** (deny-listed) |
| `e2ekit/` | Pure-Go **reference implementation** of the full E2E construction (Task 1.3) | yes, by design |
| `wire/` | Endpoint-side frame + envelope codec (deliberately not shared with relay code) | no, but endpoint-side |
| `fakehost/` | Scripted host-side responder (pairing, sessions, snapshots, events, approvals) | yes, by design |
| `devclient/` | Device-side client library (pair / connect / watch / approve) | yes, by design |
| `cmd/fakehost/`, `cmd/remotectl/` | The Task 1.3 CLI instruments | yes, by design |

### `e2ekit` — the reference implementation, gated by the frozen vectors

`e2ekit` implements the full `ADR-remote-pairing-crypto` construction on
`golang.org/x/crypto` primitives only (no CGo, no libsodium binding — ADR
Decision 7): `crypto_kx` both roles, the directional pairing roots, the keyed-
BLAKE2b session-key schedule (97-byte transcript, version-locked DS strings,
`conf_h`/`conf_d`), `K_mbx`, a hand-rolled libsodium-compatible
`secretstream` push/pull state machine (including libsodium's kept-for-compat
Poly1305 pad misalignment, the `TAG_REKEY`/`TAG_FINAL` rekey, and the
**protocol-layer** post-`TAG_FINAL` refusal — the frame *decrypts*; the layer
above must refuse it), the stateless XChaCha20-Poly1305 mailbox construction,
the canonical 25-byte AD + 22-char base64url channel codec, `mac_pair` over
the B3-widened 145-byte field set, the strict Decision-8 QR codec
(duplicate/unknown parameters rejected), `account_bind`, and the two-regime
sequence-acceptance logic.

`e2ekit/vectors_test.go` is the conformance gate: it loads **all 17 frozen
golden vector files** from `../specs/074-kenaz-ios-remote/contracts/vectors/`
(override with `KENAZ_VECTORS_DIR`; generated against real libsodium 1.0.22),
reproduces every positive chain byte-exactly, asserts every negative case
fails the way its `expect` marker demands, and hard-counts files and cases so
a silently-skipped vector fails the suite. The vectors are **immutable**: a
mismatch means the implementation is wrong, never the vectors.

### remotectl demo — the one-command end-to-end exit gate

```sh
go run ./cmd/remotectl demo
```

spawns an in-process fakerelay + fakehost, pairs a fresh device, receives
`snapshot.full` + the live event stream, gets the scripted
`approval.request`, approves it over the two-valued remote surface
(`allow` → `allow_once`, `[device-auth simulated]`), asserts the
`approval.resolved` round-trip, and prints `PASS`/`FAIL`.

Manual, multi-process flavour:

```sh
go run ./cmd/fakerelay -addr 127.0.0.1:7900 &
go run ./cmd/fakehost -relay http://127.0.0.1:7900 -auto-confirm
# copy the printed QR URI — it alone suffices (§3.2: pairing attach is
# addressed by the QR's host_id; window_id never appears on a device path):
go run ./cmd/remotectl pair --qr 'kenaz://pair?...'
go run ./cmd/remotectl list
go run ./cmd/remotectl watch
go run ./cmd/remotectl approve rid-<24hex> --decision allow
```

Device state persists in `~/.remotectl/state.json` (0600); seq high-water
marks are persisted write-through — loss is fail-closed by design (ADR N5)
and there is deliberately no reset affordance.

## What is in this repo today (Task 1.2 bootstrap)

- **`internal/fakerelay/`** — the contract-faithful, in-memory test double for
  the relay, consumed by **every** spec-074 lane (kenaz host-agent tests, iOS
  integration tests, the Task 1.3 `fakehost`/`remotectl` tools). `New(Config)`
  returns a relay whose `Handler()` mounts on an `httptest.Server`; the control
  surface (`Recorder()`, `HostOnline()`, `FakeClock.Advance()`, pluggable
  `TokenValidator`) lets tests drive presence, mailbox TTL, window expiry, and
  APNs assertions without wall-clock sleeps or real infrastructure. Frames are
  forwarded/buffered **verbatim** — bodies are opaque bytes end to end.
- **`cmd/fakerelay/`** — the fake as a runnable binary (`-addr`, TTL, and
  rate-limit flags) for manual poking and the Task 1.3 CLI tools. Logs
  connection metadata only (ids, counts, status codes) per relay-api.md §9 —
  never frame bytes, never tokens.

The real relay (`cmd/relayd`, `internal/relay/`, Zitadel JWKS validation, real
APNs) lands in Phase 2 Lane A; the fake stays here as the parity reference —
`fakerelay` ↔ real-relay parity is a STABLE-promotion condition of
`kameas.relay.protocol`.

Auth in the fake is a pluggable `TokenValidator`; the default accepts
`Bearer fake-<subject>` and extracts the subject. Deliberately no real JWT
parsing: relay authN is metadata-level defense in depth (§XII condition 6), and
JWT signature validation would drag crypto into the deny-listed import graph.

## Dependency choice

Two third-party dependencies:

- **`golang.org/x/crypto`** — the substrate of the `e2ekit` endpoint
  instrument (curve25519, blake2b, chacha20, chacha20poly1305, poly1305), per
  ADR Decision 7. Structurally unreachable from relay packages (deny-list).
- **`github.com/coder/websocket`** (v1.8.15),
chosen over `golang.org/x/net/websocket` because:

- it has **zero transitive dependencies**, keeping the Simplicity Gate and the
  deny-list story trivially auditable (`go.mod` is two lines);
- it is actively maintained (the continuation of `nhooyr.io/websocket`) with a
  context-aware API, per-message types, and first-class close-status support —
  the contract's WSS close codes (4400/4413/4429/…) need exactly that;
- `x/net/websocket` is documented by its own maintainers as lacking modern
  WebSocket features and is effectively frozen.

Everything else is stdlib.

## Contract alignment (2026-08-06 rulings)

The Task 1.2/1.3 interpretation questions and flagged gaps were all ruled by
the architect on 2026-08-06 (relay-api.md changelog, both entries) and this
repo implements the ruled contract:

1. **APNs: NSE model (§5.3, candidate (d)).** The relay never learns a
   notification category. Alert pushes are the generic, text-free shape —
   `loc-key: KENAZ_NOTIF_GENERIC` + optional `loc-args: [host_label]`,
   `mutable-content: 1`, no title/body/category — and the device's
   Notification Service Extension decrypts over the E2E path and rewrites
   locally. `categories` is gone from APNs registration (the fake refuses it);
   clearing `host_label` removes `loc-args` entirely.
2. **Attach surface (§2.1).** `?host_id=` on `/v1/host` (refuses `?channel=`),
   `?channel=` on `/v1/device` for durable attach, `?host=` on `/v1/device`
   for pairing attach. Bearer tokens ride the `Authorization` header ONLY — a
   token in any query parameter is refused even alongside a valid header.
3. **Account binding (§2.2).** Created only by a successful `/v1/host` attach,
   immutable (differing `sub` ⇒ `forbidden`, no rebind), reaped after 30 days
   idle with zero pairings. Windows and pairing registrations REQUIRE an
   existing binding; device attaches never create one.
4. **Pairing attach addressed by `host_id` (§3.2).** The QR alone suffices —
   `window_id` is a host-facing handle only. The path has exactly two
   outcomes: accept, or one **byte-identical `window_closed`** refusal for
   every cause (unknown/unbound host, account mismatch, no/expired window,
   attach-rate excess) so no window-existence oracle exists. At most one open
   window per host (§3.1); a second POST displaces the first (4410).
5. **Routing when the peer is absent (§4.1).** Device→host with the host
   detached: drop + `{"error":"peer_unavailable","channel"}` TEXT (never a
   close). Host→device is a three-way split: attached ⇒ live forward;
   registered-but-detached ⇒ mailbox **regardless of push_class**;
   unregistered ⇒ drop + `{"error":"not_found","channel"}` TEXT.
6. **Mailbox (§4).** Items are `{seq, push_class, body}` — the class-M body is
   ONE opaque blob; the `nonce(24) ‖ ct` split is the receiver's
   (e2e-envelope §1.2). Reads are non-destructive (NSE + app fetch the same
   item). A drain item that fails authentication is discarded and the drain
   ABANDONED (never skip-and-continue); recovery is the forward-jump
   `snapshot.full` reconcile — `devclient` implements exactly that.
7. **§6.1 device presence to the host.** The relay publishes
   `{"presence":"device","channel","attached","last_seen"}` on the host's
   TEXT channel (current state once on host attach, then transitions).
   `fakehost` consumes it to choose class L (attached) vs class M (detached,
   sealed under `K_mbx` via e2ekit) — the construction choice is the
   sender's, and the fake demonstrates the full offline→mailbox→drain→
   reconcile loop end-to-end in `fakehost/integration_test.go`.

Remaining ambiguity flagged (not adapted): whether an *unknown* channel on
durable device attach / mailbox GET should return `not_found` (the §7.2 table
still lists it) or collapse into `forbidden` (§2.1's bullet folds
"not registered" into the account rule). The fake keeps the split — 404 for
unknown, 403 for wrong account — matching the §7.2 table.

## Build / test

```sh
go build ./...
go vet ./...
go test -race ./...
```

Requires Go 1.24+. No network, no Docker, no external services — the entire
test suite runs against in-memory state with an injected clock.

## License

**Apache-2.0** — see [LICENSE](LICENSE). Operator decision, 2026-08-06.

This repository is public by constitutional requirement, not by preference:
[§XII condition 7](../workspace/.specify/memory/constitution.md) obliges the
relay's source to be public and auditable, because the privacy claim this
service makes — that it *cannot* read what it forwards — is only credible if
anyone can check it. Read `internal/fakerelay/denylist_test.go` first: it is
the structural proof that no relay package imports a crypto library.
