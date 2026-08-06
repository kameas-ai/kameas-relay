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
  walks the import graph of every **relay package** — `internal/fakerelay`,
  `internal/relay`, `internal/jwtverify`, `internal/relayparity`,
  `cmd/fakerelay`, `cmd/relayd` — and fails the build if any of them reaches
  a cryptographic primitive or any endpoint code. It hard-counts the packages
  it walked, so a walk that silently stopped covering the real relay fails
  rather than passing vacuously.

  **Deny-list scope (rescoped at Task 1.3, deliberately).** Relay scope is
  `internal/...` (the whole tree is reserved for relay code) plus
  `cmd/fakerelay` / `cmd/relayd`. The top-level packages — `e2ekit`, `wire`,
  `fakehost`, `devclient`, `sc2`, `cmd/fakehost`, `cmd/remotectl` — are
  **host/device-side instruments that hold and derive keys BY DESIGN**: they
  are the two E2E endpoints in miniature. §XII condition 2's property is
  that the *relay* cannot decrypt, not that no code anywhere can; a
  module-wide crypto ban would make the endpoint instruments unimplementable
  while proving nothing extra. The inverse guard is enforced too: relay
  packages may import **no** first-party package outside relay scope, so
  `e2ekit` (and every other key-holding package) is structurally unreachable
  from relay code, and — because relay packages can only import relay
  packages first-party-wise — no import chain can smuggle crypto in
  transitively.

  **Two tiers, and one narrow exception (Task 2.A3).** Tier 1 is the
  E2E-crypto set — `golang.org/x/crypto/...`, any libsodium binding, anything
  under `kenaz/internal/remote`, and every first-party package outside relay
  scope — and it is **absolute, with no allow-list**. Tier 2 is stdlib
  `crypto` / `crypto/*`, banned in every relay package **except**
  `internal/jwtverify`, allow-listed by exact import path.

  That exception exists because the real relay must validate Zitadel JWTs and
  a signature cannot be verified without a signature primitive. It does not
  weaken the claim: `internal/jwtverify` holds only **public** keys from a
  published JWKS document, has no AEAD open / stream cipher / key agreement /
  KDF and refuses HS\* algorithms (which would need a symmetric key), is never
  handed ciphertext so cannot produce plaintext, and returns a one-field
  `Claims` carrying only `sub` — the single claim inside the §XII condition-3
  budget. The package is still bound by tier 1 in full, and
  `TestCryptoAllowList` asserts all three properties: the allow-list is
  exactly one package, it matches by exact path so nothing inherits it by
  adjacency, and the allow-listed package still cannot reach E2E crypto.
  `crypto/rand` remains banned in the router — relay ids are routing metadata
  (§3.1) generated from `math/rand/v2`, so an auditor reading `internal/relay`
  finds no crypto import at all.

  **Negative verification** (performed 2026-08-06, both directions): injecting
  `crypto/rand` + `golang.org/x/crypto/chacha20poly1305` into `internal/relay`
  fails `TestZeroCryptoDenyList`; injecting `chacha20poly1305` into the
  *allow-listed* `internal/jwtverify` **also** fails it. `TestDenyListClassifier`
  keeps the classifier itself honest.
- **Behavioural proof**: `sc2/noplaintext_test.go` (SC-2, Task 2.A4) drives
  complete E2E sessions — pairing, live stream, an approval round-trip, an
  offline mailbox cycle, and the drain — through the **real** relay with known
  plaintext canaries, then asserts the canary appears in **no** stored record
  (raw bytes, not just the JSON rendering), **no** log line at debug level,
  **no** health surface, **no** APNs payload, and **no** error message. It
  carries three anti-vacuity guards: a positive control (`host_label`, which
  the relay legitimately holds, must be *found*), a non-vacuity check (every
  canary must have been decrypted at an endpoint, proving it really traversed
  the relay), and a deliberate-failure test that plants each canary in a
  fabricated surface and asserts the detector fires. It runs in `make check`,
  so a red SC-2 is a ship-blocking constitutional failure, not a flake.
- **Public source** (§XII condition 7): this repository **MUST be public at
  first push**. Auditability of the relay's inability to see content is a
  ratified condition, not a preference.

## Repo map

| Path | What it is | Holds keys? |
|---|---|---|
| `internal/relay/` | **The production relay** (Task 2.A2/2.A3): attach surface, channel router, mailbox, presence, pairing windows, APNs trigger, `Store` | **never** (deny-listed) |
| `cmd/relayd/` | The production binary | **never** (deny-listed) |
| `internal/jwtverify/` | Zitadel JWT / JWKS **signature verification** — the one tier-2 allow-list entry | public keys only |
| `internal/relayparity/` | One scripted contract table run against **both** relay implementations | **never** (deny-listed) |
| `internal/fakerelay/` | In-memory relay test double (Task 1.2); also hosts the deny-list proof | **never** (deny-listed) |
| `cmd/fakerelay/` | The fake relay as a runnable binary | **never** (deny-listed) |
| `sc2/` | The SC-2 no-plaintext property test (Task 2.A4) | yes, by design (endpoint-side) |
| `e2ekit/` | Pure-Go **reference implementation** of the full E2E construction (Task 1.3) | yes, by design |
| `wire/` | Endpoint-side frame + envelope codec (deliberately not shared with relay code) | no, but endpoint-side |
| `fakehost/` | Scripted host-side responder (pairing, sessions, snapshots, events, approvals) | yes, by design |
| `devclient/` | Device-side client library (pair / connect / watch / approve) | yes, by design |
| `cmd/fakehost/`, `cmd/remotectl/` | The Task 1.3 CLI instruments | yes, by design |

### `internal/relay` and `internal/fakerelay` are independent, and pinned together

The fake is **contract-defining** for four other lanes (kenaz host agent, iOS
integration tests, `remotectl`, the harness). If it drifts from the service,
those lanes are testing against a relay that does not exist and the drift
surfaces at integration time. The two are therefore *independent*
implementations of one contract — neither wraps the other — and
`internal/relayparity` runs a single scripted table against both so nothing
can diverge silently. A case that passes against only one of them is a bug in
one of them, or a contract gap; either way it goes to review rather than into
a per-implementation branch.

`fakerelay` ↔ `relay` parity is a STABLE-promotion condition of
`kameas.relay.protocol`.

### `internal/relay/store.go` — the §8 persistence budget as a type

`Store`'s method set is exactly the six persistence classes of relay-api.md §8
and nothing else, so adding a seventh requires adding a method, which requires
a review, which is where the NFR-3 threat-model obligation bites. `MemStore`
is the only implementation today and is adequate for LLE, where every class is
ephemeral or short-TTL by contract.

**Restart semantics, stated rather than discovered.** Mailbox loss is
absorbed by the device's forward-only drain plus the mandatory `snapshot.full`
reconcile (eviction and TTL already produce `seq` gaps, so a restart is
indistinguishable from a heavy eviction); presence rebuilds on the next
heartbeat; pairing windows are ≤5 min and human-gated; rate-limit counters are
non-durable **by contract**. The real cost is **routing registrations and host
bindings** — losing those refuses every paired device until the host
re-registers, and re-opens the §2.2 TOFU window. That is why a durable `Store`
is a prerequisite for anything past LLE, and why those two classes would move
first.

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

## Running the production relay (`relayd`)

Configuration is entirely environmental and is **validated at boot** — a bad
value is fatal rather than clamped, because a relay running with a silently
adjusted privacy posture is worse than a relay that pages you. The full
variable list is in [`internal/relay/env.go`](internal/relay/env.go); the
essentials:

```sh
RELAY_OIDC_ISSUER=https://<zitadel-instance>   # REQUIRED
RELAY_AUDIENCE=kameas-api                      # default
RELAY_JWKS_URL=...                             # default <issuer>/oauth/v2/keys
RELAY_ADDR=:8080                               # default
go run ./cmd/relayd
```

Three properties worth stating because they are enforced, not merely
intended:

- **There is no unauthenticated mode.** No flag and no variable disables JWT
  validation; `relay.New` refuses a nil `Validator`; without
  `RELAY_OIDC_ISSUER` the process exits non-zero. A test asserts that a set of
  plausible bypass variables (`RELAY_INSECURE`, `RELAY_DEV_MODE`, …) produce
  no valid configuration.
- **The contract's bounds are a ratchet.** Mailbox TTL / frame cap / byte cap,
  window TTL, and offline-after may be tuned **downward** only; the §7.1 frame
  and header caps are hard in both directions and are not reachable from the
  environment at all. Raising any of them fails at boot with a pointer to the
  `CONTRACTS.md` revision that would be required.
- **JWKS failure is fail-closed.** No fresh cache and no reachable JWKS means
  every attach is refused with `auth_unavailable` (503 / WSS 4503) — never a
  fallback to accepting unverified tokens — and `/readyz` reports 503 while it
  lasts. An expired cache entry counts as no cache.

The container image is multi-stage with a distroless/static non-root final
stage and no shell; `HEALTHCHECK` runs `relayd -healthcheck`, which probes the
process's own `/healthz`.

APNs delivery is **not** wired to Apple in this lane: provider credentials are
operator item [OP] 0.7, which gates Phase 4. `relayd` runs a `LogPusher`, so
frames still mailbox and the device still finds them on reconnect; only the
notification is absent. See the `Pusher` doc in
[`internal/relay/apns.go`](internal/relay/apns.go) for why certificate-based
APNs auth should be priced before provider-token auth — the latter needs
signing with a private key in relay scope and therefore a second, separately
argued deny-list entry.

## What is in this repo today

- **`internal/relay/` + `cmd/relayd/`** — the production service (Task
  2.A2/2.A3). Full relay-api.md surface, `Store`-backed persistence, real
  Zitadel JWT validation, structured metadata-only logging, graceful
  shutdown.
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

Auth in the fake is a pluggable `TokenValidator`; the default accepts
`Bearer fake-<subject>` and extracts the subject. Deliberately no real JWT
parsing there: relay authN is metadata-level defense in depth (§XII condition
6), and dragging JWT signature validation into the fake would spend the tier-2
allow-list on a package that does not need it. The production relay exposes
the same seam and wires `internal/jwtverify` into it; `relay.TestOnlySubjectValidator`
mirrors the fake's behaviour so the parity and SC-2 harnesses can drive the
real service without standing up an identity provider — and `cmd/relayd` never
references that type, so no deployment can select it.

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
the architect on 2026-08-06 (relay-api.md changelog, both entries). BOTH the
fake and the production relay implement the ruled contract, and
`internal/relayparity` is what keeps that claim true:

1. **APNs: NSE model (§5.3, candidate (d)).** The relay never learns a
   notification category. Alert pushes are the generic, text-free shape —
   `loc-key: KENAZ_NOTIF_GENERIC` + optional `loc-args: [host_label]`,
   `mutable-content: 1`, no title/body/category — and the device's
   Notification Service Extension decrypts over the E2E path and rewrites
   locally. `categories` is gone from APNs registration (both implementations refuse a
   registration that carries one);
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

### Ambiguities flagged, not adapted

1. **Unknown channel: `not_found` or `forbidden`?** On durable device attach
   and mailbox GET, §7.2's table lists `not_found` for an unknown channel,
   while §2.1's bullet folds "not registered" into the account rule, which
   would argue for `forbidden` everywhere. Both implementations keep the split
   — 404 unknown, 403 wrong account — matching the §7.2 table, and the parity
   suite pins them together so a future ruling moves them as one. *(The
   pairing-attach path is unaffected: §3.2 collapses every refusal there into
   `window_closed`, and that collapse is implemented.)*
2. **`GET /readyz` has no stated failure semantics beyond "incl. JWKS
   reachability" (§7.3).** Implemented as 503 with a fixed `not ready` body
   and no dependency detail, because §7.3's "return no operator data" and the
   §7.2 non-content rule both point that way — but the status code is an
   inference, not a quotation.
3. **The relay-generated id CSPRNG question (§3.1).** §3.1 says the
   provisional channel is "16 relay-generated random bytes" and "metadata
   only. No key material is involved", while the deny-list bans `crypto/rand`
   in relay scope. Implemented with `math/rand/v2` seeded from the runtime's
   entropy, and no component may treat a relay-generated id as an unguessable
   secret — a guessed provisional channel buys only arrival at a ceremony that
   fails closed without the QR's token. If any future design wants these ids
   to be secrets, that is a contract change, not a code change.
4. **`POST /v1/pairing-windows` is rate-limited before the binding check.**
   §7.1 caps windows per host and §3.1 requires the binding, but the contract
   does not order them. Limiting first means an unbound `host_id` can consume
   a bucket keyed on itself; the alternative (authorize first) would let an
   authenticated caller probe binding existence without spending budget.
   Neither leaks anything a caller does not already know, and the two
   implementations agree — but the choice is ours, not the contract's.
5. **APNs provider authentication is unspecified in relay-api.md** and gated
   on [OP] 0.7. Flagged because the two options differ in deny-list impact:
   see the `Pusher` doc in `internal/relay/apns.go`.

Also flagged: **`sc2/noplaintext_test.go` is not at
`internal/relay/noplaintext_test.go`** as tasks.md 2.A4 names it. The test
needs real E2E encryption to mean anything, `go list` attributes test imports
to their package, and hosting it under `internal/relay` would have required
carving a *second* deny-list hole — in the router — for a test's benefit. The
obligation, coverage, and CI wiring are as specified; only the location moved.
The reasoning is in `sc2/doc.go`.

## Build / test

```sh
make check     # gofmt + go vet + go test -race -p 2 ./...  (the gate)
make build     # every binary into bin/
make run-fake  # the in-memory fake relay on 127.0.0.1:7900
make demo      # the one-command end-to-end exit gate
make docker    # the relayd container image
```

`make check` carries **both** halves of the §XII condition-2 proof — the
import deny-list and the SC-2 no-plaintext property test — and CI runs it on
every push and PR to `main`, alongside a `remotectl demo` smoke and a
container build. Neither proof is an optional job: a red SC-2 must fail the
default gate.

Test parallelism is bounded (`-p 2`) by default: the race detector across the
WebSocket suites is file-descriptor hungry, and unbounded package parallelism
alongside other work can exhaust a laptop's process file table.

Requires the Go toolchain named in `go.mod`. No network, no Docker, and no
external services are needed for the test suite — it runs entirely against
in-memory state, with an injected clock wherever time matters.

## License

**Apache-2.0** — see [LICENSE](LICENSE). Operator decision, 2026-08-06.

This repository is public by constitutional requirement, not by preference:
[§XII condition 7](../workspace/.specify/memory/constitution.md) obliges the
relay's source to be public and auditable, because the privacy claim this
service makes — that it *cannot* read what it forwards — is only credible if
anyone can check it. Two files are the proof, and they are the two to read
first: `internal/fakerelay/denylist_test.go`, which shows that no relay
package can reach a cryptographic primitive, and `sc2/noplaintext_test.go`,
which shows that no plaintext reaches the relay when the whole system runs.
