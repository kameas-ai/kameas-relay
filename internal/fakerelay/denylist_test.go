package fakerelay

// Zero-crypto structural proof — ADR-remote-access-amendment §XII
// condition 2, relay-api.md §1.
//
// §XII asks for a relay that PROVABLY cannot decrypt. The behavioural
// half of that proof is the SC-2 no-plaintext property test (a standing
// CI obligation of the real relay lane); this test is the STRUCTURAL
// half: the import graph of every RELAY package in this module is walked
// and the build fails if any of them imports a cryptographic primitive
// or any E2E-endpoint code.
//
// SCOPE (rescoped at Task 1.3, deliberately): the deny-list covers the
// RELAY packages only —
//
//   - `internal/...`  (internal/fakerelay today; internal/relay* when
//     the real relay lands — the whole internal tree is RESERVED for
//     relay code)
//   - `cmd/fakerelay`, and the future `cmd/relay` / `cmd/relayd`
//
// It does NOT cover the top-level host/device-side test instruments
// (`e2ekit`, `wire`, `fakehost`, `devclient`, `cmd/fakehost`,
// `cmd/remotectl`). Those packages hold and derive keys BY DESIGN — they
// are the two E2E endpoints in miniature, and e2ekit is the reference
// implementation validated against the frozen golden vectors. The §XII
// condition-2 property is that the RELAY cannot decrypt, not that no
// code anywhere can; banning crypto module-wide would make the endpoint
// instruments unimplementable and prove nothing extra.
//
// Within the relay scope there are TWO tiers.
//
// TIER 1 — the E2E-crypto set. ABSOLUTE: no relay-scope package may import
// any of these, and there is no allow-list:
//
//   - `golang.org/x/crypto/...` (the whole tree — chacha20poly1305,
//     curve25519, blake2b-as-KDF, and everything alongside them).
//   - any libsodium binding or sodium wrapper (cgo or pure-Go).
//   - anything under `kenaz/internal/remote` (relay-api.md §1: the relay
//     must not share code with the E2E endpoints).
//   - **any first-party package outside the relay scope** — which bans
//     `e2ekit`, `wire`, `fakehost`, and `devclient` by construction (the
//     inverse guard), and closes the transitive hole: since every
//     relay-scope package may only import relay-scope first-party
//     packages, and every relay-scope package is walked, no chain of
//     first-party imports can smuggle crypto in.
//
// TIER 2 — stdlib `crypto` / `crypto/*`. Banned in every relay-scope
// package EXCEPT the packages named in cryptoAllowList, which today is
// exactly one: `internal/jwtverify`.
//
// # Why tier 2 has an exception, and why the claim survives it
//
// The deny-list was absolute through Task 1.3 because the fake relay needed
// no crypto at all. Task 2.A3 requires the REAL relay to validate Zitadel
// JWTs, and a JWT signature cannot be verified without a signature
// primitive. Two ways to resolve that honestly were available: widen the
// list, or narrow it. This narrows it.
//
// relay-api.md §1 already states the relay's cryptographic surface as "TLS
// (Go stdlib) and JWT/JWKS validation" — so JWT validation was never
// outside the contract's budget; the Task-1.3 deny-list was simply stricter
// than the contract because nothing yet needed the allowance. What §XII
// condition 2 asks for is a relay that PROVABLY CANNOT DECRYPT, and
// public-key signature verification is disjoint from decryption in every
// respect that matters:
//
//   - it holds only PUBLIC keys, fetched from a published JWKS document;
//   - it has no AEAD open, no stream cipher, no key agreement, no KDF, and
//     no symmetric key anywhere — HS* algorithms are refused for exactly
//     that reason;
//   - it consumes a signature and produces a boolean; it is never handed
//     ciphertext, so it cannot produce plaintext;
//   - it reads ONE claim (`sub`, the only one inside the §XII condition-3
//     plaintext budget) and its return type has one field.
//
// The exception is scoped by EXACT IMPORT PATH, not by prefix, so a new
// package cannot inherit it by being adjacent. The allow-listed package is
// still subject to tier 1 in full — TestCryptoAllowList below asserts that
// explicitly rather than leaving it to the walk — so the hole admits
// stdlib signature verification and nothing else. And the negative
// property is intact in both directions: adding an AEAD import to the
// router fails the build, and adding one to internal/jwtverify fails it
// too.
//
// Note what remains banned even for the relay's own convenience:
// `crypto/rand` in the router. Relay ids are routing metadata, not key
// material (relay-api.md §3.1: "It is metadata only. No key material is
// involved"), and they are generated from math/rand/v2 so that a reader
// auditing internal/relay finds no crypto import at all.
//
// Scope note on stdlib transitivity, unchanged: the walk covers DIRECT
// imports (including test files) because any HTTPS-capable Go program
// transitively reaches crypto/tls through net/http — TLS is the real
// relay's one permitted cryptographic surface (§1: "Its entire
// cryptographic surface is TLS (Go stdlib) and JWT/JWKS validation").
// What this test proves is that no RELAY-AUTHORED code touches a crypto
// primitive, and that none can be added without failing CI.

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const modulePath = "github.com/kameas-ai/kameas-relay"

// relayScoped reports whether an import path is a RELAY package of this
// module — the packages the deny-list protects.
func relayScoped(imp string) bool {
	switch {
	case strings.HasPrefix(imp, modulePath+"/internal/"):
		return true // internal/ is reserved for relay code
	case imp == modulePath+"/cmd/fakerelay",
		imp == modulePath+"/cmd/relay",
		imp == modulePath+"/cmd/relayd":
		return true
	}
	return false
}

// cryptoAllowList names the ONLY relay-scope packages permitted to import
// stdlib `crypto` / `crypto/*`, by EXACT import path.
//
// Adding an entry here is a constitutional change, not a refactor: it must
// be argued against §XII condition 2 in the package's own doc comment the
// way internal/jwtverify does, and the entry must still satisfy tier 1.
var cryptoAllowList = map[string]bool{
	// Zitadel JWT / JWKS signature verification (Task 2.A3). Public keys
	// only, no decryption, one claim out. See internal/jwtverify/doc.go.
	modulePath + "/internal/jwtverify": true,
}

// deniedE2E is TIER 1: the E2E-crypto and endpoint-code set, banned in
// every relay-scope package with no exceptions.
func deniedE2E(imp string) bool {
	switch {
	case strings.HasPrefix(imp, "golang.org/x/crypto"):
		return true
	case strings.Contains(strings.ToLower(imp), "sodium"): // libsodium / go-sodium / sodium wrappers
		return true
	case strings.Contains(imp, "kenaz/internal/remote"):
		return true
	case strings.HasPrefix(imp, modulePath+"/") && !relayScoped(imp):
		// The inverse guard: relay code must not import the key-holding
		// endpoint instruments (e2ekit, wire, fakehost, devclient) — or
		// any other non-relay first-party package.
		return true
	}
	return false
}

// deniedStdlibCrypto is TIER 2: stdlib crypto, banned everywhere in relay
// scope except the exact packages in cryptoAllowList.
func deniedStdlibCrypto(pkg, imp string) bool {
	if imp != "crypto" && !strings.HasPrefix(imp, "crypto/") {
		return false
	}
	return !cryptoAllowList[pkg]
}

// deniedImport reports whether relay-scope package pkg may import imp.
func deniedImport(pkg, imp string) bool {
	return deniedE2E(imp) || deniedStdlibCrypto(pkg, imp)
}

// TestDenyListClassifier is the self-test that keeps the negative
// verification property honest: if the classifier stops flagging these,
// the walk below would pass vacuously.
func TestDenyListClassifier(t *testing.T) {
	// The router — the package a "helpful" optimization would land in.
	const router = modulePath + "/internal/relay"

	mustDeny := []string{
		"crypto",
		"crypto/rand",
		"crypto/subtle",
		"crypto/aes",
		"crypto/cipher",
		"golang.org/x/crypto/chacha20poly1305",
		"golang.org/x/crypto/curve25519",
		"golang.org/x/crypto/blake2b",
		"github.com/jamesruan/sodium",
		"github.com/GoKillers/libsodium-go/cryptobox",
		"github.com/kameas-ai/kenaz/internal/remote/crypto",
		modulePath + "/e2ekit",
		modulePath + "/wire",
		modulePath + "/fakehost",
		modulePath + "/devclient",
		modulePath + "/cmd/remotectl",
	}
	for _, imp := range mustDeny {
		if !deniedImport(router, imp) {
			t.Errorf("deny-list classifier no longer flags %q in the router — the structural proof is broken", imp)
		}
		if !deniedImport(modulePath+"/internal/fakerelay", imp) {
			t.Errorf("deny-list classifier no longer flags %q in the fake — the structural proof is broken", imp)
		}
	}
	mustAllow := []string{
		"net/http",
		"math/rand/v2",
		"log/slog",
		"github.com/coder/websocket",
		modulePath + "/internal/fakerelay",
		modulePath + "/internal/jwtverify",
		modulePath + "/cmd/fakerelay",
	}
	for _, imp := range mustAllow {
		if deniedImport(router, imp) {
			t.Errorf("deny-list classifier wrongly flags %q", imp)
		}
	}
	if !relayScoped(modulePath+"/internal/relay") || !relayScoped(modulePath+"/internal/relay/store") {
		t.Error("internal/relay packages must be relay-scoped")
	}
	if !relayScoped(modulePath + "/cmd/relayd") {
		t.Error("cmd/relayd must be relay-scoped")
	}
	if relayScoped(modulePath + "/e2ekit") {
		t.Error("e2ekit must not be relay-scoped")
	}
}

// TestCryptoAllowList pins the tier-2 exception. It is the test an auditor
// reads immediately after the file header, and it asserts the three things
// that make the exception safe rather than merely convenient.
func TestCryptoAllowList(t *testing.T) {
	// 1. The exception is ONE package. If this fails, someone widened the
	//    §XII condition-2 surface and this test is where they must argue
	//    for it.
	if len(cryptoAllowList) != 1 || !cryptoAllowList[modulePath+"/internal/jwtverify"] {
		t.Fatalf("crypto allow-list is %v; it must be exactly {internal/jwtverify} — "+
			"widening it is a constitutional change (§XII condition 2), not a refactor", cryptoAllowList)
	}

	// 2. The exception is by EXACT path, so nothing inherits it by
	//    adjacency or by living underneath it.
	for _, neighbour := range []string{
		modulePath + "/internal/jwtverify/inner",
		modulePath + "/internal/jwtverify2",
		modulePath + "/internal/relay",
		modulePath + "/cmd/relayd",
	} {
		if !deniedStdlibCrypto(neighbour, "crypto/aes") {
			t.Errorf("%s inherited the jwtverify crypto allowance; the allow-list must match exact paths only", neighbour)
		}
	}

	// 3. The allow-listed package is STILL fully bound by tier 1 — the
	//    hole admits stdlib signature verification and not E2E crypto.
	const allowed = modulePath + "/internal/jwtverify"
	for _, imp := range []string{
		"golang.org/x/crypto/chacha20poly1305",
		"golang.org/x/crypto/curve25519",
		"golang.org/x/crypto/blake2b",
		"github.com/jamesruan/sodium",
		modulePath + "/e2ekit",
		modulePath + "/wire",
	} {
		if !deniedImport(allowed, imp) {
			t.Errorf("the allow-listed package could import %q — the exception must not reach E2E crypto", imp)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file))) // internal/fakerelay/ -> module root
}

func TestZeroCryptoDenyList(t *testing.T) {
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -json ./...: %v", err)
	}

	type pkg struct {
		ImportPath   string
		Imports      []string
		TestImports  []string
		XTestImports []string
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	checked := 0
	seen := make(map[string]bool)
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decoding go list output: %v", err)
		}
		if !relayScoped(p.ImportPath) {
			continue
		}
		checked++
		seen[p.ImportPath] = true
		for _, group := range [][]string{p.Imports, p.TestImports, p.XTestImports} {
			for _, imp := range group {
				if deniedImport(p.ImportPath, imp) {
					t.Errorf("relay package %s imports deny-listed %q — the relay must provably carry no crypto and no endpoint code (§XII condition 2)", p.ImportPath, imp)
				}
			}
		}
	}
	// Hard-count the packages that MUST be in scope. A walk that silently
	// stopped covering the real relay would pass vacuously, which is the
	// failure mode this whole file exists to prevent.
	for _, must := range []string{
		modulePath + "/internal/fakerelay",
		modulePath + "/internal/relay",
		modulePath + "/internal/jwtverify",
		modulePath + "/cmd/fakerelay",
		modulePath + "/cmd/relayd",
	} {
		if !seen[must] {
			t.Errorf("deny-list walk did not cover %s — the structural proof has a gap", must)
		}
	}
	if checked < 5 {
		t.Fatalf("deny-list walked only %d relay packages; expected at least 5", checked)
	}
}

// TestZeroCryptoGoModRequireList is the second layer for the
// dependencies that could never be legitimate anywhere in this module:
// no libsodium binding may even appear in the dependency set.
//
// Note the Task 1.3 rescope: `golang.org/x/crypto` IS now in go.mod —
// it is the substrate of the e2ekit endpoint instrument — so the module-
// level ban is narrowed to sodium wrappers. The per-package walk above
// is what keeps x/crypto out of every relay package.
func TestZeroCryptoGoModRequireList(t *testing.T) {
	f, err := os.Open(filepath.Join(moduleRoot(t), "go.mod"))
	if err != nil {
		t.Fatalf("open go.mod: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		for _, banned := range []string{"sodium", "libsodium"} {
			if strings.Contains(strings.ToLower(line), banned) {
				t.Errorf("go.mod line %q references deny-listed dependency %q", line, banned)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
}
