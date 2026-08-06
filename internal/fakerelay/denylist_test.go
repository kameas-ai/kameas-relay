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
// Within the relay scope the deny-list is ABSOLUTE:
//
//   - `crypto` or any `crypto/*` stdlib package — even `crypto/rand`;
//     relay ids are routing metadata generated from math/rand/v2
//     (relay-api.md §3.1).
//   - `golang.org/x/crypto/...` (the whole tree).
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

// deniedImport reports whether an import path violates the deny-list
// when found in a relay-scoped package.
func deniedImport(imp string) bool {
	switch {
	case imp == "crypto" || strings.HasPrefix(imp, "crypto/"):
		return true
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

// TestDenyListClassifier is the self-test that keeps the negative
// verification property honest: if the classifier stops flagging these,
// the walk below would pass vacuously.
func TestDenyListClassifier(t *testing.T) {
	mustDeny := []string{
		"crypto",
		"crypto/rand",
		"crypto/subtle",
		"crypto/aes",
		"golang.org/x/crypto/chacha20poly1305",
		"golang.org/x/crypto/curve25519",
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
		if !deniedImport(imp) {
			t.Errorf("deny-list classifier no longer flags %q — the structural proof is broken", imp)
		}
	}
	mustAllow := []string{
		"net/http",
		"math/rand/v2",
		"github.com/coder/websocket",
		modulePath + "/internal/fakerelay",
		modulePath + "/cmd/fakerelay",
	}
	for _, imp := range mustAllow {
		if deniedImport(imp) {
			t.Errorf("deny-list classifier wrongly flags %q", imp)
		}
	}
	if !relayScoped(modulePath+"/internal/relay") || !relayScoped(modulePath+"/internal/relay/store") {
		t.Error("future internal/relay packages must be relay-scoped")
	}
	if relayScoped(modulePath + "/e2ekit") {
		t.Error("e2ekit must not be relay-scoped")
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
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decoding go list output: %v", err)
		}
		if !relayScoped(p.ImportPath) {
			continue
		}
		checked++
		for _, group := range [][]string{p.Imports, p.TestImports, p.XTestImports} {
			for _, imp := range group {
				if deniedImport(imp) {
					t.Errorf("relay package %s imports deny-listed %q — the relay must provably carry no crypto and no endpoint code (§XII condition 2)", p.ImportPath, imp)
				}
			}
		}
	}
	if checked < 2 {
		t.Fatalf("deny-list walked only %d relay packages; expected internal/fakerelay and cmd/fakerelay at minimum", checked)
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
