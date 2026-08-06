package jwtverify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------
// test JWKS provider + locally minted tokens
// ---------------------------------------------------------------------

const (
	testIssuer = "https://lle.zitadel.example"
	testAud    = "kameas-api"
	testKid    = "test-key-1"
)

type provider struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	srv    *httptest.Server

	fetches atomic.Int64
	down    atomic.Bool
	// omitRSA drops the RSA key from the published set, simulating a
	// rotation the relay has not seen yet.
	omitRSA atomic.Bool
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	p := &provider{rsaKey: rk, ecKey: ek}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		p.fetches.Add(1)
		if p.down.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var keys []jwk
		if !p.omitRSA.Load() {
			keys = append(keys, jwk{
				Kty: "RSA", Kid: testKid, Alg: "RS256", Use: "sig",
				N: b64(rk.N.Bytes()),
				E: b64(big.NewInt(int64(rk.E)).Bytes()),
			})
		}
		keys = append(keys, jwk{
			Kty: "EC", Kid: "ec-key-1", Alg: "ES256", Use: "sig", Crv: "P-256",
			X: b64(ek.X.Bytes()), Y: b64(ek.Y.Bytes()),
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwkSet{Keys: keys})
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type claimSet struct {
	Iss   string `json:"iss,omitempty"`
	Sub   string `json:"sub,omitempty"`
	Aud   any    `json:"aud,omitempty"`
	Exp   any    `json:"exp,omitempty"`
	Nbf   any    `json:"nbf,omitempty"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

func defaultClaims() claimSet {
	return claimSet{
		Iss: testIssuer,
		Sub: "user-42",
		Aud: testAud,
		Exp: time.Now().Add(time.Hour).Unix(),
	}
}

// mintRS signs a token with the provider's RSA key.
func (p *provider) mintRS(t *testing.T, kid string, c claimSet) string {
	t.Helper()
	return p.mint(t, map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"}, c, func(signed []byte) []byte {
		d := sha256.Sum256(signed)
		sig, err := rsa.SignPKCS1v15(rand.Reader, p.rsaKey, crypto.SHA256, d[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return sig
	})
}

// mintES signs a token with the provider's P-256 key.
func (p *provider) mintES(t *testing.T, c claimSet) string {
	t.Helper()
	return p.mint(t, map[string]string{"alg": "ES256", "kid": "ec-key-1", "typ": "JWT"}, c, func(signed []byte) []byte {
		d := sha256.Sum256(signed)
		r, s, err := ecdsa.Sign(rand.Reader, p.ecKey, d[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	})
}

func (p *provider) mint(t *testing.T, hdr map[string]string, c claimSet, sign func([]byte) []byte) string {
	t.Helper()
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(c)
	signed := b64(hb) + "." + b64(cb)
	return signed + "." + b64(sign([]byte(signed)))
}

func newVerifier(t *testing.T, p *provider, mut ...func(*Config)) *Verifier {
	t.Helper()
	cfg := Config{
		Issuer:   testIssuer,
		Audience: testAud,
		JWKSURL:  p.srv.URL,
		CacheTTL: MinCacheTTL,
	}
	for _, m := range mut {
		m(&cfg)
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

// ---------------------------------------------------------------------
// the table the contract asks for (relay-api.md §2, tasks.md 2.A3)
// ---------------------------------------------------------------------

func TestVerifyRejectionTable(t *testing.T) {
	p := newProvider(t)
	v := newVerifier(t, p)
	ctx := context.Background()

	// A malformed-but-well-signed token needs a key the verifier does not
	// have; mint one from a foreign key of the right shape.
	foreign, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	badSig := func() string {
		hb, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": testKid, "typ": "JWT"})
		cb, _ := json.Marshal(defaultClaims())
		signed := b64(hb) + "." + b64(cb)
		d := sha256.Sum256([]byte(signed))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, foreign, crypto.SHA256, d[:])
		return signed + "." + b64(sig)
	}()

	noneAlg := func() string {
		hb, _ := json.Marshal(map[string]string{"alg": "none", "kid": testKid})
		cb, _ := json.Marshal(defaultClaims())
		return b64(hb) + "." + b64(cb) + "."
	}()

	hs256 := func() string {
		hb, _ := json.Marshal(map[string]string{"alg": "HS256", "kid": testKid, "typ": "JWT"})
		cb, _ := json.Marshal(defaultClaims())
		return b64(hb) + "." + b64(cb) + "." + b64([]byte("mac"))
	}()

	expired := defaultClaims()
	expired.Exp = time.Now().Add(-2 * time.Hour).Unix()

	future := defaultClaims()
	future.Nbf = time.Now().Add(2 * time.Hour).Unix()

	wrongAud := defaultClaims()
	wrongAud.Aud = "kameas-web"

	audArrayMiss := defaultClaims()
	audArrayMiss.Aud = []string{"kameas-web", "some-other-api"}

	wrongIss := defaultClaims()
	wrongIss.Iss = "https://evil.example"

	noExp := defaultClaims()
	noExp.Exp = nil

	noSub := defaultClaims()
	noSub.Sub = ""

	cases := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"not three parts", "aaa.bbb"},
		{"header not base64url", "!!!.bbb.ccc"},
		{"header not JSON", b64([]byte("nope")) + ".bbb.ccc"},
		{"alg none", noneAlg},
		{"alg HS256 (symmetric)", hs256},
		{"missing kid", p.mintRS(t, "", defaultClaims())},
		{"unknown kid", p.mintRS(t, "no-such-key", defaultClaims())},
		{"bad signature", badSig},
		{"expired", p.mintRS(t, testKid, expired)},
		{"not yet valid", p.mintRS(t, testKid, future)},
		{"wrong audience", p.mintRS(t, testKid, wrongAud)},
		{"audience array without ours", p.mintRS(t, testKid, audArrayMiss)},
		{"wrong issuer", p.mintRS(t, testKid, wrongIss)},
		{"no exp claim", p.mintRS(t, testKid, noExp)},
		{"no sub claim", p.mintRS(t, testKid, noSub)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Verify(ctx, tc.token); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("got err %v; want ErrUnauthenticated", err)
			}
		})
	}
}

func TestVerifyAccepts(t *testing.T) {
	p := newProvider(t)
	v := newVerifier(t, p)
	ctx := context.Background()

	audArray := defaultClaims()
	audArray.Aud = []string{"kameas-web", testAud}

	cases := []struct {
		name  string
		token string
	}{
		{"RS256", p.mintRS(t, testKid, defaultClaims())},
		{"ES256", p.mintES(t, defaultClaims())},
		{"audience array containing ours", p.mintRS(t, testKid, audArray)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := v.Verify(ctx, tc.token)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if c.Subject != "user-42" {
				t.Fatalf("sub = %q; want user-42", c.Subject)
			}
		})
	}
}

// TestOnlySubjectEscapes is the §XII condition-3 check on this package: the
// budget admits `sub` and nothing else, so a token carrying an email and a
// name must yield a Claims value that contains neither.
func TestOnlySubjectEscapes(t *testing.T) {
	p := newProvider(t)
	v := newVerifier(t, p)

	c := defaultClaims()
	c.Email = "operator@example.com"
	c.Name = "Real Human Name"

	got, err := v.Verify(context.Background(), p.mintRS(t, testKid, c))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	blob, _ := json.Marshal(got)
	for _, canary := range []string{"operator@example.com", "Real Human Name", "email", "name"} {
		if strings.Contains(strings.ToLower(string(blob)), strings.ToLower(canary)) {
			t.Fatalf("Claims leaked %q: %s", canary, blob)
		}
	}
	// Structural, not just value-level: Claims has exactly one field, so
	// there is nowhere for a second claim to be added without a review.
	if got != (Claims{Subject: "user-42"}) {
		t.Fatalf("Claims = %+v; want only Subject", got)
	}
}

// ---------------------------------------------------------------------
// JWKS cache behaviour (relay-api.md §2)
// ---------------------------------------------------------------------

func TestFailsClosedWhenJWKSUnavailable(t *testing.T) {
	p := newProvider(t)
	p.down.Store(true)
	v := newVerifier(t, p)

	_, err := v.Verify(context.Background(), p.mintRS(t, testKid, defaultClaims()))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v; want ErrUnavailable — the relay MUST fail closed, never accept unverified", err)
	}
	if errors.Is(err, ErrUnauthenticated) {
		t.Fatal("auth_unavailable must be distinguishable from unauthenticated (§7.2: 503/4503 vs 401/4401)")
	}
	if err := v.Ready(context.Background()); err == nil {
		t.Fatal("Ready must report not-ready while JWKS is unreachable")
	}
}

func TestStaleCacheIsNotAcceptedWhenProviderGoesDown(t *testing.T) {
	p := newProvider(t)
	now := time.Now()
	v := newVerifier(t, p, func(c *Config) {
		c.CacheTTL = MinCacheTTL
		c.Now = func() time.Time { return now }
	})
	tok := p.mintRS(t, testKid, defaultClaims())
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("warm-up Verify: %v", err)
	}

	// Provider goes away and the cache ages past its TTL. An EXPIRED cache
	// entry is exactly the "no unexpired cache entry" case, so the relay
	// must refuse rather than serve from stale keys.
	p.down.Store(true)
	now = now.Add(MinCacheTTL + time.Minute)
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v; want ErrUnavailable on a stale cache with a dead provider", err)
	}
}

func TestUnknownKidRefreshIsRateLimited(t *testing.T) {
	p := newProvider(t)
	now := time.Now()
	v := newVerifier(t, p, func(c *Config) { c.Now = func() time.Time { return now } })

	// Warm the cache.
	if _, err := v.Verify(context.Background(), p.mintRS(t, testKid, defaultClaims())); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	after := p.fetches.Load()

	// A flood of tokens bearing random kids must not become a fetch flood
	// against the identity provider: at most one refresh per 60 s.
	bogus := p.mintRS(t, "rotated-away", defaultClaims())
	for i := 0; i < 25; i++ {
		if _, err := v.Verify(context.Background(), bogus); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("unknown kid: got %v; want ErrUnauthenticated", err)
		}
	}
	if extra := p.fetches.Load() - after; extra > 1 {
		t.Fatalf("%d JWKS fetches for 25 unknown-kid tokens; the §2 rate limit allows at most 1 per 60s", extra)
	}

	// Past the interval, exactly one more refresh is allowed.
	now = now.Add(unknownKidRefreshInterval + time.Second)
	for i := 0; i < 10; i++ {
		_, _ = v.Verify(context.Background(), bogus)
	}
	if extra := p.fetches.Load() - after; extra > 2 {
		t.Fatalf("%d JWKS fetches across two 60s windows; want at most 2", extra)
	}
}

func TestRefreshPicksUpRotatedKey(t *testing.T) {
	p := newProvider(t)
	now := time.Now()
	v := newVerifier(t, p, func(c *Config) { c.Now = func() time.Time { return now } })
	ctx := context.Background()

	// Publish only the EC key at first, so the RSA kid is unknown.
	p.omitRSA.Store(true)
	tok := p.mintRS(t, testKid, defaultClaims())
	if _, err := v.Verify(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("got %v; want ErrUnauthenticated before the key is published", err)
	}

	// The provider rotates the key in. After the unknown-kid interval the
	// relay refreshes and the token verifies.
	p.omitRSA.Store(false)
	now = now.Add(unknownKidRefreshInterval + time.Second)
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
}

func TestConcurrentVerifyCollapsesFetches(t *testing.T) {
	p := newProvider(t)
	v := newVerifier(t, p)
	tok := p.mintRS(t, testKid, defaultClaims())

	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() {
			_, err := v.Verify(context.Background(), tok)
			done <- err
		}()
	}
	for i := 0; i < 16; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent Verify: %v", err)
		}
	}
	if n := p.fetches.Load(); n > 2 {
		t.Fatalf("%d JWKS fetches for a 16-way cold start; concurrent refreshes should collapse", n)
	}
}

func TestConfigValidation(t *testing.T) {
	base := Config{Issuer: testIssuer, Audience: testAud, JWKSURL: "https://example/keys"}
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"missing issuer", func(c *Config) { c.Issuer = "" }},
		{"missing audience", func(c *Config) { c.Audience = "" }},
		{"missing JWKS URL", func(c *Config) { c.JWKSURL = "" }},
		{"cache TTL below the contract floor", func(c *Config) { c.CacheTTL = time.Minute }},
		{"cache TTL above the contract ceiling", func(c *Config) { c.CacheTTL = 48 * time.Hour }},
		{"negative leeway", func(c *Config) { c.Leeway = -time.Second }},
		{"absurd leeway", func(c *Config) { c.Leeway = time.Hour }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mut(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("want a configuration error; got nil (config must fail fast at boot)")
			}
		})
	}
	if _, err := New(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestParseJWKRejectsWeakAndUnsupportedKeys(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cases := []struct {
		name string
		k    jwk
	}{
		{"symmetric key type", jwk{Kty: "oct", Kid: "k"}},
		{"unknown curve", jwk{Kty: "EC", Kid: "k", Crv: "P-192", X: b64([]byte{1}), Y: b64([]byte{2})}},
		{"off-curve point", jwk{Kty: "EC", Kid: "k", Crv: "P-256", X: b64([]byte{1}), Y: b64([]byte{2})}},
		{"undersized RSA modulus", jwk{Kty: "RSA", Kid: "k", N: b64(small.N.Bytes()), E: b64(big.NewInt(65537).Bytes())}},
		{"absent exponent", jwk{Kty: "RSA", Kid: "k", N: b64(make([]byte, 256))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseJWK(tc.k); err == nil {
				t.Fatal("want parseJWK to refuse this key")
			}
		})
	}
}
