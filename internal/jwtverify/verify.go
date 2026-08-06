package jwtverify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Sentinel errors. The relay maps ErrUnauthenticated to the contract's
// `unauthenticated` (401 / WSS 4401) and ErrUnavailable to `auth_unavailable`
// (503 / WSS 4503) — relay-api.md §7.2.
//
// Every rejection reason collapses into ErrUnauthenticated on purpose:
// telling a caller WHY its token failed (wrong audience vs bad signature vs
// expired) is an oracle for someone probing the relay's configuration, and
// the caller can learn nothing useful from the distinction.
var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrUnavailable     = errors.New("auth_unavailable: JWKS unreachable and no fresh cache")
	ErrNotConfigured   = errors.New("jwtverify: incomplete configuration")
)

// maxTokenBytes caps the token we will even look at. Real Zitadel access
// tokens are well under this; the cap bounds the work an unauthenticated
// caller can make the relay do.
const maxTokenBytes = 16 << 10

// Claims is everything the relay learns from a token. ONE field, and that
// is normative: relay-api.md §2 puts `sub` inside the §XII condition-3
// plaintext budget and puts every other claim outside it. There is
// deliberately nowhere here to put an email, a name, or a role.
type Claims struct {
	Subject string
}

// Config configures a Verifier.
type Config struct {
	// Issuer is the exact expected `iss`. Required.
	Issuer string
	// Audience is the required audience — `kameas-api` (relay-api.md §2).
	// Required.
	Audience string
	// JWKSURL is the provider's JWKS document. Required.
	JWKSURL string
	// CacheTTL must be within [5m, 24h] (relay-api.md §2). Default 15m.
	CacheTTL time.Duration
	// Leeway absorbs clock skew on exp/nbf. Default 60s, capped at 5m.
	Leeway time.Duration

	HTTPClient *http.Client
	// Now is injectable for tests. Default time.Now.
	Now func() time.Time
}

// Bounds on CacheTTL, from relay-api.md §2.
const (
	MinCacheTTL     = 5 * time.Minute
	MaxCacheTTL     = 24 * time.Hour
	DefaultCacheTTL = 15 * time.Minute
	DefaultLeeway   = 60 * time.Second
	MaxLeeway       = 5 * time.Minute
)

// Verifier validates Zitadel access tokens against a cached JWKS.
//
// It is safe for concurrent use. It holds public keys only.
type Verifier struct {
	cfg   Config
	cache keyCache
}

// New validates cfg and returns a Verifier. It performs no network I/O:
// the first Verify (or Ready) populates the cache, and until it does the
// verifier fails CLOSED rather than accepting anything.
func New(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.JWKSURL == "" {
		return nil, fmt.Errorf("%w: issuer, audience, and JWKS URL are all required", ErrNotConfigured)
	}
	switch {
	case cfg.CacheTTL == 0:
		cfg.CacheTTL = DefaultCacheTTL
	case cfg.CacheTTL < MinCacheTTL, cfg.CacheTTL > MaxCacheTTL:
		return nil, fmt.Errorf("%w: JWKS cache TTL %s is outside the contract bound [%s, %s]",
			ErrNotConfigured, cfg.CacheTTL, MinCacheTTL, MaxCacheTTL)
	}
	switch {
	case cfg.Leeway == 0:
		cfg.Leeway = DefaultLeeway
	case cfg.Leeway < 0, cfg.Leeway > MaxLeeway:
		return nil, fmt.Errorf("%w: clock leeway %s is outside [0, %s]", ErrNotConfigured, cfg.Leeway, MaxLeeway)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg}, nil
}

func (v *Verifier) now() time.Time { return v.cfg.Now() }

// Ready reports whether the verifier can currently authenticate anyone: it
// backs the JWKS half of `GET /readyz` (relay-api.md §7.3). It never
// enumerates channels, devices, or hosts — it answers one boolean about the
// relay's own dependency.
func (v *Verifier) Ready(ctx context.Context) error {
	if _, _, fresh := v.cache.get("", v.cfg.CacheTTL, v.now()); fresh {
		return nil
	}
	if err := v.refresh(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

// Verify checks a bearer token and returns its subject.
//
// The order is deliberate: cheap structural checks, then signature, then
// claims. Signature is verified BEFORE any claim is trusted, so no claim
// value from an unsigned token ever reaches a decision.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	if token == "" || len(token) > maxTokenBytes {
		return Claims{}, ErrUnauthenticated
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrUnauthenticated
	}

	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrUnauthenticated
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return Claims{}, ErrUnauthenticated
	}
	// `none` and every other unsupported alg are refused before a key is
	// even looked up, so an alg-confusion token cannot reach the key cache.
	if !supportedAlg(hdr.Alg) {
		return Claims{}, ErrUnauthenticated
	}
	if hdr.Typ != "" && !strings.EqualFold(hdr.Typ, "JWT") && !strings.EqualFold(hdr.Typ, "at+jwt") {
		return Claims{}, ErrUnauthenticated
	}
	if hdr.Kid == "" {
		return Claims{}, ErrUnauthenticated
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrUnauthenticated
	}
	signed := []byte(parts[0] + "." + parts[1])

	key, err := v.keyFor(ctx, hdr.Kid)
	if err != nil {
		return Claims{}, err
	}
	if err := verifySignature(hdr.Alg, key, signed, sig); err != nil {
		return Claims{}, ErrUnauthenticated
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrUnauthenticated
	}
	return v.checkClaims(payload)
}

// keyFor resolves a signing key, refreshing the JWKS on an unknown kid
// (rate-limited per relay-api.md §2) and failing CLOSED when the provider is
// unreachable and no fresh cache exists. It NEVER falls back to accepting an
// unverified token.
func (v *Verifier) keyFor(ctx context.Context, kid string) (crypto.PublicKey, error) {
	now := v.now()
	key, present, fresh := v.cache.get(kid, v.cfg.CacheTTL, now)
	if present && fresh {
		return key, nil
	}
	// Refresh when the cache is stale, or when the kid is unknown and the
	// unknown-kid rate limit allows another attempt.
	if !fresh || v.cache.mayRefresh(now) {
		if err := v.refresh(ctx); err != nil {
			// Fail closed. A stale cache entry is NOT good enough: the
			// contract's escape hatch is "no unexpired cache entry exists",
			// and an expired entry is exactly that.
			if key, present, fresh = v.cache.get(kid, v.cfg.CacheTTL, v.now()); present && fresh {
				return key, nil
			}
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		if key, present, _ = v.cache.get(kid, v.cfg.CacheTTL, v.now()); present {
			return key, nil
		}
		// Refresh succeeded and the kid still is not there: the token was
		// signed by a key this issuer does not publish.
		return nil, ErrUnauthenticated
	}
	if present {
		return key, nil
	}
	// Unknown kid, and we may not refresh yet. Refusing is correct: the
	// alternative is letting a stream of random kids drive the fetch rate.
	return nil, ErrUnauthenticated
}

// checkClaims validates iss / aud / exp / nbf and extracts `sub`.
//
// Only `sub` is decoded into a named field. The rest of the payload is
// parsed into locals that go out of scope here — there is no path by which
// an email or a name reaches a caller, a log, or the store.
func (v *Verifier) checkClaims(payload []byte) (Claims, error) {
	var c struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
		Exp *float64        `json:"exp"`
		Nbf *float64        `json:"nbf"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, ErrUnauthenticated
	}
	if c.Iss != v.cfg.Issuer {
		return Claims{}, ErrUnauthenticated
	}
	if c.Sub == "" {
		return Claims{}, ErrUnauthenticated
	}
	if !audienceContains(c.Aud, v.cfg.Audience) {
		return Claims{}, ErrUnauthenticated
	}
	// `exp` is REQUIRED. A token that never expires is not a token this
	// relay accepts, whatever the provider thinks.
	if c.Exp == nil {
		return Claims{}, ErrUnauthenticated
	}
	now := v.now()
	if !now.Add(-v.cfg.Leeway).Before(unixFloat(*c.Exp)) {
		return Claims{}, ErrUnauthenticated
	}
	if c.Nbf != nil && now.Add(v.cfg.Leeway).Before(unixFloat(*c.Nbf)) {
		return Claims{}, ErrUnauthenticated
	}
	return Claims{Subject: c.Sub}, nil
}

// audienceContains implements RFC 7519's aud, which is either a string or an
// array of strings. Anything else fails closed.
func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one == want
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return false
	}
	for _, a := range many {
		if a == want {
			return true
		}
	}
	return false
}

func unixFloat(f float64) time.Time {
	sec, frac := int64(f), f-float64(int64(f))
	return time.Unix(sec, int64(frac*1e9))
}

// supportedAlg is the closed set of signature algorithms. `none` is absent,
// as are all MAC algorithms (HS*): an HMAC alg would make the verifier take
// a SYMMETRIC key, which is exactly the shape §XII condition 2 forbids
// anywhere in relay scope.
func supportedAlg(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
		"ES256", "ES384", "ES512":
		return true
	}
	return false
}

func hashFor(alg string) (crypto.Hash, hash.Hash) {
	switch alg[2:] {
	case "384":
		return crypto.SHA384, sha512.New384()
	case "512":
		return crypto.SHA512, sha512.New()
	default:
		return crypto.SHA256, sha256.New()
	}
}

func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	cryptoHash, h := hashFor(alg)
	h.Write(signed)
	digest := h.Sum(nil)

	switch alg[:2] {
	case "RS":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrUnauthenticated // alg/key-type confusion
		}
		return rsa.VerifyPKCS1v15(pub, cryptoHash, digest, sig)

	case "PS":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrUnauthenticated
		}
		return rsa.VerifyPSS(pub, cryptoHash, digest, sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       cryptoHash,
		})

	case "ES":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return ErrUnauthenticated
		}
		// JWS ECDSA signatures are the fixed-width R‖S form, not ASN.1.
		n := (pub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return ErrUnauthenticated
		}
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return ErrUnauthenticated
		}
		return nil
	}
	return ErrUnauthenticated
}
