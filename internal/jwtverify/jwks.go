package jwtverify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// maxJWKSBytes caps the JWKS response we will read. A public JWKS document
// is a few kilobytes; anything larger is a misconfiguration or an attempt to
// make the relay allocate.
const maxJWKSBytes = 1 << 20 // 1 MiB

// unknownKidRefreshInterval is relay-api.md §2's rate limit on refreshing
// because of an unrecognised `kid`: at most one refresh per 60 s, so an
// attacker minting tokens with random kids cannot turn the relay into a
// request amplifier against the identity provider.
const unknownKidRefreshInterval = 60 * time.Second

// jwk is the subset of RFC 7517 the relay understands: RSA and EC public
// keys. Anything else (oct/symmetric keys above all) is ignored rather than
// rejected, so a provider that publishes extra key types still works.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`

	// RSA
	N string `json:"n"`
	E string `json:"e"`

	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// keyCache holds the fetched JWKS. Public keys only — this cache can never
// hold a private or symmetric key, because parseJWK cannot construct one.
type keyCache struct {
	mu sync.Mutex

	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
	// lastAttempt records the last fetch ATTEMPT (successful or not) so the
	// unknown-kid refresh stays rate-limited even when the provider is down.
	lastAttempt time.Time
	// inflight serialises concurrent refreshes so a burst of attaches after
	// a key rotation produces one fetch, not one per connection.
	inflight bool
	waiters  []chan struct{}
}

// get returns the cached key for kid. fresh reports whether the cache is
// within its TTL; present reports whether the kid was found.
func (c *keyCache) get(kid string, ttl time.Duration, now time.Time) (key crypto.PublicKey, present, fresh bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fresh = !c.fetchedAt.IsZero() && now.Sub(c.fetchedAt) < ttl
	if c.keys == nil {
		return nil, false, fresh
	}
	k, ok := c.keys[kid]
	return k, ok, fresh
}

// mayRefresh reports whether an unknown-kid refresh is permitted now.
func (c *keyCache) mayRefresh(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastAttempt.IsZero() || now.Sub(c.lastAttempt) >= unknownKidRefreshInterval
}

// refresh fetches and installs the JWKS. It collapses concurrent callers
// onto a single HTTP request.
func (v *Verifier) refresh(ctx context.Context) error {
	c := &v.cache
	c.mu.Lock()
	if c.inflight {
		// Someone else is fetching; wait for their result rather than
		// piling more requests onto the provider.
		ch := make(chan struct{})
		c.waiters = append(c.waiters, ch)
		c.mu.Unlock()
		select {
		case <-ch:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.inflight = true
	c.lastAttempt = v.now()
	c.mu.Unlock()

	keys, err := v.fetchJWKS(ctx)

	c.mu.Lock()
	c.inflight = false
	if err == nil {
		c.keys = keys
		c.fetchedAt = v.now()
	}
	for _, ch := range c.waiters {
		close(ch)
	}
	c.waiters = nil
	c.mu.Unlock()
	return err
}

func (v *Verifier) fetchJWKS(ctx context.Context) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching JWKS: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return nil, fmt.Errorf("reading JWKS: %w", err)
	}
	var set jwkSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}
	keys := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue // encryption keys are not ours to hold
		}
		pub, err := parseJWK(k)
		if err != nil {
			continue // one unusable key must not poison the whole set
		}
		if k.Kid == "" {
			continue // unaddressable
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contained no usable signing keys")
	}
	return keys, nil
}

// parseJWK builds a PUBLIC key from a JWK. There is deliberately no branch
// that can produce a private or symmetric key: `oct` and any key carrying
// private parameters fall through to the error return.
func parseJWK(k jwk) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64uint(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64uint(k.E)
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return nil, errors.New("implausible RSA exponent")
		}
		if n.BitLen() < 2048 {
			return nil, errors.New("RSA modulus below 2048 bits")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil

	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		x, err := b64uint(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uint(k.Y)
		if err != nil {
			return nil, err
		}
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("EC point is not on the named curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil

	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}

func b64uint(s string) (*big.Int, error) {
	if s == "" {
		return nil, errors.New("empty base64url parameter")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("malformed base64url parameter: %w", err)
	}
	return new(big.Int).SetBytes(raw), nil
}
