package relay

// AuthN and AuthZ — relay-api.md §2, FR-4, tasks.md Task 2.A3.
//
// # This file is NOT the security boundary. Read this before changing it.
//
// ADR-remote-access-amendment §XII condition 6 and relay-api.md §2:
// "AuthZ here is metadata-level defense in depth and MUST NOT be relied on
// for confidentiality or integrity. Compromise of relay-side authorization
// MUST NOT yield content or command capability. No feature in any repo may
// be designed on the assumption that the relay enforces anything."
//
// Concretely: if every check below were bypassed, an attacker would gain
// the ability to route opaque ciphertext to endpoints that will refuse to
// authenticate it. Confidentiality is enforced by the AEAD; command
// authority is enforced by the host; revocation is enforced by the host
// deleting the device record, after which the pairing root is not
// computable and any mailboxed frames become permanently undecryptable.
// What this file buys is that an attacker must be authenticated to even
// waste those endpoints' time — worth having, never load-bearing.
//
// # The three rules
//
//  1. AuthN — a Zitadel JWT with the `kameas-api` audience on EVERY
//     connection and request, validated (signature, issuer, audience,
//     expiry) against JWKS before the WebSocket upgrade completes, failing
//     CLOSED when JWKS is unavailable. internal/jwtverify does this.
//  2. Channel authz — a device may attach only to channels named by a
//     pairing record whose account_sub equals the JWT `sub`; a host may
//     attach only to a host_id bound to its `sub` (§2.2).
//  3. Bearer placement — the JWT rides the `Authorization` header ONLY.
//     A token supplied as a query parameter is refused EVEN IF VALID and
//     even alongside a valid header, because query strings are logged by
//     load balancers and proxies outside our control. host_id and channel
//     are 128-bit routing identifiers already inside the enumerated
//     plaintext budget, so they are safe in a query string; a bearer token
//     is not.
//
// # One claim, and only one
//
// §2: "The JWT `sub` is in the enumerated plaintext budget. Nothing else
// from the token — email, name, or any other claim — may be read, stored,
// or logged." TokenValidator therefore returns a bare subject string. There
// is no Claims struct at this seam and no way to widen one without changing
// this interface, which is the point.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/kameas-ai/kameas-relay/internal/jwtverify"
)

// TokenValidator is the authN seam.
//
// Implementations MUST NOT log token bytes and MUST NOT return any claim
// other than the subject.
type TokenValidator interface {
	// Validate returns the subject for a bearer token.
	//
	// It returns ErrTokenUnavailable when the identity provider cannot be
	// reached and no fresh key cache exists — the relay maps that to
	// `auth_unavailable` (503 / 4503) and MUST NOT fall back to accepting
	// unverified tokens. Every other failure returns any other error and
	// maps to `unauthenticated` (401 / 4401).
	Validate(ctx context.Context, token string) (sub string, err error)
}

// ErrTokenUnavailable signals the fail-closed JWKS path of §2.
var ErrTokenUnavailable = errors.New("auth_unavailable")

// ---------------------------------------------------------------------
// Production validator — Zitadel JWT over JWKS
// ---------------------------------------------------------------------

// JWTValidator adapts internal/jwtverify to TokenValidator. It is the only
// validator cmd/relayd will construct.
type JWTValidator struct{ V *jwtverify.Verifier }

// NewJWTValidator builds the production validator.
func NewJWTValidator(cfg jwtverify.Config) (*JWTValidator, error) {
	v, err := jwtverify.New(cfg)
	if err != nil {
		return nil, err
	}
	return &JWTValidator{V: v}, nil
}

func (j *JWTValidator) Validate(ctx context.Context, token string) (string, error) {
	claims, err := j.V.Verify(ctx, token)
	switch {
	case err == nil:
		return claims.Subject, nil
	case errors.Is(err, jwtverify.ErrUnavailable):
		return "", ErrTokenUnavailable
	default:
		// Deliberately collapsed: the caller learns "no", not which of
		// signature / audience / issuer / expiry said so.
		return "", errors.New("token not accepted")
	}
}

// Ready backs the JWKS half of GET /readyz (§7.3).
func (j *JWTValidator) Ready(ctx context.Context) error { return j.V.Ready(ctx) }

// ---------------------------------------------------------------------
// Test-only validator
// ---------------------------------------------------------------------

// TestOnlySubjectValidator accepts tokens of the form "<Prefix><subject>"
// and returns the subject.
//
// It exists so the parity harness (internal/relayparity) and the SC-2
// property test (sc2/) can drive the REAL relay with the same
// `Bearer fake-<sub>` credentials the Phase-1 endpoint instruments already
// emit, without standing up an identity provider. cmd/relayd never
// references this type: relayd's configuration has no mode that selects it
// and no env var that reaches it, so there is no deployment in which it can
// be switched on by accident.
type TestOnlySubjectValidator struct{ Prefix string }

func (v TestOnlySubjectValidator) Validate(_ context.Context, token string) (string, error) {
	prefix := v.Prefix
	if prefix == "" {
		prefix = "fake-"
	}
	sub, ok := strings.CutPrefix(token, prefix)
	if !ok || sub == "" {
		return "", errors.New("token not accepted")
	}
	return sub, nil
}

// ---------------------------------------------------------------------
// Bearer extraction (§2.1 rule 3)
// ---------------------------------------------------------------------

// tokenQueryParams are query-parameter names that would carry a bearer
// token. Presence of ANY of them fails the request outright.
var tokenQueryParams = []string{
	"token", "access_token", "authorization", "bearer", "jwt", "id_token",
}

// bearerSub extracts and validates the Authorization: Bearer token,
// refusing any request that smuggles a token through the query string.
//
// It returns the subject, or the §7.2 code to answer with.
func (r *Relay) bearerSub(req *http.Request) (string, ErrCode) {
	q := req.URL.Query()
	for _, p := range tokenQueryParams {
		if q.Has(p) {
			return "", CodeUnauthenticated
		}
	}
	tok, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return "", CodeUnauthenticated
	}
	sub, err := r.cfg.Validator.Validate(req.Context(), tok)
	if err != nil {
		if errors.Is(err, ErrTokenUnavailable) {
			// Fail closed and say so distinctly: an operator debugging a
			// JWKS outage needs 503, and an endpoint needs to know to
			// retry rather than to re-authenticate.
			return "", CodeAuthUnavailable
		}
		return "", CodeUnauthenticated
	}
	return sub, ""
}

// ---------------------------------------------------------------------
// Channel-level authorization
// ---------------------------------------------------------------------

// authorizeChannel resolves a channel to its pairing and applies the §2
// channel rule: a device may attach only to channels a pairing registration
// names, and only when that registration's account_sub matches the caller.
//
// The unknown/wrong-account split is deliberate and is the ambiguity this
// repo has flagged rather than silently resolved: §7.2's table lists
// `not_found` for "unknown channel", while §2.1's bullet folds "not
// registered" into the account rule, which would argue for `forbidden`
// everywhere. Both this package and internal/fakerelay keep the split —
// 404 unknown, 403 wrong account — matching the §7.2 table, and the parity
// suite pins the two implementations together so a future ruling changes
// them as one.
//
// Note that the pairing-attach path (§3.2) is NOT this function: there,
// every refusal collapses into a single `window_closed` to close the
// window-existence oracle. See devicePairingAttach.
func (r *Relay) authorizeChannel(ctx context.Context, channelID, sub string) (Pairing, ErrCode) {
	pr, ok, err := r.cfg.Store.PairingByChannel(ctx, channelID)
	switch {
	case err != nil:
		return Pairing{}, CodeInternal
	case !ok:
		return Pairing{}, CodeNotFound
	case pr.AccountSub != sub:
		return Pairing{}, CodeForbidden
	}
	return pr, ""
}

// authorizeHostID applies §2.2 to a REST caller: the host_id must already be
// bound, and bound to this account. Note the asymmetry with a /v1/host
// attach — only an attach may CREATE a binding (§3.2), so a REST endpoint
// that finds no binding refuses rather than creating one.
func (r *Relay) authorizeHostID(ctx context.Context, hostID, sub string) ErrCode {
	b, ok, err := r.cfg.Store.LookupBinding(ctx, hostID, r.cfg.Clock.Now())
	switch {
	case err != nil:
		return CodeInternal
	case !ok, b.AccountSub != sub:
		return CodeForbidden
	}
	return ""
}
