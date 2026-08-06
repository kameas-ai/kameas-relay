package fakerelay

import (
	"errors"
	"net/http"
	"strings"
)

// TokenValidator is the pluggable authN seam. The real relay validates
// Zitadel JWTs (kameas-api audience) against JWKS; the fake never parses
// a real JWT — that would pull crypto dependencies the deny-list forbids,
// and relay authN is metadata-level defense in depth, never the security
// boundary (relay-api.md §2, §XII condition 6). Only the `sub` may be
// extracted; no other claim exists at this seam by construction.
type TokenValidator interface {
	// Validate returns the subject for a bearer token, or an error if the
	// token is invalid. Implementations MUST NOT log token bytes.
	Validate(token string) (sub string, err error)
}

// FakeValidator accepts tokens of the form "fake-<subject>" and returns
// the subject. Mirrors the contract's metadata-only posture.
type FakeValidator struct{}

func (FakeValidator) Validate(token string) (string, error) {
	sub, ok := strings.CutPrefix(token, "fake-")
	if !ok || sub == "" {
		return "", errors.New("token not accepted")
	}
	return sub, nil
}

// tokenQueryParams are query-parameter names that would carry a bearer
// token. §2.1: the JWT MUST be carried in the Authorization header ONLY
// — query strings are logged by load balancers and proxies outside our
// control, so a token in a query parameter is rejected even when a valid
// header is also present.
var tokenQueryParams = []string{"token", "access_token", "authorization", "bearer", "jwt", "id_token"}

// bearerSub extracts and validates the Authorization: Bearer token,
// refusing any request that smuggles a token through the query string.
func (r *Relay) bearerSub(req *http.Request) (string, errCode) {
	q := req.URL.Query()
	for _, p := range tokenQueryParams {
		if q.Has(p) {
			return "", codeUnauthenticated
		}
	}
	h := req.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" {
		return "", codeUnauthenticated
	}
	sub, err := r.cfg.Validator.Validate(tok)
	if err != nil {
		return "", codeUnauthenticated
	}
	return sub, ""
}
