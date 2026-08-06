package e2ekit

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// QR payload codec per ADR Decision 8 and its freeze-annotated encoding
// rules (pinned by vector V9):
//
//	kenaz://pair?v=1&r=<relay>&h=<host_id>&k=<host_pk>&t=<token>&a=<account_bind>&e=<exp>
//
//   - Parameter order is canonical exactly v, r, h, k, t, a, e; emitters
//     MUST use it.
//   - Binary fields are unpadded base64url at fixed widths; parsers
//     decode STRICTLY (no padding, no non-canonical trailing bits).
//   - In r, ':' and '/' are emitted unencoded (legal query characters);
//     '&', '=', '#', '%' are always percent-encoded, as is anything not
//     query-legal.
//   - Duplicate and unknown parameters are REJECTED, never resolved
//     first- or last-wins — the one place Go and Swift URL parsers
//     diverge by default, so neither parser is used here.

// QRPayload is a parsed pairing QR.
type QRPayload struct {
	Version     int
	RelayOrigin string
	HostID      [16]byte
	HostPK      [32]byte
	Token       [32]byte
	AccountBind [16]byte
	ExpiresUnix int64
}

// QR parse/validate errors (closed causes; all are hard rejections).
var (
	ErrQRScheme        = errors.New("e2ekit: QR does not start with kenaz://pair?")
	ErrQRVersion       = errors.New("e2ekit: unsupported QR protocol version")
	ErrQRDuplicate     = errors.New("e2ekit: duplicate QR parameter")
	ErrQRUnknownParam  = errors.New("e2ekit: unknown QR parameter (the set is closed: v,r,h,k,t,a,e)")
	ErrQRMalformed     = errors.New("e2ekit: malformed QR parameter")
	ErrQRMissingParam  = errors.New("e2ekit: missing QR parameter")
	ErrQRExpired       = errors.New("e2ekit: QR expired (device-clock pre-check; host TTL is authoritative)")
	ErrQRAccountBind   = errors.New("e2ekit: account_bind mismatch — QR was minted for a different account")
	ErrQRRelayEncoding = errors.New("e2ekit: relay origin carries a character that must be percent-encoded")
)

const qrPrefix = "kenaz://pair?"

// qrRelayAllowed reports whether byte c may appear UNENCODED in the r
// value: RFC 3986 query characters minus the unconditionally-encoded
// set {'&', '=', '#', '%'}.
func qrRelayAllowed(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '.', '_', '~', // unreserved
		'!', '$', '\'', '(', ')', '*', '+', ',', ';', // sub-delims minus & and =
		':', '@', '/', '?': // pchar extras + query extras
		return true
	}
	return false
}

func escapeRelay(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if qrRelayAllowed(c) {
			b.WriteByte(c)
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

func unescapeRelay(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%':
			if i+2 >= len(s) {
				return "", ErrQRRelayEncoding
			}
			hi, err1 := hexNibble(s[i+1])
			lo, err2 := hexNibble(s[i+2])
			if err1 != nil || err2 != nil {
				return "", ErrQRRelayEncoding
			}
			b.WriteByte(hi<<4 | lo)
			i += 2
		case qrRelayAllowed(c):
			b.WriteByte(c)
		default:
			return "", ErrQRRelayEncoding
		}
	}
	return b.String(), nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	}
	return 0, ErrQRMalformed
}

// Encode emits the canonical QR URI (parameter order v,r,h,k,t,a,e).
func (p *QRPayload) Encode() string {
	var b strings.Builder
	b.WriteString(qrPrefix)
	b.WriteString("v=")
	b.WriteString(strconv.Itoa(p.Version))
	b.WriteString("&r=")
	b.WriteString(escapeRelay(p.RelayOrigin))
	b.WriteString("&h=")
	b.WriteString(EncodeBin(p.HostID[:]))
	b.WriteString("&k=")
	b.WriteString(EncodeBin(p.HostPK[:]))
	b.WriteString("&t=")
	b.WriteString(EncodeBin(p.Token[:]))
	b.WriteString("&a=")
	b.WriteString(EncodeBin(p.AccountBind[:]))
	b.WriteString("&e=")
	b.WriteString(strconv.FormatInt(p.ExpiresUnix, 10))
	return b.String()
}

// ParseQR parses and structurally validates a pairing QR URI. It rejects
// unknown versions, duplicate parameters, unknown parameters, missing
// parameters, and every non-canonical encoding. Expiry and account
// binding are checked separately by Validate (they need a clock and the
// signed-in subject).
func ParseQR(uri string) (*QRPayload, error) {
	rest, ok := strings.CutPrefix(uri, qrPrefix)
	if !ok {
		return nil, ErrQRScheme
	}
	seen := make(map[string]bool, 7)
	vals := make(map[string]string, 7)
	for _, part := range strings.Split(rest, "&") {
		key, val, found := strings.Cut(part, "=")
		if !found || key == "" {
			return nil, ErrQRMalformed
		}
		switch key {
		case "v", "r", "h", "k", "t", "a", "e":
		default:
			return nil, fmt.Errorf("%w: %q", ErrQRUnknownParam, key)
		}
		if seen[key] {
			return nil, fmt.Errorf("%w: %q", ErrQRDuplicate, key)
		}
		seen[key] = true
		vals[key] = val
	}
	for _, key := range []string{"v", "r", "h", "k", "t", "a", "e"} {
		if !seen[key] {
			return nil, fmt.Errorf("%w: %q", ErrQRMissingParam, key)
		}
	}

	p := &QRPayload{}

	// v: strictly the literal "1" for this Suite version.
	if vals["v"] != "1" {
		return nil, fmt.Errorf("%w: v=%q", ErrQRVersion, vals["v"])
	}
	p.Version = 1

	relay, err := unescapeRelay(vals["r"])
	if err != nil {
		return nil, err
	}
	p.RelayOrigin = relay

	h, err := DecodeBin(vals["h"], 16)
	if err != nil {
		return nil, fmt.Errorf("%w: h: %w", ErrQRMalformed, err)
	}
	copy(p.HostID[:], h)
	k, err := DecodeBin(vals["k"], 32)
	if err != nil {
		return nil, fmt.Errorf("%w: k: %w", ErrQRMalformed, err)
	}
	copy(p.HostPK[:], k)
	t, err := DecodeBin(vals["t"], 32)
	if err != nil {
		return nil, fmt.Errorf("%w: t: %w", ErrQRMalformed, err)
	}
	copy(p.Token[:], t)
	a, err := DecodeBin(vals["a"], 16)
	if err != nil {
		return nil, fmt.Errorf("%w: a: %w", ErrQRMalformed, err)
	}
	copy(p.AccountBind[:], a)

	e := vals["e"]
	if e == "" {
		return nil, fmt.Errorf("%w: e", ErrQRMalformed)
	}
	for i := 0; i < len(e); i++ {
		if e[i] < '0' || e[i] > '9' {
			return nil, fmt.Errorf("%w: e", ErrQRMalformed)
		}
	}
	exp, err := strconv.ParseInt(e, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: e", ErrQRMalformed)
	}
	p.ExpiresUnix = exp
	return p, nil
}

// Validate runs the device-side pre-checks that need context: the expiry
// pre-check against the device clock (UX only — the host token TTL is
// authoritative, ADR Decision 8) and the account_bind recomputation
// against the device's signed-in subject (constant-time compare).
func (p *QRPayload) Validate(nowUnix int64, sub string) error {
	if nowUnix >= p.ExpiresUnix {
		return ErrQRExpired
	}
	want := V1.AccountBind(p.HostPK, sub)
	if !VerifyMAC(want[:], p.AccountBind[:]) {
		return ErrQRAccountBind
	}
	return nil
}
