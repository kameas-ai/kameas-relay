package e2ekit

import (
	"errors"
	"strings"
	"testing"
)

func testPayload() *QRPayload {
	p := &QRPayload{
		Version:     1,
		RelayOrigin: "https://relay.lle.kameas.ai",
		ExpiresUnix: 1754400300,
	}
	for i := range p.HostID {
		p.HostID[i] = byte(i + 1)
	}
	for i := range p.HostPK {
		p.HostPK[i] = byte(i + 0x40)
	}
	for i := range p.Token {
		p.Token[i] = byte(i + 0x80)
	}
	p.AccountBind = V1.AccountBind(p.HostPK, "sub-123")
	return p
}

func TestQRRoundTrip(t *testing.T) {
	p := testPayload()
	uri := p.Encode()
	got, err := ParseQR(uri)
	if err != nil {
		t.Fatalf("ParseQR: %v", err)
	}
	if *got != *p {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, p)
	}
	if err := got.Validate(1754400000, "sub-123"); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := got.Validate(1754400300, "sub-123"); !errors.Is(err, ErrQRExpired) {
		t.Errorf("Validate at exact expiry: want ErrQRExpired, got %v", err)
	}
	if err := got.Validate(1754400000, "other-sub"); !errors.Is(err, ErrQRAccountBind) {
		t.Errorf("Validate wrong sub: want ErrQRAccountBind, got %v", err)
	}
}

func TestQRRelayPercentEncoding(t *testing.T) {
	p := testPayload()
	p.RelayOrigin = "https://relay.example.com:8443/path?x" // ':' '/' '?' stay raw
	uri := p.Encode()
	if !strings.Contains(uri, "r=https://relay.example.com:8443/path?x&") {
		t.Errorf(": and / must be emitted unencoded, got %s", uri)
	}
	got, err := ParseQR(uri)
	if err != nil || got.RelayOrigin != p.RelayOrigin {
		t.Fatalf("round-trip: %v %q", err, got.RelayOrigin)
	}

	// '&', '=', '#', '%' and non-query-legal bytes are always encoded.
	p.RelayOrigin = "https://x/a&b=c#d%e f"
	uri = p.Encode()
	if !strings.Contains(uri, "r=https://x/a%26b%3Dc%23d%25e%20f&") {
		t.Errorf("unconditional set not percent-encoded: %s", uri)
	}
	got, err = ParseQR(uri)
	if err != nil || got.RelayOrigin != p.RelayOrigin {
		t.Fatalf("encoded round-trip: %v %q", err, got.RelayOrigin)
	}
}

func TestQRParseRejections(t *testing.T) {
	canonical := testPayload().Encode()
	swap := func(old, new string) string { return strings.Replace(canonical, old, new, 1) }
	cases := []struct {
		name    string
		uri     string
		wantErr error
	}{
		{"wrong scheme", "https://pair?" + canonical[len(qrPrefix):], ErrQRScheme},
		{"duplicate parameter", canonical + "&e=1754400300", ErrQRDuplicate},
		{"duplicate token", swap("&a=", "&t=AAAA&a="), ErrQRDuplicate},
		{"unknown parameter", canonical + "&x=1", ErrQRUnknownParam},
		{"missing parameter", swap("&e=1754400300", ""), ErrQRMissingParam},
		{"bare parameter without =", canonical + "&z", ErrQRMalformed},
		{"unsupported version", swap("v=1", "v=2"), ErrQRVersion},
		{"non-canonical version 01", swap("v=1", "v=01"), ErrQRVersion},
		{"padded base64url", swap("&k=", "&k=A="), ErrQRMalformed},
		{"raw percent garbage in r", swap("r=https", "r=%zzhttps"), ErrQRRelayEncoding},
		{"raw = in r", swap("r=https://relay", "r=ht=ps://relay"), ErrQRRelayEncoding},
		{"non-digit expiry", swap("&e=1754400300", "&e=17x5"), ErrQRMalformed},
		{"signed expiry", swap("&e=1754400300", "&e=+1754400300"), ErrQRMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseQR(c.uri); !errors.Is(err, c.wantErr) {
				t.Errorf("ParseQR(%q): got %v, want %v", c.uri, err, c.wantErr)
			}
		})
	}
}

func TestQRWrongFieldWidthRejected(t *testing.T) {
	p := testPayload()
	uri := p.Encode()
	// Swap h (22 chars) for a canonical-but-32-byte value (43 chars).
	long := EncodeBin(make([]byte, 32))
	bad := strings.Replace(uri, "h="+EncodeChannelID(p.HostID), "h="+long, 1)
	if _, err := ParseQR(bad); !errors.Is(err, ErrQRMalformed) {
		t.Errorf("oversized h accepted: %v", err)
	}
}
