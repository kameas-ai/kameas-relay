package e2ekit

// Golden-vector conformance: every positive chain in the 17 frozen
// vector files must reproduce byte-exactly, and every negative case
// (`expect` marker) must fail the asserted way. The vectors were
// generated against real libsodium 1.0.22 and are IMMUTABLE — a mismatch
// here means THIS package is wrong, never the vectors
// (specs/074-kenaz-ios-remote/contracts/vectors/README.md).
//
// The suite hard-counts files and cases so a silently-skipped vector
// fails the test.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// vectorsDir resolves the frozen vector directory: KENAZ_VECTORS_DIR
// overrides; the default is ../specs/074-kenaz-ios-remote/contracts/
// vectors relative to the repo root (the workspace checkout layout).
func vectorsDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("KENAZ_VECTORS_DIR"); d != "" {
		return d
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	repoRoot := filepath.Dir(filepath.Dir(file)) // e2ekit/ -> repo root
	return filepath.Join(repoRoot, "..", "specs", "074-kenaz-ios-remote", "contracts", "vectors")
}

var vectorFiles = []string{
	"v01-kx-keypair.json",
	"v02-kx-session-keys.json",
	"v03-session-key-schedule.json",
	"v04-mailbox-key.json",
	"v05-secretstream-frames.json",
	"v06-mailbox-frame.json",
	"v07-pairing-mac.json",
	"v08-account-bind.json",
	"v09-qr-payload.json",
	"v10-live-frame-negatives.json",
	"v11-cross-direction-negative.json",
	"v12-cross-construction-negatives.json",
	"v13-mailbox-negatives.json",
	"v14-version-separation.json",
	"v15-confirm-negatives.json",
	"v16-pairing-mac-negatives.json",
	"v17-handshake-frames.json",
}

// fixture recomputes the generator's seed scheme:
// fixture(label, n) = crypto_generichash(n, "KENAZ-074-VECTORS:"+label, key=NULL).
func fixture(t *testing.T, label string, n int) []byte {
	t.Helper()
	h, err := blake2b.New(n, nil)
	if err != nil {
		t.Fatalf("fixture blake2b: %v", err)
	}
	h.Write([]byte("KENAZ-074-VECTORS:" + label))
	return h.Sum(nil)
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture %q: %v", s, err)
	}
	return b
}

func as16(t *testing.T, s string) (out [16]byte) { copy(out[:], unhex(t, s)); return }
func as24(t *testing.T, s string) (out [24]byte) { copy(out[:], unhex(t, s)); return }
func as32(t *testing.T, s string) (out [32]byte) { copy(out[:], unhex(t, s)); return }

func eqHex(t *testing.T, what string, got []byte, wantHex string) bool {
	t.Helper()
	if hex.EncodeToString(got) != wantHex {
		t.Errorf("%s mismatch:\n  got  %x\n  want %s", what, got, wantHex)
		return false
	}
	return true
}

func tagByte(t *testing.T, name string) byte {
	t.Helper()
	switch name {
	case "TAG_MESSAGE":
		return TagMessage
	case "TAG_PUSH":
		return TagPush
	case "TAG_REKEY":
		return TagRekey
	case "TAG_FINAL":
		return TagFinal
	}
	t.Fatalf("unknown tag %q", name)
	return 0
}

func loadJSON(t *testing.T, dir, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("reading vector %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parsing vector %s: %v", name, err)
	}
}

// vFrame is the shared secretstream-frame shape used by v05/v10/v11/v12.
type vFrame struct {
	ADHex         string `json:"ad_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	PlaintextUTF8 string `json:"plaintext_utf8"`
	Tag           string `json:"tag"`
	Seq           uint64 `json:"seq"`
	PushClass     string `json:"push_class"`
	Header        struct {
		Channel   string `json:"channel"`
		PushClass string `json:"push_class"`
		Seq       uint64 `json:"seq"`
	} `json:"header"`
}

// counters tallied across the whole suite; asserted at the end so
// nothing can be skipped silently.
type tally struct {
	files     int
	positives int
	negatives int
}

func TestGoldenVectors(t *testing.T) {
	dir := vectorsDir(t)
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("GOLDEN VECTORS NOT FOUND at %s (set KENAZ_VECTORS_DIR) — the e2ekit conformance gate DID NOT RUN: %v", dir, err)
	}
	var tl tally

	// ---- v01 ------------------------------------------------------------
	var v01 struct {
		Cases []struct {
			PublicKeyHex string `json:"public_key_hex"`
			SecretKeyHex string `json:"secret_key_hex"`
			SeedHex      string `json:"seed_hex"`
			SeedLabel    string `json:"seed_label"`
			Role         string `json:"role"`
		} `json:"cases"`
	}
	loadJSON(t, dir, vectorFiles[0], &v01)
	tl.files++
	if len(v01.Cases) != 2 {
		t.Fatalf("v01: want 2 cases, got %d", len(v01.Cases))
	}
	type kp struct{ pk, sk [32]byte }
	keypairs := map[string]kp{} // seed_label -> keypair
	for _, c := range v01.Cases {
		pk, sk, err := KXSeedKeypair(unhex(t, c.SeedHex))
		if err != nil {
			t.Fatalf("v01 %s: %v", c.SeedLabel, err)
		}
		eqHex(t, "v01 "+c.SeedLabel+" pk", pk[:], c.PublicKeyHex)
		eqHex(t, "v01 "+c.SeedLabel+" sk", sk[:], c.SecretKeyHex)
		keypairs[c.SeedLabel] = kp{pk, sk}
		tl.positives++
	}
	host, dev := keypairs["host-kx-seed"], keypairs["device-kx-seed"]

	// ---- v02 ------------------------------------------------------------
	var v02 struct {
		Inputs struct {
			ClientPK string `json:"client_public_key_hex"`
			ServerPK string `json:"server_public_key_hex"`
		} `json:"inputs"`
		Outputs struct {
			RD2H     string `json:"R_d2h_hex"`
			RH2D     string `json:"R_h2d_hex"`
			ClientRX string `json:"client_rx_hex"`
			ClientTX string `json:"client_tx_hex"`
			ServerRX string `json:"server_rx_hex"`
			ServerTX string `json:"server_tx_hex"`
		} `json:"outputs"`
	}
	loadJSON(t, dir, vectorFiles[1], &v02)
	tl.files++
	if v02.Inputs.ClientPK != hex.EncodeToString(dev.pk[:]) || v02.Inputs.ServerPK != hex.EncodeToString(host.pk[:]) {
		t.Fatalf("v02 inputs do not match the v01 keypairs")
	}
	cRX, cTX, err := KXClientSessionKeys(dev.pk, dev.sk, host.pk)
	if err != nil {
		t.Fatalf("v02 client: %v", err)
	}
	sRX, sTX, err := KXServerSessionKeys(host.pk, host.sk, dev.pk)
	if err != nil {
		t.Fatalf("v02 server: %v", err)
	}
	eqHex(t, "v02 client.rx", cRX[:], v02.Outputs.ClientRX)
	eqHex(t, "v02 client.tx", cTX[:], v02.Outputs.ClientTX)
	eqHex(t, "v02 server.rx", sRX[:], v02.Outputs.ServerRX)
	eqHex(t, "v02 server.tx", sTX[:], v02.Outputs.ServerTX)
	if cRX != sTX || cTX != sRX {
		t.Errorf("v02 cross-role identity violated")
	}
	devRoots, err := DeviceRoots(dev.pk, dev.sk, host.pk)
	if err != nil {
		t.Fatalf("v02 DeviceRoots: %v", err)
	}
	hostRoots, err := HostRoots(host.pk, host.sk, dev.pk)
	if err != nil {
		t.Fatalf("v02 HostRoots: %v", err)
	}
	if devRoots != hostRoots {
		t.Errorf("v02 DeviceRoots != HostRoots")
	}
	eqHex(t, "v02 R_h2d", devRoots.H2D[:], v02.Outputs.RH2D)
	eqHex(t, "v02 R_d2h", devRoots.D2H[:], v02.Outputs.RD2H)
	if devRoots.H2D == devRoots.D2H {
		t.Errorf("v02 R_h2d == R_d2h")
	}
	roots := devRoots
	tl.positives++

	// ---- v03 ------------------------------------------------------------
	var v03 struct {
		Inputs struct {
			RD2H       string `json:"R_d2h_hex"`
			RH2D       string `json:"R_h2d_hex"`
			DeviceID   string `json:"device_id_hex"`
			HostID     string `json:"host_id_hex"`
			ND         string `json:"n_d_hex"`
			NH         string `json:"n_h_hex"`
			Proto      int    `json:"proto"`
			Transcript string `json:"transcript_T_hex"`
			DSStrings  map[string]string
		} `json:"inputs"`
		Outputs struct {
			KsessD2H string `json:"Ksess_d2h_hex"`
			KsessH2D string `json:"Ksess_h2d_hex"`
			ConfD    string `json:"conf_d_hex"`
			ConfH    string `json:"conf_h_hex"`
		} `json:"outputs"`
	}
	loadJSON(t, dir, vectorFiles[2], &v03)
	tl.files++
	if v03.Inputs.RH2D != hex.EncodeToString(roots.H2D[:]) || v03.Inputs.RD2H != hex.EncodeToString(roots.D2H[:]) {
		t.Fatalf("v03 roots do not match v02 outputs")
	}
	hostID, deviceID := as16(t, v03.Inputs.HostID), as16(t, v03.Inputs.DeviceID)
	nD, nH := as32(t, v03.Inputs.ND), as32(t, v03.Inputs.NH)
	tr := V1.Transcript(hostID, deviceID, nD, nH)
	eqHex(t, "v03 transcript T", tr[:], v03.Inputs.Transcript)
	sk1 := V1.SessionKeys(roots, tr)
	eqHex(t, "v03 Ksess_h2d", sk1.H2D[:], v03.Outputs.KsessH2D)
	eqHex(t, "v03 Ksess_d2h", sk1.D2H[:], v03.Outputs.KsessD2H)
	eqHex(t, "v03 conf_h", sk1.ConfH[:], v03.Outputs.ConfH)
	eqHex(t, "v03 conf_d", sk1.ConfD[:], v03.Outputs.ConfD)
	tl.positives++

	// ---- v04 ------------------------------------------------------------
	var v04 struct {
		Outputs struct {
			KMbx string `json:"K_mbx_hex"`
		} `json:"outputs"`
	}
	loadJSON(t, dir, vectorFiles[3], &v04)
	tl.files++
	kMbx := V1.MailboxKey(roots, hostID, deviceID)
	eqHex(t, "v04 K_mbx", kMbx[:], v04.Outputs.KMbx)
	tl.positives++

	// ---- v05 ------------------------------------------------------------
	var v05 struct {
		Frames []vFrame `json:"frames"`
		Inputs struct {
			ChannelIDHex string `json:"channel_id_hex"`
			ChannelWire  string `json:"channel_wire"`
			HeaderHex    string `json:"header_hex"`
			KeyHex       string `json:"key_hex"`
		} `json:"inputs"`
	}
	loadJSON(t, dir, vectorFiles[4], &v05)
	tl.files++
	if len(v05.Frames) != 4 {
		t.Fatalf("v05: want 4 frames, got %d", len(v05.Frames))
	}
	v05Key, v05Hdr := as32(t, v05.Inputs.KeyHex), as24(t, v05.Inputs.HeaderHex)
	v05Chan := as16(t, v05.Inputs.ChannelIDHex)
	if EncodeChannelID(v05Chan) != v05.Inputs.ChannelWire {
		t.Errorf("v05 channel wire encoding mismatch")
	}
	// Push side: headers are INPUTS — the push state is seeded via the
	// pull initializer, state-identical per libsodium (production draws
	// headers from the CSPRNG via NewPushStream).
	push := NewPullStream(v05Key, v05Hdr)
	for i, f := range v05.Frames {
		ad := BuildAD(v05Chan, f.Seq, mustPushClass(t, f.PushClass))
		eqHex(t, fmt.Sprintf("v05 frame %d AD", i), ad[:], f.ADHex)
		ct, err := push.Push(unhex(t, f.PlaintextHex), ad[:], tagByte(t, f.Tag))
		if err != nil {
			t.Fatalf("v05 push %d: %v", i, err)
		}
		eqHex(t, fmt.Sprintf("v05 frame %d ciphertext", i), ct, f.CiphertextHex)
		tl.positives++
	}
	// Pull round-trip on a fresh state.
	pull := NewPullStream(v05Key, v05Hdr)
	for i, f := range v05.Frames {
		pt, tag, err := pull.Pull(unhex(t, f.CiphertextHex), unhex(t, f.ADHex))
		if err != nil {
			t.Fatalf("v05 pull %d: %v", i, err)
		}
		eqHex(t, fmt.Sprintf("v05 pull %d plaintext", i), pt, f.PlaintextHex)
		if tag != tagByte(t, f.Tag) {
			t.Errorf("v05 pull %d tag: got %d want %s", i, tag, f.Tag)
		}
		tl.positives++
	}
	if !pull.Finished() {
		t.Errorf("v05: pull stream not finished after TAG_FINAL")
	}

	// ---- v06 ------------------------------------------------------------
	var v06 struct {
		Inputs struct {
			KMbxHex      string `json:"K_mbx_hex"`
			ADHex        string `json:"ad_hex"`
			NonceHex     string `json:"nonce_hex"`
			PlaintextHex string `json:"plaintext_hex"`
		} `json:"inputs"`
		Outputs struct {
			CiphertextHex string `json:"ciphertext_hex"`
		} `json:"outputs"`
	}
	loadJSON(t, dir, vectorFiles[5], &v06)
	tl.files++
	if v06.Inputs.KMbxHex != hex.EncodeToString(kMbx[:]) {
		t.Fatalf("v06 K_mbx does not match v04")
	}
	v06Nonce := as24(t, v06.Inputs.NonceHex)
	ct := SealMailbox(kMbx, v06Nonce, unhex(t, v06.Inputs.PlaintextHex), unhex(t, v06.Inputs.ADHex))
	eqHex(t, "v06 ciphertext", ct, v06.Outputs.CiphertextHex)
	if pt, err := OpenMailbox(kMbx, v06Nonce, ct, unhex(t, v06.Inputs.ADHex)); err != nil || hex.EncodeToString(pt) != v06.Inputs.PlaintextHex {
		t.Errorf("v06 open round-trip failed: %v", err)
	}
	tl.positives++

	// ---- v07 ------------------------------------------------------------
	var v07 struct {
		Inputs struct {
			AccountBind string `json:"account_bind_hex"`
			DevPK       string `json:"dev_pk_hex"`
			DeviceID    string `json:"device_id_hex"`
			HostID      string `json:"host_id_hex"`
			HostPK      string `json:"host_pk_hex"`
			ND          string `json:"n_d_hex"`
			Proto       int    `json:"proto"`
			Token       string `json:"token_hex"`
		} `json:"inputs"`
		Outputs struct {
			MacPair string `json:"mac_pair_hex"`
		} `json:"outputs"`
	}
	loadJSON(t, dir, vectorFiles[6], &v07)
	tl.files++
	v07Token := as32(t, v07.Inputs.Token)
	v07Bind := as16(t, v07.Inputs.AccountBind)
	mac := V1.MacPair(v07Token, as16(t, v07.Inputs.HostID), as32(t, v07.Inputs.HostPK),
		as16(t, v07.Inputs.DeviceID), as32(t, v07.Inputs.DevPK), as32(t, v07.Inputs.ND), v07Bind)
	eqHex(t, "v07 mac_pair", mac[:], v07.Outputs.MacPair)
	if !VerifyMAC(mac[:], unhex(t, v07.Outputs.MacPair)) {
		t.Errorf("v07 constant-time verify failed on the genuine MAC")
	}
	tl.positives++

	// ---- v08 ------------------------------------------------------------
	var v08 struct {
		Inputs struct {
			HostPK string `json:"host_pk_hex"`
			Sub    string `json:"sub_utf8"`
		} `json:"inputs"`
		Outputs struct {
			AccountBind string `json:"account_bind_hex"`
			Wire        string `json:"account_bind_wire"`
			FullHex     string `json:"blake2b256_full_hex"`
		} `json:"outputs"`
	}
	loadJSON(t, dir, vectorFiles[7], &v08)
	tl.files++
	bind := V1.AccountBind(as32(t, v08.Inputs.HostPK), v08.Inputs.Sub)
	eqHex(t, "v08 account_bind", bind[:], v08.Outputs.AccountBind)
	if EncodeBin(bind[:]) != v08.Outputs.Wire {
		t.Errorf("v08 wire encoding: got %s want %s", EncodeBin(bind[:]), v08.Outputs.Wire)
	}
	// Truncation check: the first 16 bytes of the full 32-byte digest.
	full, _ := blake2b.New256(nil)
	full.Write(V1.dsAcct())
	full.Write(unhex(t, v08.Inputs.HostPK))
	full.Write([]byte(v08.Inputs.Sub))
	eqHex(t, "v08 full blake2b-256", full.Sum(nil), v08.Outputs.FullHex)
	tl.positives++

	// ---- v09 ------------------------------------------------------------
	tl.files++
	runV09(t, dir, &tl)

	// ---- v10 ------------------------------------------------------------
	tl.files++
	runV10(t, dir, &tl, v05Key, v05Hdr)

	// ---- v11 / v12 ------------------------------------------------------
	tl.files += 2
	runV11V12(t, dir, &tl, kMbx)

	// ---- v13 ------------------------------------------------------------
	var v13 struct {
		Base struct {
			KMbxHex       string `json:"K_mbx_hex"`
			ADHex         string `json:"ad_hex"`
			CiphertextHex string `json:"ciphertext_hex"`
			NonceHex      string `json:"nonce_hex"`
		} `json:"base_frame"`
		Cases []struct {
			Case     string `json:"case"`
			ADHex    string `json:"ad_hex"`
			Expect   string `json:"expect"`
			NonceHex string `json:"nonce_hex"`
		} `json:"cases"`
	}
	loadJSON(t, dir, vectorFiles[12], &v13)
	tl.files++
	if len(v13.Cases) != 4 {
		t.Fatalf("v13: want 4 cases, got %d", len(v13.Cases))
	}
	baseCT := unhex(t, v13.Base.CiphertextHex)
	for _, c := range v13.Cases {
		if c.Expect != "decrypt_failure" {
			t.Fatalf("v13 %s: unexpected expect marker %q", c.Case, c.Expect)
		}
		if _, err := OpenMailbox(kMbx, as24(t, c.NonceHex), baseCT, unhex(t, c.ADHex)); err == nil {
			t.Errorf("v13 %s: decrypt succeeded; want failure", c.Case)
		}
		tl.negatives++
	}
	// wrong_nonce fixture cross-check.
	eqHex(t, "v13 wrong-nonce fixture", fixture(t, "v13-wrong-nonce", 24), v13.Cases[3].NonceHex)

	// ---- v14 ------------------------------------------------------------
	runV14(t, dir, &tl, roots, hostID, deviceID, nD, nH, v07Token, v07Bind)

	// ---- v15 ------------------------------------------------------------
	runV15(t, dir, &tl, roots, sk1)

	// ---- v16 ------------------------------------------------------------
	runV16(t, dir, &tl, v07Token, as16(t, v07.Inputs.HostID), as32(t, v07.Inputs.HostPK),
		as16(t, v07.Inputs.DeviceID), as32(t, v07.Inputs.DevPK), as32(t, v07.Inputs.ND), v07Bind)

	// ---- v17 ------------------------------------------------------------
	runV17(t, dir, &tl, roots, hostID, deviceID, dev.pk, sk1, mac)

	// ---- totals ---------------------------------------------------------
	if tl.files != len(vectorFiles) {
		t.Errorf("processed %d vector files, want %d — a vector file was silently skipped", tl.files, len(vectorFiles))
	}
	const wantPositives = 43
	const wantNegatives = 36
	if tl.positives != wantPositives {
		t.Errorf("ran %d positive conformance checks, want %d — a positive chain was silently skipped", tl.positives, wantPositives)
	}
	if tl.negatives != wantNegatives {
		t.Errorf("ran %d negative cases, want %d — a negative case was silently skipped", tl.negatives, wantNegatives)
	}
	t.Logf("golden vectors: %d files, %d positive checks, %d negative cases — all conformant", tl.files, tl.positives, tl.negatives)
}

func mustPushClass(t *testing.T, s string) byte {
	t.Helper()
	b, err := ParsePushClass(s)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return b
}

func runV09(t *testing.T, dir string, tl *tally) {
	var v09 struct {
		Canonical struct {
			DeviceSub   string `json:"device_sub_utf8"`
			EvalNowUnix int64  `json:"eval_now_unix"`
			Expect      string `json:"expect"`
			URI         string `json:"uri"`
			Fields      struct {
				A struct{ RawHex, Wire string }
				E int64
				H struct{ RawHex, Wire string }
				K struct{ RawHex, Wire string }
				R string
				T struct{ RawHex, Wire string }
				V int
			} `json:"fields"`
		} `json:"canonical"`
		Rejections []struct {
			Case        string `json:"case"`
			DeviceSub   string `json:"device_sub_utf8"`
			EvalNowUnix int64  `json:"eval_now_unix"`
			Expect      string `json:"expect"`
			URI         string `json:"uri"`
		} `json:"rejections"`
	}
	// The nested raw_hex/wire keys use snake_case; re-decode with a raw map
	// for those fields.
	var raw struct {
		Canonical struct {
			Fields map[string]json.RawMessage `json:"fields"`
		} `json:"canonical"`
	}
	loadJSON(t, dir, vectorFiles[8], &v09)
	loadJSON(t, dir, vectorFiles[8], &raw)
	field := func(name string) (rawHex, wire string) {
		var f struct {
			RawHex string `json:"raw_hex"`
			Wire   string `json:"wire"`
		}
		if err := json.Unmarshal(raw.Canonical.Fields[name], &f); err != nil {
			t.Fatalf("v09 field %s: %v", name, err)
		}
		return f.RawHex, f.Wire
	}
	var rStr string
	if err := json.Unmarshal(raw.Canonical.Fields["r"], &rStr); err != nil {
		t.Fatalf("v09 field r: %v", err)
	}
	var eNum int64
	if err := json.Unmarshal(raw.Canonical.Fields["e"], &eNum); err != nil {
		t.Fatalf("v09 field e: %v", err)
	}

	hHex, hWire := field("h")
	kHex, _ := field("k")
	tHex, _ := field("t")
	aHex, aWire := field("a")

	p := &QRPayload{
		Version:     1,
		RelayOrigin: rStr,
		HostID:      as16(t, hHex),
		HostPK:      as32(t, kHex),
		Token:       as32(t, tHex),
		AccountBind: as16(t, aHex),
		ExpiresUnix: eNum,
	}
	if got := p.Encode(); got != v09.Canonical.URI {
		t.Errorf("v09 canonical encode mismatch:\n  got  %s\n  want %s", got, v09.Canonical.URI)
	}
	parsed, err := ParseQR(v09.Canonical.URI)
	if err != nil {
		t.Fatalf("v09 canonical parse: %v", err)
	}
	if *parsed != *p {
		t.Errorf("v09 canonical parse round-trip mismatch: %+v vs %+v", parsed, p)
	}
	if EncodeChannelID(parsed.HostID) != hWire || EncodeBin(parsed.AccountBind[:]) != aWire {
		t.Errorf("v09 wire field encodings mismatch")
	}
	if err := parsed.Validate(v09.Canonical.EvalNowUnix, v09.Canonical.DeviceSub); err != nil {
		t.Errorf("v09 canonical Validate: %v", err)
	}
	tl.positives++

	if len(v09.Rejections) != 7 {
		t.Fatalf("v09: want 7 rejection cases, got %d", len(v09.Rejections))
	}
	for _, c := range v09.Rejections {
		if c.Expect != "reject" {
			t.Fatalf("v09 %s: unexpected expect marker %q", c.Case, c.Expect)
		}
		sub := c.DeviceSub
		if sub == "" {
			sub = v09.Canonical.DeviceSub
		}
		pp, err := ParseQR(c.URI)
		if err == nil {
			err = pp.Validate(c.EvalNowUnix, sub)
		}
		if err == nil {
			t.Errorf("v09 %s: accepted; want rejection", c.Case)
		}
		tl.negatives++
	}
}

func runV10(t *testing.T, dir string, tl *tally, key [32]byte, hdr [24]byte) {
	var v10 struct {
		Base struct {
			Frames    []vFrame `json:"frames"`
			HeaderHex string   `json:"header_hex"`
			KeyHex    string   `json:"key_hex"`
		} `json:"base_stream"`
		Cases []struct {
			Case          string `json:"case"`
			ADHex         string `json:"ad_hex"`
			Expect        string `json:"expect"`
			FrameIndex    int    `json:"frame_index"`
			WrongKeyHex   string `json:"wrong_key_hex"`
			CiphertextHex string `json:"ciphertext_hex"`
			PlaintextUTF8 string `json:"plaintext_utf8"`
		} `json:"cases"`
	}
	loadJSON(t, dir, vectorFiles[9], &v10)
	if len(v10.Cases) != 5 || len(v10.Base.Frames) != 4 {
		t.Fatalf("v10: want 5 cases over 4 base frames, got %d/%d", len(v10.Cases), len(v10.Base.Frames))
	}
	if v10.Base.KeyHex != hex.EncodeToString(key[:]) || v10.Base.HeaderHex != hex.EncodeToString(hdr[:]) {
		t.Fatalf("v10 base stream fixtures do not match v05")
	}
	frames := v10.Base.Frames
	for _, c := range v10.Cases {
		switch c.Case {
		case "tampered_ad_push_class", "tampered_header_channel":
			if c.Expect != "decrypt_failure" {
				t.Fatalf("v10 %s: expect %q", c.Case, c.Expect)
			}
			s := NewPullStream(key, hdr)
			if _, _, err := s.Pull(unhex(t, frames[c.FrameIndex].CiphertextHex), unhex(t, c.ADHex)); err == nil {
				t.Errorf("v10 %s: decrypt succeeded; want failure", c.Case)
			}
			tl.negatives++
		case "wrong_key":
			if c.Expect != "decrypt_failure" {
				t.Fatalf("v10 %s: expect %q", c.Case, c.Expect)
			}
			s := NewPullStream(as32(t, c.WrongKeyHex), hdr)
			if _, _, err := s.Pull(unhex(t, frames[c.FrameIndex].CiphertextHex), unhex(t, c.ADHex)); err == nil {
				t.Errorf("v10 wrong_key: decrypt succeeded; want failure")
			}
			tl.negatives++
		case "out_of_order":
			if c.Expect != "decrypt_failure" {
				t.Fatalf("v10 %s: expect %q", c.Case, c.Expect)
			}
			s := NewPullStream(key, hdr)
			if _, _, err := s.Pull(unhex(t, frames[1].CiphertextHex), unhex(t, frames[1].ADHex)); err == nil {
				t.Errorf("v10 out_of_order: decrypt succeeded; want failure")
			}
			tl.negatives++
		case "post_final_frame":
			if c.Expect != "reject_post_final" {
				t.Fatalf("v10 post_final_frame: expect %q, want reject_post_final", c.Expect)
			}
			// (a) The frame is cryptographically PRODUCIBLE: pushing the ack
			// past TAG_FINAL reproduces the vector ciphertext byte-exactly.
			push := NewPullStream(key, hdr)
			for _, f := range frames {
				push.pushRaw(unhex(t, f.PlaintextHex), unhex(t, f.ADHex), tagByte(t, f.Tag))
			}
			postCT := push.pushRaw([]byte(c.PlaintextUTF8), unhex(t, c.ADHex), TagMessage)
			eqHex(t, "v10 post-final ciphertext", postCT, c.CiphertextHex)
			tl.positives++
			// (b) It DECRYPTS cryptographically (TAG_FINAL rekeys both sides)…
			raw := NewPullStream(key, hdr)
			for _, f := range frames {
				if _, _, err := raw.pullRaw(unhex(t, f.CiphertextHex), unhex(t, f.ADHex)); err != nil {
					t.Fatalf("v10 base pull: %v", err)
				}
			}
			pt, _, err := raw.pullRaw(unhex(t, c.CiphertextHex), unhex(t, c.ADHex))
			if err != nil || string(pt) != c.PlaintextUTF8 {
				t.Errorf("v10 post_final_frame: the frame must DECRYPT cryptographically (got err=%v pt=%q) — asserting an AEAD failure here would be asserting something false", err, pt)
			}
			// (c) …and the PROTOCOL layer refuses it anyway.
			proto := NewPullStream(key, hdr)
			for _, f := range frames {
				if _, _, err := proto.Pull(unhex(t, f.CiphertextHex), unhex(t, f.ADHex)); err != nil {
					t.Fatalf("v10 base pull (protocol): %v", err)
				}
			}
			if _, _, err := proto.Pull(unhex(t, c.CiphertextHex), unhex(t, c.ADHex)); err != ErrStreamFinished {
				t.Errorf("v10 post_final_frame: want ErrStreamFinished (protocol refusal), got %v", err)
			}
			tl.negatives++
		default:
			t.Fatalf("v10: unknown case %q", c.Case)
		}
	}
}

func runV11V12(t *testing.T, dir string, tl *tally, kMbx [32]byte) {
	var v11 struct {
		Cases []struct {
			Case   string `json:"case"`
			Expect string `json:"expect"`
			Pull   string `json:"pull"`
		} `json:"cases"`
		Frame  vFrame `json:"frame"`
		Inputs struct {
			KsessD2H string `json:"Ksess_d2h_hex"`
			KsessH2D string `json:"Ksess_h2d_hex"`
			HdrD2H   string `json:"hdr_d2h_hex"`
			HdrH2D   string `json:"hdr_h2d_hex"`
		} `json:"inputs"`
	}
	loadJSON(t, dir, vectorFiles[10], &v11)
	if len(v11.Cases) != 2 {
		t.Fatalf("v11: want 2 cases, got %d", len(v11.Cases))
	}
	kd2h := as32(t, v11.Inputs.KsessD2H)
	hd2h, hh2d := as24(t, v11.Inputs.HdrD2H), as24(t, v11.Inputs.HdrH2D)
	frameCT, frameAD := unhex(t, v11.Frame.CiphertextHex), unhex(t, v11.Frame.ADHex)
	for _, c := range v11.Cases {
		if c.Expect != "decrypt_failure" {
			t.Fatalf("v11 %s: expect %q", c.Case, c.Expect)
		}
		var s *Stream
		switch c.Case {
		case "h2d_frame_into_d2h_state":
			s = NewPullStream(kd2h, hd2h)
		case "h2d_header_with_d2h_key":
			s = NewPullStream(kd2h, hh2d)
		default:
			t.Fatalf("v11: unknown case %q", c.Case)
		}
		if _, _, err := s.Pull(frameCT, frameAD); err == nil {
			t.Errorf("v11 %s: decrypt succeeded; want failure", c.Case)
		}
		tl.negatives++
	}

	var v12 struct {
		Cases []struct {
			Case   string `json:"case"`
			Expect string `json:"expect"`
		} `json:"cases"`
		Live struct {
			KsessH2D string `json:"Ksess_h2d_hex"`
			HdrH2D   string `json:"hdr_h2d_hex"`
			Frame    vFrame `json:"frame"`
		} `json:"live_frame"`
		Mailbox struct {
			KMbxHex       string `json:"K_mbx_hex"`
			ADHex         string `json:"ad_hex"`
			CiphertextHex string `json:"ciphertext_hex"`
			NonceHex      string `json:"nonce_hex"`
		} `json:"mailbox_frame"`
	}
	loadJSON(t, dir, vectorFiles[11], &v12)
	if len(v12.Cases) != 2 {
		t.Fatalf("v12: want 2 cases, got %d", len(v12.Cases))
	}
	if v12.Mailbox.KMbxHex != hex.EncodeToString(kMbx[:]) {
		t.Fatalf("v12 K_mbx does not match v04")
	}
	for _, c := range v12.Cases {
		if c.Expect != "decrypt_failure" {
			t.Fatalf("v12 %s: expect %q", c.Case, c.Expect)
		}
		switch c.Case {
		case "mailbox_frame_on_live_stream":
			s := NewPullStream(as32(t, v12.Live.KsessH2D), as24(t, v12.Live.HdrH2D))
			if _, _, err := s.Pull(unhex(t, v12.Mailbox.CiphertextHex), unhex(t, v12.Mailbox.ADHex)); err == nil {
				t.Errorf("v12 %s: decrypt succeeded; want failure", c.Case)
			}
		case "live_frame_under_K_mbx":
			if _, err := OpenMailbox(kMbx, as24(t, v12.Mailbox.NonceHex),
				unhex(t, v12.Live.Frame.CiphertextHex), unhex(t, v12.Live.Frame.ADHex)); err == nil {
				t.Errorf("v12 %s: decrypt succeeded; want failure", c.Case)
			}
		default:
			t.Fatalf("v12: unknown case %q", c.Case)
		}
		tl.negatives++
	}
}

func runV14(t *testing.T, dir string, tl *tally, roots Roots, hostID, deviceID [16]byte, nD, nH [32]byte, token [32]byte, bind [16]byte) {
	var v14 struct {
		Inputs struct {
			DSv2       map[string]string `json:"ds_strings_v2"`
			Proto      int               `json:"proto"`
			Transcript string            `json:"transcript_T_v2_hex"`
		} `json:"inputs"`
		V1 map[string]string `json:"outputs_v1_reference"`
		V2 map[string]string `json:"outputs_v2"`
	}
	loadJSON(t, dir, vectorFiles[13], &v14)
	tl.files++
	s2 := Suite{Proto: 2}
	// DS strings are version-locked and derived, not stored — check them.
	wantDS := map[string]func() []byte{
		"DS_CONFIRM": s2.dsConfirm, "DS_D2H": s2.dsD2H, "DS_H2D": s2.dsH2D,
		"DS_MBX": s2.dsMbx, "DS_PAIR": s2.dsPair,
	}
	for name, fn := range wantDS {
		if got := string(fn()); got != v14.Inputs.DSv2[name] {
			t.Errorf("v14 %s: got %q want %q", name, got, v14.Inputs.DSv2[name])
		}
	}
	tr2 := s2.Transcript(hostID, deviceID, nD, nH)
	eqHex(t, "v14 transcript T v2", tr2[:], v14.Inputs.Transcript)
	sk2 := s2.SessionKeys(roots, tr2)
	kMbx2 := s2.MailboxKey(roots, hostID, deviceID)
	mac2 := s2.MacPair(token, hostID, as32(t, ""), deviceID, as32(t, ""), nD, bind)
	_ = mac2 // recomputed below with the real pk inputs
	// mac_pair v2 uses the V7 inputs; host_pk/dev_pk must come from v07.
	// Re-derive them from the v1 reference by recomputing with Suite v1 —
	// instead, load v07 inputs again.
	var v07 struct {
		Inputs struct {
			DevPK  string `json:"dev_pk_hex"`
			HostPK string `json:"host_pk_hex"`
		} `json:"inputs"`
	}
	loadJSON(t, dir, vectorFiles[6], &v07)
	mac2 = s2.MacPair(token, hostID, as32(t, v07.Inputs.HostPK), deviceID, as32(t, v07.Inputs.DevPK), nD, bind)

	got := map[string][]byte{
		"K_mbx_hex":     kMbx2[:],
		"Ksess_d2h_hex": sk2.D2H[:],
		"Ksess_h2d_hex": sk2.H2D[:],
		"conf_d_hex":    sk2.ConfD[:],
		"conf_h_hex":    sk2.ConfH[:],
		"mac_pair_hex":  mac2[:],
	}
	for name, g := range got {
		eqHex(t, "v14 v2 "+name, g, v14.V2[name])
		if hex.EncodeToString(g) == v14.V1[name] {
			t.Errorf("v14 %s: v2 output equals the v1 reference — version separation broken", name)
		}
	}
	tl.positives++
}

func runV15(t *testing.T, dir string, tl *tally, roots Roots, sk SessionKeys) {
	var v15 struct {
		Cases []struct {
			Case       string `json:"case"`
			ConfD      string `json:"conf_d_over_tampered_T_hex"`
			ConfH      string `json:"conf_h_over_tampered_T_hex"`
			Expect     string `json:"expect"`
			Transcript string `json:"transcript_T_hex"`
			Expected   string `json:"expected"`
			Presented  string `json:"presented"`
		} `json:"cases"`
		Genuine struct {
			ConfD      string `json:"conf_d_hex"`
			ConfH      string `json:"conf_h_hex"`
			Transcript string `json:"transcript_T_hex"`
		} `json:"genuine"`
	}
	loadJSON(t, dir, vectorFiles[14], &v15)
	tl.files++
	if len(v15.Cases) != 6 {
		t.Fatalf("v15: want 6 cases, got %d", len(v15.Cases))
	}
	if v15.Genuine.ConfH != hex.EncodeToString(sk.ConfH[:]) || v15.Genuine.ConfD != hex.EncodeToString(sk.ConfD[:]) {
		t.Fatalf("v15 genuine confs do not match the v03 schedule")
	}
	for _, c := range v15.Cases {
		if c.Expect != "confirm_mismatch" {
			t.Fatalf("v15 %s: expect %q", c.Case, c.Expect)
		}
		if c.Case == "reflection_conf_h_as_conf_d" {
			if hex.EncodeToString(sk.ConfD[:]) != c.Expected || hex.EncodeToString(sk.ConfH[:]) != c.Presented {
				t.Errorf("v15 reflection fixtures do not match the schedule")
			}
			if VerifyMAC(unhex(t, c.Expected), unhex(t, c.Presented)) {
				t.Errorf("v15 reflection: conf_h accepted where conf_d expected")
			}
			tl.negatives++
			continue
		}
		tampered := unhex(t, c.Transcript)
		if len(tampered) != TranscriptLen {
			t.Fatalf("v15 %s: tampered transcript is %d bytes", c.Case, len(tampered))
		}
		confH := keyedHash32(roots.H2D[:], V1.dsConfirm(), tampered)
		confD := keyedHash32(roots.D2H[:], V1.dsConfirm(), tampered)
		eqHex(t, "v15 "+c.Case+" conf_h'", confH[:], c.ConfH)
		eqHex(t, "v15 "+c.Case+" conf_d'", confD[:], c.ConfD)
		tl.positives++
		if VerifyMAC(sk.ConfH[:], confH[:]) || VerifyMAC(sk.ConfD[:], confD[:]) {
			t.Errorf("v15 %s: tampered conf accepted against genuine", c.Case)
		}
		tl.negatives++
	}
}

func runV16(t *testing.T, dir string, tl *tally, token [32]byte, hostID [16]byte, hostPK [32]byte, deviceID [16]byte, devPK [32]byte, nD [32]byte, bind [16]byte) {
	var v16 struct {
		Cases []struct {
			Case   string `json:"case"`
			Detail string `json:"detail"`
			Expect string `json:"expect"`
			MacHex string `json:"mac_over_tampered_inputs_hex"`
		} `json:"cases"`
		Genuine struct {
			MacPair string `json:"mac_pair_hex"`
		} `json:"genuine"`
	}
	loadJSON(t, dir, vectorFiles[15], &v16)
	tl.files++
	if len(v16.Cases) != 8 {
		t.Fatalf("v16: want 8 cases, got %d", len(v16.Cases))
	}
	genuine := V1.MacPair(token, hostID, hostPK, deviceID, devPK, nD, bind)
	if hex.EncodeToString(genuine[:]) != v16.Genuine.MacPair {
		t.Fatalf("v16 genuine mac does not match v07")
	}
	flip := func(b []byte) []byte { out := append([]byte(nil), b...); out[0] ^= 0x01; return out }
	for _, c := range v16.Cases {
		if c.Expect != "mac_mismatch" {
			t.Fatalf("v16 %s: expect %q", c.Case, c.Expect)
		}
		var tampered [32]byte
		switch c.Case {
		case "wrong_token":
			var wrong [32]byte
			copy(wrong[:], fixture(t, "v16-wrong-token", 32))
			tampered = V1.MacPair(wrong, hostID, hostPK, deviceID, devPK, nD, bind)
		case "tampered_proto":
			// proto byte 0x01→0x02 with the DS string left at v1 — field
			// isolation, deliberately not expressible through Suite{2}.
			tampered = keyedHash32(token[:], V1.dsPair(), []byte{0x02},
				hostID[:], hostPK[:], deviceID[:], devPK[:], nD[:], bind[:])
		case "tampered_host_id":
			var f [16]byte
			copy(f[:], flip(hostID[:]))
			tampered = V1.MacPair(token, f, hostPK, deviceID, devPK, nD, bind)
		case "tampered_host_pk":
			var f [32]byte
			copy(f[:], flip(hostPK[:]))
			tampered = V1.MacPair(token, hostID, f, deviceID, devPK, nD, bind)
		case "tampered_device_id":
			var f [16]byte
			copy(f[:], flip(deviceID[:]))
			tampered = V1.MacPair(token, hostID, hostPK, f, devPK, nD, bind)
		case "tampered_dev_pk":
			var f [32]byte
			copy(f[:], flip(devPK[:]))
			tampered = V1.MacPair(token, hostID, hostPK, deviceID, f, nD, bind)
		case "tampered_n_d":
			var f [32]byte
			copy(f[:], flip(nD[:]))
			tampered = V1.MacPair(token, hostID, hostPK, deviceID, devPK, f, bind)
		case "tampered_account_bind":
			var f [16]byte
			copy(f[:], flip(bind[:]))
			tampered = V1.MacPair(token, hostID, hostPK, deviceID, devPK, nD, f)
		default:
			t.Fatalf("v16: unknown case %q", c.Case)
		}
		eqHex(t, "v16 "+c.Case+" tampered mac", tampered[:], c.MacHex)
		tl.positives++
		if VerifyMAC(genuine[:], tampered[:]) {
			t.Errorf("v16 %s: genuine MAC verified against tampered inputs", c.Case)
		}
		tl.negatives++
	}
}

func runV17(t *testing.T, dir string, tl *tally, roots Roots, hostID, deviceID [16]byte, devPK [32]byte, pairSK SessionKeys, pairMac [32]byte) {
	type v17Wire struct {
		AD            json.RawMessage `json:"ad"`
		ADHex         string          `json:"ad_hex"`
		Body          json.RawMessage `json:"body"`
		CiphertextHex string          `json:"ciphertext_hex"`
		Class         string          `json:"class"`
		PlaintextHex  string          `json:"plaintext_hex"`
		PlaintextUTF8 string          `json:"plaintext_utf8"`
		Tag           string          `json:"tag"`
		Header        struct {
			Channel   string `json:"channel"`
			PushClass string `json:"push_class"`
			Seq       uint64 `json:"seq"`
		} `json:"header"`
	}
	type v17Frame struct {
		Direction string  `json:"direction"`
		Frame     int     `json:"frame"`
		Kind      string  `json:"kind"`
		Wire      v17Wire `json:"wire"`
	}
	var v17 struct {
		Fixtures struct {
			DurableHex      string            `json:"durable_channel_id_hex"`
			DurableWire     string            `json:"durable_channel_wire"`
			ProvisionalHex  string            `json:"provisional_channel_id_hex"`
			ProvisionalWire string            `json:"provisional_channel_wire"`
			PairingRaw      map[string]string `json:"pairing_session"`
			ReconnectRaw    map[string]string `json:"reconnect_session"`
		} `json:"fixtures"`
		PairingFlow []v17Frame `json:"pairing_flow"`
		SessionFlow []v17Frame `json:"session_flow"`
		Rejections  []struct {
			Case          string          `json:"case"`
			Expect        string          `json:"expect"`
			Body          json.RawMessage `json:"body"`
			CiphertextHex string          `json:"ciphertext_hex"`
			Header        struct {
				Channel   string `json:"channel"`
				PushClass string `json:"push_class"`
				Seq       uint64 `json:"seq"`
			} `json:"header"`
		} `json:"rejections"`
	}
	loadJSON(t, dir, vectorFiles[16], &v17)
	tl.files++
	if len(v17.PairingFlow) != 5 || len(v17.SessionFlow) != 5 || len(v17.Rejections) != 2 {
		t.Fatalf("v17: want 5+5 frames and 2 rejections, got %d/%d/%d",
			len(v17.PairingFlow), len(v17.SessionFlow), len(v17.Rejections))
	}
	durable, provisional := as16(t, v17.Fixtures.DurableHex), as16(t, v17.Fixtures.ProvisionalHex)
	if EncodeChannelID(durable) != v17.Fixtures.DurableWire || EncodeChannelID(provisional) != v17.Fixtures.ProvisionalWire {
		t.Errorf("v17 channel wire encodings mismatch")
	}
	pfix, rfix := v17.Fixtures.PairingRaw, v17.Fixtures.ReconnectRaw

	// Pairing-session schedule must equal the V3 schedule.
	if pfix["Ksess_h2d_hex"] != hex.EncodeToString(pairSK.H2D[:]) ||
		pfix["conf_d_hex"] != hex.EncodeToString(pairSK.ConfD[:]) {
		t.Fatalf("v17 pairing_session does not match the v03 schedule")
	}
	// Reconnect-session schedule: same roots, fresh nonces — derive it.
	rND, rNH := as32(t, rfix["n_d_hex"]), as32(t, rfix["n_h_hex"])
	rTr := V1.Transcript(hostID, deviceID, rND, rNH)
	rSK := V1.SessionKeys(roots, rTr)
	eqHex(t, "v17 reconnect Ksess_h2d", rSK.H2D[:], rfix["Ksess_h2d_hex"])
	eqHex(t, "v17 reconnect Ksess_d2h", rSK.D2H[:], rfix["Ksess_d2h_hex"])
	eqHex(t, "v17 reconnect conf_h", rSK.ConfH[:], rfix["conf_h_hex"])
	eqHex(t, "v17 reconnect conf_d", rSK.ConfD[:], rfix["conf_d_hex"])
	tl.positives++

	// Class-P body field pins (pairing frames 1–3).
	checkP := func(f v17Frame, wantChannel string, checks map[string]string) {
		t.Helper()
		if f.Wire.Class != "P" {
			t.Fatalf("v17 %s: want class P", f.Kind)
		}
		if err := CheckFrameClass(f.Wire.Header.Seq, true); err != nil {
			t.Errorf("v17 %s: class check: %v", f.Kind, err)
		}
		if f.Wire.Header.Channel != wantChannel || f.Wire.Header.Seq != 0 || f.Wire.Header.PushClass != "none" {
			t.Errorf("v17 %s: header pin mismatch: %+v", f.Kind, f.Wire.Header)
		}
		var env struct {
			V    int             `json:"v"`
			Kind string          `json:"kind"`
			Body json.RawMessage `json:"body"`
		}
		if err := json.Unmarshal(f.Wire.Body, &env); err != nil {
			t.Fatalf("v17 %s body: %v", f.Kind, err)
		}
		if env.V != 1 || env.Kind != f.Kind {
			t.Errorf("v17 %s: envelope pin mismatch: v=%d kind=%s", f.Kind, env.V, env.Kind)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(env.Body, &body); err != nil {
			t.Fatalf("v17 %s inner body: %v", f.Kind, err)
		}
		for field, want := range checks {
			var got string
			if err := json.Unmarshal(body[field], &got); err != nil {
				t.Errorf("v17 %s field %s: %v", f.Kind, field, err)
				continue
			}
			if got != want {
				t.Errorf("v17 %s field %s: got %s want %s", f.Kind, field, got, want)
			}
		}
	}

	// checkL pushes the GIVEN plaintext (opaque bytes — no JSON
	// canonicalization) on a deterministically-seeded stream and matches
	// the ciphertext.
	checkL := func(f v17Frame, key [32]byte, hdr [24]byte, channel [16]byte) {
		t.Helper()
		if f.Wire.Class != "L" {
			t.Fatalf("v17 %s: want class L", f.Kind)
		}
		if err := CheckFrameClass(f.Wire.Header.Seq, false); err != nil {
			t.Errorf("v17 %s: class check: %v", f.Kind, err)
		}
		pc, err := ParsePushClass(f.Wire.Header.PushClass)
		if err != nil {
			t.Fatalf("v17 %s: %v", f.Kind, err)
		}
		ad := BuildAD(channel, f.Wire.Header.Seq, pc)
		eqHex(t, "v17 "+f.Kind+" AD", ad[:], f.Wire.ADHex)
		s := NewPullStream(key, hdr)
		ct, err := s.Push(unhex(t, f.Wire.PlaintextHex), ad[:], tagByte(t, f.Wire.Tag))
		if err != nil {
			t.Fatalf("v17 %s push: %v", f.Kind, err)
		}
		eqHex(t, "v17 "+f.Kind+" ciphertext", ct, f.Wire.CiphertextHex)
	}

	// Pairing flow.
	pf := v17.PairingFlow
	checkP(pf[0], v17.Fixtures.ProvisionalWire, map[string]string{
		"dev_pk":    EncodeBin(devPK[:]),
		"device_id": EncodeChannelID(deviceID),
		"mac_pair":  EncodeBin(pairMac[:]),
		"n_d":       EncodeBin(unhex(t, pfix["n_d_hex"])),
	})
	tl.positives++
	checkP(pf[1], v17.Fixtures.ProvisionalWire, map[string]string{
		"hdr_h2d": EncodeBin(unhex(t, pfix["hdr_h2d_hex"])),
		"host_id": EncodeChannelID(hostID),
		"n_h":     EncodeBin(unhex(t, pfix["n_h_hex"])),
	})
	tl.positives++
	checkP(pf[2], v17.Fixtures.ProvisionalWire, map[string]string{
		"hdr_d2h": EncodeBin(unhex(t, pfix["hdr_d2h_hex"])),
	})
	tl.positives++
	// pair.identity: first AEAD frame device→host EVER — seq 1, AD over
	// the PROVISIONAL channel, d2h stream.
	if pf[3].Wire.Header.Seq != 1 {
		t.Errorf("v17 pair.identity: seq %d, want 1 (pairing-lifetime counter starts at 1)", pf[3].Wire.Header.Seq)
	}
	checkL(pf[3], as32(t, pfix["Ksess_d2h_hex"]), as24(t, pfix["hdr_d2h_hex"]), provisional)
	tl.positives++
	if pf[4].Wire.Header.Seq != 1 {
		t.Errorf("v17 pair.complete: seq %d, want 1", pf[4].Wire.Header.Seq)
	}
	checkL(pf[4], as32(t, pfix["Ksess_h2d_hex"]), as24(t, pfix["hdr_h2d_hex"]), provisional)
	tl.positives++

	// Session (reconnect) flow.
	sf := v17.SessionFlow
	checkP(sf[0], v17.Fixtures.DurableWire, map[string]string{
		"device_id": EncodeChannelID(deviceID),
		"n_d":       EncodeBin(rND[:]),
	})
	tl.positives++
	checkP(sf[1], v17.Fixtures.DurableWire, map[string]string{
		"hdr_h2d": EncodeBin(unhex(t, rfix["hdr_h2d_hex"])),
		"host_id": EncodeChannelID(hostID),
		"n_h":     EncodeBin(rNH[:]),
	})
	tl.positives++
	checkP(sf[2], v17.Fixtures.DurableWire, map[string]string{
		"hdr_d2h": EncodeBin(unhex(t, rfix["hdr_d2h_hex"])),
	})
	tl.positives++
	// sess.confirm frames: seq 2 in this SCENARIO (pairing consumed 1) —
	// the rule is "next pairing-lifetime counter value", never a constant.
	for _, f := range sf[3:5] {
		if f.Wire.Header.Seq != 2 {
			t.Errorf("v17 sess.confirm %s: seq %d, want 2 for this scenario", f.Direction, f.Wire.Header.Seq)
		}
		var env struct {
			Body struct {
				TranscriptMAC string `json:"transcript_mac"`
			} `json:"body"`
		}
		if err := json.Unmarshal([]byte(f.Wire.PlaintextUTF8), &env); err != nil {
			t.Fatalf("v17 sess.confirm plaintext: %v", err)
		}
		if f.Direction == "device->host" {
			checkL(f, rSK.D2H, as24(t, rfix["hdr_d2h_hex"]), durable)
			if env.Body.TranscriptMAC != EncodeBin(rSK.ConfD[:]) {
				t.Errorf("v17 sess.confirm d2h: transcript_mac != conf_d")
			}
		} else {
			checkL(f, rSK.H2D, as24(t, rfix["hdr_h2d_hex"]), durable)
			if env.Body.TranscriptMAC != EncodeBin(rSK.ConfH[:]) {
				t.Errorf("v17 sess.confirm h2d: transcript_mac != conf_h")
			}
		}
		tl.positives++
	}
	// Tracker semantics across the scenario: pairing frame at 1, then a
	// reconnect session-start at exactly 2 (no reconcile — nothing lost).
	tr := NewSeqTracker(0)
	if rec, err := tr.Accept(1); err != nil || rec {
		t.Errorf("v17 tracker: pairing seq 1: rec=%v err=%v", rec, err)
	}
	tr.StartSession()
	if rec, err := tr.Accept(2); err != nil || rec {
		t.Errorf("v17 tracker: reconnect sess.confirm seq 2: rec=%v err=%v", rec, err)
	}

	// Rejections.
	for _, c := range v17.Rejections {
		if c.Expect != "reject" {
			t.Fatalf("v17 %s: expect %q", c.Case, c.Expect)
		}
		switch c.Case {
		case "plaintext_frame_with_nonzero_seq":
			if err := CheckFrameClass(c.Header.Seq, true); err != ErrPlaintextNonzeroSeq {
				t.Errorf("v17 %s: want ErrPlaintextNonzeroSeq, got %v", c.Case, err)
			}
		case "aead_frame_with_seq_zero":
			// Rejected BEFORE any decrypt attempt.
			if err := CheckFrameClass(c.Header.Seq, false); err != ErrAEADSeqZero {
				t.Errorf("v17 %s: want ErrAEADSeqZero, got %v", c.Case, err)
			}
		default:
			t.Fatalf("v17: unknown rejection %q", c.Case)
		}
		tl.negatives++
	}
}
