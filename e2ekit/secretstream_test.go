package e2ekit

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// Round-trip smoke over random keys/messages; the byte-exactness gate is
// the golden-vector suite.
func TestStreamRoundTrip(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	push, header, err := NewPushStream(key)
	if err != nil {
		t.Fatal(err)
	}
	pull := NewPullStream(key, header)

	var channel [16]byte
	channel[0] = 0xAB
	msgs := [][]byte{
		[]byte("first"),
		bytes.Repeat([]byte("x"), 4096),
		{}, // empty message
		[]byte("closing"),
	}
	tags := []byte{TagMessage, TagMessage, TagRekey, TagFinal}
	for i, m := range msgs {
		ad := BuildAD(channel, uint64(i+1), PushClassNone)
		ct, err := push.Push(m, ad[:], tags[i])
		if err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
		if len(ct) != len(m)+StreamOverhead {
			t.Fatalf("push %d: frame length %d, want %d", i, len(ct), len(m)+StreamOverhead)
		}
		pt, tag, err := pull.Pull(ct, ad[:])
		if err != nil {
			t.Fatalf("pull %d: %v", i, err)
		}
		if !bytes.Equal(pt, m) || tag != tags[i] {
			t.Fatalf("pull %d: plaintext/tag mismatch", i)
		}
	}
	if !push.Finished() || !pull.Finished() {
		t.Error("both sides must be finished after TAG_FINAL")
	}
	if _, err := push.Push([]byte("late"), nil, TagMessage); !errors.Is(err, ErrStreamFinished) {
		t.Errorf("push after final: want ErrStreamFinished, got %v", err)
	}
	if _, _, err := pull.Pull([]byte("0123456789abcdef0"), nil); !errors.Is(err, ErrStreamFinished) {
		t.Errorf("pull after final: want ErrStreamFinished, got %v", err)
	}
}

func TestStreamFailedPullDoesNotAdvanceState(t *testing.T) {
	var key [32]byte
	push, header, err := NewPushStream(key)
	if err != nil {
		t.Fatal(err)
	}
	pull := NewPullStream(key, header)
	ad := []byte("ad")
	ct1, _ := push.Push([]byte("one"), ad, TagMessage)
	ct2, _ := push.Push([]byte("two"), ad, TagMessage)

	// A tampered frame fails…
	bad := append([]byte(nil), ct1...)
	bad[len(bad)-1] ^= 0x01
	if _, _, err := pull.Pull(bad, ad); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("tampered frame: want ErrDecryptFailed, got %v", err)
	}
	// …and the state is untouched: the genuine frames still decrypt in order.
	for i, ct := range [][]byte{ct1, ct2} {
		if _, _, err := pull.Pull(ct, ad); err != nil {
			t.Fatalf("frame %d after failed pull: %v", i, err)
		}
	}
}

func TestNewPushStreamHeadersAreRandom(t *testing.T) {
	// Headers are CSPRNG-drawn, never derived from the key (ADR §How to
	// read the vectors — deriving them would reintroduce whole-session
	// replay).
	var key [32]byte
	_, h1, err := NewPushStream(key)
	if err != nil {
		t.Fatal(err)
	}
	_, h2, err := NewPushStream(key)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("two push streams drew identical headers")
	}
}
