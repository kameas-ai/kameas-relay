package fakerelay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type mailboxResp struct {
	Frames []struct {
		Seq       uint64 `json:"seq"`
		PushClass string `json:"push_class"`
		Body      string `json:"body"`
	} `json:"frames"`
	NextAfter uint64 `json:"next_after"`
	Truncated bool   `json:"truncated"`
}

func (e *testEnv) mailboxGet(t *testing.T, query string) mailboxResp {
	t.Helper()
	status, body := e.rest("GET", "/v1/channels/"+channelA+"/frames"+query, tokAlice, nil)
	if status != http.StatusOK {
		t.Fatalf("mailbox GET: status %d body %s", status, body)
	}
	var out mailboxResp
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("mailbox decode: %v", err)
	}
	return out
}

// sendMailboxFrames pushes n host frames with no device attached (⇒ all
// mailboxed). Bodies are nonce(24B) ‖ ct as class-M frames are on the
// wire. Returns after the last frame is buffered (send is synchronous
// per connection: the relay mailboxes in the read loop, and a follow-up
// REST call observes relay state under the same mutex).
func (e *testEnv) sendMailboxFrames(t *testing.T, seqs []uint64, pushClass string) {
	t.Helper()
	host := e.dialHost(hostA, tokAlice)
	for _, s := range seqs {
		body := append(bytes.Repeat([]byte{byte(s)}, 24), []byte(fmt.Sprintf("ct-%d", s))...)
		writeFrame(t, host, frame(t, channelA, s, pushClass, body))
	}
	// The read loop is asynchronous; wait until the last seq is visible.
	waitMailboxSeq(t, e, seqs[len(seqs)-1])
	_ = host.CloseNow()
}

func waitMailboxSeq(t *testing.T, e *testEnv, seq uint64) {
	t.Helper()
	deadline := time.Now().Add(readTimeout)
	for time.Now().Before(deadline) {
		e.relay.mu.Lock()
		mb := e.relay.mailboxes[channelA]
		found := false
		if mb != nil {
			for _, it := range mb.items {
				if it.seq == seq {
					found = true
					break
				}
			}
		}
		e.relay.mu.Unlock()
		if found {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("frame seq %d never reached the mailbox", seq)
}

// TestMailboxBufferAndCatchUp: host→device frames buffered while the
// device is detached are returned by seq-filtered catch-up as ONE
// opaque body each — the relay never decomposes the nonce ‖ ciphertext
// layout; that split is the receiver's (e2e-envelope.md §1.2).
func TestMailboxBufferAndCatchUp(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)
	e.sendMailboxFrames(t, []uint64{1, 2, 3}, PushNone)

	got := e.mailboxGet(t, "?after=0")
	if len(got.Frames) != 3 || got.NextAfter != 3 || got.Truncated {
		t.Fatalf("catch-up = %+v, want 3 frames next_after=3 truncated=false", got)
	}
	for i, f := range got.Frames {
		wantSeq := uint64(i + 1)
		if f.Seq != wantSeq || f.PushClass != PushNone {
			t.Fatalf("frame %d = %+v, want seq %d push_class none", i, f, wantSeq)
		}
		body, err := b64.DecodeString(f.Body)
		if err != nil {
			t.Fatalf("frame %d body not base64url: %v", i, err)
		}
		// Exactly the bytes the host sent: 24 filler-nonce bytes ‖ ct.
		want := append(bytes.Repeat([]byte{byte(wantSeq)}, 24), []byte(fmt.Sprintf("ct-%d", wantSeq))...)
		if !bytes.Equal(body, want) {
			t.Fatalf("frame %d body was not returned verbatim", i)
		}
	}

	// after=2 returns only seq 3.
	got = e.mailboxGet(t, "?after=2")
	if len(got.Frames) != 1 || got.Frames[0].Seq != 3 {
		t.Fatalf("after=2 = %+v, want exactly seq 3", got)
	}
}

// TestMailboxReadsAreNonDestructive: fetching never consumes (§4) — the
// NSE and the app both fetch the same items.
func TestMailboxReadsAreNonDestructive(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)
	e.sendMailboxFrames(t, []uint64{1, 2}, PushNone)

	first := e.mailboxGet(t, "?after=0")
	second := e.mailboxGet(t, "?after=0") // the NSE fetched; now the app fetches
	if len(first.Frames) != 2 || len(second.Frames) != 2 {
		t.Fatalf("reads consumed items: first %d, second %d, want 2/2", len(first.Frames), len(second.Frames))
	}
	for i := range first.Frames {
		if first.Frames[i] != second.Frames[i] {
			t.Fatalf("frame %d differs across reads: %+v vs %+v", i, first.Frames[i], second.Frames[i])
		}
	}
}

// TestMailboxTTLExpiry: frames expire after the 15-minute TTL (§4).
func TestMailboxTTLExpiry(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)
	e.sendMailboxFrames(t, []uint64{1, 2}, PushNone)

	e.clock.Advance(14 * time.Minute)
	if got := e.mailboxGet(t, "?after=0"); len(got.Frames) != 2 {
		t.Fatalf("before TTL: %d frames, want 2", len(got.Frames))
	}
	e.clock.Advance(2 * time.Minute)
	got := e.mailboxGet(t, "?after=0")
	if len(got.Frames) != 0 {
		t.Fatalf("after TTL: %d frames, want 0", len(got.Frames))
	}
	if got.NextAfter != 0 {
		t.Fatalf("next_after = %d, want the caller's after (0)", got.NextAfter)
	}
}

// TestMailboxCapEvictionProducesGap: the frame cap evicts oldest, and a
// catch-up after eviction returns a seq GAP — expected and correct (§4);
// the relay must not repair it.
func TestMailboxCapEvictionProducesGap(t *testing.T) {
	e := newTestEnv(t, Config{MailboxMaxFrames: 4})
	e.createPairing(nil)
	e.sendMailboxFrames(t, []uint64{1, 2, 3, 4, 5, 6}, PushNone)

	got := e.mailboxGet(t, "?after=0")
	var seqs []uint64
	for _, f := range got.Frames {
		seqs = append(seqs, f.Seq)
	}
	want := []uint64{3, 4, 5, 6}
	if len(seqs) != len(want) {
		t.Fatalf("post-eviction seqs = %v, want %v", seqs, want)
	}
	for i := range want {
		if seqs[i] != want[i] {
			t.Fatalf("post-eviction seqs = %v, want %v (gap after eviction is the contract)", seqs, want)
		}
	}

	// A device that last saw seq 1 now observes the gap: catch-up from 1
	// starts at 3. The gap is not an error and nothing fills it.
	got = e.mailboxGet(t, "?after=1")
	if len(got.Frames) == 0 || got.Frames[0].Seq != 3 {
		t.Fatalf("catch-up from 1 = %+v, want first seq 3 (gap by design)", got)
	}
}

// TestMailboxByteCapEviction: the 4 MiB byte cap binds independently of
// the frame cap, whichever binds first (§4).
func TestMailboxByteCapEviction(t *testing.T) {
	e := newTestEnv(t, Config{MailboxMaxBytes: 100})
	e.createPairing(nil)
	// Each body is 24 nonce + 4..5 ct ≈ 28-29 bytes ⇒ only 3 fit in 100.
	e.sendMailboxFrames(t, []uint64{1, 2, 3, 4}, PushNone)
	got := e.mailboxGet(t, "?after=0")
	if len(got.Frames) != 3 || got.Frames[0].Seq != 2 {
		t.Fatalf("byte-cap eviction = %+v, want seqs 2..4", got)
	}
}

// TestMailboxLimitAndTruncated: limit paging with truncated:true and
// next_after re-fetch (§4: default 64, max 256).
func TestMailboxLimitAndTruncated(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)
	e.sendMailboxFrames(t, []uint64{1, 2, 3, 4, 5}, PushNone)

	got := e.mailboxGet(t, "?after=0&limit=2")
	if len(got.Frames) != 2 || !got.Truncated || got.NextAfter != 2 {
		t.Fatalf("page 1 = %+v, want 2 frames truncated=true next_after=2", got)
	}
	got = e.mailboxGet(t, fmt.Sprintf("?after=%d&limit=2", got.NextAfter))
	if len(got.Frames) != 2 || !got.Truncated || got.NextAfter != 4 {
		t.Fatalf("page 2 = %+v, want seqs 3,4 truncated=true", got)
	}
	got = e.mailboxGet(t, fmt.Sprintf("?after=%d&limit=2", got.NextAfter))
	if len(got.Frames) != 1 || got.Truncated || got.NextAfter != 5 {
		t.Fatalf("page 3 = %+v, want seq 5 truncated=false", got)
	}
}

// TestMailboxSkippedWhenDeviceAttached: a live attachment means frames
// forward instead of buffering (§5.2's "no live WSS attachment" is also
// the mailbox condition).
func TestMailboxSkippedWhenDeviceAttached(t *testing.T) {
	e := newTestEnv(t, Config{})
	e.createPairing(nil)
	host := e.dialHost(hostA, tokAlice)
	device := e.dialDevice(channelA, tokAlice)
	readPresence(t, device)

	writeFrame(t, host, frame(t, channelA, 1, PushNone, nil))
	readMessage(t, device, websocket.MessageBinary)

	if got := e.mailboxGet(t, "?after=0"); len(got.Frames) != 0 {
		t.Fatalf("mailbox has %d frames despite live attachment, want 0", len(got.Frames))
	}
}
