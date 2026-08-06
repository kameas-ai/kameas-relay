package e2ekit

import (
	"errors"
	"testing"
)

func TestCheckFrameClass(t *testing.T) {
	cases := []struct {
		name      string
		seq       uint64
		plaintext bool
		wantErr   error
	}{
		{"plaintext at 0", 0, true, nil},
		{"plaintext at 1", 1, true, ErrPlaintextNonzeroSeq},
		{"plaintext at 7", 7, true, ErrPlaintextNonzeroSeq},
		{"aead at 0", 0, false, ErrAEADSeqZero},
		{"aead at 1", 1, false, nil},
		{"aead at max", ^uint64(0), false, nil},
	}
	for _, c := range cases {
		if err := CheckFrameClass(c.seq, c.plaintext); !errors.Is(err, c.wantErr) {
			t.Errorf("%s: got %v want %v", c.name, err, c.wantErr)
		}
	}
}

func TestSeqTrackerRegimes(t *testing.T) {
	type step struct {
		op            string // "accept" | "start" | "mailbox"
		seq           uint64
		wantReconcile bool
		wantErr       error
	}
	cases := []struct {
		name  string
		start uint64
		steps []step
	}{
		{"first pairing counters start at 1", 0, []step{
			{op: "accept", seq: 1},
			{op: "accept", seq: 2},
			{op: "accept", seq: 3},
		}},
		{"mid-session gap is fatal", 0, []step{
			{op: "accept", seq: 1},
			{op: "accept", seq: 3, wantErr: ErrSeqGap},
		}},
		{"mid-session repeat is fatal", 0, []step{
			{op: "accept", seq: 1},
			{op: "accept", seq: 1, wantErr: ErrSeqRegression},
		}},
		{"session-start forward jump mandates reconcile", 5, []step{
			{op: "accept", seq: 9, wantReconcile: true},
			{op: "accept", seq: 10},
		}},
		{"session-start exact next is not a reconcile", 5, []step{
			{op: "accept", seq: 6},
		}},
		{"session-start regression is fatal", 5, []step{
			{op: "accept", seq: 5, wantErr: ErrSeqRegression},
		}},
		{"session-start seq zero is rejected", 5, []step{
			{op: "accept", seq: 0, wantErr: ErrAEADSeqZero},
		}},
		{"reconnect re-enters session-start", 0, []step{
			{op: "accept", seq: 1},
			{op: "accept", seq: 2},
			{op: "start"},
			{op: "accept", seq: 7, wantReconcile: true}, // jump OK again
			{op: "accept", seq: 9, wantErr: ErrSeqGap},  // but mid-session after that
		}},
		{"failed accept does not move the mark", 3, []step{
			{op: "accept", seq: 2, wantErr: ErrSeqRegression},
			{op: "accept", seq: 4},
		}},
		{"mailbox drain: gaps expected, regression fatal", 2, []step{
			{op: "mailbox", seq: 3},
			{op: "mailbox", seq: 7, wantReconcile: true}, // gap => reconcile
			{op: "mailbox", seq: 7, wantErr: ErrSeqRegression},
			{op: "accept", seq: 8}, // handshake follows the drain
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := NewSeqTracker(c.start)
			for i, s := range c.steps {
				switch s.op {
				case "start":
					tr.StartSession()
				case "accept":
					rec, err := tr.Accept(s.seq)
					if !errors.Is(err, s.wantErr) || rec != s.wantReconcile {
						t.Fatalf("step %d Accept(%d): rec=%v err=%v, want rec=%v err=%v",
							i, s.seq, rec, err, s.wantReconcile, s.wantErr)
					}
				case "mailbox":
					gap, err := tr.AcceptMailbox(s.seq)
					if !errors.Is(err, s.wantErr) || gap != s.wantReconcile {
						t.Fatalf("step %d AcceptMailbox(%d): gap=%v err=%v, want gap=%v err=%v",
							i, s.seq, gap, err, s.wantReconcile, s.wantErr)
					}
				}
			}
		})
	}
}

func TestSeqTrackerMailboxAfterSessionPanics(t *testing.T) {
	tr := NewSeqTracker(0)
	if _, err := tr.Accept(1); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("AcceptMailbox after session start must panic (drain precedes the handshake)")
		}
	}()
	_, _ = tr.AcceptMailbox(2)
}
