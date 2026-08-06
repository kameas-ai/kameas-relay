package e2ekit

import (
	"errors"
	"fmt"
)

// Sequence acceptance — two regimes, deliberately not one rule
// (e2e-envelope.md §4, ADR Decision 5 / B1). seq is per direction,
// monotonic, and never resets for the lifetime of the pairing.
//
//   - Mid-session: the AD seq MUST equal exactly last_seen+1; any gap,
//     repeat, or regression is FATAL (abort, fresh nonces on reconnect).
//   - Session start (the first AEAD frame of the session in that
//     direction): seq MAY jump forward past last_seen+1 — frames were
//     lost to mailbox expiry — and a forward jump MANDATES a
//     snapshot.full reconcile. Backward or repeated seq is still fatal.
//   - Mailbox drain: forward-only with gaps EXPECTED (TTL/eviction);
//     backward or repeated seq is fatal; a gap mandates the reconcile.
//
// There is no replay window to tune: the AEAD state plus this monotonic
// high-water mark IS the replay protection. High-water-mark loss is
// fail-closed by design (N5): recovery is re-pairing, and no reset
// affordance exists here.

// Seq-regime errors. Both are fatal session aborts (§4.4).
var (
	// ErrSeqRegression covers seq <= last_seen in every regime.
	ErrSeqRegression = errors.New("e2ekit: seq regression or replay (fatal)")
	// ErrSeqGap covers a mid-session gap (seq > last_seen+1 after the
	// first AEAD frame of the session).
	ErrSeqGap = errors.New("e2ekit: mid-session seq gap (fatal)")
)

// Frame-class errors (e2e-envelope.md §1.1: seq is the only class
// discriminator, and it is structural).
var (
	// ErrPlaintextNonzeroSeq rejects a plaintext-bodied control frame
	// whose seq != 0.
	ErrPlaintextNonzeroSeq = errors.New("e2ekit: plaintext control frame with seq != 0 (seq 0 is a reserved sentinel)")
	// ErrAEADSeqZero rejects an AEAD frame whose seq == 0, BEFORE any
	// decrypt attempt.
	ErrAEADSeqZero = errors.New("e2ekit: AEAD frame with seq == 0 (structurally disjoint from the AEAD sequence)")
)

// CheckFrameClass enforces the structural plaintext/AEAD disjunction: a
// relay cannot promote a plaintext frame into the authenticated sequence
// nor demote an AEAD frame out of it. Vector V17 pins both rejections.
func CheckFrameClass(seq uint64, plaintextBody bool) error {
	if plaintextBody && seq != 0 {
		return ErrPlaintextNonzeroSeq
	}
	if !plaintextBody && seq == 0 {
		return ErrAEADSeqZero
	}
	return nil
}

// SeqTracker is one direction's receive-side high-water mark plus the
// session-start/mid-session regime switch.
type SeqTracker struct {
	lastSeen  uint64
	inSession bool
}

// NewSeqTracker starts a tracker at a persisted high-water mark
// (0 at first pairing). The tracker begins in the session-start regime.
func NewSeqTracker(lastSeen uint64) *SeqTracker {
	return &SeqTracker{lastSeen: lastSeen}
}

// LastSeen returns the current high-water mark (persist it).
func (t *SeqTracker) LastSeen() uint64 { return t.lastSeen }

// StartSession re-enters the session-start regime (call on every
// reconnect, before the first AEAD frame of the new session).
func (t *SeqTracker) StartSession() { t.inSession = false }

// Accept validates one received AEAD-frame seq. reconcile is true when a
// session-start forward jump occurred — the receiver MUST treat cached
// state as stale and expect snapshot.full. A non-nil error is a fatal
// session abort; the tracker state is unchanged on error.
func (t *SeqTracker) Accept(seq uint64) (reconcile bool, err error) {
	if err := CheckFrameClass(seq, false); err != nil {
		return false, err
	}
	if seq <= t.lastSeen {
		return false, fmt.Errorf("%w: seq %d <= last_seen %d", ErrSeqRegression, seq, t.lastSeen)
	}
	if !t.inSession {
		reconcile = seq > t.lastSeen+1
		t.lastSeen = seq
		t.inSession = true
		return reconcile, nil
	}
	if seq != t.lastSeen+1 {
		return false, fmt.Errorf("%w: seq %d, want exactly %d", ErrSeqGap, seq, t.lastSeen+1)
	}
	t.lastSeen = seq
	return false, nil
}

// AcceptMailbox validates one mailbox-drain seq (forward-only, gaps
// expected and non-fatal). gap reports whether frames were lost, which
// mandates expecting snapshot.full. Drain runs before the handshake, so
// calling it mid-session is a programming error and panics.
func (t *SeqTracker) AcceptMailbox(seq uint64) (gap bool, err error) {
	if t.inSession {
		panic("e2ekit: mailbox drain after session start")
	}
	if seq == 0 {
		return false, ErrAEADSeqZero
	}
	if seq <= t.lastSeen {
		return false, fmt.Errorf("%w: mailbox seq %d <= last_seen %d", ErrSeqRegression, seq, t.lastSeen)
	}
	gap = seq > t.lastSeen+1
	t.lastSeen = seq
	return gap, nil
}
