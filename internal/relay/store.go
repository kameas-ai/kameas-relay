package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------
// The six persistence classes of relay-api.md §8 — exhaustive.
//
// "The relay persists EXACTLY these six classes. Anything else is a §XII
// condition-4 defect." The Store interface below is deliberately shaped so
// that adding a seventh class requires adding a method, which requires a
// review, which is where the NFR-3 threat-model obligation bites.
// ---------------------------------------------------------------------

// Binding is §8 row 2 — the host account binding created by
// trust-on-first-use on a successful /v1/host attach (§2.2). It outlives
// every pairing, which is why it is its own record rather than a column on
// a routing registration: a threat model that cannot see it cannot reason
// about the TOFU residual.
type Binding struct {
	HostID       string
	AccountSub   string
	BoundAt      time.Time
	LastAttachAt time.Time
}

// Pairing is §8 row 1 — a routing registration. HostLabel is the optional
// operator-authored push label; it is folded in here rather than made a
// seventh class so the budget stays exhaustive, and the NFR-3 threat model
// names it explicitly as operator plaintext the relay holds.
type Pairing struct {
	PairingID  string
	ChannelID  string
	HostID     string
	DeviceID   string
	AccountSub string
	HostLabel  *string
	CreatedAt  time.Time
}

// Window is §8 row 6 — an ephemeral pairing window, TTL ≤ 5 minutes (§3.1).
// Attaches counts pairing attaches for the §7.1 flood guard; it dies with
// the window and is never durable per-operator state.
type Window struct {
	WindowID           string
	HostID             string
	ProvisionalChannel string
	ExpiresAt          time.Time
	Attaches           int
}

// MailboxItem is one row of §8 row 5 — the ciphertext mailbox.
//
// Body is ONE OPAQUE BLOB. The relay MUST NOT split, offset into, or
// otherwise structure it (§4, §10): the class-M layout is
// nonce(24) ‖ ciphertext and the RECEIVER performs that split. A store that
// kept nonce and ciphertext in separate columns would have taken a
// dependency on the AEAD's layout — harmless today, a relay code change the
// day the construction moves.
type MailboxItem struct {
	Seq       uint64
	PushClass string
	Body      []byte
	StoredAt  time.Time
}

// MailboxPolicy carries the §4 TTL and caps. Defaults may be tuned DOWNWARD
// by config; raising them needs a CONTRACTS.md revision, because "short TTL,
// bounded" is the constitutional constraint.
type MailboxPolicy struct {
	TTL       time.Duration
	MaxFrames int
	MaxBytes  int64
}

// APNSToken is §8 row 4. There is deliberately no `categories` field: the
// relay does not know a frame's notification category (§5.3) and cannot
// enforce a subscription it has no category for. Storing unenforceable
// state is the worst of both.
type APNSToken struct {
	DeviceID string
	Token    string
	Env      string // "sandbox" | "production"
}

// HostPresence and DevicePresence are the two halves of §8 row 3 — live +
// last-seen only, never a history.
type HostPresence struct {
	HostID   string
	Online   bool
	LastSeen time.Time
}

type DevicePresence struct {
	ChannelID string
	Attached  bool
	LastSeen  time.Time
}

// Store errors. These are control-flow signals, not diagnostics: the
// handler maps them onto the closed §7.2 error set and never surfaces the
// underlying text.
var (
	// ErrChannelRegistered is §7.2 `conflict` — channel_id already
	// registered (§3.4).
	ErrChannelRegistered = errors.New("channel_id already registered")
	// ErrBoundToOtherAccount is §7.2 `forbidden` — the §2.2 binding is
	// immutable, so an attach presenting a different sub is refused. The
	// relay MUST NOT rebind, merge, or prompt.
	ErrBoundToOtherAccount = errors.New("host_id is bound to a different account")
)

// Store is the relay's ENTIRE persistence surface.
//
// # Why an interface
//
// MemStore is the only implementation today and is adequate for LLE: every
// class above is ephemeral or short-TTL by contract. The interface exists so
// a durable implementation can land later without touching the router, and
// so the exhaustive §8 budget is legible as a type rather than as a
// convention.
//
// # Restart semantics, stated rather than discovered
//
// With MemStore, a relay restart drops everything. Each class degrades
// safely, and the contract already handles every case:
//
//   - Mailbox — buffered frames are lost. The device's forward-only drain
//     regime and the mandatory snapshot.full reconcile handle seq gaps by
//     design (§4, e2e-envelope.md §4): eviction and TTL expiry already
//     produce gaps, so a restart is indistinguishable from a heavy eviction.
//     Cost is one snapshot.
//   - Presence — rebuilt on the next heartbeat, and the relay publishes
//     current state once on attach (§6, §6.1). Bounded by the 15s/30s
//     cadence.
//   - Pairing windows — a window is ≤5 min and human-gated; the operator
//     shows another QR. Nothing cryptographic is lost, because the relay
//     holds nothing cryptographic.
//   - Rate-limit counters — in-memory by contract (§8) and intentionally
//     not durable.
//   - Routing registrations and host bindings — THESE ARE THE REAL COST.
//     Losing them means every paired device is refused (`forbidden` /
//     `not_found`) until the host re-registers, and a lost binding re-opens
//     the TOFU window of §2.2. This is the reason a durable Store is a
//     prerequisite for anything past LLE, and it is why those two classes
//     would be the first (and possibly only) ones to move.
//
// All methods take a context so a durable implementation can honour
// deadlines and cancellation. MemStore ignores it apart from cancellation
// checks it does not need.
type Store interface {
	// --- §8 row 2: host account binding (§2.2) ---

	// BindHost implements trust-on-first-use. It creates the binding if
	// hostID is unbound (or has been reaped), refreshes LastAttachAt if it
	// is already bound to sub, and returns ErrBoundToOtherAccount otherwise.
	// It is called ONLY from a successful /v1/host attach — a device attach
	// must never create or modify a binding (§3.2).
	BindHost(ctx context.Context, hostID, sub string, now time.Time) (Binding, error)
	// LookupBinding returns the binding for hostID, applying the idle
	// reaper first (no pairings + idle horizon ⇒ deleted, so a regenerated
	// or mistyped host_id cannot squat forever).
	LookupBinding(ctx context.Context, hostID string, now time.Time) (Binding, bool, error)
	// TouchBinding refreshes LastAttachAt so the idle horizon runs from
	// last activity rather than from first bind.
	TouchBinding(ctx context.Context, hostID string, now time.Time) error

	// --- §8 row 1: routing registration (§3.4) ---

	// CreatePairing registers a pairing, returning ErrChannelRegistered if
	// the host-generated channel_id is already taken.
	CreatePairing(ctx context.Context, p Pairing) error
	LookupPairing(ctx context.Context, pairingID string) (Pairing, bool, error)
	PairingByChannel(ctx context.Context, channelID string) (Pairing, bool, error)
	PairingsForHost(ctx context.Context, hostID string) ([]Pairing, error)
	PairingsForDevice(ctx context.Context, deviceID string) ([]Pairing, error)
	// SetHostLabel updates or clears host_label. Clearing it is the §XII
	// condition-5 reduction control.
	SetHostLabel(ctx context.Context, pairingID string, label *string) error
	// DeletePairing removes a registration and returns what it removed so
	// the caller can cascade (mailbox, device presence, APNs token).
	// Deregistration is metadata defense in depth only: real revocation is
	// the host deleting the device record, after which the pairing root is
	// not computable and mailboxed frames are permanently undecryptable.
	DeletePairing(ctx context.Context, pairingID string) (Pairing, bool, error)

	// --- §8 row 6: pairing window (§3.1) ---

	// OpenWindow inserts w and atomically invalidates any window already
	// open for w.HostID — at most one per host_id, because two live windows
	// mean two provisional channels and an ambiguous AD. The displaced
	// window is returned so the caller can close its attaches with 4410.
	OpenWindow(ctx context.Context, w Window) (displaced *Window, err error)
	LookupWindow(ctx context.Context, windowID string) (Window, bool, error)
	// WindowForHost returns the single open, unexpired window for hostID.
	WindowForHost(ctx context.Context, hostID string, now time.Time) (Window, bool, error)
	// CountWindowAttach increments the window's pairing-attach counter and
	// reports whether the attach is within max (0 disables the guard).
	// Refusal is `window_closed` like every other refusal on that path — a
	// distinguishable rate_limited would re-open the window-existence
	// oracle (§3.3).
	CountWindowAttach(ctx context.Context, windowID string, max int) (bool, error)
	DeleteWindow(ctx context.Context, windowID string) (Window, bool, error)

	// --- §8 row 5: ciphertext mailbox (§4) ---

	// AppendMailbox buffers one host→device frame, pruning by TTL and then
	// evicting oldest until both caps hold. Eviction and TTL expiry produce
	// seq gaps; that is expected and correct, and the relay never
	// retransmits, reorders, or gap-repairs.
	AppendMailbox(ctx context.Context, channelID string, it MailboxItem, pol MailboxPolicy) error
	// FetchMailbox returns up to limit items with Seq > after, in arrival
	// order. Reads are NON-DESTRUCTIVE: items expire by TTL or cap eviction
	// only, never by having been fetched, because the app and its
	// Notification Service Extension both fetch the same item.
	FetchMailbox(ctx context.Context, channelID string, after uint64, limit int, now time.Time, ttl time.Duration) (items []MailboxItem, nextAfter uint64, truncated bool, err error)
	DropMailbox(ctx context.Context, channelID string) error

	// --- §8 row 4: APNs token (§5.1) ---

	PutAPNSToken(ctx context.Context, tok APNSToken) error
	LookupAPNSToken(ctx context.Context, deviceID string) (APNSToken, bool, error)
	DeleteAPNSToken(ctx context.Context, deviceID string) error

	// --- §8 row 3: presence (§6, §6.1) ---

	PutHostPresence(ctx context.Context, p HostPresence) error
	LookupHostPresence(ctx context.Context, hostID string) (HostPresence, bool, error)
	PutDevicePresence(ctx context.Context, p DevicePresence) error
	LookupDevicePresence(ctx context.Context, channelID string) (DevicePresence, bool, error)
}

// ---------------------------------------------------------------------
// MemStore
// ---------------------------------------------------------------------

// MemStore is the in-memory Store. See the Store doc for restart semantics.
type MemStore struct {
	// idleReap is the §2.2 horizon: a binding with zero pairings and no
	// attach for this long is deleted.
	idleReap time.Duration

	mu        sync.Mutex
	bindings  map[string]Binding
	pairings  map[string]Pairing // pairing_id -> pairing
	byChannel map[string]string  // channel_id -> pairing_id
	windows   map[string]Window  // window_id -> window
	winByHost map[string]string  // host_id -> window_id (at most one, §3.1)
	mailboxes map[string]*mailbox
	apns      map[string]APNSToken
	hostPres  map[string]HostPresence
	devPres   map[string]DevicePresence
}

// NewMemStore returns an empty MemStore. idleReap is the §2.2 binding
// reaper horizon (contract: 30 days).
func NewMemStore(idleReap time.Duration) *MemStore {
	if idleReap <= 0 {
		idleReap = DefaultBindingIdleReap
	}
	return &MemStore{
		idleReap:  idleReap,
		bindings:  make(map[string]Binding),
		pairings:  make(map[string]Pairing),
		byChannel: make(map[string]string),
		windows:   make(map[string]Window),
		winByHost: make(map[string]string),
		mailboxes: make(map[string]*mailbox),
		apns:      make(map[string]APNSToken),
		hostPres:  make(map[string]HostPresence),
		devPres:   make(map[string]DevicePresence),
	}
}

var _ Store = (*MemStore)(nil)

// hostHasPairingsLocked reports whether any registration references hostID.
func (s *MemStore) hostHasPairingsLocked(hostID string) bool {
	for _, p := range s.pairings {
		if p.HostID == hostID {
			return true
		}
	}
	return false
}

// bindingLocked applies the §2.2 reaper lazily and returns the survivor.
func (s *MemStore) bindingLocked(hostID string, now time.Time) (Binding, bool) {
	b, ok := s.bindings[hostID]
	if !ok {
		return Binding{}, false
	}
	if !s.hostHasPairingsLocked(hostID) && now.Sub(b.LastAttachAt) >= s.idleReap {
		delete(s.bindings, hostID)
		return Binding{}, false
	}
	return b, true
}

func (s *MemStore) BindHost(_ context.Context, hostID, sub string, now time.Time) (Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.bindingLocked(hostID, now); ok {
		if b.AccountSub != sub {
			return Binding{}, ErrBoundToOtherAccount
		}
		b.LastAttachAt = now
		s.bindings[hostID] = b
		return b, nil
	}
	b := Binding{HostID: hostID, AccountSub: sub, BoundAt: now, LastAttachAt: now}
	s.bindings[hostID] = b
	return b, nil
}

func (s *MemStore) LookupBinding(_ context.Context, hostID string, now time.Time) (Binding, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bindingLocked(hostID, now)
	return b, ok, nil
}

func (s *MemStore) TouchBinding(_ context.Context, hostID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.bindings[hostID]; ok {
		b.LastAttachAt = now
		s.bindings[hostID] = b
	}
	return nil
}

func (s *MemStore) CreatePairing(_ context.Context, p Pairing) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.byChannel[p.ChannelID]; taken {
		return ErrChannelRegistered
	}
	s.pairings[p.PairingID] = p
	s.byChannel[p.ChannelID] = p.PairingID
	return nil
}

func (s *MemStore) LookupPairing(_ context.Context, pairingID string) (Pairing, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pairings[pairingID]
	return p, ok, nil
}

func (s *MemStore) PairingByChannel(_ context.Context, channelID string) (Pairing, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byChannel[channelID]
	if !ok {
		return Pairing{}, false, nil
	}
	p, ok := s.pairings[id]
	return p, ok, nil
}

func (s *MemStore) PairingsForHost(_ context.Context, hostID string) ([]Pairing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Pairing
	for _, p := range s.pairings {
		if p.HostID == hostID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *MemStore) PairingsForDevice(_ context.Context, deviceID string) ([]Pairing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Pairing
	for _, p := range s.pairings {
		if p.DeviceID == deviceID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *MemStore) SetHostLabel(_ context.Context, pairingID string, label *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pairings[pairingID]
	if !ok {
		return nil
	}
	p.HostLabel = label
	s.pairings[pairingID] = p
	return nil
}

func (s *MemStore) DeletePairing(_ context.Context, pairingID string) (Pairing, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pairings[pairingID]
	if !ok {
		return Pairing{}, false, nil
	}
	delete(s.pairings, pairingID)
	delete(s.byChannel, p.ChannelID)
	delete(s.mailboxes, p.ChannelID)
	delete(s.devPres, p.ChannelID)
	// §8: an APNs token is retained "until re-registration or pairing
	// deletion" — drop it unless another pairing still references the
	// device.
	still := false
	for _, other := range s.pairings {
		if other.DeviceID == p.DeviceID {
			still = true
			break
		}
	}
	if !still {
		delete(s.apns, p.DeviceID)
	}
	return p, true, nil
}

func (s *MemStore) OpenWindow(_ context.Context, w Window) (*Window, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var displaced *Window
	if oldID, ok := s.winByHost[w.HostID]; ok {
		if old, ok := s.windows[oldID]; ok {
			cp := old
			displaced = &cp
			delete(s.windows, oldID)
		}
		delete(s.winByHost, w.HostID)
	}
	s.windows[w.WindowID] = w
	s.winByHost[w.HostID] = w.WindowID
	return displaced, nil
}

func (s *MemStore) LookupWindow(_ context.Context, windowID string) (Window, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.windows[windowID]
	return w, ok, nil
}

func (s *MemStore) WindowForHost(_ context.Context, hostID string, now time.Time) (Window, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.winByHost[hostID]
	if !ok {
		return Window{}, false, nil
	}
	w, ok := s.windows[id]
	if !ok {
		return Window{}, false, nil
	}
	if !now.Before(w.ExpiresAt) {
		// Server-side expiry (§3.1); the relay MUST NOT extend on activity.
		delete(s.windows, id)
		delete(s.winByHost, hostID)
		return Window{}, false, nil
	}
	return w, true, nil
}

func (s *MemStore) CountWindowAttach(_ context.Context, windowID string, max int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.windows[windowID]
	if !ok {
		return false, nil
	}
	if max > 0 && w.Attaches >= max {
		return false, nil
	}
	w.Attaches++
	s.windows[windowID] = w
	return true, nil
}

func (s *MemStore) DeleteWindow(_ context.Context, windowID string) (Window, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.windows[windowID]
	if !ok {
		return Window{}, false, nil
	}
	delete(s.windows, windowID)
	if s.winByHost[w.HostID] == windowID {
		delete(s.winByHost, w.HostID)
	}
	return w, true, nil
}

func (s *MemStore) AppendMailbox(_ context.Context, channelID string, it MailboxItem, pol MailboxPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mb, ok := s.mailboxes[channelID]
	if !ok {
		mb = &mailbox{}
		s.mailboxes[channelID] = mb
	}
	mb.append(it, pol)
	return nil
}

func (s *MemStore) FetchMailbox(_ context.Context, channelID string, after uint64, limit int, now time.Time, ttl time.Duration) ([]MailboxItem, uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mb, ok := s.mailboxes[channelID]
	if !ok {
		return nil, after, false, nil
	}
	items, next, trunc := mb.fetch(after, limit, now, ttl)
	return items, next, trunc, nil
}

func (s *MemStore) DropMailbox(_ context.Context, channelID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.mailboxes, channelID)
	return nil
}

func (s *MemStore) PutAPNSToken(_ context.Context, tok APNSToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apns[tok.DeviceID] = tok
	return nil
}

func (s *MemStore) LookupAPNSToken(_ context.Context, deviceID string) (APNSToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.apns[deviceID]
	return t, ok, nil
}

func (s *MemStore) DeleteAPNSToken(_ context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.apns, deviceID)
	return nil
}

func (s *MemStore) PutHostPresence(_ context.Context, p HostPresence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostPres[p.HostID] = p
	return nil
}

func (s *MemStore) LookupHostPresence(_ context.Context, hostID string) (HostPresence, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.hostPres[hostID]
	return p, ok, nil
}

func (s *MemStore) PutDevicePresence(_ context.Context, p DevicePresence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devPres[p.ChannelID] = p
	return nil
}

func (s *MemStore) LookupDevicePresence(_ context.Context, channelID string) (DevicePresence, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.devPres[channelID]
	return p, ok, nil
}

// AuditRecord is one stored record rendered for the SC-2 walk.
//
// Raw carries byte fields VERBATIM rather than through JSON, because a
// canary hidden in a mailbox body would be base64-encoded by JSON and a
// substring search over the encoded form would miss it. An audit that can
// be defeated by an encoding is not an audit.
type AuditRecord struct {
	Class string   // the §8 persistence class
	JSON  []byte   // the record, JSON-encoded
	Raw   [][]byte // raw byte fields, unencoded
}

// AuditRecords returns EVERY record the store holds, for the SC-2
// no-plaintext property test (sc2/noplaintext_test.go) to walk.
//
// This is a GO API, not an HTTP surface: relay-api.md §7.3 forbids the
// health endpoints from enumerating channels, devices, hosts, or counts
// thereof, and nothing here is reachable over the network. It exists so the
// behavioural half of the §XII condition-2 proof can assert over the REAL
// storage rather than over a reconstruction of it — an audit that walks a
// summary proves nothing about what the summary omitted.
//
// Mailbox bodies are included deliberately: they are precisely what the
// test must confirm is ciphertext.
func (s *MemStore) AuditRecords() []AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []AuditRecord
	add := func(class string, v any, raw ...[]byte) {
		blob, err := json.Marshal(v)
		if err != nil {
			blob = []byte(fmt.Sprintf("%+v", v))
		}
		out = append(out, AuditRecord{Class: class, JSON: blob, Raw: raw})
	}
	for _, b := range s.bindings {
		add("host_account_binding", b)
	}
	for _, p := range s.pairings {
		add("routing_registration", p)
	}
	for _, w := range s.windows {
		add("pairing_window", w)
	}
	for ch, mb := range s.mailboxes {
		for _, it := range mb.items {
			add("ciphertext_mailbox", struct {
				ChannelID string
				Seq       uint64
				PushClass string
				BodyLen   int
				StoredAt  time.Time
			}{ch, it.Seq, it.PushClass, len(it.Body), it.StoredAt}, it.Body)
		}
	}
	for _, t := range s.apns {
		add("apns_token", t)
	}
	for _, p := range s.hostPres {
		add("presence_host", p)
	}
	for _, p := range s.devPres {
		add("presence_device", p)
	}
	return out
}

// ---------------------------------------------------------------------
// mailbox — the per-channel ciphertext buffer (§4)
// ---------------------------------------------------------------------

type mailbox struct {
	items []MailboxItem
	bytes int64
}

func (m *mailbox) append(it MailboxItem, pol MailboxPolicy) {
	m.prune(it.StoredAt, pol.TTL)
	m.items = append(m.items, it)
	m.bytes += int64(len(it.Body))
	for len(m.items) > 0 && (len(m.items) > pol.MaxFrames || m.bytes > pol.MaxBytes) {
		m.bytes -= int64(len(m.items[0].Body))
		m.items[0] = MailboxItem{}
		m.items = m.items[1:]
	}
}

func (m *mailbox) prune(now time.Time, ttl time.Duration) {
	i := 0
	for ; i < len(m.items); i++ {
		if now.Sub(m.items[i].StoredAt) < ttl {
			break
		}
		m.bytes -= int64(len(m.items[i].Body))
	}
	m.items = m.items[i:]
}

// fetch is non-destructive by construction: it prunes only by TTL and never
// removes an item because it was read.
func (m *mailbox) fetch(after uint64, limit int, now time.Time, ttl time.Duration) ([]MailboxItem, uint64, bool) {
	m.prune(now, ttl)
	next := after
	var items []MailboxItem
	for _, it := range m.items {
		if it.Seq <= after {
			continue
		}
		if len(items) >= limit {
			return items, next, true
		}
		items = append(items, it)
		next = it.Seq
	}
	return items, next, false
}
