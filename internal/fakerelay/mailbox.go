package fakerelay

import "time"

// mailbox is the per-channel ciphertext buffer (relay-api.md §4):
// host→device only, TTL'd, capped at N frames / M bytes (whichever binds
// first, evicting oldest). Eviction and TTL expiry produce seq gaps —
// that is expected and correct; the relay never retransmits, repairs, or
// reorders.
type mailbox struct {
	items []mbxItem
	bytes int64
}

type mbxItem struct {
	seq       uint64
	pushClass string
	body      []byte // opaque: never parsed, split only at the fixed 24-byte nonce boundary on read-out
	at        time.Time
}

// append stores one frame, pruning expired items first and then evicting
// oldest until both caps hold. Caller holds r.mu.
func (m *mailbox) append(it mbxItem, now time.Time, ttl time.Duration, maxFrames int, maxBytes int64) {
	m.prune(now, ttl)
	m.items = append(m.items, it)
	m.bytes += int64(len(it.body))
	for len(m.items) > 0 && (len(m.items) > maxFrames || m.bytes > maxBytes) {
		m.bytes -= int64(len(m.items[0].body))
		m.items[0] = mbxItem{}
		m.items = m.items[1:]
	}
}

// prune drops items older than ttl. Caller holds r.mu.
func (m *mailbox) prune(now time.Time, ttl time.Duration) {
	i := 0
	for ; i < len(m.items); i++ {
		if now.Sub(m.items[i].at) < ttl {
			break
		}
		m.bytes -= int64(len(m.items[i].body))
	}
	m.items = m.items[i:]
}

// get returns up to limit items with seq > after, in arrival order, plus
// next_after and whether more remain. Caller holds r.mu.
func (m *mailbox) get(after uint64, limit int, now time.Time, ttl time.Duration) (items []mbxItem, nextAfter uint64, truncated bool) {
	m.prune(now, ttl)
	nextAfter = after
	for _, it := range m.items {
		if it.seq <= after {
			continue
		}
		if len(items) >= limit {
			truncated = true
			break
		}
		items = append(items, it)
		nextAfter = it.seq
	}
	return items, nextAfter, truncated
}
