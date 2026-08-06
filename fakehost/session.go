package fakehost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kameas-ai/kameas-relay/e2ekit"
	"github.com/kameas-ai/kameas-relay/wire"
)

// ---------------------------------------------------------------------
// durable-channel sessions (ADR Decision 4; e2e-envelope.md §5.1)
// ---------------------------------------------------------------------

func (h *Host) handleSessionFrame(hdr wire.Header, body []byte) {
	dev := h.device
	if hdr.Seq == 0 {
		env, err := wire.ParseEnvelope(body)
		if err != nil {
			h.cfg.Logf("session: bad control envelope: %v", err)
			return
		}
		switch env.Kind {
		case "sess.hello":
			h.handleSessHello(env)
		case "sess.header":
			h.handleSessHeader(env)
		default:
			h.cfg.Logf("session: unexpected control kind %s", env.Kind)
		}
		return
	}

	// Class L.
	s := h.sess
	if s == nil || s.pull == nil {
		h.cfg.Logf("session: AEAD frame with no session (dropped)")
		return
	}
	if _, err := dev.d2h.Accept(hdr.Seq); err != nil {
		h.cfg.Logf("session: %v — fatal abort", err)
		h.abortSession()
		return
	}
	ad, err := hdr.AD()
	if err != nil {
		h.abortSession()
		return
	}
	pt, _, err := s.pull.Pull(body, ad)
	if err != nil {
		h.cfg.Logf("session: frame failed authentication — fatal abort")
		h.abortSession()
		return
	}
	env, err := wire.ParseEnvelope(pt)
	if err != nil {
		h.abortSession()
		return
	}
	switch env.Kind {
	case "sess.confirm":
		var sc wire.SessConfirm
		if err := env.DecodeBody(&sc); err != nil {
			h.abortSession()
			return
		}
		got, err := e2ekit.DecodeBin(sc.TranscriptMAC, 32)
		if err != nil || !e2ekit.VerifyMAC(s.keys.ConfD[:], got) {
			h.cfg.Logf("session: sess.confirm mismatch — fatal abort")
			h.abortSession()
			return
		}
		s.step = 3
		h.cfg.Logf("session established with %s", dev.name)
		// The host's first post-handshake envelope is snapshot.full —
		// the reconcile the session-start seq regime mandates.
		h.sendSnapshot("")
		h.startLoops()
	case "rpc.request":
		if s.step != 3 {
			return
		}
		var req wire.RPCRequest
		if err := env.DecodeBody(&req); err != nil {
			h.abortSession()
			return
		}
		h.handleRPC(env.ID, req)
	case "ack":
		// optional liveness ack; carries no state
	default:
		// Unknown kinds are rejected, not ignored (§6.2).
		h.cfg.Logf("session: unknown envelope kind %q — fatal abort", env.Kind)
		h.abortSession()
	}
}

func (h *Host) handleSessHello(env wire.Envelope) {
	dev := h.device
	var sh wire.SessHello
	if err := env.DecodeBody(&sh); err != nil {
		return
	}
	if sh.Proto != 1 {
		h.sendControl(dev.channelWire, "sess.denied", wire.SessDenied{Reason: wire.DeniedProtoUnsupported})
		return
	}
	devID, err := e2ekit.DecodeBin(sh.DeviceID, 16)
	nD, err2 := e2ekit.DecodeBin(sh.ND, 32)
	if err != nil || err2 != nil {
		return
	}
	if e2ekit.EncodeBin(devID) != e2ekit.EncodeChannelID(dev.deviceID) {
		h.sendControl(dev.channelWire, "sess.denied", wire.SessDenied{Reason: wire.DeniedUnknownDevice})
		return
	}
	// Fresh session: rotate everything derived (ADR Decision 6).
	h.abortSession()
	var nDArr, nH [32]byte
	copy(nDArr[:], nD)
	if _, err := rand.Read(nH[:]); err != nil {
		return
	}
	tr := e2ekit.V1.Transcript(h.hostID, dev.deviceID, nDArr, nH)
	keys := e2ekit.V1.SessionKeys(dev.roots, tr)
	push, hdrH2D, err := e2ekit.NewPushStream(keys.H2D)
	if err != nil {
		return
	}
	dev.d2h.StartSession()
	h.sess = &session{keys: keys, push: push, step: 1}
	h.sendControl(dev.channelWire, "sess.accept", wire.SessAccept{
		HostID: h.HostIDWire(),
		NH:     e2ekit.EncodeBin(nH[:]),
		HdrH2D: e2ekit.EncodeBin(hdrH2D[:]),
	})
}

func (h *Host) handleSessHeader(env wire.Envelope) {
	s := h.sess
	if s == nil || s.step != 1 {
		return
	}
	var sh wire.SessHeader
	if err := env.DecodeBody(&sh); err != nil {
		h.abortSession()
		return
	}
	raw, err := e2ekit.DecodeBin(sh.HdrD2H, 24)
	if err != nil {
		h.abortSession()
		return
	}
	var hd [24]byte
	copy(hd[:], raw)
	s.pull = e2ekit.NewPullStream(s.keys.D2H, hd)
	s.step = 2
	// Host's sess.confirm: first AEAD frame of the session in the h2d
	// direction; consumes the next pairing-lifetime counter value.
	h.sendEncryptedOn(s.push, &h.device.h2dSent, h.device.channelWire,
		"sess.confirm", wire.SessConfirm{TranscriptMAC: e2ekit.EncodeBin(s.keys.ConfH[:])},
		"none", e2ekit.TagMessage, "")
}

// abortSession drops the current session (fatal abort semantics: discard
// stream state; the device reconnects with fresh nonces). Caller holds h.mu.
func (h *Host) abortSession() {
	if h.sess != nil && h.sess.cancelLoops != nil {
		h.sess.cancelLoops()
	}
	h.sess = nil
}

// sendEnvelope seals a payload envelope host→device, choosing the
// construction from the relay's §6.1 device-presence signal — the
// choice is the SENDER's (relay-api.md §4.1):
//
//   - device attached + established session ⇒ class L on the session
//     stream;
//   - device detached ⇒ class M under K_mbx — the relay will mailbox it
//     regardless of push_class;
//   - device attached but no established session (mid-handshake) ⇒
//     drop; the post-handshake snapshot.full carries the state.
//
// Caller holds h.mu.
func (h *Host) sendEnvelope(kind, id string, body any, pushClass string) {
	dev := h.device
	if dev == nil {
		return
	}
	if !dev.attached {
		// transcript.page is never mailboxed (e2e-envelope §6.2):
		// transcripts are pull-only and meaningless without a live
		// request.
		if kind == "transcript.page" {
			return
		}
		h.sendMailboxEnvelope(kind, id, body, pushClass)
		return
	}
	s := h.sess
	if s == nil || s.step != 3 {
		return
	}
	h.sendEncryptedOn(s.push, &dev.h2dSent, dev.channelWire, kind, body, pushClass, e2ekit.TagMessage, id)
}

// sendMailboxEnvelope seals one envelope as a class-M frame (stateless
// XChaCha20-Poly1305 under K_mbx, nonce ‖ ct body) and sends it on the
// host WSS; with the device detached the relay buffers it (§4.1 arm 2).
// Consumes the same pairing-lifetime h2d counter as class L — seq never
// resets and the mailbox's ?after= depends on it. Caller holds h.mu.
func (h *Host) sendMailboxEnvelope(kind, id string, body any, pushClass string) {
	dev := h.device
	env, err := wire.NewPayload(kind, id, time.Now(), body)
	if err != nil {
		h.cfg.Logf("mailbox envelope %s: %v", kind, err)
		return
	}
	raw, err := env.Marshal()
	if err != nil {
		h.cfg.Logf("mailbox envelope %s: %v", kind, err)
		return
	}
	pc, err := e2ekit.ParsePushClass(pushClass)
	if err != nil {
		return
	}
	dev.h2dSent++
	seq := dev.h2dSent
	ad := e2ekit.BuildAD(dev.channel, seq, pc)
	mBody, err := e2ekit.SealMailboxFrame(dev.kMbx, raw, ad[:])
	if err != nil {
		h.cfg.Logf("mailbox seal %s: %v", kind, err)
		return
	}
	h.sendFrame(dev.channelWire, seq, pushClass, mBody)
}

// EmitEvent emits one scripted event envelope immediately, routed per
// device presence (class L live, class M into the mailbox). Control
// surface for tests and tooling.
func (h *Host) EmitEvent(ev ScriptEvent) {
	h.emitScriptEvent(ev)
}

// EmitEventClassL seals one event on the CURRENT session stream
// regardless of the §6.1 presence signal. Test instrument ONLY: it
// deterministically reproduces the presence race of relay-api.md §4.1 —
// a class-L frame landing in the mailbox, where it cannot authenticate;
// the device's recovery (discard, abandon drain, snapshot.full
// reconcile) is what tests pin with it. Returns false when no
// established session stream exists.
func (h *Host) EmitEventClassL(ev ScriptEvent) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sess
	if s == nil || s.step != 3 || h.device == nil {
		return false
	}
	body, pushClass := scriptEventBody(ev)
	h.sendEncryptedOn(s.push, &h.device.h2dSent, h.device.channelWire, "event", body, pushClass, e2ekit.TagMessage, "")
	return true
}

// ---------------------------------------------------------------------
// scripted serving: snapshot, events, approvals, transcript
// ---------------------------------------------------------------------

func (h *Host) snapshotBody() wire.SnapshotFull {
	now := time.Now()
	wbStatus := "active"
	if h.wbSuspended {
		wbStatus = "suspended"
	}
	ended := wire.TS(now.Add(-time.Minute))
	pending := make([]wire.ApprovalRequest, 0, len(h.pending))
	for _, p := range h.pending {
		pending = append(pending, p.req)
	}
	return wire.SnapshotFull{
		Host: wire.SnapshotHost{
			HostID: h.HostIDWire(), HostName: h.cfg.HostName,
			Version: "0.0.0-fake", GeneratedAt: wire.TS(now),
		},
		Workbenches: []wire.SnapshotWorkbench{
			{
				WorkbenchID: "wb-042", Name: "daily-driver", Status: wbStatus, ProfileID: "profile-dev",
				Apps:      []wire.SnapshotApp{{AppID: "harness", Name: "Harness", Surface: "web"}},
				Resources: wire.SnapshotResources{CPUPct: 12.5, MemUsedMB: 2048, MemTotalMB: 8192, DiskUsedMB: 9216, DiskTotalMB: 65536},
				UpdatedAt: wire.TS(now),
			},
			{
				WorkbenchID: "wb-043", Name: "sandbox", Status: "stopped", ProfileID: "profile-sandbox",
				Apps:      []wire.SnapshotApp{},
				Resources: wire.SnapshotResources{},
				UpdatedAt: wire.TS(now.Add(-time.Hour)),
			},
		},
		Tasks: []wire.SnapshotTask{
			{TaskID: "task-1", WorkbenchID: "wb-042", Status: "running", StartedAt: wire.TS(now.Add(-5 * time.Minute)), EndedAt: nil},
			{TaskID: "task-0", WorkbenchID: "wb-042", Status: "completed", StartedAt: wire.TS(now.Add(-2 * time.Hour)), EndedAt: &ended},
		},
		Approvals:         pending,
		ApprovalsBrokered: true,
	}
}

func (h *Host) sendSnapshot(requestID string) {
	h.sendEnvelope("snapshot.full", requestID, h.snapshotBody(), "none")
}

// startLoops starts the scripted event feed and the approval timer for
// the established session. Caller holds h.mu.
func (h *Host) startLoops() {
	s := h.sess
	ctx, cancel := context.WithCancel(context.WithoutCancel(h.runCtx))
	s.cancelLoops = cancel

	// Scripted approval.request after ApprovalAfter.
	t := time.AfterFunc(h.cfg.ApprovalAfter, func() { h.raiseApproval() })
	go func() { <-ctx.Done(); t.Stop() }()

	// Event feed: explicit script, or the built-in status-flip loop.
	if len(h.cfg.Script) > 0 {
		go func() {
			start := time.Now()
			for _, ev := range h.cfg.Script {
				d := time.Duration(ev.AfterMS)*time.Millisecond - time.Since(start)
				if d > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(d):
					}
				}
				h.emitScriptEvent(ev)
			}
		}()
		return
	}
	go func() {
		tick := time.NewTicker(h.cfg.EventInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				h.mu.Lock()
				h.wbSuspended = !h.wbSuspended
				kind := "suspended"
				if !h.wbSuspended {
					kind = "resumed"
				}
				h.mu.Unlock()
				h.emitScriptEvent(ScriptEvent{Source: "workbench", Kind: kind, WorkbenchID: "wb-042"})
			}
		}
	}()
}

// scriptEventBody maps a ScriptEvent to its wire body and push class
// (plan.md §Event→push mapping: security ⇒ attention, workbench
// lifecycle ⇒ wake, everything else ⇒ none).
func scriptEventBody(ev ScriptEvent) (wire.Event, string) {
	var wb, task *string
	if ev.WorkbenchID != "" {
		wb = &ev.WorkbenchID
	}
	if ev.TaskID != "" {
		task = &ev.TaskID
	}
	pushClass := "none"
	if ev.Source == "security" {
		pushClass = "attention"
	} else if ev.Source == "workbench" {
		pushClass = "wake"
	}
	return wire.Event{
		Source: ev.Source, Kind: ev.Kind, At: wire.TS(time.Now()),
		WorkbenchID: wb, TaskID: task, Attrs: ev.Attrs,
	}, pushClass
}

func (h *Host) emitScriptEvent(ev ScriptEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	body, pushClass := scriptEventBody(ev)
	h.sendEnvelope("event", "", body, pushClass)
}

func (h *Host) raiseApproval() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sess == nil || h.sess.step != 3 {
		return
	}
	h.approvalSeq++
	var idBytes [12]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return
	}
	id := "rid-" + hex.EncodeToString(idBytes[:])
	now := time.Now()
	req := wire.ApprovalRequest{
		ApprovalID:  id,
		TaskID:      "task-1",
		WorkbenchID: "wb-042",
		Family:      "bash",
		ActionKind:  "bash::shell::exec",
		Summary:     "run make check",
		Dangerous:   false,
		RequestedAt: wire.TS(now),
		DeadlineAt:  wire.TS(now.Add(h.cfg.ApprovalTimeout)),
		TimeoutS:    int(h.cfg.ApprovalTimeout / time.Second),
	}
	p := &pendingApproval{req: req}
	p.timer = time.AfterFunc(h.cfg.ApprovalTimeout, func() {
		// Fail-closed: absence of consent is denial.
		h.mu.Lock()
		defer h.mu.Unlock()
		h.resolveApproval(id, "deny", "timeout", "")
	})
	h.pending[id] = p
	h.sendEnvelope("approval.request", "", req, "attention")
}

// resolveApproval applies first-decision-wins resolution. Returns the
// resolved record and whether this call performed the resolution.
// Caller holds h.mu.
func (h *Host) resolveApproval(id, decision, source, deviceID string) (wire.ApprovalResolved, bool) {
	if res, done := h.resolved[id]; done {
		return res, false
	}
	p, ok := h.pending[id]
	if !ok {
		return wire.ApprovalResolved{}, false
	}
	p.timer.Stop()
	delete(h.pending, id)
	reqAt, _ := time.Parse("2006-01-02T15:04:05.000Z", p.req.RequestedAt)
	res := wire.ApprovalResolved{
		ApprovalID: id,
		TaskID:     p.req.TaskID,
		Decision:   decision,
		Source:     source,
		ResolvedAt: wire.TS(time.Now()),
		LatencyMS:  time.Since(reqAt).Milliseconds(),
	}
	h.resolved[id] = res
	// Fan out to every attached device — including the winner.
	h.sendEnvelope("approval.resolved", "", res, "attention")
	// Ledger (approval-events.md §6): device_id present iff source is
	// remote; summary is NEVER written.
	ledgerKind := "approval.denied"
	if decision == "allow_once" || decision == "allow_always" {
		ledgerKind = "approval.granted"
	}
	rec := map[string]any{
		"kind":        ledgerKind,
		"approval_id": id,
		"task_id":     p.req.TaskID,
		"workbench_id": p.req.
			WorkbenchID,
		"family":      p.req.Family,
		"action_kind": p.req.ActionKind,
		"source":      source,
		"latency_ms":  res.LatencyMS,
	}
	if source == "remote" && deviceID != "" {
		rec["device_id"] = deviceID
	}
	h.ledger(rec)
	return res, true
}

func (h *Host) ledger(rec map[string]any) {
	raw, err := json.Marshal(rec)
	if err != nil {
		return
	}
	fmt.Fprintln(h.cfg.Out, string(raw))
}

// ---------------------------------------------------------------------
// RPC surface (remote-rpc.md — the subset the tooling exercises)
// ---------------------------------------------------------------------

func (h *Host) rpcError(id, code string, retryable bool) {
	h.sendEnvelope("rpc.response", id, wire.RPCErrorBody{Error: wire.RPCError{Code: code, Retryable: retryable}}, "none")
}

// ledgerCommand writes the FR-14 remote.command record BEFORE the reply.
// Caller holds h.mu.
func (h *Host) ledgerCommand(method, result, reason string) {
	rec := map[string]any{
		"kind":      "remote.command",
		"method":    method,
		"device_id": e2ekit.EncodeChannelID(h.device.deviceID),
		"result":    result,
	}
	if reason != "" {
		rec["reason"] = reason
	}
	h.ledger(rec)
}

func (h *Host) handleRPC(id string, req wire.RPCRequest) {
	type decideParams struct {
		ApprovalID string `json:"approval_id"`
		Decision   string `json:"decision"`
	}
	type transcriptParams struct {
		TaskID   string `json:"task_id"`
		Cursor   string `json:"cursor,omitempty"`
		MaxBytes int    `json:"max_bytes,omitempty"`
	}
	// Strict, closed param parsing (remote-rpc.md §1): unknown fields
	// reject.
	strict := func(out any) bool {
		if req.Params == nil {
			return true
		}
		dec := json.NewDecoder(bytes.NewReader(req.Params))
		dec.DisallowUnknownFields()
		return dec.Decode(out) == nil
	}

	switch req.Method {
	case "snapshot.request":
		h.ledgerCommand(req.Method, "accepted", "")
		h.sendSnapshot(id)

	case "approval.decide":
		var p decideParams
		if !strict(&p) || p.ApprovalID == "" {
			h.ledgerCommand(req.Method, "rejected", "invalid_params")
			h.rpcError(id, "invalid_params", false)
			return
		}
		// The remote surface is two-valued; allow_always MUST be refused.
		if p.Decision != "allow" && p.Decision != "deny" {
			h.ledgerCommand(req.Method, "rejected", "invalid_params")
			h.rpcError(id, "invalid_params", false)
			return
		}
		decision := "deny"
		if p.Decision == "allow" {
			decision = "allow_once" // remote allow maps to allow_once, never allow_always
		}
		devID := e2ekit.EncodeChannelID(h.device.deviceID)
		if res, applied := h.resolveApproval(p.ApprovalID, decision, "remote", devID); applied {
			h.ledgerCommand(req.Method, "accepted", "")
			h.sendEnvelope("rpc.response", id, map[string]any{
				"approval_id": p.ApprovalID, "status": "applied",
				"decision": res.Decision, "source": res.Source,
			}, "none")
		} else if res, done := h.resolved[p.ApprovalID]; done {
			// already_resolved is a RESULT, not an error.
			h.ledgerCommand(req.Method, "accepted", "")
			h.sendEnvelope("rpc.response", id, map[string]any{
				"approval_id": p.ApprovalID, "status": "already_resolved",
				"decision": res.Decision, "source": res.Source,
			}, "none")
		} else {
			h.ledgerCommand(req.Method, "rejected", "unknown_approval")
			h.rpcError(id, "unknown_approval", false)
		}

	case "task.transcript":
		var p transcriptParams
		if !strict(&p) || p.TaskID == "" {
			h.ledgerCommand(req.Method, "rejected", "invalid_params")
			h.rpcError(id, "invalid_params", false)
			return
		}
		h.ledgerCommand(req.Method, "accepted", "")
		total := uint(2)
		pages := []wire.TranscriptPage{
			{RequestID: id, TaskID: p.TaskID, Page: 1, TotalPages: &total, HasMore: true,
				Chunk: "$ make check\nrunning gofmt…\nrunning go vet…\n"},
			{RequestID: id, TaskID: p.TaskID, Page: 2, TotalPages: &total, HasMore: false,
				Chunk: "ok  \tall tests pass\n"},
		}
		for _, pg := range pages {
			h.sendEnvelope("transcript.page", id, pg, "none")
		}

	case "workbench.list":
		h.ledgerCommand(req.Method, "accepted", "")
		h.sendEnvelope("rpc.response", id, map[string]any{
			"workbenches": h.snapshotBody().Workbenches,
		}, "none")

	default:
		// The method table is the whole surface. Absent = forbidden.
		h.ledgerCommand(req.Method, "rejected", "unknown_method")
		h.rpcError(id, "unknown_method", false)
	}
}
