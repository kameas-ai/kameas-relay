package wire

import (
	"encoding/json"
	"fmt"
	"time"
)

// Envelope is the JSON object inside class-P bodies and class-L/M
// plaintexts (e2e-envelope.md §6.1). Class-P control frames omit ts and
// id (§5.1); rpc.request / rpc.response / transcript.page carry id.
type Envelope struct {
	V    int             `json:"v"`
	Kind string          `json:"kind"`
	TS   string          `json:"ts,omitempty"`
	ID   string          `json:"id,omitempty"`
	Body json.RawMessage `json:"body"`
}

// EnvelopeV1 is the envelope schema version this implementation speaks.
const EnvelopeV1 = 1

// TS formats a timestamp per the contract: RFC3339 UTC, millisecond
// precision.
func TS(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// NewControl builds a class-P/handshake envelope ({v, kind, body} — no
// ts, no id).
func NewControl(kind string, body any) (Envelope, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{V: EnvelopeV1, Kind: kind, Body: raw}, nil
}

// NewPayload builds a payload envelope with a ts (and optional id).
func NewPayload(kind, id string, at time.Time, body any) (Envelope, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{V: EnvelopeV1, Kind: kind, TS: TS(at), ID: id, Body: raw}, nil
}

// Marshal serializes the envelope. Receivers treat the bytes as opaque —
// nothing on this surface re-encodes-and-compares (ADR freeze ruling 8).
func (e Envelope) Marshal() ([]byte, error) { return json.Marshal(e) }

// ParseEnvelope parses an envelope and enforces the schema version (an
// unknown v is a fatal session abort, §6.1).
func ParseEnvelope(raw []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return e, fmt.Errorf("wire: malformed envelope: %w", err)
	}
	if e.V != EnvelopeV1 {
		return e, fmt.Errorf("wire: unsupported envelope version %d", e.V)
	}
	return e, nil
}

// DecodeBody unmarshals the envelope body into out.
func (e Envelope) DecodeBody(out any) error { return json.Unmarshal(e.Body, out) }

// Control / handshake bodies (e2e-envelope.md §5.1–§5.3). Binary fields
// are unpadded canonical base64url at their fixed widths.

type SessHello struct {
	Proto    int    `json:"proto"`
	DeviceID string `json:"device_id"`
	ND       string `json:"n_d"`
}

type SessAccept struct {
	HostID string `json:"host_id"`
	NH     string `json:"n_h"`
	HdrH2D string `json:"hdr_h2d"`
}

type SessHeader struct {
	HdrD2H string `json:"hdr_d2h"`
}

type SessConfirm struct {
	TranscriptMAC string `json:"transcript_mac"`
}

type SessDenied struct {
	Reason string `json:"reason"`
}

type PairInit struct {
	Proto    int    `json:"proto"`
	DeviceID string `json:"device_id"`
	DevPK    string `json:"dev_pk"`
	ND       string `json:"n_d"`
	MacPair  string `json:"mac_pair"`
}

type PairIdentity struct {
	ConfD       string `json:"conf_d"`
	IDToken     string `json:"id_token"`
	DeviceName  string `json:"device_name"`
	DeviceModel string `json:"device_model"`
}

type PairComplete struct {
	ConfH       string `json:"conf_h"`
	HostID      string `json:"host_id"`
	HostName    string `json:"host_name"`
	AccountBind string `json:"account_bind"`
	ChannelID   string `json:"channel_id"`
}

type PairDenied struct {
	Reason string `json:"reason"`
}

type SessionRevoked struct {
	Reason string `json:"reason"`
}

// Payload bodies (e2e-envelope.md §6.3–§6.6, remote-rpc.md §2).

type SnapshotHost struct {
	HostID      string `json:"host_id"`
	HostName    string `json:"host_name"`
	Version     string `json:"version"`
	GeneratedAt string `json:"generated_at"`
}

type SnapshotApp struct {
	AppID   string `json:"app_id"`
	Name    string `json:"name"`
	Surface string `json:"surface"`
}

type SnapshotResources struct {
	CPUPct      float64 `json:"cpu_pct"`
	MemUsedMB   uint64  `json:"mem_used_mb"`
	MemTotalMB  uint64  `json:"mem_total_mb"`
	DiskUsedMB  uint64  `json:"disk_used_mb"`
	DiskTotalMB uint64  `json:"disk_total_mb"`
}

type SnapshotWorkbench struct {
	WorkbenchID string            `json:"workbench_id"`
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	ProfileID   string            `json:"profile_id"`
	Apps        []SnapshotApp     `json:"apps"`
	Resources   SnapshotResources `json:"resources"`
	UpdatedAt   string            `json:"updated_at"`
}

type SnapshotTask struct {
	TaskID      string  `json:"task_id"`
	WorkbenchID string  `json:"workbench_id"`
	Status      string  `json:"status"`
	StartedAt   string  `json:"started_at"`
	EndedAt     *string `json:"ended_at"`
}

type SnapshotFull struct {
	Host              SnapshotHost        `json:"host"`
	Workbenches       []SnapshotWorkbench `json:"workbenches"`
	Tasks             []SnapshotTask      `json:"tasks"`
	Approvals         []ApprovalRequest   `json:"approvals"`
	ApprovalsBrokered bool                `json:"approvals_brokered"`
}

type Event struct {
	Source      string         `json:"source"`
	Kind        string         `json:"kind"`
	At          string         `json:"at"`
	WorkbenchID *string        `json:"workbench_id"`
	TaskID      *string        `json:"task_id"`
	Attrs       map[string]any `json:"attrs"`
}

type ApprovalRequest struct {
	ApprovalID  string `json:"approval_id"`
	TaskID      string `json:"task_id"`
	WorkbenchID string `json:"workbench_id"`
	Family      string `json:"family"`
	ActionKind  string `json:"action_kind"`
	Summary     string `json:"summary"`
	Dangerous   bool   `json:"dangerous"`
	RequestedAt string `json:"requested_at"`
	DeadlineAt  string `json:"deadline_at"`
	TimeoutS    int    `json:"timeout_s"`
}

type ApprovalResolved struct {
	ApprovalID string `json:"approval_id"`
	TaskID     string `json:"task_id"`
	Decision   string `json:"decision"`
	Source     string `json:"source"`
	ResolvedAt string `json:"resolved_at"`
	LatencyMS  int64  `json:"latency_ms"`
}

type TranscriptPage struct {
	RequestID  string  `json:"request_id"`
	TaskID     string  `json:"task_id"`
	Page       uint    `json:"page"`
	TotalPages *uint   `json:"total_pages"`
	HasMore    bool    `json:"has_more"`
	Cursor     *string `json:"cursor"`
	Chunk      string  `json:"chunk"`
}

type RPCRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type RPCError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// RPCErrorBody is the §8 error envelope body: {"error": {...}}.
type RPCErrorBody struct {
	Error RPCError `json:"error"`
}

type Ack struct {
	SeqSeen uint64 `json:"seq_seen"`
}

// Closed sess.denied reason enum (§5.3).
const (
	DeniedUnknownDevice    = "unknown_device"
	DeniedRevoked          = "revoked"
	DeniedProtoUnsupported = "proto_unsupported"
	DeniedRateLimited      = "rate_limited"
	DeniedPairFailed       = "pair_failed"
)
