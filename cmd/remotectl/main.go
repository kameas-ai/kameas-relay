// Command remotectl is the device-side CLI test client for spec-074
// (Task 1.3): QR pairing, one-shot snapshots, a live watch stream, the
// two-valued remote approval surface, and a self-contained end-to-end
// demo (in-process fakerelay + fakehost).
//
// Device-auth (Face ID / passcode) is device-side normative for the real
// app; remotectl prints a "[device-auth simulated]" line before every
// mutating transmission to keep the flow honest.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kameas-ai/kameas-relay/devclient"
	"github.com/kameas-ai/kameas-relay/wire"
)

func usage() {
	fmt.Fprint(os.Stderr, `usage: remotectl [flags] <command> [command flags]

commands:
  pair --qr <uri|@file>                 pair with a host from its QR payload (the QR alone suffices)
  list                                  one-shot snapshot fetch
  watch [--duration d]                  live snapshot + event stream
  approve <approval_id> --decision allow|deny
  demo [--timeout d]                    end-to-end orchestration (in-process fakerelay + fakehost)

flags:
`)
	flag.PrintDefaults()
}

var (
	stateDir = flag.String("state-dir", defaultStateDir(), "device state directory (state.json, 0600)")
	sub      = flag.String("sub", "demo-user", "fake account subject (Bearer fake-<sub>)")
)

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".remotectl"
	}
	return filepath.Join(home, ".remotectl")
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var err error
	switch flag.Arg(0) {
	case "pair":
		err = cmdPair(ctx, flag.Args()[1:])
	case "list":
		err = cmdList(ctx)
	case "watch":
		err = cmdWatch(ctx, flag.Args()[1:])
	case "approve":
		err = cmdApprove(ctx, flag.Args()[1:])
	case "demo":
		err = cmdDemo(ctx, flag.Args()[1:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "remotectl:", err)
		os.Exit(1)
	}
}

func loadState() (*devclient.State, error) {
	st, err := devclient.Load(*stateDir)
	if err != nil {
		return nil, fmt.Errorf("no pairing state in %s (run `remotectl pair` first): %w", *stateDir, err)
	}
	return st, nil
}

// ---------------------------------------------------------------------
// pair
// ---------------------------------------------------------------------

func cmdPair(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	qr := fs.String("qr", "", "QR payload URI, or @file containing it")
	name := fs.String("name", "Test iPhone", "device name shown in the host confirmation prompt")
	model := fs.String("model", "iPhone15,2", "device model")
	_ = fs.Parse(args)
	if *qr == "" {
		return errors.New("pair: --qr is required")
	}
	uri := *qr
	if strings.HasPrefix(uri, "@") {
		raw, err := os.ReadFile(uri[1:])
		if err != nil {
			return err
		}
		uri = strings.TrimSpace(string(raw))
	}
	st, err := devclient.Pair(ctx, devclient.PairConfig{
		QRURI:       uri,
		Sub:         *sub,
		DeviceName:  *name,
		DeviceModel: *model,
	})
	if err != nil {
		return err
	}
	if err := st.Save(*stateDir); err != nil {
		return err
	}
	fmt.Printf("paired with %q (host %s) on channel %s\nstate: %s\n",
		st.HostName, st.HostID, st.ChannelID, filepath.Join(*stateDir, "state.json"))
	return nil
}

// ---------------------------------------------------------------------
// list / watch
// ---------------------------------------------------------------------

func renderEnvelope(env wire.Envelope) {
	switch env.Kind {
	case "snapshot.full":
		var s wire.SnapshotFull
		if env.DecodeBody(&s) != nil {
			return
		}
		fmt.Printf("── snapshot @ %s ── host %q (%s)\n", env.TS, s.Host.HostName, s.Host.HostID)
		for _, wb := range s.Workbenches {
			fmt.Printf("   workbench %-8s %-14s status=%-12s cpu=%.1f%% mem=%d/%dMB\n",
				wb.WorkbenchID, wb.Name, wb.Status, wb.Resources.CPUPct, wb.Resources.MemUsedMB, wb.Resources.MemTotalMB)
		}
		for _, t := range s.Tasks {
			fmt.Printf("   task      %-8s wb=%-8s status=%s\n", t.TaskID, t.WorkbenchID, t.Status)
		}
		if !s.ApprovalsBrokered {
			// The forbidden-empty-list rule (approval-events.md §2).
			fmt.Println("   approvals: NOT BROKERED on this workbench — decide in the workbench UI")
		} else if len(s.Approvals) == 0 {
			fmt.Println("   approvals: none pending")
		}
		for _, a := range s.Approvals {
			fmt.Printf("   approval  %s [%s] %s — deadline %s\n", a.ApprovalID, a.Family, a.Summary, a.DeadlineAt)
		}
	case "event":
		var e wire.Event
		if env.DecodeBody(&e) != nil {
			return
		}
		target := ""
		if e.WorkbenchID != nil {
			target = " " + *e.WorkbenchID
		}
		if e.TaskID != nil {
			target += " " + *e.TaskID
		}
		fmt.Printf("event   %s %s/%s%s\n", e.At, e.Source, e.Kind, target)
	case "approval.request":
		var a wire.ApprovalRequest
		if env.DecodeBody(&a) != nil {
			return
		}
		danger := ""
		if a.Dangerous {
			danger = " [DANGEROUS]"
		}
		fmt.Printf("APPROVAL %s%s [%s %s] %q — decide with: remotectl approve %s --decision allow|deny (deadline %s)\n",
			a.ApprovalID, danger, a.Family, a.ActionKind, a.Summary, a.ApprovalID, a.DeadlineAt)
	case "approval.resolved":
		var r wire.ApprovalResolved
		if env.DecodeBody(&r) != nil {
			return
		}
		fmt.Printf("resolved %s -> %s (source=%s, %dms)\n", r.ApprovalID, r.Decision, r.Source, r.LatencyMS)
	case "session.revoked":
		var rv wire.SessionRevoked
		_ = env.DecodeBody(&rv)
		fmt.Printf("SESSION REVOKED by host: %s\n", rv.Reason)
	case "transcript.page":
		var p wire.TranscriptPage
		if env.DecodeBody(&p) != nil {
			return
		}
		fmt.Printf("transcript %s page %d (has_more=%v):\n%s", p.TaskID, p.Page, p.HasMore, p.Chunk)
	case "rpc.response":
		fmt.Printf("rpc.response %s: %s\n", env.ID, string(env.Body))
	default:
		fmt.Printf("%s: %s\n", env.Kind, string(env.Body))
	}
}

func cmdList(ctx context.Context) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	sess, err := devclient.Connect(cctx, st)
	if err != nil {
		return err
	}
	defer sess.Close()
	for _, env := range sess.DrainedEnvelopes {
		renderEnvelope(env)
	}
	// The host's first post-handshake envelope is snapshot.full.
	for {
		env, err := sess.Recv(cctx)
		if err != nil {
			return err
		}
		renderEnvelope(env)
		if env.Kind == "snapshot.full" {
			return nil
		}
	}
}

func cmdWatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	duration := fs.Duration("duration", 0, "stop after this long (0 = run until interrupted)")
	_ = fs.Parse(args)
	st, err := loadState()
	if err != nil {
		return err
	}
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	for {
		err := watchOnce(ctx, st)
		switch {
		case ctx.Err() != nil:
			return nil
		case err == nil:
			return nil
		case errors.Is(err, devclient.ErrRevoked):
			return err
		default:
			// Fatal session abort: reconnect with fresh nonces — this is
			// the session-start seq regime in action.
			fmt.Fprintf(os.Stderr, "watch: %v — reconnecting\n", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
		}
	}
}

func watchOnce(ctx context.Context, st *devclient.State) error {
	sess, err := devclient.Connect(ctx, st)
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.OnPresence = func(p devclient.Presence) {
		state := "OFFLINE"
		if p.Online {
			state = "online"
		}
		fmt.Printf("presence: host %s (last seen %s)\n", state, p.LastSeen)
	}
	if sess.ReconcileExpected {
		fmt.Println("watch: seq jumped forward at session start (frames expired) — reconciling from snapshot.full")
	}
	for _, env := range sess.DrainedEnvelopes {
		renderEnvelope(env)
	}
	for {
		env, err := sess.Recv(ctx)
		if err != nil {
			return err
		}
		renderEnvelope(env)
	}
}

// ---------------------------------------------------------------------
// approve
// ---------------------------------------------------------------------

func cmdApprove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	decision := fs.String("decision", "", "allow | deny (the remote surface is two-valued; allow maps to allow_once)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 || (*decision != "allow" && *decision != "deny") {
		return errors.New("usage: remotectl approve <approval_id> --decision allow|deny")
	}
	approvalID := fs.Arg(0)
	st, err := loadState()
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	sess, err := devclient.Connect(cctx, st)
	if err != nil {
		return err
	}
	defer sess.Close()
	fmt.Println("[device-auth simulated] Face ID / passcode challenge passed")
	id, err := sess.SendRPC(cctx, "approval.decide", map[string]string{
		"approval_id": approvalID,
		"decision":    *decision,
	})
	if err != nil {
		return err
	}
	for {
		env, err := sess.Recv(cctx)
		if err != nil {
			return err
		}
		if env.Kind == "rpc.response" && env.ID == id {
			var errBody wire.RPCErrorBody
			if env.DecodeBody(&errBody) == nil && errBody.Error.Code != "" {
				return fmt.Errorf("approval.decide failed: %s", errBody.Error.Code)
			}
			var res struct {
				ApprovalID string `json:"approval_id"`
				Status     string `json:"status"`
				Decision   string `json:"decision"`
				Source     string `json:"source"`
			}
			if err := env.DecodeBody(&res); err != nil {
				return err
			}
			if res.Status == "already_resolved" {
				fmt.Printf("already decided — %s by another surface (%s)\n", res.Decision, res.Source)
			} else {
				fmt.Printf("applied: %s -> %s\n", res.ApprovalID, res.Decision)
			}
			return nil
		}
		renderEnvelope(env)
	}
}

// helper for demo output
func jsonLine(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
