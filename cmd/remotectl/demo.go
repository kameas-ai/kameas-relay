package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/kameas-ai/kameas-relay/devclient"
	"github.com/kameas-ai/kameas-relay/fakehost"
	"github.com/kameas-ai/kameas-relay/internal/fakerelay"
	"github.com/kameas-ai/kameas-relay/wire"
)

// cmdDemo is the Task 1.3 exit-gate orchestration: it spawns an
// in-process fakerelay and fakehost, pairs a fresh device, watches the
// live stream (snapshot.full + scripted events), receives the scripted
// approval.request, auto-approves it over the two-valued remote surface,
// asserts the approval.resolved round-trip, and prints PASS or FAIL.
func cmdDemo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	timeout := fs.Duration("timeout", 30*time.Second, "overall demo deadline")
	approvalAfter := fs.Duration("approval-after", 2*time.Second, "scripted approval delay")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	// 1. In-process fake relay.
	relay := fakerelay.New(fakerelay.Config{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: relay.Handler()}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	origin := "http://" + ln.Addr().String()
	fmt.Printf("demo: fakerelay listening at %s\n", origin)

	// 2. In-process fake host.
	host, err := fakehost.New(fakehost.Config{
		RelayOrigin:     origin,
		Sub:             *sub,
		HostName:        "Demo Host",
		AutoConfirm:     true,
		ApprovalAfter:   *approvalAfter,
		ApprovalTimeout: 60 * time.Second,
		EventInterval:   time.Second,
		Out:             os.Stdout,
	})
	if err != nil {
		return err
	}
	// Attach first: the §2.2 binding is created by the host attach and
	// the pairing window requires it.
	hostErr := make(chan error, 1)
	go func() { hostErr <- host.Run(ctx) }()
	if err := host.WaitAttached(ctx); err != nil {
		return fmt.Errorf("demo FAIL: host attach: %w", err)
	}
	qr, _, err := host.OpenPairingWindow(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("demo: QR payload: %s\n", qr)

	// 3. Pair (fresh ephemeral device state; the QR alone suffices —
	// the pairing attach is addressed by the QR's host_id, §3.2).
	st, err := devclient.Pair(ctx, devclient.PairConfig{
		QRURI:       qr,
		Sub:         *sub,
		DeviceName:  "Demo iPhone",
		DeviceModel: "iPhone15,2",
	})
	if err != nil {
		return fmt.Errorf("demo FAIL: pairing: %w", err)
	}
	fmt.Printf("demo: paired with %q on channel %s\n", st.HostName, st.ChannelID)

	// 4. Watch: snapshot.full on session start, live events, then the
	// scripted approval — approve it and assert the resolved round-trip.
	sess, err := devclient.Connect(ctx, st)
	if err != nil {
		return fmt.Errorf("demo FAIL: connect: %w", err)
	}
	defer sess.Close()

	var (
		sawSnapshot   bool
		sawEvent      bool
		approvalID    string
		rpcID         string
		sawApplied    bool
		sawResolved   bool
		resolvedMatch wire.ApprovalResolved
	)
	for !(sawSnapshot && sawEvent && sawApplied && sawResolved) {
		env, err := sess.Recv(ctx)
		if err != nil {
			select {
			case herr := <-hostErr:
				return fmt.Errorf("demo FAIL: host exited: %v (recv: %w)", herr, err)
			default:
			}
			return fmt.Errorf("demo FAIL: %w", err)
		}
		renderEnvelope(env)
		switch env.Kind {
		case "snapshot.full":
			sawSnapshot = true
		case "event":
			sawEvent = true
		case "approval.request":
			var a wire.ApprovalRequest
			if err := env.DecodeBody(&a); err != nil {
				return fmt.Errorf("demo FAIL: %w", err)
			}
			approvalID = a.ApprovalID
			fmt.Println("[device-auth simulated] Face ID / passcode challenge passed")
			rpcID, err = sess.SendRPC(ctx, "approval.decide", map[string]string{
				"approval_id": approvalID,
				"decision":    "allow",
			})
			if err != nil {
				return fmt.Errorf("demo FAIL: approval.decide: %w", err)
			}
		case "rpc.response":
			if env.ID != rpcID {
				continue
			}
			var res struct {
				ApprovalID string `json:"approval_id"`
				Status     string `json:"status"`
				Decision   string `json:"decision"`
				Source     string `json:"source"`
			}
			if err := env.DecodeBody(&res); err != nil {
				return fmt.Errorf("demo FAIL: %w", err)
			}
			if res.Status != "applied" || res.Decision != "allow_once" || res.Source != "remote" {
				return fmt.Errorf("demo FAIL: unexpected decide result %s", jsonLine(res))
			}
			sawApplied = true
		case "approval.resolved":
			var r wire.ApprovalResolved
			if err := env.DecodeBody(&r); err != nil {
				return fmt.Errorf("demo FAIL: %w", err)
			}
			if r.ApprovalID == approvalID {
				if r.Decision != "allow_once" || r.Source != "remote" {
					return fmt.Errorf("demo FAIL: unexpected resolution %s", jsonLine(r))
				}
				resolvedMatch = r
				sawResolved = true
			}
		}
	}

	fmt.Printf("demo: approval %s resolved %s/%s in %dms — full E2E round-trip verified\n",
		resolvedMatch.ApprovalID, resolvedMatch.Decision, resolvedMatch.Source, resolvedMatch.LatencyMS)
	fmt.Println("PASS")
	return nil
}
