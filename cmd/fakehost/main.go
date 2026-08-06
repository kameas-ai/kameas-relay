// Command fakehost is the scripted host-side responder for spec-074
// tooling (Task 1.3). It attaches to a (fake) relay (which creates the
// §2.2 account binding), opens a pairing window, prints the QR payload
// URI, completes pairing, and then serves scripted snapshots, events,
// approvals, and transcript pages — class L while the device is
// attached, class M into the mailbox when the relay's §6.1 presence
// says it is not.
//
// Typical use against cmd/fakerelay:
//
//	fakerelay -addr 127.0.0.1:7900 &
//	fakehost -relay http://127.0.0.1:7900 -auto-confirm
//	# then: remotectl pair --qr '<uri>' && remotectl watch
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/kameas-ai/kameas-relay/fakehost"
)

func main() {
	var (
		relay           = flag.String("relay", "http://127.0.0.1:7900", "relay origin")
		sub             = flag.String("sub", "demo-user", "fake account subject (Bearer fake-<sub>)")
		hostName        = flag.String("host-name", "Fake Host", "operator-authored host label")
		autoConfirm     = flag.Bool("auto-confirm", false, "auto-approve the pairing confirmation prompt")
		qrFile          = flag.String("qr-file", "", "also write the QR payload URI to this file")
		script          = flag.String("script", "", "JSON script file: [{after_ms, source, kind, workbench_id?, task_id?, attrs?}]")
		approvalAfter   = flag.Duration("approval-after", 5*time.Second, "emit the scripted approval.request this long after session start")
		approvalTimeout = flag.Duration("approval-timeout", 60*time.Second, "fail-closed deny after this long")
		eventInterval   = flag.Duration("event-interval", 2*time.Second, "built-in status-flip event period (ignored with -script)")
	)
	flag.Parse()

	cfg := fakehost.Config{
		RelayOrigin:     *relay,
		Sub:             *sub,
		HostName:        *hostName,
		AutoConfirm:     *autoConfirm,
		ApprovalAfter:   *approvalAfter,
		ApprovalTimeout: *approvalTimeout,
		EventInterval:   *eventInterval,
		Out:             os.Stdout,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "fakehost: "+format+"\n", args...)
		},
	}
	if *script != "" {
		evs, err := fakehost.LoadScript(*script)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cfg.Script = evs
	}

	host, err := fakehost.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Attach FIRST: only a successful /v1/host attach creates the §2.2
	// account binding, and opening a window requires it.
	runErr := make(chan error, 1)
	go func() { runErr <- host.Run(ctx) }()
	if err := host.WaitAttached(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "fakehost: relay attach:", err)
		os.Exit(1)
	}

	qr, windowID, err := host.OpenPairingWindow(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("QR payload URI:\n%s\n", qr)
	fmt.Printf("pairing window id (host-facing handle only): %s\n", windowID)
	if *qrFile != "" {
		if err := os.WriteFile(*qrFile, []byte(qr+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := <-runErr; err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
