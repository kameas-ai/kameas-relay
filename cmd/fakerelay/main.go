// Command fakerelay runs the in-memory fake relay as a standalone
// process for manual testing and for the Task 1.3 fakehost/remotectl
// tooling.
//
// Logging is connection metadata ONLY (relay-api.md §9): ids, counts,
// error codes, timings. Never frame bytes, never Authorization headers,
// never APNs token bytes.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/kameas-ai/kameas-relay/internal/fakerelay"
)

func main() {
	var (
		addr             = flag.String("addr", "127.0.0.1:7900", "listen address")
		mailboxTTL       = flag.Duration("mailbox-ttl", fakerelay.DefaultMailboxTTL, "mailbox frame TTL (contract default 15m; may only be tuned downward)")
		mailboxMaxFrames = flag.Int("mailbox-max-frames", fakerelay.DefaultMailboxMaxFrames, "per-channel mailbox frame cap")
		mailboxMaxBytes  = flag.Int64("mailbox-max-bytes", fakerelay.DefaultMailboxMaxBytes, "per-channel mailbox byte cap")
		windowTTL        = flag.Duration("window-ttl", fakerelay.DefaultWindowTTL, "pairing window TTL (contract: <= 5m)")
		offlineAfter     = flag.Duration("offline-after", fakerelay.DefaultOfflineAfter, "presence offline flip after this much host silence")
		hostFPS          = flag.Float64("host-frames-per-sec", 200, "host frame rate limit (sustained)")
		deviceFPS        = flag.Float64("device-frames-per-sec", 60, "device frame rate limit (sustained)")
		mailboxGetPerMin = flag.Int("mailbox-get-per-min", 30, "mailbox GET rate limit per device")
	)
	flag.Parse()

	if *windowTTL > 5*time.Minute {
		fmt.Fprintln(os.Stderr, "fakerelay: window-ttl must be <= 5m (relay-api.md §3.1)")
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	relay := fakerelay.New(fakerelay.Config{
		Logger:           logger,
		MailboxTTL:       *mailboxTTL,
		MailboxMaxFrames: *mailboxMaxFrames,
		MailboxMaxBytes:  *mailboxMaxBytes,
		WindowTTL:        *windowTTL,
		OfflineAfter:     *offlineAfter,
		Limits: fakerelay.Limits{
			HostFramesPerSec:   *hostFPS,
			DeviceFramesPerSec: *deviceFPS,
			MailboxGetPerMin:   *mailboxGetPerMin,
		},
	})

	logger.Info("fakerelay listening", "addr", *addr,
		"mailbox_ttl", mailboxTTL.String(), "window_ttl", windowTTL.String())
	srv := &http.Server{Addr: *addr, Handler: requestLog(logger, relay.Handler())}
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server exited", "err", err)
		os.Exit(1)
	}
}

// requestLog logs method, path, status, and duration — path parameters
// are channel/pairing/device ids, which §9 permits. Bodies, tokens, and
// query strings carrying no ids are never logged.
func requestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		logger.Info("request", "method", r.Method, "path", r.URL.Path,
			"status", sw.status, "dur_ms", time.Since(start).Milliseconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer so
// WebSocket upgrades (hijack / flush) work through the logging wrapper.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
