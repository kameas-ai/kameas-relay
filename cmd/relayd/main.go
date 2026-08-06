// Command relayd is the production Kameas relay (spec 074, Lane A).
//
// It serves the relay-api.md surface: WSS attach for hosts and devices,
// opaque frame routing, a short-TTL ciphertext mailbox, presence, pairing
// windows, and the APNs trigger. It authenticates every connection and
// request against Zitadel JWKS and fails closed when JWKS is unreachable.
//
// It cannot decrypt anything it forwards. See internal/relay's package doc
// and internal/fakerelay/denylist_test.go for why that is a structural
// property of the binary rather than a claim about its behaviour.
//
// Configuration is entirely environmental; see internal/relay/env.go for the
// variable list. There is no flag or variable that disables authentication.
//
// Logging is CONNECTION METADATA ONLY (relay-api.md §9): timestamps, ids,
// counts, sizes, error codes. Never frame bytes, never token bytes, never
// any claim other than `sub`, never a QR URI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/kameas-ai/kameas-relay/internal/jwtverify"
	"github.com/kameas-ai/kameas-relay/internal/relay"
)

// version is stamped by the build (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	var (
		showVersion = flag.Bool("version", false, "print the version and exit")
		healthcheck = flag.Bool("healthcheck", false, "probe the local /healthz endpoint and exit 0 (healthy) or 1")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("relayd", buildVersion())
		return
	}
	if *healthcheck {
		if err := probeHealth(os.Getenv("RELAY_ADDR")); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "relayd:", err)
		os.Exit(1)
	}
}

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				return "dev+" + s.Value[:min(12, len(s.Value))]
			}
		}
	}
	return version
}

func run() error {
	cfg, err := relay.LoadServerConfig(os.Getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogJSON {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	logger := slog.New(handler)

	validator, err := relay.NewJWTValidator(jwtverify.Config{
		Issuer:   cfg.Issuer,
		Audience: cfg.Audience,
		JWKSURL:  cfg.JWKSURL,
		CacheTTL: cfg.JWKSCacheTTL,
		Leeway:   cfg.JWTLeeway,
	})
	if err != nil {
		return fmt.Errorf("JWT validation: %w", err)
	}

	rcfg := cfg.Relay
	rcfg.Store = relay.NewMemStore(cfg.BindingReaper)
	rcfg.Validator = validator
	rcfg.Logger = logger
	// No Apple credentials in LLE ([OP] 0.7 gates them). Mailboxing and
	// routing are unaffected; only the notification is absent, and the
	// device finds the frame on reconnect.
	rcfg.Pusher = relay.LogPusher{Logger: logger}
	rcfg.Ready = validator.Ready

	r, err := relay.New(rcfg)
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}
	defer func() { _ = r.Close() }()

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           requestLog(logger, r.Handler()),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		// No WriteTimeout on purpose: it would kill long-lived WSS
		// attachments, which are the whole point of this service.
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("relayd listening",
		"addr", cfg.Addr,
		"version", buildVersion(),
		"issuer", cfg.Issuer,
		"audience", cfg.Audience,
		"mailbox_ttl", cfg.Relay.MailboxTTL.String(),
		"window_ttl", cfg.Relay.WindowTTL.String(),
		"offline_after", cfg.Relay.OfflineAfter.String(),
		"store", "memory")

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutting down", "grace", cfg.ShutdownGrace.String())
		sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}

// probeHealth backs the container HEALTHCHECK. The final image has no shell
// and no curl, so the binary probes itself.
func probeHealth(addr string) error {
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("RELAY_ADDR %q: %w", addr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port) + "/healthz"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/healthz returned %d", resp.StatusCode)
	}
	return nil
}

// requestLog logs method, path, status, and duration.
//
// §9 permits path parameters — they are channel / pairing / device ids,
// which are enumerated routing identifiers. It does NOT permit the query
// string: `host_id` and `channel` there would be fine, but a bearer token
// smuggled into one would not, and the relay refuses those requests rather
// than logging them. Bodies and headers are never logged.
func requestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/healthz" || req.URL.Path == "/readyz" {
			next.ServeHTTP(w, req) // probe noise buys nothing
			return
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, req)
		logger.Info("request",
			"method", req.Method,
			"path", redactPath(req.URL.Path),
			"status", sw.status,
			"dur_ms", time.Since(start).Milliseconds())
	})
}

// redactPath keeps the route shape. Ids are permitted by §9, and they are
// what makes a log line useful for tracing a pairing, so they stay.
func redactPath(p string) string {
	if !strings.HasPrefix(p, "/v1/") {
		return "/"
	}
	return p
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
