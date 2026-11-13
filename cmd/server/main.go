package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ranajahanzaib/enterprise-user-provisioning/internal/oidc"
	"github.com/ranajahanzaib/enterprise-user-provisioning/internal/scim"
	"github.com/ranajahanzaib/enterprise-user-provisioning/internal/security"
	"github.com/ranajahanzaib/enterprise-user-provisioning/migrations"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		slog.Error("DATABASE_URL is required")
		os.Exit(1)
	}
	if len(os.Getenv("TOKEN_HASH_SECRET")) < 32 {
		slog.Error("TOKEN_HASH_SECRET must contain at least 32 bytes")
		os.Exit(1)
	}
	if err := security.ValidateKey(); err != nil {
		slog.Error("OIDC_CONFIG_KEY is invalid", "error", err)
		os.Exit(1)
	}
	if os.Getenv("DEV_MODE") != "true" && os.Getenv("COOKIE_SECURE") != "true" {
		slog.Error("COOKIE_SECURE=true is required outside development")
		os.Exit(1)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		slog.Error("database config", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		slog.Error("database unavailable", "error", err)
		os.Exit(1)
	}
	if err = migrations.Apply(ctx, pool); err != nil {
		slog.Error("database migration", "error", err)
		os.Exit(1)
	}
	base := os.Getenv("PUBLIC_BASE_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	if os.Getenv("DEV_MODE") != "true" && !strings.HasPrefix(strings.ToLower(base), "https://") {
		slog.Error("PUBLIC_BASE_URL must use HTTPS outside development")
		os.Exit(1)
	}
	h := scim.New(pool, base)
	mux := http.NewServeMux()
	mux.Handle("/scim/v2/", h)
	mux.Handle("/healthz", h)
	mux.Handle("/readyz", h)
	oidc.New(pool).Register(mux)
	srv := &http.Server{Addr: env("LISTEN_ADDR", ":8080"), Handler: requestIDs(securityHeaders(mux)), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		slog.Info("server listening", "addr", srv.Addr)
		if e := srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			slog.Error("server", "error", e)
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
func requestIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 16)
		if _, e := rand.Read(b); e == nil {
			w.Header().Set("X-Request-ID", hex.EncodeToString(b))
		}
		next.ServeHTTP(w, r)
	})
}
func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
