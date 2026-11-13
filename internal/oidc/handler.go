package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ranajahanzaib/enterprise-user-provisioning/internal/ratelimit"
	"github.com/ranajahanzaib/enterprise-user-provisioning/internal/security"
	"golang.org/x/oauth2"
)

type Handler struct {
	db      *pgxpool.Pool
	secure  bool
	limiter ratelimit.Limiter
}

func New(db *pgxpool.Pool) *Handler {
	return &Handler{db: db, secure: strings.EqualFold(os.Getenv("COOKIE_SECURE"), "true")}
}
func (h *Handler) Register(m *http.ServeMux) {
	m.Handle("GET /login", h.rate(10, http.HandlerFunc(h.login)))
	m.Handle("GET /oidc/callback", h.rate(30, http.HandlerFunc(h.callback)))
	m.HandleFunc("POST /logout", h.logout)
	m.Handle("GET /app", h.require(h.permission("portal:read")))
	m.Handle("GET /app/reports", h.require(h.permission("reports:read")))
	m.Handle("GET /app/billing", h.require(h.permission("billing:read")))
	m.Handle("GET /app/support", h.require(h.permission("tickets:read")))
	m.Handle("GET /app/admin", h.require(h.permission("admin:read")))
}
func (h *Handler) rate(limit int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil {
			host = r.RemoteAddr
		}
		if !h.limiter.Allow(host, limit, time.Minute, time.Now()) {
			http.Error(w, "Too many requests", 429)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var pid, issuer, client, redirect, tid string
	var encrypted []byte
	if e := h.db.QueryRow(r.Context(), `SELECT p.id::text,p.issuer,p.client_id,p.client_secret,p.redirect_url,p.tenant_id::text FROM identity_providers p JOIN tenants t ON t.id=p.tenant_id WHERE t.name=$1 AND p.enabled`, r.URL.Query().Get("tenant")).Scan(&pid, &issuer, &client, &encrypted, &redirect, &tid); e != nil {
		http.Error(w, "Unknown organization", 404)
		return
	}
	secret, e := security.Decrypt(encrypted)
	if e != nil {
		http.Error(w, "Identity provider configuration unavailable", 500)
		return
	}
	provider, e := oidc.NewProvider(r.Context(), issuer)
	if e != nil {
		http.Error(w, "Identity provider unavailable", 503)
		return
	}
	cfg := oauth2.Config{ClientID: client, ClientSecret: secret, Endpoint: provider.Endpoint(), RedirectURL: redirect, Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	state, e := random(32)
	if e != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	nonce, e := random(32)
	if e != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	verifier := oauth2.GenerateVerifier()
	sum := sha256.Sum256([]byte(state))
	if _, e = h.db.Exec(r.Context(), `INSERT INTO oidc_login_states(state_hash,provider_id,tenant_id,nonce,pkce_verifier,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '5 minutes')`, sum[:], pid, tid, nonce, verifier); e != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "eup_oidc_state", Value: state, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	http.Redirect(w, r, cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), 302)
}
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("error") != "" {
		http.Error(w, "Sign-in denied", 401)
		return
	}
	state, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "Invalid sign-in response", 400)
		return
	}
	cookie, e := r.Cookie("eup_oidc_state")
	if e != nil || cookie.Value != state {
		http.Error(w, "Invalid sign-in state", 401)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "eup_oidc_state", Value: "", Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	sh := sha256.Sum256([]byte(state))
	tx, e := h.db.Begin(r.Context())
	if e != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	defer tx.Rollback(r.Context())
	var pid, tid, nonce, verifier string
	if e = tx.QueryRow(r.Context(), `DELETE FROM oidc_login_states WHERE state_hash=$1 AND expires_at>now() RETURNING provider_id::text,tenant_id::text,nonce,pkce_verifier`, sh[:]).Scan(&pid, &tid, &nonce, &verifier); e != nil {
		http.Error(w, "Invalid or expired sign-in state", 401)
		return
	}
	var issuer, client, redirect string
	var encrypted []byte
	if e = tx.QueryRow(r.Context(), `SELECT issuer,client_id,client_secret,redirect_url FROM identity_providers WHERE id=$1 AND tenant_id=$2 AND enabled`, pid, tid).Scan(&issuer, &client, &encrypted, &redirect); e != nil {
		http.Error(w, "Identity provider unavailable", 401)
		return
	}
	secret, e := security.Decrypt(encrypted)
	if e != nil {
		http.Error(w, "Identity provider configuration unavailable", 500)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	provider, e := oidc.NewProvider(r.Context(), issuer)
	if e != nil {
		http.Error(w, "Identity provider unavailable", 503)
		return
	}
	cfg := oauth2.Config{ClientID: client, ClientSecret: secret, Endpoint: provider.Endpoint(), RedirectURL: redirect, Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	tok, e := cfg.Exchange(r.Context(), code, oauth2.VerifierOption(verifier))
	if e != nil {
		http.Error(w, "Authentication failed", 401)
		return
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Authentication failed", 401)
		return
	}
	idToken, e := provider.Verifier(&oidc.Config{ClientID: client}).Verify(r.Context(), raw)
	if e != nil || idToken.Nonce != nonce {
		http.Error(w, "Authentication failed", 401)
		return
	}
	var uid string
	e = h.db.QueryRow(r.Context(), `SELECT l.user_id::text FROM identity_links l JOIN users u ON u.tenant_id=l.tenant_id AND u.id=l.user_id JOIN tenants t ON t.id=u.tenant_id WHERE l.tenant_id=$1 AND l.provider_id=$2 AND l.issuer=$3 AND l.subject=$4 AND u.active AND u.deleted_at IS NULL AND t.active`, tid, pid, issuer, idToken.Subject).Scan(&uid)
	if e != nil {
		_, _ = h.db.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,outcome,details) VALUES($1,'oidc','authentication.denied','denied','{"reason":"unlinked_or_inactive"}')`, tid)
		http.Error(w, "No active provisioned account is linked to this identity", 403)
		return
	}
	value, e := random(32)
	if e != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	hash := sha256.Sum256([]byte(value))
	if _, e = h.db.Exec(r.Context(), `INSERT INTO app_sessions(tenant_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '8 hours')`, tid, uid, hash[:]); e != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	_, _ = h.db.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,actor_id,action,resource_type,resource_id) VALUES($1,'user',$2,'session.created','user',$2)`, tid, uid)
	http.SetCookie(w, &http.Cookie{Name: "eup_session", Value: value, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode, MaxAge: 28800})
	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

type principal struct{ tenant, user, username string }
type contextKey struct{}

func (h *Handler) require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("eup_session")
		if e != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		sum := sha256.Sum256([]byte(c.Value))
		var p principal
		e = h.db.QueryRow(r.Context(), `SELECT s.tenant_id::text,s.user_id::text,u.username FROM app_sessions s JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id JOIN tenants t ON t.id=s.tenant_id WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.active AND u.deleted_at IS NULL AND t.active`, sum[:]).Scan(&p.tenant, &p.user, &p.username)
		if e != nil {
			clear(w, h.secure)
			http.Error(w, "Sign in required", 401)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, p)))
	})
}
func (h *Handler) permission(permission string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.Context().Value(contextKey{}).(principal)
		var ok bool
		e := h.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM group_members gm JOIN group_role_mappings gr ON gr.tenant_id=gm.tenant_id AND gr.group_id=gm.group_id JOIN role_permissions rp ON rp.tenant_id=gr.tenant_id AND rp.role_id=gr.role_id WHERE gm.tenant_id=$1 AND gm.user_id=$2 AND rp.permission_id=$3)`, p.tenant, p.user, permission).Scan(&ok)
		if e != nil {
			http.Error(w, "Authorization unavailable", 500)
			return
		}
		if !ok {
			_, _ = h.db.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,actor_id,action,resource_type,resource_id,outcome,details) VALUES($1,'user',$2,'authorization.denied','user',$2,'denied',jsonb_build_object('permission',$3))`, p.tenant, p.user, permission)
			http.Error(w, "Permission denied", 403)
			return
		}
		page(w, permission, p.username)
	})
}
func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(contextKey{}).(principal)
	page(w, "Dashboard · "+p.tenant, p.username)
}
func page(w http.ResponseWriter, title, user string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><title>%s</title><main><h1>%s</h1><p>Signed in as %s</p><nav><a href='/app'>Portal</a> · <a href='/app/reports'>Reports</a> · <a href='/app/billing'>Billing</a> · <a href='/app/support'>Support</a> · <a href='/app/admin'>Admin</a></nav><form method='post' action='/logout'><button>Sign out</button></form></main>", template.HTMLEscapeString(title), template.HTMLEscapeString(title), template.HTMLEscapeString(user))
}
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	c, e := r.Cookie("eup_session")
	if e == nil {
		sum := sha256.Sum256([]byte(c.Value))
		_, _ = h.db.Exec(r.Context(), `UPDATE app_sessions SET revoked_at=now() WHERE token_hash=$1 AND revoked_at IS NULL`, sum[:])
	}
	clear(w, h.secure)
	w.WriteHeader(204)
}
func clear(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: "eup_session", Value: "", Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
func random(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
