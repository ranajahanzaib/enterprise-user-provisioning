package oidc

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ranajahanzaib/enterprise-user-provisioning/migrations"
)

func TestOIDCRequireUnauthenticatedRedirects(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest("GET", "/app", nil)
	rec := httptest.NewRecorder()

	protected := h.require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303 See Other, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestOIDCRandomGenerator(t *testing.T) {
	s1, err := random(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s2, err := random(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s1 == "" || s2 == "" {
		t.Fatal("expected non-empty random strings")
	}
	if s1 == s2 {
		t.Fatal("expected distinct random values")
	}
}

func TestOIDCSessionAndPermissionEvaluation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; PostgreSQL OIDC integration test skipped")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err = migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}

	// 1. Create a tenant
	var tenantID string
	err = db.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('oidc-test-'||gen_random_uuid()::text) RETURNING id::text`).Scan(&tenantID)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Create a user
	var userID string
	err = db.QueryRow(ctx, `INSERT INTO users(tenant_id, username, active) VALUES($1, 'alice@test.example', true) RETURNING id::text`, tenantID).Scan(&userID)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Create a group and add user
	var groupID string
	err = db.QueryRow(ctx, `INSERT INTO groups(tenant_id, display_name) VALUES($1, 'Engineering') RETURNING id::text`, tenantID).Scan(&groupID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `INSERT INTO group_members(tenant_id, group_id, user_id) VALUES($1, $2, $3)`, tenantID, groupID, userID)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Create role and permission
	_, err = db.Exec(ctx, `INSERT INTO permissions(tenant_id, id, description) VALUES($1, 'portal:read', 'Access portal')`, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `INSERT INTO roles(tenant_id, id, description) VALUES($1, 'developer', 'Developer role')`, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `INSERT INTO role_permissions(tenant_id, role_id, permission_id) VALUES($1, 'developer', 'portal:read')`, tenantID)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Create session
	sessionToken, err := random(32)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(sessionToken))
	_, err = db.Exec(ctx, `INSERT INTO app_sessions(tenant_id, user_id, token_hash, expires_at) VALUES($1, $2, $3, now() + interval '1 hour')`, tenantID, userID, sum[:])
	if err != nil {
		t.Fatal(err)
	}

	h := New(db)
	mux := http.NewServeMux()
	h.Register(mux)

	// Step A: Request /app before binding role -> should be 403 Forbidden (no portal:read permission)
	reqA := httptest.NewRequest("GET", "/app", nil)
	reqA.AddCookie(&http.Cookie{Name: "eup_session", Value: sessionToken})
	recA := httptest.NewRecorder()
	mux.ServeHTTP(recA, reqA)
	if recA.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when group not mapped to role, got %d", recA.Code)
	}

	// Step B: Bind group to role -> should be 200 OK
	_, err = db.Exec(ctx, `INSERT INTO group_role_mappings(tenant_id, group_id, role_id) VALUES($1, $2, 'developer')`, tenantID, groupID)
	if err != nil {
		t.Fatal(err)
	}

	reqB := httptest.NewRequest("GET", "/app", nil)
	reqB.AddCookie(&http.Cookie{Name: "eup_session", Value: sessionToken})
	recB := httptest.NewRecorder()
	mux.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Fatalf("expected 200 OK after role mapping, got %d", recB.Code)
	}

	// Step C: Request /app/admin (admin:read) -> should still be 403 Forbidden
	reqC := httptest.NewRequest("GET", "/app/admin", nil)
	reqC.AddCookie(&http.Cookie{Name: "eup_session", Value: sessionToken})
	recC := httptest.NewRecorder()
	mux.ServeHTTP(recC, reqC)
	if recC.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for ungranted admin:read, got %d", recC.Code)
	}

	// Step D: Suspend user (active=false) -> subsequent request to /app must be 401 Unauthorized
	_, err = db.Exec(ctx, `UPDATE users SET active=false WHERE id=$1`, userID)
	if err != nil {
		t.Fatal(err)
	}

	reqD := httptest.NewRequest("GET", "/app", nil)
	reqD.AddCookie(&http.Cookie{Name: "eup_session", Value: sessionToken})
	recD := httptest.NewRecorder()
	mux.ServeHTTP(recD, reqD)
	if recD.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized after user suspension, got %d", recD.Code)
	}

	// Step E: Logout
	reqE := httptest.NewRequest("POST", "/logout", nil)
	reqE.AddCookie(&http.Cookie{Name: "eup_session", Value: sessionToken})
	recE := httptest.NewRecorder()
	mux.ServeHTTP(recE, reqE)
	if recE.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for logout, got %d", recE.Code)
	}
}
