package scim

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ranajahanzaib/enterprise-user-provisioning/migrations"
)

func TestSCIMTenantLifecycle(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; PostgreSQL SCIM integration test skipped")
	}
	ctx := context.Background()
	db, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if e = db.Ping(ctx); e != nil {
		t.Fatal(e)
	}
	if e = migrations.Apply(ctx, db); e != nil {
		t.Fatal(e)
	}
	secret := []byte("integration-test-secret-0123456789")
	t.Setenv("TOKEN_HASH_SECRET", string(secret))
	tenantA := newTenant(t, db, "north")
	tenantB := newTenant(t, db, "harbor")
	tokenA := "eup_integration-northstar"
	tokenB := "eup_integration-harbor"
	newToken(t, db, tenantA, tokenA, secret)
	newToken(t, db, tenantB, tokenB, secret)
	h := New(db, "http://localhost:8080")
	userBody := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"sam-` + tenantA + `@example.test","externalId":"subject-` + tenantA + `","name":{"givenName":"Sam","familyName":"Rivera"},"active":true}`
	created := callSCIM(t, h, tokenA, "POST", "/scim/v2/Users", userBody, 201)
	var user User
	if e = json.Unmarshal(created.Body.Bytes(), &user); e != nil {
		t.Fatal(e)
	}
	if user.ID == "" || user.Meta.Location == "" || user.Meta.Version == "" {
		t.Fatalf("missing SCIM identity metadata: %+v", user.Meta)
	}
	callSCIM(t, h, tokenA, "POST", "/scim/v2/Users", userBody, 409)
	callSCIM(t, h, tokenB, "GET", "/scim/v2/Users/"+user.ID, "", 404)
	callSCIM(t, h, tokenB, "GET", "/scim/v2/Groups/"+user.ID, "", 404)
	groupBody := fmt.Sprintf(`{"schemas":[%q],"displayName":"Employees","members":[{"value":%q}]}`, CoreGroup, user.ID)
	groupResponse := callSCIM(t, h, tokenA, "POST", "/scim/v2/Groups", groupBody, 201)
	var group Group
	if e = json.Unmarshal(groupResponse.Body.Bytes(), &group); e != nil {
		t.Fatal(e)
	}
	if len(group.Members) != 1 {
		t.Fatalf("expected one group member, got %d", len(group.Members))
	}
	crossTenantGroup := fmt.Sprintf(`{"schemas":[%q],"displayName":"Cross-tenant probe","members":[{"value":%q}]}`, CoreGroup, user.ID)
	callSCIM(t, h, tokenB, "POST", "/scim/v2/Groups", crossTenantGroup, 400)
	filtered := callSCIM(t, h, tokenA, "GET", "/scim/v2/Users?filter="+url.QueryEscape("userName eq \""+user.UserName+"\""), "", 200)
	var filteredList List
	if e = json.Unmarshal(filtered.Body.Bytes(), &filteredList); e != nil || filteredList.TotalResults != 1 {
		t.Fatalf("userName filter did not match exactly one resource: total=%d err=%v", filteredList.TotalResults, e)
	}
	sessionRaw := []byte("integration-session-" + user.ID)
	sessionHash := sha256.Sum256(sessionRaw)
	if _, e = db.Exec(ctx, `INSERT INTO app_sessions(tenant_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, tenantA, user.ID, sessionHash[:], time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	patched := callSCIM(t, h, tokenA, "PATCH", "/scim/v2/Users/"+user.ID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`, 200)
	var inactive User
	if e = json.Unmarshal(patched.Body.Bytes(), &inactive); e != nil {
		t.Fatal(e)
	}
	if inactive.Active == nil || *inactive.Active {
		t.Fatal("PATCH did not deactivate user")
	}
	var revoked bool
	if e = db.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM app_sessions WHERE token_hash=$1`, sessionHash[:]).Scan(&revoked); e != nil || !revoked {
		t.Fatalf("suspension did not revoke session: %v", e)
	}
	stale := httptest.NewRequest("PATCH", "/scim/v2/Users/"+user.ID, bytes.NewBufferString(`{"Operations":[{"op":"replace","path":"displayName","value":"stale"}]}`))
	stale.Header.Set("Authorization", "Bearer "+tokenA)
	stale.Header.Set("If-Match", `W/"999"`)
	stale.Header.Set("Content-Type", "application/scim+json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, stale)
	if rec.Code != 412 {
		t.Fatalf("stale If-Match status=%d body=%s", rec.Code, rec.Body.String())
	}
	reactivated := callSCIM(t, h, tokenA, "PATCH", "/scim/v2/Users/"+user.ID, `{"Operations":[{"op":"replace","path":"active","value":true}]}`, 200)
	if e = db.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM app_sessions WHERE token_hash=$1`, sessionHash[:]).Scan(&revoked); e != nil || !revoked {
		t.Fatalf("reactivation restored a revoked session: %v", e)
	}
	delete := httptest.NewRequest("DELETE", "/scim/v2/Users/"+user.ID, nil)
	delete.Header.Set("Authorization", "Bearer "+tokenA)
	delete.Header.Set("If-Match", reactivated.Header().Get("ETag"))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, delete)
	if rec.Code != 204 {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	callSCIM(t, h, tokenA, "GET", "/scim/v2/Users/"+user.ID, "", 404)
	remaining := callSCIM(t, h, tokenA, "GET", "/scim/v2/Groups/"+group.ID, "", 200)
	var finalGroup Group
	if e = json.Unmarshal(remaining.Body.Bytes(), &finalGroup); e != nil || len(finalGroup.Members) != 0 {
		t.Fatalf("user deletion did not remove membership: %v", e)
	}
}
func newTenant(t *testing.T, db *pgxpool.Pool, name string) string {
	t.Helper()
	var id string
	if e := db.QueryRow(context.Background(), `INSERT INTO tenants(name) VALUES($1||'-'||gen_random_uuid()::text) RETURNING id::text`, name).Scan(&id); e != nil {
		t.Fatal(e)
	}
	return id
}
func newToken(t *testing.T, db *pgxpool.Pool, tenant, token string, secret []byte) {
	t.Helper()
	m := hmac.New(sha256.New, secret)
	_, _ = m.Write([]byte(token))
	if _, e := db.Exec(context.Background(), `INSERT INTO provisioning_tokens(tenant_id,integration_name,token_prefix,token_hash) VALUES($1,'test',$2,$3)`, tenant, prefix(token), hex.EncodeToString(m.Sum(nil))); e != nil {
		t.Fatal(e)
	}
}
func callSCIM(t *testing.T, h http.Handler, token, method, path, body string, want int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/scim+json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, rec.Code, want, rec.Body.String())
	}
	return rec
}
