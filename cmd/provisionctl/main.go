package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ranajahanzaib/enterprise-user-provisioning/internal/security"
)

func main() {
	if len(os.Args) < 3 {
		usage()
		return
	}
	ctx := context.Background()
	db, e := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if e != nil {
		fatal(e)
	}
	defer db.Close()
	if e = db.Ping(ctx); e != nil {
		fatal(e)
	}
	a := os.Args[1:]
	switch a[0] + " " + a[1] {
	case "tenant create":
		need(a, 3)
		var id string
		e = db.QueryRow(ctx, `INSERT INTO tenants(name) VALUES($1) RETURNING id::text`, strings.Join(a[2:], " ")).Scan(&id)
		if e != nil {
			fatal(e)
		}
		fmt.Println(id)
	case "tenant list":
		rows, e := db.Query(ctx, `SELECT id::text,name,active FROM tenants ORDER BY name`)
		if e != nil {
			fatal(e)
		}
		defer rows.Close()
		for rows.Next() {
			var id, name string
			var active bool
			_ = rows.Scan(&id, &name, &active)
			fmt.Printf("%s\t%s\tactive=%t\n", id, name, active)
		}
	case "token create":
		need(a, 3)
		tokenCommand(ctx, db, a)
	case "token list":
		tokenList(ctx, db)
	case "token revoke":
		need(a, 3)
		tx, e := db.Begin(ctx)
		if e != nil {
			fatal(e)
		}
		defer tx.Rollback(ctx)
		var tenant, name string
		e = tx.QueryRow(ctx, `UPDATE provisioning_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE id::text=$1 OR token_prefix=$1 RETURNING tenant_id::text,integration_name`, a[2]).Scan(&tenant, &name)
		if e != nil {
			fatal(fmt.Errorf("token not found or unable to revoke"))
		}
		if _, e = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,action,details) VALUES($1,'admin_cli','token.revoked',jsonb_build_object('integration',$2))`, tenant, name); e != nil {
			fatal(e)
		}
		if e = tx.Commit(ctx); e != nil {
			fatal(e)
		}
		fmt.Println("revoked")
	case "token rotate":
		need(a, 3)
		rotateToken(ctx, db, a[2])
	case "oidc configure":
		oidcConfigure(ctx, db, a)
	case "identity link":
		identityLink(ctx, db, a)
	case "users list":
		need(a, 3)
		rows, e := db.Query(ctx, `SELECT id::text,username,active,COALESCE(external_id,'') FROM users WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY username`, a[2])
		if e != nil {
			fatal(e)
		}
		defer rows.Close()
		for rows.Next() {
			var id, name, ext string
			var active bool
			_ = rows.Scan(&id, &name, &active, &ext)
			fmt.Printf("%s\t%s\tactive=%t\texternalId=%s\n", id, name, active, ext)
		}
	case "groups list":
		need(a, 3)
		rows, e := db.Query(ctx, `SELECT id::text,display_name FROM groups WHERE tenant_id=$1 ORDER BY display_name`, a[2])
		if e != nil {
			fatal(e)
		}
		defer rows.Close()
		for rows.Next() {
			var id, name string
			_ = rows.Scan(&id, &name)
			fmt.Printf("%s\t%s\n", id, name)
		}
	case "roles seed":
		need(a, 3)
		seedRoles(ctx, db, a[2])
	case "roles bind":
		need(a, 5)
		mapped, e := db.Exec(ctx, `INSERT INTO group_role_mappings(tenant_id,group_id,role_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, a[2], a[3], a[4])
		if e != nil {
			fatal(e)
		}
		if mapped.RowsAffected() > 0 {
			if _, e = db.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id,details) VALUES($1,'admin_cli','role_mapping.created','group',$2,jsonb_build_object('role_id',$3))`, a[2], a[3], a[4]); e != nil {
				fatal(e)
			}
		}
		fmt.Println("mapping approved")
	case "roles unbind":
		need(a, 5)
		removed, e := db.Exec(ctx, `DELETE FROM group_role_mappings WHERE tenant_id=$1 AND group_id=$2 AND role_id=$3`, a[2], a[3], a[4])
		if e != nil {
			fatal(e)
		}
		if removed.RowsAffected() > 0 {
			if _, e = db.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id,details) VALUES($1,'admin_cli','role_mapping.deleted','group',$2,jsonb_build_object('role_id',$3))`, a[2], a[3], a[4]); e != nil {
				fatal(e)
			}
		}
		fmt.Println("mapping removed")
	case "roles list":
		need(a, 3)
		rows, e := db.Query(ctx, `SELECT r.id,r.description,COALESCE(string_agg(rp.permission_id,', ' ORDER BY rp.permission_id),'') FROM roles r LEFT JOIN role_permissions rp ON rp.tenant_id=r.tenant_id AND rp.role_id=r.id WHERE r.tenant_id=$1 GROUP BY r.id,r.description ORDER BY r.id`, a[2])
		if e != nil {
			fatal(e)
		}
		defer rows.Close()
		for rows.Next() {
			var id, description, permissions string
			_ = rows.Scan(&id, &description, &permissions)
			fmt.Printf("%s\t%s\t%s\n", id, description, permissions)
		}
	case "audit list":
		need(a, 3)
		rows, e := db.Query(ctx, `SELECT occurred_at,action,COALESCE(resource_type,''),COALESCE(resource_id,''),outcome FROM audit_events WHERE tenant_id=$1 ORDER BY occurred_at DESC LIMIT 100`, a[2])
		if e != nil {
			fatal(e)
		}
		defer rows.Close()
		for rows.Next() {
			var at, action, typ, id, outcome string
			_ = rows.Scan(&at, &action, &typ, &id, &outcome)
			fmt.Printf("%s\t%s\t%s\t%s\t%s\n", at, action, typ, id, outcome)
		}
	case "demo run":
		need(a, 3)
		demoRun(ctx, db, a[2])
	default:
		usage()
	}
}
func tokenCommand(ctx context.Context, db *pgxpool.Pool, a []string) {
	secret := []byte(os.Getenv("TOKEN_HASH_SECRET"))
	if len(secret) < 32 {
		fatal(fmt.Errorf("TOKEN_HASH_SECRET must contain at least 32 bytes"))
	}
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		fatal(e)
	}
	token := "eup_" + hex.EncodeToString(raw)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(token))
	name := "default"
	if len(a) > 3 {
		name = strings.Join(a[3:], " ")
	}
	prefix := token[:20]
	_, e := db.Exec(ctx, `INSERT INTO provisioning_tokens(tenant_id,integration_name,token_prefix,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '90 days')`, a[2], name, prefix, hex.EncodeToString(mac.Sum(nil)))
	if e != nil {
		fatal(e)
	}
	_, _ = db.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,action,details) VALUES($1,'admin_cli','token.created',jsonb_build_object('integration',$2,'prefix',$3))`, a[2], name, prefix)
	fmt.Println("Provisioning token (shown once):")
	fmt.Println(token)
}
func tokenList(ctx context.Context, db *pgxpool.Pool) {
	rows, e := db.Query(ctx, `SELECT id::text,integration_name,token_prefix,last_used_at,expires_at,revoked_at FROM provisioning_tokens ORDER BY created_at DESC`)
	if e != nil {
		fatal(e)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name, prefix string
		var used, expires, revoked *time.Time
		_ = rows.Scan(&id, &name, &prefix, &used, &expires, &revoked)
		fmt.Printf("%s\t%s\tprefix=%s\tlast_used=%v\texpires=%v\trevoked=%v\n", id, name, prefix, used, expires, revoked)
	}
}
func rotateToken(ctx context.Context, db *pgxpool.Pool, id string) {
	key := []byte(os.Getenv("TOKEN_HASH_SECRET"))
	if len(key) < 32 {
		fatal(fmt.Errorf("TOKEN_HASH_SECRET must contain at least 32 bytes"))
	}
	tx, e := db.Begin(ctx)
	if e != nil {
		fatal(e)
	}
	defer tx.Rollback(ctx)
	var tenant, name string
	if e = tx.QueryRow(ctx, `UPDATE provisioning_tokens SET expires_at=now()+interval '15 minutes' WHERE id::text=$1 AND revoked_at IS NULL RETURNING tenant_id::text,integration_name`, id).Scan(&tenant, &name); e != nil {
		fatal(e)
	}
	raw := make([]byte, 32)
	if _, e = rand.Read(raw); e != nil {
		fatal(e)
	}
	token := "eup_" + hex.EncodeToString(raw)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(token))
	p := token[:20]
	if _, e = tx.Exec(ctx, `INSERT INTO provisioning_tokens(tenant_id,integration_name,token_prefix,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '90 days')`, tenant, name, p, hex.EncodeToString(mac.Sum(nil))); e != nil {
		fatal(e)
	}
	if _, e = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,action,details) VALUES($1,'admin_cli','token.rotated',jsonb_build_object('integration',$2,'prefix',$3))`, tenant, name, p); e != nil {
		fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		fatal(e)
	}
	fmt.Println("New provisioning token (shown once); old token expires in 15 minutes:")
	fmt.Println(token)
}
func oidcConfigure(ctx context.Context, db *pgxpool.Pool, a []string) {
	need(a, 7)
	issuer := a[3]
	u, e := url.Parse(issuer)
	devLoopback := u != nil && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback())
	if e != nil || (u.Scheme != "https" && !(os.Getenv("DEV_MODE") == "true" && u.Scheme == "http" && devLoopback)) {
		fatal(fmt.Errorf("OIDC issuer must use HTTPS; HTTP is allowed only for an explicitly enabled loopback development issuer"))
	}
	redirect, e := url.Parse(a[6])
	if e != nil || redirect.Host == "" || (redirect.Scheme != "https" && !(os.Getenv("DEV_MODE") == "true" && redirect.Scheme == "http" && (redirect.Hostname() == "localhost" || net.ParseIP(redirect.Hostname()) != nil && net.ParseIP(redirect.Hostname()).IsLoopback()))) {
		fatal(fmt.Errorf("OIDC redirect URL must use HTTPS except for loopback development URLs"))
	}
	if _, e = oidc.NewProvider(ctx, issuer); e != nil {
		fatal(fmt.Errorf("OIDC discovery failed: %w", e))
	}
	cipher, e := security.Encrypt(a[5])
	if e != nil {
		fatal(e)
	}
	var id string
	e = db.QueryRow(ctx, `INSERT INTO identity_providers(tenant_id,issuer,client_id,client_secret,redirect_url) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,issuer) DO UPDATE SET client_id=excluded.client_id,client_secret=excluded.client_secret,redirect_url=excluded.redirect_url,enabled=true RETURNING id::text`, a[2], issuer, a[4], cipher, a[6]).Scan(&id)
	if e != nil {
		fatal(e)
	}
	if _, e = db.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id) SELECT tenant_id,'admin_cli','oidc_provider.configured','identity_provider',$2 FROM identity_providers WHERE id=$1`, id, id); e != nil {
		fatal(e)
	}
	fmt.Println(id)
}
func identityLink(ctx context.Context, db *pgxpool.Pool, a []string) {
	need(a, 5)
	tag, e := db.Exec(ctx, `INSERT INTO identity_links(tenant_id,user_id,provider_id,issuer,subject) SELECT p.tenant_id,$2,p.id,p.issuer,$3 FROM identity_providers p JOIN users u ON u.tenant_id=p.tenant_id AND u.id=$2 AND u.deleted_at IS NULL WHERE p.id=$1`, a[2], a[3], a[4])
	if e != nil {
		fatal(e)
	}
	if tag.RowsAffected() != 1 {
		fatal(fmt.Errorf("provider or active tenant-scoped user not found"))
	}
	if _, e = db.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id,details) SELECT tenant_id,'admin_cli','identity_link.created','user',$2,'{}' FROM identity_providers WHERE id=$1`, a[2], a[3]); e != nil {
		fatal(e)
	}
	fmt.Println("verified subject linked to provisioned user")
}
func seedRoles(ctx context.Context, db *pgxpool.Pool, tenant string) {
	tx, e := db.Begin(ctx)
	if e != nil {
		fatal(e)
	}
	defer tx.Rollback(ctx)
	permissions := map[string]string{"portal:read": "View portal", "reports:read": "View reports", "billing:read": "View billing", "tickets:read": "View support tickets", "admin:read": "View tenant administration"}
	roles := map[string]struct {
		desc  string
		perms []string
	}{"employee": {"Employee", []string{"portal:read"}}, "billing_viewer": {"Billing viewer", []string{"portal:read", "billing:read"}}, "support_agent": {"Support agent", []string{"portal:read", "tickets:read"}}, "tenant_admin": {"Tenant administrator", []string{"portal:read", "reports:read", "billing:read", "tickets:read", "admin:read"}}}
	for id, desc := range permissions {
		if _, e = tx.Exec(ctx, `INSERT INTO permissions(tenant_id,id,description) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, tenant, id, desc); e != nil {
			fatal(e)
		}
	}
	for id, role := range roles {
		if _, e = tx.Exec(ctx, `INSERT INTO roles(tenant_id,id,description) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, tenant, id, role.desc); e != nil {
			fatal(e)
		}
		for _, p := range role.perms {
			if _, e = tx.Exec(ctx, `INSERT INTO role_permissions(tenant_id,role_id,permission_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, tenant, id, p); e != nil {
				fatal(e)
			}
		}
	}
	if e = tx.Commit(ctx); e != nil {
		fatal(e)
	}
	fmt.Println("default roles and permissions seeded")
}
func demoRun(ctx context.Context, db *pgxpool.Pool, tenant string) {
	secret := []byte(os.Getenv("TOKEN_HASH_SECRET"))
	if len(secret) < 32 {
		fatal(fmt.Errorf("TOKEN_HASH_SECRET must contain at least 32 bytes"))
	}
	randomBytes := make([]byte, 6)
	if _, e := rand.Read(randomBytes); e != nil {
		fatal(e)
	}
	suffix := hex.EncodeToString(randomBytes)
	tokenEntropy := make([]byte, 32)
	if _, e := rand.Read(tokenEntropy); e != nil {
		fatal(e)
	}
	token := "eup_" + hex.EncodeToString(tokenEntropy)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(token))
	tokenID := ""
	e := db.QueryRow(ctx, `INSERT INTO provisioning_tokens(tenant_id,integration_name,token_prefix,token_hash,expires_at) VALUES($1,'demo',$2,$3,now()+interval '1 hour') RETURNING id::text`, tenant, token[:20], hex.EncodeToString(mac.Sum(nil))).Scan(&tokenID)
	if e != nil {
		fatal(e)
	}
	_, _ = db.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,action,details) VALUES($1,'admin_cli','token.created','{"integration":"demo"}')`, tenant)
	defer func() {
		_, _ = db.Exec(context.Background(), `UPDATE provisioning_tokens SET revoked_at=now() WHERE id=$1`, tokenID)
	}()
	base := os.Getenv("PUBLIC_BASE_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	client := &http.Client{Timeout: 20 * time.Second}
	username := "sam.rivera+" + suffix + "@example.test"
	external := "demo-sam-rivera-" + suffix
	userRaw := fmt.Sprintf(`{"schemas":[%q],"externalId":%q,"userName":%q,"active":true,"name":{"givenName":"Sam","familyName":"Rivera"},"department":"Support"}`, "urn:ietf:params:scim:schemas:core:2.0:User", external, username)
	var user struct {
		ID string `json:"id"`
	}
	response := demoRequest(client, base, token, "POST", "/scim/v2/Users", userRaw, 201)
	if e = json.NewDecoder(response.Body).Decode(&user); e != nil {
		response.Body.Close()
		fatal(e)
	}
	response.Body.Close()
	if user.ID == "" {
		fatal(fmt.Errorf("SCIM create response omitted user id"))
	}
	groupRaw := fmt.Sprintf(`{"schemas":[%q],"externalId":%q,"displayName":%q}`, "urn:ietf:params:scim:schemas:core:2.0:Group", "demo-employees-"+suffix, "Employees Demo "+suffix)
	var group struct {
		ID string `json:"id"`
	}
	response = demoRequest(client, base, token, "POST", "/scim/v2/Groups", groupRaw, 201)
	if e = json.NewDecoder(response.Body).Decode(&group); e != nil {
		response.Body.Close()
		fatal(e)
	}
	response.Body.Close()
	if group.ID == "" {
		fatal(fmt.Errorf("SCIM create response omitted group id"))
	}
	demoRequest(client, base, token, "PATCH", "/scim/v2/Groups/"+group.ID, fmt.Sprintf(`{"Operations":[{"op":"add","path":"members","value":[{"value":%q,"type":"User"}]}]}`, user.ID), 200).Body.Close()
	demoRequest(client, base, token, "PATCH", "/scim/v2/Users/"+user.ID, `{"Operations":[{"op":"replace","path":"department","value":"Finance"}]}`, 200).Body.Close()
	demoRequest(client, base, token, "PATCH", "/scim/v2/Groups/"+group.ID, `{"Operations":[{"op":"remove","path":"members"}]}`, 200).Body.Close()
	demoRequest(client, base, token, "PATCH", "/scim/v2/Users/"+user.ID, `{"Operations":[{"op":"replace","path":"active","value":false}]}`, 200).Body.Close()
	response = demoRequest(client, base, token, "GET", "/scim/v2/Users/"+user.ID, "", 200)
	var state struct {
		Active bool `json:"active"`
	}
	_ = json.NewDecoder(response.Body).Decode(&state)
	response.Body.Close()
	if state.Active {
		fatal(fmt.Errorf("suspension was not reflected by GET"))
	}
	response = demoRequest(client, base, token, "PATCH", "/scim/v2/Users/"+user.ID, `{"Operations":[{"op":"replace","path":"active","value":true}]}`, 200)
	etag := response.Header.Get("ETag")
	response.Body.Close()
	if etag == "" {
		fatal(fmt.Errorf("activation response omitted ETag"))
	}
	req, e := http.NewRequest("DELETE", base+"/scim/v2/Users/"+user.ID, nil)
	if e != nil {
		fatal(e)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("If-Match", etag)
	response, e = client.Do(req)
	if e != nil {
		fatal(e)
	}
	if response.StatusCode != 204 {
		b, _ := io.ReadAll(response.Body)
		response.Body.Close()
		fatal(fmt.Errorf("delete user returned %d: %s", response.StatusCode, b))
	}
	response.Body.Close()
	response = demoRequest(client, base, token, "GET", "/scim/v2/Groups/"+group.ID, "", 200)
	etag = response.Header.Get("ETag")
	response.Body.Close()
	req, e = http.NewRequest("DELETE", base+"/scim/v2/Groups/"+group.ID, nil)
	if e != nil {
		fatal(e)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("If-Match", etag)
	response, e = client.Do(req)
	if e != nil {
		fatal(e)
	}
	if response.StatusCode != 204 {
		b, _ := io.ReadAll(response.Body)
		response.Body.Close()
		fatal(fmt.Errorf("delete group returned %d: %s", response.StatusCode, b))
	}
	response.Body.Close()
	fmt.Printf("Demo lifecycle complete: Sam Rivera (%s) created in Support, moved to Finance, removed from Employees, suspended, reactivated, then deprovisioned. Group membership and user resource were deleted.\n", username)
}
func demoRequest(client *http.Client, base, token, method, path, body string, want int) *http.Response {
	req, e := http.NewRequest(method, base+path, strings.NewReader(body))
	if e != nil {
		fatal(e)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/scim+json")
	response, e := client.Do(req)
	if e != nil {
		fatal(e)
	}
	if response.StatusCode != want {
		b, _ := io.ReadAll(response.Body)
		response.Body.Close()
		fatal(fmt.Errorf("demo %s %s returned %d (wanted %d): %s", method, path, response.StatusCode, want, b))
	}
	return response
}
func need(a []string, n int) {
	if len(a) < n {
		usage()
		os.Exit(2)
	}
}
func fatal(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
func usage() {
	fmt.Fprintln(os.Stderr, "provisionctl tenant create <name>|list; token create <tenant-id> [integration]; token list|revoke|rotate <token-id>; oidc configure <tenant-id> <issuer> <client-id> <client-secret> <redirect-url>; identity link <provider-id> <user-id> <subject>; users list <tenant-id>; groups list <tenant-id>; roles seed|list <tenant-id>; roles bind|unbind <tenant-id> <group-id> <role-id>; audit list <tenant-id>")
}
