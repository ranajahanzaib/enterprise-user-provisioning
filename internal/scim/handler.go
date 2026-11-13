package scim

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ranajahanzaib/enterprise-user-provisioning/internal/ratelimit"
)

type Handler struct {
	db      *pgxpool.Pool
	base    string
	limiter ratelimit.Limiter
}

func New(db *pgxpool.Pool, base string) *Handler {
	return &Handler{db: db, base: strings.TrimRight(base, "/")}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json;charset=utf-8")
	if r.URL.Path == "/healthz" {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}
	if r.URL.Path == "/readyz" {
		if h.db.Ping(r.Context()) != nil {
			http.Error(w, "not ready", 503)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/scim/v2/") && !h.limiter.Allow(remoteIP(r), 300, time.Minute, time.Now()) {
		h.fail(w, 429, "request rate limit exceeded", "tooMany", 429)
		return
	}
	tenant, ok := h.authenticate(r)
	if !ok {
		h.fail(w, 401, "invalid or missing bearer token", "invalidToken", http.StatusUnauthorized)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/scim/v2/") {
		h.fail(w, 404, "not found", "", 404)
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/scim/v2/"), "/"), "/")
	if len(parts) == 1 {
		switch parts[0] {
		case "ServiceProviderConfig":
			h.write(w, 200, serviceProviderConfig())
			return
		case "ResourceTypes":
			h.write(w, 200, List{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, TotalResults: 2, StartIndex: 1, ItemsPerPage: 2, Resources: resourceTypes(h.base)})
			return
		case "Schemas":
			all := schemas()
			h.write(w, 200, List{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, TotalResults: len(all), StartIndex: 1, ItemsPerPage: len(all), Resources: all})
			return
		}
	}
	if len(parts) == 2 && parts[0] == "ResourceTypes" {
		if v, ok := resourceTypeByID(h.base, parts[1]); ok {
			h.write(w, 200, v)
		} else {
			h.fail(w, 404, "resource type not found", "", 404)
		}
		return
	}
	if len(parts) == 2 && parts[0] == "Schemas" {
		if v, ok := schemaByID(parts[1]); ok {
			h.write(w, 200, v)
		} else {
			h.fail(w, 404, "schema not found", "", 404)
		}
		return
	}
	if len(parts) < 1 || (parts[0] != "Users" && parts[0] != "Groups") {
		h.fail(w, 404, "resource not found", "", 404)
		return
	}
	switch parts[0] {
	case "Users":
		h.users(w, r, tenant, parts[1:])
	case "Groups":
		h.groups(w, r, tenant, parts[1:])
	}
}
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func (h *Handler) authenticate(r *http.Request) (string, bool) {
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(a, "Bearer ")
	secret := []byte(os.Getenv("TOKEN_HASH_SECRET"))
	if len(secret) < 32 {
		return "", false
	}
	var tenant, expected, tokenID string
	err := h.db.QueryRow(r.Context(), `SELECT p.tenant_id::text,p.token_hash,p.id::text FROM provisioning_tokens p JOIN tenants t ON t.id=p.tenant_id WHERE p.revoked_at IS NULL AND (p.expires_at IS NULL OR p.expires_at>now()) AND p.token_prefix=$1 AND t.active`, prefix(token)).Scan(&tenant, &expected, &tokenID)
	if err != nil {
		return "", false
	}
	got := fingerprint(token, secret)
	valid := subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
	if valid {
		_, _ = h.db.Exec(r.Context(), `UPDATE provisioning_tokens SET last_used_at=now() WHERE id=$1`, tokenID)
	}
	return tenant, valid
}
func prefix(s string) string {
	if len(s) > 20 {
		return s[:20]
	}
	return s
}
func fingerprint(s string, secret []byte) string {
	m := hmac.New(sha256.New, secret)
	_, _ = m.Write([]byte(s))
	return fmt.Sprintf("%x", m.Sum(nil))
}
func (h *Handler) users(w http.ResponseWriter, r *http.Request, t string, p []string) {
	if len(p) == 0 {
		switch r.Method {
		case "GET":
			h.listUsers(w, r, t)
		case "POST":
			h.createUser(w, r, t)
		default:
			w.Header().Set("Allow", "GET, POST")
			h.fail(w, 405, "method not allowed", "", 405)
		}
		return
	}
	id, err := url.PathUnescape(p[0])
	if err != nil {
		h.fail(w, 400, "invalid resource id", "invalidPath", 400)
		return
	}
	switch r.Method {
	case "GET":
		h.getUser(w, r, t, id)
	case "PUT":
		if !h.checkVersion(w, r, t, id, "users") {
			return
		}
		h.replaceUser(w, r, t, id)
	case "PATCH":
		if !h.checkVersion(w, r, t, id, "users") {
			return
		}
		h.patchUser(w, r, t, id)
	case "DELETE":
		h.deleteUser(w, r, t, id)
	default:
		w.Header().Set("Allow", "GET, PUT, PATCH, DELETE")
		h.fail(w, 405, "method not allowed", "", 405)
	}
}
func (h *Handler) createUser(w http.ResponseWriter, r *http.Request, t string) {
	var u User
	if !h.decode(w, r, &u) {
		return
	}
	if u.UserName == "" {
		h.fail(w, 400, "userName is required", "invalidValue", 400)
		return
	}
	if u.Active == nil {
		v := true
		u.Active = &v
	}
	if len(u.Schemas) > 0 && !has(u.Schemas, CoreUser) {
		h.fail(w, 400, "unsupported schema", "invalidSyntax", 400)
		return
	}
	for _, schema := range u.Schemas {
		if schema != CoreUser && schema != EnterpriseUserSchema {
			h.fail(w, 400, "unsupported schema", "invalidSyntax", 400)
			return
		}
	}
	if u.Enterprise.Manager.Value != "" && !managerExists(r.Context(), h.db, t, u.Enterprise.Manager.Value) {
		h.fail(w, 400, "manager must reference a provisioned user in this tenant", "invalidValue", 400)
		return
	}
	if u.Enterprise.Manager.Value != "" {
		var username string
		if e := h.db.QueryRow(r.Context(), `SELECT username FROM users WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, t, u.Enterprise.Manager.Value).Scan(&username); e != nil {
			h.fail(w, 400, "manager must reference a provisioned user in this tenant", "invalidValue", 400)
			return
		}
		u.Enterprise.Manager.DisplayName = username
		u.Enterprise.Manager.Ref = h.base + "/scim/v2/Users/" + u.Enterprise.Manager.Value
	}
	ctx := r.Context()
	tx, err := h.db.Begin(ctx)
	if err != nil {
		h.fail(w, 500, "unable to create user", "", 500)
		return
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `INSERT INTO users(tenant_id,external_id,username,active,given_name,family_name,formatted_name,display_name,title,department,user_type,preferred_language,employee_number,organization_name,division,cost_center,manager,emails) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING id::text,created_at,updated_at,version`, t, null(u.ExternalID), u.UserName, *u.Active, null(u.Name.GivenName), null(u.Name.FamilyName), null(u.Name.Formatted), null(u.DisplayName), null(u.Title), null(u.Department), null(u.UserType), null(u.PreferredLanguage), null(u.Enterprise.EmployeeNumber), null(u.Enterprise.Organization), null(u.Enterprise.Division), null(u.Enterprise.CostCenter), jsonBytes(u.Enterprise.Manager), jsonBytes(u.Emails)).Scan(&u.ID, &u.Meta.Created, &u.Meta.LastModified, &u.Meta.Version)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			h.fail(w, 409, "userName or externalId already exists", "uniqueness", 409)
		} else {
			h.fail(w, 500, "unable to create user", "", 500)
		}
		return
	}
	if _, e := tx.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id) VALUES($1,'scim','user.created','user',$2)`, t, u.ID); e != nil {
		h.fail(w, 500, "unable to record audit event", "", 500)
		return
	}
	if err = tx.Commit(ctx); err != nil {
		h.fail(w, 500, "unable to create user", "", 500)
		return
	}
	u.Schemas = []string{CoreUser}
	if u.Enterprise.EmployeeNumber != "" || u.Enterprise.Organization != "" || u.Enterprise.Division != "" || u.Enterprise.CostCenter != "" || u.Enterprise.Manager.Value != "" {
		u.Schemas = append(u.Schemas, EnterpriseUserSchema)
	}
	u.Meta.ResourceType = "User"
	u.Meta.Location = h.base + "/scim/v2/Users/" + u.ID
	u.Meta.Version = weakETag(u.Meta.Version)
	h.writeResource(w, 201, u, u.Meta.Version)
}
func (h *Handler) getUser(w http.ResponseWriter, r *http.Request, t, id string) {
	u, e := h.loadUser(r.Context(), t, id)
	if e != nil {
		h.dbError(w, e)
		return
	}
	h.writeResource(w, 200, u, u.Meta.Version)
}
func (h *Handler) loadUser(ctx context.Context, t, id string) (User, error) {
	var u User
	var ext, gn, fn, formatted, display, title, dept *string
	var active bool
	var emails []byte
	var userType, lang, employee, org, division, cost *string
	var manager []byte
	e := h.db.QueryRow(ctx, `SELECT id::text,external_id,username,active,given_name,family_name,formatted_name,display_name,title,department,user_type,preferred_language,employee_number,organization_name,division,cost_center,manager,emails,created_at,updated_at,version FROM users WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, t, id).Scan(&u.ID, &ext, &u.UserName, &active, &gn, &fn, &formatted, &display, &title, &dept, &userType, &lang, &employee, &org, &division, &cost, &manager, &emails, &u.Meta.Created, &u.Meta.LastModified, &u.Meta.Version)
	if e != nil {
		return u, e
	}
	u.Schemas = []string{CoreUser}
	u.Active = &active
	u.ExternalID = deref(ext)
	u.Name = Name{deref(gn), deref(fn), deref(formatted)}
	u.DisplayName = deref(display)
	u.Title = deref(title)
	u.Department = deref(dept)
	u.UserType = deref(userType)
	u.PreferredLanguage = deref(lang)
	u.Enterprise.EmployeeNumber = deref(employee)
	u.Enterprise.Organization = deref(org)
	u.Enterprise.Division = deref(division)
	u.Enterprise.CostCenter = deref(cost)
	_ = json.Unmarshal(manager, &u.Enterprise.Manager)
	if u.Enterprise.EmployeeNumber != "" || u.Enterprise.Organization != "" || u.Enterprise.Division != "" || u.Enterprise.CostCenter != "" || u.Enterprise.Manager.Value != "" {
		u.Schemas = append(u.Schemas, EnterpriseUserSchema)
	}
	if u.Enterprise.Manager.Value != "" {
		var username string
		if e = h.db.QueryRow(ctx, `SELECT username FROM users WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, t, u.Enterprise.Manager.Value).Scan(&username); e != nil {
			return u, e
		}
		u.Enterprise.Manager.DisplayName = username
		u.Enterprise.Manager.Ref = h.base + "/scim/v2/Users/" + u.Enterprise.Manager.Value
	}
	_ = json.Unmarshal(emails, &u.Emails)
	rows, e := h.db.Query(ctx, `SELECT g.id::text,g.display_name FROM group_members gm JOIN groups g ON g.tenant_id=gm.tenant_id AND g.id=gm.group_id WHERE gm.tenant_id=$1 AND gm.user_id=$2 ORDER BY g.display_name`, t, id)
	if e != nil {
		return u, e
	}
	defer rows.Close()
	u.Groups = []Member{}
	for rows.Next() {
		var m Member
		if e = rows.Scan(&m.Value, &m.Display); e != nil {
			return u, e
		}
		m.Type = "direct"
		m.Ref = h.base + "/scim/v2/Groups/" + m.Value
		u.Groups = append(u.Groups, m)
	}
	if e = rows.Err(); e != nil {
		return u, e
	}
	u.Meta.ResourceType = "User"
	u.Meta.Location = h.base + "/scim/v2/Users/" + u.ID
	return u, nil
}
func (h *Handler) replaceUser(w http.ResponseWriter, r *http.Request, t, id string) {
	var in User
	if !h.decode(w, r, &in) {
		return
	}
	if in.UserName == "" {
		h.fail(w, 400, "userName is required", "invalidValue", 400)
		return
	}
	active := true
	if in.Active != nil {
		active = *in.Active
	}
	if in.Enterprise.Manager.Value != "" && !managerExists(r.Context(), h.db, t, in.Enterprise.Manager.Value) {
		h.fail(w, 400, "manager must reference a provisioned user in this tenant", "invalidValue", 400)
		return
	}
	tx, e := h.db.Begin(r.Context())
	if e != nil {
		h.fail(w, 500, "unable to update user", "", 500)
		return
	}
	defer tx.Rollback(r.Context())
	var previous bool
	var currentVersion string
	if e = tx.QueryRow(r.Context(), `SELECT active,version::text FROM users WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, t, id).Scan(&previous, &currentVersion); e != nil {
		h.dbError(w, e)
		return
	}
	if !matchesIfMatch(r.Header.Get("If-Match"), currentVersion) {
		h.fail(w, 412, "resource version does not match", "", 412)
		return
	}
	if in.Enterprise.Manager.Value != "" && !managerExists(r.Context(), tx, t, in.Enterprise.Manager.Value) {
		h.fail(w, 400, "manager must reference a provisioned user in this tenant", "invalidValue", 400)
		return
	}
	_, e = tx.Exec(r.Context(), `UPDATE users SET external_id=$3,username=$4,active=$5,given_name=$6,family_name=$7,formatted_name=$8,display_name=$9,title=$10,department=$11,user_type=$12,preferred_language=$13,employee_number=$14,organization_name=$15,division=$16,cost_center=$17,manager=$18,emails=$19,updated_at=now(),version=version+1 WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, t, id, null(in.ExternalID), in.UserName, active, null(in.Name.GivenName), null(in.Name.FamilyName), null(in.Name.Formatted), null(in.DisplayName), null(in.Title), null(in.Department), null(in.UserType), null(in.PreferredLanguage), null(in.Enterprise.EmployeeNumber), null(in.Enterprise.Organization), null(in.Enterprise.Division), null(in.Enterprise.CostCenter), jsonBytes(in.Enterprise.Manager), jsonBytes(in.Emails))
	if e != nil {
		if strings.Contains(e.Error(), "unique") {
			h.fail(w, 409, "username or externalId already exists", "uniqueness", 409)
		} else {
			h.fail(w, 500, "unable to update user", "", 500)
		}
		return
	}
	if !active {
		_, e = tx.Exec(r.Context(), `UPDATE app_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL`, t, id)
		if e != nil {
			h.fail(w, 500, "unable to revoke sessions", "", 500)
			return
		}
	}
	action := "user.updated"
	if previous && !active {
		action = "user.suspended"
	}
	if !previous && active {
		action = "user.reactivated"
	}
	if _, e = tx.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id) VALUES($1,'scim',$2,'user',$3)`, t, action, id); e != nil {
		h.fail(w, 500, "unable to record audit event", "", 500)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		h.fail(w, 500, "unable to update user", "", 500)
		return
	}
	u, e := h.loadUser(r.Context(), t, id)
	if e != nil {
		h.dbError(w, e)
		return
	}
	h.writeResource(w, 200, u, u.Meta.Version)
}
func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request, t, id string) {
	var body struct {
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if !h.decode(w, r, &body) {
		return
	}
	if len(body.Operations) == 0 {
		h.fail(w, 400, "Operations is required", "invalidValue", 400)
		return
	}
	u, e := h.loadUser(r.Context(), t, id)
	if e != nil {
		h.dbError(w, e)
		return
	}
	tx, e := h.db.Begin(r.Context())
	if e != nil {
		h.fail(w, 500, "unable to update user", "", 500)
		return
	}
	defer tx.Rollback(r.Context())
	if !lockVersion(h, w, r, tx, t, id, "users") {
		return
	}
	for _, op := range body.Operations {
		switch strings.ToLower(op.Op) {
		case "replace", "add":
			path := strings.ToLower(op.Path)
			if path == "" {
				if invalid := patchUserObject(r.Context(), tx, t, id, op.Value); invalid != nil {
					h.fail(w, 400, invalid.Error(), "invalidValue", 400)
					return
				}
				break
			}
			path = strings.TrimPrefix(path, strings.ToLower(EnterpriseUserSchema)+":")
			switch path {
			case "active":
				var v bool
				if json.Unmarshal(op.Value, &v) != nil {
					h.fail(w, 400, "active must be boolean", "invalidValue", 400)
					return
				}
				_, e = tx.Exec(r.Context(), `UPDATE users SET active=$3 WHERE tenant_id=$1 AND id=$2`, t, id, v)
			case "displayname":
				var v string
				if json.Unmarshal(op.Value, &v) != nil {
					h.fail(w, 400, "displayName must be string", "invalidValue", 400)
					return
				}
				_, e = tx.Exec(r.Context(), `UPDATE users SET display_name=$3 WHERE tenant_id=$1 AND id=$2`, t, id, null(v))
			case "department":
				var v string
				if json.Unmarshal(op.Value, &v) != nil {
					h.fail(w, 400, "department must be string", "invalidValue", 400)
					return
				}
				_, e = tx.Exec(r.Context(), `UPDATE users SET department=$3 WHERE tenant_id=$1 AND id=$2`, t, id, null(v))
			case "name.familyname":
				var v string
				if json.Unmarshal(op.Value, &v) != nil {
					h.fail(w, 400, "familyName must be string", "invalidValue", 400)
					return
				}
				_, e = tx.Exec(r.Context(), `UPDATE users SET family_name=$3 WHERE tenant_id=$1 AND id=$2`, t, id, null(v))
			case "name.givenname", "name.formatted", "title", "usertype", "preferredlanguage", "externalid", "employeenumber", "organization", "division", "costcenter", "manager":
				if path == "manager" {
					var m Manager
					if json.Unmarshal(op.Value, &m) != nil {
						h.fail(w, 400, "manager must be an object", "invalidValue", 400)
						return
					}
					if m.Value != "" && !managerExists(r.Context(), tx, t, m.Value) {
						h.fail(w, 400, "manager must reference a provisioned user in this tenant", "invalidValue", 400)
						return
					}
					_, e = tx.Exec(r.Context(), `UPDATE users SET manager=$3 WHERE tenant_id=$1 AND id=$2`, t, id, jsonBytes(m))
				} else {
					var v string
					if json.Unmarshal(op.Value, &v) != nil {
						h.fail(w, 400, "attribute must be a string", "invalidValue", 400)
						return
					}
					column := map[string]string{"name.givenname": "given_name", "name.formatted": "formatted_name", "title": "title", "usertype": "user_type", "preferredlanguage": "preferred_language", "externalid": "external_id", "employeenumber": "employee_number", "organization": "organization_name", "division": "division", "costcenter": "cost_center"}[path]
					_, e = tx.Exec(r.Context(), `UPDATE users SET `+column+`=$3 WHERE tenant_id=$1 AND id=$2`, t, id, null(v))
				}
			case "emails":
				var emails []Email
				if json.Unmarshal(op.Value, &emails) != nil {
					h.fail(w, 400, "emails must be an array", "invalidValue", 400)
					return
				}
				for _, email := range emails {
					if email.Value == "" {
						h.fail(w, 400, "email value is required", "invalidValue", 400)
						return
					}
				}
				_, e = tx.Exec(r.Context(), `UPDATE users SET emails=$3 WHERE tenant_id=$1 AND id=$2`, t, id, jsonBytes(emails))
			default:
				h.fail(w, 400, "unsupported PATCH path", "invalidPath", 400)
				return
			}
		case "remove":
			path := strings.ToLower(op.Path)
			path = strings.TrimPrefix(path, strings.ToLower(EnterpriseUserSchema)+":")
			columns := map[string]string{"displayname": "display_name", "department": "department", "name.familyname": "family_name", "name.givenname": "given_name", "name.formatted": "formatted_name", "title": "title", "usertype": "user_type", "preferredlanguage": "preferred_language", "externalid": "external_id", "employeenumber": "employee_number", "organization": "organization_name", "division": "division", "costcenter": "cost_center"}
			if path == "active" {
				_, e = tx.Exec(r.Context(), `UPDATE users SET active=true WHERE tenant_id=$1 AND id=$2`, t, id)
			} else if path == "emails" {
				_, e = tx.Exec(r.Context(), `UPDATE users SET emails='[]'::jsonb WHERE tenant_id=$1 AND id=$2`, t, id)
			} else if path == "manager" {
				_, e = tx.Exec(r.Context(), `UPDATE users SET manager='{}'::jsonb WHERE tenant_id=$1 AND id=$2`, t, id)
			} else if column, ok := columns[path]; ok {
				_, e = tx.Exec(r.Context(), `UPDATE users SET `+column+`=NULL WHERE tenant_id=$1 AND id=$2`, t, id)
			} else {
				h.fail(w, 400, "unsupported or read-only PATCH path", "invalidPath", 400)
				return
			}
		default:
			h.fail(w, 400, "unsupported PATCH operation", "invalidSyntax", 400)
			return
		}
		if e != nil {
			if strings.Contains(e.Error(), "unique") {
				h.fail(w, 409, "username or externalId already exists", "uniqueness", 409)
			} else {
				h.fail(w, 500, "unable to update user", "", 500)
			}
			return
		}
	}
	_, e = tx.Exec(r.Context(), `UPDATE users SET updated_at=now(),version=version+1 WHERE tenant_id=$1 AND id=$2`, t, id)
	if e != nil {
		h.fail(w, 500, "unable to update user", "", 500)
		return
	}
	var isActive bool
	if e = tx.QueryRow(r.Context(), `SELECT active FROM users WHERE tenant_id=$1 AND id=$2`, t, id).Scan(&isActive); e != nil {
		h.fail(w, 500, "unable to update user", "", 500)
		return
	}
	if !isActive {
		if _, e = tx.Exec(r.Context(), `UPDATE app_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL`, t, id); e != nil {
			h.fail(w, 500, "unable to revoke sessions", "", 500)
			return
		}
	}
	action := "user.updated"
	if u.Active != nil && *u.Active && !isActive {
		action = "user.suspended"
	}
	if u.Active != nil && !*u.Active && isActive {
		action = "user.reactivated"
	}
	if _, e = tx.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id) VALUES($1,'scim',$2,'user',$3)`, t, action, id); e != nil {
		h.fail(w, 500, "unable to record audit event", "", 500)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		h.fail(w, 500, "unable to update user", "", 500)
		return
	}
	u, e = h.loadUser(r.Context(), t, id)
	if e != nil {
		h.dbError(w, e)
		return
	}
	h.writeResource(w, 200, u, u.Meta.Version)
}
func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, t, id string) {
	if !h.checkVersion(w, r, t, id, "users") {
		return
	}
	tx, e := h.db.Begin(r.Context())
	if e != nil {
		h.fail(w, 500, "unable to delete user", "", 500)
		return
	}
	defer tx.Rollback(r.Context())
	if !lockVersion(h, w, r, tx, t, id, "users") {
		return
	}
	ct, e := tx.Exec(r.Context(), `UPDATE users SET deleted_at=now(),active=false,updated_at=now(),version=version+1 WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, t, id)
	if e != nil {
		h.fail(w, 500, "unable to delete user", "", 500)
		return
	}
	if ct.RowsAffected() == 0 {
		h.fail(w, 404, "user not found", "", 404)
		return
	}
	if _, e = tx.Exec(r.Context(), `UPDATE app_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL`, t, id); e != nil {
		h.fail(w, 500, "unable to revoke sessions", "", 500)
		return
	}
	rows, e := tx.Query(r.Context(), `DELETE FROM group_members WHERE tenant_id=$1 AND user_id=$2 RETURNING group_id::text`, t, id)
	if e != nil {
		h.fail(w, 500, "unable to remove memberships", "", 500)
		return
	}
	for rows.Next() {
		var groupID string
		if e = rows.Scan(&groupID); e != nil {
			rows.Close()
			h.fail(w, 500, "unable to remove memberships", "", 500)
			return
		}
		if _, e = tx.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id,details) VALUES($1,'scim','membership.removed','group',$2,jsonb_build_object('user_id',$3::text))`, t, groupID, id); e != nil {
			rows.Close()
			h.fail(w, 500, "unable to record audit event", "", 500)
			return
		}
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		h.fail(w, 500, "unable to remove memberships", "", 500)
		return
	}
	rows.Close()
	if _, e = tx.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id) VALUES($1,'scim','user.deleted','user',$2)`, t, id); e != nil {
		h.fail(w, 500, "unable to record audit event", "", 500)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		h.fail(w, 500, "unable to delete user", "", 500)
		return
	}
	w.WriteHeader(204)
}
func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request, t string) {
	start, count := page(r)
	filter := r.URL.Query().Get("filter")
	where, args, e := compileFilter(filter, map[string]filterColumn{"userName": {"username", false}, "externalId": {"external_id", true}, "id": {"id::text", true}, "displayName": {"display_name", false}}, 2)
	if e != nil {
		h.fail(w, 400, e.Error(), "invalidFilter", 400)
		return
	}
	args = append([]any{t}, args...)
	var total int
	if e = h.db.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE tenant_id=$1 AND deleted_at IS NULL`+where, args...).Scan(&total); e != nil {
		h.fail(w, 500, "unable to list users", "", 500)
		return
	}
	rows, e := h.db.Query(r.Context(), `SELECT id::text FROM users WHERE tenant_id=$1 AND deleted_at IS NULL`+where+fmt.Sprintf(" ORDER BY username,id LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2), append(args, count, start-1)...)
	if e != nil {
		h.fail(w, 500, "unable to list users", "", 500)
		return
	}
	defer rows.Close()
	list := []User{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			h.fail(w, 500, "unable to list users", "", 500)
			return
		}
		u, e := h.loadUser(r.Context(), t, id)
		if e != nil {
			h.fail(w, 500, "unable to list users", "", 500)
			return
		}
		list = append(list, u)
	}
	if e = rows.Err(); e != nil {
		h.fail(w, 500, "unable to list users", "", 500)
		return
	}
	h.write(w, 200, List{[]string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, total, start, len(list), list})
}
func (h *Handler) groups(w http.ResponseWriter, r *http.Request, t string, p []string) {
	if len(p) == 0 {
		if r.Method == "POST" {
			h.createGroup(w, r, t)
			return
		}
		if r.Method == "GET" {
			h.listGroups(w, r, t)
			return
		}
	}
	if len(p) > 0 {
		if r.Method == "PATCH" || r.Method == "PUT" || r.Method == "DELETE" {
			if !h.checkVersion(w, r, t, p[0], "groups") {
				return
			}
		}
		switch r.Method {
		case "GET":
			g, e := h.loadGroup(r.Context(), t, p[0])
			if e != nil {
				h.dbError(w, e)
			} else {
				h.writeResource(w, 200, g, g.Meta.Version)
			}
		case "DELETE":
			tx, e := h.db.Begin(r.Context())
			if e != nil {
				h.fail(w, 500, "unable to delete group", "", 500)
				return
			}
			defer tx.Rollback(r.Context())
			if !lockVersion(h, w, r, tx, t, p[0], "groups") {
				return
			}
			members, e := membershipIDs(r.Context(), tx, t, p[0])
			if e != nil {
				h.fail(w, 500, "unable to read group memberships", "", 500)
				return
			}
			for uid := range members {
				if _, e = tx.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id,details) VALUES($1,'scim','membership.removed','group',$2,jsonb_build_object('user_id',$3::text))`, t, p[0], uid); e != nil {
					h.fail(w, 500, "unable to record audit event", "", 500)
					return
				}
			}
			ct, e := tx.Exec(r.Context(), `DELETE FROM groups WHERE tenant_id=$1 AND id=$2`, t, p[0])
			if e != nil {
				h.fail(w, 500, "unable to delete group", "", 500)
			} else if ct.RowsAffected() == 0 {
				h.fail(w, 404, "group not found", "", 404)
			} else {
				_, e = tx.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id) VALUES($1,'scim','group.deleted','group',$2)`, t, p[0])
				if e != nil {
					h.fail(w, 500, "unable to record audit event", "", 500)
					return
				}
				if e = tx.Commit(r.Context()); e != nil {
					h.fail(w, 500, "unable to delete group", "", 500)
					return
				}
				w.WriteHeader(204)
			}
		case "PUT":
			h.replaceGroup(w, r, t, p[0])
		case "PATCH":
			h.patchGroup(w, r, t, p[0])
		default:
			h.fail(w, 405, "method not allowed", "", 405)
		}
		return
	}
	h.fail(w, 405, "method not allowed", "", 405)
}
func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request, t string) {
	var g Group
	if !h.decode(w, r, &g) {
		return
	}
	if g.DisplayName == "" {
		h.fail(w, 400, "displayName is required", "invalidValue", 400)
		return
	}
	if len(g.Schemas) > 0 && !has(g.Schemas, CoreGroup) {
		h.fail(w, 400, "unsupported schema", "invalidSyntax", 400)
		return
	}
	tx, e := h.db.Begin(r.Context())
	if e != nil {
		h.fail(w, 500, "unable to create group", "", 500)
		return
	}
	defer tx.Rollback(r.Context())
	e = tx.QueryRow(r.Context(), `INSERT INTO groups(tenant_id,external_id,display_name) VALUES($1,$2,$3) RETURNING id::text,created_at,updated_at,version`, t, null(g.ExternalID), g.DisplayName).Scan(&g.ID, &g.Meta.Created, &g.Meta.LastModified, &g.Meta.Version)
	if e != nil {
		h.fail(w, 409, "group already exists or could not be created", "uniqueness", 409)
		return
	}
	for _, m := range g.Members {
		if !validMemberShape(m, h.base) {
			h.fail(w, 400, "invalid group member reference", "invalidValue", 400)
			return
		}
		var ct pgconn.CommandTag
		ct, e = tx.Exec(r.Context(), `INSERT INTO group_members(tenant_id,group_id,user_id) SELECT $1,$2,id FROM users WHERE tenant_id=$1 AND id=$3 AND deleted_at IS NULL`, t, g.ID, m.Value)
		if e != nil {
			h.fail(w, 400, "invalid group member", "invalidValue", 400)
			return
		}
		if ct.RowsAffected() != 1 {
			h.fail(w, 400, "invalid group member", "invalidValue", 400)
			return
		}
		if _, e = tx.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id,details) VALUES($1,'scim','membership.added','group',$2,jsonb_build_object('user_id',$3::text))`, t, g.ID, m.Value); e != nil {
			h.fail(w, 500, "unable to record audit event", "", 500)
			return
		}
	}
	if _, e = tx.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id) VALUES($1,'scim','group.created','group',$2)`, t, g.ID); e != nil {
		h.fail(w, 500, "unable to record audit event", "", 500)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		h.fail(w, 500, "unable to create group", "", 500)
		return
	}
	g, e = h.loadGroup(r.Context(), t, g.ID)
	if e != nil {
		h.fail(w, 500, "unable to load group", "", 500)
		return
	}
	h.writeResource(w, 201, g, g.Meta.Version)
}
func (h *Handler) replaceGroup(w http.ResponseWriter, r *http.Request, t, id string) {
	var in Group
	if !h.decode(w, r, &in) {
		return
	}
	if in.DisplayName == "" {
		h.fail(w, 400, "displayName is required", "invalidValue", 400)
		return
	}
	tx, e := h.db.Begin(r.Context())
	if e != nil {
		h.fail(w, 500, "unable to update group", "", 500)
		return
	}
	defer tx.Rollback(r.Context())
	if !lockVersion(h, w, r, tx, t, id, "groups") {
		return
	}
	before, e := membershipIDs(r.Context(), tx, t, id)
	if e != nil {
		h.fail(w, 500, "unable to read group memberships", "", 500)
		return
	}
	var exists bool
	if e = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM groups WHERE tenant_id=$1 AND id=$2)`, t, id).Scan(&exists); e != nil || !exists {
		h.fail(w, 404, "group not found", "", 404)
		return
	}
	if _, e = tx.Exec(r.Context(), `UPDATE groups SET external_id=$3,display_name=$4,updated_at=now(),version=version+1 WHERE tenant_id=$1 AND id=$2`, t, id, null(in.ExternalID), in.DisplayName); e != nil {
		h.fail(w, 409, "group name or externalId already exists", "uniqueness", 409)
		return
	}
	if _, e = tx.Exec(r.Context(), `DELETE FROM group_members WHERE tenant_id=$1 AND group_id=$2`, t, id); e != nil {
		h.fail(w, 500, "unable to replace memberships", "", 500)
		return
	}
	for _, m := range in.Members {
		if !validMemberShape(m, h.base) {
			h.fail(w, 400, "invalid group member reference", "invalidValue", 400)
			return
		}
		ct, err := tx.Exec(r.Context(), `INSERT INTO group_members(tenant_id,group_id,user_id) SELECT $1,$2,id FROM users WHERE tenant_id=$1 AND id=$3 AND deleted_at IS NULL ON CONFLICT DO NOTHING`, t, id, m.Value)
		if err != nil {
			h.fail(w, 400, "invalid group member", "invalidValue", 400)
			return
		}
		if ct.RowsAffected() == 0 {
			var present bool
			_ = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM group_members WHERE tenant_id=$1 AND group_id=$2 AND user_id=$3)`, t, id, m.Value).Scan(&present)
			if !present {
				h.fail(w, 400, "invalid group member", "invalidValue", 400)
				return
			}
		}
	}
	if !recordMembershipDiff(r.Context(), tx, t, id, before) {
		h.fail(w, 500, "unable to record membership changes", "", 500)
		return
	}
	if _, e = tx.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id) VALUES($1,'scim','group.updated','group',$2)`, t, id); e != nil {
		h.fail(w, 500, "unable to record audit event", "", 500)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		h.fail(w, 500, "unable to update group", "", 500)
		return
	}
	g, e := h.loadGroup(r.Context(), t, id)
	if e != nil {
		h.dbError(w, e)
		return
	}
	h.writeResource(w, 200, g, g.Meta.Version)
}
func (h *Handler) loadGroup(ctx context.Context, t, id string) (Group, error) {
	var g Group
	var ext *string
	e := h.db.QueryRow(ctx, `SELECT id::text,external_id,display_name,created_at,updated_at,version FROM groups WHERE tenant_id=$1 AND id=$2`, t, id).Scan(&g.ID, &ext, &g.DisplayName, &g.Meta.Created, &g.Meta.LastModified, &g.Meta.Version)
	if e != nil {
		return g, e
	}
	g.ExternalID = deref(ext)
	g.Schemas = []string{CoreGroup}
	g.Meta.ResourceType = "Group"
	g.Meta.Location = h.base + "/scim/v2/Groups/" + id
	g.Meta.Version = weakETag(g.Meta.Version)
	rows, e := h.db.Query(ctx, `SELECT u.id::text,u.username FROM group_members gm JOIN users u ON u.tenant_id=gm.tenant_id AND u.id=gm.user_id WHERE gm.tenant_id=$1 AND gm.group_id=$2 AND u.deleted_at IS NULL ORDER BY u.username`, t, id)
	if e != nil {
		return g, e
	}
	defer rows.Close()
	g.Members = []Member{}
	for rows.Next() {
		var m Member
		if e = rows.Scan(&m.Value, &m.Display); e != nil {
			return g, e
		}
		m.Type = "User"
		m.Ref = h.base + "/scim/v2/Users/" + m.Value
		g.Members = append(g.Members, m)
	}
	return g, rows.Err()
}
func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request, t string) {
	start, count := page(r)
	filters, args, err := compileFilter(r.URL.Query().Get("filter"), map[string]filterColumn{"displayName": {"display_name", false}, "externalId": {"external_id", true}, "id": {"id::text", true}}, 2)
	if err != nil {
		h.fail(w, 400, err.Error(), "invalidFilter", 400)
		return
	}
	var total int
	if err = h.db.QueryRow(r.Context(), `SELECT count(*) FROM groups WHERE tenant_id=$1`+filters, append([]any{t}, args...)...).Scan(&total); err != nil {
		h.fail(w, 500, "unable to list groups", "", 500)
		return
	}
	rows, e := h.db.Query(r.Context(), `SELECT id::text FROM groups WHERE tenant_id=$1`+filters+fmt.Sprintf(" ORDER BY display_name,id LIMIT $%d OFFSET $%d", len(args)+2, len(args)+3), append(append([]any{t}, args...), count, start-1)...)
	if e != nil {
		h.fail(w, 500, "unable to list groups", "", 500)
		return
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			h.fail(w, 500, "unable to list groups", "", 500)
			return
		}
		g, e := h.loadGroup(r.Context(), t, id)
		if e != nil {
			h.fail(w, 500, "unable to list groups", "", 500)
			return
		}
		out = append(out, g)
	}
	if e = rows.Err(); e != nil {
		h.fail(w, 500, "unable to list groups", "", 500)
		return
	}
	h.write(w, 200, List{[]string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, total, start, len(out), out})
}
func (h *Handler) patchGroup(w http.ResponseWriter, r *http.Request, t, id string) {
	var b struct {
		Operations []struct {
			Op, Path string
			Value    json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if !h.decode(w, r, &b) {
		return
	}
	tx, e := h.db.Begin(r.Context())
	if e != nil {
		h.fail(w, 500, "unable to update group", "", 500)
		return
	}
	defer tx.Rollback(r.Context())
	if !lockVersion(h, w, r, tx, t, id, "groups") {
		return
	}
	before, e := membershipIDs(r.Context(), tx, t, id)
	if e != nil {
		h.fail(w, 500, "unable to read group memberships", "", 500)
		return
	}
	for _, o := range b.Operations {
		p := strings.ToLower(o.Path)
		switch strings.ToLower(o.Op) {
		case "add", "replace":
			if p == "" {
				if err := patchGroupObject(r.Context(), tx, t, id, o.Value, strings.ToLower(o.Op), h.base); err != nil {
					h.fail(w, 400, err.Error(), "invalidValue", 400)
					return
				}
				break
			}
			if p != "members" {
				h.fail(w, 400, "unsupported PATCH path", "invalidPath", 400)
				return
			}
			var ms []Member
			if json.Unmarshal(o.Value, &ms) != nil {
				var m Member
				if json.Unmarshal(o.Value, &m) != nil {
					h.fail(w, 400, "invalid members value", "invalidValue", 400)
					return
				}
				ms = []Member{m}
			}
			if strings.ToLower(o.Op) == "replace" {
				_, e = tx.Exec(r.Context(), `DELETE FROM group_members WHERE tenant_id=$1 AND group_id=$2`, t, id)
			}
			for _, m := range ms {
				if !validMemberShape(m, h.base) {
					h.fail(w, 400, "invalid group member reference", "invalidValue", 400)
					return
				}
				var ct pgconn.CommandTag
				ct, e = tx.Exec(r.Context(), `INSERT INTO group_members(tenant_id,group_id,user_id) SELECT $1,$2,id FROM users WHERE tenant_id=$1 AND id=$3 AND deleted_at IS NULL ON CONFLICT DO NOTHING`, t, id, m.Value)
				if e != nil {
					h.fail(w, 400, "invalid group member", "invalidValue", 400)
					return
				}
				if ct.RowsAffected() != 1 {
					var exists bool
					_ = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM group_members WHERE tenant_id=$1 AND group_id=$2 AND user_id=$3)`, t, id, m.Value).Scan(&exists)
					if !exists {
						h.fail(w, 400, "invalid group member", "invalidValue", 400)
						return
					}
				}
			}
		case "remove":
			if strings.EqualFold(o.Path, "members") {
				_, e = tx.Exec(r.Context(), `DELETE FROM group_members WHERE tenant_id=$1 AND group_id=$2`, t, id)
			} else {
				memberPath := regexp.MustCompile(`(?i)^members\[value eq "([^"\\]+)"\]$`)
				match := memberPath.FindStringSubmatch(o.Path)
				if match == nil {
					h.fail(w, 400, "unsupported PATCH path", "invalidPath", 400)
					return
				}
				_, e = tx.Exec(r.Context(), `DELETE FROM group_members WHERE tenant_id=$1 AND group_id=$2 AND user_id=$3`, t, id, match[1])
			}
		default:
			h.fail(w, 400, "unsupported PATCH operation", "invalidSyntax", 400)
			return
		}
		if e != nil {
			if strings.Contains(e.Error(), "unique") {
				h.fail(w, 409, "group displayName or externalId already exists", "uniqueness", 409)
			} else {
				h.fail(w, 500, "unable to update group", "", 500)
			}
			return
		}
	}
	_, e = tx.Exec(r.Context(), `UPDATE groups SET updated_at=now(),version=version+1 WHERE tenant_id=$1 AND id=$2`, t, id)
	if e == nil {
		if !recordMembershipDiff(r.Context(), tx, t, id, before) {
			e = fmt.Errorf("membership audit insert failed")
		}
	}
	if e == nil {
		_, e = tx.Exec(r.Context(), `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id) VALUES($1,'scim','group.updated','group',$2)`, t, id)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		if strings.Contains(e.Error(), "unique") {
			h.fail(w, 409, "group displayName or externalId already exists", "uniqueness", 409)
		} else {
			h.fail(w, 500, "unable to update group", "", 500)
		}
		return
	}
	g, e := h.loadGroup(r.Context(), t, id)
	if e != nil {
		h.dbError(w, e)
		return
	}
	h.writeResource(w, 200, g, g.Meta.Version)
}
func (h *Handler) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(e, &tooLarge) {
			h.fail(w, 413, "request body exceeds the 1 MiB limit", "tooLarge", 413)
		} else {
			h.fail(w, 400, "invalid JSON or unsupported attribute", "invalidSyntax", 400)
		}
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		h.fail(w, 400, "request must contain one JSON value", "invalidSyntax", 400)
		return false
	}
	return true
}
func (h *Handler) dbError(w http.ResponseWriter, e error) {
	if e == pgx.ErrNoRows {
		h.fail(w, 404, "resource not found", "", 404)
	} else {
		h.fail(w, 500, "database operation failed", "", 500)
	}
}
func (h *Handler) fail(w http.ResponseWriter, code int, msg, typ string, status int) {
	h.write(w, status, Error{[]string{ErrorSchema}, msg, strconv.Itoa(code), typ})
}
func (h *Handler) write(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	if status != 204 {
		_ = json.NewEncoder(w).Encode(v)
	}
}
func (h *Handler) writeResource(w http.ResponseWriter, status int, v any, version string) {
	w.Header().Set("ETag", version)
	h.write(w, status, v)
}
func weakETag(v string) string {
	if strings.HasPrefix(v, `W/"`) {
		return v
	}
	return `W/"` + v + `"`
}
func (h *Handler) checkVersion(w http.ResponseWriter, r *http.Request, tenant, id, table string) bool {
	tag := strings.TrimSpace(r.Header.Get("If-Match"))
	if tag == "" || tag == "*" {
		return true
	}
	if table != "users" && table != "groups" {
		h.fail(w, 500, "resource operation failed", "", 500)
		return false
	}
	deletedClause := map[string]string{"users": " AND deleted_at IS NULL", "groups": ""}[table]
	var current string
	err := h.db.QueryRow(r.Context(), `SELECT version::text FROM `+table+` WHERE tenant_id=$1 AND id=$2`+deletedClause, tenant, id).Scan(&current)
	if err != nil {
		h.dbError(w, err)
		return false
	}
	for _, candidate := range strings.Split(tag, ",") {
		if matchesIfMatch(candidate, current) {
			return true
		}
	}
	h.fail(w, 412, "resource version does not match", "", 412)
	return false
}
func matchesIfMatch(tag, version string) bool {
	tag = strings.TrimSpace(tag)
	if tag == "" || tag == "*" {
		return true
	}
	tag = strings.TrimPrefix(tag, "W/")
	return strings.Trim(tag, `"`) == version
}
func lockVersion(h *Handler, w http.ResponseWriter, r *http.Request, tx pgx.Tx, tenant, id, table string) bool {
	if table != "users" && table != "groups" {
		h.fail(w, 500, "resource operation failed", "", 500)
		return false
	}
	clause := ""
	if table == "users" {
		clause = " AND deleted_at IS NULL"
	}
	var version string
	err := tx.QueryRow(r.Context(), `SELECT version::text FROM `+table+` WHERE tenant_id=$1 AND id=$2`+clause+` FOR UPDATE`, tenant, id).Scan(&version)
	if err != nil {
		h.dbError(w, err)
		return false
	}
	if !matchesIfMatch(r.Header.Get("If-Match"), version) {
		h.fail(w, 412, "resource version does not match", "", 412)
		return false
	}
	return true
}
func page(r *http.Request) (int, int) {
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if start < 1 {
		start = 1
	}
	if count < 1 {
		count = 100
	}
	if count > 200 {
		count = 200
	}
	return start, count
}

type filterColumn struct {
	sql   string
	exact bool
}

var filterTerm = regexp.MustCompile(`(?i)^\s*([a-z][a-zA-Z0-9.]*)\s+(eq|co|sw|pr)\s*(?:"((?:[^"\\]|\\.)*)")?\s*$`)

func compileFilter(f string, columns map[string]filterColumn, start int) (string, []any, error) {
	if strings.TrimSpace(f) == "" {
		return "", nil, nil
	}
	terms, err := splitFilterAnd(f)
	if err != nil {
		return "", nil, err
	}
	clauses := make([]string, 0, len(terms))
	args := make([]any, 0, len(terms))
	for _, term := range terms {
		m := filterTerm.FindStringSubmatch(term)
		if m == nil {
			return "", nil, fmt.Errorf("unsupported or malformed filter")
		}
		c, ok := columns[strings.ToLower(m[1])]
		if !ok {
			for name, col := range columns {
				if strings.EqualFold(name, m[1]) {
					c = col
					ok = true
					break
				}
			}
		}
		if !ok {
			return "", nil, fmt.Errorf("unsupported filter attribute")
		}
		op := strings.ToLower(m[2])
		n := start + len(args)
		switch op {
		case "pr":
			if m[3] != "" {
				return "", nil, fmt.Errorf("pr does not accept a value")
			}
			clauses = append(clauses, "("+c.sql+" IS NOT NULL AND "+c.sql+"::text <> '')")
		case "eq", "co", "sw":
			if m[3] == "" {
				return "", nil, fmt.Errorf("filter value must be quoted")
			}
			v := strings.ReplaceAll(strings.ReplaceAll(m[3], `\"`, `"`), `\\`, `\`)
			switch op {
			case "eq":
				if c.exact {
					clauses = append(clauses, c.sql+fmt.Sprintf("=$%d", n))
				} else {
					clauses = append(clauses, "lower("+c.sql+fmt.Sprintf("::text)=lower($%d)", n))
				}
				args = append(args, v)
			case "co":
				clauses = append(clauses, fmt.Sprintf("position(lower($%d) in lower(%s::text))>0", n, c.sql))
				args = append(args, v)
			case "sw":
				clauses = append(clauses, fmt.Sprintf("left(lower(%s::text),char_length($%d))=lower($%d)", c.sql, n, n))
				args = append(args, v)
			}
		}
	}
	return " AND (" + strings.Join(clauses, ") AND (") + ")", args, nil
}
func splitFilterAnd(s string) ([]string, error) {
	parts := []string{}
	start := 0
	quoted, escaped := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if quoted && c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			quoted = !quoted
			continue
		}
		if !quoted && i+5 <= len(s) && strings.EqualFold(s[i:i+5], " and ") {
			parts = append(parts, strings.TrimSpace(s[start:i]))
			start = i + 5
			i += 4
		}
	}
	if quoted {
		return nil, fmt.Errorf("unterminated filter string")
	}
	parts = append(parts, strings.TrimSpace(s[start:]))
	return parts, nil
}
func filterSQL(f, col1, col2, col3 string) (string, []any, error) {
	return compileFilter(f, map[string]filterColumn{"userName": {col1, false}, "externalId": {col2, true}, "id": {col3, true}}, 2)
}
func has(a []string, v string) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}
func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
func jsonBytes(v any) []byte { b, _ := json.Marshal(v); return b }

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func managerExists(ctx context.Context, q queryRower, tenant, id string) bool {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL)`, tenant, id).Scan(&ok)
	return err == nil && ok
}
func patchUserObject(ctx context.Context, tx pgx.Tx, tenant, id string, raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return fmt.Errorf("PATCH value must be an attribute object")
	}
	if len(fields) == 0 {
		return fmt.Errorf("PATCH value must contain attributes")
	}
	known := map[string]bool{"schemas": true, "username": true, "externalid": true, "active": true, "name": true, "displayname": true, "emails": true, "title": true, "department": true, "usertype": true, "preferredlanguage": true, "groups": true, "id": true, "meta": true, strings.ToLower(EnterpriseUserSchema): true}
	for key := range fields {
		if !known[strings.ToLower(key)] {
			return fmt.Errorf("unsupported PATCH attribute %s", key)
		}
	}
	for key, value := range fields {
		lower := strings.ToLower(key)
		var e error
		switch lower {
		case "schemas", "groups", "id", "meta":
			continue
		case "active":
			var v bool
			if e = json.Unmarshal(value, &v); e == nil {
				_, e = tx.Exec(ctx, `UPDATE users SET active=$3 WHERE tenant_id=$1 AND id=$2`, tenant, id, v)
			}
		case "name":
			var n Name
			if e = json.Unmarshal(value, &n); e == nil {
				_, e = tx.Exec(ctx, `UPDATE users SET given_name=$3,family_name=$4,formatted_name=$5 WHERE tenant_id=$1 AND id=$2`, tenant, id, null(n.GivenName), null(n.FamilyName), null(n.Formatted))
			}
		case "emails":
			var v []Email
			if e = json.Unmarshal(value, &v); e == nil {
				for _, item := range v {
					if item.Value == "" {
						return fmt.Errorf("email value is required")
					}
				}
				_, e = tx.Exec(ctx, `UPDATE users SET emails=$3 WHERE tenant_id=$1 AND id=$2`, tenant, id, jsonBytes(v))
			}
		case strings.ToLower(EnterpriseUserSchema):
			var ext EnterpriseUser
			if e = json.Unmarshal(value, &ext); e == nil {
				if ext.Manager.Value != "" && !managerExists(ctx, tx, tenant, ext.Manager.Value) {
					return fmt.Errorf("manager must reference a provisioned user in this tenant")
				}
				_, e = tx.Exec(ctx, `UPDATE users SET employee_number=$3,organization_name=$4,division=$5,cost_center=$6,manager=$7 WHERE tenant_id=$1 AND id=$2`, tenant, id, null(ext.EmployeeNumber), null(ext.Organization), null(ext.Division), null(ext.CostCenter), jsonBytes(ext.Manager))
			}
		default:
			var v string
			if e = json.Unmarshal(value, &v); e == nil {
				column := map[string]string{"username": "username", "externalid": "external_id", "displayname": "display_name", "title": "title", "department": "department", "usertype": "user_type", "preferredlanguage": "preferred_language"}[lower]
				if lower == "username" && v == "" {
					return fmt.Errorf("userName cannot be empty")
				}
				_, e = tx.Exec(ctx, `UPDATE users SET `+column+`=$3 WHERE tenant_id=$1 AND id=$2`, tenant, id, null(v))
			}
		}
		if e != nil {
			return fmt.Errorf("invalid value for %s", key)
		}
	}
	return nil
}
func patchGroupObject(ctx context.Context, tx pgx.Tx, tenant, id string, raw json.RawMessage, op, base string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) == 0 {
		return fmt.Errorf("PATCH value must be a non-empty group attribute object")
	}
	for key, value := range fields {
		var err error
		switch strings.ToLower(key) {
		case "schemas", "id", "meta":
			continue
		case "members":
			var members []Member
			if err = unmarshalStrict(value, &members); err == nil && op == "replace" {
				_, err = tx.Exec(ctx, `DELETE FROM group_members WHERE tenant_id=$1 AND group_id=$2`, tenant, id)
			}
			if err == nil {
				for _, m := range members {
					if !validMemberShape(m, base) {
						err = fmt.Errorf("invalid group member reference")
						break
					}
					tag, e := tx.Exec(ctx, `INSERT INTO group_members(tenant_id,group_id,user_id) SELECT $1,$2,id FROM users WHERE tenant_id=$1 AND id=$3 AND deleted_at IS NULL ON CONFLICT DO NOTHING`, tenant, id, m.Value)
					if e != nil {
						err = e
						break
					}
					if tag.RowsAffected() == 0 {
						var exists bool
						_ = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM group_members WHERE tenant_id=$1 AND group_id=$2 AND user_id=$3)`, tenant, id, m.Value).Scan(&exists)
						if !exists {
							err = fmt.Errorf("invalid group member")
							break
						}
					}
				}
			}
		case "displayname", "externalid":
			var v string
			if err = unmarshalStrict(value, &v); err == nil {
				column := "display_name"
				if strings.EqualFold(key, "externalId") {
					column = "external_id"
				}
				_, err = tx.Exec(ctx, `UPDATE groups SET `+column+`=$3 WHERE tenant_id=$1 AND id=$2`, tenant, id, null(v))
			}
		default:
			return fmt.Errorf("unsupported group PATCH attribute %s", key)
		}
		if err != nil {
			return fmt.Errorf("invalid group attribute %s", key)
		}
	}
	return nil
}
func validMemberShape(m Member, base string) bool {
	if m.Value == "" || (m.Type != "" && !strings.EqualFold(m.Type, "User")) {
		return false
	}
	return m.Ref == "" || m.Ref == strings.TrimRight(base, "/")+"/scim/v2/Users/"+m.Value
}
func unmarshalStrict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("multiple JSON values")
	}
	return nil
}
func membershipIDs(ctx context.Context, tx pgx.Tx, tenant, group string) (map[string]bool, error) {
	rows, e := tx.Query(ctx, `SELECT user_id::text FROM group_members WHERE tenant_id=$1 AND group_id=$2`, tenant, group)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		out[id] = true
	}
	return out, rows.Err()
}
func recordMembershipDiff(ctx context.Context, tx pgx.Tx, tenant, group string, before map[string]bool) bool {
	after, e := membershipIDs(ctx, tx, tenant, group)
	if e != nil {
		return false
	}
	for uid := range after {
		if !before[uid] {
			if _, e = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id,details) VALUES($1,'scim','membership.added','group',$2,jsonb_build_object('user_id',$3::text))`, tenant, group, uid); e != nil {
				return false
			}
		}
	}
	for uid := range before {
		if !after[uid] {
			if _, e = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id,details) VALUES($1,'scim','membership.removed','group',$2,jsonb_build_object('user_id',$3::text))`, tenant, group, uid); e != nil {
				return false
			}
		}
	}
	return true
}
