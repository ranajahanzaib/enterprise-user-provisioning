package main

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ranajahanzaib/enterprise-user-provisioning/migrations"
)

func TestProvisionctlRolesAndAudit(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration test")
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

	// Create test tenant
	var tenantID string
	err = db.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('prov-test-'||gen_random_uuid()::text) RETURNING id::text`).Scan(&tenantID)
	if err != nil {
		t.Fatal(err)
	}

	// Seed roles
	seedRoles(ctx, db, tenantID)

	// Verify roles seeded
	var count int
	err = db.QueryRow(ctx, `SELECT count(*) FROM roles WHERE tenant_id=$1`, tenantID).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("expected 4 seeded roles, got %d", count)
	}

	// Create a group
	var groupID string
	err = db.QueryRow(ctx, `INSERT INTO groups(tenant_id, display_name) VALUES($1, 'Auditors') RETURNING id::text`, tenantID).Scan(&groupID)
	if err != nil {
		t.Fatal(err)
	}

	// Test role binding audit event creation with explicit text cast
	_, err = db.Exec(ctx, `INSERT INTO group_role_mappings(tenant_id, group_id, role_id) VALUES($1, $2, 'billing_viewer')`, tenantID, groupID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(ctx, `INSERT INTO audit_events(tenant_id, actor_type, action, resource_type, resource_id, details) VALUES($1, 'admin_cli', 'role_mapping.created', 'group', $2, jsonb_build_object('role_id', $3::text))`, tenantID, groupID, "billing_viewer")
	if err != nil {
		t.Fatalf("audit event insertion failed: %v", err)
	}

	// Test audit event query
	var auditCount int
	err = db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='role_mapping.created'`, tenantID).Scan(&auditCount)
	if err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("expected 1 audit event, got %d", auditCount)
	}
}
