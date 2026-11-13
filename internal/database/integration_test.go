package database_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ranajahanzaib/enterprise-user-provisioning/migrations"
)

func TestTenantCompositeForeignKeys(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; PostgreSQL integration test skipped")
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
		t.Fatalf("apply migrations to empty test database: %v", e)
	}
	tx, e := db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	var tenantA, tenantB, userB, groupA string
	if e = tx.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('integration-a-'||gen_random_uuid()::text) RETURNING id::text`).Scan(&tenantA); e != nil {
		t.Fatal(e)
	}
	if e = tx.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('integration-b-'||gen_random_uuid()::text) RETURNING id::text`).Scan(&tenantB); e != nil {
		t.Fatal(e)
	}
	if e = tx.QueryRow(ctx, `INSERT INTO users(tenant_id,username) VALUES($1,'u') RETURNING id::text`, tenantB).Scan(&userB); e != nil {
		t.Fatal(e)
	}
	if e = tx.QueryRow(ctx, `INSERT INTO groups(tenant_id,display_name) VALUES($1,'g') RETURNING id::text`, tenantA).Scan(&groupA); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, `INSERT INTO group_members(tenant_id,group_id,user_id) VALUES($1,$2,$3)`, tenantA, groupA, userB); e == nil {
		t.Fatal("cross-tenant membership unexpectedly satisfied the composite foreign keys")
	}
}
