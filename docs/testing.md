# Testing

Run unit tests, race checks, vet, and builds:

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/server ./cmd/provisionctl
```

The PostgreSQL integration tests run when `TEST_DATABASE_URL` points to a disposable PostgreSQL 16 database. CI starts PostgreSQL 16 and sets that variable, so the tests apply the initial migration to an empty database. Without `TEST_DATABASE_URL`, database-backed tests are skipped. The test suite does not start authentik; use the [authentik setup guide](authentik-setup.md) for manual interoperability checks.
