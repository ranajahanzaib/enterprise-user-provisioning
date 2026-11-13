# Contributing

Contributions to the service, documentation, and test suite are welcome. For substantial changes, open an issue first to discuss the approach. For smaller fixes, submit a pull request with a clear description of the problem and solution.

## Development setup

The project requires Go 1.25 or newer. PostgreSQL-backed tests require a disposable PostgreSQL 16 database.

```sh
git clone https://github.com/ranajahanzaib/enterprise-user-provisioning.git
cd enterprise-user-provisioning
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/server ./cmd/provisionctl
```

To run the database-backed tests, set `TEST_DATABASE_URL` to a database that can be discarded; the tests apply the project migration. Do not point integration tests at production or valuable data.

## Pull requests

- Keep changes focused and describe user-visible behavior, security impact, and compatibility changes.
- Add or update tests for behavior changes.
- Run `gofmt` on changed Go files and run the checks listed above when applicable.
- Update documentation when commands, configuration, API behavior, or limitations change.
- Never commit credentials, generated secrets, personal data, or production records. Use clearly synthetic fixtures.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Pull requests are reviewed before merging. Review may request changes or additional evidence for security-sensitive behavior.

## Reporting issues

Use the repository's issue templates for bug reports and feature requests. Do not include credentials, access tokens, or personal data in public issues. Report suspected vulnerabilities using the process in [SECURITY.md](.github/SECURITY.md).
