.PHONY: test build vet demo

test:
	go test ./...

build:
	go build ./cmd/server ./cmd/provisionctl

vet:
	go vet ./...

demo:
	@test -n "$(DEMO_TENANT_ID)" || (echo "set DEMO_TENANT_ID to a tenant UUID" >&2; exit 2)
	go run ./cmd/provisionctl demo run "$(DEMO_TENANT_ID)"
