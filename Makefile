.PHONY: build test test-pg cover vectors run-api run-merchant dev agent probe probe-pay balance mint up

ENV = set -a; [ -f .env ] && . ./.env; set +a;

build:
	go build -o bin/kya-api ./apps/api
	go build -o bin/merchant-demo ./apps/merchant-demo
	go build -o bin/telegraph-probe ./apps/telegraph-probe
	npm run build

test:
	go vet ./...
	go test ./...
	npm test
	npm run typecheck

# Storage conformance against a throwaway Postgres DB (its tables are truncated).
test-pg:
	go test ./internal/storage/ -count=1 -v

cover:
	go test ./internal/... -coverpkg=./internal/policy,./internal/service,./internal/delegation,./internal/identity,./internal/canonical -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1

vectors:
	KYA_UPDATE_VECTORS=1 go test ./internal/identity/ -run Vectors -count=1

run-api:
	$(ENV) go run ./apps/api

run-merchant:
	$(ENV) go run ./apps/merchant-demo

dev:
	npm run dev:dashboard

agent:
	npm run agent -- all

probe:
	$(ENV) go run ./apps/telegraph-probe

balance:
	$(ENV) go run ./apps/telegraph-probe -balance

# make mint USDC=10
USDC ?= 10
mint:
	$(ENV) go run ./apps/telegraph-probe -mint $(USDC)

probe-pay:
	$(ENV) go run ./apps/telegraph-probe -pay

up:
	podman-compose up --build
