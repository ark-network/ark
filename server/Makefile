.PHONY: build clean cov help intergrationtest lint run run-neutrino run-neutrino-mutinynet test vet

## build: build for all platforms
build:
	@echo "Building arkd binary..."
	@bash ./scripts/build

## clean: cleans the binary
clean:
	@echo "Cleaning..."
	@go clean

## cov: generates coverage report
cov:
	@echo "Coverage..."
	@go test -cover ./...

## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

## intergrationtest: runs integration tests
integrationtest:
	@echo "Running integration tests..."
	@go test -v -count 1 -timeout 500s github.com/ark-network/ark/server/test/e2e/covenant
	@go test -v -count 1 -timeout 500s github.com/ark-network/ark/server/test/e2e/covenantless

## lint: lint codebase
lint:
	@echo "Linting code..."
	@golangci-lint run --fix

## run: run in regtest mode with bitcoind
run: clean
	@echo "Running arkd with Bitcoin Core in regtest mode ..."
	@export ARK_ROUND_INTERVAL=10; \
	export ARK_LOG_LEVEL=5; \
	export ARK_NETWORK=regtest; \
	export ARK_PORT=7070; \
	export ARK_NO_TLS=true; \
	export ARK_NO_MACAROONS=true; \
	export ARK_TX_BUILDER_TYPE=covenantless; \
	export ARK_BITCOIND_RPC_USER=admin1; \
	export ARK_BITCOIND_RPC_PASS=123; \
	export ARK_BITCOIND_RPC_HOST=localhost:18443; \
	export ARK_BITCOIND_ZMQ_BLOCK=tcp://127.0.0.1:28332; \
	export ARK_BITCOIND_ZMQ_TX=tcp://127.0.0.1:28333; \
	export ARK_DATADIR=./data/regtest; \
	go run ./cmd/arkd

## run-neutrino: run in regtest mode with neutrino
run-neutrino: clean
	@echo "Running arkd with Neutrino in regtest mode ..."
	@export ARK_ROUND_INTERVAL=10; \
	export ARK_LOG_LEVEL=5; \
	export ARK_NETWORK=regtest; \
	export ARK_PORT=7070; \
	export ARK_NO_TLS=true; \
	export ARK_NO_MACAROONS=true; \
	export ARK_TX_BUILDER_TYPE=covenantless; \
	export ARK_ESPLORA_URL=http://localhost:3000; \
	export ARK_NEUTRINO_PEER=localhost:18444; \
	export ARK_DATADIR=./data/regtest; \
	export ARK_ALLOW_ZERO_FEES=true; \
	go run ./cmd/arkd

## run-neutrino-mutinynet: run in signet mode
run-neutrino-mutinynet: clean
	@echo "Running arkd with Neutrino in signet mode ..."
	@export ARK_ROUND_INTERVAL=10; \
	export ARK_LOG_LEVEL=5; \
	export ARK_NETWORK=mutinynet; \
	export ARK_PORT=7070; \
	export ARK_NO_TLS=true; \
	export ARK_NO_MACAROONS=true; \
	export ARK_TX_BUILDER_TYPE=covenantless; \
	export ARK_ESPLORA_URL=https://mutinynet.com/api; \
	export ARK_NEUTRINO_PEER=45.79.52.207:38333; \
	export ARK_DATADIR=./data/mutinynet; \
	go run ./cmd/arkd

## test: runs unit and component tests
test:
	@echo "Running unit tests..."
	@go test -v -count=1 -race ./internal/...
	@find ./pkg -name go.mod -execdir go test -v -count=1 -race ./... \;

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...

## mig_file: creates pg migration file(eg. make FILE=init mig_file)
mig_file:
	@migrate create -ext sql -dir ./internal/infrastructure/db/sqlite/migration/ $(FILE)

## mig_up: creates db schema for provided db path
mig_up:
	@echo "creating db schema..."
	@migrate -database "sqlite://$(DB_PATH)/sqlite.db" -path ./internal/infrastructure/db/sqlite/migration/ up

## mig_down: apply down migration
mig_down:
	@echo "migration down..."
	@migrate -database "sqlite://$(DB_PATH)/sqlite.db" -path ./internal/infrastructure/db/sqlite/migration/ down

## mig_down_yes: apply down migration without prompt
mig_down_yes:
	@echo "migration down..."
	@"yes" | migrate -database "sqlite://path/to/database" -path ./internal/infrastructure/db/sqlite/migration/ down

## vet_db: check if mig_up and mig_down are ok
vet_db: recreatedb mig_up mig_down_yes
	@echo "vet db migration scripts..."

## sqlc: gen sql
sqlc:
	@echo "gen sql..."
	cd ./internal/infrastructure/db/sqlite; sqlc generate