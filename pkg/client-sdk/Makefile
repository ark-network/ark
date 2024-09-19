.PHONY: genrest test vet lint

## genrest: compiles rest client from stub with https://github.com/go-swagger/go-swagger
genrest:
	@echo "Generating rest client from stub..."
	@swagger generate client -f ../../api-spec/openapi/swagger/ark/v1/service.swagger.json -t ./client/rest/service --client-package=arkservice

## test: runs unit tests
test:
	@echo "Running unit tests..."
	@go test -v -count=1 -race ./...

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...

## lint: lint codebase
lint:
	@echo "Linting code..."
	@golangci-lint run --fix --verbose

## wasm: compiles the client-sdk to wasm
WASM_DIR = wasm
BUILD_DIR = build
VERSION := $(shell git describe --tags --always --dirty)
GO_VERSION := $(shell go version | cut -d' ' -f3)

.PHONY: build-wasm

build-wasm:
	@mkdir -p $(BUILD_DIR)
	@echo "Version: $(VERSION)"
	@GOOS=js GOARCH=wasm GO111MODULE=on go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(BUILD_DIR)/ark-sdk.wasm $(WASM_DIR)/main.go

### Sqlc

## mig_file: creates pg migration file(eg. make FILE=init mig_file)
mig_file:
	@migrate create -ext sql -dir ./store/sqlite/migration/ $(FILE)

## mig_up: creates db schema for provided db path
mig_up:
	@echo "creating db schema..."
	@migrate -database "sqlite://$(DB_PATH)/sqlite.db" -path ./store/sqlite/migration/ up

## mig_down: apply down migration
mig_down:
	@echo "migration down..."
	@migrate -database "sqlite://$(DB_PATH)/sqlite.db" -path ./store/sqlite/migration/ down

## mig_down_yes: apply down migration without prompt
mig_down_yes:
	@echo "migration down..."
	@"yes" | migrate -database "sqlite://path/to/database" -path ./store/sqlite/migration/ down

## vet_db: check if mig_up and mig_down are ok
vet_db: recreatedb mig_up mig_down_yes
	@echo "vet db migration scripts..."

## sqlc: gen sql
sqlc:
	@echo "gen sql..."
	cd ./store/sqlite; sqlc generate