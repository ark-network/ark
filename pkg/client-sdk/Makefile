.PHONY: genrest test vet lint prepare-wasm-test

client_dir = $(or $(REST_DIR),$(PWD)/client/rest/service)

## genrest: compiles rest client from stub with https://github.com/go-swagger/go-swagger
genrest:
	@echo "Cleaning existing files..."
	@rm -rf $(client_dir)
	@echo "Generating rest client from stub..."
	@mkdir -p $(client_dir)
	@swagger generate client -f ../../api-spec/openapi/swagger/ark/v1/service.swagger.json -t $(client_dir) --client-package=arkservice
	@swagger generate client -f ../../api-spec/openapi/swagger/ark/v1/explorer.swagger.json -t $(client_dir) --client-package=explorerservice

## test: runs unit tests
test:
	@echo "Running unit tests..."
	@go test -v -count=1 -race $$(go list ./... | grep -v '/test/wasm')

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
	@GOOS=js GOARCH=wasm GO111MODULE=on go build -ldflags="-s -w -X 'main.Version=$(VERSION)'" -o $(BUILD_DIR)/ark-sdk.wasm $(WASM_DIR)/*.go

test-wasm:
	$(MAKE) build-wasm BUILD_DIR=./test/wasm/web
	@echo "Copying $(go env GOROOT)/misc/wasm/wasm_exec.js"
	@cp `go env GOROOT`/misc/wasm/wasm_exec.js ./test/wasm/web
	@echo "Starting web server..."
	@cd ./test/wasm/web && python3 -m http.server 8000 &
	@echo "Waiting for server to start..."
	@sleep 3
	@echo "Running tests..."
	@cd ./test/wasm && go test -v