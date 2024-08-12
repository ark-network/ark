.PHONY: genrest test vet lint

## genrest: compiles rest client from stub with https://github.com/go-swagger/go-swagger
genrest:
	@echo "Generating rest client from stub..."
	@swagger generate client -f ../../server/api-spec/openapi/swagger/ark/v1/service.swagger.json -t ./client/rest/service --client-package=arkservice

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
	@GOOS=js GOARCH=wasm GO111MODULE=on go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(BUILD_DIR)/client-sdk.wasm $(WASM_DIR)/main.go
