.PHONY: build build-noah clean cov help intergrationtest lint run test vet proto proto-lint

## build: build for all platforms
build:
	@echo "Building arkd binary..."
	@bash ./scripts/build

build-noah:
	@echo "Building noah binary..."
	@bash ./scripts/build-noah

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
	@go test -v -count=1 -race ./... $(go list ./... | grep internal/test)

## lint: lint codebase
lint:
	@echo "Linting code..."
	@golangci-lint run --fix

## run: run in dev mode
run: clean
	@echo "Running arkd in dev mode..."
	@export ARK_WALLET_ADDR=localhost:18000; \
	go run ./cmd/arkd

## test: runs unit and component tests
test:
	@echo "Running unit tests..."
	@find . -name go.mod -execdir go test -v -count=1 -race ./... $(go list ./... | grep -v internal/test) \;

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...
	
## proto: compile proto stubs
proto: proto-lint
	@echo "Compiling stubs..."
	@buf generate buf.build/vulpemventures/ocean
	@buf generate

## proto-lint: lint protos
proto-lint:
	@echo "Linting protos..."
	@buf lint
		