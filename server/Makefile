.PHONY: build clean cov help intergrationtest lint run test vet proto proto-lint

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
	@go test -v -count=1 -race -timeout 200s github.com/ark-network/ark/test/e2e

## lint: lint codebase
lint:
	@echo "Linting code..."
	@golangci-lint run --fix

## run: run in dev mode
run: clean
	@echo "Running arkd in dev mode..."
	@export ARK_WALLET_ADDR=localhost:18000; \
	export ARK_ROUND_INTERVAL=10; \
	export ARK_LOG_LEVEL=5; \
	export ARK_NETWORK=regtest; \
	go run ./cmd/arkd

## test: runs unit and component tests
test:
	@echo "Running unit tests..."
	@find . -name go.mod -execdir go test -v -count=1 -race ./internal/... \;

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...

## proto: compile proto stubs
proto: proto-lint
	@echo "Compiling stubs..."
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate buf.build/vulpemventures/ocean
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

## proto-lint: lint protos
proto-lint:
	@echo "Linting protos..."
	@docker build -q -t buf -f buf.Dockerfile . &> /dev/null
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf lint

## build-dashboard-templates: build html templates for embedded dashboard
build-dashboard-templates:
	@echo "Building dashboard templates..."
	@go run github.com/a-h/templ/cmd/templ@latest generate
		