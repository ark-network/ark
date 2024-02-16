.PHONY: build build-all clean help lint vet

BUILD_FLAG=

build:
	@echo "Building binary..."
	@bash ./scripts/build ${BUILD_FLAG}

build-all:
	@echo "Building binary..."
	@bash ./scripts/build-all ${BUILD_FLAG}

## clean: cleans the binary
clean:
	@echo "Cleaning..."
	@go clean

## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

## lint: lint codebase
lint:
	@echo "Linting code..."
	@golangci-lint run --fix

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...
	
