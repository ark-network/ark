.PHONY: build clean help lint vet

build:
	@echo "Building binary..."
	@bash ./scripts/build

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
	
