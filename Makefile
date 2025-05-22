.PHONY: build-server build-all-server proto proto-lint build build-all

build-server:
	@echo "Building arkd binary..."
	@bash ./server/scripts/build

build-client:
	@echo "Building ark binary..."
	@bash ./client/scripts/build

# Client and WASM builds are no longer actively maintained in this repository
# Kept for reference but not used in the main build targets

build-all-server:
	@echo "Building arkd binary for all archs..."
	@bash ./server/scripts/build-all

build-all-client:
	@echo "Building ark binary for all archs..."
	@bash ./client/scripts/build-all

build-wasm:
	@echo "Building wasm..."
	@$(MAKE) -C pkg/client-sdk build-wasm

build: build-server
build-all: build-all-server

proto: proto-lint
	@echo "Compiling stubs..."
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate buf.build/vulpemventures/ocean
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

proto-lint:
	@echo "Linting protos..."
	@docker build -q -t buf -f buf.Dockerfile . &> /dev/null
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf lint