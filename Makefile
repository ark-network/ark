.PHONY: build-server build-client build-all-server build-all-client

build-server:
	@echo "Building arkd binary..."
	@bash ./server/scripts/build

build-client:
	@echo "Building ark binary..."
	@bash ./client/scripts/build

build-all-server:
	@echo "Building arkd binary for all archs..."
	@bash ./server/scripts/build-all

build-all-client:
	@echo "Building ark binary for all archs..."
	@bash ./client/scripts/build-all

build-wasm:
	@echo "Building wasm..."
	@$(MAKE) -C pkg/client-sdk build-wasm

build: build-server build-client build-wasm
build-all: build-all-server build-all-client build-wasm
