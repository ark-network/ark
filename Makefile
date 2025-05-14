.PHONY: build-server build-client build-all-server build-all-client build build-all proto proto-lint docker-run docker-stop

# build-server: builds arkd binary
build-server:
	@echo "Building arkd binary..."
	@bash ./server/scripts/build

# build-client: builds ark cli binary
build-client:
	@echo "Building ark binary..."
	@bash ./client/scripts/build

# build-all-server: builds arkd binary for all archs
build-all-server:
	@echo "Building arkd binary for all archs..."
	@bash ./server/scripts/build-all

# build-all-client: builds ark cli binary for all archs
build-all-client:
	@echo "Building ark binary for all archs..."
	@bash ./client/scripts/build-all

# build: builds arkd and ark cli binaries
build: build-server build-client

# build-all: builds arkd and ark cli binaries for all archs
build-all: build-all-server build-all-client

# proto: compiles protos
proto: proto-lint
	@echo "Compiling stubs..."
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

# proto-lint: lints protos
proto-lint:
	@echo "Linting protos..."
	@docker build -q -t buf -f buf.Dockerfile . &> /dev/null
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf lint

# docker-run: starts docker test environment
docker-run:
	@echo "Running arkd and arkd-wallet services..."
	docker compose -f docker-compose.regtest.yml up --build -d

# docker-stop: tears down docker test environment
docker-stop:
	@echo "Stopping arkd and arkd-wallet services..."
	docker compose -f docker-compose.regtest.yml down -v