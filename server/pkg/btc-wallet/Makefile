.PHONY: proto proto-lint vet

proto: proto-lint
	@echo "Compiling stubs..."
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

proto-lint:
	@echo "Linting protos..."
	@docker build -q -t buf -f buf.Dockerfile . &> /dev/null
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf lint

vet:
	@echo "Running go vet..."
	go vet ./...

run:
	@echo "Running btc-wallet service..."
	ARK_BTC_WALLET_NETWORK=regtest \
	ARK_BTC_WALLET_ESPLORA_URL=http://localhost:3000 \
	ARK_BTC_WALLET_NEUTRINO_PEER=localhost:18444 \
	go run ./cmd/main.go