.PHONY: vet run

vet:
	@echo "Running go vet..."
	go vet ./...

run:
	@echo "Running btc-wallet service..."
	ARK_WALLET_NETWORK=regtest \
	ARK_WALLET_ESPLORA_URL=http://localhost:3000 \
	ARK_WALLET_NEUTRINO_PEER=localhost:18444 \
	go run ./cmd/main.go