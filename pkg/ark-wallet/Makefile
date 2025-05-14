.PHONY: vet run run-neutrino run-bitcoind run-neutrino-mutinynet lint

define setup_env
    $(eval include $(1))
    $(eval export)
endef

vet:
	@echo "Running go vet..."
	go vet ./...

## run-neutrino: run wallet in dev mode with neutrino on regtest
run-neutrino:
	@echo "Running btc-wallet service..."
	$(call setup_env, envs/neutrino.regtest.env)
	go run ./cmd


## run-bitcoind: run wallet in dev mode with bitcoind on regtest
run-bitcoind:
	@echo "Running arkd with Bitcoin Core in dev mode on regtest ..."
	$(call setup_env, envs/bitcoind.regtest.env)
	go run ./cmd

## run-neutrino-mutinynet: run wallet in dev mode with neutrino on mutinynet
run-neutrino-mutinynet:
	@echo "Running arkd with Neutrino in dev mode on mutinynet ..."
	$(call setup_env, envs/neutrino.mutinynet.env)
	go run ./cmd

## lint: lint codebase
lint:
	@echo "Linting code..."
	@golangci-lint run --fix