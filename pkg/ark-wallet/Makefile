.PHONY: proto proto-lint vet run run-neutrino

define setup_env
    $(eval include $(1))
    $(eval export)
endef

vet:
	@echo "Running go vet..."
	go vet ./...

run-neutrino:
	@echo "Running btc-wallet service..."
	$(call setup_env, envs/neutrino.regtest.env)
	go run ./cmd


## run: run arkd in dev mode with bitcoind on regtest
run-bitcoind:
	@echo "Running arkd with Bitcoin Core in dev mode on regtest ..."
	$(call setup_env, envs/bitcoind.regtest.env)
	go run ./cmd

## run-neutrino-mutinynet: run arkd in dev mode with neutrino on mutinynet
run-neutrino-mutinynet:
	@echo "Running arkd with Neutrino in dev mode on mutinynet ..."
	$(call setup_env, envs/neutrino.mutinynet.env)
	go run ./cmd