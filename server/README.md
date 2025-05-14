# Ark Server
This is a Go implementation of the Ark server. An Ark server it's an always-on server that provides bitcoin liquidity in the Ark layer-two protocol.

**ALPHA STAGE SOFTWARE: USE AT YOUR OWN RISK!**

## Development

### Prerequisites

- [Go](https://go.dev/doc/install)
- [Bitcoin Core](https://bitcoincore.org) with `compact block filters` enabled

### Run the arkd and arkd-wallet servers

1. Run arkd-wallet
```bash
cd ../pkg/ark-wallet && make run-neutrino
```

2. Run arkd
```bash
make run-neutrino
```

Refer to [config.go](./internal/config/config.go) for the available configuration options via ENV VARs.
