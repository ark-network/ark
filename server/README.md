# Ark Server
This is a Go implementation of the Ark server. An Ark server it's an always-on server that provides bitcoin liquidity in the Ark layer-two protocol. It supports Bitcoin and Liquid (with more experimantal features using covenants).

**ALPHA STAGE SOFTWARE: USE AT YOUR OWN RISK!**

## Development

### Prerequisites

- [Go](https://go.dev/doc/install)
- [Bitcoin Core](https://bitcoincore.org) with `compact block filters` enabled

### Build Server

```bash
make build
```

### Run the server

```bash
go run ./cmd/arkd
```

Refer to [config.go](./internal/config/config.go) for the available configuration options via ENV VARs.
