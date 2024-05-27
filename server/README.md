# Ark Server

This is a Go implementation of an Ark Service Provider (ASP). An ASP it's an always-on server that provide Bitcoin liquidity to the Ark protocol. It's built using the [Elements introspection opcodes](https://github.com/ElementsProject/elements/blob/master/doc/tapscript_opcodes.md) and currently supports Elements as chain of deployment.

This is in an early phase of development, the goal is to experiment with many possibile use-cases of Ark and adapt quickly based on user feedback early on.

**ALPHA STAGE SOFTWARE: USE AT YOUR OWN RISK!**

## Development

### Prerequisites

- [Go](https://go.dev/doc/install)

### Build Server

```bash
make build
```

### Run the server

```bash
go run ./cmd/arkd
```

Refer to [config.go](./internal/config/config.go) for the available configuration options via ENV VARs.
