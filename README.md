# Ark Monorepo

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/ark-network/ark)](https://github.com/ark-network/ark/releases)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io%2Fark--network%2Fark-blue?logo=docker)](https://github.com/ark-network/ark/pkgs/container/ark)
[![Integration](https://github.com/ark-network/ark/actions/workflows/ark.integration.yaml/badge.svg)](https://github.com/ark-network/ark/actions/workflows/ark.integration.yaml)
[![ci_unit](https://github.com/ark-network/ark/actions/workflows/ark.unit.yaml/badge.svg)](https://github.com/ark-network/ark/actions/workflows/ark.unit.yaml)
[![GitHub](https://img.shields.io/github/license/ark-network/ark)](https://github.com/ark-network/ark/blob/master/LICENSE)
![Go Reference](https://pkg.go.dev/badge/github.com/ark-network/ark.svg)

Welcome to the Ark monorepo, a comprehensive solution for off-chain Bitcoin and Liquid transactions.

Welcome to the Ark monorepo, a comprehensive solution for off-chain Bitcoin and Liquid transactions.

<p align="center">
  <img src="https://github.com/user-attachments/assets/169d6ae5-7d90-448d-b768-4e40a412bf70" alt="Ark logo">
</p>

## Repository Structure

- [`server`](./server/): `arkd` Ark Service Provider (ASP) - the always-on daemon
- [`client`](./client/): `ark` Single-key wallet CLI for interacting with the ASP
- [`common`](./common/): Shared code between the server and client
- [`pkg/client-sdk`](./pkg/client-sdk/): Go SDK for interacting with ASPs runnig the Ark protocol. It offers WASM bindings to interact with the SDK from the browser and other environments.


## Ark Service Provider (ASP) Setup

### Supported Networks and Wallets

|         | Covenant-less                | Covenant                               |
|---------|-----------------------------|-----------------------------------------|
| Network | Bitcoin (regtest only)       | Liquid, Liquid testnet, Liquid regtest |
| Wallet  | Embedded [lnwallet](https://pkg.go.dev/github.com/lightningnetwork/lnd/lnwallet/btcwallet) | [Ocean](https://github.com/vulpemventures/ocean) wallet |

## Development

For detailed development instructions, including building from source, running tests, and contributing guidelines, please refer to the README files in the `server` and `client` directories.

## Security Disclosures

Security is a top priority for Ark. If you discover a security issue, please bring it to our attention right away. Please DO NOT file a public issue, instead send your report privately to `security@arklabs.to`. Security reports are greatly appreciated and we will publicly thank you for it.
