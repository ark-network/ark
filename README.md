# Ark Monorepo

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/ark-network/ark)](https://github.com/ark-network/ark/releases)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io%2Fark--network%2Fark-blue?logo=docker)](https://github.com/ark-network/ark/pkgs/container/ark)
[![Integration](https://github.com/ark-network/ark/actions/workflows/ark.integration.yaml/badge.svg)](https://github.com/ark-network/ark/actions/workflows/ark.integration.yaml)
[![ci_unit](https://github.com/ark-network/ark/actions/workflows/ark.unit.yaml/badge.svg)](https://github.com/ark-network/ark/actions/workflows/ark.unit.yaml)
[![GitHub](https://img.shields.io/github/license/ark-network/ark)](https://github.com/ark-network/ark/blob/master/LICENSE)
![Go Reference](https://pkg.go.dev/badge/github.com/ark-network/ark.svg)

Welcome to the Ark monorepo, a comprehensive solution for off-chain Bitcoin and Liquid transactions.

<p align="center">
  <img src="https://github.com/user-attachments/assets/169d6ae5-7d90-448d-b768-4e40a412bf70" alt="Ark logo">
</p>

> **⚠️ IMPORTANT DISCLAIMER: ALPHA SOFTWARE**
> 
> Ark is currently in alpha stage. This software is experimental and under active development. 
> **DO NOT ATTEMPT TO USE IN PRODUCTION**. Use at your own risk.

## Repository Structure

- [`server`](./server/): `arkd` Ark Service Provider (ASP) - the always-on daemon
- [`client`](./client/): `ark` Single-key wallet CLI for interacting with the ASP
- [`common`](./common/): Shared code between the server and client
- [`pkg/client-sdk`](./pkg/client-sdk/): Go SDK for interacting with ASPs running the Ark protocol. It offers WASM bindings to interact with the SDK from the browser and other environments.

## Ark Service Provider (ASP) Setup

### Supported Networks and Wallets

|         | Covenant-less                | Covenant                               |
|---------|-----------------------------|-----------------------------------------|
| Network | Bitcoin signet, Bitcoin regtest | Liquid, Liquid testnet, Liquid regtest |
| Wallet  | Embedded [lnwallet](https://pkg.go.dev/github.com/lightningnetwork/lnd/lnwallet/btcwallet) | [Ocean](https://github.com/vulpemventures/ocean) wallet |

## Usage Documentation

For a comprehensive guide on how to set up and use Ark, please visit our [Developer Portal](https://arkdev.info). 
For a quick-start with Docker, head over to our [Quick Start guide](https://arkdev.info/docs/quick-start/intro) where you can setup an Ark Server and Clients in a local Bitcoin regtest network.

## Development

For detailed development instructions, including building from source, running tests, and contributing guidelines, please refer to the README files in the `server` and `client` directories.

### Contributing Guidelines

1. **No force pushing in PRs**: Always use `git push --force-with-lease` to avoid overwriting others' work.
2. **Sign your commits**: Use GPG to sign your commits for verification.
3. **Squash and merge**: When merging PRs, use the "Squash and merge" option to maintain a clean commit history.
4. **Testing**: Add tests for each new major feature or bug fix.
5. **Keep master green**: The master branch should always be in a passing state. All tests must pass before merging.

### Local Development Setup

1. Install Go (version 1.18 or later)
2. Install [Nigiri](https://nigiri.vulpem.com/) for local Bitcoin and Liquid networks
3. Clone this repository:
   ```
   git clone https://github.com/ark-network/ark.git
   cd ark
   ```
4. Install dependencies:
   ```
   go mod download
   ```
5. Build the project:
   ```
   cd server
   make build
   cd ../client
   make build
   ```

Note: You need to run `make build` in both the `server` and `client` directories separately.

## Support

If you encounter any issues or have questions, please file an issue on our [GitHub Issues](https://github.com/ark-network/ark/issues) page. 

## Security

We take the security of Ark seriously. If you discover a security vulnerability, we appreciate your responsible disclosure.

Currently, we do not have an official bug bounty program. However, we value the efforts of security researchers and will consider offering appropriate compensation for significant, [responsibly disclosed vulnerabilities](./SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
