# arkd

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/ark-network/ark)](https://github.com/ark-network/ark/releases)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io%2Fark--network%2Fark-blue?logo=docker)](https://github.com/ark-network/ark/pkgs/container/ark)
[![Integration](https://github.com/ark-network/ark/actions/workflows/ark.integration.yaml/badge.svg)](https://github.com/ark-network/ark/actions/workflows/ark.integration.yaml)
[![ci_unit](https://github.com/ark-network/ark/actions/workflows/ark.unit.yaml/badge.svg)](https://github.com/ark-network/ark/actions/workflows/ark.unit.yaml)
[![GitHub](https://img.shields.io/github/license/ark-network/ark)](https://github.com/ark-network/ark/blob/master/LICENSE)
![Go Reference](https://pkg.go.dev/badge/github.com/ark-network/ark.svg)

> **⚠️ IMPORTANT DISCLAIMER: ALPHA SOFTWARE**
> `arkd` is currently in alpha stage. This software is experimental and under active development.
> **DO NOT ATTEMPT TO USE IN PRODUCTION**. Use at your own risk.


## What is arkd?

`arkd` is the server implementation of Arkade instance that builds on top of the Ark protocol, a Bitcoin scaling solution that enables fast, low-cost off-chain transactions while maintaining Bitcoin's security guarantees. As an Arkade Operator, the server:

- Creates and manages Batch Outputs through on-chain Bitcoin transactions
- Facilitates off-chain transactions between users
- Provides liquidity for commitment transactions (on-chain settlements that finalize each batch)
- Co-signs multisignature arrangements while preserving user exit rights

The Operator's role is designed with strict boundaries that ensure users always maintain control over their funds. This architecture allows for efficient transaction batching while preserving the trustless nature of Bitcoin.


## Supported Networks and Wallets

`arkd` supports the following Bitcoin network:
* regtest
* testnet3
* signet
* mutinynet
* mainnet

and uses [lnwallet](https://pkg.go.dev/github.com/lightningnetwork/lnd/lnwallet/btcwallet) as embedded on-chain wallet.

## Usage Documentation

In this documentation, you'll learn how to install and use `arkd`, a Bitcoin server for off-chain Bitcoin transactions.

### Installing from GitHub Releases

1. Download the latest `arkd` binary from the [GitHub Releases page](https://github.com/ark-network/ark/releases)

2. Make the binary executable:
   ```sh
   chmod +x arkd
   ```

3. Move the binary to a directory in your PATH (optional):
   ```sh
   sudo mv arkd /usr/local/bin/
   ```

### Configuration Options

The `arkd` server can be configured using environment variables.

| Environment Variable | Description | Default |
|---------------------|-------------|--------|
| `ARK_NETWORK` | Bitcoin network (bitcoin, testnet3, regtest, signet, mutinynet) | `bitcoin` |
| `ARK_DATADIR` | Directory to store data | App data directory |
| `ARK_PORT` | Port to listen on | `7070` |
| `ARK_LOG_LEVEL` | Logging level (0-6, where 6 is trace) | `4` (info) |
| `ARK_ROUND_INTERVAL` | Interval between rounds in seconds | `30` |
| `ARK_DB_TYPE` | Database type (sqlite, badger) | `sqlite` |
| `ARK_EVENT_DB_TYPE` | Event database type (badger) | `badger` |
| `ARK_SCHEDULER_TYPE` | Scheduler type (gocron, block) | `gocron` |
| `ARK_TX_BUILDER_TYPE` | Transaction builder type (covenantless) | `covenantless` |
| `ARK_VTXO_TREE_EXPIRY` | VTXO tree expiry in blocks | `604672` (7 days) |
| `ARK_UNILATERAL_EXIT_DELAY` | Unilateral exit delay in blocks | `86400` (24 hours) |
| `ARK_BOARDING_EXIT_DELAY` | Boarding exit delay in blocks | `7776000` (3 months) |
| `ARK_ESPLORA_URL` | Esplora API URL | `https://blockstream.info/api` |
| `ARK_NEUTRINO_PEER` | Neutrino peer address | - |
| `ARK_BITCOIND_RPC_USER` | Bitcoin Core RPC username | - |
| `ARK_BITCOIND_RPC_PASS` | Bitcoin Core RPC password | - |
| `ARK_BITCOIND_RPC_HOST` | Bitcoin Core RPC host | - |
| `ARK_BITCOIND_ZMQ_BLOCK` | Bitcoin Core ZMQ block endpoint | - |
| `ARK_BITCOIND_ZMQ_TX` | Bitcoin Core ZMQ transaction endpoint | - |
| `ARK_NO_MACAROONS` | Disable macaroon authentication | `false` |
| `ARK_NO_TLS` | Disable TLS | `true` |
| `ARK_UNLOCKER_TYPE` | Wallet unlocker type (env, file) | - |
| `ARK_UNLOCKER_FILE_PATH` | Path to unlocker file | - |
| `ARK_UNLOCKER_PASSWORD` | Wallet unlocker password | - |
| `ARK_ROUND_MAX_PARTICIPANTS_COUNT` | Maximum number of participants per round | `128` |

For a complete list of configuration options, run:
```sh
arkd help
```

## Provisioning

### Data Directory

By default, `arkd` stores all data in the following location:

- Linux: `~/.arkd/`
- macOS: `~/Library/Application Support/arkd/`
- Windows: `%APPDATA%\arkd\`

You can specify a custom data directory using the `ARK_DATADIR` environment variable.

### Connecting to Bitcoin

#### Option 1: Connect to Bitcoin Core via RPC

To connect `arkd` to your own Bitcoin Core node via RPC, use these environment variables:

```sh
export ARK_BITCOIND_RPC_USER=admin1
export ARK_BITCOIND_RPC_PASS=123
export ARK_BITCOIND_RPC_HOST=localhost:18443
```

For ZMQ notifications (recommended for better performance):

```sh
export ARK_BITCOIND_ZMQ_BLOCK=tcp://localhost:28332
export ARK_BITCOIND_ZMQ_TX=tcp://localhost:28333
```

#### Option 2: Connect via Neutrino

For a lighter setup using Neutrino (BIP 157/158):

```sh
export ARK_NEUTRINO_PEER=yourhost:p2p_port_bitcoin
```

### Wallet Setup

1. Start the server:
   ```sh
   arkd
   ```

2. Create a new wallet:
   ```sh
   arkd wallet create --password <password>
   ```

   Or restore from mnemonic:
   ```sh
   arkd wallet create --mnemonic "your twelve word mnemonic phrase here" --password <password>
   ```

3. Unlock the wallet:
   ```sh
   arkd wallet unlock --password <password>
   ```

4. Generate a funding address:
   ```sh
   arkd wallet address
   ```

5. Fund the on-chain address with BTC and wait for at least 2 confirmations.

6. Check your wallet balance:
   ```sh
   arkd wallet balance
   ```

For a complete list of available commands and options:
   ```sh
   arkd help
   ```

## Repository Structure

- [`api-spec`](./api-spec/): Ark Protocol Buffer API specification
- [`server`](./server/): `arkd` Ark server - the always-on daemon

*Note: This repository now focuses only on the server component (`arkd`). The client, common, and pkg directories are currently maintained but not actively developed in this repository.*

## Development

For detailed development instructions, including running tests, and contributing to the implementation, please refer to the README file in the `server` directory.

### Compile binary from source

To compile the `arkd` binary from source, you can use the following Make commands from the root of the repository:

- `make build-server`: Builds the `arkd` binary
- `make build`: Alias for `make build-server`

For example, to build the server binary, run:

```sh
make build
```

This will compile the `arkd` binary for your current architecture. For more detailed build instructions and options, please refer to the README file in the `server` directory.

### Contributing Guidelines

1. **No force pushing in PRs**: Always use `git push --force-with-lease` to avoid overwriting others' work.
2. **Sign your commits**: Use GPG to sign your commits for verification.
3. **Squash and merge**: When merging PRs, use the "Squash and merge" option to maintain a clean commit history.
4. **Testing**: Add tests for each new major feature or bug fix.
5. **Keep master green**: The master branch should always be in a passing state. All tests must pass before merging.

### Local Development Setup

1. Install Go (version 1.18 or later)
2. Install [Nigiri](https://nigiri.vulpem.com/) for local Bitcoin networks
3. Clone this repository:

   ```sh
   git clone https://github.com/ark-network/ark.git
   cd ark
   ```

4. Install dependencies:

   ```sh
   go work sync
   ```

5. Build the project:

   ```sh
   cd server
   make build
   ```

## Support

If you encounter any issues or have questions, please file an issue on our [GitHub Issues](https://github.com/ark-network/ark/issues) page.

## Security

We take the security of Ark seriously. If you discover a security vulnerability, we appreciate your responsible disclosure.

Currently, we do not have an official bug bounty program. However, we value the efforts of security researchers and will consider offering appropriate compensation for significant, [responsibly disclosed vulnerabilities](./SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
