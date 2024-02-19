# Roadmap

The roadmap provides an overview of the planned projects and modules for the Ark network. It outlines the current development status and expected functionalities of each module. Please note that the roadmap is subject to change as the project evolves.

For the latest updates and progress reports, please check the this page regularly.

## Projects

### ☁️ `arkd` - Ark Service Provider Daemon

- Status: Pre-Alpha

The `arkd` is the Ark daemon, the initial implementation of an ASP (Ark Service Provider) as a standalone always-on server.
It uses [Ocean](https://github.com/vulpemventures/ocean) as Bitcoin and Liquid wallet backend.
It exposes a gRPC interface that Ark wallets can use to interact with the Provider.

- [x] Setup Ocean Wallet for funding rounds
- [ ] Start producing rounds from Ark wallets
  - [x] Register VTXOs to be spent & new VTXOs to be created
  - [x] Build congestion control tree
    - [x] Root node
    - [x] VTXOs Script
    - [x] Tap Leaf Script Validation
    - [x] Unroll Clause Transaction Builder.
  - [ ] Verifiy forfeit transactions
- [x] Sign & Broadcast Pool transactions
- [x] Sweep expired VTXOs
- [ ] Accept VTXOs from Boarding transactions
- [ ] Detect double spends to recover with forfeit transactions

### 🌐 Ark Explorer

Status: Not started yet

The Ark Explorer module will consist of a console and an Electrum-like server. It will allow users to retrieve VTXOs, pool transactions, and access transaction data. More details about this module will be provided as development progresses.

### 👩‍💻 `ark` - Ark CLI

- Status: Pre-Alpha

The `ark` module will be an Ark wallet implemented as a command line interface (CLI). It will also be in the alpha status, indicating that it is still being developed and may have some limitations.

- [x] Create and manage Ark wallets
- [x] Connect to an Ark Service Provider.
- [ ] Send and receive Ark transactions
  - [x] Join a round
  - [ ] Validate Tree and Sign forfeit transaction
  - [x] Finalize a Tree
- [ ] on-boarding
  - [ ] Boarding address Script
  - [ ] Tap Leaf Script Validation
- [ ] off-boarding
  - [x] Cooperative exit
  - [ ] Unilateral exit

### 🚰 Ark Faucet

Status: Alpha

The Ark Faucet allows users to request testnet VTXOs for testing purposes, without having to onboard to the Ark provider.

### 📱 Ark Mobile App

Status: Not started yet

The Ark App module will serve as a reference implementation for an Ark wallet as Mobile App. It will provide a user-friendly interface for managing Ark transactions and other wallet-related functionalities.

### 🖥️ Ark Desktop App

Status: Not started yet

The Ark Desktop module will be a reference implementation for an Ark wallet as a desktop application. It will provide a user-friendly interface for managing Ark transactions and other wallet-related functionalities.

### 👨🏻‍💻 Ark SDK

Status: Not started yet

Rust-based SDK with first-class support Java, Swift and JavaScript bindings for implementing Ark wallets and interacting with ASPs. It will provide a set of APIs for managing wallets, transactions, and other Ark-related functionalities.

### 🗼 Ark Tower

Status: Not started yet

Delegate automatic refereshes of VTXOs to trust-minimized Ark Tower nodes. Additional information about this module will be shared as development continues.
