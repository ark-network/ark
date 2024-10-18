# Simulation Framework for Server Testing

This simulation framework is designed to test the **Ark Server** by simulating multiple clients performing 
various actions over several rounds. It reads simulation configurations from YAML files, validates them against a predefined schema, 
and executes the simulation accordingly.

## Usage

### 1. Start Nigiri

Ensure that Nigiri (a Bitcoin Regtest environment) is running:

```sh
nigiri start
```

#### 2. Configure the Testing Scenario
Create a simulation YAML file based on the [schema.yaml](./schema.yaml). You can refer to the [this](./simulation1.yaml) example for guidance.

#### 3. Run simulation

```sh
make run SIMULATION=your_simulation.yaml
```

Replace your_simulation.yaml with the path to your simulation configuration file.