// index.js

const fs = require('fs').promises;
const path = require('path');

// Load the Go WASM runtime
require('./wasm_exec');

// Custom ConfigStore implementation using local filesystem
class LocalConfigStore {
  constructor(baseDir) {
    this.baseDir = baseDir;
    this.filePath = path.join(baseDir, 'config.json');
  }

  async getData() {
    try {
      const data = await fs.readFile(this.filePath, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      if (error.code === 'ENOENT') {
        return null; // File doesn't exist yet
      }
      throw error;
    }
  }

  async addData(data) {
    await fs.mkdir(this.baseDir, { recursive: true });
    await fs.writeFile(this.filePath, JSON.stringify(data, null, 2));
  }

  async cleanData() {
    try {
      await fs.unlink(this.filePath);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
  }

  getType() {
    return 'file';
  }

  getDatadir() {
    return this.baseDir;
  }
}

async function loadWasm() {
  const go = new Go();
  const wasmBuffer = await fs.readFile(path.join(__dirname, 'build/ark-sdk.wasm'));
  const result = await WebAssembly.instantiate(wasmBuffer, go.importObject);
  go.run(result.instance);
}

async function main() {
  try {
    await loadWasm();
    console.log("ARK SDK WASM module loaded successfully");

    // Create a local config store
    const configStore = new LocalConfigStore(path.join(__dirname, 'config'));

    // Override the WASM module's ConfigStore methods
    global.addData = (data) => configStore.addData(data);
    global.getData = () => configStore.getData();
    global.cleanData = () => configStore.cleanData();
    global.getType = () => configStore.getType();
    global.getDatadir = () => configStore.getDatadir();

    // Set the network
    const network = await global.getNetwork();
    console.log("Network:", network);

    // Call the Init function
    try {
      const result = await global.init(
        "singlekey",           // Wallet type
        "rest",                // Client type
        "http://127.0.0.1:7070", // ASP URL
        "abandon abandon abandon", // Seed (replace with actual seed)
        "secret",              // Password (replace with actual password)
        "regtest"               // Chain
      );
      console.log("Init function called successfully", result);
    } catch (error) {
      console.error("Error calling Init function:", error);
    }

    // Keep the Node.js process alive
    setInterval(() => {}, 1000);
  } catch (error) {
    console.error("Error loading WASM module:", error);
  }
}

main().catch(console.error);