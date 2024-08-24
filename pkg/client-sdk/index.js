// index.js

const fs = require('fs').promises;
const path = require('path');
const dns = require('dns');

// Set Google's DNS server
dns.setServers(['8.8.8.8']);

// Load the Go WASM runtime
require('./wasm_exec');

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

    // Set the network
    const network = await global.getNetwork();
    console.log("Network:", network);
    // Call the Init function
    try {
      const result = await global.init(
        "singlekey",           // Wallet type
        "grpc",        // Client type
        "https://asp-signet.arklabs.to", // ASP URL (replace with actual URL)
        "abandon abandon abandon",   // Seed (replace with actual seed)
        "sercet",      // Password (replace with actual password)
        "signet"              // Chain (either "bitcoin" or "liquid")
      );
      console.log("Init function called successfully", result);
    } catch (error) {
      console.error("Error calling Init function:", error);
    }

  } catch (error) {
    console.error("Error loading WASM module:", error);
  }
}

main().catch(console.error);