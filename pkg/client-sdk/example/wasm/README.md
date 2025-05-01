## USAGE

This example demonstrates how to compile ARK Go SDK to WebAssembly and use it in a web page.

1. Copy `wasm_exec.js` to a new directory:

    ```bash
    cp $(go env GOROOT)/misc/wasm/wasm_exec.js .
    ```

2. On the root directory of this repo, build the Go code to WebAssembly:

    ```bash
    make build-wasm
    ```

3. Move the wasm file to your directory

    ```bash
    mv <repo>/pkg/client-sdk/build/ark-sdk.wasm .

4. Load the WebAssembly module in a web page, check [index.html](index.html).

5. Serve the files:

    ```bash
    python3 -m http.server 8000
    ```