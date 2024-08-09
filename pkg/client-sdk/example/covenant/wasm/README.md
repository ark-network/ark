## USAGE

This example demonstrates how to compile ARK Go SDK to WebAssembly and use it in a web page.

1. Create a Go file with the main package, check [main.go](main.go).

2. Copy `wasm_exec.js`:

    ```bash
    cp $(go env GOROOT)/misc/wasm/wasm_exec.js .
    ```

3. Build the Go code to WebAssembly:

    ```bash
    GOOS=js GOARCH=wasm go build -o main.wasm main.go
    ```

4. Load the WebAssembly module in a web page, check [index.html](index.html).

5. Serve the files:

    ```bash
    python3 -m http.server 8000
    ```