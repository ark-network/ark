//go:build js && wasm
// +build js,wasm

package main

import (
	"context"
	"syscall/js"

	inmemory "github.com/ark-network/ark/pkg/client-sdk/store/inmemory"
)

func main() {
	c := make(chan struct{}, 0)

	storeSvc, err := inmemory.NewConfigStore()
	if err != nil {
		js.Global().Get("console").Call("error", err.Error())
		return
	}

	if err := NewCovenantlessClient(context.Background(), storeSvc); err != nil {
		js.Global().Get("console").Call("error", err.Error())
		return
	}

	println("ARK SDK WebAssembly module initialized")
	<-c
}

func init() {
	// You can add any additional initialization here if needed
	// This runs before the main function
}
