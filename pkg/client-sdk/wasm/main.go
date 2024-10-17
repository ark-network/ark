//go:build js && wasm
// +build js,wasm

package main

import (
	"context"

	"github.com/ark-network/ark/pkg/client-sdk/wasm/browser"
)

func main() {
	c := make(chan struct{}, 0)
	ctx := context.Background()
	storeSvc := browser.NewLocalStorageStore()

	if err := browser.NewCovenantlessClient(ctx, storeSvc); err != nil {
		browser.ConsoleError(err)
		return
	}
	println("ARK SDK WebAssembly module initialized")
	<-c
}

func init() {
	// You can add any additional initialization here if needed
	// This runs before the main function
}
