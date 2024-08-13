//go:build js && wasm
// +build js,wasm

package main

import (
	"context"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/store/inmemory"
	"github.com/ark-network/ark/pkg/client-sdk/wasm/browser"
)

func main() {
	c := make(chan struct{}, 0)
	var (
		ctx = context.Background()
	)
	store, err := browser.NewLocalStorageStore()
	if err != nil {
		browser.ConsoleError(err)
		return
	}
	if store != nil {
		if err := browser.NewCovenantlessClient(ctx, store); err != nil {
			browser.ConsoleError(err)
			return
		}
	} else {
		storeSvc, err := inmemorystore.NewConfigStore()
		if err != nil {
			browser.ConsoleError(err)
			return
		}
		if err := browser.NewCovenantlessClient(ctx, storeSvc); err != nil {
			browser.ConsoleError(err)
			return
		}
	}
	println("ARK SDK WebAssembly module initialized")
	<-c
}

func init() {
	// You can add any additional initialization here if needed
	// This runs before the main function
}
