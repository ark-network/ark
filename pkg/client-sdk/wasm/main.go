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

	if err := browser.NewCovenantlessClient(ctx, storeSvc, Version); err != nil {
		browser.ConsoleError(err)
		return
	}
	println("ARK SDK WebAssembly module initialized")
	<-c
}
