//go:build js && wasm
// +build js,wasm

package main

import (
	"context"

	"github.com/ark-network/ark/pkg/client-sdk/wasm/browser"
)

var version = ""

func main() {
	c := make(chan struct{}, 0)
	ctx := context.Background()
	storeSvc := browser.NewLocalStorageStore()

	if err := browser.NewCovenantlessClient(ctx, storeSvc, version); err != nil {
		browser.ConsoleError(err)
		return
	}
	println("ARK SDK WebAssembly module initialized")
	<-c
}
