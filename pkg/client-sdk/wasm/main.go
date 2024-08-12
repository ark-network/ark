//go:build js && wasm
// +build js,wasm

package main

import (
	"github.com/ark-network/ark/pkg/client-sdk/wasm/browser"
)

func main() {
	c := make(chan struct{}, 0)
	println("ARK SDK WebAssembly module initialized")
	browser.InitWrapper()
	<-c
}

func init() {
	// You can add any additional initialization here if needed
	// This runs before the main function
}
