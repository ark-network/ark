//go:build js && wasm
// +build js,wasm

package main

import (
	"syscall/js"

	arkwasmclient "github.com/ark-network/ark/common/client-sdk/wasm"
)

func main() {
	js.Global().Set("Log", arkwasmclient.Log())
	js.Global().Set("RestServiceClient", arkwasmclient.RestServiceClientWrapper())

	select {}
}
