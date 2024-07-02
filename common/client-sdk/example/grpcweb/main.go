//go:build js && wasm
// +build js,wasm

package main

import (
	"syscall/js"

	arkclient "github.com/ark-network/ark/common/client-sdk"
)

func main() {
	js.Global().Set("NewArkGrpcWebClient", js.FuncOf(arkclient.NewGrpcWebClientJS))
	select {}
}
