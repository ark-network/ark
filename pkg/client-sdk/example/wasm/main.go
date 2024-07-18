//go:build js && wasm
// +build js,wasm

package main

import (
	"context"

	arksdkwasm "github.com/ark-network/ark-sdk/wasm"
)

func main() {
	var (
		aspUrl = "http://localhost:8080"
		ctx    = context.Background()
	)

	arksdkwasm.New(ctx, aspUrl)
}
