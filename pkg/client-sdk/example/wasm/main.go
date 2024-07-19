//go:build js && wasm
// +build js,wasm

package main

import (
	"context"
	"fmt"

	arksdkwasm "github.com/ark-network/ark-sdk/wasm"
)

func main() {
	var (
		storeType = "inmemory"
		ctx       = context.Background()
	)

	store, _ := arksdkwasm.NewLocalStorageStore()
	if store != nil {
		if err := arksdkwasm.NewWithCustomStore(ctx, store); err != nil {
			fmt.Println(err)
		}
	} else {
		if err := arksdkwasm.New(ctx, storeType); err != nil {
			fmt.Println(err)
		}
	}
}
