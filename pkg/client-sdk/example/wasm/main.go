//go:build js && wasm
// +build js,wasm

package main

import (
	"context"
	"fmt"

	inmemorystore "github.com/ark-network/ark-sdk/store/inmemory"
	arksdkwasm "github.com/ark-network/ark-sdk/wasm"
)

func main() {
	var (
		ctx = context.Background()
	)

	store, _ := arksdkwasm.NewLocalStorageStore()
	if store != nil {
		if err := arksdkwasm.New(ctx, store); err != nil {
			fmt.Println(err)
		}
	} else {
		storeSvc, err := inmemorystore.NewConfigStore()
		if err != nil {
			fmt.Println(err)
			return
		}
		if err := arksdkwasm.New(ctx, storeSvc); err != nil {
			fmt.Println(err)
		}
	}
}
