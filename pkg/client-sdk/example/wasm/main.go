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
		// read from local storage
		// instantiate wallet if local storage is not empty:
		//    - instantiate local storage WalletStore impl
		// if err := arksdkwasm.New(ctx, store, walletSvc); err != nil {
		if err := arksdkwasm.New(ctx, store); err != nil {
			fmt.Println(err)
		}
	} else {
		storeSvc, err := inmemorystore.NewStore()
		if err != nil {
			fmt.Println(err)
			return
		}
		if err := arksdkwasm.New(ctx, storeSvc); err != nil {
			fmt.Println(err)
		}
	}
}
