//go:build js && wasm
// +build js,wasm

package main

import (
	"context"

	arksdk "github.com/ark-network/ark-sdk"
	inmemorystore "github.com/ark-network/ark-sdk/store/inmemory"
	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		explorerUrl = "http://localhost:3001"
		network     = "regtest"
		aspUrl      = "http://localhost:6000"
		aspPubKey   = "A1B2C3D4E5F67890"

		ctx         = context.Background()
		explorerSvc = arksdk.NewExplorer(explorerUrl)
	)

	configStore := &inmemorystore.ConfigStore{
		ExplorerUrl:  explorerUrl,
		Protocol:     arksdk.Grpc,
		Net:          network,
		AspUrl:       aspUrl,
		AspPubKeyHex: aspPubKey,
	}
	defer configStore.Save(ctx)

	aliceWalletStore := &inmemorystore.WalletStore{}
	if _, err := aliceWalletStore.CreatePrivateKey(ctx); err != nil {
		log.Fatal(err)
	}
	defer aliceWalletStore.Save(ctx)

	aliceWallet, err := arksdk.NewSingleKeyWallet(
		ctx, explorerSvc, network, aliceWalletStore,
	)
	if err != nil {
		log.Fatal(err)
	}

	arksdk.NewArkSdkWasmClient(ctx, aliceWallet, configStore)
}
