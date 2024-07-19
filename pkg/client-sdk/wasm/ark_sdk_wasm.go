package arksdkwasm

import (
	"context"
	"syscall/js"

	arksdk "github.com/ark-network/ark-sdk"
	walletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store"
)

var (
	arkSdkClient arksdk.ArkClient
)

func init() {
	js.Global().Set("init", InitWrapper())
	js.Global().Set("unlock", UnlockWrapper())
	js.Global().Set("lock", LockWrapper())
	js.Global().Set("balance", BalanceWrapper())
	js.Global().Set("onboard", OnboardWrapper())
	js.Global().Set("receive", ReceiveWrapper())
	js.Global().Set("sendOnChain", SendOnChainWrapper())
	js.Global().Set("sendOffChain", SendOffChainWrapper())
	js.Global().Set("unilateralRedeem", UnilateralRedeemWrapper())
	js.Global().Set("collaborativeRedeem", CollaborativeRedeemWrapper())
	js.Global().Set("log", LogWrapper())

	js.Global().Set("getAspUrl", GetAspUrlWrapper())
	js.Global().Set("getAspPubKeyHex", GetAspPubkeyWrapper())
	js.Global().Set("getWalletType", GetWalletTypeWrapper())
	js.Global().Set("getClientType", GetClientTypeWrapper())
	js.Global().Set("getExplorerUrl", GetExplorerUrlWrapper())
	js.Global().Set("getNetwork", GetNetworkWrapper())
	js.Global().Set("getRoundLifetime", GetRoundLifetimeWrapper())
	js.Global().Set("getUnilateralExitDelay", GetUnilateralExitDelayWrapper())
	js.Global().Set("getMinRelayFee", GetMinRelayFeeWrapper())
}

func New(ctx context.Context, storeType string) error {
	var err error

	arkSdkClient, err = arksdk.New(arksdk.Config{
		StoreType: storeType,
	})
	if err != nil {
		js.Global().Get("console").Call("error", err.Error())
		return err
	}

	select {}
}

func NewWithCustomStore(
	ctx context.Context, store walletstore.WalletStore,
) error {
	var err error

	arkSdkClient, err = arksdk.New(arksdk.Config{
		CustomStore: store,
	})
	if err != nil {
		js.Global().Get("console").Call("error", err.Error())
		return err
	}

	select {}
}
