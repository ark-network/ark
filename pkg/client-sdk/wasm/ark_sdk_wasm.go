package arksdkwasm

import (
	"context"
	"errors"
	"syscall/js"

	"github.com/ark-network/ark-sdk"
	inmemorystore "github.com/ark-network/ark-sdk/store/inmemory"
)

var (
	arkSdkClient        arksdk.ArkClient
	inMemoryConfigStore arksdk.ConfigStore
	inMemoryWalletStore arksdk.WalletStore
)

func New(ctx context.Context, aspUrl string) error {
	var err error

	inMemoryConfigStore, err = inmemorystore.New(aspUrl, arksdk.Rest)
	if err != nil {
		return err
	}

	inMemoryWalletStore = inmemorystore.NewWalletStore()
	wallet, err := arksdk.NewSingleKeyWallet(ctx, inMemoryWalletStore)
	if err != nil {
		return err
	}

	arkSdkClient, err = arksdk.New(ctx, wallet, inMemoryConfigStore)
	if err != nil {
		js.Global().Get("console").Call("error", err.Error())
		return err
	}

	js.Global().Set("connect", ConnectWrapper())
	js.Global().Set("balance", BalanceWrapper())
	js.Global().Set("onboard", OnboardWrapper())
	js.Global().Set("trustedOnboard", TrustedOnboardWrapper())
	js.Global().Set("receive", ReceiveWrapper())
	js.Global().Set("sendOnChain", SendOnChainWrapper())
	js.Global().Set("sendOffChain", SendOffChainWrapper())
	js.Global().Set("unilateralRedeem", UnilateralRedeemWrapper())
	js.Global().Set("collaborativeRedeem", CollaborativeRedeemWrapper())
	js.Global().Set("log", LogWrapper())

	js.Global().Set("getAspUrl", GetAspUrlWrapper())
	js.Global().Set("getAspPubKeyHex", GetAspPubKeyHexWrapper())
	js.Global().Set("getTransportProtocol", GetTransportProtocolWrapper())
	js.Global().Set("getExplorerUrl", GetExplorerUrlWrapper())
	js.Global().Set("getNetwork", GetNetworkWrapper())
	js.Global().Set("setAspUrl", SetAspUrlWrapper())
	js.Global().Set("setAspPubKeyHex", SetAspPubKeyHexWrapper())
	js.Global().Set("setTransportProtocol", SetTransportProtocolWrapper())
	js.Global().Set("setExplorerUrl", SetExplorerUrlWrapper())
	js.Global().Set("setNetwork", SetNetworkWrapper())
	js.Global().Set("saveConfigStore", SaveWrapper())

	js.Global().Set("createPrivateKey", CreatePrivateKeyWrapper())
	js.Global().Set("getPrivateKeyHex", GetPrivateKeyHexWrapper())
	js.Global().Set("saveWalletStore", SaveWalletStoreWrapper())

	select {}
}

func LogWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		logMsg(p[0].String())
		return nil
	})
}

func logMsg(msg string) {
	js.Global().Get("console").Call("log", msg)
}

func ConnectWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		err := arkSdkClient.Connect(context.Background())
		return nil, err
	})
}

func BalanceWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		computeExpiryDetails := args[0].Bool()
		resp, err := arkSdkClient.Balance(context.Background(), computeExpiryDetails)
		if err != nil {
			return nil, err
		}

		var (
			onchainBalance  int
			offchainBalance int
		)

		if resp == nil {
			onchainBalance = 0
			offchainBalance = 0
		} else {
			onchainBalance = int(resp.OnchainBalance.SpendableAmount)
			offchainBalance = int(resp.OffchainBalance.Total)
		}

		result := map[string]interface{}{
			"onchain_balance":  onchainBalance,
			"offchain_balance": offchainBalance,
		}

		return js.ValueOf(result), nil
	})
}

func OnboardWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) == 0 {
			return nil, errors.New("no amount provided")
		}
		amount := uint64(args[0].Int())
		txID, err := arkSdkClient.Onboard(context.Background(), amount)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
	})
}

func TrustedOnboardWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		addr, err := arkSdkClient.TrustedOnboard(context.Background())
		if err != nil {
			return nil, err
		}
		return js.ValueOf(addr), nil
	})
}

func ReceiveWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		offchainAddr, onchainAddr, err := arkSdkClient.Receive(context.Background())
		if err != nil {
			return nil, err
		}
		result := map[string]interface{}{
			"offchainAddr": offchainAddr,
			"onchainAddr":  onchainAddr,
		}
		return js.ValueOf(result), nil
	})
}

func SendOnChainWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		receivers := make([]arksdk.Receiver, args[0].Length())
		for i := 0; i < args[0].Length(); i++ {
			receiver := args[0].Index(i)
			receivers[i] = arksdk.Receiver{
				To:     receiver.Get("To").String(),
				Amount: uint64(receiver.Get("Amount").Int()),
			}
		}
		txID, err := arkSdkClient.SendOnChain(context.Background(), receivers)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
	})
}

func SendOffChainWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		withExpiryCoinselect := args[0].Bool()
		receivers := make([]arksdk.Receiver, args[1].Length())
		for i := 0; i < args[1].Length(); i++ {
			receiver := args[1].Index(i)
			receivers[i] = arksdk.Receiver{
				To:     receiver.Get("To").String(),
				Amount: uint64(receiver.Get("Amount").Int()),
			}
		}
		txID, err := arkSdkClient.SendOffChain(context.Background(), withExpiryCoinselect, receivers)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
	})
}

func UnilateralRedeemWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		return arkSdkClient.UnilateralRedeem(context.Background())
	})
}

func CollaborativeRedeemWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		addr := args[0].String()
		amount := uint64(args[1].Int())
		withExpiryCoinselect := args[2].Bool()
		txID, err := arkSdkClient.CollaborativeRedeem(context.Background(), addr, amount, withExpiryCoinselect)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
	})
}

type promise func(args []js.Value) (interface{}, error)

func JSPromise(fn promise) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		handlerArgs := args
		handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			resolve := args[0]
			reject := args[1]

			go func() {
				data, err := fn(handlerArgs)
				if err != nil {
					errorConstructor := js.Global().Get("Error")
					errorObject := errorConstructor.New(err.Error())
					reject.Invoke(errorObject)
				} else {
					resolve.Invoke(data)
				}
			}()

			return nil
		})

		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})
}
