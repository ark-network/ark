package arksdk

import (
	"context"
	"syscall/js"
)

var arkSdkClient ArkClient

func NewArkSdkWasmClient(ctx context.Context, wallet Wallet, configStore ConfigStore) error {
	var err error
	arkSdkClient, err = New(ctx, wallet, configStore)
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
	js.Global().Set("forceRedeem", ForceRedeemWrapper())
	js.Global().Set("collaborativeRedeem", CollaborativeRedeemWrapper())
	js.Global().Set("log", LogWrapper())

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
		return js.ValueOf(resp), nil
	})
}

func OnboardWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
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
		return js.ValueOf(map[string]string{
			"offchainAddr": offchainAddr,
			"onchainAddr":  onchainAddr,
		}), nil
	})
}

func SendOnChainWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		receivers := make([]Receiver, args[0].Length())
		for i := 0; i < args[0].Length(); i++ {
			receiver := args[0].Index(i)
			receivers[i] = Receiver{
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
		receivers := make([]Receiver, args[1].Length())
		for i := 0; i < args[1].Length(); i++ {
			receiver := args[1].Index(i)
			receivers[i] = Receiver{
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

func ForceRedeemWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		err := arkSdkClient.ForceRedeem(context.Background())
		return nil, err
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
