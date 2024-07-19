package arksdkwasm

import (
	"context"
	"encoding/hex"
	"errors"
	"syscall/js"

	arksdk "github.com/ark-network/ark-sdk"
)

func LogWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		logMsg(p[0].String())
		return nil
	})
}

func logMsg(msg string) {
	js.Global().Get("console").Call("log", msg)
}

func InitWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 7 {
			return nil, errors.New("invalid number of args")
		}

		err := arkSdkClient.Init(context.Background(), arksdk.InitArgs{
			WalletType:  args[0].String(),
			ClientType:  args[1].String(),
			Network:     args[2].String(),
			AspUrl:      args[3].String(),
			ExplorerUrl: args[4].String(),
			Password:    args[5].String(),
			PrivateKey:  args[6].String(),
		})
		return nil, err
	})
}

func UnlockWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("invalid number of args")
		}
		password := args[0].String()
		err := arkSdkClient.Unlock(context.Background(), password)
		return nil, err
	})
}

func LockWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("invalid number of args")
		}
		password := args[0].String()
		err := arkSdkClient.Unlock(context.Background(), password)
		return nil, err
	})
}

func BalanceWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("invalid number of args")
		}
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
		if len(args) != 2 {
			return nil, errors.New("invalid number of args")
		}
		amount := uint64(args[0].Int())
		password := args[1].String()
		txID, err := arkSdkClient.Onboard(context.Background(), amount, password)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
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
		if len(args) != 2 {
			return nil, errors.New("invalid number of args")
		}
		receivers := make([]arksdk.Receiver, args[0].Length())
		for i := 0; i < args[0].Length(); i++ {
			receiver := args[0].Index(i)
			receivers[i] = arksdk.Receiver{
				To:     receiver.Get("To").String(),
				Amount: uint64(receiver.Get("Amount").Int()),
			}
		}
		password := args[1].String()
		txID, err := arkSdkClient.SendOnChain(
			context.Background(), receivers, password,
		)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
	})
}

func SendOffChainWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 3 {
			return nil, errors.New("invalid number of args")
		}
		withExpiryCoinselect := args[0].Bool()
		receivers := make([]arksdk.Receiver, args[1].Length())
		for i := 0; i < args[1].Length(); i++ {
			receiver := args[1].Index(i)
			receivers[i] = arksdk.Receiver{
				To:     receiver.Get("To").String(),
				Amount: uint64(receiver.Get("Amount").Int()),
			}
		}
		password := args[2].String()
		txID, err := arkSdkClient.SendOffChain(
			context.Background(), withExpiryCoinselect, receivers, password,
		)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
	})
}

func UnilateralRedeemWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("invalid number of args")
		}
		password := args[0].String()
		return nil, arkSdkClient.UnilateralRedeem(
			context.Background(), password,
		)
	})
}

func CollaborativeRedeemWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 4 {
			return nil, errors.New("invalid number of args")
		}
		addr := args[0].String()
		amount := uint64(args[1].Int())
		withExpiryCoinselect := args[2].Bool()
		password := args[3].String()
		txID, err := arkSdkClient.CollaborativeRedeem(
			context.Background(), addr, amount, withExpiryCoinselect, password,
		)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
	})
}

func GetAspUrlWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.Store().GetData(context.Background())
		var url string
		if data != nil {
			url = data.AspUrl
		}
		return js.ValueOf(url)
	})
}

func GetAspPubkeyWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.Store().GetData(context.Background())
		var aspPubkey string
		if data != nil {
			aspPubkey = hex.EncodeToString(data.AspPubkey.SerializeCompressed())
		}
		return js.ValueOf(aspPubkey)
	})
}

func GetWalletTypeWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.Store().GetData(context.Background())
		var walletType string
		if data != nil {
			walletType = data.WalletType
		}
		return js.ValueOf(walletType)
	})
}

func GetClientTypeWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.Store().GetData(context.Background())
		var clientType string
		if data != nil {
			clientType = data.ClientType
		}
		return js.ValueOf(clientType)
	})
}

func GetExplorerUrlWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.Store().GetData(context.Background())
		var url string
		if data != nil {
			url = data.ExplorerURL
		}
		return js.ValueOf(url)
	})
}

func GetNetworkWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.Store().GetData(context.Background())
		var network string
		if data != nil {
			network = data.Network.Name
		}
		return js.ValueOf(network)
	})
}

func GetRoundLifetimeWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.Store().GetData(context.Background())
		var roundLifettime int64
		if data != nil {
			roundLifettime = data.RoundLifetime
		}
		return js.ValueOf(roundLifettime)
	})
}

func GetUnilateralExitDelayWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.Store().GetData(context.Background())
		var unilateralExitDelay int64
		if data != nil {
			unilateralExitDelay = data.UnilateralExitDelay
		}
		return js.ValueOf(unilateralExitDelay)
	})
}

func GetMinRelayFeeWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.Store().GetData(context.Background())
		var minRelayFee uint64
		if data != nil {
			minRelayFee = data.MinRelayFee
		}
		return js.ValueOf(minRelayFee)
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
