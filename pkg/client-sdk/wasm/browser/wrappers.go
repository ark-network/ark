//go:build js && wasm
// +build js,wasm

package browser

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"syscall/js"
	"time"

	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	singlekeywallet "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey"
)

func ConsoleLog(msg string) {
	js.Global().Get("console").Call("log", msg)
}

func ConsoleError(err error) {
	js.Global().Get("console").Call("error", err.Error())
}

func LogWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		ConsoleLog(p[0].String())
		return nil
	})
}

func InitWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 6 {
			return nil, errors.New("invalid number of args")
		}
		chain := args[5].String()
		if chain != "bitcoin" && chain != "liquid" {
			return nil, errors.New("invalid chain, select either 'bitcoin' or 'liquid'")
		}

		var walletSvc wallet.WalletService
		switch args[0].String() {
		case arksdk.SingleKeyWallet:
			walletStore, err := getWalletStore(configStore.GetType())
			if err != nil {
				return nil, fmt.Errorf("failed to init wallet store: %s", err)
			}
			if chain == "liquid" {
				walletSvc, err = singlekeywallet.NewLiquidWallet(configStore, walletStore)
				if err != nil {
					return nil, err
				}
			} else {
				walletSvc, err = singlekeywallet.NewBitcoinWallet(configStore, walletStore)
				if err != nil {
					return nil, err
				}
			}
		default:
			return nil, fmt.Errorf("unsupported wallet type")
		}

		err := arkSdkClient.InitWithWallet(context.Background(), arksdk.InitWithWalletArgs{
			ClientType: args[1].String(),
			Wallet:     walletSvc,
			AspUrl:     args[2].String(),
			Seed:       args[3].String(),
			Password:   args[4].String(),
		})

		// Add this log message
		ConsoleLog("ARK SDK client initialized successfully")
		return nil, err
	})
}

func IsLockedWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		return js.ValueOf(arkSdkClient.IsLocked(context.Background()))
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
			onchainSpendableBalance int
			onchainLockedBalance    int
			offchainBalance         int
		)

		if resp != nil {
			onchainSpendableBalance = int(resp.OnchainBalance.SpendableAmount)
			for _, b := range resp.OnchainBalance.LockedAmount {
				onchainLockedBalance += int(b.Amount)
			}
			offchainBalance = int(resp.OffchainBalance.Total)
		}

		result := map[string]interface{}{
			"onchainBalance": map[string]interface{}{
				"spendable": onchainSpendableBalance,
				"locked":    onchainLockedBalance,
			},
			"offchainBalance": offchainBalance,
		}

		return js.ValueOf(result), nil
	})
}

func ReceiveWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if arkSdkClient == nil {
			return nil, errors.New("ARK SDK client is not initialized")
		}
		offchainAddr, boardingAddr, err := arkSdkClient.Receive(context.Background())
		if err != nil {
			return nil, err
		}
		result := map[string]interface{}{
			"offchainAddr": offchainAddr,
			"boardingAddr": boardingAddr,
		}
		return js.ValueOf(result), nil
	})
}

func DumpWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if arkSdkClient == nil {
			return nil, errors.New("ARK SDK client is not initialized")
		}
		seed, err := arkSdkClient.Dump(context.Background())
		if err != nil {
			return nil, err
		}
		return js.ValueOf(seed), nil
	})
}

func SendOnChainWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("invalid number of args")
		}
		receivers := make([]arksdk.Receiver, args[0].Length())
		for i := 0; i < args[0].Length(); i++ {
			receiver := args[0].Index(i)
			receivers[i] = arksdk.NewBitcoinReceiver(
				receiver.Get("To").String(), uint64(receiver.Get("Amount").Int()),
			)
		}

		txID, err := arkSdkClient.SendOnChain(
			context.Background(), receivers,
		)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
	})
}

func SendOffChainWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 2 {
			return nil, errors.New("invalid number of args")
		}
		withExpiryCoinselect := args[0].Bool()
		receivers := make([]arksdk.Receiver, args[1].Length())
		for i := 0; i < args[1].Length(); i++ {
			receiver := args[1].Index(i)
			receivers[i] = arksdk.NewBitcoinReceiver(
				receiver.Get("To").String(), uint64(receiver.Get("Amount").Int()),
			)
		}

		txID, err := arkSdkClient.SendOffChain(
			context.Background(), withExpiryCoinselect, receivers,
		)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
	})
}

func SendAsyncWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 2 {
			return nil, errors.New("invalid number of args")
		}
		withExpiryCoinselect := args[0].Bool()
		receivers := make([]arksdk.Receiver, args[1].Length())
		for i := 0; i < args[1].Length(); i++ {
			receiver := args[1].Index(i)
			receivers[i] = arksdk.NewBitcoinReceiver(
				receiver.Get("To").String(), uint64(receiver.Get("Amount").Int()),
			)
		}

		txID, err := arkSdkClient.SendAsync(
			context.Background(), withExpiryCoinselect, receivers,
		)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
	})
}

func ClaimWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 0 {
			return nil, errors.New("invalid number of args")
		}

		resp, err := arkSdkClient.Claim(context.Background())
		if err != nil {
			return nil, err
		}

		return js.ValueOf(resp), nil
	})
}

func UnilateralRedeemWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		return nil, arkSdkClient.UnilateralRedeem(context.Background())
	})
}

func CollaborativeRedeemWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 3 {
			return nil, errors.New("invalid number of args")
		}
		addr := args[0].String()
		amount := uint64(args[1].Int())
		withExpiryCoinselect := args[2].Bool()

		txID, err := arkSdkClient.CollaborativeRedeem(
			context.Background(), addr, amount, withExpiryCoinselect,
		)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(txID), nil
	})
}

func GetTransactionHistoryWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		history, err := arkSdkClient.GetTransactionHistory(context.Background())
		if err != nil {
			return nil, err
		}
		rawHistory := make([]map[string]interface{}, 0)
		for _, record := range history {
			rawHistory = append(rawHistory, map[string]interface{}{
				"boardingTxid": record.BoardingTxid,
				"roundTxid":    record.RoundTxid,
				"redeemTxid":   record.RedeemTxid,
				"amount":       strconv.Itoa(int(record.Amount)),
				"type":         record.Type,
				"isPending":    record.IsPending,
				"createdAt":    record.CreatedAt.Format(time.RFC3339),
			})
		}
		result, err := json.MarshalIndent(rawHistory, "", "  ")
		if err != nil {
			return nil, err
		}
		return js.ValueOf(string(result)), nil
	})
}

func GetAspUrlWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var url string
		if data != nil {
			url = data.AspUrl
		}
		return js.ValueOf(url)
	})
}

func GetAspPubkeyWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var aspPubkey string
		if data != nil {
			aspPubkey = hex.EncodeToString(data.AspPubkey.SerializeCompressed())
		}
		return js.ValueOf(aspPubkey)
	})
}

func GetWalletTypeWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var walletType string
		if data != nil {
			walletType = data.WalletType
		}
		return js.ValueOf(walletType)
	})
}

func GetClientTypeWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var clientType string
		if data != nil {
			clientType = data.ClientType
		}
		return js.ValueOf(clientType)
	})
}

func GetNetworkWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var network string
		if data != nil {
			network = data.Network.Name
		}
		return js.ValueOf(network)
	})
}

func GetRoundLifetimeWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var roundLifettime int64
		if data != nil {
			roundLifettime = data.RoundLifetime
		}
		return js.ValueOf(roundLifettime)
	})
}

func GetUnilateralExitDelayWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var unilateralExitDelay int64
		if data != nil {
			unilateralExitDelay = data.UnilateralExitDelay
		}
		return js.ValueOf(unilateralExitDelay)
	})
}

func GetDustWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var dust uint64
		if data != nil {
			dust = data.Dust
		}
		return js.ValueOf(dust)
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
