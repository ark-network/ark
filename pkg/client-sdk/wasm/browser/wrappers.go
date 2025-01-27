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
	"github.com/ark-network/ark/pkg/client-sdk/client"
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
		// TODO: add another withTransactionFeed args to configure client listen to
		// new txs from the server. Requires server to use websockets.
		if len(args) != 7 {
			return nil, errors.New("invalid number of args")
		}
		chain := args[5].String()
		if chain != "bitcoin" && chain != "liquid" {
			return nil, errors.New("invalid chain, select either 'bitcoin' or 'liquid'")
		}

		configStore := store.ConfigStore()
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
			ClientType:  args[1].String(),
			Wallet:      walletSvc,
			ServerUrl:   args[2].String(),
			Seed:        args[3].String(),
			Password:    args[4].String(),
			ExplorerURL: args[6].String(),
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

func ListVtxosWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if arkSdkClient == nil {
			return nil, errors.New("ARK SDK client is not initialized")
		}
		spendable, spent, err := arkSdkClient.ListVtxos(context.Background())
		if err != nil {
			return nil, err
		}
		rawList := map[string]interface{}{
			"spendable": spendable,
			"spent":     spent,
		}
		result, err := json.Marshal(rawList)
		if err != nil {
			return nil, err
		}
		return js.ValueOf(string(result)), nil
	})
}

func SendOnChainWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("invalid number of args")
		}

		receivers, err := parseReceivers(args[0])
		if err != nil {
			return nil, err
		}

		if receivers == nil || len(receivers) == 0 {
			return nil, errors.New("no receivers specified")
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
		if len(args) != 2 {
			return nil, errors.New("invalid number of args")
		}

		withExpiryCoinselect := args[0].Bool()
		receivers, err := parseReceivers(args[1])
		if err != nil {
			return nil, err
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

func SettleWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 0 {
			return nil, errors.New("invalid number of args")
		}

		resp, err := arkSdkClient.Settle(context.Background())
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
				"settled":      record.Settled,
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

func GetServerUrlWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var url string
		if data != nil {
			url = data.ServerUrl
		}
		return js.ValueOf(url)
	})
}

func GetServerPubkeyWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var serverPubkey string
		if data != nil {
			serverPubkey = hex.EncodeToString(data.ServerPubKey.SerializeCompressed())
		}
		return js.ValueOf(serverPubkey)
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

func GetVtxoTreeExpiryWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var vtxoTreeExpiry int64
		if data != nil {
			vtxoTreeExpiry = data.VtxoTreeExpiry.Seconds()
		}
		return js.ValueOf(vtxoTreeExpiry)
	})
}

func GetUnilateralExitDelayWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		data, _ := arkSdkClient.GetConfigData(context.Background())
		var unilateralExitDelay int64
		if data != nil {
			unilateralExitDelay = data.UnilateralExitDelay.Seconds()
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

func GetVersionWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		return js.ValueOf(version)
	})
}

func RedeemNotesWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("invalid number of args")
		}

		// Parse notes array from JS
		jsNotes := args[0]
		if jsNotes.Type() != js.TypeObject || jsNotes.Get("length").Type() != js.TypeNumber {
			return nil, errors.New("invalid notes argument: expected array")
		}

		notes := make([]string, 0, jsNotes.Length())
		for i := 0; i < jsNotes.Length(); i++ {
			notes = append(notes, jsNotes.Index(i).String())
		}

		txID, err := arkSdkClient.RedeemNotes(context.Background(), notes)
		if err != nil {
			return nil, err
		}

		return js.ValueOf(txID), nil
	})
}

func SetNostrNotificationRecipientWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("invalid number of args")
		}

		nostrRecipient := args[0].String()
		err := arkSdkClient.SetNostrNotificationRecipient(context.Background(), nostrRecipient)
		return nil, err
	})
}

func SignTransactionWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("invalid number of args")
		}

		tx := args[0]

		if tx.Type() != js.TypeString {
			return nil, errors.New("invalid transaction argument: expected string")
		}

		return arkSdkClient.SignTransaction(context.Background(), tx.String())
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

func parseReceivers(jsReceivers js.Value) ([]arksdk.Receiver, error) {
	if jsReceivers.IsNull() || jsReceivers.IsUndefined() {
		return nil, nil // Return nil slice if input is null or undefined
	}

	if jsReceivers.Type() != js.TypeObject || jsReceivers.Get("length").Type() != js.TypeNumber {
		return nil, errors.New("invalid receivers argument: expected array")
	}

	length := jsReceivers.Length()
	if length == 0 {
		return []arksdk.Receiver{}, nil // Return empty slice if input array is empty
	}

	receivers := make([]arksdk.Receiver, length)
	for i := 0; i < length; i++ {
		receiver := jsReceivers.Index(i)
		if receiver.Type() != js.TypeObject {
			return nil, fmt.Errorf("invalid receiver at index %d: expected object", i)
		}

		to := receiver.Get("To")
		amount := receiver.Get("Amount")
		if to.Type() != js.TypeString || amount.Type() != js.TypeNumber {
			return nil, fmt.Errorf("invalid receiver at index %d: expected 'To' (string) and 'Amount' (number)", i)
		}

		receivers[i] = arksdk.NewBitcoinReceiver(to.String(), uint64(amount.Int()))
	}

	return receivers, nil
}

func parseOutpoints(jsOutpoints js.Value) ([]client.Outpoint, error) {
	if jsOutpoints.Length() == 0 {
		return nil, nil
	}

	outpoints := make([]client.Outpoint, jsOutpoints.Length())
	for i := 0; i < jsOutpoints.Length(); i++ {
		jsOutpoint := jsOutpoints.Index(i)
		if jsOutpoint.Type() != js.TypeObject {
			return nil, fmt.Errorf("invalid outpoint at index %d: expected object", i)
		}

		txid := jsOutpoint.Get("Txid")
		vout := jsOutpoint.Get("Vout")
		if txid.Type() != js.TypeString || vout.Type() != js.TypeNumber {
			return nil, fmt.Errorf("invalid outpoint at index %d: expected 'Txid' (string) and 'Vout' (number)", i)
		}

		outpoints[i] = client.Outpoint{
			Txid: txid.String(),
			VOut: uint32(vout.Int()),
		}
	}

	return outpoints, nil
}
