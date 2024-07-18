package arksdkwasm

import (
	"context"
	"syscall/js"
)

func CreatePrivateKeyWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		_, err := inMemoryWalletStore.CreatePrivateKey()
		if err != nil {
			return js.ValueOf(map[string]interface{}{
				"error": err.Error(),
			})
		}

		pkHex, err := inMemoryWalletStore.GetPrivateKeyHex()
		if err != nil {
			return js.ValueOf(map[string]interface{}{
				"error": err.Error(),
			})
		}

		return js.ValueOf(pkHex)
	})
}

func GetPrivateKeyHexWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		keyHex, err := inMemoryWalletStore.GetPrivateKeyHex()
		if err != nil {
			return js.ValueOf(map[string]interface{}{
				"error": err.Error(),
			})
		}
		return js.ValueOf(keyHex)
	})
}

func SaveWalletStoreWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		err := inMemoryWalletStore.Save(context.Background())
		if err != nil {
			return js.ValueOf(map[string]interface{}{
				"error": err.Error(),
			})
		}
		return nil
	})
}
