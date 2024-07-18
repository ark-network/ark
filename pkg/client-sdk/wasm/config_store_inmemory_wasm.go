package arksdkwasm

import (
	"context"
	"syscall/js"

	arksdk "github.com/ark-network/ark-sdk"
)

func GetAspUrlWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		url, _ := inMemoryConfigStore.GetAspUrl(context.Background())
		return js.ValueOf(url)
	})
}

func GetAspPubKeyHexWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		key, _ := inMemoryConfigStore.GetAspPubKeyHex(context.Background())
		return js.ValueOf(key)
	})
}

func GetTransportProtocolWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		protocol, _ := inMemoryConfigStore.GetTransportProtocol(context.Background())
		return js.ValueOf(int(protocol))
	})
}

func GetExplorerUrlWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		url, _ := inMemoryConfigStore.GetExplorerUrl(context.Background())
		return js.ValueOf(url)
	})
}

func GetNetworkWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		network, _ := inMemoryConfigStore.GetNetwork(context.Background())
		return js.ValueOf(network)
	})
}

func SetAspUrlWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		aspUrl := p[0].String()
		inMemoryConfigStore.SetAspUrl(aspUrl)
		return nil
	})
}

func SetAspPubKeyHexWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		aspPubKeyHex := p[0].String()
		inMemoryConfigStore.SetAspPubKeyHex(aspPubKeyHex)
		return nil
	})
}

func SetTransportProtocolWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		protocol := arksdk.TransportProtocol(p[0].Int())
		inMemoryConfigStore.SetTransportProtocol(protocol)
		return nil
	})
}

func SetExplorerUrlWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		explorerUrl := p[0].String()
		inMemoryConfigStore.SetExplorerUrl(explorerUrl)
		return nil
	})
}

func SetNetworkWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		network := p[0].String()
		inMemoryConfigStore.SetNetwork(network)
		return nil
	})
}

func SaveWrapper() js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		err := inMemoryConfigStore.Save(context.Background())
		if err != nil {
			return js.ValueOf(map[string]interface{}{
				"error": err.Error(),
			})
		}
		return nil
	})
}
