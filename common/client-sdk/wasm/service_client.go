//go:build js && wasm
// +build js,wasm

package arkwasmclient

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"syscall/js"

	"encoding/json"
	"errors"

	"github.com/ark-network/ark/common/client-sdk/rest/service/arkservicerestclient"
	"github.com/ark-network/ark/common/client-sdk/rest/service/arkservicerestclient/ark_service"
	"github.com/ark-network/ark/common/client-sdk/rest/service/models"
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

var (
	invalidArgsError = errors.New("invalid number of arguments")
)

func main() {
	js.Global().Set("RestServiceClient", RestServiceClientWrapper())
	js.Global().Set("InvokeRestServiceClientMethod", RestServiceClientWrapper())
	js.Global().Set("Log", Log())
	select {}
}

func Log() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		js.Global().Get("console").Call("log", "Hello from Service ArkWasmClient!")
		return nil
	})
}

func RestServiceClientWrapper() js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) < 1 {
			return nil, invalidArgsError
		}

		baseURL := args[0].String()
		formats := strfmt.Default

		serviceClient := NewHTTPClientService(baseURL, formats)

		return js.ValueOf(serviceClient), nil // Wrap the serviceClient in js.ValueOf
	})
}

func InvokeRestServiceClientMethod(serviceClient *arkservicerestclient.ArkV1ServiceProto) js.Func {
	return JSPromise(func(args []js.Value) (interface{}, error) {
		if len(args) < 2 {
			return nil, invalidArgsError
		}

		method := args[0].String()
		params := args[1:]

		switch method {
		case "RegisterPayment":
			if len(params) != 1 {
				return nil, invalidArgsError
			}
			p := ark_service.NewArkServiceRegisterPaymentParams()
			body := models.V1RegisterPaymentRequest{}
			if err := json.Unmarshal([]byte(params[0].String()), &body); err != nil {
				return nil, err
			}
			p.SetBody(&body)
			return wrapServiceRegisterPayment(serviceClient, p)
		case "ClaimPayment":
			if len(params) != 1 {
				return nil, invalidArgsError
			}
			p := ark_service.NewArkServiceClaimPaymentParams()
			body := models.V1ClaimPaymentRequest{}
			if err := json.Unmarshal([]byte(params[0].String()), &body); err != nil {
				return nil, err
			}
			p.SetBody(&body)
			return wrapServiceClaimPayment(serviceClient, p)
		case "GetInfo":
			return wrapServiceGetInfo(serviceClient)
		case "ListVtxos":
			if len(params) != 1 {
				return nil, invalidArgsError
			}
			p := ark_service.NewArkServiceListVtxosParams()
			p.SetAddress(params[0].String())
			return wrapServiceListVtxos(serviceClient, p)
		case "Ping":
			if len(params) != 1 {
				return nil, invalidArgsError
			}
			p := ark_service.NewArkServicePingParams()
			p.SetPaymentID(params[0].String())
			return wrapServicePing(serviceClient, p)
		case "GetEventStream":
			return wrapServiceGetEventStream(serviceClient)
		case "Onboard":
			if len(params) != 1 {
				return nil, invalidArgsError
			}
			p := ark_service.NewArkServiceOnboardParams()
			body := models.V1OnboardRequest{}
			if err := json.Unmarshal([]byte(params[0].String()), &body); err != nil {
				return nil, err
			}
			p.SetBody(&body)
			return wrapServiceOnboard(serviceClient, p)
		case "FinalizePayment":
			if len(params) != 1 {
				return nil, invalidArgsError
			}
			p := ark_service.NewArkServiceFinalizePaymentParams()
			body := models.V1FinalizePaymentRequest{}
			if err := json.Unmarshal([]byte(params[0].String()), &body); err != nil {
				return nil, err
			}
			p.SetBody(&body)
			return wrapServiceFinalizePayment(serviceClient, p)
		case "TrustedOnboarding":
			if len(params) != 1 {
				return nil, invalidArgsError
			}
			p := ark_service.NewArkServiceTrustedOnboardingParams()
			body := models.V1TrustedOnboardingRequest{}
			if err := json.Unmarshal([]byte(params[0].String()), &body); err != nil {
				return nil, err
			}
			p.SetBody(&body)
			return wrapServiceTrustedOnboarding(serviceClient, p)
		case "GetRound":
			if len(params) != 1 {
				return nil, invalidArgsError
			}
			p := ark_service.NewArkServiceGetRoundParams()
			p.SetTxid(params[0].String())
			return wrapServiceGetRound(serviceClient, p)
		case "GetUser":
			if len(params) != 1 {
				return nil, invalidArgsError
			}
			req := Request{}
			if err := json.Unmarshal([]byte(params[0].String()), &req); err != nil {
				return nil, err
			}
			return wrapServiceGetUser(req)
		default:
			return nil, errors.New("unknown method")
		}
	})
}

type Request struct {
	Name    string `json:"name"`
	Surname string `json:"surname"`
}

func wrapServiceGetUser(req Request) (interface{}, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post("http://localhost:9000/info", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return string(respBody), nil
}

func wrapServiceRegisterPayment(
	serviceClient *arkservicerestclient.ArkV1ServiceProto,
	params *ark_service.ArkServiceRegisterPaymentParams,
) (string, error) {
	result, err := serviceClient.ArkService.ArkServiceRegisterPayment(params)
	if err != nil {
		return "", err
	}
	jsonResult, err := json.Marshal(result.Payload)
	if err != nil {
		return "", err
	}
	return string(jsonResult), nil
}

func wrapServiceClaimPayment(
	serviceClient *arkservicerestclient.ArkV1ServiceProto,
	params *ark_service.ArkServiceClaimPaymentParams,
) (string, error) {
	result, err := serviceClient.ArkService.ArkServiceClaimPayment(params)
	if err != nil {
		return "", err
	}
	jsonResult, err := json.Marshal(result.Payload)
	if err != nil {
		return "", err
	}
	return string(jsonResult), nil
}

func wrapServiceGetInfo(
	serviceClient *arkservicerestclient.ArkV1ServiceProto,
) (string, error) {
	result, err := serviceClient.ArkService.ArkServiceGetInfo(ark_service.NewArkServiceGetInfoParams())
	if err != nil {
		return "", err
	}
	jsonResult, err := json.Marshal(result.Payload)
	if err != nil {
		return "", err
	}
	return string(jsonResult), nil
}

func wrapServiceListVtxos(
	serviceClient *arkservicerestclient.ArkV1ServiceProto,
	params *ark_service.ArkServiceListVtxosParams,
) (string, error) {
	result, err := serviceClient.ArkService.ArkServiceListVtxos(params)
	if err != nil {
		return "", err
	}
	jsonResult, err := json.Marshal(result.Payload)
	if err != nil {
		return "", err
	}
	return string(jsonResult), nil
}

func wrapServicePing(
	serviceClient *arkservicerestclient.ArkV1ServiceProto,
	params *ark_service.ArkServicePingParams,
) (string, error) {
	result, err := serviceClient.ArkService.ArkServicePing(params)
	if err != nil {
		return "", err
	}
	jsonResult, err := json.Marshal(result.Payload)
	if err != nil {
		return "", err
	}
	return string(jsonResult), nil
}

func wrapServiceGetEventStream(
	serviceClient *arkservicerestclient.ArkV1ServiceProto,
) (string, error) {
	result, err := serviceClient.ArkService.ArkServiceGetEventStream(
		ark_service.NewArkServiceGetEventStreamParams(),
	)
	if err != nil {
		return "", err
	}
	jsonResult, err := json.Marshal(result.Payload)
	if err != nil {
		return "", err
	}
	return string(jsonResult), nil
}

func wrapServiceOnboard(
	serviceClient *arkservicerestclient.ArkV1ServiceProto,
	params *ark_service.ArkServiceOnboardParams) (string, error) {
	result, err := serviceClient.ArkService.ArkServiceOnboard(params)
	if err != nil {
		return "", err
	}
	jsonResult, err := json.Marshal(result.Payload)
	if err != nil {
		return "", err
	}
	return string(jsonResult), nil
}

func wrapServiceFinalizePayment(
	serviceClient *arkservicerestclient.ArkV1ServiceProto,
	params *ark_service.ArkServiceFinalizePaymentParams,
) (string, error) {
	result, err := serviceClient.ArkService.ArkServiceFinalizePayment(params)
	if err != nil {
		return "", err
	}
	jsonResult, err := json.Marshal(result.Payload)
	if err != nil {
		return "", err
	}
	return string(jsonResult), nil
}

func wrapServiceTrustedOnboarding(
	serviceClient *arkservicerestclient.ArkV1ServiceProto,
	params *ark_service.ArkServiceTrustedOnboardingParams,
) (string, error) {
	result, err := serviceClient.ArkService.ArkServiceTrustedOnboarding(params)
	if err != nil {
		return "", err
	}
	jsonResult, err := json.Marshal(result.Payload)
	if err != nil {
		return "", err
	}
	return string(jsonResult), nil
}

func wrapServiceGetRound(
	serviceClient *arkservicerestclient.ArkV1ServiceProto,
	params *ark_service.ArkServiceGetRoundParams,
) (string, error) {
	result, err := serviceClient.ArkService.ArkServiceGetRound(params)
	if err != nil {
		return "", err
	}
	jsonResult, err := json.Marshal(result.Payload)
	if err != nil {
		return "", err
	}
	return string(jsonResult), nil
}

func NewHTTPClientService(baseURL string, formats strfmt.Registry) *arkservicerestclient.ArkV1ServiceProto {
	if formats == nil {
		formats = strfmt.Default
	}
	transport := httptransport.New(baseURL, arkservicerestclient.DefaultBasePath, arkservicerestclient.DefaultSchemes)
	return NewService(transport, formats)
}

func NewService(transport runtime.ClientTransport, formats strfmt.Registry) *arkservicerestclient.ArkV1ServiceProto {
	cli := new(arkservicerestclient.ArkV1ServiceProto)
	cli.Transport = transport
	cli.ArkService = ark_service.New(transport, formats)
	return cli
}

type promise func(args []js.Value) (interface{}, error)

func JSPromise(fn promise) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// args[0] is a js.Value, so we need to get a string out of it
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
				}

				resolve.Invoke(data)
			}()

			// The handler of a Promise doesn't return any value
			return nil
		})

		// Create and return the Promise object
		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})
}
