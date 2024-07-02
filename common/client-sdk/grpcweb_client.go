//go:build js && wasm
// +build js,wasm

package arkclient

import (
	"syscall/js"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"google.golang.org/grpc"
)

func NewGrpcWebClient(aspUrl string) (ArkGrpcWebClient, func(), error) {
	if aspUrl == "" {
		return nil, nil, errAspUrlEmpty
	}

	creds := insecure.NewCredentials()
	port := 80
	if strings.HasPrefix(aspUrl, "https://") {
		aspUrl = strings.TrimPrefix(aspUrl, "https://")
		creds = credentials.NewTLS(nil)
		port = 443
	}
	if !strings.Contains(aspUrl, ":") {
		aspUrl = fmt.Sprintf("%s:%d", aspUrl, port)
	}
	conn, err := grpc.NewClient(aspUrl, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, err
	}

	closeFn := func() {
		err := conn.Close()
		if err != nil {
			fmt.Printf("error closing connection: %s\n", err)
		}
	}

	return &arkGrpcWebClient{conn: nil}, nil, nil
}

type ArkGrpcWebClient interface {
	ArkGrpcClient
	Log() js.Value
}

type arkGrpcWebClient struct {
	conn *grpc.ClientConn
}

func (a *arkGrpcWebClient) Admin() arkv1.AdminServiceClient {
	return arkv1.NewAdminServiceClient(a.conn)
}

func (a *arkGrpcWebClient) Service() arkv1.ArkServiceClient {
	return arkv1.NewArkServiceClient(a.conn)
}

func (a *arkGrpcWebClient) Log() js.Value {
	js.Global().Get("console").Call("log", "Ark Grpc Web Client configured")
	return js.Undefined()
}

func main() {
	js.Global().Set("NewArkGrpcWebClient", js.FuncOf(NewArkGrpcWebClientJS))
	select {}
}

func NewArkGrpcWebClientJS(this js.Value, p []js.Value) interface{} {
	if len(p) < 1 {
		return js.ValueOf("error: missing ASP URL")
	}
	aspUrl := p[0].String()
	client, err := NewArkGrpcWebClient(aspUrl)
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}
	return js.ValueOf(map[string]interface{}{
		"Admin": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			return js.ValueOf(client.Admin())
		}),
		"Service": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			return js.ValueOf(client.Service())
		}),
		"Log": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			return client.Log()
		}),
	})
}
