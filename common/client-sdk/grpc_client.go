package arkclient

import (
	"fmt"
	"strings"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func NewGrpcClient(aspUrl string) (ArkGrpcClient, func(), error) {
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

	return &arkGrpcClient{conn: conn}, closeFn, nil
}

type ArkGrpcClient interface {
	Admin() arkv1.AdminServiceClient
	Service() arkv1.ArkServiceClient
}

type arkGrpcClient struct {
	conn *grpc.ClientConn
}

func (a *arkGrpcClient) Admin() arkv1.AdminServiceClient {
	return arkv1.NewAdminServiceClient(a.conn)
}

func (a *arkGrpcClient) Service() arkv1.ArkServiceClient {
	return arkv1.NewArkServiceClient(a.conn)
}
