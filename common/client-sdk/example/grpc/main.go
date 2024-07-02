package main

import (
	"context"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	arkclient "github.com/ark-network/ark/common/client-sdk"
	log "github.com/sirupsen/logrus"
)

func main() {
	client, cleanFn, err := arkclient.NewGrpcClient("your-asp-url")
	if err != nil {
		log.Fatalf("error creating grpc client: %s", err)
	}
	defer cleanFn()

	resp, err := client.Admin().GetBalance(
		context.Background(),
		&arkv1.GetBalanceRequest{},
	)
	if err != nil {
		log.Fatalf("error getting balance: %s", err)
	}

	log.Infof("balance: %s", resp.GetMainAccount().GetAvailable())
}
