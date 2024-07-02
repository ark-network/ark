package main

import (
	"context"
	"net/http"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	arkclient "github.com/ark-network/ark/common/client-sdk"
	log "github.com/sirupsen/logrus"
)

func main() {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	client, err := arkclient.NewRestClient("your-asp-url", httpClient)
	if err != nil {
		log.Fatalf("error creating rest client: %s", err)
	}

	resp, err := client.Admin().GetBalance(
		context.Background(), &arkv1.GetBalanceRequest{},
	)
	if err != nil {
		log.Fatalf("error getting balance: %s", err)
	}

	log.Infof("balance: %s", resp.GetMainAccount().GetAvailable())
}
