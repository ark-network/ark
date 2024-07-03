package main

import (
	"os"

	adminclient "github.com/ark-network/ark/common/client-sdk/rest/admin/client"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
)

func main() {
	transport := httptransport.New(os.Getenv("TODOLIST_HOST"), "", nil)
	client := adminclient.New(transport, strfmt.Default)
	resp, err := client.AdminService.AdminServiceGetBalance(nil)
	if err != nil {
		log.Fatalf("error getting balance: %s", err)
	}

	log.Infof("balance: %s", resp.Payload.MainAccount.Available)
}
