package main

import (
	"encoding/json"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/urfave/cli/v2"
)

var (
	receiversFlag = cli.StringFlag{
		Name:     "receivers",
		Usage:    "receivers of the send transaction, JSON encoded: '[{\"to\": \"<...>\", \"amount\": <...>}, ...]'",
		Value:    "",
		Required: true,
	}
)

var sendCommand = cli.Command{
	Name:   "send",
	Usage:  "Send VTXOs to a list of addresses",
	Action: sendAction,
	Flags:  []cli.Flag{&receiversFlag},
}

func sendAction(ctx *cli.Context) error {
	receivers := ctx.String("receivers")

	// parse json encoded receivers
	var receiversJSON []receiverJSON
	if err := json.Unmarshal([]byte(receivers), &receiversJSON); err != nil {
		return fmt.Errorf("invalid receivers: %s", err)
	}

	if len(receiversJSON) <= 0 {
		return fmt.Errorf("no receivers specified")
	}

	for _, receiver := range receiversJSON {
		// TODO: check if receiver asp public key is valid
		_, _, _, err := common.DecodeAddress(receiver.To)
		if err != nil {
			return fmt.Errorf("invalid receiver address: %s", err)
		}

		if receiver.Amount <= 0 {
			return fmt.Errorf("invalid amount: %d", receiver.Amount)
		}
	}

	req := &arkv1.RegisterPayment{}

	fmt.Println("send command is not implemented yet")

	return nil
}

type receiverJSON struct {
	To     string `json:"to"`
	Amount int64  `json:"amount"`
}
