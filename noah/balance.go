package main

import (
	"sync"

	"github.com/urfave/cli/v2"
)

var balanceCommand = cli.Command{
	Name:   "balance",
	Usage:  "Print balance of the Noah wallet",
	Action: balanceAction,
}

func balanceAction(ctx *cli.Context) error {
	client, cancel, err := getClientFromState(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	offchainAddr, onchainAddr, err := getAddress()
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)

	chRes := make(chan balanceRes, 2)
	go func() {
		defer wg.Done()
		balance, err := getOffchainBalance(ctx, client, offchainAddr)
		if err != nil {
			chRes <- balanceRes{0, 0, err}
			return
		}
		chRes <- balanceRes{balance, 0, nil}
	}()
	go func() {
		defer wg.Done()
		balance, err := getOnchainBalance(onchainAddr)
		if err != nil {
			chRes <- balanceRes{0, 0, err}
			return
		}
		chRes <- balanceRes{0, balance, nil}
	}()

	wg.Wait()

	offchainBalance, onchainBalance := uint64(0), uint64(0)
	count := 0
	for res := range chRes {
		if res.err != nil {
			return res.err
		}
		if res.offchainBalance > 0 {
			offchainBalance = res.offchainBalance
		}
		if res.onchainBalance > 0 {
			onchainBalance = res.onchainBalance
		}
		count++
		if count == 2 {
			break
		}
	}

	return printJSON(map[string]interface{}{
		"offchain_balance": offchainBalance,
		"onchain_balance":  onchainBalance,
	})
}

type balanceRes struct {
	offchainBalance uint64
	onchainBalance  uint64
	err             error
}
