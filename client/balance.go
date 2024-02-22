package main

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
)

var expiryDetailsFlag = cli.BoolFlag{
	Name:     "expiry-details",
	Usage:    "show cumulative balance by expiry time",
	Value:    false,
	Required: false,
}

var balanceCommand = cli.Command{
	Name:   "balance",
	Usage:  "Print balance of the Ark wallet",
	Action: balanceAction,
	Flags:  []cli.Flag{&expiryDetailsFlag},
}

func balanceAction(ctx *cli.Context) error {
	withExpiryDetails := ctx.Bool("expiry-details")

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
	wg.Add(3)

	chRes := make(chan balanceRes, 3)
	go func() {
		defer wg.Done()
		explorer := NewExplorer()
		balance, amountByExpiration, err := getOffchainBalance(
			ctx, explorer, client, offchainAddr, withExpiryDetails,
		)
		if err != nil {
			chRes <- balanceRes{0, 0, nil, nil, err}
			return
		}

		chRes <- balanceRes{balance, 0, nil, amountByExpiration, nil}
	}()

	go func() {
		defer wg.Done()
		balance, err := getOnchainBalance(onchainAddr)
		if err != nil {
			chRes <- balanceRes{0, 0, nil, nil, err}
			return
		}
		chRes <- balanceRes{0, balance, nil, nil, nil}
	}()

	go func() {
		defer wg.Done()
		availableBalance, futureBalance, err := getOnchainVtxosBalance()
		if err != nil {
			chRes <- balanceRes{0, 0, nil, nil, err}
			return
		}

		chRes <- balanceRes{0, availableBalance, futureBalance, nil, err}
	}()

	wg.Wait()

	lockedOnchainBalance := []map[string]interface{}{}
	details := make([]map[string]interface{}, 0)
	offchainBalance, onchainBalance := uint64(0), uint64(0)
	nextExpiration := int64(0)
	count := 0
	for res := range chRes {
		if res.err != nil {
			return res.err
		}
		if res.offchainBalance > 0 {
			offchainBalance = res.offchainBalance
		}
		if res.onchainBalance > 0 {
			onchainBalance += res.onchainBalance
		}
		if res.amountByExpiration != nil {
			for timestamp, amount := range res.amountByExpiration {
				if nextExpiration == 0 || timestamp < nextExpiration {
					nextExpiration = timestamp
				}

				fancyTime := time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
				details = append(
					details,
					map[string]interface{}{
						"expiry_time": fancyTime,
						"amount":      amount,
					},
				)
			}
		}
		if res.futureBalance != nil {
			for timestamp, amount := range res.futureBalance {
				fancyTime := time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
				lockedOnchainBalance = append(
					lockedOnchainBalance,
					map[string]interface{}{
						"spendable_at": fancyTime,
						"amount":       amount,
					},
				)
			}
		}

		count++
		if count == 3 {
			break
		}
	}

	response := make(map[string]interface{})
	response["onchain_balance"] = map[string]interface{}{
		"spendable_amount": onchainBalance,
	}

	if len(lockedOnchainBalance) > 0 {
		response["onchain_balance"].(map[string]interface{})["locked_amount"] = lockedOnchainBalance
	}

	offchainBalanceJSON := map[string]interface{}{
		"total": offchainBalance,
	}

	fancyTimeExpiration := ""
	if nextExpiration != 0 {
		t := time.Unix(nextExpiration, 0)
		if t.Before(time.Now().Add(48 * time.Hour)) {
			// print the duration instead of the absolute time
			until := time.Until(t)
			seconds := math.Abs(until.Seconds())
			minutes := math.Abs(until.Minutes())
			hours := math.Abs(until.Hours())

			if hours < 1 {
				if minutes < 1 {
					fancyTimeExpiration = fmt.Sprintf("%d seconds", int(seconds))
				} else {
					fancyTimeExpiration = fmt.Sprintf("%d minutes", int(minutes))
				}
			} else {
				fancyTimeExpiration = fmt.Sprintf("%d hours", int(hours))
			}
		} else {
			fancyTimeExpiration = t.Format("2006-01-02 15:04:05")
		}

		offchainBalanceJSON["next_expiration"] = fancyTimeExpiration
	}

	if withExpiryDetails {
		offchainBalanceJSON["details"] = details
	}

	response["offchain_balance"] = offchainBalanceJSON

	return printJSON(response)
}

type balanceRes struct {
	offchainBalance    uint64
	onchainBalance     uint64
	futureBalance      map[int64]uint64 // availableAt -> onchain balance
	amountByExpiration map[int64]uint64 // expireAt -> offchain balance
	err                error
}
