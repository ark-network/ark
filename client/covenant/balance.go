package covenant

import (
	"fmt"
	"math"
	"sync"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/client/flags"
	"github.com/ark-network/ark/client/utils"
	"github.com/ark-network/ark/pkg/descriptor"
	"github.com/urfave/cli/v2"
)

func (*covenantLiquidCLI) Balance(ctx *cli.Context) error {
	computeExpiryDetails := ctx.Bool(flags.ExpiryDetailsFlag.Name)

	client, cancel, err := getClientFromState(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	offchainAddr, onboardingAddr, redemptionAddr, err := getAddress(ctx)
	if err != nil {
		return err
	}

	// No need to check for error here becuase this function is called also by getAddress().
	// nolint:all
	unilateralExitDelay, _ := utils.GetUnilateralExitDelay(ctx)

	boardingDescriptor, err := utils.GetBoardingDescriptor(ctx)
	if err != nil {
		return err
	}

	desc, err := descriptor.ParseTaprootDescriptor(boardingDescriptor)
	if err != nil {
		return err
	}

	_, timeoutBoarding, err := descriptor.ParseBoardingDescriptor(desc)
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(3)

	chRes := make(chan balanceRes, 3)
	go func() {
		defer wg.Done()
		explorer := utils.NewExplorer(ctx)
		balance, amountByExpiration, err := getOffchainBalance(
			ctx, explorer, client, offchainAddr, computeExpiryDetails,
		)
		if err != nil {
			chRes <- balanceRes{0, 0, nil, nil, err}
			return
		}

		chRes <- balanceRes{balance, 0, nil, amountByExpiration, nil}
	}()

	go func() {
		defer wg.Done()
		explorer := utils.NewExplorer(ctx)
		spendableBalance, lockedBalance, err := explorer.GetDelayedBalance(onboardingAddr, int64(timeoutBoarding))
		if err != nil {
			chRes <- balanceRes{0, 0, nil, nil, err}
			return
		}
		chRes <- balanceRes{0, spendableBalance, lockedBalance, nil, nil}
	}()

	go func() {
		defer wg.Done()
		explorer := utils.NewExplorer(ctx)

		spendableBalance, lockedBalance, err := explorer.GetDelayedBalance(
			redemptionAddr, unilateralExitDelay,
		)
		if err != nil {
			chRes <- balanceRes{0, 0, nil, nil, err}
			return
		}

		chRes <- balanceRes{0, spendableBalance, lockedBalance, nil, err}
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
		if res.onchainSpendableBalance > 0 {
			onchainBalance += res.onchainSpendableBalance
		}
		if res.offchainBalanceByExpiration != nil {
			for timestamp, amount := range res.offchainBalanceByExpiration {
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
		if res.onchainLockedBalance != nil {
			for timestamp, amount := range res.onchainLockedBalance {
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

	offchainBalanceJSON["details"] = details

	response["offchain_balance"] = offchainBalanceJSON

	return utils.PrintJSON(response)
}

type balanceRes struct {
	offchainBalance             uint64
	onchainSpendableBalance     uint64
	onchainLockedBalance        map[int64]uint64
	offchainBalanceByExpiration map[int64]uint64
	err                         error
}

func getOffchainBalance(
	ctx *cli.Context, explorer utils.Explorer, client arkv1.ArkServiceClient,
	addr string, computeExpiration bool,
) (uint64, map[int64]uint64, error) {
	amountByExpiration := make(map[int64]uint64, 0)

	vtxos, err := getVtxos(ctx, explorer, client, addr, computeExpiration)
	if err != nil {
		return 0, nil, err
	}
	var balance uint64
	for _, vtxo := range vtxos {
		balance += vtxo.amount

		if vtxo.expireAt != nil {
			expiration := vtxo.expireAt.Unix()

			if _, ok := amountByExpiration[expiration]; !ok {
				amountByExpiration[expiration] = 0
			}

			amountByExpiration[expiration] += vtxo.amount
		}
	}

	return balance, amountByExpiration, nil
}
