package main

import (
	"math/rand"
	"strconv"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
)

func randomSats() string {
	randomNumber := 666 + rand.Intn(100000)
	return strconv.Itoa(randomNumber)
}

func getBalance() *arkv1.GetBalanceResponse {
	return &arkv1.GetBalanceResponse{
		MainAccount:       &arkv1.Balance{Available: "675884", Locked: "76523"},
		ConnectorsAccount: &arkv1.Balance{Available: "65442", Locked: "7653"},
	}
}

func getNextSweeps() *arkv1.GetScheduledSweepResponse {
	var vout uint32 = 1
	var when int64 = 1718891827

	outputs := make([]*arkv1.SweepableOutput, 0)

	outputs = append(outputs, &arkv1.SweepableOutput{
		Txid:        "83b54521f2cd2e4dc6265686276641d9918aebdaa86d8d38730adfdb5359c956",
		Vout:        vout,
		ScheduledAt: when,
		Amount:      randomSats(),
	})

	outputs = append(outputs, &arkv1.SweepableOutput{
		Txid:        "d8053da1306627baba4545269188f095f03838273a933289db91113601957eeb",
		Vout:        vout,
		ScheduledAt: when,
		Amount:      randomSats(),
	})

	sweeps := make([]*arkv1.ScheduledSweep, 0)

	sweeps = append(sweeps, &arkv1.ScheduledSweep{
		RoundId: "83b54521f2cd2e4dc6265686276641d9918aebdaa86d8d38730adfdb5359c956",
		Outputs: outputs,
	})

	sweeps = append(sweeps, &arkv1.ScheduledSweep{
		RoundId: "c4cd8111d1b4aeaae0a6e66166615f3ce5685024758765db376894b10ab5d434",
		Outputs: outputs,
	})

	sweeps = append(sweeps, &arkv1.ScheduledSweep{
		RoundId: "ff3975a31f9ebc14421f820c45456badfd7a406d91d626efe68b4f0888c62a6d",
		Outputs: outputs,
	})

	return &arkv1.GetScheduledSweepResponse{Sweeps: sweeps}
}

func getRoundDetails(txid ...string) *arkv1.GetRoundDetailsResponse {
	var round_txid string
	if len(txid) > 0 {
		round_txid = txid[0]
	} else {
		round_txid = "4606d68e0a1cd77be1a246b69778c65c7693973bf4f000b21d131e8b9d32bc59"
	}

	inputVtxos := []string{
		"6f165e2b0ae69b260a32c505f7204bf8c6e0aef654157136dca9194494b78a81", "b5f6a61df2c72c32cbee4042848c37a7c268ca424049ebabb6e30d50bd035c71", "0ab565c1f56b60a26c7daf92cc825d40b8675417792b3b7e73784f56d41116b5",
	}
	outputVtxos := []string{
		"aebee95dfbd7d3cbf855432d0c239ec115837467f3051ac986b5c8f5d9fae906", "c4a35b7b2ce9a4b6996e86e29609f5e8f73f29bacd749b3610e4f89a75c216ca", "3a639ccd65ce60f90b6be07f9209598d2aea76b9938cc30db1de3fa1034ecf9d",
	}
	exitAddresses := []string{
		"bc1qr4356l02af8ura6hgxrqa2wx0lesdxfjxdnau0",
		"bc1q0y6h8xe97pnf85dcd5puwsm5up94aesxrcd8yp",
		"bc1q83ep02rpedffsn9xm57yd54v48x7xsf6cdwfea",
	}

	return &arkv1.GetRoundDetailsResponse{
		RoundId:          "550e8400-e29b-41d4-a716-446655440000",
		Txid:             round_txid,
		ForfeitedAmount:  randomSats(),
		TotalVtxosAmount: randomSats(),
		TotalExitAmount:  randomSats(),
		FeesAmount:       randomSats(),
		InputsVtxos:      inputVtxos,
		OutputsVtxos:     outputVtxos,
		ExitAddresses:    exitAddresses,
	}
}

func getLastRounds() *arkv1.GetRoundsResponse {
	return &arkv1.GetRoundsResponse{
		Rounds: []string{
			"40f841c3a2cb4505fbf4ce8559afad7cb4db71c712bf52d22beea5b30590a4b2",
			"08a69f876323f6e3db720a05b8b998b36f260cf4684d7f7339fa9ca7b3c9302c",
			"65ebd01e19fa7c0e454eb029c979d3870dfc3a256c3e4678891399927c50bc8f",
			"dc589c615ef93792f5d5bf644ec61f69a55d7158073f2882e730fe7388af5e37",
			"92a4c33f03724905e32ceaba4fc517114b5e3a0d93e46942ba236ccec0eadbfd",
			"5b769201439baaffb095d8d92e494f1831f7b507f36710fbe1fb43761dfc6679",
			"10d3ea26e37f168855db9970289eadb259cc2b711ddadb6e454cae8390617685",
			"d01a330430dead8370b3aace285111337118c30dffa6a07af45c177de7b5a418",
			"bf59db410a0049b4a9566089e89a55ec6bb4825f8e23c8a06fddb793d5308a37", "40f841c3a2cb4505fbf4ce8559afad7cb4db71c712bf52d22beea5b30590a4b2",
			"08a69f876323f6e3db720a05b8b998b36f260cf4684d7f7339fa9ca7b3c9302c",
			"65ebd01e19fa7c0e454eb029c979d3870dfc3a256c3e4678891399927c50bc8f",
			"dc589c615ef93792f5d5bf644ec61f69a55d7158073f2882e730fe7388af5e37",
			"92a4c33f03724905e32ceaba4fc517114b5e3a0d93e46942ba236ccec0eadbfd",
			"5b769201439baaffb095d8d92e494f1831f7b507f36710fbe1fb43761dfc6679",
			"10d3ea26e37f168855db9970289eadb259cc2b711ddadb6e454cae8390617685",
			"d01a330430dead8370b3aace285111337118c30dffa6a07af45c177de7b5a418",
			"bf59db410a0049b4a9566089e89a55ec6bb4825f8e23c8a06fddb793d5308a37",
		},
	}
}
