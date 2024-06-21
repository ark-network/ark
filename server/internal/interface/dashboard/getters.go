package main

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"strconv"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
)

func randomSats() string {
	randomNumber := 666 + rand.Intn(10000)
	return strconv.Itoa(randomNumber)
}

func randomSweepableOutput(when int64) *arkv1.SweepableOutput {
	return &arkv1.SweepableOutput{
		Txid:        randomTxId(),
		Vout:        1,
		ScheduledAt: when,
		Amount:      randomSats(),
	}
}

func randomOutputs(when int64) []*arkv1.SweepableOutput {
	outputs := make([]*arkv1.SweepableOutput, 0)
	for i := 0; i < 2+rand.Intn(2); i++ {
		outputs = append(outputs, randomSweepableOutput(when))
	}
	return outputs
}

func randomSweep(when int64) *arkv1.ScheduledSweep {
	return &arkv1.ScheduledSweep{
		RoundId: randomTxId(),
		Outputs: randomOutputs(when),
	}
}

func randomTxId() string {
	randomBytes := make([]byte, 32)
	cryptorand.Read(randomBytes)
	hash := sha256.Sum256(randomBytes)
	return hex.EncodeToString(hash[:])
}

func randomUuid() string {
	r := randomTxId()
	return r[0:8] + "-" + r[8:12] + "-" + r[12:16] + "-" + r[16:20] + "-" + r[21:32]
}

func getBalance() *arkv1.GetBalanceResponse {
	return &arkv1.GetBalanceResponse{
		MainAccount:       &arkv1.Balance{Available: "675884", Locked: "76523"},
		ConnectorsAccount: &arkv1.Balance{Available: "65442", Locked: "7653"},
	}
}

func getNextSweeps() *arkv1.GetScheduledSweepResponse {
	var when int64 = time.Now().Unix()
	sweeps := make([]*arkv1.ScheduledSweep, 0)
	for i := 0; i < 5; i++ {
		when = when + int64(rand.Intn(2100))
		sweeps = append(sweeps, randomSweep(when))
	}
	return &arkv1.GetScheduledSweepResponse{Sweeps: sweeps}
}

func getRoundDetails(txid ...string) *arkv1.GetRoundDetailsResponse {
	var round_txid string
	if len(txid) > 0 {
		round_txid = txid[0]
	} else {
		round_txid = randomTxId()
	}

	inputVtxos := []string{
		randomTxId() + ":1",
		randomTxId() + ":1",
		randomTxId() + ":1",
	}
	outputVtxos := []string{
		randomTxId() + ":1",
		randomTxId() + ":1",
		randomTxId() + ":1",
	}
	exitAddresses := []string{
		"bc1qr4356l02af8ura6hgxrqa2wx0lesdxfjxdnau0",
		"bc1q0y6h8xe97pnf85dcd5puwsm5up94aesxrcd8yp",
		"bc1q83ep02rpedffsn9xm57yd54v48x7xsf6cdwfea",
	}

	return &arkv1.GetRoundDetailsResponse{
		RoundId:          randomUuid(),
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
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
			randomTxId(),
		},
	}
}
