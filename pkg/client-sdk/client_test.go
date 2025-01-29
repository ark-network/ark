package arksdk

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/client"
	sdktypes "github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/stretchr/testify/require"
)

type fixture struct {
	name              string
	ignoreTxs         map[string]struct{}
	spendableVtxos    []client.Vtxo
	spentVtxos        []client.Vtxo
	expectedTxHistory []sdktypes.Transaction
}

func TestVtxosToTxs(t *testing.T) {
	fixtures, err := loadFixtures()
	require.NoError(t, err)

	for _, tt := range fixtures {
		t.Run(tt.name, func(t *testing.T) {
			txHistory, err := vtxosToTxsCovenantless(tt.spendableVtxos, tt.spentVtxos, tt.ignoreTxs)
			require.NoError(t, err)
			require.Len(t, txHistory, len(tt.expectedTxHistory))

			// Check each expected transaction, excluding CreatedAt
			for i, wantTx := range tt.expectedTxHistory {
				gotTx := txHistory[i]
				require.Equal(t, wantTx.TransactionKey, gotTx.TransactionKey)
				require.Equal(t, int(wantTx.Amount), int(gotTx.Amount))
				require.Equal(t, wantTx.Type, gotTx.Type)
				require.Equal(t, wantTx.Settled, gotTx.Settled)
				require.Equal(t, wantTx.CreatedAt, gotTx.CreatedAt)
			}
		})
	}
}

type vtxo struct {
	Outpoint struct {
		Txid string `json:"txid"`
		VOut uint32 `json:"vout"`
	} `json:"outpoint"`
	Amount    string `json:"amount"`
	Spent     bool   `json:"spent"`
	RoundTxid string `json:"roundTxid"`
	SpentBy   string `json:"spentBy"`
	ExpiresAt string `json:"expireAt"`
	Swept     bool   `json:"swept"`
	RedeemTx  string `json:"redeemTx"`
	CreatedAt string `json:"createdAt"`
	IsPending bool   `json:"isPending"`
}

type vtxos []vtxo

func (v vtxos) parse() []client.Vtxo {
	list := make([]client.Vtxo, 0, len(v))
	for _, vv := range v {
		list = append(list, client.Vtxo{
			Outpoint: client.Outpoint{
				Txid: vv.Outpoint.Txid,
				VOut: vv.Outpoint.VOut,
			},
			Amount:    parseAmount(vv.Amount),
			RoundTxid: vv.RoundTxid,
			ExpiresAt: parseTimestamp(vv.ExpiresAt),
			CreatedAt: parseTimestamp(vv.CreatedAt),
			RedeemTx:  vv.RedeemTx,
			SpentBy:   vv.SpentBy,
			IsPending: vv.IsPending,
		})
	}
	return list
}

type tx struct {
	BoardingTxid string `json:"boardingTxid"`
	RoundTxid    string `json:"roundTxid"`
	RedeemTxid   string `json:"redeemTxid"`
	Amount       string `json:"amount"`
	Type         string `json:"type"`
	Settled      bool   `json:"settled"`
	CreatedAt    string `json:"createdAt"`
}

type txs []tx

func (t txs) parse() []sdktypes.Transaction {
	list := make([]sdktypes.Transaction, 0, len(t))
	for _, tx := range t {
		list = append(list, sdktypes.Transaction{
			TransactionKey: sdktypes.TransactionKey{
				BoardingTxid: tx.BoardingTxid,
				RedeemTxid:   tx.RedeemTxid,
				RoundTxid:    tx.RoundTxid,
			},
			Amount:    parseAmount(tx.Amount),
			Type:      sdktypes.TxType(tx.Type),
			Settled:   tx.Settled,
			CreatedAt: parseTimestamp(tx.CreatedAt),
		},
		)
	}
	return list
}

func loadFixtures() ([]fixture, error) {
	data := make([]struct {
		Name              string   `json:"name"`
		IgnoreTxs         []string `json:"ignoreTxs"`
		SpendableVtxos    vtxos    `json:"spendableVtxos"`
		SpentVtxos        vtxos    `json:"spentVtxos"`
		ExpectedTxHistory txs      `json:"expectedTxHistory"`
	}, 0)
	buf, err := os.ReadFile("test_data.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read fixtures: %s", err)
	}
	if err := json.Unmarshal(buf, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fixtures: %s", err)
	}

	fixtures := make([]fixture, 0, len(data))
	for _, r := range data {
		indexedTxs := make(map[string]struct{})
		for _, tx := range r.IgnoreTxs {
			indexedTxs[tx] = struct{}{}
		}
		fixtures = append(fixtures, fixture{
			name:              r.Name,
			ignoreTxs:         indexedTxs,
			spendableVtxos:    r.SpendableVtxos.parse(),
			spentVtxos:        r.SpentVtxos.parse(),
			expectedTxHistory: r.ExpectedTxHistory.parse(),
		})
	}
	return fixtures, nil
}

func parseAmount(amountStr string) uint64 {
	amount, _ := strconv.ParseUint(amountStr, 10, 64)
	return amount
}

func parseTimestamp(timestamp string) time.Time {
	seconds, _ := strconv.ParseInt(timestamp, 10, 64)
	return time.Unix(seconds, 0)
}
