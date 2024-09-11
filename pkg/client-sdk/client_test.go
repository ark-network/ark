package arksdk

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/stretchr/testify/require"
)

func TestVtxosToTxs(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    []Transaction
	}{
		{
			name:    "Alice Before Sending Async",
			fixture: aliceBeforeSendingAsync,
			want: []Transaction{
				{
					RoundTxid: "377fa2fbd27c82bdbc095478384c88b6c75432c0ef464189e49c965194446cdf",
					Amount:    20000,
					Type:      TxReceived,
					Pending:   false,
					Claimed:   true,
					CreatedAt: time.Unix(1726054898, 0),
				},
			},
		},
		{
			name:    "Alice After Sending Async",
			fixture: aliceAfterSendingAsync,
			want: []Transaction{
				{
					RedeemTxid: "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
					Amount:     1000,
					Type:       TxSent,
					Pending:    true,
					Claimed:    false,
					CreatedAt:  time.Unix(1726054898, 0),
				},
				{
					RoundTxid: "377fa2fbd27c82bdbc095478384c88b6c75432c0ef464189e49c965194446cdf",
					Amount:    20000,
					Type:      TxReceived,
					Pending:   false,
					Claimed:   true,
					CreatedAt: time.Unix(1726054898, 0),
				},
			},
		},
		{
			name:    "Bob Before Claiming Async",
			fixture: bobBeforeClaimingAsync,
			want: []Transaction{
				{
					RedeemTxid: "766fc46ba5c2da41cd4c4bc0566e0f4e0f24c184c41acd3bead5cd7b11120367",
					Amount:     2000,
					Type:       TxReceived,
					Pending:    true,
					Claimed:    false,
					CreatedAt:  time.Unix(1726486359, 0),
				},
				{
					RedeemTxid: "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
					Amount:     1000,
					Type:       TxReceived,
					Pending:    true,
					Claimed:    false,
					CreatedAt:  time.Unix(1726054898, 0),
				},
			},
		},
		{
			name:    "Bob After Claiming Async",
			fixture: bobAfterClaimingAsync,
			want: []Transaction{
				{
					RedeemTxid: "766fc46ba5c2da41cd4c4bc0566e0f4e0f24c184c41acd3bead5cd7b11120367",
					Amount:     2000,
					Type:       TxReceived,
					Pending:    false,
					Claimed:    true,
					CreatedAt:  time.Unix(1726486359, 0),
				},
				{
					RedeemTxid: "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
					Amount:     1000,
					Type:       TxReceived,
					Pending:    false,
					Claimed:    true,
					CreatedAt:  time.Unix(1726054898, 0),
				},
			},
		},
		{
			name:    "Bob After Sending Async",
			fixture: bobAfterSendingAsync,
			want: []Transaction{
				{
					RedeemTxid: "23c3a885f0ea05f7bdf83f3bf7f8ac9dc3f791ad292f4e63a6f53fa5e4935ab0",
					Amount:     2100,
					Type:       TxSent,
					Pending:    true,
					Claimed:    false,
					CreatedAt:  time.Unix(1726503865, 0),
				},
				{
					RedeemTxid: "766fc46ba5c2da41cd4c4bc0566e0f4e0f24c184c41acd3bead5cd7b11120367",
					Amount:     2000,
					Type:       TxReceived,
					Pending:    false,
					Claimed:    true,
					CreatedAt:  time.Unix(1726486359, 0),
				},
				{
					RedeemTxid: "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
					Amount:     1000,
					Type:       TxReceived,
					Pending:    false,
					Claimed:    true,
					CreatedAt:  time.Unix(1726054898, 0),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, err := loadFixtures(tt.fixture)
			if err != nil {
				t.Fatalf("failed to load fixture: %s", err)
			}
			got, err := vtxosToTxsCovenantless(30, args.spendable, args.spent, nil)
			require.NoError(t, err)
			require.Len(t, got, len(tt.want))

			// Check each expected transaction, excluding CreatedAt
			for i, wantTx := range tt.want {
				gotTx := got[i]
				require.Equal(t, wantTx.RoundTxid, gotTx.RoundTxid)
				require.Equal(t, wantTx.RedeemTxid, gotTx.RedeemTxid)
				require.Equal(t, int(wantTx.Amount), int(gotTx.Amount))
				require.Equal(t, wantTx.Type, gotTx.Type)
				require.Equal(t, wantTx.Pending, gotTx.Pending)
				require.Equal(t, wantTx.Claimed, gotTx.Claimed)
			}
		})
	}
}

type vtxos struct {
	spendable []client.Vtxo
	spent     []client.Vtxo
}

func loadFixtures(jsonStr string) (vtxos, error) {
	var data struct {
		SpendableVtxos []struct {
			Outpoint struct {
				Txid string `json:"txid"`
				Vout uint32 `json:"vout"`
			} `json:"outpoint"`
			Receiver struct {
				Address string `json:"address"`
				Amount  string `json:"amount"`
			} `json:"receiver"`
			Spent       bool   `json:"spent"`
			PoolTxid    string `json:"poolTxid"`
			SpentBy     string `json:"spentBy"`
			ExpireAt    string `json:"expireAt"`
			Swept       bool   `json:"swept"`
			Pending     bool   `json:"pending"`
			PendingData struct {
				RedeemTx                string   `json:"redeemTx"`
				UnconditionalForfeitTxs []string `json:"unconditionalForfeitTxs"`
			} `json:"pendingData"`
		} `json:"spendableVtxos"`
		SpentVtxos []struct {
			Outpoint struct {
				Txid string `json:"txid"`
				Vout uint32 `json:"vout"`
			} `json:"outpoint"`
			Receiver struct {
				Address string `json:"address"`
				Amount  string `json:"amount"`
			} `json:"receiver"`
			Spent       bool   `json:"spent"`
			PoolTxid    string `json:"poolTxid"`
			SpentBy     string `json:"spentBy"`
			ExpireAt    string `json:"expireAt"`
			Swept       bool   `json:"swept"`
			Pending     bool   `json:"pending"`
			PendingData struct {
				RedeemTx                string   `json:"redeemTx"`
				UnconditionalForfeitTxs []string `json:"unconditionalForfeitTxs"`
			} `json:"pendingData"`
		} `json:"spentVtxos"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return vtxos{}, err
	}

	spendable := make([]client.Vtxo, len(data.SpendableVtxos))
	for i, vtxo := range data.SpendableVtxos {
		expireAt, err := parseTimestamp(vtxo.ExpireAt)
		if err != nil {
			return vtxos{}, err
		}
		amount, err := parseAmount(vtxo.Receiver.Amount)
		if err != nil {
			return vtxos{}, err
		}
		spendable[i] = client.Vtxo{
			VtxoKey: client.VtxoKey{
				Txid: vtxo.Outpoint.Txid,
				VOut: vtxo.Outpoint.Vout,
			},
			Amount:                  amount,
			RoundTxid:               vtxo.PoolTxid,
			ExpiresAt:               &expireAt,
			RedeemTx:                vtxo.PendingData.RedeemTx,
			UnconditionalForfeitTxs: vtxo.PendingData.UnconditionalForfeitTxs,
			Pending:                 vtxo.Pending,
			SpentBy:                 vtxo.SpentBy,
		}
	}

	spent := make([]client.Vtxo, len(data.SpentVtxos))
	for i, vtxo := range data.SpentVtxos {
		expireAt, err := parseTimestamp(vtxo.ExpireAt)
		if err != nil {
			return vtxos{}, err
		}
		amount, err := parseAmount(vtxo.Receiver.Amount)
		if err != nil {
			return vtxos{}, err
		}
		spent[i] = client.Vtxo{
			VtxoKey: client.VtxoKey{
				Txid: vtxo.Outpoint.Txid,
				VOut: vtxo.Outpoint.Vout,
			},
			Amount:                  amount,
			RoundTxid:               vtxo.PoolTxid,
			ExpiresAt:               &expireAt,
			RedeemTx:                vtxo.PendingData.RedeemTx,
			UnconditionalForfeitTxs: vtxo.PendingData.UnconditionalForfeitTxs,
			Pending:                 vtxo.Pending,
			SpentBy:                 vtxo.SpentBy,
		}
	}

	return vtxos{
		spendable: spendable,
		spent:     spent,
	}, nil
}

func parseAmount(amountStr string) (uint64, error) {
	amount, err := strconv.ParseUint(amountStr, 10, 64)
	if err != nil {
		return 0, err
	}

	return amount, nil
}

func parseTimestamp(timestamp string) (time.Time, error) {
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp format: %w", err)
	}

	return time.Unix(seconds, 0), nil
}

// bellow fixtures are used in bellow scenario:
// 1. Alice boards with 20OOO
// 2. Alice sends 1000 to Bob
// 3. Bob claims 1000
var (
	aliceBeforeSendingAsync = `
	{
	  "spendableVtxos": [
			{
				"outpoint": {
					"txid": "69ccb6520e0b91ac1cbaa459b16ec1e3ff5f6349990b0d149dd8e6c6485d316c",
					"vout": 0
				},
				"receiver": {
					"address": "tark1qwnakvl59d5wckz9lqhhdav0uvns6uu3zkc6hg65gh0kgh6wve9pwqa0qjq9ajm57ss4m7wutyhp3vexxzgkn2r5awtzytp8qfk8exfn4vm5d8ff",
					"amount": "20000"
				},
				"spent": false,
				"poolTxid": "377fa2fbd27c82bdbc095478384c88b6c75432c0ef464189e49c965194446cdf",
				"spentBy": "",
				"expireAt": "1726054928",
				"swept": false,
				"pending": false,
				"pendingData": null
			}
	  ],
	  "spentVtxos": []
	}`

	aliceAfterSendingAsync = `
	{
	  "spendableVtxos": [
			{
				"outpoint": {
					"txid": "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
					"vout": 1
				},
				"receiver": {
					"address": "tark1qwnakvl59d5wckz9lqhhdav0uvns6uu3zkc6hg65gh0kgh6wve9pwqa0qjq9ajm57ss4m7wutyhp3vexxzgkn2r5awtzytp8qfk8exfn4vm5d8ff",
					"amount": "19000"
				},
				"spent": false,
				"poolTxid": "",
				"spentBy": "",
				"expireAt": "1726054928",
				"swept": false,
				"pending": true,
				"pendingData": {
					"redeemTx": "cHNidP8BAIkCAAAAAWwxXUjG5tidFA0LmUljX//jwW6xWaS6HKyRCw5StsxpAAAAAAD/////AugDAAAAAAAAIlEgt2eR8LtqTP7yUcQtSydeGrRiHnVmHHnZwYjdC23G7MZwSQAAAAAAACJRIKfUzf/o9h+r0v9y4nmyOt9qO8EkDumQPQZGTbEv8fSFAAAAAAABASsgTgAAAAAAACJRIKfUzf/o9h+r0v9y4nmyOt9qO8EkDumQPQZGTbEv8fSFIgYDp9sz9Cto7FhF+C929Y/jJw1zkRWxq6NURd9kX05mShcYAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAQRSvBIBey3T0IV353FkuGLMmMJFpqHTrliIsJwJsfJkzq7J0B8bQ0j9842h5lUfOWcbj2TeoFx6OCpgoHIqWIBhHQAFqkBLiRmP3AZ8MS77s1QIWZswMV3L72D9gN0f0MbD6XHkmzZeC1clF3uzxr+13wsF0vcFe29Zl3e2gAhMNGYVCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wKRtST8P7teUpSF4DAEbfJj5OIXITx5QGbZns/AtxqGyRSCn2zP0K2jsWEX4L3b1j+MnDXORFbGro1RF32RfTmZKF60grwSAXst09CFd+dxZLhizJjCRaah065YiLCcCbHyZM6uswCEWp9sz9Cto7FhF+C929Y/jJw1zkRWxq6NURd9kX05mShc5AbJ0B8bQ0j9842h5lUfOWcbj2TeoFx6OCpgoHIqWIBhHAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=",
					"unconditionalForfeitTxs": [
						"cHNidP8BAFICAAAAAWwxXUjG5tidFA0LmUljX//jwW6xWaS6HKyRCw5StsxpAAAAAAD/////AVhNAAAAAAAAFgAUSU38/3Mzx5BdILG4oUO+JoHcoT8AAAAAAAEBKyBOAAAAAAAAIlEgp9TN/+j2H6vS/3LiebI632o7wSQO6ZA9BkZNsS/x9IVBFK8EgF7LdPQhXfncWS4YsyYwkWmodOuWIiwnAmx8mTOrsnQHxtDSP3zjaHmVR85ZxuPZN6gXHo4KmCgcipYgGEdAjH8Mg1Z3GdjGzp78Mg2xq1fop9KDfeji+xoyMgYS7q0Nl0AGOAaNzkDRW4cNcefll5jZC2i3nfygKdXsUsR+LEIVwVCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrApG1JPw/u15SlIXgMARt8mPk4hchPHlAZtmez8C3GobJFIKfbM/QraOxYRfgvdvWP4ycNc5EVsaujVEXfZF9OZkoXrSCvBIBey3T0IV353FkuGLMmMJFpqHTrliIsJwJsfJkzq6zAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAA=="
					]
				}
			}
	  ],
	  "spentVtxos": [
			{
				"outpoint": {
					"txid": "69ccb6520e0b91ac1cbaa459b16ec1e3ff5f6349990b0d149dd8e6c6485d316c",
					"vout": 0
				},
				"receiver": {
					"address": "tark1qwnakvl59d5wckz9lqhhdav0uvns6uu3zkc6hg65gh0kgh6wve9pwqa0qjq9ajm57ss4m7wutyhp3vexxzgkn2r5awtzytp8qfk8exfn4vm5d8ff",
					"amount": "20000"
				},
				"spent": true,
				"poolTxid": "377fa2fbd27c82bdbc095478384c88b6c75432c0ef464189e49c965194446cdf",
				"spentBy": "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
				"expireAt": "1726054928",
				"swept": false,
				"pending": false,
				"pendingData": null
			}
	  ]
	}`

	bobBeforeClaimingAsync = `
	{
	  "spendableVtxos": [
			{
				"outpoint": {
					"txid": "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
					"vout": 0
				},
				"receiver": {
					"address": "tark1qwnakvl59d5wckz9lqhhdav0uvns6uu3zkc6hg65gh0kgh6wve9pwqa8vzms5xcr7pqgt0sw88vc287dse5rw6fnxuk9f08frf8amxjcrya0tkgt",
					"amount": "1000"
				},
				"spent": false,
				"poolTxid": "",
				"spentBy": "",
				"expireAt": "1726054928",
				"swept": false,
				"pending": true,
				"pendingData": {
					"redeemTx": "cHNidP8BAIkCAAAAAWwxXUjG5tidFA0LmUljX//jwW6xWaS6HKyRCw5StsxpAAAAAAD/////AugDAAAAAAAAIlEgt2eR8LtqTP7yUcQtSydeGrRiHnVmHHnZwYjdC23G7MZwSQAAAAAAACJRIKfUzf/o9h+r0v9y4nmyOt9qO8EkDumQPQZGTbEv8fSFAAAAAAABASsgTgAAAAAAACJRIKfUzf/o9h+r0v9y4nmyOt9qO8EkDumQPQZGTbEv8fSFIgYDp9sz9Cto7FhF+C929Y/jJw1zkRWxq6NURd9kX05mShcYAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAQRSvBIBey3T0IV353FkuGLMmMJFpqHTrliIsJwJsfJkzq7J0B8bQ0j9842h5lUfOWcbj2TeoFx6OCpgoHIqWIBhHQAFqkBLiRmP3AZ8MS77s1QIWZswMV3L72D9gN0f0MbD6XHkmzZeC1clF3uzxr+13wsF0vcFe29Zl3e2gAhMNGYVCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wKRtST8P7teUpSF4DAEbfJj5OIXITx5QGbZns/AtxqGyRSCn2zP0K2jsWEX4L3b1j+MnDXORFbGro1RF32RfTmZKF60grwSAXst09CFd+dxZLhizJjCRaah065YiLCcCbHyZM6uswCEWp9sz9Cto7FhF+C929Y/jJw1zkRWxq6NURd9kX05mShc5AbJ0B8bQ0j9842h5lUfOWcbj2TeoFx6OCpgoHIqWIBhHAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=",
					"unconditionalForfeitTxs": [
						"cHNidP8BAFICAAAAAWwxXUjG5tidFA0LmUljX//jwW6xWaS6HKyRCw5StsxpAAAAAAD/////AVhNAAAAAAAAFgAUSU38/3Mzx5BdILG4oUO+JoHcoT8AAAAAAAEBKyBOAAAAAAAAIlEgp9TN/+j2H6vS/3LiebI632o7wSQO6ZA9BkZNsS/x9IVBFK8EgF7LdPQhXfncWS4YsyYwkWmodOuWIiwnAmx8mTOrsnQHxtDSP3zjaHmVR85ZxuPZN6gXHo4KmCgcipYgGEdAjH8Mg1Z3GdjGzp78Mg2xq1fop9KDfeji+xoyMgYS7q0Nl0AGOAaNzkDRW4cNcefll5jZC2i3nfygKdXsUsR+LEIVwVCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrApG1JPw/u15SlIXgMARt8mPk4hchPHlAZtmez8C3GobJFIKfbM/QraOxYRfgvdvWP4ycNc5EVsaujVEXfZF9OZkoXrSCvBIBey3T0IV353FkuGLMmMJFpqHTrliIsJwJsfJkzq6zAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAA=="
					]
				}
			},
			{
				"outpoint": {
					"txid": "766fc46ba5c2da41cd4c4bc0566e0f4e0f24c184c41acd3bead5cd7b11120367",
					"vout": 0
				},
				"receiver": {
					"address": "tark1qgw4gpt40zet7q399hv78z7pdak5sxlcgzhy6y6qq7hw3syeudc6xqsws4tegt5r88eahx7g5try2ua4n9rflsncpresjfwcrq80k0d3systnm98",
					"amount": "2000"
				},
				"spent": false,
				"poolTxid": "",
				"spentBy": "",
				"expireAt": "1726486389",
				"swept": false,
				"pending": true,
				"pendingData": {
					"redeemTx": "cHNidP8BAIkCAAAAARH6LJRGP/pFIkD/o5bBp8fXAhjl8yjfN7MhJsxdt5lrAQAAAAD/////AtAHAAAAAAAAIlEguuBh3KQUVZp+NHV2sixQ/mrsngCuLCGXzsgJPC1FzY7ANQ8AAAAAACJRIP7uXXtl4jLUcVVQU+sX7WFXmx2H6iCMzn7gye0v1Y8JAAAAAAABAStYPg8AAAAAACJRIP7uXXtl4jLUcVVQU+sX7WFXmx2H6iCMzn7gye0v1Y8JIgYCHVQFdXiyvwIlLdnji8FvbUgb+ECuTRNAB67owJnjcaMYAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAQRSc1yjQ/vHRHev23fKGANLvbOhkNYmGtmRWt8fSszlOJUzRFbnfxd1fq9gIEpaI0vrZww8tlZ94iEL75QoaIbVqQJsPdLYf7fAoXO82VoqwYHu1WevE4g6LxUGBPzfd96q5EEZkoW5qqg+v5dWJUEY467Q6qZLFHwziUaB3KEY8yEpCFcBQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wO5D2Mh3x0XNGxFCS67GNughkENFodpFeVpZjn76chI8RSAdVAV1eLK/AiUt2eOLwW9tSBv4QK5NE0AHrujAmeNxo60gnNco0P7x0R3r9t3yhgDS72zoZDWJhrZkVrfH0rM5TiWswCEWHVQFdXiyvwIlLdnji8FvbUgb+ECuTRNAB67owJnjcaM5AUzRFbnfxd1fq9gIEpaI0vrZww8tlZ94iEL75QoaIbVqAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=",
					"unconditionalForfeitTxs": [
						"cHNidP8BAFICAAAAARH6LJRGP/pFIkD/o5bBp8fXAhjl8yjfN7MhJsxdt5lrAQAAAAD/////AZA9DwAAAAAAFgAU+9NJhjFhe8jX1hrXh3NvDyHZ1cYAAAAAAAEBK1g+DwAAAAAAIlEg/u5de2XiMtRxVVBT6xftYVebHYfqIIzOfuDJ7S/VjwlBFJzXKND+8dEd6/bd8oYA0u9s6GQ1iYa2ZFa3x9KzOU4lTNEVud/F3V+r2AgSlojS+tnDDy2Vn3iIQvvlChohtWpARJzBjlEkN/kTpyFEtpvP2Ui7ypevuxb9J/NUAwhYf8Pmnnj1l3WuKCSi4Fcp1O+lQjIiZlNpwY6J73q/V8Fe2kIVwFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrA7kPYyHfHRc0bEUJLrsY26CGQQ0Wh2kV5WlmOfvpyEjxFIB1UBXV4sr8CJS3Z44vBb21IG/hArk0TQAeu6MCZ43GjrSCc1yjQ/vHRHev23fKGANLvbOhkNYmGtmRWt8fSszlOJazAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAA=="
					]
				}
			}
	  ],
	  "spentVtxos": []
	}`
	bobAfterClaimingAsync = `
	{
		"spendableVtxos": [
			{
				"outpoint": {
					"txid": "11cba4cbb06290fb7426157efe439940e1e4143d51bdd20567d7bfd28f0d9090",
					"vout": 0
				},
				"receiver": {
					"address": "tark1qgw4gpt40zet7q399hv78z7pdak5sxlcgzhy6y6qq7hw3syeudc6xqsws4tegt5r88eahx7g5try2ua4n9rflsncpresjfwcrq80k0d3systnm98",
					"amount": "3000"
				},
				"spent": false,
				"poolTxid": "d6684a5b9e6939dccdf07d1f0eaf7fdd7b31de4d123e63e400d23de739800d4e",
				"spentBy": "",
				"expireAt": "1726503895",
				"swept": false,
				"pending": false,
				"pendingData": null
			}
		],
		"spentVtxos": [
			{
				"outpoint": {
					"txid": "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
					"vout": 0
				},
				"receiver": {
					"address": "tark1qwnakvl59d5wckz9lqhhdav0uvns6uu3zkc6hg65gh0kgh6wve9pwqa8vzms5xcr7pqgt0sw88vc287dse5rw6fnxuk9f08frf8amxjcrya0tkgt",
					"amount": "1000"
				},
				"spent": true,
				"poolTxid": "",
				"spentBy": "d6684a5b9e6939dccdf07d1f0eaf7fdd7b31de4d123e63e400d23de739800d4e",
				"expireAt": "1726054928",
				"swept": false,
				"pending": true,
				"pendingData": {
					"redeemTx": "cHNidP8BAIkCAAAAAWwxXUjG5tidFA0LmUljX//jwW6xWaS6HKyRCw5StsxpAAAAAAD/////AugDAAAAAAAAIlEgt2eR8LtqTP7yUcQtSydeGrRiHnVmHHnZwYjdC23G7MZwSQAAAAAAACJRIKfUzf/o9h+r0v9y4nmyOt9qO8EkDumQPQZGTbEv8fSFAAAAAAABASsgTgAAAAAAACJRIKfUzf/o9h+r0v9y4nmyOt9qO8EkDumQPQZGTbEv8fSFIgYDp9sz9Cto7FhF+C929Y/jJw1zkRWxq6NURd9kX05mShcYAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAQRSvBIBey3T0IV353FkuGLMmMJFpqHTrliIsJwJsfJkzq7J0B8bQ0j9842h5lUfOWcbj2TeoFx6OCpgoHIqWIBhHQAFqkBLiRmP3AZ8MS77s1QIWZswMV3L72D9gN0f0MbD6XHkmzZeC1clF3uzxr+13wsF0vcFe29Zl3e2gAhMNGYVCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wKRtST8P7teUpSF4DAEbfJj5OIXITx5QGbZns/AtxqGyRSCn2zP0K2jsWEX4L3b1j+MnDXORFbGro1RF32RfTmZKF60grwSAXst09CFd+dxZLhizJjCRaah065YiLCcCbHyZM6uswCEWp9sz9Cto7FhF+C929Y/jJw1zkRWxq6NURd9kX05mShc5AbJ0B8bQ0j9842h5lUfOWcbj2TeoFx6OCpgoHIqWIBhHAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=",
					"unconditionalForfeitTxs": [
						"cHNidP8BAFICAAAAAWwxXUjG5tidFA0LmUljX//jwW6xWaS6HKyRCw5StsxpAAAAAAD/////AVhNAAAAAAAAFgAUSU38/3Mzx5BdILG4oUO+JoHcoT8AAAAAAAEBKyBOAAAAAAAAIlEgp9TN/+j2H6vS/3LiebI632o7wSQO6ZA9BkZNsS/x9IVBFK8EgF7LdPQhXfncWS4YsyYwkWmodOuWIiwnAmx8mTOrsnQHxtDSP3zjaHmVR85ZxuPZN6gXHo4KmCgcipYgGEdAjH8Mg1Z3GdjGzp78Mg2xq1fop9KDfeji+xoyMgYS7q0Nl0AGOAaNzkDRW4cNcefll5jZC2i3nfygKdXsUsR+LEIVwVCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrApG1JPw/u15SlIXgMARt8mPk4hchPHlAZtmez8C3GobJFIKfbM/QraOxYRfgvdvWP4ycNc5EVsaujVEXfZF9OZkoXrSCvBIBey3T0IV353FkuGLMmMJFpqHTrliIsJwJsfJkzq6zAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAA=="
					]
				}
			},
			{
				"outpoint": {
					"txid": "766fc46ba5c2da41cd4c4bc0566e0f4e0f24c184c41acd3bead5cd7b11120367",
					"vout": 0
				},
				"receiver": {
					"address": "tark1qgw4gpt40zet7q399hv78z7pdak5sxlcgzhy6y6qq7hw3syeudc6xqsws4tegt5r88eahx7g5try2ua4n9rflsncpresjfwcrq80k0d3systnm98",
					"amount": "2000"
				},
				"spent": true,
				"poolTxid": "",
				"spentBy": "d6684a5b9e6939dccdf07d1f0eaf7fdd7b31de4d123e63e400d23de739800d4e",
				"expireAt": "1726486389",
				"swept": false,
				"pending": true,
				"pendingData": {
					"redeemTx": "cHNidP8BAIkCAAAAARH6LJRGP/pFIkD/o5bBp8fXAhjl8yjfN7MhJsxdt5lrAQAAAAD/////AtAHAAAAAAAAIlEguuBh3KQUVZp+NHV2sixQ/mrsngCuLCGXzsgJPC1FzY7ANQ8AAAAAACJRIP7uXXtl4jLUcVVQU+sX7WFXmx2H6iCMzn7gye0v1Y8JAAAAAAABAStYPg8AAAAAACJRIP7uXXtl4jLUcVVQU+sX7WFXmx2H6iCMzn7gye0v1Y8JIgYCHVQFdXiyvwIlLdnji8FvbUgb+ECuTRNAB67owJnjcaMYAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAQRSc1yjQ/vHRHev23fKGANLvbOhkNYmGtmRWt8fSszlOJUzRFbnfxd1fq9gIEpaI0vrZww8tlZ94iEL75QoaIbVqQJsPdLYf7fAoXO82VoqwYHu1WevE4g6LxUGBPzfd96q5EEZkoW5qqg+v5dWJUEY467Q6qZLFHwziUaB3KEY8yEpCFcBQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wO5D2Mh3x0XNGxFCS67GNughkENFodpFeVpZjn76chI8RSAdVAV1eLK/AiUt2eOLwW9tSBv4QK5NE0AHrujAmeNxo60gnNco0P7x0R3r9t3yhgDS72zoZDWJhrZkVrfH0rM5TiWswCEWHVQFdXiyvwIlLdnji8FvbUgb+ECuTRNAB67owJnjcaM5AUzRFbnfxd1fq9gIEpaI0vrZww8tlZ94iEL75QoaIbVqAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=",
					"unconditionalForfeitTxs": [
						"cHNidP8BAFICAAAAARH6LJRGP/pFIkD/o5bBp8fXAhjl8yjfN7MhJsxdt5lrAQAAAAD/////AZA9DwAAAAAAFgAU+9NJhjFhe8jX1hrXh3NvDyHZ1cYAAAAAAAEBK1g+DwAAAAAAIlEg/u5de2XiMtRxVVBT6xftYVebHYfqIIzOfuDJ7S/VjwlBFJzXKND+8dEd6/bd8oYA0u9s6GQ1iYa2ZFa3x9KzOU4lTNEVud/F3V+r2AgSlojS+tnDDy2Vn3iIQvvlChohtWpARJzBjlEkN/kTpyFEtpvP2Ui7ypevuxb9J/NUAwhYf8Pmnnj1l3WuKCSi4Fcp1O+lQjIiZlNpwY6J73q/V8Fe2kIVwFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrA7kPYyHfHRc0bEUJLrsY26CGQQ0Wh2kV5WlmOfvpyEjxFIB1UBXV4sr8CJS3Z44vBb21IG/hArk0TQAeu6MCZ43GjrSCc1yjQ/vHRHev23fKGANLvbOhkNYmGtmRWt8fSszlOJazAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAA=="
					]
				}
			}
		]
	}`
	bobAfterSendingAsync = `
	{
		"spendableVtxos": [
			{
				"outpoint": {
					"txid": "23c3a885f0ea05f7bdf83f3bf7f8ac9dc3f791ad292f4e63a6f53fa5e4935ab0",
					"vout": 0
				},
				"receiver": {
					"address": "tark1qwnakvl59d5wckz9lqhhdav0uvns6uu3zkc6hg65gh0kgh6wve9pwqa8vzms5xcr7pqgt0sw88vc287dse5rw6fnxuk9f08frf8amxjcrya0tkgt",
					"amount": "900"
				},
				"spent": false,
				"poolTxid": "",
				"spentBy": "",
				"expireAt": "1726503895",
				"swept": false,
				"pending": true,
				"pendingData": {
					"redeemTx": "cHNidP8BAIkCAAAAAdOK9YzYw1ceJznqJxtRXGe0KeHj6CLcLtqLVwcbMCivAAAAAAD/////ArgLAAAAAAAAIlEgC39Vxhw3dIa4heHgFS6X4XwDl1mBggsKLVTBwF1h3qEgegEAAAAAACJRIMkktfIFxFNTtAmy3K0p+7JqVn2kcA0P6y2vJ1QX2zysAAAAAAABASughgEAAAAAACJRIMkktfIFxFNTtAmy3K0p+7JqVn2kcA0P6y2vJ1QX2zysIgYDjGeMfnNwCrU45iB3iRqiFdWTADaiJ968+w3ruFuq1F0YAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAQRTYEOuHJ0hyLBGzY8nSHpD2F1nby5/XQ5Sh2Je+cQ5Wsx0ZucLmB/LLspxMRN9JcJn3Q2KJRMhhg7415cCg1d0gQNSvgaBk/1WLYqQxCKxCfv8ViVJ7vjBxvNO5tc2FEDy27V9cIrfL1jPJoVrhgPZT0GwY7dkVZS7saIKI03CbipBCFcBQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wPKiQ0JM6aw2kcUByijEbOydM3gTIVCGN/69q+dmyxcqRSCMZ4x+c3AKtTjmIHeJGqIV1ZMANqIn3rz7Deu4W6rUXa0g2BDrhydIciwRs2PJ0h6Q9hdZ28uf10OUodiXvnEOVrOswCEWjGeMfnNwCrU45iB3iRqiFdWTADaiJ968+w3ruFuq1F05AR0ZucLmB/LLspxMRN9JcJn3Q2KJRMhhg7415cCg1d0gAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=",
					"unconditionalForfeitTxs": [
						"cHNidP8BAFICAAAAAdOK9YzYw1ceJznqJxtRXGe0KeHj6CLcLtqLVwcbMCivAAAAAAD/////AdiFAQAAAAAAFgAUlsBYsQa9BEiB8ZumuN4J50lbQIoAAAAAAAEBK6CGAQAAAAAAIlEgySS18gXEU1O0CbLcrSn7smpWfaRwDQ/rLa8nVBfbPKxBFNgQ64cnSHIsEbNjydIekPYXWdvLn9dDlKHYl75xDlazHRm5wuYH8suynExE30lwmfdDYolEyGGDvjXlwKDV3SBAZadgbU8gCDvq3XN0EeLIwGKGSAYHZRkGbAnr9ZjCHGKAQlfFNYS0af1Lz4j7Th2osVY8JJv7O736sC5NNQome0IVwFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrA8qJDQkzprDaRxQHKKMRs7J0zeBMhUIY3/r2r52bLFypFIIxnjH5zcAq1OOYgd4kaohXVkwA2oifevPsN67hbqtRdrSDYEOuHJ0hyLBGzY8nSHpD2F1nby5/XQ5Sh2Je+cQ5Ws6zAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAA=="
					]
				}
			}
		],
		"spentVtxos": [
			{
				"outpoint": {
					"txid": "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
					"vout": 0
				},
				"receiver": {
					"address": "tark1qwnakvl59d5wckz9lqhhdav0uvns6uu3zkc6hg65gh0kgh6wve9pwqa8vzms5xcr7pqgt0sw88vc287dse5rw6fnxuk9f08frf8amxjcrya0tkgt",
					"amount": "1000"
				},
				"spent": true,
				"poolTxid": "",
				"spentBy": "d6684a5b9e6939dccdf07d1f0eaf7fdd7b31de4d123e63e400d23de739800d4e",
				"expireAt": "1726054928",
				"swept": false,
				"pending": true,
				"pendingData": {
					"redeemTx": "cHNidP8BAIkCAAAAAWwxXUjG5tidFA0LmUljX//jwW6xWaS6HKyRCw5StsxpAAAAAAD/////AugDAAAAAAAAIlEgt2eR8LtqTP7yUcQtSydeGrRiHnVmHHnZwYjdC23G7MZwSQAAAAAAACJRIKfUzf/o9h+r0v9y4nmyOt9qO8EkDumQPQZGTbEv8fSFAAAAAAABASsgTgAAAAAAACJRIKfUzf/o9h+r0v9y4nmyOt9qO8EkDumQPQZGTbEv8fSFIgYDp9sz9Cto7FhF+C929Y/jJw1zkRWxq6NURd9kX05mShcYAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAQRSvBIBey3T0IV353FkuGLMmMJFpqHTrliIsJwJsfJkzq7J0B8bQ0j9842h5lUfOWcbj2TeoFx6OCpgoHIqWIBhHQAFqkBLiRmP3AZ8MS77s1QIWZswMV3L72D9gN0f0MbD6XHkmzZeC1clF3uzxr+13wsF0vcFe29Zl3e2gAhMNGYVCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wKRtST8P7teUpSF4DAEbfJj5OIXITx5QGbZns/AtxqGyRSCn2zP0K2jsWEX4L3b1j+MnDXORFbGro1RF32RfTmZKF60grwSAXst09CFd+dxZLhizJjCRaah065YiLCcCbHyZM6uswCEWp9sz9Cto7FhF+C929Y/jJw1zkRWxq6NURd9kX05mShc5AbJ0B8bQ0j9842h5lUfOWcbj2TeoFx6OCpgoHIqWIBhHAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=",
					"unconditionalForfeitTxs": [
						"cHNidP8BAFICAAAAAWwxXUjG5tidFA0LmUljX//jwW6xWaS6HKyRCw5StsxpAAAAAAD/////AVhNAAAAAAAAFgAUSU38/3Mzx5BdILG4oUO+JoHcoT8AAAAAAAEBKyBOAAAAAAAAIlEgp9TN/+j2H6vS/3LiebI632o7wSQO6ZA9BkZNsS/x9IVBFK8EgF7LdPQhXfncWS4YsyYwkWmodOuWIiwnAmx8mTOrsnQHxtDSP3zjaHmVR85ZxuPZN6gXHo4KmCgcipYgGEdAjH8Mg1Z3GdjGzp78Mg2xq1fop9KDfeji+xoyMgYS7q0Nl0AGOAaNzkDRW4cNcefll5jZC2i3nfygKdXsUsR+LEIVwVCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrApG1JPw/u15SlIXgMARt8mPk4hchPHlAZtmez8C3GobJFIKfbM/QraOxYRfgvdvWP4ycNc5EVsaujVEXfZF9OZkoXrSCvBIBey3T0IV353FkuGLMmMJFpqHTrliIsJwJsfJkzq6zAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAA=="
					]
				}
			},
			{
				"outpoint": {
					"txid": "766fc46ba5c2da41cd4c4bc0566e0f4e0f24c184c41acd3bead5cd7b11120367",
					"vout": 0
				},
				"receiver": {
					"address": "tark1qgw4gpt40zet7q399hv78z7pdak5sxlcgzhy6y6qq7hw3syeudc6xqsws4tegt5r88eahx7g5try2ua4n9rflsncpresjfwcrq80k0d3systnm98",
					"amount": "2000"
				},
				"spent": true,
				"poolTxid": "",
				"spentBy": "d6684a5b9e6939dccdf07d1f0eaf7fdd7b31de4d123e63e400d23de739800d4e",
				"expireAt": "1726486389",
				"swept": false,
				"pending": true,
				"pendingData": {
					"redeemTx": "cHNidP8BAIkCAAAAARH6LJRGP/pFIkD/o5bBp8fXAhjl8yjfN7MhJsxdt5lrAQAAAAD/////AtAHAAAAAAAAIlEguuBh3KQUVZp+NHV2sixQ/mrsngCuLCGXzsgJPC1FzY7ANQ8AAAAAACJRIP7uXXtl4jLUcVVQU+sX7WFXmx2H6iCMzn7gye0v1Y8JAAAAAAABAStYPg8AAAAAACJRIP7uXXtl4jLUcVVQU+sX7WFXmx2H6iCMzn7gye0v1Y8JIgYCHVQFdXiyvwIlLdnji8FvbUgb+ECuTRNAB67owJnjcaMYAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAQRSc1yjQ/vHRHev23fKGANLvbOhkNYmGtmRWt8fSszlOJUzRFbnfxd1fq9gIEpaI0vrZww8tlZ94iEL75QoaIbVqQJsPdLYf7fAoXO82VoqwYHu1WevE4g6LxUGBPzfd96q5EEZkoW5qqg+v5dWJUEY467Q6qZLFHwziUaB3KEY8yEpCFcBQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wO5D2Mh3x0XNGxFCS67GNughkENFodpFeVpZjn76chI8RSAdVAV1eLK/AiUt2eOLwW9tSBv4QK5NE0AHrujAmeNxo60gnNco0P7x0R3r9t3yhgDS72zoZDWJhrZkVrfH0rM5TiWswCEWHVQFdXiyvwIlLdnji8FvbUgb+ECuTRNAB67owJnjcaM5AUzRFbnfxd1fq9gIEpaI0vrZww8tlZ94iEL75QoaIbVqAAAAAFYAAIAAAACAAQAAgAAAAAAAAAAAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=",
					"unconditionalForfeitTxs": [
						"cHNidP8BAFICAAAAARH6LJRGP/pFIkD/o5bBp8fXAhjl8yjfN7MhJsxdt5lrAQAAAAD/////AZA9DwAAAAAAFgAU+9NJhjFhe8jX1hrXh3NvDyHZ1cYAAAAAAAEBK1g+DwAAAAAAIlEg/u5de2XiMtRxVVBT6xftYVebHYfqIIzOfuDJ7S/VjwlBFJzXKND+8dEd6/bd8oYA0u9s6GQ1iYa2ZFa3x9KzOU4lTNEVud/F3V+r2AgSlojS+tnDDy2Vn3iIQvvlChohtWpARJzBjlEkN/kTpyFEtpvP2Ui7ypevuxb9J/NUAwhYf8Pmnnj1l3WuKCSi4Fcp1O+lQjIiZlNpwY6J73q/V8Fe2kIVwFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrA7kPYyHfHRc0bEUJLrsY26CGQQ0Wh2kV5WlmOfvpyEjxFIB1UBXV4sr8CJS3Z44vBb21IG/hArk0TQAeu6MCZ43GjrSCc1yjQ/vHRHev23fKGANLvbOhkNYmGtmRWt8fSszlOJazAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAA=="
					]
				}
			},
			{
				"outpoint": {
					"txid": "11cba4cbb06290fb7426157efe439940e1e4143d51bdd20567d7bfd28f0d9090",
					"vout": 0
				},
				"receiver": {
					"address": "tark1qgw4gpt40zet7q399hv78z7pdak5sxlcgzhy6y6qq7hw3syeudc6xqsws4tegt5r88eahx7g5try2ua4n9rflsncpresjfwcrq80k0d3systnm98",
					"amount": "3000"
				},
				"spent": false,
				"poolTxid": "d6684a5b9e6939dccdf07d1f0eaf7fdd7b31de4d123e63e400d23de739800d4e",
				"spentBy": "23c3a885f0ea05f7bdf83f3bf7f8ac9dc3f791ad292f4e63a6f53fa5e4935ab0",
				"expireAt": "1726503895",
				"swept": false,
				"pending": false,
				"pendingData": null
			}
		]
	}`
)
