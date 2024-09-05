package arksdk

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/stretchr/testify/assert"
)

func TestVtxosToTxs(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    []Transaction
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "Alice Before Sending Async",
			fixture: aliceBeforeSendingAsync,
			want: []Transaction{
				{
					TxID:    "377fa2fbd27c82bdbc095478384c88b6c75432c0ef464189e49c965194446cdf",
					Amount:  20000,
					Type:    TxReceived,
					Pending: false,
					Claimed: false,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "Alice After Sending Async",
			fixture: aliceAfterSendingAsync,
			want: []Transaction{
				{
					TxID:    "377fa2fbd27c82bdbc095478384c88b6c75432c0ef464189e49c965194446cdf",
					Amount:  20000,
					Type:    TxSent,
					Pending: false,
					Claimed: false,
				},
				{
					TxID:    "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
					Amount:  19000,
					Type:    TxReceived,
					Pending: true, // TODO: expect false once the ASP handles the change properly
					Claimed: false,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "Bob Before Claiming Async",
			fixture: bobBeforeClaimingAsync,
			want: []Transaction{
				{
					TxID:    "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
					Amount:  1000,
					Type:    TxReceived,
					Pending: true,
					Claimed: false,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "Bob After Claiming Async",
			fixture: bobAfterClaimingAsync,
			want: []Transaction{
				{
					TxID:    "94fa598302f17f00c8881e742ec0ce2f8c8d16f3d54fe6ba0fb7d13a493d84ad",
					Amount:  1000,
					Type:    TxReceived,
					Pending: false,
					Claimed: true,
				},
			},
			wantErr: assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, err := loadFixtures(tt.fixture)
			if err != nil {
				t.Fatalf("failed to load fixture: %s", err)
			}
			got, err := vtxosToTxsCovenantless(args.spendable, args.spent)
			if !tt.wantErr(t, err, fmt.Sprintf("vtxosToTxs(%v, %v)", args.spendable, args.spent)) {
				return
			}
			assert.Equalf(t, tt.want, got, "vtxosToTxs(%v, %v)", args.spendable, args.spent)
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
		}
	  ],
	  "spentVtxos": []
	}`
	bobAfterClaimingAsync = `
	{
		"spendableVtxos": [
		{
		  "outpoint": {
			"txid": "9b32fb4b1adb757598af9ef5d1709e853513078176bec6484077a450d62fe96f",
			"vout": 0
		  },
		  "receiver": {
			"address": "tark1qwnakvl59d5wckz9lqhhdav0uvns6uu3zkc6hg65gh0kgh6wve9pwqa8vzms5xcr7pqgt0sw88vc287dse5rw6fnxuk9f08frf8amxjcrya0tkgt",
			"amount": "1000"
		  },
		  "spent": false,
		  "poolTxid": "d6684a5b9e6939dccdf07d1f0eaf7fdd7b31de4d123e63e400d23de739800d4e",
		  "spentBy": "",
		  "expireAt": "1726055243",
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
		}
		]
	}`
)
