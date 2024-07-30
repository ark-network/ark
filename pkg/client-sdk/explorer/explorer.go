package explorer

import "github.com/vulpemventures/go-elements/network"

const (
	BitcoinExplorer = "bitcoin"
	LiquidExplorer  = "liquid"
)

type Utxo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Amount uint64 `json:"value"`
	Asset  string `json:"asset"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		Blocktime int64 `json:"block_time"`
	} `json:"status"`
}

type Explorer interface {
	GetTxHex(txid string) (string, error)
	Broadcast(txHex string) (string, error)
	GetUtxos(addr string) ([]Utxo, error)
	GetBalance(addr string) (uint64, error)
	GetRedeemedVtxosBalance(
		addr string, unilateralExitDelay int64,
	) (uint64, map[int64]uint64, error)
	GetTxBlockTime(
		txid string,
	) (confirmed bool, blocktime int64, err error)
	GetNetwork() network.Network
	BaseUrl() string
}
