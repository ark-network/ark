package filestore

import (
	"encoding/hex"
	"strconv"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type storeData struct {
	ServerUrl                  string `json:"server_url"`
	ServerPubKey               string `json:"server_pubkey"`
	WalletType                 string `json:"wallet_type"`
	ClientType                 string `json:"client_type"`
	Network                    string `json:"network"`
	VtxoTreeExpiry             string `json:"vtxo_tree_expiry"`
	RoundInterval              string `json:"round_interval"`
	UnilateralExitDelay        string `json:"unilateral_exit_delay"`
	Dust                       string `json:"dust"`
	BoardingDescriptorTemplate string `json:"boarding_descriptor_template"`
	ExplorerURL                string `json:"explorer_url"`
	ForfeitAddress             string `json:"forfeit_address"`
	WithTransactionFeed        string `json:"with_transaction_feed"`
}

func (d storeData) isEmpty() bool {
	if d.ServerUrl == "" &&
		d.ServerPubKey == "" {
		return true
	}

	return false
}

func (d storeData) decode() types.Config {
	network := utils.NetworkFromString(d.Network)
	vtxoTreeExpiry, _ := strconv.Atoi(d.VtxoTreeExpiry)
	roundInterval, _ := strconv.Atoi(d.RoundInterval)
	unilateralExitDelay, _ := strconv.Atoi(d.UnilateralExitDelay)
	withTransactionFeed, _ := strconv.ParseBool(d.WithTransactionFeed)
	dust, _ := strconv.Atoi(d.Dust)
	buf, _ := hex.DecodeString(d.ServerPubKey)
	serverPubkey, _ := secp256k1.ParsePubKey(buf)
	explorerURL := d.ExplorerURL

	vtxoTreeExpiryType := common.LocktimeTypeBlock
	if vtxoTreeExpiry >= 512 {
		vtxoTreeExpiryType = common.LocktimeTypeSecond
	}

	unilateralExitDelayType := common.LocktimeTypeBlock
	if unilateralExitDelay >= 512 {
		unilateralExitDelayType = common.LocktimeTypeSecond
	}

	return types.Config{
		ServerUrl:                  d.ServerUrl,
		ServerPubKey:               serverPubkey,
		WalletType:                 d.WalletType,
		ClientType:                 d.ClientType,
		Network:                    network,
		VtxoTreeExpiry:             common.RelativeLocktime{Type: vtxoTreeExpiryType, Value: uint32(vtxoTreeExpiry)},
		UnilateralExitDelay:        common.RelativeLocktime{Type: unilateralExitDelayType, Value: uint32(unilateralExitDelay)},
		RoundInterval:              int64(roundInterval),
		Dust:                       uint64(dust),
		BoardingDescriptorTemplate: d.BoardingDescriptorTemplate,
		ExplorerURL:                explorerURL,
		ForfeitAddress:             d.ForfeitAddress,
		WithTransactionFeed:        withTransactionFeed,
	}
}

func (d storeData) asMap() map[string]string {
	return map[string]string{
		"server_url":                   d.ServerUrl,
		"server_pubkey":                d.ServerPubKey,
		"wallet_type":                  d.WalletType,
		"client_type":                  d.ClientType,
		"network":                      d.Network,
		"vtxo_tree_expiry":             d.VtxoTreeExpiry,
		"round_interval":               d.RoundInterval,
		"unilateral_exit_delay":        d.UnilateralExitDelay,
		"dust":                         d.Dust,
		"boarding_descriptor_template": d.BoardingDescriptorTemplate,
		"explorer_url":                 d.ExplorerURL,
		"forfeit_address":              d.ForfeitAddress,
		"with_transaction_feed":        d.WithTransactionFeed,
	}
}
