package filestore

import (
	"encoding/hex"
	"strconv"

	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type storeData struct {
	AspUrl                     string `json:"asp_url"`
	AspPubkey                  string `json:"asp_pubkey"`
	WalletType                 string `json:"wallet_type"`
	ClientType                 string `json:"client_type"`
	Network                    string `json:"network"`
	RoundLifetime              string `json:"round_lifetime"`
	RoundInterval              string `json:"round_interval"`
	UnilateralExitDelay        string `json:"unilateral_exit_delay"`
	Dust                       string `json:"dust"`
	BoardingDescriptorTemplate string `json:"boarding_descriptor_template"`
	ExplorerURL                string `json:"explorer_url"`
	ForfeitAddress             string `json:"forfeit_address"`
	WithTransactionFeed        string `json:"with_transaction_feed"`
}

func (d storeData) isEmpty() bool {
	if d.AspUrl == "" &&
		d.AspPubkey == "" {
		return true
	}

	return false
}

func (d storeData) decode() types.Config {
	network := utils.NetworkFromString(d.Network)
	roundLifetime, _ := strconv.Atoi(d.RoundLifetime)
	roundInterval, _ := strconv.Atoi(d.RoundInterval)
	unilateralExitDelay, _ := strconv.Atoi(d.UnilateralExitDelay)
	withTransactionFeed, _ := strconv.ParseBool(d.WithTransactionFeed)
	dust, _ := strconv.Atoi(d.Dust)
	buf, _ := hex.DecodeString(d.AspPubkey)
	aspPubkey, _ := secp256k1.ParsePubKey(buf)
	explorerURL := d.ExplorerURL
	return types.Config{
		AspUrl:                     d.AspUrl,
		AspPubkey:                  aspPubkey,
		WalletType:                 d.WalletType,
		ClientType:                 d.ClientType,
		Network:                    network,
		RoundLifetime:              int64(roundLifetime),
		UnilateralExitDelay:        int64(unilateralExitDelay),
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
		"asp_url":                      d.AspUrl,
		"asp_pubkey":                   d.AspPubkey,
		"wallet_type":                  d.WalletType,
		"client_type":                  d.ClientType,
		"network":                      d.Network,
		"round_lifetime":               d.RoundLifetime,
		"round_interval":               d.RoundInterval,
		"unilateral_exit_delay":        d.UnilateralExitDelay,
		"dust":                         d.Dust,
		"boarding_descriptor_template": d.BoardingDescriptorTemplate,
		"explorer_url":                 d.ExplorerURL,
		"forfeit_address":              d.ForfeitAddress,
		"with_transaction_feed":        d.WithTransactionFeed,
	}
}
