package store

import (
	"github.com/ark-network/ark-sdk/store"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type WalletData struct {
	EncryptedPrvkey []byte
	PasswordHash    []byte
	Pubkey          *secp256k1.PublicKey
}

type WalletStore interface {
	store.Store
	AddWallet(data WalletData) error
	GetWallet() (*WalletData, error)
}
