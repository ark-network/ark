package store

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type WalletData struct {
	EncryptedPrvkey []byte
	PasswordHash    []byte
	PubKey          *secp256k1.PublicKey
}

type WalletStore interface {
	AddWallet(data WalletData) error
	GetWallet() (*WalletData, error)
}
