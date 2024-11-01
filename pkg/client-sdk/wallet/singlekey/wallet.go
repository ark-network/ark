package singlekeywallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	walletstore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type singlekeyWallet struct {
	configStore types.ConfigStore
	walletStore walletstore.WalletStore
	privateKey  *secp256k1.PrivateKey
	walletData  *walletstore.WalletData
}

func (w *singlekeyWallet) GetType() string {
	return wallet.SingleKeyWallet
}

func (w *singlekeyWallet) Create(
	_ context.Context, password, seed string,
) (string, error) {
	var privateKey *secp256k1.PrivateKey
	if len(seed) <= 0 {
		privKey, err := utils.GenerateRandomPrivateKey()
		if err != nil {
			return "", err
		}
		privateKey = privKey
	} else {
		// handle nsec format
		if strings.HasPrefix(seed, "nsec") {
			hrp, data, err := bech32.Decode(seed)
			if err != nil {
				return "", fmt.Errorf("invalid nsec format: %w", err)
			}
			if hrp != "nsec" {
				return "", fmt.Errorf("invalid nsec prefix")
			}
			converted, err := bech32.ConvertBits(data, 5, 8, false)
			if err != nil {
				return "", fmt.Errorf("failed to convert bits: %w", err)
			}
			privateKey = secp256k1.PrivKeyFromBytes(converted)

			// else raw priv key
		} else {
			privKeyBytes, err := hex.DecodeString(seed)
			if err != nil {
				return "", err
			}
			privateKey = secp256k1.PrivKeyFromBytes(privKeyBytes)
		}
	}

	pwd := []byte(password)
	passwordHash := utils.HashPassword(pwd)
	pubkey := privateKey.PubKey()
	buf := privateKey.Serialize()
	encryptedPrivateKey, err := utils.EncryptAES256(buf, pwd)
	if err != nil {
		return "", err
	}

	walletData := walletstore.WalletData{
		EncryptedPrvkey: encryptedPrivateKey,
		PasswordHash:    passwordHash,
		Pubkey:          pubkey,
	}
	if err := w.walletStore.AddWallet(walletData); err != nil {
		return "", err
	}

	w.walletData = &walletData

	return hex.EncodeToString(privateKey.Serialize()), nil
}

func (w *singlekeyWallet) Lock(_ context.Context, password string) error {
	if w.walletData == nil {
		return fmt.Errorf("wallet not initialized")
	}

	if w.privateKey == nil {
		return nil
	}

	pwd := []byte(password)
	currentPassHash := utils.HashPassword(pwd)

	if !bytes.Equal(w.walletData.PasswordHash, currentPassHash) {
		return fmt.Errorf("invalid password")
	}

	w.privateKey = nil
	return nil
}

func (w *singlekeyWallet) Unlock(
	_ context.Context, password string,
) (bool, error) {
	if w.walletData == nil {
		return false, fmt.Errorf("wallet not initialized")
	}

	if w.privateKey != nil {
		return true, nil
	}

	pwd := []byte(password)
	currentPassHash := utils.HashPassword(pwd)

	if !bytes.Equal(w.walletData.PasswordHash, currentPassHash) {
		return false, fmt.Errorf("invalid password")
	}

	privateKeyBytes, err := utils.DecryptAES256(w.walletData.EncryptedPrvkey, pwd)
	if err != nil {
		return false, err
	}

	w.privateKey = secp256k1.PrivKeyFromBytes(privateKeyBytes)
	return false, nil
}

func (w *singlekeyWallet) IsLocked() bool {
	return w.privateKey == nil
}

func (w *singlekeyWallet) Dump(ctx context.Context) (string, error) {
	if w.walletData == nil {
		return "", fmt.Errorf("wallet not initialized")
	}

	if w.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	return hex.EncodeToString(w.privateKey.Serialize()), nil

}
