package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"golang.org/x/crypto/scrypt"
)

func CoinSelect(
	vtxos []client.DescriptorVtxo, amount, dust uint64, sortByExpirationTime bool,
) ([]client.DescriptorVtxo, uint64, error) {
	selected := make([]client.DescriptorVtxo, 0)
	notSelected := make([]client.DescriptorVtxo, 0)
	selectedAmount := uint64(0)

	if sortByExpirationTime {
		// sort vtxos by expiration (older first)
		sort.SliceStable(vtxos, func(i, j int) bool {
			if vtxos[i].ExpiresAt == nil || vtxos[j].ExpiresAt == nil {
				return false
			}

			return vtxos[i].ExpiresAt.Before(*vtxos[j].ExpiresAt)
		})
	}

	for _, vtxo := range vtxos {
		if selectedAmount >= amount {
			notSelected = append(notSelected, vtxo)
			break
		}

		selected = append(selected, vtxo)
		selectedAmount += vtxo.Amount
	}

	if selectedAmount < amount {
		return nil, 0, fmt.Errorf("not enough funds to cover amount %d", amount)
	}

	change := selectedAmount - amount

	if change < dust {
		if len(notSelected) > 0 {
			selected = append(selected, notSelected[0])
			change += notSelected[0].Amount
		}
	}

	return selected, change, nil
}

func ParseLiquidAddress(addr string) (
	bool, []byte, error,
) {
	outputScript, err := address.ToOutputScript(addr)
	if err != nil {
		return false, nil, nil
	}

	return true, outputScript, nil
}

func ParseBitcoinAddress(addr string, net chaincfg.Params) (
	bool, []byte, error,
) {
	btcAddr, err := btcutil.DecodeAddress(addr, &net)
	if err != nil {
		return false, nil, nil
	}

	onchainScript, err := txscript.PayToAddrScript(btcAddr)
	if err != nil {
		return false, nil, err
	}
	return true, onchainScript, nil
}

func IsOnchainOnly(receivers []client.Output) bool {
	for _, receiver := range receivers {
		isOnChain := len(receiver.Address) > 0

		if !isOnChain {
			return false
		}
	}

	return true
}

func NetworkFromString(net string) common.Network {
	switch net {
	case common.Liquid.Name:
		return common.Liquid
	case common.LiquidTestNet.Name:
		return common.LiquidTestNet
	case common.LiquidRegTest.Name:
		return common.LiquidRegTest
	case common.BitcoinTestNet.Name:
		return common.BitcoinTestNet
	case common.BitcoinRegTest.Name:
		return common.BitcoinRegTest
	case common.BitcoinSigNet.Name:
		return common.BitcoinSigNet
	case common.Bitcoin.Name:
		fallthrough
	default:
		return common.Bitcoin
	}
}

func ToElementsNetwork(net common.Network) network.Network {
	switch net.Name {
	case common.Liquid.Name:
		return network.Liquid
	case common.LiquidTestNet.Name:
		return network.Testnet
	case common.LiquidRegTest.Name:
		return network.Regtest
	default:
		return network.Liquid
	}
}

func ToBitcoinNetwork(net common.Network) chaincfg.Params {
	mutinyNetSigNetParams := chaincfg.CustomSignetParams(common.MutinyNetChallenge, nil)
	mutinyNetSigNetParams.TargetTimePerBlock = common.MutinyNetBlockTime
	switch net.Name {
	case common.Bitcoin.Name:
		return chaincfg.MainNetParams
	case common.BitcoinTestNet.Name:
		return chaincfg.TestNet3Params
	case common.BitcoinRegTest.Name:
		return chaincfg.RegressionNetParams
	case common.BitcoinSigNet.Name:
		return mutinyNetSigNetParams
	default:
		return chaincfg.MainNetParams
	}
}

func GenerateRandomPrivateKey() (*secp256k1.PrivateKey, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func HashPassword(password []byte) []byte {
	hash := sha256.Sum256(password)
	return hash[:]
}

func EncryptAES128(privateKey, password []byte) ([]byte, error) {
	// Due to https://github.com/golang/go/issues/7168.
	// This call makes sure that memory is freed in case the GC doesn't do that
	// right after the encryption/decryption.
	defer debug.FreeOSMemory()

	if len(privateKey) == 0 {
		return nil, fmt.Errorf("missing plaintext private key")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("missing encryption password")
	}

	key, salt, err := deriveKey(password, nil)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, privateKey, nil)
	ciphertext = append(ciphertext, salt...)

	return ciphertext, nil
}

func DecryptAES128(encrypted, password []byte) ([]byte, error) {
	defer debug.FreeOSMemory()

	if len(encrypted) == 0 {
		return nil, fmt.Errorf("missing encrypted mnemonic")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("missing decryption password")
	}

	salt := encrypted[len(encrypted)-32:]
	data := encrypted[:len(encrypted)-32]

	key, _, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce, text := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	// #nosec G407
	plaintext, err := gcm.Open(nil, nonce, text, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}
	return plaintext, nil
}

var lock = &sync.Mutex{}

// deriveKey derives a 32 byte array key from a custom passhprase
func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	lock.Lock()
	defer lock.Unlock()

	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	// 2^20 = 1048576 recommended length for key-stretching
	// check the doc for other recommended values:
	// https://godoc.org/golang.org/x/crypto/scrypt
	key, err := scrypt.Key(password, salt, 1048576, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}
