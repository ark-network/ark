package filestore

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/ark-network/ark-sdk/store"
	walletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	filename = "state.json"
)

type walletData struct {
	EncryptedPrvkey string `json:"encrypted_private_key"`
	PasswordHash    string `json:"password_hash"`
	Pubkey          string `json:"pubkey"`
}

func (d walletData) isEmpty() bool {
	return d == walletData{}
}

func (d walletData) decode() walletstore.WalletData {
	encryptedPrvkey, _ := hex.DecodeString(d.EncryptedPrvkey)
	passwordHash, _ := hex.DecodeString(d.PasswordHash)
	buf, _ := hex.DecodeString(d.Pubkey)
	pubkey, _ := secp256k1.ParsePubKey(buf)
	return walletstore.WalletData{
		EncryptedPrvkey: encryptedPrvkey,
		PasswordHash:    passwordHash,
		Pubkey:          pubkey,
	}
}

func (d walletData) asMap() map[string]string {
	return map[string]string{
		"encrypted_private_key": d.EncryptedPrvkey,
		"password_hash":         d.PasswordHash,
		"pubkey":                d.Pubkey,
	}
}

type fileStore struct {
	store.Store
	filePath string
}

func NewWalletStore(
	baseDir string, store store.Store,
) (walletstore.WalletStore, error) {
	datadir := cleanAndExpandPath(baseDir)
	if err := makeDirectoryIfNotExists(datadir); err != nil {
		return nil, fmt.Errorf("failed to initialize datadir: %s", err)
	}
	filePath := filepath.Join(datadir, filename)

	fileStore := &fileStore{store, filePath}

	if _, err := fileStore.open(); err != nil {
		return nil, fmt.Errorf("failed to open file store")
	}

	return fileStore, nil
}

func (s *fileStore) AddWallet(data walletstore.WalletData) error {
	wd := &walletData{
		EncryptedPrvkey: hex.EncodeToString(data.EncryptedPrvkey),
		PasswordHash:    hex.EncodeToString(data.PasswordHash),
		Pubkey:          hex.EncodeToString(data.Pubkey.SerializeCompressed()),
	}

	if err := s.write(wd); err != nil {
		return fmt.Errorf("failed to write to file store: %s", err)
	}
	return nil
}

func (s *fileStore) GetWallet() (*walletstore.WalletData, error) {
	wd, err := s.open()
	if err != nil {
		return nil, err
	}
	if wd.isEmpty() {
		return nil, nil
	}

	data := wd.decode()
	return &data, nil
}

func (s *fileStore) open() (*walletData, error) {
	file, err := os.ReadFile(s.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to open file store: %s", err)
		}
		if err := s.write(&walletData{}); err != nil {
			return nil, fmt.Errorf("failed to initialize file store: %s", err)
		}
		return nil, nil
	}

	data := &walletData{}
	if err := json.Unmarshal(file, data); err != nil {
		return nil, fmt.Errorf("failed to read file store: %s", err)
	}
	return data, nil
}

func (s *fileStore) write(data *walletData) error {
	file, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	currentData := map[string]string{}
	if err := json.Unmarshal(file, &data); err != nil {
		return fmt.Errorf("failed to read file store: %s", err)
	}

	mergedData := merge(currentData, data.asMap())

	jsonString, err := json.Marshal(mergedData)
	if err != nil {
		return err
	}

	err = os.WriteFile(s.filePath, jsonString, 0755)
	if err != nil {
		return err
	}

	return nil
}

func cleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string
		u, err := user.Current()
		if err == nil {
			homeDir = u.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

func makeDirectoryIfNotExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, os.ModeDir|0755)
	}
	return nil
}

func merge(maps ...map[string]string) map[string]string {
	merge := make(map[string]string, 0)
	for _, m := range maps {
		for k, v := range m {
			merge[k] = v
		}
	}
	return merge
}
