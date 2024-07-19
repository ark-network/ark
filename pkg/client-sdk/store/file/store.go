package filestore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ark-network/ark-sdk/store"
	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	filename = "state.json"
)

type storeData struct {
	AspUrl              string `json:"asp_url"`
	AspPubkey           string `json:"asp_pubkey"`
	WalletType          string `json:"wallet_type"`
	ClientType          string `json:"client_type"`
	ExplorerURL         string `json:"explorer_url"`
	Network             string `json:"network"`
	RoundLifetime       string `json:"round_lifetime"`
	UnilateralExitDelay string `json:"unilateral_exit_delay"`
	MinRelayFee         string `json:"min_relay_fee"`
}

func (d storeData) isEmpty() bool {
	return d == storeData{}
}

func (d storeData) decode() store.StoreData {
	network := networkFromString(d.Network)
	roundLifetime, _ := strconv.Atoi(d.RoundLifetime)
	unilateralExitDelay, _ := strconv.Atoi(d.UnilateralExitDelay)
	minRelayFee, _ := strconv.Atoi(d.MinRelayFee)
	buf, _ := hex.DecodeString(d.AspPubkey)
	aspPubkey, _ := secp256k1.ParsePubKey(buf)
	return store.StoreData{
		AspUrl:              d.AspUrl,
		AspPubkey:           aspPubkey,
		WalletType:          d.WalletType,
		ClientType:          d.ClientType,
		ExplorerURL:         d.ExplorerURL,
		Network:             network,
		RoundLifetime:       int64(roundLifetime),
		UnilateralExitDelay: int64(unilateralExitDelay),
		MinRelayFee:         uint64(minRelayFee),
	}
}

func (d storeData) asMap() map[string]string {
	return map[string]string{
		"asp_url":               d.AspUrl,
		"asp_pubkey":            d.AspPubkey,
		"wallet_type":           d.WalletType,
		"client_type":           d.ClientType,
		"explorer_url":          d.ExplorerURL,
		"network":               d.Network,
		"round_lifetime":        d.RoundLifetime,
		"unilateral_exit_delay": d.UnilateralExitDelay,
		"min_relay_fee":         d.MinRelayFee,
	}
}

type Store struct {
	filePath string
}

func NewStore(args ...interface{}) (store.Store, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("invalid number of args")
	}
	baseDir, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid base dir")
	}

	datadir := cleanAndExpandPath(baseDir)
	if err := makeDirectoryIfNotExists(datadir); err != nil {
		return nil, fmt.Errorf("failed to initialize datadir: %s", err)
	}
	filePath := filepath.Join(datadir, filename)

	fileStore := &Store{filePath}

	if _, err := fileStore.open(); err != nil {
		return nil, fmt.Errorf("failed to open store")
	}

	return fileStore, nil
}

func (s *Store) AddData(ctx context.Context, data store.StoreData) error {
	sd := &storeData{
		AspUrl:              data.AspUrl,
		AspPubkey:           hex.EncodeToString(data.AspPubkey.SerializeCompressed()),
		ClientType:          data.ClientType,
		ExplorerURL:         data.ExplorerURL,
		Network:             data.Network.Name,
		RoundLifetime:       fmt.Sprintf("%d", data.RoundLifetime),
		UnilateralExitDelay: fmt.Sprintf("%d", data.UnilateralExitDelay),
		MinRelayFee:         fmt.Sprintf("%d", data.MinRelayFee),
	}

	if err := s.write(sd); err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

func (s *Store) GetData(_ context.Context) (*store.StoreData, error) {
	sd, err := s.open()
	if err != nil {
		return nil, err
	}
	if sd.isEmpty() {
		return nil, nil
	}

	data := sd.decode()
	return &data, nil
}

func (s *Store) CleanData(ctx context.Context) error {
	if err := s.write(&storeData{}); err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

func (s *Store) open() (*storeData, error) {
	file, err := os.ReadFile(s.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to open store: %s", err)
		}
		if err := s.write(&storeData{}); err != nil {
			return nil, fmt.Errorf("failed to initialize store: %s", err)
		}
		return nil, nil
	}

	data := &storeData{}
	if err := json.Unmarshal(file, data); err != nil {
		return nil, fmt.Errorf("failed to read file store: %s", err)
	}
	return data, nil
}

func (s *Store) write(data *storeData) error {
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

func networkFromString(net string) common.Network {
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
	case common.Bitcoin.Name:
		fallthrough
	default:
		return common.Bitcoin
	}
}
