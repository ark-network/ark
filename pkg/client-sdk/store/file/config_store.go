package filestore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ark-network/ark/pkg/client-sdk/types"
)

const (
	configStoreFilename = "state.json"
)

type configStore struct {
	filePath string
}

func NewConfigStore(baseDir string) (types.ConfigStore, error) {
	if len(baseDir) <= 0 {
		return nil, fmt.Errorf("missing base directory")
	}

	datadir := cleanAndExpandPath(baseDir)
	if err := makeDirectoryIfNotExists(datadir); err != nil {
		return nil, fmt.Errorf("failed to initialize datadir: %s", err)
	}
	filePath := filepath.Join(datadir, configStoreFilename)

	store := &configStore{filePath}

	if _, err := store.open(); err != nil {
		return nil, fmt.Errorf("failed to open store: %s", err)
	}

	return store, nil
}

func (s *configStore) Close() {}

func (s *configStore) GetType() string {
	return "file"
}

func (s *configStore) GetDatadir() string {
	return filepath.Dir(s.filePath)
}

func (s *configStore) AddData(ctx context.Context, data types.Config) error {
	sd := &storeData{
		AspUrl:                     data.AspUrl,
		AspPubkey:                  hex.EncodeToString(data.AspPubkey.SerializeCompressed()),
		WalletType:                 data.WalletType,
		ClientType:                 data.ClientType,
		Network:                    data.Network.Name,
		RoundLifetime:              fmt.Sprintf("%d", data.RoundLifetime),
		RoundInterval:              fmt.Sprintf("%d", data.RoundInterval),
		UnilateralExitDelay:        fmt.Sprintf("%d", data.UnilateralExitDelay),
		Dust:                       fmt.Sprintf("%d", data.Dust),
		BoardingDescriptorTemplate: data.BoardingDescriptorTemplate,
		ExplorerURL:                data.ExplorerURL,
		ForfeitAddress:             data.ForfeitAddress,
		WithTransactionFeed:        strconv.FormatBool(data.WithTransactionFeed),
	}

	if err := s.write(sd); err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

func (s *configStore) GetData(_ context.Context) (*types.Config, error) {
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

func (s *configStore) CleanData(ctx context.Context) error {
	if err := s.write(&storeData{}); err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

func (s *configStore) open() (*storeData, error) {
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

func (s *configStore) write(data *storeData) error {
	file, err := os.ReadFile(s.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}
	currentData := map[string]string{}
	if len(file) > 0 {
		if err := json.Unmarshal(file, &currentData); err != nil {
			return fmt.Errorf("failed to read file store: %s", err)
		}
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
