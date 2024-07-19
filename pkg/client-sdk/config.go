package arksdk

import (
	"fmt"
	"strings"

	"github.com/ark-network/ark-sdk/store"
	filestore "github.com/ark-network/ark-sdk/store/file"
	inmemorystore "github.com/ark-network/ark-sdk/store/inmemory"
	walletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store"
)

var (
	supportedStores = supportedType[store.StoreFactory]{
		"inmemory": inmemorystore.NewStore,
		"file":     filestore.NewStore,
	}
)

type Config struct {
	StoreType   string
	StoreArgs   []interface{}
	CustomStore walletstore.WalletStore
}

func (c Config) validate() error {
	if c.CustomStore != nil {
		return nil
	}
	if len(c.StoreType) <= 0 {
		return fmt.Errorf("missing store type")
	}
	if !supportedStores.supports(c.StoreType) {
		return fmt.Errorf("store type not supported, please select one of: %s", supportedStores)
	}
	return nil
}

func (c Config) store() (store.Store, error) {
	factory := supportedStores[c.StoreType]
	return factory(c.StoreArgs...)
}

type supportedType[V any] map[string]V

func (t supportedType[V]) String() string {
	types := make([]string, 0, len(t))
	for tt := range t {
		types = append(types, tt)
	}
	return strings.Join(types, " | ")
}

func (t supportedType[V]) supports(typeStr string) bool {
	_, ok := t[typeStr]
	return ok
}
