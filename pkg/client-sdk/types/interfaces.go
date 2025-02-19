package types

import "context"

type Store interface {
	ConfigStore() ConfigStore
	TransactionStore() TransactionStore
	VtxoStore() VtxoStore
	Close()
}

type ConfigStore interface {
	GetType() string
	GetDatadir() string
	AddData(ctx context.Context, data Config) error
	GetData(ctx context.Context) (*Config, error)
	CleanData(ctx context.Context) error
	Close()
}

type TransactionStore interface {
	AddTransactions(ctx context.Context, txs []Transaction) (int, error)
	UpdateTransactions(ctx context.Context, txs []Transaction) (int, error)
	GetAllTransactions(ctx context.Context) ([]Transaction, error)
	GetTransactions(ctx context.Context, txids []string) ([]Transaction, error)
	GetEventChannel() chan Transaction
	Close()
}

type VtxoStore interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) (int, error)
	UpdateVtxos(ctx context.Context, vtxos []Vtxo) (int, error)
	SpendVtxos(ctx context.Context, vtxos []VtxoKey, spentBy string) (int, error)
	GetAllVtxos(ctx context.Context) (spendable []Vtxo, spent []Vtxo, err error)
	GetVtxos(ctx context.Context, keys []VtxoKey) ([]Vtxo, error)
	Close()
}
