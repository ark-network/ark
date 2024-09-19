package store

import (
	"context"
)

const (
	InMemoryStore = "inmemory"
	FileStore     = "file"
)

type ConfigStore interface {
	GetType() string
	GetDatadir() string
	AddData(ctx context.Context, data StoreData) error
	GetData(ctx context.Context) (*StoreData, error)
	CleanData(ctx context.Context) error
}

type AppDataStore interface {
	TransactionRepository() TransactionRepository
	VtxoRepository() VtxoRepository

	Stop()
}

type TransactionRepository interface {
	InsertTransactions(ctx context.Context, txs []Transaction) error
	GetAll(ctx context.Context) ([]Transaction, error)
	GetEventChannel() chan Transaction
	GetBoardingTxs(ctx context.Context) ([]Transaction, error)
	Stop()
}

type VtxoRepository interface {
	InsertVtxos(ctx context.Context, vtxos []Vtxo) error
	GetAll(ctx context.Context) (spendable []Vtxo, spent []Vtxo, err error)
}
