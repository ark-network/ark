package domain

import "context"

type SdkRepository interface {
	AppDataRepository() AppDataRepository
	ConfigRepository() ConfigRepository
}

type AppDataRepository interface {
	TransactionRepository() TransactionRepository
	VtxoRepository() VtxoRepository

	Stop() error
}

type ConfigRepository interface {
	GetType() string
	GetDatadir() string
	AddData(ctx context.Context, data ConfigData) error
	GetData(ctx context.Context) (*ConfigData, error)
	CleanData(ctx context.Context) error
}

type TransactionRepository interface {
	InsertTransactions(ctx context.Context, txs []Transaction) error
	UpdateTransactions(ctx context.Context, txs []Transaction) error
	GetAll(ctx context.Context) ([]Transaction, error)
	GetEventChannel() chan Transaction
	GetBoardingTxs(ctx context.Context) ([]Transaction, error)
	Stop() error
}

type VtxoRepository interface {
	InsertVtxos(ctx context.Context, vtxos []Vtxo) error
	GetAll(ctx context.Context) (spendable []Vtxo, spent []Vtxo, err error)
	DeleteAll(ctx context.Context) error
	Stop() error
}
