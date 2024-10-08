package domain

import "context"

type SdkRepository interface {
	AppDataRepository() AppDataRepository
	ConfigRepository() ConfigRepository
}

type AppDataRepository interface {
	TransactionRepository() TransactionRepository

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
	GetEventChannel() chan TransactionEvent
	GetBoardingTxs(ctx context.Context) ([]Transaction, error)
	Stop() error
}
