package ports

import "github.com/ark-network/ark/internal/core/domain"

type TxBuilder interface {
	BuildPoolTx(wallet WalletService, payments []domain.Payment) (poolTx string, err error)
	BuildCongestionTree(poolTx string, payments []domain.Payment) (congestionTree []string, err error)
	BuildForfeitTxs(poolTx string, payments []domain.Payment) (connectors []string, forfeitTxs []string, err error)
}
