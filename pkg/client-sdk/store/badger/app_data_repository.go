package badgerstore

import (
	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
)

type appDataRepository struct {
	transactionRepository domain.TransactionRepository
	vtxoRepository        domain.VtxoRepository
}

func NewAppDataRepository(
	transactionRepository domain.TransactionRepository,
	vtxoRepository domain.VtxoRepository,
) domain.AppDataRepository {
	return &appDataRepository{
		transactionRepository: transactionRepository,
		vtxoRepository:        vtxoRepository,
	}
}

func (a *appDataRepository) TransactionRepository() domain.TransactionRepository {
	return a.transactionRepository
}

func (a *appDataRepository) VtxoRepository() domain.VtxoRepository {
	return a.vtxoRepository
}

func (a *appDataRepository) Stop() error {
	if err := a.transactionRepository.Stop(); err != nil {
		return err
	}

	return a.vtxoRepository.Stop()
}
