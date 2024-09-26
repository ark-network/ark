package badgerstore

import (
	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
)

type appDataRepository struct {
	transactionRepository domain.TransactionRepository
}

func NewAppDataRepository(
	transactionRepository domain.TransactionRepository,
) domain.AppDataRepository {
	return &appDataRepository{
		transactionRepository: transactionRepository,
	}
}

func (a *appDataRepository) TransactionRepository() domain.TransactionRepository {
	return a.transactionRepository
}

func (a *appDataRepository) Stop() error {
	if err := a.transactionRepository.Stop(); err != nil {
		return err
	}

	return nil
}
