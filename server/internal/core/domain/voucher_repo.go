package domain

import "context"

type VoucherRepository interface {
	Contains(ctx context.Context, id uint64) (bool, error)
	Add(ctx context.Context, id uint64) error
	Close()
}
