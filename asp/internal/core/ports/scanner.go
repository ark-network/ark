package ports

import (
	"github.com/ark-network/ark/internal/core/domain"
	"golang.org/x/net/context"
)

type BlockchainScanner interface {
	WatchScripts(ctx context.Context, scripts []string) error
	UnwatchScripts(ctx context.Context, scripts []string) error
	GetNotificationChannel(ctx context.Context) chan []domain.VtxoKey
}
