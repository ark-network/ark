package handlers

import (
	"context"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/server/internal/core/ports"
	log "github.com/sirupsen/logrus"
)

type walletInitHandler struct {
	walletService ports.WalletService
	onInit        func(password string)
	onUnlock      func(password string)
	onReady       func()
}

func NewWalletInitializerHandler(
	walletService ports.WalletService, onInit, onUnlock func(string), onReady func(),
) arkv1.WalletInitializerServiceServer {
	svc := walletInitHandler{walletService, onInit, onUnlock, onReady}
	go svc.listenWhenReady()
	return &svc
}

func (a *walletInitHandler) GenSeed(ctx context.Context, _ *arkv1.GenSeedRequest) (*arkv1.GenSeedResponse, error) {
	seed, err := a.walletService.GenSeed(ctx)
	if err != nil {
		return nil, err
	}

	return &arkv1.GenSeedResponse{Seed: seed}, nil
}

func (a *walletInitHandler) Create(ctx context.Context, req *arkv1.CreateRequest) (*arkv1.CreateResponse, error) {
	if len(req.GetSeed()) <= 0 {
		return nil, fmt.Errorf("missing wallet seed")
	}
	if len(req.GetPassword()) <= 0 {
		return nil, fmt.Errorf("missing wallet password")
	}

	if err := a.walletService.Create(
		ctx, req.GetSeed(), req.GetPassword(),
	); err != nil {
		return nil, err
	}

	go a.onInit(req.GetPassword())

	return &arkv1.CreateResponse{}, nil
}

func (a *walletInitHandler) Restore(ctx context.Context, req *arkv1.RestoreRequest) (*arkv1.RestoreResponse, error) {
	if len(req.GetSeed()) <= 0 {
		return nil, fmt.Errorf("missing wallet seed")
	}
	if len(req.GetPassword()) <= 0 {
		return nil, fmt.Errorf("missing wallet password")
	}

	if err := a.walletService.Restore(
		ctx, req.GetSeed(), req.GetPassword(),
	); err != nil {
		return nil, err
	}

	go a.onInit(req.GetPassword())

	return &arkv1.RestoreResponse{}, nil
}

func (a *walletInitHandler) Unlock(ctx context.Context, req *arkv1.UnlockRequest) (*arkv1.UnlockResponse, error) {
	if len(req.GetPassword()) <= 0 {
		return nil, fmt.Errorf("missing wallet password")
	}
	if err := a.walletService.Unlock(ctx, req.GetPassword()); err != nil {
		return nil, err
	}

	go a.onUnlock(req.GetPassword())

	go func() {
		status, err := a.walletService.Status(context.Background())
		if err != nil {
			log.Warnf("failed to get wallet status: %s", err)
			return
		}
		if status.IsUnlocked() && status.IsSynced() {
			a.onReady()
		}
	}()

	return &arkv1.UnlockResponse{}, nil
}

func (a *walletInitHandler) GetStatus(ctx context.Context, _ *arkv1.GetStatusRequest) (*arkv1.GetStatusResponse, error) {
	status, err := a.walletService.Status(ctx)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetStatusResponse{
		Initialized: status.IsInitialized(),
		Unlocked:    status.IsUnlocked(),
		Synced:      status.IsSynced(),
	}, nil
}

func (a *walletInitHandler) listenWhenReady() {
	ctx := context.Background()
	<-a.walletService.GetSyncedUpdate(ctx)

	status, err := a.walletService.Status(ctx)
	if err != nil {
		log.Warnf("failed to get wallet status: %s", err)
	}
	if status.IsUnlocked() && status.IsSynced() {
		a.onReady()
	}
}

type walletHandler struct {
	walletService ports.WalletService
}

func NewWalletHandler(walletService ports.WalletService) arkv1.WalletServiceServer {
	return &walletHandler{walletService}
}

func (a *walletHandler) Lock(ctx context.Context, req *arkv1.LockRequest) (*arkv1.LockResponse, error) {
	if len(req.GetPassword()) <= 0 {
		return nil, fmt.Errorf("missing wallet password")
	}
	if err := a.walletService.Lock(ctx, req.GetPassword()); err != nil {
		return nil, err
	}

	return &arkv1.LockResponse{}, nil
}

func (a *walletHandler) DeriveAddress(ctx context.Context, _ *arkv1.DeriveAddressRequest) (*arkv1.DeriveAddressResponse, error) {
	addr, err := a.walletService.DeriveAddresses(ctx, 1)
	if err != nil {
		return nil, err
	}

	return &arkv1.DeriveAddressResponse{Address: addr[0]}, nil
}

func (a *walletHandler) GetBalance(ctx context.Context, _ *arkv1.GetBalanceRequest) (*arkv1.GetBalanceResponse, error) {
	availableMainBalance, lockedMainBalance, err := a.walletService.MainAccountBalance(ctx)
	if err != nil {
		return nil, err
	}
	availableConnectorsBalance, lockedConnectorsBalance, err := a.walletService.ConnectorsAccountBalance(ctx)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetBalanceResponse{
		MainAccount: &arkv1.Balance{
			Locked:    convertSatsToBTCStr(lockedMainBalance),
			Available: convertSatsToBTCStr(availableMainBalance),
		},
		ConnectorsAccount: &arkv1.Balance{
			Locked:    convertSatsToBTCStr(lockedConnectorsBalance),
			Available: convertSatsToBTCStr(availableConnectorsBalance),
		},
	}, nil
}
