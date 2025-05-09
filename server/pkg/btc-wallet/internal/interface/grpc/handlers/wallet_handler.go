package handlers

import (
	"context"
	application "github.com/ark-network/ark/server/pkg/btc-wallet/internal/core"

	walletv1 "github.com/ark-network/ark/server/pkg/btc-wallet/api-spec/protobuf/gen/wallet/v1"
)

type WalletServiceHandler struct {
	walletSvc application.WalletService
}

func NewWalletServiceHandler(walletSvc application.WalletService) walletv1.WalletServiceServer {
	return &WalletServiceHandler{walletSvc: walletSvc}
}

func (h *WalletServiceHandler) GenSeed(ctx context.Context, _ *walletv1.GenSeedRequest) (*walletv1.GenSeedResponse, error) {
	seed, err := h.walletSvc.GenSeed(ctx)
	if err != nil {
		return nil, err
	}
	return &walletv1.GenSeedResponse{Seed: seed}, nil
}

func (h *WalletServiceHandler) Create(ctx context.Context, req *walletv1.CreateRequest) (*walletv1.CreateResponse, error) {
	if err := h.walletSvc.Create(ctx, req.GetSeed(), req.GetPassword()); err != nil {
		return nil, err
	}
	return &walletv1.CreateResponse{}, nil
}

func (h *WalletServiceHandler) Restore(ctx context.Context, req *walletv1.RestoreRequest) (*walletv1.RestoreResponse, error) {
	if err := h.walletSvc.Restore(ctx, req.GetSeed(), req.GetPassword()); err != nil {
		return nil, err
	}
	return &walletv1.RestoreResponse{}, nil
}

func (h *WalletServiceHandler) Unlock(ctx context.Context, req *walletv1.UnlockRequest) (*walletv1.UnlockResponse, error) {
	if err := h.walletSvc.Unlock(ctx, req.GetPassword()); err != nil {
		return nil, err
	}
	return &walletv1.UnlockResponse{}, nil
}

func (h *WalletServiceHandler) Lock(ctx context.Context, req *walletv1.LockRequest) (*walletv1.LockResponse, error) {
	if err := h.walletSvc.Lock(ctx, req.GetPassword()); err != nil {
		return nil, err
	}
	return &walletv1.LockResponse{}, nil
}

func (h *WalletServiceHandler) Status(ctx context.Context, _ *walletv1.StatusRequest) (*walletv1.StatusResponse, error) {
	status, err := h.walletSvc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return &walletv1.StatusResponse{
		Initialized: status.IsInitialized,
		Unlocked:    status.IsUnlocked,
		Synced:      status.IsSynced,
	}, nil
}

func (h *WalletServiceHandler) GetPubkey(ctx context.Context, _ *walletv1.GetPubkeyRequest) (*walletv1.GetPubkeyResponse, error) {
	pubkey, err := h.walletSvc.GetPubkey(ctx)
	if err != nil {
		return nil, err
	}
	return &walletv1.GetPubkeyResponse{Pubkey: pubkey.SerializeCompressed()}, nil
}

func (h *WalletServiceHandler) GetForfeitAddress(
	ctx context.Context, req *walletv1.GetForfeitAddressRequest,
) (*walletv1.GetForfeitAddressResponse, error) {
	addr, err := h.walletSvc.GetForfeitAddress(ctx)
	if err != nil {
		return nil, err
	}
	return &walletv1.GetForfeitAddressResponse{Address: addr}, nil
}

func (h *WalletServiceHandler) DeriveConnectorAddress(
	ctx context.Context, _ *walletv1.DeriveConnectorAddressRequest,
) (*walletv1.DeriveConnectorAddressResponse, error) {
	addr, err := h.walletSvc.DeriveConnectorAddress(ctx)
	if err != nil {
		return nil, err
	}
	return &walletv1.DeriveConnectorAddressResponse{Address: addr}, nil
}

func (h *WalletServiceHandler) DeriveAddresses(
	ctx context.Context, req *walletv1.DeriveAddressesRequest,
) (*walletv1.DeriveAddressesResponse, error) {
	addresses, err := h.walletSvc.DeriveAddresses(ctx, int(req.Num))
	if err != nil {
		return nil, err
	}
	return &walletv1.DeriveAddressesResponse{Addresses: addresses}, nil
}

func (h *WalletServiceHandler) SignTransaction(
	ctx context.Context, req *walletv1.SignTransactionRequest,
) (*walletv1.SignTransactionResponse, error) {
	tx, err := h.walletSvc.SignTransaction(ctx, req.PartialTx, req.ExtractRawTx)
	if err != nil {
		return nil, err
	}
	return &walletv1.SignTransactionResponse{SignedTx: tx}, nil
}

func (h *WalletServiceHandler) SignTransactionTapscript(
	ctx context.Context, req *walletv1.SignTransactionTapscriptRequest,
) (*walletv1.SignTransactionTapscriptResponse, error) {
	inIndexes := make([]int, 0, len(req.GetInputIndexes()))
	for _, v := range req.GetInputIndexes() {
		inIndexes = append(inIndexes, int(v))
	}
	tx, err := h.walletSvc.SignTransactionTapscript(ctx, req.GetPartialTx(), inIndexes)
	if err != nil {
		return nil, err
	}
	return &walletv1.SignTransactionTapscriptResponse{SignedTx: tx}, nil
}

func (h *WalletServiceHandler) SelectUtxos(
	ctx context.Context, req *walletv1.SelectUtxosRequest,
) (*walletv1.SelectUtxosResponse, error) {
	utxos, total, err := h.walletSvc.SelectUtxos(ctx, req.Asset, req.Amount)
	if err != nil {
		return nil, err
	}
	var respUtxos []*walletv1.TxInput
	for _, u := range utxos {
		respUtxos = append(respUtxos, &walletv1.TxInput{
			Txid:   u.Txid,
			Index:  u.Index,
			Script: u.Script,
			Value:  u.Value,
		})
	}
	return &walletv1.SelectUtxosResponse{Utxos: respUtxos, TotalAmount: total}, nil
}

func (h *WalletServiceHandler) BroadcastTransaction(
	ctx context.Context, req *walletv1.BroadcastTransactionRequest,
) (*walletv1.BroadcastTransactionResponse, error) {
	txid, err := h.walletSvc.BroadcastTransaction(ctx, req.GetTxHex())
	if err != nil {
		return nil, err
	}
	return &walletv1.BroadcastTransactionResponse{Txid: txid}, nil
}

func (h *WalletServiceHandler) WaitForSync(
	ctx context.Context, req *walletv1.WaitForSyncRequest,
) (*walletv1.WaitForSyncResponse, error) {
	if err := h.walletSvc.WaitForSync(ctx, req.GetTxid()); err != nil {
		return nil, err
	}
	return &walletv1.WaitForSyncResponse{}, nil
}

func (h *WalletServiceHandler) EstimateFees(
	ctx context.Context, req *walletv1.EstimateFeesRequest,
) (*walletv1.EstimateFeesResponse, error) {
	fee, err := h.walletSvc.EstimateFees(ctx, req.GetPsbt())
	if err != nil {
		return nil, err
	}
	return &walletv1.EstimateFeesResponse{Fee: fee}, nil
}

func (h *WalletServiceHandler) MinRelayFee(
	ctx context.Context, req *walletv1.MinRelayFeeRequest,
) (*walletv1.MinRelayFeeResponse, error) {
	fee, err := h.walletSvc.MinRelayFee(ctx, req.GetVbytes())
	if err != nil {
		return nil, err
	}
	return &walletv1.MinRelayFeeResponse{Fee: fee}, nil
}

func (h *WalletServiceHandler) MinRelayFeeRate(
	ctx context.Context, _ *walletv1.MinRelayFeeRateRequest,
) (*walletv1.MinRelayFeeRateResponse, error) {
	feeRate := h.walletSvc.MinRelayFeeRate(ctx)
	return &walletv1.MinRelayFeeRateResponse{SatPerKvbyte: uint64(feeRate)}, nil
}

func (h *WalletServiceHandler) ListConnectorUtxos(
	ctx context.Context, req *walletv1.ListConnectorUtxosRequest,
) (*walletv1.ListConnectorUtxosResponse, error) {
	utxos, err := h.walletSvc.ListConnectorUtxos(ctx, req.GetConnectorAddress())
	if err != nil {
		return nil, err
	}
	respUtxos := make([]*walletv1.TxInput, 0, len(utxos))
	for _, u := range utxos {
		respUtxos = append(respUtxos, &walletv1.TxInput{
			Txid:   u.Txid,
			Index:  u.Index,
			Script: u.Script,
			Value:  u.Value,
		})
	}
	return &walletv1.ListConnectorUtxosResponse{Utxos: respUtxos}, nil
}

func (h *WalletServiceHandler) MainAccountBalance(
	ctx context.Context, _ *walletv1.MainAccountBalanceRequest,
) (*walletv1.MainAccountBalanceResponse, error) {
	confirmed, unconfirmed, err := h.walletSvc.MainAccountBalance(ctx)
	if err != nil {
		return nil, err
	}
	return &walletv1.MainAccountBalanceResponse{Confirmed: confirmed, Unconfirmed: unconfirmed}, nil
}

func (h *WalletServiceHandler) ConnectorsAccountBalance(
	ctx context.Context, _ *walletv1.ConnectorsAccountBalanceRequest,
) (*walletv1.ConnectorsAccountBalanceResponse, error) {
	confirmed, unconfirmed, err := h.walletSvc.ConnectorsAccountBalance(ctx)
	if err != nil {
		return nil, err
	}
	return &walletv1.ConnectorsAccountBalanceResponse{Confirmed: confirmed, Unconfirmed: unconfirmed}, nil
}

func (h *WalletServiceHandler) LockConnectorUtxos(
	ctx context.Context, req *walletv1.LockConnectorUtxosRequest,
) (*walletv1.LockConnectorUtxosResponse, error) {
	utxos := make([]application.TxOutpoint, 0, len(req.GetUtxos()))
	for _, u := range req.Utxos {
		utxos = append(utxos, application.TxOutpoint{
			Txid:  u.GetTxid(),
			Index: u.GetIndex(),
		})
	}
	if err := h.walletSvc.LockConnectorUtxos(ctx, utxos); err != nil {
		return nil, err
	}
	return &walletv1.LockConnectorUtxosResponse{}, nil
}

func (h *WalletServiceHandler) GetDustAmount(
	ctx context.Context, _ *walletv1.GetDustAmountRequest,
) (*walletv1.GetDustAmountResponse, error) {
	dust, err := h.walletSvc.GetDustAmount(ctx)
	if err != nil {
		return nil, err
	}
	return &walletv1.GetDustAmountResponse{DustAmount: dust}, nil
}

func (h *WalletServiceHandler) GetTransaction(
	ctx context.Context, req *walletv1.GetTransactionRequest,
) (*walletv1.GetTransactionResponse, error) {
	tx, err := h.walletSvc.GetTransaction(ctx, req.GetTxid())
	if err != nil {
		return nil, err
	}
	return &walletv1.GetTransactionResponse{TxHex: tx}, nil
}

func (h *WalletServiceHandler) SignMessage(
	ctx context.Context, req *walletv1.SignMessageRequest,
) (*walletv1.SignMessageResponse, error) {
	sig, err := h.walletSvc.SignMessage(ctx, req.GetMessage())
	if err != nil {
		return nil, err
	}
	return &walletv1.SignMessageResponse{Signature: sig}, nil
}

func (h *WalletServiceHandler) VerifyMessageSignature(
	ctx context.Context, req *walletv1.VerifyMessageSignatureRequest,
) (*walletv1.VerifyMessageSignatureResponse, error) {
	valid, err := h.walletSvc.VerifyMessageSignature(ctx, req.GetMessage(), req.GetSignature())
	if err != nil {
		return nil, err
	}
	return &walletv1.VerifyMessageSignatureResponse{Valid: valid}, nil
}

func (h *WalletServiceHandler) GetCurrentBlockTime(
	ctx context.Context, _ *walletv1.GetCurrentBlockTimeRequest,
) (*walletv1.GetCurrentBlockTimeResponse, error) {
	ts, err := h.walletSvc.GetCurrentBlockTime(ctx)
	if err != nil {
		return nil, err
	}
	return &walletv1.GetCurrentBlockTimeResponse{
		Timestamp: &walletv1.BlockTimestamp{
			Height: ts.Height,
			Time:   ts.Time,
		},
	}, nil
}

func (h *WalletServiceHandler) Withdraw(
	ctx context.Context, req *walletv1.WithdrawRequest,
) (*walletv1.WithdrawResponse, error) {
	txid, err := h.walletSvc.Withdraw(ctx, req.GetAddress(), req.GetAmount())
	if err != nil {
		return nil, err
	}
	return &walletv1.WithdrawResponse{Txid: txid}, nil
}
