package middleware

import (
	"context"

	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/types"
)

type ArkClientProxy struct {
	client arksdk.ArkClient
	chain  *Chain
}

func NewArkClientProxy(client arksdk.ArkClient, chain *Chain) arksdk.ArkClient {
	return &ArkClientProxy{client: client, chain: chain}
}

func (p *ArkClientProxy) GetConfigData(ctx context.Context) (*types.Config, error) {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "GetConfigData", middlewareArgs)

	ret0, ret1 := p.client.GetConfigData(ctx)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "GetConfigData", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) Init(ctx context.Context, args arksdk.InitArgs) error {

	middlewareArgs := []interface{}{ctx, args}
	ctx = p.chain.Before(ctx, "Init", middlewareArgs)

	ret0 := p.client.Init(ctx, args)
	results := []interface{}{ret0}

	p.chain.After(ctx, "Init", results, ret0)

	return ret0

}

func (p *ArkClientProxy) InitWithWallet(ctx context.Context, args arksdk.InitWithWalletArgs) error {

	middlewareArgs := []interface{}{ctx, args}
	ctx = p.chain.Before(ctx, "InitWithWallet", middlewareArgs)

	ret0 := p.client.InitWithWallet(ctx, args)
	results := []interface{}{ret0}

	p.chain.After(ctx, "InitWithWallet", results, ret0)

	return ret0

}

func (p *ArkClientProxy) IsLocked(ctx context.Context) bool {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "IsLocked", middlewareArgs)

	ret0 := p.client.IsLocked(ctx)
	results := []interface{}{ret0}

	p.chain.After(ctx, "IsLocked", results, nil)

	return ret0

}

func (p *ArkClientProxy) Unlock(ctx context.Context, password string) error {

	middlewareArgs := []interface{}{ctx, password}
	ctx = p.chain.Before(ctx, "Unlock", middlewareArgs)

	ret0 := p.client.Unlock(ctx, password)
	results := []interface{}{ret0}

	p.chain.After(ctx, "Unlock", results, ret0)

	return ret0

}

func (p *ArkClientProxy) Lock(ctx context.Context) error {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "Lock", middlewareArgs)

	ret0 := p.client.Lock(ctx)
	results := []interface{}{ret0}

	p.chain.After(ctx, "Lock", results, ret0)

	return ret0

}

func (p *ArkClientProxy) Balance(ctx context.Context, computeExpiryDetails bool) (*arksdk.Balance, error) {

	middlewareArgs := []interface{}{ctx, computeExpiryDetails}
	ctx = p.chain.Before(ctx, "Balance", middlewareArgs)

	ret0, ret1 := p.client.Balance(ctx, computeExpiryDetails)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "Balance", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) Receive(ctx context.Context) (offchainAddr string, boardingAddr string, err error) {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "Receive", middlewareArgs)

	// Assign to named return variables

	offchainAddr, boardingAddr, err = p.client.Receive(ctx)
	results := []interface{}{offchainAddr, boardingAddr}

	p.chain.After(ctx, "Receive", results, err)

	return

}

func (p *ArkClientProxy) SendOffChain(ctx context.Context, withExpiryCoinselect bool, receivers []arksdk.Receiver, withZeroFees bool) (string, error) {

	middlewareArgs := []interface{}{ctx, withExpiryCoinselect, receivers, withZeroFees}
	ctx = p.chain.Before(ctx, "SendOffChain", middlewareArgs)

	ret0, ret1 := p.client.SendOffChain(ctx, withExpiryCoinselect, receivers, withZeroFees)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "SendOffChain", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) Settle(ctx context.Context, opts ...arksdk.Option) (string, error) {

	middlewareArgs := []interface{}{ctx, opts}
	ctx = p.chain.Before(ctx, "Settle", middlewareArgs)

	ret0, ret1 := p.client.Settle(ctx, opts...)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "Settle", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) CollaborativeExit(ctx context.Context, addr string, amount uint64, withExpiryCoinselect bool, opts ...arksdk.Option) (string, error) {

	middlewareArgs := []interface{}{ctx, addr, amount, withExpiryCoinselect, opts}
	ctx = p.chain.Before(ctx, "CollaborativeExit", middlewareArgs)

	ret0, ret1 := p.client.CollaborativeExit(ctx, addr, amount, withExpiryCoinselect, opts...)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "CollaborativeExit", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) StartUnilateralExit(ctx context.Context) error {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "StartUnilateralExit", middlewareArgs)

	ret0 := p.client.StartUnilateralExit(ctx)
	results := []interface{}{ret0}

	p.chain.After(ctx, "StartUnilateralExit", results, ret0)

	return ret0

}

func (p *ArkClientProxy) CompleteUnilateralExit(ctx context.Context, to string) (string, error) {

	middlewareArgs := []interface{}{ctx, to}
	ctx = p.chain.Before(ctx, "CompleteUnilateralExit", middlewareArgs)

	ret0, ret1 := p.client.CompleteUnilateralExit(ctx, to)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "CompleteUnilateralExit", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error) {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "OnboardAgainAllExpiredBoardings", middlewareArgs)

	ret0, ret1 := p.client.OnboardAgainAllExpiredBoardings(ctx)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "OnboardAgainAllExpiredBoardings", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) WithdrawFromAllExpiredBoardings(ctx context.Context, to string) (string, error) {

	middlewareArgs := []interface{}{ctx, to}
	ctx = p.chain.Before(ctx, "WithdrawFromAllExpiredBoardings", middlewareArgs)

	ret0, ret1 := p.client.WithdrawFromAllExpiredBoardings(ctx, to)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "WithdrawFromAllExpiredBoardings", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) ListVtxos(ctx context.Context) (spendable []client.Vtxo, spent []client.Vtxo, err error) {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "ListVtxos", middlewareArgs)

	// Assign to named return variables

	spendable, spent, err = p.client.ListVtxos(ctx)
	results := []interface{}{spendable, spent}

	p.chain.After(ctx, "ListVtxos", results, err)

	return

}

func (p *ArkClientProxy) Dump(ctx context.Context) (seed string, err error) {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "Dump", middlewareArgs)

	// Assign to named return variables

	seed, err = p.client.Dump(ctx)
	results := []interface{}{seed}

	p.chain.After(ctx, "Dump", results, err)

	return

}

func (p *ArkClientProxy) GetTransactionHistory(ctx context.Context) ([]types.Transaction, error) {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "GetTransactionHistory", middlewareArgs)

	ret0, ret1 := p.client.GetTransactionHistory(ctx)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "GetTransactionHistory", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) GetTransactionEventChannel(ctx context.Context) chan types.TransactionEvent {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "GetTransactionEventChannel", middlewareArgs)

	ret0 := p.client.GetTransactionEventChannel(ctx)
	results := []interface{}{ret0}

	p.chain.After(ctx, "GetTransactionEventChannel", results, nil)

	return ret0

}

func (p *ArkClientProxy) GetVtxoEventChannel(ctx context.Context) chan types.VtxoEvent {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "GetVtxoEventChannel", middlewareArgs)

	ret0 := p.client.GetVtxoEventChannel(ctx)
	results := []interface{}{ret0}

	p.chain.After(ctx, "GetVtxoEventChannel", results, nil)

	return ret0

}

func (p *ArkClientProxy) RedeemNotes(ctx context.Context, notes []string, opts ...arksdk.Option) (string, error) {

	middlewareArgs := []interface{}{ctx, notes, opts}
	ctx = p.chain.Before(ctx, "RedeemNotes", middlewareArgs)

	ret0, ret1 := p.client.RedeemNotes(ctx, notes, opts...)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "RedeemNotes", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) SetNostrNotificationRecipient(ctx context.Context, nostrRecipient string) error {

	middlewareArgs := []interface{}{ctx, nostrRecipient}
	ctx = p.chain.Before(ctx, "SetNostrNotificationRecipient", middlewareArgs)

	ret0 := p.client.SetNostrNotificationRecipient(ctx, nostrRecipient)
	results := []interface{}{ret0}

	p.chain.After(ctx, "SetNostrNotificationRecipient", results, ret0)

	return ret0

}

func (p *ArkClientProxy) SignTransaction(ctx context.Context, tx string) (string, error) {

	middlewareArgs := []interface{}{ctx, tx}
	ctx = p.chain.Before(ctx, "SignTransaction", middlewareArgs)

	ret0, ret1 := p.client.SignTransaction(ctx, tx)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "SignTransaction", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) NotifyIncomingFunds(ctx context.Context, address string) ([]types.Vtxo, error) {

	middlewareArgs := []interface{}{ctx, address}
	ctx = p.chain.Before(ctx, "NotifyIncomingFunds", middlewareArgs)

	ret0, ret1 := p.client.NotifyIncomingFunds(ctx, address)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "NotifyIncomingFunds", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) Reset(ctx context.Context) {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "Reset", middlewareArgs)

	p.client.Reset(ctx)

	p.chain.After(ctx, "Reset", nil, nil)

}

func (p *ArkClientProxy) Stop() error {

	p.chain.Before(nil, "Stop", nil)

	ret0 := p.client.Stop()
	results := []interface{}{ret0}

	p.chain.After(nil, "Stop", results, ret0)

	return ret0

}
