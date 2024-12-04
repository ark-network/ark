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

func (p *ArkClientProxy) Lock(ctx context.Context, password string) error {

	middlewareArgs := []interface{}{ctx, password}
	ctx = p.chain.Before(ctx, "Lock", middlewareArgs)

	ret0 := p.client.Lock(ctx, password)
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

func (p *ArkClientProxy) SendOnChain(ctx context.Context, receivers []arksdk.Receiver) (string, error) {

	middlewareArgs := []interface{}{ctx, receivers}
	ctx = p.chain.Before(ctx, "SendOnChain", middlewareArgs)

	ret0, ret1 := p.client.SendOnChain(ctx, receivers)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "SendOnChain", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) SendOffChain(ctx context.Context, withExpiryCoinselect bool, receivers []arksdk.Receiver) (string, error) {

	middlewareArgs := []interface{}{ctx, withExpiryCoinselect, receivers}
	ctx = p.chain.Before(ctx, "SendOffChain", middlewareArgs)

	ret0, ret1 := p.client.SendOffChain(ctx, withExpiryCoinselect, receivers)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "SendOffChain", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) UnilateralRedeem(ctx context.Context) error {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "UnilateralRedeem", middlewareArgs)

	ret0 := p.client.UnilateralRedeem(ctx)
	results := []interface{}{ret0}

	p.chain.After(ctx, "UnilateralRedeem", results, ret0)

	return ret0

}

func (p *ArkClientProxy) CollaborativeRedeem(ctx context.Context, addr string, amount uint64, withExpiryCoinselect bool) (string, error) {

	middlewareArgs := []interface{}{ctx, addr, amount, withExpiryCoinselect}
	ctx = p.chain.Before(ctx, "CollaborativeRedeem", middlewareArgs)

	ret0, ret1 := p.client.CollaborativeRedeem(ctx, addr, amount, withExpiryCoinselect)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "CollaborativeRedeem", results, ret1)

	return ret0, ret1

}

func (p *ArkClientProxy) Settle(ctx context.Context) (string, error) {

	middlewareArgs := []interface{}{ctx}
	ctx = p.chain.Before(ctx, "Settle", middlewareArgs)

	ret0, ret1 := p.client.Settle(ctx)
	results := []interface{}{ret0, ret1}

	p.chain.After(ctx, "Settle", results, ret1)

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

func (p *ArkClientProxy) GetTransactionEventChannel() chan types.TransactionEvent {

	p.chain.Before(nil, "GetTransactionEventChannel", nil)

	ret0 := p.client.GetTransactionEventChannel()
	results := []interface{}{ret0}

	p.chain.After(nil, "GetTransactionEventChannel", results, nil)

	return ret0

}

func (p *ArkClientProxy) RedeemNotes(ctx context.Context, notes []string) (string, error) {

	middlewareArgs := []interface{}{ctx, notes}
	ctx = p.chain.Before(ctx, "RedeemNotes", middlewareArgs)

	ret0, ret1 := p.client.RedeemNotes(ctx, notes)
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

func (p *ArkClientProxy) Stop() error {

	p.chain.Before(nil, "Stop", nil)

	ret0 := p.client.Stop()
	results := []interface{}{ret0}

	p.chain.After(nil, "Stop", results, ret0)

	return ret0

}
