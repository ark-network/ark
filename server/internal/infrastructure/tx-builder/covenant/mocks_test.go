package txbuilder_test

import (
	"context"

	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/mock"
)

type mockedWallet struct {
	mock.Mock
}

func (m *mockedWallet) GenSeed(ctx context.Context) (string, error) {
	args := m.Called(ctx)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) Create(ctx context.Context, seed, password string) error {
	args := m.Called(ctx, seed, password)
	return args.Error(0)
}

func (m *mockedWallet) Restore(ctx context.Context, seed, password string) error {
	args := m.Called(ctx, seed, password)
	return args.Error(0)
}

func (m *mockedWallet) Unlock(ctx context.Context, password string) error {
	args := m.Called(ctx, password)
	return args.Error(0)
}

func (m *mockedWallet) Lock(ctx context.Context, password string) error {
	args := m.Called(ctx, password)
	return args.Error(0)
}

func (m *mockedWallet) BroadcastTransaction(ctx context.Context, txHex string) (string, error) {
	args := m.Called(ctx, txHex)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) Close() {
	m.Called()
}

func (m *mockedWallet) DeriveAddresses(ctx context.Context, num int) ([]string, error) {
	args := m.Called(ctx, num)

	var res []string
	if a := args.Get(0); a != nil {
		res = a.([]string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) DeriveConnectorAddress(ctx context.Context) (string, error) {
	args := m.Called(ctx)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error) {
	args := m.Called(ctx)

	var res *secp256k1.PublicKey
	if a := args.Get(0); a != nil {
		res = a.(*secp256k1.PublicKey)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) SignTransaction(ctx context.Context, pset string, extractRawTx bool) (string, error) {
	args := m.Called(ctx, pset, extractRawTx)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) Status(ctx context.Context) (ports.WalletStatus, error) {
	args := m.Called(ctx)

	var res ports.WalletStatus
	if a := args.Get(0); a != nil {
		res = a.(ports.WalletStatus)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) SelectUtxos(ctx context.Context, asset string, amount uint64) ([]ports.TxInput, uint64, error) {
	args := m.Called(ctx, asset, amount)

	var res0 func() []ports.TxInput
	if a := args.Get(0); a != nil {
		res0 = a.(func() []ports.TxInput)
	}
	var res1 uint64
	if a := args.Get(1); a != nil {
		res1 = a.(uint64)
	}
	return res0(), res1, args.Error(2)
}

func (m *mockedWallet) EstimateFees(ctx context.Context, pset string) (uint64, error) {
	args := m.Called(ctx, pset)

	var res uint64
	if a := args.Get(0); a != nil {
		res = a.(uint64)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) MinRelayFee(ctx context.Context, vbytes uint64) (uint64, error) {
	args := m.Called(ctx, vbytes)

	var res uint64
	if a := args.Get(0); a != nil {
		res = a.(uint64)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) GetDustAmount(ctx context.Context) (uint64, error) {
	args := m.Called(ctx)

	var res uint64
	if a := args.Get(0); a != nil {
		res = a.(uint64)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) IsTransactionConfirmed(ctx context.Context, txid string) (bool, int64, int64, error) {
	args := m.Called(ctx, txid)

	var res bool
	if a := args.Get(0); a != nil {
		res = a.(bool)
	}

	var height int64
	if h := args.Get(1); h != nil {
		height = h.(int64)
	}

	var blocktime int64
	if b := args.Get(1); b != nil {
		blocktime = b.(int64)
	}

	return res, height, blocktime, args.Error(2)
}

func (m *mockedWallet) SignTransactionTapscript(ctx context.Context, pset string, inputIndexes []int) (string, error) {
	args := m.Called(ctx, pset, inputIndexes)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) WatchScripts(
	ctx context.Context, scripts []string,
) error {
	args := m.Called(ctx, scripts)
	return args.Error(0)
}

func (m *mockedWallet) UnwatchScripts(
	ctx context.Context, scripts []string,
) error {
	args := m.Called(ctx, scripts)
	return args.Error(0)
}

func (m *mockedWallet) GetNotificationChannel(ctx context.Context) <-chan map[string][]ports.VtxoWithValue {
	args := m.Called(ctx)

	var res <-chan map[string][]ports.VtxoWithValue
	if a := args.Get(0); a != nil {
		res = a.(<-chan map[string][]ports.VtxoWithValue)
	}
	return res
}

func (m *mockedWallet) ListConnectorUtxos(ctx context.Context, addr string) ([]ports.TxInput, error) {
	args := m.Called(ctx, addr)

	var res []ports.TxInput
	if a := args.Get(0); a != nil {
		res = a.([]ports.TxInput)
	}

	return res, args.Error(1)
}

func (m *mockedWallet) LockConnectorUtxos(ctx context.Context, utxos []ports.TxOutpoint) error {
	args := m.Called(ctx, utxos)
	return args.Error(0)
}

func (m *mockedWallet) WaitForSync(ctx context.Context, txid string) error {
	args := m.Called(ctx, txid)
	return args.Error(0)
}

func (m *mockedWallet) ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error) {
	args := m.Called(ctx)

	var res uint64
	if a := args.Get(0); a != nil {
		res = a.(uint64)
	}
	var res2 uint64
	if a := args.Get(1); a != nil {
		res2 = a.(uint64)
	}
	return res, res2, args.Error(2)
}

func (m *mockedWallet) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	args := m.Called(ctx)

	var res uint64
	if a := args.Get(0); a != nil {
		res = a.(uint64)
	}
	var res2 uint64
	if a := args.Get(1); a != nil {
		res2 = a.(uint64)
	}
	return res, res2, args.Error(2)
}

func (m *mockedWallet) GetTransaction(ctx context.Context, txid string) (string, error) {
	args := m.Called(ctx, txid)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) MinRelayFeeRate(ctx context.Context) chainfee.SatPerKVByte {
	args := m.Called(ctx)

	var res chainfee.SatPerKVByte
	if a := args.Get(0); a != nil {
		res = a.(chainfee.SatPerKVByte)
	}
	return res
}

func (m *mockedWallet) GetForfeitAddress(ctx context.Context) (string, error) {
	args := m.Called(ctx)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

type mockedInput struct {
	mock.Mock
}

func (m *mockedInput) GetTxid() string {
	args := m.Called()

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}

	return res
}

func (m *mockedInput) GetIndex() uint32 {
	args := m.Called()

	var res uint32
	if a := args.Get(0); a != nil {
		res = a.(uint32)
	}
	return res
}

func (m *mockedInput) GetScript() string {
	args := m.Called()

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res
}

func (m *mockedInput) GetAsset() string {
	args := m.Called()

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res
}

func (m *mockedInput) GetValue() uint64 {
	args := m.Called()

	var res uint64
	if a := args.Get(0); a != nil {
		res = a.(uint64)
	}
	return res
}
