package walletclient

import (
	"context"
	"fmt"
	"github.com/ark-network/ark/server/internal/core/domain"
	log "github.com/sirupsen/logrus"

	"github.com/ark-network/ark/server/internal/core/ports"
	walletv1 "github.com/ark-network/ark/server/pkg/ark-wallet-daemon/api-spec/protobuf/gen/wallet/v1"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type walletDaemonClient struct {
	client walletv1.WalletServiceClient
	conn   *grpc.ClientConn
}

// New creates a ports.WalletService backed by a gRPC client.
func New(ctx context.Context, addr string) (ports.WalletService, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to dial btc-wallet grpc server: %w", err)
	}
	client := walletv1.NewWalletServiceClient(conn)
	return &walletDaemonClient{client: client, conn: conn}, nil
}

func (w *walletDaemonClient) GenSeed(ctx context.Context) (string, error) {
	resp, err := w.client.GenSeed(ctx, &walletv1.GenSeedRequest{})
	if err != nil {
		return "", err
	}
	return resp.Seed, nil
}

func (w *walletDaemonClient) Create(ctx context.Context, seed, password string) error {
	_, err := w.client.Create(ctx, &walletv1.CreateRequest{Seed: seed, Password: password})
	return err
}

func (w *walletDaemonClient) Restore(ctx context.Context, seed, password string) error {
	_, err := w.client.Restore(ctx, &walletv1.RestoreRequest{Seed: seed, Password: password})
	return err
}

func (w *walletDaemonClient) Unlock(ctx context.Context, password string) error {
	_, err := w.client.Unlock(ctx, &walletv1.UnlockRequest{Password: password})
	return err
}

func (w *walletDaemonClient) Lock(ctx context.Context, password string) error {
	_, err := w.client.Lock(ctx, &walletv1.LockRequest{Password: password})
	return err
}

func (w *walletDaemonClient) Status(ctx context.Context) (ports.WalletStatus, error) {
	resp, err := w.client.Status(ctx, &walletv1.StatusRequest{})
	if err != nil {
		return nil, err
	}
	return &walletStatus{resp}, nil
}

func (w *walletDaemonClient) GetTransaction(ctx context.Context, txid string) (string, error) {
	resp, err := w.client.GetTransaction(ctx, &walletv1.GetTransactionRequest{Txid: txid})
	if err != nil {
		return "", err
	}
	return resp.GetTxHex(), nil
}

func (w *walletDaemonClient) WatchScripts(ctx context.Context, scripts []string) error {
	_, err := w.client.WatchScripts(ctx, &walletv1.WatchScriptsRequest{Scripts: scripts})
	return err
}

func (w *walletDaemonClient) UnwatchScripts(ctx context.Context, scripts []string) error {
	_, err := w.client.UnwatchScripts(ctx, &walletv1.UnwatchScriptsRequest{Scripts: scripts})
	return err
}

func (w *walletDaemonClient) SignMessage(ctx context.Context, message []byte) ([]byte, error) {
	resp, err := w.client.SignMessage(ctx, &walletv1.SignMessageRequest{Message: message})
	if err != nil {
		return nil, err
	}
	return resp.GetSignature(), nil
}

func (w *walletDaemonClient) GetNotificationChannel(ctx context.Context) <-chan map[string][]ports.VtxoWithValue {
	ch := make(chan map[string][]ports.VtxoWithValue)
	stream, err := w.client.NotificationStream(ctx, &walletv1.NotificationStreamRequest{})
	if err != nil {
		close(ch)
		return ch
	}
	go func() {
		defer close(ch)
		for {
			resp, err := stream.Recv()
			if err != nil {
				log.Errorf("GetNotificationChannel: failed to receive notification: %v", err)
				return
			}
			m := make(map[string][]ports.VtxoWithValue)
			for _, entry := range resp.Entries {
				vtxos := make([]ports.VtxoWithValue, 0, len(entry.Vtxos))
				for _, v := range entry.Vtxos {
					vtxos = append(vtxos, ports.VtxoWithValue{
						VtxoKey: domain.VtxoKey{
							Txid: v.Txid,
							VOut: v.Vout,
						},
						Value: v.Value,
					})
				}
				m[entry.Script] = vtxos
			}
			ch <- m
		}
	}()
	return ch
}

func (w *walletDaemonClient) IsTransactionConfirmed(ctx context.Context, txid string) (bool, int64, int64, error) {
	resp, err := w.client.IsTransactionConfirmed(ctx, &walletv1.IsTransactionConfirmedRequest{Txid: txid})
	if err != nil {
		return false, 0, 0, err
	}
	return resp.Confirmed, resp.Blocknumber, resp.Blocktime, nil
}

func (w *walletDaemonClient) GetSyncedUpdate(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{})
	stream, err := w.client.GetSyncedUpdate(ctx, &walletv1.GetSyncedUpdateRequest{})
	if err != nil {
		close(ch)
		return ch
	}
	go func() {
		defer close(ch)
		for {
			_, err := stream.Recv()
			if err != nil {
				log.Errorf("GetSyncedUpdate: failed to receive notification: %v", err)
				return
			}

			return
		}
	}()
	return ch
}

func (w *walletDaemonClient) GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error) {
	resp, err := w.client.GetPubkey(ctx, &walletv1.GetPubkeyRequest{})
	if err != nil {
		return nil, err
	}
	pubkey, err := secp256k1.ParsePubKey(resp.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pubkey: %w", err)
	}
	return pubkey, nil
}

func (w *walletDaemonClient) GetForfeitAddress(ctx context.Context) (string, error) {
	resp, err := w.client.GetForfeitAddress(ctx, &walletv1.GetForfeitAddressRequest{})
	if err != nil {
		return "", err
	}
	return resp.GetAddress(), nil
}

func (w *walletDaemonClient) DeriveConnectorAddress(ctx context.Context) (string, error) {
	resp, err := w.client.DeriveConnectorAddress(ctx, &walletv1.DeriveConnectorAddressRequest{})
	if err != nil {
		return "", err
	}
	return resp.GetAddress(), nil
}

func (w *walletDaemonClient) DeriveAddresses(ctx context.Context, num int) ([]string, error) {
	resp, err := w.client.DeriveAddresses(ctx, &walletv1.DeriveAddressesRequest{Num: int32(num)})
	if err != nil {
		return nil, err
	}
	return resp.GetAddresses(), nil
}

func (w *walletDaemonClient) SignTransaction(ctx context.Context, partialTx string, extractRawTx bool) (string, error) {
	resp, err := w.client.SignTransaction(ctx, &walletv1.SignTransactionRequest{PartialTx: partialTx, ExtractRawTx: extractRawTx})
	if err != nil {
		return "", err
	}
	return resp.GetSignedTx(), nil
}

func (w *walletDaemonClient) SignTransactionTapscript(ctx context.Context, partialTx string, inputIndexes []int) (string, error) {
	indexes := make([]int32, len(inputIndexes))
	for i, v := range inputIndexes {
		indexes[i] = int32(v)
	}
	resp, err := w.client.SignTransactionTapscript(ctx, &walletv1.SignTransactionTapscriptRequest{PartialTx: partialTx, InputIndexes: indexes})
	if err != nil {
		return "", err
	}
	return resp.GetSignedTx(), nil
}

func (w *walletDaemonClient) SelectUtxos(ctx context.Context, asset string, amount uint64) ([]ports.TxInput, uint64, error) {
	resp, err := w.client.SelectUtxos(ctx, &walletv1.SelectUtxosRequest{
		Asset:  asset,
		Amount: amount,
	})
	if err != nil {
		return nil, 0, err
	}
	inputs := make([]ports.TxInput, len(resp.Utxos))
	for i, utxo := range resp.Utxos {
		inputs[i] = &txInput{
			txId:   utxo.GetTxid(),
			index:  utxo.GetIndex(),
			script: utxo.GetScript(),
			value:  utxo.GetValue(),
		}
	}
	return inputs, resp.GetTotalAmount(), nil
}

func (w *walletDaemonClient) BroadcastTransaction(ctx context.Context, txHex string) (string, error) {
	resp, err := w.client.BroadcastTransaction(ctx, &walletv1.BroadcastTransactionRequest{TxHex: txHex})
	if err != nil {
		return "", err
	}
	return resp.GetTxid(), nil
}

func (w *walletDaemonClient) WaitForSync(ctx context.Context, txid string) error {
	_, err := w.client.WaitForSync(ctx, &walletv1.WaitForSyncRequest{Txid: txid})
	return err
}

func (w *walletDaemonClient) EstimateFees(ctx context.Context, psbt string) (uint64, error) {
	resp, err := w.client.EstimateFees(ctx, &walletv1.EstimateFeesRequest{Psbt: psbt})
	if err != nil {
		return 0, err
	}
	return resp.GetFee(), nil
}

func (w *walletDaemonClient) MinRelayFee(ctx context.Context, vbytes uint64) (uint64, error) {
	resp, err := w.client.MinRelayFee(ctx, &walletv1.MinRelayFeeRequest{Vbytes: vbytes})
	if err != nil {
		return 0, err
	}
	return resp.GetFee(), nil
}

func (w *walletDaemonClient) MinRelayFeeRate(ctx context.Context) chainfee.SatPerKVByte {
	resp, err := w.client.MinRelayFeeRate(ctx, &walletv1.MinRelayFeeRateRequest{})
	if err != nil {
		//TODO should we update MinRelayFeeRate with returning error
		log.Errorf("failed to get min relay fee rate: %s", err)
		return 0
	}
	return chainfee.SatPerKVByte(resp.GetSatPerKvbyte())
}

func (w *walletDaemonClient) ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]ports.TxInput, error) {
	resp, err := w.client.ListConnectorUtxos(ctx, &walletv1.ListConnectorUtxosRequest{ConnectorAddress: connectorAddress})
	if err != nil {
		return nil, err
	}
	inputs := make([]ports.TxInput, len(resp.Utxos))
	for i, utxo := range resp.Utxos {
		inputs[i] = &txInput{
			txId:   utxo.GetTxid(),
			index:  utxo.GetIndex(),
			script: utxo.GetScript(),
			value:  utxo.GetValue(),
		}
	}
	return inputs, nil
}

func (w *walletDaemonClient) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	resp, err := w.client.MainAccountBalance(ctx, &walletv1.MainAccountBalanceRequest{})
	if err != nil {
		return 0, 0, err
	}
	return resp.GetConfirmed(), resp.GetUnconfirmed(), nil
}

func (w *walletDaemonClient) ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error) {
	resp, err := w.client.ConnectorsAccountBalance(ctx, &walletv1.ConnectorsAccountBalanceRequest{})
	if err != nil {
		return 0, 0, err
	}
	return resp.GetConfirmed(), resp.GetUnconfirmed(), nil
}

func (w *walletDaemonClient) LockConnectorUtxos(ctx context.Context, utxos []ports.TxOutpoint) error {
	protoUtxos := make([]*walletv1.TxOutpoint, len(utxos))
	for i, u := range utxos {
		protoUtxos[i] = &walletv1.TxOutpoint{
			Txid:  u.GetTxid(),
			Index: u.GetIndex(),
		}
	}
	_, err := w.client.LockConnectorUtxos(ctx, &walletv1.LockConnectorUtxosRequest{Utxos: protoUtxos})
	return err
}

func (w *walletDaemonClient) GetDustAmount(ctx context.Context) (uint64, error) {
	resp, err := w.client.GetDustAmount(ctx, &walletv1.GetDustAmountRequest{})
	if err != nil {
		return 0, err
	}
	return resp.GetDustAmount(), nil
}

func (w *walletDaemonClient) VerifyMessageSignature(ctx context.Context, message, signature []byte) (bool, error) {
	resp, err := w.client.VerifyMessageSignature(
		ctx,
		&walletv1.VerifyMessageSignatureRequest{Message: message, Signature: signature},
	)
	if err != nil {
		return false, err
	}
	return resp.GetValid(), nil
}

func (w *walletDaemonClient) GetCurrentBlockTime(ctx context.Context) (*ports.BlockTimestamp, error) {
	resp, err := w.client.GetCurrentBlockTime(ctx, &walletv1.GetCurrentBlockTimeRequest{})
	if err != nil {
		return nil, err
	}
	if resp.Timestamp == nil {
		return nil, fmt.Errorf("missing timestamp in response")
	}
	return &ports.BlockTimestamp{Height: resp.GetTimestamp().GetHeight(), Time: resp.GetTimestamp().GetTime()}, nil
}

func (w *walletDaemonClient) Withdraw(ctx context.Context, address string, amount uint64) (string, error) {
	resp, err := w.client.Withdraw(ctx, &walletv1.WithdrawRequest{Address: address, Amount: amount})
	if err != nil {
		return "", err
	}
	return resp.GetTxid(), nil
}
