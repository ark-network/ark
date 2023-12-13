package txbuilder

import (
	"context"
	"encoding/hex"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

const (
	connectorAmount = 450
)

type txBuilder struct {
	net network.Network
}

func NewTxBuilder(net network.Network) ports.TxBuilder {
	return &txBuilder{net}
}

// BuildCongestionTree implements ports.TxBuilder.
func (b *txBuilder) BuildCongestionTree(
	aspPubkey *secp256k1.PublicKey, poolTx string, payments []domain.Payment,
) (congestionTree domain.CongestionTree, err error) {
	poolTxID, err := getTxid(poolTx)
	if err != nil {
		return nil, err
	}

	receivers := receiversFromPayments(payments)

	return buildCongestionTree(
		newOutputScriptFactory(aspPubkey, b.net),
		b.net,
		poolTxID,
		receivers,
	)
}

// BuildForfeitTxs implements ports.TxBuilder.
func (b *txBuilder) BuildForfeitTxs(
	aspPubkey *secp256k1.PublicKey, poolTx string, payments []domain.Payment,
) (connectors []string, forfeitTxs []string, err error) {
	poolTxID, err := getTxid(poolTx)
	if err != nil {
		return nil, nil, err
	}

	aspScript, err := p2wpkhScript(aspPubkey, b.net)
	if err != nil {
		return nil, nil, err
	}

	numberOfConnectors := numberOfVTXOs(payments)

	connectors, err = createConnectors(
		poolTxID,
		1,
		psetv2.OutputArgs{
			Asset:  b.net.AssetID,
			Amount: connectorAmount,
			Script: aspScript,
		},
		aspScript,
		numberOfConnectors,
	)
	if err != nil {
		return nil, nil, err
	}

	connectorsAsInputs, err := connectorsToInputArgs(connectors)
	if err != nil {
		return nil, nil, err
	}

	forfeitTxs = make([]string, 0)
	for _, payment := range payments {
		for _, vtxo := range payment.Inputs {
			for _, connector := range connectorsAsInputs {
				forfeitTx, err := createForfeitTx(
					connector,
					psetv2.InputArgs{
						Txid:    vtxo.Txid,
						TxIndex: vtxo.VOut,
					},
					vtxo.Amount,
					aspScript,
					b.net,
				)
				if err != nil {
					return nil, nil, err
				}

				forfeitTxs = append(forfeitTxs, forfeitTx)
			}
		}
	}

	return connectors, forfeitTxs, nil
}

// BuildPoolTx implements ports.TxBuilder.
func (b *txBuilder) BuildPoolTx(
	aspPubkey *secp256k1.PublicKey, wallet ports.WalletService, payments []domain.Payment,
) (poolTx string, err error) {
	aspScriptBytes, err := p2wpkhScript(aspPubkey, b.net)
	if err != nil {
		return "", err
	}

	aspScript := hex.EncodeToString(aspScriptBytes)

	receivers := receiversFromPayments(payments)
	sharedOutputAmount := sumReceivers(receivers)

	numberOfConnectors := numberOfVTXOs(payments)
	connectorOutputAmount := connectorAmount * numberOfConnectors

	ctx := context.Background()

	return wallet.Transfer(ctx, []ports.TxOutput{
		newOutput(aspScript, sharedOutputAmount, b.net.AssetID),
		newOutput(aspScript, connectorOutputAmount, b.net.AssetID),
	})
}

func connectorsToInputArgs(connectors []string) ([]psetv2.InputArgs, error) {
	inputs := make([]psetv2.InputArgs, 0, len(connectors)+1)
	for i, psetb64 := range connectors {
		tx, err := psetv2.NewPsetFromBase64(psetb64)
		if err != nil {
			return nil, err
		}
		utx, err := tx.UnsignedTx()
		if err != nil {
			return nil, err
		}
		txid := utx.TxHash().String()
		for j := range tx.Outputs {
			inputs = append(inputs, psetv2.InputArgs{
				Txid:    txid,
				TxIndex: uint32(j),
			})
			if i != len(connectors)-1 {
				break
			}
		}
	}
	return inputs, nil
}

func getTxid(txStr string) (string, error) {
	pset, err := psetv2.NewPsetFromBase64(txStr)
	if err != nil {
		tx, err := transaction.NewTxFromHex(txStr)
		if err != nil {
			return "", err
		}
		return tx.TxHash().String(), nil
	}

	utx, err := pset.UnsignedTx()
	if err != nil {
		return "", err
	}

	return utx.TxHash().String(), nil
}

func numberOfVTXOs(payments []domain.Payment) uint64 {
	var sum uint64
	for _, payment := range payments {
		sum += uint64(len(payment.Inputs))
	}
	return sum
}

func receiversFromPayments(payments []domain.Payment) []domain.Receiver {
	receivers := make([]domain.Receiver, 0)
	for _, payment := range payments {
		receivers = append(receivers, payment.Receivers...)
	}
	return receivers
}

func sumReceivers(receivers []domain.Receiver) uint64 {
	var sum uint64
	for _, r := range receivers {
		sum += r.Amount
	}
	return sum
}

type output struct {
	script string
	amount uint64
	asset  string
}

func newOutput(script string, amount uint64, asset string) ports.TxOutput {
	return &output{
		script: script,
		amount: amount,
		asset:  asset,
	}
}

func (o *output) GetAmount() uint64 {
	return o.amount
}

func (o *output) GetAsset() string {
	return o.asset
}

func (o *output) GetScript() string {
	return o.script
}
