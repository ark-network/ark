package txbuilder

import (
	"context"
	"encoding/hex"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
)

const (
	feeAmount       = 500
	connectorAmount = 450
)

type txBuilder struct {
	net          *network.Network
	aspPublicKey *secp256k1.PublicKey
}

func NewTxBuilder(aspPublicKey *secp256k1.PublicKey, net *network.Network) *txBuilder {
	return &txBuilder{
		net: net,
	}
}

// BuildCongestionTree implements ports.TxBuilder.
func (b *txBuilder) BuildCongestionTree(poolTx string, payments []domain.Payment) (congestionTree []string, err error) {
	poolTxID, err := getTxID(poolTx)
	if err != nil {
		return nil, err
	}

	receivers := receiversFromPayments(payments)

	return buildCongestionTree(
		centralizedOutputScriptFactory(b.aspPublicKey, b.net),
		b.net,
		poolTxID,
		receivers,
	)
}

// BuildForfeitTxs implements ports.TxBuilder.
func (b *txBuilder) BuildForfeitTxs(poolTx string, payments []domain.Payment) (connectors []string, forfeitTxs []string, err error) {
	poolTxID, err := getTxID(poolTx)
	if err != nil {
		return nil, nil, err
	}

	aspScript, err := p2wpkhScript(b.aspPublicKey, b.net)
	if err != nil {
		return nil, nil, err
	}

	receivers := receiversFromPayments(payments)
	numberOfConnectors := numberOfVTXOs(payments)

	connectors, err = createConnectors(
		poolTxID,
		1,
		psetv2.OutputArgs{
			Asset:  b.net.AssetID,
			Amount: connectorAmount,
			Script: aspScript,
		},
		feeAmount,
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

	for _, payment := range payments {
		for _, vtxo := range payment.Inputs {
			for _, connector := range connectorsAsInputs {
				forfeitTx, err := createForfeitTx(
					connector,
					psetv2.InputArgs{
						Txid:    vtxo.Txid,
						TxIndex: vtxo.Vout,
					},
				)
				if err != nil {
					return nil, nil, err
				}
			}
		}
	}

}

// BuildPoolTx implements ports.TxBuilder.
func (b *txBuilder) BuildPoolTx(wallet ports.WalletService, payments []domain.Payment) (poolTx string, err error) {
	aspScriptBytes, err := p2wpkhScript(b.aspPublicKey, b.net)
	if err != nil {
		return "", err
	}

	aspScript := hex.EncodeToString(aspScriptBytes)

	receivers := receiversFromPayments(payments)
	sharedOutputAmount := sumReceivers(receivers)

	numberOfConnectors := numberOfVTXOs(payments)
	connectorOutputAmount := (connectorAmount + feeAmount) * numberOfConnectors

	ctx := context.Background()

	return wallet.Transaction().Transfer(ctx, []ports.TxOutput{
		newOutput(aspScript, sharedOutputAmount),
		newOutput(aspScript, connectorOutputAmount),
	})
}

func connectorsToInputArgs(connectors []string) ([]psetv2.InputArgs, error) {
	inputs := make([]psetv2.InputArgs, len(connectors), len(connectors))
	for i, psetb64 := range connectors {
		txID, err := getTxID(psetb64)
		if err != nil {
			return nil, err
		}

		input := psetv2.InputArgs{
			Txid:    txID,
			TxIndex: 0,
		}

		inputs[i] = input
	}
	return inputs, nil
}

func getTxID(psetBase64 string) (string, error) {
	pset, err := psetv2.NewPsetFromBase64(psetBase64)
	if err != nil {
		return "", err
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

var _ ports.TxBuilder = (*txBuilder)(nil)

type output struct {
	script string
	amount uint64
}

func newOutput(script string, amount uint64) ports.TxOutput {
	return &output{
		script: script,
		amount: amount,
	}
}

func (o *output) GetAmount() uint64 {
	return o.amount
}

func (o *output) GetScript() string {
	return o.script
}
