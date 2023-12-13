package txbuilder

import (
	"context"
	"encoding/hex"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

const (
	connectorAmount = 450
)

type txBuilder struct {
	net *network.Network
}

func NewTxBuilder(net *network.Network) ports.TxBuilder {
	return &txBuilder{
		net,
	}
}

func p2wpkhScript(publicKey *secp256k1.PublicKey, net *network.Network) ([]byte, error) {
	payment := payment.FromPublicKey(publicKey, net, nil)
	addr, err := payment.WitnessPubKeyHash()
	if err != nil {
		return nil, err
	}

	return address.ToOutputScript(addr)
}

// BuildForfeitTxs implements ports.TxBuilder.
func (b *txBuilder) BuildForfeitTxs(
	aspPubkey *secp256k1.PublicKey,
	poolTx string,
	payments []domain.Payment,
) (connectors []string, forfeitTxs []string, err error) {
	poolTxID, err := getTxID(poolTx)
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
	aspPubkey *secp256k1.PublicKey,
	wallet ports.WalletService,
	payments []domain.Payment,
) (poolTx string, congestionTree domain.CongestionTree, err error) {
	aspScriptBytes, err := p2wpkhScript(aspPubkey, b.net)
	if err != nil {
		return "", nil, err
	}

	aspScript := hex.EncodeToString(aspScriptBytes)

	receivers := receiversFromPayments(payments)
	sharedOutputAmount := sumReceivers(receivers)

	numberOfConnectors := numberOfVTXOs(payments)
	connectorOutputAmount := connectorAmount * numberOfConnectors

	ctx := context.Background()

	makeTree, sharedOutputScript, err := buildCongestionTree(
		b.net,
		aspPubkey,
		receivers,
	)
	if err != nil {
		return "", nil, err
	}

	sharedOutputScriptHex := hex.EncodeToString(sharedOutputScript)

	poolTx, err = wallet.Transfer(ctx, []ports.TxOutput{
		newOutput(sharedOutputScriptHex, sharedOutputAmount, b.net.AssetID),
		newOutput(aspScript, connectorOutputAmount, b.net.AssetID),
	})
	if err != nil {
		return "", nil, err
	}

	poolTransaction, err := transaction.NewTxFromHex(poolTx)
	if err != nil {
		return "", nil, err
	}

	congestionTree, err = makeTree(psetv2.InputArgs{
		Txid:    poolTransaction.TxHash().String(),
		TxIndex: 0,
	})
	if err != nil {
		return "", nil, err
	}

	return poolTx, congestionTree, nil
}

func connectorsToInputArgs(connectors []string) ([]psetv2.InputArgs, error) {
	inputs := make([]psetv2.InputArgs, 0, len(connectors)+1)
	for i, psetb64 := range connectors {
		txID, err := getTxID(psetb64)
		if err != nil {
			return nil, err
		}

		input := psetv2.InputArgs{
			Txid:    txID,
			TxIndex: 0,
		}
		inputs = append(inputs, input)

		if i == len(connectors)-1 {
			input := psetv2.InputArgs{
				Txid:    txID,
				TxIndex: 1,
			}
			inputs = append(inputs, input)
		}
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

func (o *output) GetAsset() string {
	return o.asset
}

func (o *output) GetAmount() uint64 {
	return o.amount
}

func (o *output) GetScript() string {
	return o.script
}
