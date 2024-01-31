package ports

import (
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/psetv2"
)

type SweepInput struct {
	InputArgs psetv2.InputArgs
	SweepLeaf psetv2.TapLeafScript
	Amount    uint64
}

type TxBuilder interface {
	BuildPoolTx(
		aspPubkey *secp256k1.PublicKey, wallet WalletService, payments []domain.Payment, minRelayFee uint64,
	) (poolTx string, congestionTree tree.CongestionTree, err error)
	BuildForfeitTxs(
		aspPubkey *secp256k1.PublicKey, poolTx string, payments []domain.Payment,
	) (connectors []string, forfeitTxs []string, err error)
	GetLeafOutputScript(userPubkey, aspPubkey *secp256k1.PublicKey) ([]byte, error)
	BuildSweepTx(
		wallet WalletService,
		inputs []SweepInput,
	) (signedSweepTx string, err error)
}
