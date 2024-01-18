package ports

import (
	"github.com/ark-network/ark/common/pkg/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type TxBuilder interface {
	BuildPoolTx(
		aspPubkey *secp256k1.PublicKey, wallet WalletService, payments []domain.Payment, minRelayFee uint64,
	) (poolTx string, congestionTree tree.CongestionTree, err error)
	BuildForfeitTxs(
		aspPubkey *secp256k1.PublicKey, poolTx string, payments []domain.Payment,
	) (connectors []string, forfeitTxs []string, err error)
	GetLeafOutputScript(userPubkey, aspPubkey *secp256k1.PublicKey) ([]byte, error)
}
