package ports

import (
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type TxBuilder interface {
	BuildPoolTx(
		aspPubkey *secp256k1.PublicKey, wallet WalletService, payments []domain.Payment,
	) (poolTx string, congestionTree domain.CongestionTree, err error)
	BuildForfeitTxs(
		aspPubkey *secp256k1.PublicKey, poolTx string, payments []domain.Payment,
	) (connectors []string, forfeitTxs []string, err error)
	GetLeafOutputScript(userPubkey, aspPubkey *secp256k1.PublicKey) ([]byte, error)
	GetLifetime(tree domain.CongestionTree) (int64, error)
	BuildSweepTx(
		wallet WalletService,
		tree domain.CongestionTree,
	) (signedSweepTx string, err error)
}
