package application

import (
	"sync"

	"github.com/ark-network/ark/common/tree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// musigSigningSession holds the state of ephemeral nonces and signatures in order to coordinate the signing of the tree
type musigSigningSession struct {
	lock        sync.Mutex
	nbCosigners int
	cosigners   map[string]struct{}
	nonces      map[*secp256k1.PublicKey]tree.TreeNonces
	nonceDoneC  chan struct{}

	signatures map[*secp256k1.PublicKey]tree.TreePartialSigs
	sigDoneC   chan struct{}
}

func newMusigSigningSession(cosigners map[string]struct{}) *musigSigningSession {
	return &musigSigningSession{
		nonces:     make(map[*secp256k1.PublicKey]tree.TreeNonces),
		nonceDoneC: make(chan struct{}),

		signatures:  make(map[*secp256k1.PublicKey]tree.TreePartialSigs),
		sigDoneC:    make(chan struct{}),
		lock:        sync.Mutex{},
		cosigners:   cosigners,
		nbCosigners: len(cosigners), // include the server
	}
}
