package application

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ark-network/ark/common/note"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

type timedPayment struct {
	domain.Payment
	boardingInputs []ports.BoardingInput
	notes          []note.Note
	timestamp      time.Time
	pingTimestamp  time.Time
}

type paymentsMap struct {
	lock          *sync.RWMutex
	payments      map[string]*timedPayment
	ephemeralKeys map[string]*secp256k1.PublicKey
}

func newPaymentsMap() *paymentsMap {
	paymentsById := make(map[string]*timedPayment)
	lock := &sync.RWMutex{}
	return &paymentsMap{lock, paymentsById, make(map[string]*secp256k1.PublicKey)}
}

func (m *paymentsMap) len() int64 {
	m.lock.RLock()
	defer m.lock.RUnlock()

	count := int64(0)
	for _, p := range m.payments {
		if len(p.Receivers) > 0 {
			count++
		}
	}
	return count
}

func (m *paymentsMap) delete(id string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.payments[id]; !ok {
		return errPaymentNotFound{id}
	}

	delete(m.payments, id)
	return nil
}

func (m *paymentsMap) pushWithNotes(payment domain.Payment, notes []note.Note) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.payments[payment.Id]; ok {
		return fmt.Errorf("duplicated payment %s", payment.Id)
	}

	for _, note := range notes {
		for _, payment := range m.payments {
			for _, pNote := range payment.notes {
				if note.ID == pNote.ID {
					return fmt.Errorf("duplicated note %s", note)
				}
			}
		}
	}

	m.payments[payment.Id] = &timedPayment{payment, make([]ports.BoardingInput, 0), notes, time.Now(), time.Time{}}
	return nil
}

func (m *paymentsMap) push(
	payment domain.Payment,
	boardingInputs []ports.BoardingInput,
) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.payments[payment.Id]; ok {
		return fmt.Errorf("duplicated payment %s", payment.Id)
	}

	for _, input := range payment.Inputs {
		for _, pay := range m.payments {
			for _, pInput := range pay.Inputs {
				if input.VtxoKey.Txid == pInput.VtxoKey.Txid && input.VtxoKey.VOut == pInput.VtxoKey.VOut {
					return fmt.Errorf("duplicated input, %s:%d already used by payment %s", input.VtxoKey.Txid, input.VtxoKey.VOut, pay.Id)
				}
			}
		}
	}

	for _, input := range boardingInputs {
		for _, pay := range m.payments {
			for _, pBoardingInput := range pay.boardingInputs {
				if input.Txid == pBoardingInput.Txid && input.VOut == pBoardingInput.VOut {
					return fmt.Errorf("duplicated boarding input, %s:%d already used by payment %s", input.Txid, input.VOut, pay.Id)
				}
			}
		}
	}

	m.payments[payment.Id] = &timedPayment{payment, boardingInputs, make([]note.Note, 0), time.Now(), time.Time{}}
	return nil
}

func (m *paymentsMap) pushEphemeralKey(paymentId string, pubkey *secp256k1.PublicKey) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.payments[paymentId]; !ok {
		return fmt.Errorf("payment %s not found, cannot register signing ephemeral public key", paymentId)
	}

	m.ephemeralKeys[paymentId] = pubkey
	return nil
}

func (m *paymentsMap) pop(num int64) ([]domain.Payment, []ports.BoardingInput, []*secp256k1.PublicKey, []note.Note) {
	m.lock.Lock()
	defer m.lock.Unlock()

	paymentsByTime := make([]timedPayment, 0, len(m.payments))
	for _, p := range m.payments {
		// Skip payments without registered receivers.
		if len(p.Receivers) <= 0 {
			continue
		}
		// Skip payments for which users didn't notify to be online in the last minute.
		if p.pingTimestamp.IsZero() || time.Since(p.pingTimestamp).Minutes() > 1 {
			continue
		}
		paymentsByTime = append(paymentsByTime, *p)
	}
	sort.SliceStable(paymentsByTime, func(i, j int) bool {
		return paymentsByTime[i].timestamp.Before(paymentsByTime[j].timestamp)
	})

	if num < 0 || num > int64(len(paymentsByTime)) {
		num = int64(len(paymentsByTime))
	}

	payments := make([]domain.Payment, 0, num)
	boardingInputs := make([]ports.BoardingInput, 0)
	cosigners := make([]*secp256k1.PublicKey, 0, num)
	notes := make([]note.Note, 0)
	for _, p := range paymentsByTime[:num] {
		boardingInputs = append(boardingInputs, p.boardingInputs...)
		payments = append(payments, p.Payment)
		if pubkey, ok := m.ephemeralKeys[p.Payment.Id]; ok {
			cosigners = append(cosigners, pubkey)
			delete(m.ephemeralKeys, p.Payment.Id)
		}
		notes = append(notes, p.notes...)
		delete(m.payments, p.Id)
	}
	return payments, boardingInputs, cosigners, notes
}

func (m *paymentsMap) update(payment domain.Payment) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	p, ok := m.payments[payment.Id]
	if !ok {
		return fmt.Errorf("payment %s not found", payment.Id)
	}

	// sum inputs = vtxos + boarding utxos + notes
	sumOfInputs := uint64(0)
	for _, input := range payment.Inputs {
		sumOfInputs += input.Amount
	}

	for _, boardingInput := range p.boardingInputs {
		sumOfInputs += boardingInput.Amount
	}

	for _, note := range p.notes {
		sumOfInputs += uint64(note.Value)
	}

	// sum outputs = receivers VTXOs
	sumOfOutputs := uint64(0)
	for _, receiver := range payment.Receivers {
		sumOfOutputs += receiver.Amount
	}

	if sumOfInputs != sumOfOutputs {
		return fmt.Errorf("sum of inputs %d does not match sum of outputs %d", sumOfInputs, sumOfOutputs)
	}

	p.Payment = payment

	return nil
}

func (m *paymentsMap) updatePingTimestamp(id string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	payment, ok := m.payments[id]
	if !ok {
		return errPaymentNotFound{id}
	}

	payment.pingTimestamp = time.Now()
	return nil
}

func (m *paymentsMap) view(id string) (*domain.Payment, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	payment, ok := m.payments[id]
	if !ok {
		return nil, false
	}

	return &domain.Payment{
		Id:        payment.Id,
		Inputs:    payment.Inputs,
		Receivers: payment.Receivers,
	}, true
}

type forfeitTxsMap struct {
	lock    *sync.RWMutex
	builder ports.TxBuilder

	forfeitTxs map[domain.VtxoKey][]string
	connectors []string
	vtxos      []domain.Vtxo
}

func newForfeitTxsMap(txBuilder ports.TxBuilder) *forfeitTxsMap {
	return &forfeitTxsMap{&sync.RWMutex{}, txBuilder, make(map[domain.VtxoKey][]string), nil, nil}
}

func (m *forfeitTxsMap) init(connectors []string, payments []domain.Payment) {
	vtxosToSign := make([]domain.Vtxo, 0)
	for _, payment := range payments {
		vtxosToSign = append(vtxosToSign, payment.Inputs...)
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	m.vtxos = vtxosToSign
	m.connectors = connectors
	for _, vtxo := range vtxosToSign {
		m.forfeitTxs[vtxo.VtxoKey] = make([]string, 0)
	}
}

func (m *forfeitTxsMap) sign(txs []string) error {
	if len(txs) == 0 {
		return nil
	}

	if len(m.vtxos) == 0 || len(m.connectors) == 0 {
		return fmt.Errorf("forfeit txs map not initialized")
	}

	// verify the txs are valid
	validTxs, err := m.builder.VerifyForfeitTxs(m.vtxos, m.connectors, txs)
	if err != nil {
		return err
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	for vtxoKey, txs := range validTxs {
		m.forfeitTxs[vtxoKey] = txs
	}

	return nil
}

func (m *forfeitTxsMap) reset() {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.forfeitTxs = make(map[domain.VtxoKey][]string)
	m.connectors = nil
}

func (m *forfeitTxsMap) pop() ([]string, error) {
	m.lock.Lock()
	defer func() {
		m.lock.Unlock()
		m.reset()
	}()

	txs := make([]string, 0)
	for vtxoKey, signed := range m.forfeitTxs {
		if len(signed) == 0 {
			return nil, fmt.Errorf("missing forfeit txs for vtxo %s", vtxoKey)
		}
		txs = append(txs, signed...)
	}

	return txs, nil
}

// onchainOutputs iterates over all the nodes' outputs in the congestion tree and checks their onchain state
// returns the sweepable outputs as ports.SweepInput mapped by their expiration time
func findSweepableOutputs(
	ctx context.Context,
	walletSvc ports.WalletService,
	txbuilder ports.TxBuilder,
	schedulerUnit ports.TimeUnit,
	congestionTree tree.CongestionTree,
) (map[int64][]ports.SweepInput, error) {
	sweepableOutputs := make(map[int64][]ports.SweepInput)
	blocktimeCache := make(map[string]int64) // txid -> blocktime / blockheight
	nodesToCheck := congestionTree[0]        // init with the root

	for len(nodesToCheck) > 0 {
		newNodesToCheck := make([]tree.Node, 0)

		for _, node := range nodesToCheck {
			isConfirmed, height, blocktime, err := walletSvc.IsTransactionConfirmed(ctx, node.Txid)
			if err != nil {
				return nil, err
			}

			var expirationTime int64
			var sweepInput ports.SweepInput

			if !isConfirmed {
				if _, ok := blocktimeCache[node.ParentTxid]; !ok {
					isConfirmed, height, blocktime, err := walletSvc.IsTransactionConfirmed(ctx, node.ParentTxid)
					if !isConfirmed || err != nil {
						return nil, fmt.Errorf("tx %s not found", node.ParentTxid)
					}

					if schedulerUnit == ports.BlockHeight {
						blocktimeCache[node.ParentTxid] = height
					} else {
						blocktimeCache[node.ParentTxid] = blocktime
					}
				}

				var lifetime int64
				lifetime, sweepInput, err = txbuilder.GetSweepInput(node)
				if err != nil {
					return nil, err
				}
				expirationTime = blocktimeCache[node.ParentTxid] + lifetime
			} else {
				// cache the blocktime for future use
				if schedulerUnit == ports.BlockHeight {
					blocktimeCache[node.Txid] = height
				} else {
					blocktimeCache[node.Txid] = blocktime
				}

				// if the tx is onchain, it means that the input is spent
				// add the children to the nodes in order to check them during the next iteration
				// We will return the error below, but are we going to schedule the tasks for the "children roots"?
				if !node.Leaf {
					children := congestionTree.Children(node.Txid)
					newNodesToCheck = append(newNodesToCheck, children...)
				}
				continue
			}

			if _, ok := sweepableOutputs[expirationTime]; !ok {
				sweepableOutputs[expirationTime] = make([]ports.SweepInput, 0)
			}
			sweepableOutputs[expirationTime] = append(sweepableOutputs[expirationTime], sweepInput)
		}

		nodesToCheck = newNodesToCheck
	}

	return sweepableOutputs, nil
}

func getSpentVtxos(payments map[string]domain.Payment) []domain.VtxoKey {
	vtxos := make([]domain.VtxoKey, 0)
	for _, p := range payments {
		for _, vtxo := range p.Inputs {
			vtxos = append(vtxos, vtxo.VtxoKey)
		}
	}
	return vtxos
}

func validateProofs(ctx context.Context, vtxoRepo domain.VtxoRepository, proofs []SignedVtxoOutpoint) error {
	for _, signedVtxo := range proofs {
		vtxos, err := vtxoRepo.GetVtxos(ctx, []domain.VtxoKey{signedVtxo.Outpoint})
		if err != nil {
			return fmt.Errorf("vtxo not found: %s (%s)", signedVtxo.Outpoint, err)
		}

		if len(vtxos) < 1 {
			return fmt.Errorf("vtxo not found: %s", signedVtxo.Outpoint)
		}

		vtxo := vtxos[0]

		if err := signedVtxo.Proof.validate(vtxo); err != nil {
			return fmt.Errorf("invalid proof for vtxo %s (%s)", signedVtxo.Outpoint, err)
		}
	}

	return nil
}

// nip19toNostrProfile decodes a NIP-19 string and returns a nostr profile
// if nprofile => returns nostrRecipient
// if npub => craft nprofile from npub and defaultRelays
func nip19toNostrProfile(nostrRecipient string, defaultRelays []string) (string, error) {
	prefix, result, err := nip19.Decode(nostrRecipient)
	if err != nil {
		return "", fmt.Errorf("failed to decode NIP-19 string: %s", err)
	}

	var nprofileRecipient string

	switch prefix {
	case "nprofile":
		recipient, ok := result.(nostr.ProfilePointer)
		if !ok {
			return "", fmt.Errorf("invalid NIP-19 result: %v", result)
		}

		// validate public key
		if !nostr.IsValidPublicKey(recipient.PublicKey) {
			return "", fmt.Errorf("invalid nostr public key: %s", recipient.PublicKey)
		}

		// validate relays
		if len(recipient.Relays) == 0 {
			return "", fmt.Errorf("invalid nostr profile: at least one relay is required")
		}

		for _, relay := range recipient.Relays {
			if !nostr.IsValidRelayURL(relay) {
				return "", fmt.Errorf("invalid relay URL: %s", relay)
			}
		}

		nprofileRecipient = nostrRecipient
	case "npub":
		recipientPubkey, ok := result.(string)
		if !ok {
			return "", fmt.Errorf("invalid NIP-19 result: %v", result)
		}

		nprofileRecipient, err = nip19.EncodeProfile(recipientPubkey, defaultRelays)
		if err != nil {
			return "", fmt.Errorf("failed to encode nostr profile: %s", err)
		}
	default:
		return "", fmt.Errorf("invalid NIP-19 prefix: %s", prefix)
	}

	if nprofileRecipient == "" {
		return "", fmt.Errorf("invalid nostr recipient")
	}

	return nprofileRecipient, nil
}
