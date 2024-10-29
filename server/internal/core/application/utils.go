package application

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/common/voucher"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/sirupsen/logrus"
)

type timedPayment struct {
	domain.Payment
	boardingInputs []ports.BoardingInput
	vouchers       []voucher.Voucher
	timestamp      time.Time
	pingTimestamp  time.Time
}

type paymentsMap struct {
	lock          *sync.RWMutex
	payments      map[string]*timedPayment
	descriptors   map[domain.VtxoKey]string
	ephemeralKeys map[string]*secp256k1.PublicKey
}

func newPaymentsMap() *paymentsMap {
	paymentsById := make(map[string]*timedPayment)
	lock := &sync.RWMutex{}
	return &paymentsMap{lock, paymentsById, make(map[domain.VtxoKey]string), make(map[string]*secp256k1.PublicKey)}
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

func (m *paymentsMap) pushWithVouchers(payment domain.Payment, vouchers []voucher.Voucher) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.payments[payment.Id]; ok {
		return fmt.Errorf("duplicated payment %s", payment.Id)
	}

	for _, voucher := range vouchers {
		for _, payment := range m.payments {
			for _, pVoucher := range payment.vouchers {
				if voucher.ID == pVoucher.ID {
					return fmt.Errorf("duplicated voucher %s", voucher)
				}
			}
		}
	}

	m.payments[payment.Id] = &timedPayment{payment, make([]ports.BoardingInput, 0), vouchers, time.Now(), time.Time{}}
	return nil
}

func (m *paymentsMap) push(
	payment domain.Payment,
	boardingInputs []ports.BoardingInput,
	descriptors map[domain.VtxoKey]string,
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

	for key, desc := range descriptors {
		m.descriptors[key] = desc
	}

	m.payments[payment.Id] = &timedPayment{payment, boardingInputs, make([]voucher.Voucher, 0), time.Now(), time.Time{}}
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

func (m *paymentsMap) pop(num int64) ([]domain.Payment, []ports.BoardingInput, map[domain.VtxoKey]string, []*secp256k1.PublicKey, []voucher.Voucher) {
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
	descriptors := make(map[domain.VtxoKey]string)
	vouchers := make([]voucher.Voucher, 0)
	for _, p := range paymentsByTime[:num] {
		boardingInputs = append(boardingInputs, p.boardingInputs...)
		payments = append(payments, p.Payment)
		if pubkey, ok := m.ephemeralKeys[p.Payment.Id]; ok {
			cosigners = append(cosigners, pubkey)
			delete(m.ephemeralKeys, p.Payment.Id)
		}

		vouchers = append(vouchers, p.vouchers...)

		for _, input := range payments {
			for _, vtxo := range input.Inputs {
				descriptors[vtxo.VtxoKey] = m.descriptors[vtxo.VtxoKey]
				delete(m.descriptors, vtxo.VtxoKey)
			}
		}
		delete(m.payments, p.Id)
	}
	return payments, boardingInputs, descriptors, cosigners, vouchers
}

func (m *paymentsMap) update(payment domain.Payment) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	p, ok := m.payments[payment.Id]
	if !ok {
		return fmt.Errorf("payment %s not found", payment.Id)
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

type signedTx struct {
	tx     string
	signed bool
}

type forfeitTxsMap struct {
	lock       *sync.RWMutex
	forfeitTxs map[string]*signedTx
	builder    ports.TxBuilder
}

func newForfeitTxsMap(txBuilder ports.TxBuilder) *forfeitTxsMap {
	return &forfeitTxsMap{&sync.RWMutex{}, make(map[string]*signedTx), txBuilder}
}

func (m *forfeitTxsMap) push(txs []string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, tx := range txs {
		txid, err := m.builder.GetTxID(tx)
		if err != nil {
			return err
		}
		m.forfeitTxs[txid] = &signedTx{tx, false}
	}

	return nil
}

func (m *forfeitTxsMap) sign(txs []string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, tx := range txs {
		valid, txid, err := m.builder.VerifyTapscriptPartialSigs(tx)
		if err != nil {
			return err
		}

		if _, ok := m.forfeitTxs[txid]; ok {
			if valid {
				m.forfeitTxs[txid].tx = tx
				m.forfeitTxs[txid].signed = true
			} else {
				logrus.Warnf("invalid forfeit tx signature (%s)", txid)
			}
		}
	}

	return nil
}

func (m *forfeitTxsMap) pop() (signed, unsigned []string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, t := range m.forfeitTxs {
		if t.signed {
			signed = append(signed, t.tx)
		} else {
			unsigned = append(unsigned, t.tx)
		}
	}

	m.forfeitTxs = make(map[string]*signedTx)
	return signed, unsigned
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
