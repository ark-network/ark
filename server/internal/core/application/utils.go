package application

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/sirupsen/logrus"
)

type timedPayment struct {
	domain.Payment
	timestamp     time.Time
	pingTimestamp time.Time
}

type paymentsMap struct {
	lock     *sync.RWMutex
	payments map[string]*timedPayment
}

func newPaymentsMap(payments []domain.Payment) *paymentsMap {
	paymentsById := make(map[string]*timedPayment)
	for _, p := range payments {
		paymentsById[p.Id] = &timedPayment{p, time.Now(), time.Time{}}
	}
	lock := &sync.RWMutex{}
	return &paymentsMap{lock, paymentsById}
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

func (m *paymentsMap) push(payment domain.Payment) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.payments[payment.Id]; ok {
		return fmt.Errorf("duplicated inputs")
	}

	m.payments[payment.Id] = &timedPayment{payment, time.Now(), time.Time{}}
	return nil
}

func (m *paymentsMap) pop(num int64) []domain.Payment {
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
	for _, p := range paymentsByTime[:num] {
		payments = append(payments, p.Payment)
		delete(m.payments, p.Id)
	}
	return payments
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
		Id:                    payment.Id,
		Inputs:                payment.Inputs,
		Receivers:             payment.Receivers,
		ReverseBoardingInputs: payment.ReverseBoardingInputs,
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

func (m *forfeitTxsMap) push(txs []string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, tx := range txs {
		signed, txid, _ := m.builder.VerifyForfeitTx(tx)
		m.forfeitTxs[txid] = &signedTx{tx, signed}
	}
}

func (m *forfeitTxsMap) sign(txs []string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, tx := range txs {
		valid, txid, err := m.builder.VerifyForfeitTx(tx)
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

func (m *forfeitTxsMap) view() []string {
	m.lock.RLock()
	defer m.lock.RUnlock()

	txs := make([]string, 0, len(m.forfeitTxs))
	for _, tx := range m.forfeitTxs {
		txs = append(txs, tx.tx)
	}
	return txs
}

// onchainOutputs iterates over all the nodes' outputs in the congestion tree and checks their onchain state
// returns the sweepable outputs as ports.SweepInput mapped by their expiration time
func findSweepableOutputs(
	ctx context.Context,
	walletSvc ports.WalletService,
	txbuilder ports.TxBuilder,
	congestionTree tree.CongestionTree,
) (map[int64][]ports.SweepInput, error) {
	sweepableOutputs := make(map[int64][]ports.SweepInput)
	blocktimeCache := make(map[string]int64) // txid -> blocktime
	nodesToCheck := congestionTree[0]        // init with the root

	for len(nodesToCheck) > 0 {
		newNodesToCheck := make([]tree.Node, 0)

		for _, node := range nodesToCheck {
			isConfirmed, blocktime, err := walletSvc.IsTransactionConfirmed(ctx, node.Txid)
			if err != nil {
				return nil, err
			}

			var expirationTime int64
			var sweepInput ports.SweepInput

			if !isConfirmed {
				if _, ok := blocktimeCache[node.ParentTxid]; !ok {
					isConfirmed, blocktime, err := walletSvc.IsTransactionConfirmed(ctx, node.ParentTxid)
					if !isConfirmed || err != nil {
						return nil, fmt.Errorf("tx %s not found", node.Txid)
					}

					blocktimeCache[node.ParentTxid] = blocktime
				}

				expirationTime, sweepInput, err = txbuilder.GetSweepInput(blocktimeCache[node.ParentTxid], node)
				if err != nil {
					return nil, err
				}
			} else {
				// cache the blocktime for future use
				blocktimeCache[node.Txid] = int64(blocktime)

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
