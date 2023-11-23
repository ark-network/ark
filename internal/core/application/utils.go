package application

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/vulpemventures/go-elements/psetv2"
)

type timedPayment struct {
	domain.Payment
	timestamp time.Time
}

type paymentsMap struct {
	lock     *sync.RWMutex
	payments map[string]timedPayment
}

func newPaymentsMap(payments []domain.Payment) *paymentsMap {
	paymentsById := make(map[string]timedPayment)
	for _, p := range payments {
		paymentsById[p.Id] = timedPayment{p, time.Now()}
	}
	lock := &sync.RWMutex{}
	return &paymentsMap{lock, paymentsById}
}

func (m *paymentsMap) len() int64 {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return int64(len(m.payments))
}

func (m *paymentsMap) push(payment domain.Payment) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.payments[payment.Id]; ok {
		return fmt.Errorf("duplicated inputs")
	}

	m.payments[payment.Id] = timedPayment{payment, time.Now()}
	return nil
}

func (m *paymentsMap) pop(num int64) []domain.Payment {
	m.lock.Lock()
	defer m.lock.Unlock()

	if num < 0 || num > int64(len(m.payments)) {
		num = int64(len(m.payments))
	}

	paymentsByTime := make([]timedPayment, 0, len(m.payments))
	for _, p := range m.payments {
		// Skip payments without registered receivers.
		if len(p.Receivers) <= 0 {
			continue
		}
		paymentsByTime = append(paymentsByTime, p)
	}
	sort.SliceStable(paymentsByTime, func(i, j int) bool {
		return paymentsByTime[i].timestamp.Before(paymentsByTime[j].timestamp)
	})

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

	if _, ok := m.payments[payment.Id]; !ok {
		return fmt.Errorf("payment %s not found", payment.Id)
	}

	m.payments[payment.Id] = timedPayment{payment, m.payments[payment.Id].timestamp}
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
}

func newForfeitTxsMap() *forfeitTxsMap {
	return &forfeitTxsMap{&sync.RWMutex{}, make(map[string]*signedTx)}
}

func (m *forfeitTxsMap) push(txs []string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, tx := range txs {
		ptx, _ := psetv2.NewPsetFromBase64(tx)
		utx, _ := ptx.UnsignedTx()
		m.forfeitTxs[utx.TxHash().String()] = &signedTx{tx, false}
	}
}

func (m *forfeitTxsMap) sign(txid, tx string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.forfeitTxs[txid]; !ok {
		return fmt.Errorf("forfeit tx %s not found ", txid)
	}
	m.forfeitTxs[txid].signed = true
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
