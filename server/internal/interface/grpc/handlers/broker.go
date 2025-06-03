package handlers

import (
	"fmt"
	"slices"
	"sync"
	"time"
)

type listener[T any] struct {
	id            string
	topics        []string
	ch            chan T
	stopTimeoutCh chan struct{}
}

// broker is a simple utility struct to manage subscriptions.
// it is used to send events to multiple listeners.
// it is thread safe and can be used to send events to multiple listeners.
type broker[T any] struct {
	lock      *sync.Mutex
	listeners []*listener[T]
}

func newBroker[T any]() *broker[T] {
	return &broker[T]{
		lock:      &sync.Mutex{},
		listeners: make([]*listener[T], 0),
	}
}

func (h *broker[T]) pushListener(l *listener[T]) {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.listeners = append(h.listeners, l)
}

func (h *broker[T]) removeListener(id string) {
	h.lock.Lock()
	defer h.lock.Unlock()

	for i, listener := range h.listeners {
		if listener.id == id {
			if listener.stopTimeoutCh != nil {
				listener.stopTimeoutCh <- struct{}{}
				close(listener.stopTimeoutCh)
				listener.stopTimeoutCh = nil
			}
			h.listeners = append(h.listeners[:i], h.listeners[i+1:]...)
			return
		}
	}
}

func (h *broker[T]) getListenerChannel(id string) (chan T, error) {
	h.lock.Lock()
	defer h.lock.Unlock()

	for _, listener := range h.listeners {
		if listener.id == id {
			return listener.ch, nil
		}
	}

	return nil, fmt.Errorf("subscription %s not found", id)
}

func (h *broker[T]) addTopics(id string, topics []string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	for _, listener := range h.listeners {
		if listener.id == id {
			// add topics to listener.topics if not already present
			for _, topic := range topics {
				if !slices.Contains(listener.topics, topic) {
					listener.topics = append(listener.topics, topic)
				}
			}
			return nil
		}
	}

	return fmt.Errorf("subscription %s not found", id)
}

func (h *broker[T]) removeTopics(id string, topics []string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	for _, listener := range h.listeners {
		if listener.id == id {
			for _, topic := range topics {
				for i, t := range listener.topics {
					if t == topic {
						listener.topics = append(listener.topics[:i], listener.topics[i+1:]...)
					}
				}
			}
			return nil
		}
	}

	return fmt.Errorf("subscription %s not found", id)
}

func (h *broker[T]) removeAllTopics(id string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	for _, listener := range h.listeners {
		if listener.id == id {
			listener.topics = make([]string, 0)
			return nil
		}
	}

	return fmt.Errorf("subscription %s not found", id)
}

func (h *broker[T]) startTimeout(id string, timeout time.Duration) {
	h.lock.Lock()
	defer h.lock.Unlock()

	for _, listener := range h.listeners {
		if listener.id == id {

			listener.stopTimeoutCh = make(chan struct{})

			go func() {
				select {
				case <-listener.stopTimeoutCh:
					return
				case <-time.After(timeout):
					h.removeListener(id)
				}
			}()

			return
		}
	}
}

func (h *broker[T]) stopTimeout(id string) {
	h.lock.Lock()
	defer h.lock.Unlock()

	for _, listener := range h.listeners {
		if listener.id == id {
			listener.stopTimeoutCh <- struct{}{}
			close(listener.stopTimeoutCh)
			listener.stopTimeoutCh = nil
			return
		}
	}
}
