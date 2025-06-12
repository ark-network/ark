package utils

import (
	"strings"
	"sync"

	"github.com/ark-network/ark/pkg/client-sdk/client"
)

type SupportedType[V any] map[string]V

func (t SupportedType[V]) String() string {
	types := make([]string, 0, len(t))
	for tt := range t {
		types = append(types, tt)
	}
	return strings.Join(types, " | ")
}

func (t SupportedType[V]) Supports(typeStr string) bool {
	_, ok := t[typeStr]
	return ok
}

type ClientFactory func(string) (client.TransportClient, error)

type Cache[V any] struct {
	mapping map[string]V
	lock    *sync.RWMutex
}

func NewCache[V any]() *Cache[V] {
	return &Cache[V]{
		mapping: make(map[string]V),
		lock:    &sync.RWMutex{},
	}
}

func (c Cache[V]) Set(key string, value V) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.mapping[key] = value
}

func (c Cache[V]) Get(key string) (V, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	val, ok := c.mapping[key]
	return val, ok
}

// Broadcaster lets you publish events of type T to many subscribers.
type Broadcaster[T any] struct {
	mu     sync.RWMutex
	once   sync.Once
	subs   map[chan T]struct{}
	buffer int
}

// NewBroadcaster creates a broadcaster whose subscriber channels have the given buffer.
func NewBroadcaster[T any](buffer int) *Broadcaster[T] {
	return &Broadcaster[T]{
		subs:   make(map[chan T]struct{}),
		buffer: buffer,
	}
}

// Subscribe returns a channel on which the caller will get all future events.
// The caller must call Unsubscribe when done.
func (b *Broadcaster[T]) Subscribe() chan T {
	ch := make(chan T, b.buffer)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscription and closes its channel.
func (b *Broadcaster[T]) Unsubscribe(ch chan T) {
	b.mu.Lock()
	if _, ok := b.subs[ch]; ok {
		delete(b.subs, ch)
		close(ch)
	}
	b.mu.Unlock()
}

// Publish sends an event to all current subscribers.
// It uses non-blocking sends so a slow subscriber won’t stop the whole broadcast.
func (b *Broadcaster[T]) Publish(evt T) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.subs {
		select {
		case ch <- evt:
			// delivered
		default:
			// subscriber’s buffer is full; skip or drop
		}
	}
}

func (b *Broadcaster[T]) PublishOnce(handler func() []T) {
	b.once.Do(func() {
		events := handler()
		for _, evt := range events {
			go b.Publish(evt)
		}
	})
}
