package domain

import "context"

type Event interface {
	GetTopic() string
}

type EventRepository interface {
	Save(ctx context.Context, topic, id string, events []Event) error
	RegisterEventsHandler(topic string, handler func(events []Event))
	ClearRegisteredHandlers(topic ...string)
	Close()
}
