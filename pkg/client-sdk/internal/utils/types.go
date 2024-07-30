package utils

import (
	"strings"

	"github.com/ark-network/ark-sdk/client"
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

type ClientFactory func(string) (client.ASPClient, error)
