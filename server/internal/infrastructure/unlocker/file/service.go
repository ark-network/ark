package fileunlocker

import (
	"bytes"
	"context"
	"os"

	"github.com/ark-network/ark/server/internal/core/ports"
)

type service struct {
	filePath string
}

func NewService(filePath string) (ports.Unlocker, error) {
	if _, err := os.Stat(filePath); err != nil {
		return nil, err
	}
	return &service{filePath: filePath}, nil
}

func (s *service) GetPassword(_ context.Context) (string, error) {
	buf, err := os.ReadFile(s.filePath)
	if err != nil {
		return "", err
	}

	password := bytes.TrimFunc(buf, func(r rune) bool {
		return r == 10 || r == 13 || r == 32
	})

	return string(password), nil
}
