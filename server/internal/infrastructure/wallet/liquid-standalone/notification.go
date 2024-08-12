package oceanwallet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func (s *service) WatchScripts(ctx context.Context, scripts []string) error {
	for _, script := range scripts {
		if _, err := s.notifyClient.WatchExternalScript(ctx, &pb.WatchExternalScriptRequest{
			Script: script,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *service) UnwatchScripts(ctx context.Context, scripts []string) error {
	for _, script := range scripts {
		scriptHash := calcScriptHash(script)
		if _, err := s.notifyClient.UnwatchExternalScript(ctx, &pb.UnwatchExternalScriptRequest{
			Label: scriptHash,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *service) GetNotificationChannel(ctx context.Context) <-chan map[string]ports.VtxoWithValue {
	return s.chVtxos
}

func calcScriptHash(script string) string {
	buf, _ := hex.DecodeString(script)
	hashedBuf := sha256.Sum256(buf)
	hash, _ := chainhash.NewHash(hashedBuf[:])
	return hash.String()
}
