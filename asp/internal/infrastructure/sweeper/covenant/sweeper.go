package covenant

import (
	"context"
	"fmt"
	"time"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/vulpemventures/go-elements/psetv2"
)

type sweeper struct {
	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder

	stop chan struct{}

	logError func(err error)
	logDebug func(msg string)
}

// Start implements ports.SweeperService.
func (s *sweeper) Start() error {
	s.stop = make(chan struct{}, 1)
	timer := time.NewTicker(30 * time.Second)

	go func() {
		for {
			select {
			case <-timer.C:
				// fancy format data
				timestamp := time.Now().Format("15:04:05")

				// find outputs to sweep, build sweep tx and broadcast it
				toSweepOutputs, rounds, err := s.findOutputsToSweep()
				if err != nil {
					s.logError(fmt.Errorf("error while finding outputs to sweep: %w", err))
					continue
				}

				s.logDebug(fmt.Sprintf("sweep routine start at %s (%d expired rounds, %d outputs)", timestamp, len(rounds), len(toSweepOutputs)))

				if len(toSweepOutputs) == 0 {
					continue
				}

				sweepTx, err := s.builder.BuildSweepTx(s.wallet, toSweepOutputs)
				if err != nil {
					s.logError(fmt.Errorf("error while building sweep tx: %w", err))
					continue
				}

				ctx := context.Background()

				s.logDebug(fmt.Sprintf("broadcasting sweep tx: %s", sweepTx))

				txid, err := s.wallet.BroadcastTransaction(ctx, sweepTx)
				if err != nil {
					s.logError(fmt.Errorf("error while broadcasting sweep tx: %w", err))
					continue
				}

				eventsRepo := s.repoManager.Events()
				roundsRepo := s.repoManager.Rounds()

				for _, r := range rounds {
					events, err := r.Sweep(txid)
					if err != nil {
						s.logError(fmt.Errorf("error while updating round: %w", err))
						continue
					}

					if err := eventsRepo.Save(ctx, r.Id, events...); err != nil {
						s.logError(fmt.Errorf("error while saving events: %w", err))
						continue
					}

					if err := roundsRepo.AddOrUpdateRound(ctx, r); err != nil {
						s.logError(fmt.Errorf("error while updating round: %w", err))
						continue
					}
				}
			case <-s.stop:
				return
			}
		}
	}()

	return nil
}

// Stop implements ports.SweeperService.
func (s *sweeper) Stop() error {
	s.stop <- struct{}{}
	close(s.stop)
	return nil
}

func NewSweeper(
	wallet ports.WalletService,
	repoManager ports.RepoManager,
	builder ports.TxBuilder,
	log func(error),
	debug func(string),
) ports.SweeperService {
	return &sweeper{
		wallet:      wallet,
		repoManager: repoManager,
		builder:     builder,
		logError:    log,
		logDebug:    debug,
	}
}

// find outputs to sweep search for expired rounds and check their congestion tree in order to find outputs to sweep
// it also update round information if the tree has been spent
// TODO handle the case where the whole tree is on-chain: should be removed from the db?
func (s *sweeper) findOutputsToSweep() ([]ports.SweepInput, []domain.Round, error) {
	expiredRounds, err := s.repoManager.Rounds().GetExpiredRounds(context.Background())
	if err != nil {
		return nil, nil, err
	}
	toSweep := make([]ports.SweepInput, 0)
	rounds := make([]domain.Round, 0)

	for _, round := range expiredRounds {
		node := round.CongestionTree.Root()
		_, rootTxBlocktime, err := s.wallet.GetTransaction(context.Background(), node.Txid)
		if err != nil {
			// if tx is not found, it means that we can sweep it
			pset, err := psetv2.NewPsetFromBase64(node.Tx)
			if err != nil {
				s.logError(fmt.Errorf("error while decoding pset: %w", err))
				continue
			}

			input := pset.Inputs[0]
			var amount uint64

			for _, out := range pset.Outputs {
				amount += out.Value
			}

			toSweep = append(toSweep, ports.SweepInput{
				InputArgs: psetv2.InputArgs{
					Txid:    chainhash.Hash(input.PreviousTxid).String(),
					TxIndex: input.PreviousTxIndex,
				},
				Leaves: input.TapLeafScript,
				Amount: amount,
			})

			rounds = append(rounds, round)
			continue
		}

		// else, update the round tree
		childrenRoot := round.CongestionTree.Children(node.Txid)

		// check left child
		_, _, err = s.wallet.GetTransaction(context.Background(), childrenRoot[0].Txid)
		if err != nil {
			round.CongestionTree = round.CongestionTree.SubTree(childrenRoot[0].Txid)
			lifetime, err := s.builder.GetLifetime(round.CongestionTree)
			if err != nil {
				s.logError(fmt.Errorf("GetLifeTime error: %w", err))
				continue
			}

			round.ExpirationTimestamp = int64(rootTxBlocktime) + lifetime

			if err := s.repoManager.Rounds().AddOrUpdateRound(context.Background(), round); err != nil {
				s.logError(fmt.Errorf("AddOrUpdateRound error: %w", err))
				continue
			}

			continue
		}

		// check right child
		_, _, err = s.wallet.GetTransaction(context.Background(), childrenRoot[1].Txid)
		if err != nil {
			round.CongestionTree = round.CongestionTree.SubTree(childrenRoot[1].Txid)
			lifetime, err := s.builder.GetLifetime(round.CongestionTree)
			if err != nil {
				s.logError(fmt.Errorf("GetLifeTime error: %w", err))
				continue
			}

			round.ExpirationTimestamp = int64(rootTxBlocktime) + lifetime

			if err := s.repoManager.Rounds().AddOrUpdateRound(context.Background(), round); err != nil {
				s.logError(fmt.Errorf("AddOrUpdateRound error: %w", err))
				continue
			}

			continue
		}
	}

	return toSweep, rounds, nil
}
