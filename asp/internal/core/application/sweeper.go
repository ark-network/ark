package application

import (
	"context"
	"fmt"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/psetv2"
)

type sweeper struct {
	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder

	stop chan struct{}
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
				toSweepOutputs, err := s.findOutputsToSweep()
				if err != nil {
					log.Error(fmt.Errorf("error while finding outputs to sweep: %w", err))
					continue
				}

				log.Debug(fmt.Sprintf("sweep routine start at %s (%d outputs)", timestamp, len(toSweepOutputs)))

				if len(toSweepOutputs) == 0 {
					continue
				}

				sweepTx, err := s.builder.BuildSweepTx(s.wallet, toSweepOutputs)
				if err != nil {
					log.Error(fmt.Errorf("error while building sweep tx: %w", err))
					continue
				}

				ctx := context.Background()

				log.Debug(fmt.Sprintf("broadcasting sweep tx: %s", sweepTx))

				txid, err := s.wallet.BroadcastTransaction(ctx, sweepTx)
				if err != nil {
					log.Error(fmt.Errorf("error while broadcasting sweep tx: %w", err))
					continue
				}

				eventsRepo := s.repoManager.Events()
				roundsRepo := s.repoManager.Rounds()
				vtxoKeys := make([]domain.VtxoKey, 0)

				for _, sweptOutput := range toSweepOutputs {
					events, err := sweptOutput.Round.Sweep(
						sweptOutput.InputArgs.Txid,
						sweptOutput.InputArgs.TxIndex,
						txid,
					)
					if err != nil {
						log.Error(fmt.Errorf("error while updating events repository: %w", err))
						continue
					}

					if err := eventsRepo.Save(ctx, sweptOutput.Round.Id, events...); err != nil {
						log.Error(fmt.Errorf("error while saving events: %w", err))
						continue
					}

					if err := roundsRepo.AddOrUpdateRound(ctx, sweptOutput.Round); err != nil {
						log.Error(fmt.Errorf("error while saving round: %w", err))
						continue
					}

					vtxosLeaves, err := sweptOutput.Round.CongestionTree.FindLeaves(sweptOutput.InputArgs.Txid)
					if err != nil {
						log.Error(fmt.Errorf("error while finding leaves: %w", err))
						continue
					}

					for _, leaf := range vtxosLeaves {
						pset, err := psetv2.NewPsetFromBase64(leaf.Tx)
						if err != nil {
							log.Error(fmt.Errorf("error while decoding pset: %w", err))
							continue
						}

						switch len(pset.Outputs) {
						case 2:
							vtxoKeys = append(vtxoKeys, domain.VtxoKey{
								Txid: leaf.Txid,
								VOut: 0,
							})
						case 3:
							vtxoKeys = append(vtxoKeys, domain.VtxoKey{
								Txid: leaf.Txid,
								VOut: 0,
							}, domain.VtxoKey{
								Txid: leaf.Txid,
								VOut: 1,
							})
						}
					}

				}

				log.Debugf("%d vtxos swept", len(vtxoKeys))
				if err := s.repoManager.Vtxos().SweepVtxos(ctx, vtxoKeys); err != nil {
					log.Error(fmt.Errorf("error while deleting vtxos: %w", err))
					continue
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

func newSweeper(
	wallet ports.WalletService,
	repoManager ports.RepoManager,
	builder ports.TxBuilder,
) *sweeper {
	return &sweeper{
		wallet:      wallet,
		repoManager: repoManager,
		builder:     builder,
	}
}

func (s *sweeper) findOutputsToSweep() ([]ports.SweepInput, error) {
	expiredRounds, err := s.repoManager.Rounds().GetExpiredOutputs(context.Background())
	if err != nil {
		return nil, err
	}
	toSweep := make([]ports.SweepInput, 0)

	for _, round := range expiredRounds {
		needUpdate := false
		log.Debugf("checking round %s, has %d expired outputs", round.Id, len(round.ExpiredOutputs))

		for _, index := range round.ExpiredOutputs {
			output := round.SharedOutputs[index]
			children := round.CongestionTree.Children(output.Txid)
			newSharedOutputs := make([]domain.SharedOutput, 0)

			for _, child := range children {
				pset, err := psetv2.NewPsetFromBase64(child.Tx)
				if err != nil {
					log.Error(fmt.Errorf("sweeper: %w", err))
					continue
				}

				// check if the child spends the sweepable output
				input := pset.Inputs[0]
				inputTxid := chainhash.Hash(input.PreviousTxid).String()
				if inputTxid != output.Txid || input.PreviousTxIndex != output.Index {
					continue
				}

				var sweepLeaf psetv2.TapLeafScript
				var lifetime uint

				for _, leaf := range input.TapLeafScript {
					isSweep, _, seconds, err := tree.DecodeSweepScript(leaf.Script)
					if err != nil {
						log.Error(fmt.Errorf("sweeper: %w", err))
						continue
					}
					if isSweep {
						lifetime = seconds
						sweepLeaf = leaf
						break
					}
				}

				_, rootTxBlocktime, err := s.wallet.GetTransaction(context.Background(), child.Txid)
				if err != nil {
					// if tx is not found, it means that we can sweep it
					var amount uint64

					for _, out := range pset.Outputs {
						amount += out.Value
					}

					sweepExists := false
					txid := chainhash.Hash(input.PreviousTxid).String()

					for _, sweepInput := range toSweep {
						if txid == sweepInput.InputArgs.Txid && input.PreviousTxIndex == sweepInput.InputArgs.TxIndex {
							sweepExists = true
							break
						}
					}

					if !sweepExists {
						toSweep = append(toSweep, ports.SweepInput{
							InputArgs: psetv2.InputArgs{
								Txid:    chainhash.Hash(input.PreviousTxid).String(),
								TxIndex: input.PreviousTxIndex,
							},
							Leaves: []psetv2.TapLeafScript{sweepLeaf},
							Amount: amount,
							Round:  round.Round,
						})
					}

					continue
				}

				// if one of the children is found on chain, it means that the output has been spent
				newSharedOutputs = append(newSharedOutputs,
					domain.SharedOutput{
						Txid:                child.Txid,
						Index:               0,
						ExpirationTimestamp: int64(rootTxBlocktime) + int64(lifetime),
						SweepTxid:           "",
					},
				)

				if len(pset.Outputs) == 3 {
					newSharedOutputs = append(newSharedOutputs,
						domain.SharedOutput{
							Txid:                child.Txid,
							Index:               1,
							ExpirationTimestamp: int64(rootTxBlocktime) + int64(lifetime),
							SweepTxid:           "",
						},
					)
				}
			}

			if len(newSharedOutputs) > 0 {
				// if we found new shared outputs, we update the round
				round.SharedOutputs[index].Spent = true
				round.SharedOutputs = append(round.SharedOutputs, newSharedOutputs...)
				needUpdate = true
			}
		}

		if needUpdate {
			if err := s.repoManager.Rounds().AddOrUpdateRound(context.Background(), round.Round); err != nil {
				return nil, err
			}
		}
	}

	return toSweep, nil
}
