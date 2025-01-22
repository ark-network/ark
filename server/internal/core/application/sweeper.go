package application

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ark-network/ark/common/note"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	nostr_notifier "github.com/ark-network/ark/server/internal/infrastructure/notifier/nostr"
	log "github.com/sirupsen/logrus"
)

// sweeper is an unexported service running while the main application service is started
// it is responsible for sweeping onchain shared outputs that expired
// it also handles delaying the sweep events in case some parts of the tree are broadcasted
// when a round is finalized, the main application service schedules a sweep event on the newly created vtxo tree
type sweeper struct {
	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scheduler   ports.SchedulerService

	noteUriPrefix string

	// cache of scheduled tasks, avoid scheduling the same sweep event multiple times
	locker         sync.Locker
	scheduledTasks map[string]struct{}
}

func newSweeper(
	wallet ports.WalletService,
	repoManager ports.RepoManager,
	builder ports.TxBuilder,
	scheduler ports.SchedulerService,
	noteUriPrefix string,
) *sweeper {
	return &sweeper{
		wallet,
		repoManager,
		builder,
		scheduler,
		noteUriPrefix,
		&sync.Mutex{},
		make(map[string]struct{}),
	}
}

func (s *sweeper) start() error {
	s.scheduler.Start()

	ctx := context.Background()

	expiredRounds, err := s.repoManager.Rounds().GetExpiredRoundsTxid(ctx)
	if err != nil {
		return err
	}

	for _, txid := range expiredRounds {
		vtxoTree, err := s.repoManager.Rounds().GetVtxoTreeWithTxid(ctx, txid)
		if err != nil {
			return err
		}

		task := s.createTask(txid, vtxoTree)
		task()
	}

	return nil
}

func (s *sweeper) stop() {
	s.scheduler.Stop()
}

// removeTask update the cached map of scheduled tasks
func (s *sweeper) removeTask(treeRootTxid string) {
	s.locker.Lock()
	defer s.locker.Unlock()
	delete(s.scheduledTasks, treeRootTxid)
}

// schedule set up a task to be executed once at the given timestamp
func (s *sweeper) schedule(
	expirationTimestamp int64, roundTxid string, vtxoTree tree.VtxoTree,
) error {
	if len(vtxoTree) <= 0 { // skip
		log.Debugf("skipping sweep scheduling (round tx %s), empty vtxo tree", roundTxid)
		return nil
	}

	root, err := vtxoTree.Root()
	if err != nil {
		return err
	}

	if _, scheduled := s.scheduledTasks[root.Txid]; scheduled {
		return nil
	}

	task := s.createTask(roundTxid, vtxoTree)

	var fancyTime string
	if s.scheduler.Unit() == ports.UnixTime {
		fancyTime = time.Unix(expirationTimestamp, 0).Format("2006-01-02 15:04:05")
	} else {
		fancyTime = fmt.Sprintf("block %d", expirationTimestamp)
	}
	log.Debugf("scheduled sweep for round %s at %s", roundTxid, fancyTime)

	if err := s.scheduler.ScheduleTaskOnce(expirationTimestamp, task); err != nil {
		return err
	}

	s.locker.Lock()
	s.scheduledTasks[root.Txid] = struct{}{}
	s.locker.Unlock()

	if err := s.updateVtxoExpirationTime(vtxoTree, expirationTimestamp); err != nil {
		log.WithError(err).Error("error while updating vtxo expiration time")
	}

	return nil
}

// createTask returns a function passed as handler in the scheduler
// it tries to craft a sweep tx containing the onchain outputs of the given vtxo tree
// if some parts of the tree have been broadcasted in the meantine, it will schedule the next taskes for the remaining parts of the tree
func (s *sweeper) createTask(
	roundTxid string, vtxoTree tree.VtxoTree,
) func() {
	return func() {
		ctx := context.Background()
		root, err := vtxoTree.Root()
		if err != nil {
			log.WithError(err).Error("error while getting root node")
			return
		}

		s.removeTask(root.Txid)
		log.Debugf("sweeper: %s", root.Txid)

		sweepInputs := make([]ports.SweepInput, 0)
		vtxoKeys := make([]domain.VtxoKey, 0) // vtxos associated to the sweep inputs

		// inspect the vtxo tree to find onchain shared outputs
		sharedOutputs, err := findSweepableOutputs(ctx, s.wallet, s.builder, s.scheduler.Unit(), vtxoTree)
		if err != nil {
			log.WithError(err).Error("error while inspecting vtxo tree")
			return
		}

		for expiredAt, inputs := range sharedOutputs {
			// if the shared outputs are not expired, schedule a sweep task for it
			if s.scheduler.AfterNow(expiredAt) {
				subtrees, err := computeSubTrees(vtxoTree, inputs)
				if err != nil {
					log.WithError(err).Error("error while computing subtrees")
					continue
				}

				for _, subTree := range subtrees {
					if err := s.schedule(expiredAt, roundTxid, subTree); err != nil {
						log.WithError(err).Error("error while scheduling sweep task")
						continue
					}
				}
				continue
			}

			// iterate over the expired shared outputs
			for _, input := range inputs {
				// sweepableVtxos related to the sweep input
				sweepableVtxos := make([]domain.VtxoKey, 0)

				// check if input is the vtxo itself
				vtxos, _ := s.repoManager.Vtxos().GetVtxos(
					ctx,
					[]domain.VtxoKey{
						{
							Txid: input.GetHash().String(),
							VOut: input.GetIndex(),
						},
					},
				)
				if len(vtxos) > 0 {
					if !vtxos[0].Swept && !vtxos[0].Redeemed {
						sweepableVtxos = append(sweepableVtxos, vtxos[0].VtxoKey)
					}
				} else {
					// if it's not a vtxo, find all the vtxos leaves reachable from that input
					vtxosLeaves, err := s.builder.FindLeaves(vtxoTree, input.GetHash().String(), input.GetIndex())
					if err != nil {
						log.WithError(err).Error("error while finding vtxos leaves")
						continue
					}

					for _, leaf := range vtxosLeaves {
						vtxo, err := extractVtxoOutpoint(leaf)
						if err != nil {
							log.Error(err)
							continue
						}

						sweepableVtxos = append(sweepableVtxos, *vtxo)
					}

					if len(sweepableVtxos) <= 0 {
						continue
					}

					firstVtxo, err := s.repoManager.Vtxos().GetVtxos(ctx, sweepableVtxos[:1])
					if err != nil {
						log.Error(fmt.Errorf("error while getting vtxo: %w", err))
						sweepInputs = append(sweepInputs, input) // add the input anyway in order to try to sweep it
						continue
					}

					if firstVtxo[0].Swept || firstVtxo[0].Redeemed {
						// we assume that if the first vtxo is swept or redeemed, the shared output has been spent
						// skip, the output is already swept or spent by a unilateral redeem
						continue
					}
				}

				if len(sweepableVtxos) > 0 {
					vtxoKeys = append(vtxoKeys, sweepableVtxos...)
					sweepInputs = append(sweepInputs, input)
				}
			}
		}

		vtxosRepository := s.repoManager.Vtxos()
		if len(sweepInputs) > 0 {
			// build the sweep transaction with all the expired non-swept shared outputs
			sweepTx, err := s.builder.BuildSweepTx(sweepInputs)
			if err != nil {
				log.WithError(err).Error("error while building sweep tx")
				return
			}

			err = nil
			txid := ""
			// retry until the tx is broadcasted or the error is not BIP68 final
			for len(txid) == 0 && (err == nil || err == ports.ErrNonFinalBIP68) {
				if err != nil {
					log.Debugln("sweep tx not BIP68 final, retrying in 5 seconds")
					time.Sleep(5 * time.Second)
				}

				txid, err = s.wallet.BroadcastTransaction(ctx, sweepTx)
			}

			if err != nil {
				log.WithError(err).Error("error while broadcasting sweep tx")
				return
			}
			if len(txid) > 0 {
				log.Debugln("sweep tx broadcasted:", txid)

				// mark the vtxos as swept
				if err := vtxosRepository.SweepVtxos(ctx, vtxoKeys); err != nil {
					log.Error(fmt.Errorf("error while deleting vtxos: %w", err))
					return
				}

				log.Debugf("%d vtxos swept", len(vtxoKeys))

				go s.createAndSendNotes(ctx, vtxoKeys)
			}
		}

		roundVtxos, err := vtxosRepository.GetVtxosForRound(ctx, roundTxid)
		if err != nil {
			log.WithError(err).Error("error while getting vtxos for round")
			return
		}

		allSwept := true
		for _, vtxo := range roundVtxos {
			allSwept = allSwept && (vtxo.Swept || vtxo.Redeemed)
			if !allSwept {
				break
			}
		}

		if allSwept {
			// update the round
			roundRepo := s.repoManager.Rounds()
			round, err := roundRepo.GetRoundWithTxid(ctx, roundTxid)
			if err != nil {
				log.WithError(err).Error("error while getting round")
				return
			}

			log.Debugf("round %s fully swept", roundTxid)
			round.Sweep()

			if err := roundRepo.AddOrUpdateRound(ctx, *round); err != nil {
				log.WithError(err).Error("error while marking round as swept")
				return
			}
		}
	}
}

func (s *sweeper) updateVtxoExpirationTime(
	tree tree.VtxoTree,
	expirationTime int64,
) error {
	leaves := tree.Leaves()
	vtxos := make([]domain.VtxoKey, 0)

	for _, leaf := range leaves {
		vtxo, err := extractVtxoOutpoint(leaf)
		if err != nil {
			return err
		}

		vtxos = append(vtxos, *vtxo)
	}

	return s.repoManager.Vtxos().UpdateExpireAt(context.Background(), vtxos, expirationTime)
}

func (s *sweeper) createAndSendNotes(ctx context.Context, vtxosKeys []domain.VtxoKey) {
	vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, vtxosKeys)
	if err != nil {
		log.Error(fmt.Errorf("error while getting vtxos: %w", err))
		return
	}

	entitiesRepo := s.repoManager.Entities()

	notifier := nostr_notifier.New()

	for _, vtxo := range vtxos {
		if !vtxo.Swept || vtxo.Redeemed || vtxo.Spent {
			continue
		}

		// get the nostr recipients
		entities, err := entitiesRepo.Get(ctx, vtxo.VtxoKey)
		if err != nil {
			log.Debugf("no entity found for vtxo %s", vtxo.VtxoKey)
			continue
		}

		if len(entities) == 0 {
			log.Debugf("no nostr recipient found for vtxo %s:%d, skipping note creation", vtxo.Txid, vtxo.VOut)
			continue
		}

		// if vtxo is not redeemed or spent and is swept, create a note for it
		noteData, err := note.New(uint32(vtxo.Amount))
		if err != nil {
			log.Error(fmt.Errorf("error while creating note data: %w", err))
			continue
		}

		signature, err := s.wallet.SignMessage(ctx, noteData.Hash())
		if err != nil {
			log.Error(fmt.Errorf("error while signing note data: %w", err))
			continue
		}

		note := noteData.ToNote(signature)

		notification := note.String()
		if len(s.noteUriPrefix) > 0 {
			notification = fmt.Sprintf("%s://%s", s.noteUriPrefix, note)
		}

		for _, entity := range entities {
			log.Debugf("sending note notification to %s", entity.NostrRecipient)
			if err := notifier.Notify(ctx, entity.NostrRecipient, notification); err != nil {
				log.Error(fmt.Errorf("error while sending note notification: %w", err))
			}
		}
	}
}

func computeSubTrees(vtxoTree tree.VtxoTree, inputs []ports.SweepInput) ([]tree.VtxoTree, error) {
	subTrees := make(map[string]tree.VtxoTree, 0)

	// for each sweepable input, create a sub vtxo tree
	// it allows to skip the part of the tree that has been broadcasted in the next task
	for _, input := range inputs {
		subTree, err := computeSubTree(vtxoTree, input.GetHash().String())
		if err != nil {
			log.WithError(err).Error("error while finding sub tree")
			continue
		}

		root, err := subTree.Root()
		if err != nil {
			log.WithError(err).Error("error while getting root node")
			continue
		}

		subTrees[root.Txid] = subTree
	}

	// filter out the sub trees, remove the ones that are included in others
	filteredSubTrees := make([]tree.VtxoTree, 0)
	for i, subTree := range subTrees {
		notIncludedInOtherTrees := true

		for j, otherSubTree := range subTrees {
			if i == j {
				continue
			}
			contains, err := containsTree(otherSubTree, subTree)
			if err != nil {
				log.WithError(err).Error("error while checking if a tree contains another")
				continue
			}

			if contains {
				notIncludedInOtherTrees = false
				break
			}
		}

		if notIncludedInOtherTrees {
			filteredSubTrees = append(filteredSubTrees, subTree)
		}
	}

	return filteredSubTrees, nil
}

func computeSubTree(vtxoTree tree.VtxoTree, newRoot string) (tree.VtxoTree, error) {
	for _, level := range vtxoTree {
		for _, node := range level {
			if node.Txid == newRoot || node.ParentTxid == newRoot {
				newTree := make(tree.VtxoTree, 0)
				newTree = append(newTree, []tree.Node{node})

				children := vtxoTree.Children(node.Txid)
				for len(children) > 0 {
					newTree = append(newTree, children)
					newChildren := make([]tree.Node, 0)
					for _, child := range children {
						newChildren = append(newChildren, vtxoTree.Children(child.Txid)...)
					}
					children = newChildren
				}

				return newTree, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to create subtree, new root not found")
}

func containsTree(tr0 tree.VtxoTree, tr1 tree.VtxoTree) (bool, error) {
	tr1Root, err := tr1.Root()
	if err != nil {
		return false, err
	}

	for _, level := range tr0 {
		for _, node := range level {
			if node.Txid == tr1Root.Txid {
				return true, nil
			}
		}
	}

	return false, nil
}

// assuming the pset is a leaf in the vtxo tree, returns the vtxo outpoint
func extractVtxoOutpoint(leaf tree.Node) (*domain.VtxoKey, error) {
	if !leaf.Leaf {
		return nil, fmt.Errorf("node is not a leaf")
	}
	return &domain.VtxoKey{
		Txid: leaf.Txid,
		VOut: 0,
	}, nil
}
