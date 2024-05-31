package application

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	log "github.com/sirupsen/logrus"
)

// sweeper is an unexported service running while the main application service is started
// it is responsible for sweeping onchain shared outputs that expired
// it also handles delaying the sweep events in case some parts of the tree are broadcasted
// when a round is finalized, the main application service schedules a sweep event on the newly created congestion tree
type sweeper struct {
	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scheduler   ports.SchedulerService

	// cache of scheduled tasks, avoid scheduling the same sweep event multiple times
	scheduledTasks map[string]struct{}
}

func newSweeper(
	wallet ports.WalletService,
	repoManager ports.RepoManager,
	builder ports.TxBuilder,
	scheduler ports.SchedulerService,
) *sweeper {
	return &sweeper{
		wallet,
		repoManager,
		builder,
		scheduler,
		make(map[string]struct{}),
	}
}

func (s *sweeper) start() error {
	s.scheduler.Start()

	allRounds, err := s.repoManager.Rounds().GetSweepableRounds(context.Background())
	if err != nil {
		return err
	}

	for _, round := range allRounds {
		task := s.createTask(round.Txid, round.CongestionTree)
		task()
	}

	return nil
}

func (s *sweeper) stop() {
	s.scheduler.Stop()
}

// removeTask update the cached map of scheduled tasks
func (s *sweeper) removeTask(treeRootTxid string) {
	delete(s.scheduledTasks, treeRootTxid)
}

// schedule set up a task to be executed once at the given timestamp
func (s *sweeper) schedule(
	expirationTimestamp int64, roundTxid string, congestionTree tree.CongestionTree,
) error {
	if len(congestionTree) <= 0 { // skip
		log.Debugf("skipping sweep scheduling (round tx %s), empty congestion tree", roundTxid)
		return nil
	}

	root, err := congestionTree.Root()
	if err != nil {
		return err
	}

	if _, scheduled := s.scheduledTasks[root.Txid]; scheduled {
		return nil
	}

	task := s.createTask(roundTxid, congestionTree)
	fancyTime := time.Unix(expirationTimestamp, 0).Format("2006-01-02 15:04:05")
	log.Debugf("scheduled sweep for round %s at %s", roundTxid, fancyTime)
	if err := s.scheduler.ScheduleTaskOnce(expirationTimestamp, task); err != nil {
		return err
	}

	s.scheduledTasks[root.Txid] = struct{}{}

	if err := s.updateVtxoExpirationTime(congestionTree, expirationTimestamp); err != nil {
		log.WithError(err).Error("error while updating vtxo expiration time")
	}

	return nil
}

// createTask returns a function passed as handler in the scheduler
// it tries to craft a sweep tx containing the onchain outputs of the given congestion tree
// if some parts of the tree have been broadcasted in the meantine, it will schedule the next taskes for the remaining parts of the tree
func (s *sweeper) createTask(
	roundTxid string, congestionTree tree.CongestionTree,
) func() {
	return func() {
		ctx := context.Background()
		root, err := congestionTree.Root()
		if err != nil {
			log.WithError(err).Error("error while getting root node")
			return
		}

		s.removeTask(root.Txid)
		log.Debugf("sweeper: %s", root.Txid)

		sweepInputs := make([]ports.SweepInput, 0)
		vtxoKeys := make([]domain.VtxoKey, 0) // vtxos associated to the sweep inputs

		// inspect the congestion tree to find onchain shared outputs
		sharedOutputs, err := s.findSweepableOutputs(ctx, congestionTree)
		if err != nil {
			log.WithError(err).Error("error while inspecting congestion tree")
			return
		}

		for expiredAt, inputs := range sharedOutputs {
			// if the shared outputs are not expired, schedule a sweep task for it
			if time.Unix(expiredAt, 0).After(time.Now()) {
				subtrees, err := computeSubTrees(congestionTree, inputs)
				if err != nil {
					log.WithError(err).Error("error while computing subtrees")
					continue
				}

				for _, subTree := range subtrees {
					// mitigate the risk to get BIP68 non-final errors by scheduling the task 30 seconds after the expiration time
					if err := s.schedule(int64(expiredAt), roundTxid, subTree); err != nil {
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
					vtxosLeaves, err := congestionTree.FindLeaves(input.GetHash().String(), input.GetIndex())
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
			for len(txid) == 0 && (err == nil || strings.Contains(err.Error(), "non-BIP68-final")) {
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

// onchainOutputs iterates over all the nodes' outputs in the congestion tree and checks their onchain state
// returns the sweepable outputs as ports.SweepInput mapped by their expiration time
func (s *sweeper) findSweepableOutputs(
	ctx context.Context,
	congestionTree tree.CongestionTree,
) (map[int64][]ports.SweepInput, error) {
	sweepableOutputs := make(map[int64][]ports.SweepInput)
	blocktimeCache := make(map[string]int64) // txid -> blocktime
	nodesToCheck := congestionTree[0]        // init with the root

	for len(nodesToCheck) > 0 {
		newNodesToCheck := make([]tree.Node, 0)

		for _, node := range nodesToCheck {
			isConfirmed, blocktime, err := s.wallet.IsTransactionConfirmed(ctx, node.Txid)
			if err != nil {
				return nil, err
			}

			var expirationTime int64
			var sweepInput ports.SweepInput

			if !isConfirmed {
				if _, ok := blocktimeCache[node.ParentTxid]; !ok {
					isConfirmed, blocktime, err := s.wallet.IsTransactionConfirmed(ctx, node.ParentTxid)
					if !isConfirmed || err != nil {
						return nil, fmt.Errorf("tx %s not found", node.Txid)
					}

					blocktimeCache[node.ParentTxid] = blocktime
				}

				expirationTime, sweepInput, err = s.builder.GetSweepInput(blocktimeCache[node.ParentTxid], node)
				if err != nil {
					return nil, err
				}
			} else {
				// cache the blocktime for future use
				blocktimeCache[node.Txid] = int64(blocktime)

				// if the tx is onchain, it means that the input is spent
				// add the children to the nodes in order to check them during the next iteration
				// We will return the error below, but are we going to schedule the tasks for the "children roots"?
				if !node.Leaf {
					children := congestionTree.Children(node.Txid)
					newNodesToCheck = append(newNodesToCheck, children...)
					continue
				}
			}

			if _, ok := sweepableOutputs[expirationTime]; !ok {
				sweepableOutputs[expirationTime] = make([]ports.SweepInput, 0)
			}
			sweepableOutputs[expirationTime] = append(sweepableOutputs[expirationTime], sweepInput)
		}

		nodesToCheck = newNodesToCheck
	}

	return sweepableOutputs, nil
}

func (s *sweeper) updateVtxoExpirationTime(
	tree tree.CongestionTree,
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

func computeSubTrees(congestionTree tree.CongestionTree, inputs []ports.SweepInput) ([]tree.CongestionTree, error) {
	subTrees := make(map[string]tree.CongestionTree, 0)

	// for each sweepable input, create a sub congestion tree
	// it allows to skip the part of the tree that has been broadcasted in the next task
	for _, input := range inputs {
		subTree, err := computeSubTree(congestionTree, input.GetHash().String())
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
	filteredSubTrees := make([]tree.CongestionTree, 0)
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

func computeSubTree(congestionTree tree.CongestionTree, newRoot string) (tree.CongestionTree, error) {
	for _, level := range congestionTree {
		for _, node := range level {
			if node.Txid == newRoot || node.ParentTxid == newRoot {
				newTree := make(tree.CongestionTree, 0)
				newTree = append(newTree, []tree.Node{node})

				children := congestionTree.Children(node.Txid)
				for len(children) > 0 {
					newTree = append(newTree, children)
					newChildren := make([]tree.Node, 0)
					for _, child := range children {
						newChildren = append(newChildren, congestionTree.Children(child.Txid)...)
					}
					children = newChildren
				}

				return newTree, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to create subtree, new root not found")
}

func containsTree(tr0 tree.CongestionTree, tr1 tree.CongestionTree) (bool, error) {
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

// assuming the pset is a leaf in the congestion tree, returns the vtxo outpoint
func extractVtxoOutpoint(leaf tree.Node) (*domain.VtxoKey, error) {
	if !leaf.Leaf {
		return nil, fmt.Errorf("node is not a leaf")
	}
	return &domain.VtxoKey{
		Txid: leaf.Txid,
		VOut: 0,
	}, nil
}
