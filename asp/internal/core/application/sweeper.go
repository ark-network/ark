package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	oceanwallet "github.com/ark-network/ark/internal/infrastructure/ocean-wallet"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

type sharedOutput struct {
	txid  string
	index uint32
}

type sweepEvent struct {
	congestionTree tree.CongestionTree
}

type sweeper struct {
	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scheduler   ports.SchedulerService

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

	allRounds, err := s.repoManager.Rounds().GetAllRounds(context.Background())
	if err != nil {
		return err
	}

	for _, round := range allRounds {
		task := s.createTask(sweepEvent{round.CongestionTree})
		task()
	}

	return nil
}

func (s *sweeper) stop() {
	s.scheduler.Stop()
}

func (s *sweeper) removeTask(treeRootTxid string) {
	if _, scheduled := s.scheduledTasks[treeRootTxid]; scheduled {
		delete(s.scheduledTasks, treeRootTxid)
	}
}

func (s *sweeper) createTask(event sweepEvent) func() {
	return func() {
		root, err := event.congestionTree.Root()
		if err != nil {
			log.WithError(err).Error("error while getting root node")
			return
		}

		defer s.removeTask(root.Txid)

		ctx := context.Background()

		log.Debugf("sweeper: %s", root.Txid)

		sweepInputs := make([]ports.SweepInput, 0)
		vtxoKeys := make([]domain.VtxoKey, 0) // vtxos associated to the sweep inputs

		// inspect the congestion tree to find onchain shared outputs
		sharedOutputs, err := onchainOutputs(ctx, s.wallet, s.repoManager.Vtxos(), event.congestionTree)
		if err != nil {
			log.WithError(err).Error("error while inspecting congestion tree")
			return
		}

		for expiredAt, inputs := range sharedOutputs {
			// if the shared output is not expired, schedule a sweep task for it
			if expiredAt > time.Now().Unix() {
				subTrees := make([]tree.CongestionTree, 0)

				for _, input := range inputs {
					subTree, err := subTree(event.congestionTree, input.InputArgs.Txid)
					if err != nil {
						log.WithError(err).Error("error while finding sub tree")
						continue
					}

					subTrees = append(subTrees, subTree)
				}

				// filter out the sub trees, remove the ones that are included in others
				filteredSubTrees := make([]tree.CongestionTree, 0)
				for i, subTree := range subTrees {
					includedInOtherTrees := true

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
							includedInOtherTrees = false
							continue
						}
					}

					if includedInOtherTrees {
						filteredSubTrees = append(filteredSubTrees, subTree)
					}
				}

				for _, subTree := range filteredSubTrees {
					if err := s.schedule(int64(expiredAt)+30, sweepEvent{subTree}); err != nil {
						log.WithError(err).Error("error while scheduling sweep task")
						continue
					}
				}
				continue
			}

			// check if the shared output has been swept
			for _, input := range inputs {
				// check if input is the vtxo itself
				vtxos := make([]domain.VtxoKey, 0)

				vtxo, err := s.repoManager.Vtxos().GetVtxos(
					ctx,
					[]domain.VtxoKey{
						{
							Txid: input.InputArgs.Txid,
							VOut: input.InputArgs.TxIndex,
						},
					},
				)
				if err != nil {
					vtxosLeaves, err := event.congestionTree.FindLeaves(input.InputArgs.Txid, input.InputArgs.TxIndex)
					if err != nil {
						log.WithError(err).Error("error while finding vtxos leaves")
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
							vtxos = append(vtxos, domain.VtxoKey{
								Txid: leaf.Txid,
								VOut: 0,
							})
						case 3:
							vtxos = append(vtxos, domain.VtxoKey{
								Txid: leaf.Txid,
								VOut: 0,
							}, domain.VtxoKey{
								Txid: leaf.Txid,
								VOut: 1,
							})
						}
					}

				} else {
					vtxos = append(vtxos, vtxo[0].VtxoKey)
				}

				if len(vtxos) <= 0 {
					continue
				}

				firstVtxo, err := s.repoManager.Vtxos().GetVtxos(ctx, vtxos[:1])
				if err != nil {
					log.Error(fmt.Errorf("error while getting vtxo: %w", err))
					sweepInputs = append(sweepInputs, input) // add the input anyway in order to try to sweep it
					continue
				}

				// TODO: check if it has been redeemed
				if firstVtxo[0].Swept {
					// skip, the output is already swept
					continue
				}

				vtxoKeys = append(vtxoKeys, vtxos...)
				sweepInputs = append(sweepInputs, input)
			}
		}

		// build and broadcast the sweep tx
		// mark the vtxos as swept
		if len(sweepInputs) > 0 {
			sweepTx, err := s.builder.BuildSweepTx(s.wallet, sweepInputs)
			if err != nil {
				log.WithError(err).Error("error while building sweep tx")
				return
			}

			err = nil
			txid := ""
			// retry until the tx is broadcasted or the error is not BIP68 final
			for len(txid) == 0 && (err == nil || err == oceanwallet.NonBIP68Final) {
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

				if err := s.repoManager.Vtxos().SweepVtxos(ctx, vtxoKeys); err != nil {
					log.Error(fmt.Errorf("error while deleting vtxos: %w", err))
					return
				}

				log.Debugf("%d vtxos swept", len(vtxoKeys))
			}
		}
	}
}

func (s *sweeper) schedule(expirationTimestamp int64, sweepEvent sweepEvent) error {
	root, err := sweepEvent.congestionTree.Root()
	if err != nil {
		return err
	}

	if _, scheduled := s.scheduledTasks[root.Txid]; scheduled {
		return nil
	}

	task := s.createTask(sweepEvent)
	fancyTime := time.Unix(expirationTimestamp, 0).Format("2006-01-02 15:04:05")
	log.Debugf("scheduled sweep task at %s", fancyTime)
	if err := s.scheduler.ScheduleTaskOnce(expirationTimestamp, task); err != nil {
		return err
	}

	s.scheduledTasks[root.Txid] = struct{}{}
	return nil
}

// onchainOutputs inspects the given congestion tree and returns a map of onchain outputs where key is their expiration time
func onchainOutputs(
	ctx context.Context,
	wallet ports.WalletService,
	vtxoRepo domain.VtxoRepository,
	congestionTree tree.CongestionTree,
) (map[int64][]ports.SweepInput, error) {
	onchainOutputs := make(map[int64][]ports.SweepInput)
	blocktimeCache := make(map[string]int64) // txid -> blocktime
	nodesToCheck := congestionTree[0]        // init with the root

	for len(nodesToCheck) > 0 {
		newNodesToCheck := make([]tree.Node, 0)

		for _, node := range nodesToCheck {
			isOnchain, blocktime, err := wallet.TransactionExists(ctx, node.Txid)
			if err != nil {
				return nil, err
			}

			pset, err := psetv2.NewPsetFromBase64(node.Tx)
			if err != nil {
				return nil, err
			}

			// if the tx is onchain, it means that the input is spent
			// add the children to the nodes in order to check them during the next iteration
			if isOnchain {
				if blocktime <= 0 {
					return nil, fmt.Errorf("invalid blocktime")
				}

				// cache the blocktime for future use
				blocktimeCache[node.Txid] = int64(blocktime)

				// if the node is a leaf, the vtxos outputs should added as onchain outputs if they are not swept yet
				if node.Leaf {
					vtxos := make([]domain.VtxoKey, 0)
					vtxos = append(vtxos, domain.VtxoKey{
						Txid: node.Txid,
						VOut: 0,
					})
					if len(pset.Outputs) == 3 {
						vtxos = append(vtxos, domain.VtxoKey{
							Txid: node.Txid,
							VOut: 1,
						})
					}

					for _, vtxo := range vtxos {
						fromRepo, err := vtxoRepo.GetVtxos(ctx, []domain.VtxoKey{vtxo})
						if err != nil {
							log.WithError(err).Error("error while getting vtxo from repo")
							continue
						}

						if len(fromRepo) == 0 {
							continue
						}

						// TODO handle redemption case
						if fromRepo[0].Swept {
							continue
						}

						// if the vtxo is not swept or redeemed, add it to the onchain outputs

						// find the sweepTapLeaf (and lifetime to compute the expiration time)
						input := pset.Inputs[0]
						var lifetime int64
						var sweepLeaf *psetv2.TapLeafScript
						for _, leaf := range input.TapLeafScript {
							isSweep, _, seconds, err := tree.DecodeSweepScript(leaf.Script)
							if err != nil {
								return nil, err
							}
							if isSweep {
								lifetime = int64(seconds)
								sweepLeaf = &leaf
								break
							}
						}

						pubKeyBytes, err := hex.DecodeString(fromRepo[0].Pubkey)
						if err != nil {
							log.WithError(err).Error("error while decoding pubkey")
							continue
						}
						pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
						if err != nil {
							log.WithError(err).Error("error while parsing pubkey")
							continue
						}

						// craft the vtxo taproot tree
						vtxoScript, err := tree.VtxoScript(pubKey)
						if err != nil {
							log.WithError(err).Error("error while generating vtxo script")
							continue
						}

						vtxoTaprootTree := taproot.AssembleTaprootScriptTree(
							*vtxoScript,
							sweepLeaf.TapElementsLeaf,
						)

						proofIndex := vtxoTaprootTree.LeafProofIndex[sweepLeaf.TapHash()]
						proof := vtxoTaprootTree.LeafMerkleProofs[proofIndex]
						controlBlock := proof.ToControlBlock(sweepLeaf.ControlBlock.InternalKey)

						sweepInput := ports.SweepInput{
							InputArgs: psetv2.InputArgs{
								Txid:    vtxo.Txid,
								TxIndex: vtxo.VOut,
							},
							SweepLeaf: psetv2.TapLeafScript{
								TapElementsLeaf: sweepLeaf.TapElementsLeaf,
								ControlBlock:    controlBlock,
							},
							Amount: fromRepo[0].Amount,
						}

						expirationTime := blocktime + lifetime
						if _, ok := onchainOutputs[expirationTime]; !ok {
							onchainOutputs[expirationTime] = []ports.SweepInput{sweepInput}
						} else {
							onchainOutputs[expirationTime] = append(onchainOutputs[expirationTime], sweepInput)
						}
					}

					continue
				}

				children := congestionTree.Children(node.Txid)
				newNodesToCheck = append(newNodesToCheck, children...)

				continue
			}

			// if the tx is not onchain, it means that the input is an existing shared output
			input := pset.Inputs[0]
			txid := chainhash.Hash(input.PreviousTxid).String()
			index := input.PreviousTxIndex

			var lifetime int64
			var sweepLeaf *psetv2.TapLeafScript
			for _, leaf := range input.TapLeafScript {
				isSweep, _, seconds, err := tree.DecodeSweepScript(leaf.Script)
				if err != nil {
					log.WithError(err).Error("error while decoding sweep script")
					continue
				}
				if isSweep {
					lifetime = int64(seconds)
					sweepLeaf = &leaf
					break
				}
			}

			if sweepLeaf == nil || lifetime == 0 {
				return nil, fmt.Errorf("sweep leaf not found")
			}

			if _, ok := blocktimeCache[txid]; !ok {
				exist, blocktime, err := wallet.TransactionExists(ctx, txid)
				if !exist || err != nil {
					return nil, fmt.Errorf("tx %s not found", txid)
				}

				if blocktime <= 0 {
					return nil, fmt.Errorf("invalid blocktime")
				}

				blocktimeCache[txid] = blocktime
			}

			expirationTime := blocktimeCache[txid] + lifetime

			amount := uint64(0)
			for _, out := range pset.Outputs {
				amount += out.Value
			}

			sweepInput := ports.SweepInput{
				InputArgs: psetv2.InputArgs{
					Txid:    txid,
					TxIndex: index,
				},
				SweepLeaf: *sweepLeaf,
				Amount:    amount,
			}

			if _, ok := onchainOutputs[expirationTime]; !ok {
				onchainOutputs[expirationTime] = []ports.SweepInput{sweepInput}
			} else {
				onchainOutputs[expirationTime] = append(onchainOutputs[expirationTime], sweepInput)
			}
		}

		nodesToCheck = newNodesToCheck
	}

	return onchainOutputs, nil
}

func subTree(congestionTree tree.CongestionTree, newRoot string) (tree.CongestionTree, error) {
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
