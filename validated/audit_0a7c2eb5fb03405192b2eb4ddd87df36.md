### Title
Silently Swallowed `PostInsertBlock` Errors in Miner Path Cause Validator-Set / Governance State Divergence on Proposer Node - (File: work/worker.go)

### Summary

In `work/worker.go`, the `handleFinalizedBlock` function invokes `PostInsertBlock` on every registered `ExecutionModule` but discards any returned error, only logging it. The identical call in `blockchain/blockchain.go:insertChain` (the sync/import path) correctly propagates the error and aborts insertion. Because the block is already committed to the chain before `PostInsertBlock` is called, a silent failure leaves the module's persistent state (validator council DB, governance vote/ratification cache, staking info, VRank checkpoints) permanently out of sync with the committed chain state on the proposer node.

### Finding Description

`work/worker.go` `handleFinalizedBlock` (the code path executed when the local node itself proposes and seals a block):

```go
// Invoke ExecutionModules after executing a block
for _, module := range self.executionModules {
    if err := module.PostInsertBlock(block); err != nil {
        logger.Error("Failed to call PostInsertBlock", "err", err)
        // ← error is discarded; execution continues
    }
}
``` [1](#0-0) 

The block has already been durably written to the chain at line 531 via `WriteBlockWithState` before this loop runs. [2](#0-1) 

The sync/import path in `blockchain/blockchain.go` handles the same call correctly — it returns the error, which aborts `insertChain` and prevents the inconsistency:

```go
for _, module := range bc.executionModules {
    if err := module.PostInsertBlock(block); err != nil {
        return i, events, coalescedLogs, err
    }
}
``` [3](#0-2) 

The execution modules whose `PostInsertBlock` can return a non-nil error include:

- **`ValsetModule`** — `postInsertBlockPermissioned` reads the council from DB (`getCouncilPermissioned`) and writes the updated council back; `postInsertBlockPermissionless` reads state via `Chain.StateAt` and caches the transition result. Either step can fail. [4](#0-3) 

- **`headerGovModule`** (via `GovModule`) — deserializes `header.Vote` and `header.Governance` and writes them to the in-memory cache and DB. [5](#0-4) 

- **`VRankModule`** — computes and writes PFS/CPMatrix checkpoints to DB. [6](#0-5) 

- **`StakingModule`** — persists staking info for the new block. [7](#0-6) 

### Impact Explanation

When `PostInsertBlock` fails silently on the miner path:

1. **Validator set divergence (most severe):** `ValsetModule` does not update the council DB for block N. Subsequent calls to `GetCouncil(N)` return the pre-N council. When the node proposes block N+1, it computes `qualified` validators from stale state and writes the wrong validator list into `header.Extra`. After the permissionless fork, `ValsetModule.VerifyHeader` on every peer checks `headerVals == qualified`; the proposer's block is rejected, causing consensus divergence on the proposer node. [8](#0-7) 

2. **Governance parameter divergence:** `headerGovModule` does not record the vote or ratification. `GetParamSet` returns stale parameters (e.g., wrong `GoverningNode`, wrong `UnitPrice`, wrong `MintingAmount`). Future blocks proposed by this node embed wrong governance data, which `VerifyGov` on peers will reject. [9](#0-8) 

3. **Reward / staking divergence:** Stale staking info causes `FinalizeState` to distribute rewards to wrong addresses or in wrong amounts, corrupting KAIA balances. [10](#0-9) 

### Likelihood Explanation

The trigger is a transient DB or state-access error during `PostInsertBlock` on the proposer node (e.g., disk I/O error, LevelDB compaction stall, or `StateAt` returning an error because the trie root is not yet flushed). These are realistic operational conditions, not exotic scenarios. The asymmetry with the sync path (which correctly propagates the error) confirms this is an unintentional omission rather than a deliberate design choice.

### Recommendation

Propagate the error from `PostInsertBlock` in `handleFinalizedBlock` the same way `insertChain` does. If the block is already committed and the error cannot be rolled back, the node should at minimum halt or trigger a re-sync rather than continuing with corrupted module state:

```go
for _, module := range self.executionModules {
    if err := module.PostInsertBlock(block); err != nil {
        logger.Crit("PostInsertBlock failed after block commit; node state is inconsistent", "num", block.NumberU64(), "err", err)
        // or: trigger re-sync / return to prevent further divergence
    }
}
```

### Proof of Concept

1. Run a Kaia node configured as a block proposer (validator).
2. Inject a transient DB write error (e.g., via fault injection or by filling the disk) timed to occur during `ValsetModule.PostInsertBlock` after `WriteBlockWithState` succeeds for a block containing a validator-set vote.
3. Observe that `work/worker.go:556` logs the error but the loop continues.
4. The council DB is not updated for that block number.
5. On the next block proposal, `ValsetModule.getQualifiedValidators` returns a stale validator list; the proposer writes the wrong set into `header.Extra`.
6. Peer nodes call `ValsetModule.VerifyHeader`, compute the correct `qualified` set, find `headerVals != qualified`, and reject the block — the proposer node is forked off the canonical chain.

### Citations

**File:** work/worker.go (L531-539)
```go
	writeResult, err := self.chain.WriteBlockWithState(block, work.receipts, work.state)
	if err != nil {
		if err == blockchain.ErrKnownBlock {
			logger.Debug("Tried to insert already known block", "num", block.NumberU64(), "hash", block.Hash().String())
		} else {
			logger.Error("Failed writing block to chain", "err", err)
		}
		return
	}
```

**File:** work/worker.go (L553-558)
```go
	// Invoke ExecutionModules after executing a block
	for _, module := range self.executionModules {
		if err := module.PostInsertBlock(block); err != nil {
			logger.Error("Failed to call PostInsertBlock", "err", err)
		}
	}
```

**File:** blockchain/blockchain.go (L2209-2214)
```go
		// Invoke ExecutionModules after inserting a block.
		for _, module := range bc.executionModules {
			if err := module.PostInsertBlock(block); err != nil {
				return i, events, coalescedLogs, err
			}
		}
```

**File:** kaiax/valset/impl/execution.go (L50-63)
```go
func (v *ValsetModule) postInsertBlockPermissioned(block *types.Block) error {
	header := block.Header()
	num := header.Number.Uint64()
	council, err := v.getCouncilPermissioned(num)
	if err != nil {
		return err
	}
	governingNode := v.GovModule.GetParamSet(num).GoverningNode
	if applyVote(header, council, governingNode) {
		insertValidatorVoteBlockNums(v.ChainKv, num)
		writeCouncil(v.ChainKv, num, council.List())
		v.validatorVoteBlockNumsCache = nil
	}
	return nil
```

**File:** kaiax/gov/headergov/impl/execution.go (L12-42)
```go
func (h *headerGovModule) PostInsertBlock(b *types.Block) error {
	if len(b.Header().Vote) > 0 {
		var vb headergov.VoteBytes = b.Header().Vote
		vote, err := vb.ToVoteData()
		if err != nil {
			logger.Error("ToVoteData error", "vote", vb, "err", err)
			return err
		}
		err = h.HandleVote(b.NumberU64(), vote)
		if err != nil {
			logger.Error("HandleVote error", "vote", vb, "err", err)
			return err
		}
	}

	if len(b.Header().Governance) > 0 {
		var gb headergov.GovBytes = b.Header().Governance
		gov, err := gb.ToGovData()
		if err != nil {
			logger.Error("DeserializeHeaderGov error", "governance", gb, "err", err)
			return err
		}
		err = h.HandleGov(b.NumberU64(), gov)
		if err != nil {
			logger.Error("HandleGov error", "governance", gb, "err", err)
			return err
		}
	}

	return nil
}
```

**File:** kaiax/vrank/impl/execution.go (L25-44)
```go
func (v *VRankModule) PostInsertBlock(block *types.Block) error {
	blockNum := block.NumberU64()
	if !v.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) {
		return nil
	}

	pfs, err := v.GetPFS(blockNum)
	if err != nil {
		return err
	}
	cpMatrix, err := v.getCPMatrix(blockNum)
	if err != nil {
		return err
	}

	if blockNum%v.scoreCheckpointInterval() == 0 {
		WriteCheckpoint(v.ChainKv, blockNum, pfs, cpMatrix)
		WriteLastCheckpoint(v.ChainKv, blockNum)
	}
	return nil
```

**File:** kaiax/staking/impl/execution.go (L24-34)
```go
func (s *StakingModule) PostInsertBlock(block *types.Block) error {
	isKaia := s.ChainConfig.IsKaiaForkEnabled(block.Number())
	if !isKaia {
		// Make sure the staking info for the new block is persisted.
		// The StakingInfo(sourceNum) will be persisted here, even if GetStakingInfo is never called elsewhere.
		if _, err := s.GetStakingInfo(block.NumberU64()); err != nil {
			return err
		}
	}
	return nil
}
```

**File:** kaiax/valset/impl/consensus.go (L32-48)
```go
func (v *ValsetModule) VerifyHeader(header *types.Header, _ *types.Header) error {
	if !v.Chain.Config().IsPermissionlessForkEnabled(header.Number) {
		return nil
	}
	num := header.Number.Uint64()
	headerVals, err := v.Chain.Sealer().Validators(header)
	if err != nil {
		return err
	}
	qualified, err := v.getQualifiedValidators(num)
	if err != nil {
		return err
	}
	if !slices.Equal(headerVals, qualified.List()) {
		return errMismatchedValidators
	}
	return nil
```

**File:** kaiax/gov/headergov/impl/header.go (L118-154)
```go
func (h *headerGovModule) VerifyGov(header *types.Header) error {
	// (1)
	if header.Number.Uint64()%h.epoch != 0 {
		if len(header.Governance) > 0 {
			logger.Error("governance is not allowed in non-epoch block", "num", header.Number.Uint64())
			return ErrGovInNonEpochBlock
		} else {
			return nil
		}
	}

	// (2), (3)
	expected := h.getExpectedGovernance(header.Number.Uint64())
	if len(header.Governance) == 0 {
		if len(expected.Items()) != 0 {
			return ErrGovVerification
		}

		return nil
	}

	// (4)
	var gb headergov.GovBytes = header.Governance
	actual, err := gb.ToGovData()
	if err != nil {
		logger.Error("DeserializeHeaderGov error", "num", header.Number.Uint64(), "governance", gb, "err", err)
		return err
	}

	// (5)
	if !reflect.DeepEqual(expected, actual) {
		logger.Error("Governance mismatch", "expected", expected, "actual", actual)
		return ErrGovVerification
	}

	return nil
}
```

**File:** kaiax/reward/impl/blockstate.go (L30-57)
```go
func (r *RewardModule) FinalizeState(header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) error {
	if r.GovModule.GetParamSet(header.Number.Uint64()).ProposerPolicy == uint64(istanbul.WeightedRandom) && common.EmptyHash(header.Root) {
		qualified, err := r.ValsetModule.GetQualifiedValidators(header.Number.Uint64())
		if err != nil {
			return err
		}
		useRewardAddress := valset.NewAddressSet(qualified).Contains(r.NodeAddress)

		if rewardAddr := r.GetRewardAddress(header.Number.Uint64(), r.NodeAddress); useRewardAddress && rewardAddr != (common.Address{}) {
			header.Rewardbase = rewardAddr
			logger.Trace("Use reward address for nodeValidator", "header.Number", header.Number.Uint64(), "nodeAddress", r.NodeAddress, "rewardbase", header.Rewardbase)
		} else {
			logger.Trace("No reward address for nodeValidator. Use node's rewardbase.", "header.Number", header.Number.Uint64(), "nodeAddress", r.NodeAddress, "rewardbase", header.Rewardbase)
		}
	}

	spec, err := r.GetDeferredReward(header, txs, receipts)
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
	return nil
}
```
