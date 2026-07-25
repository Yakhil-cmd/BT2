### Title
VRankModule Omitted from Rewindable Module Registration Causes Stale Score State After Chain Rewind — (File: `node/cn/backend.go`)

---

### Summary

`VRankModule` implements `kaiax.RewindableModule` with working `RewindTo` and `RewindDelete` methods that clean up persistent checkpoint data, but it is never added to the `mRewindable` slice in `SetupKaiaxModules`. Every other module that holds block-number-keyed persistent state (`stakingModule`, `mSupply`, `govModule`, `mValset`, `mRandao`) is in that slice. `mVRank` is not. As a result, when `setHeadBeyondRoot` iterates `bc.rewindableModules` to call `RewindDelete` and `RewindTo`, the VRank module is silently skipped, leaving stale PFS/CFS checkpoint data in the database.

---

### Finding Description

In `node/cn/backend.go`, `SetupKaiaxModules` builds the rewindable module list:

```go
mRewindable := []kaiax.RewindableModule{s.stakingModule, mSupply, s.govModule, mValset, mRandao}
```

`mVRank` is absent. [1](#0-0) 

Yet `VRankModule` fully implements `RewindableModule`:

- `RewindTo` purges both in-memory caches (`pfsCache`, `cpMatrixCache`). [2](#0-1) 
- `RewindDelete` deletes the on-disk checkpoint at the deleted block number and rolls back the `lastCheckpointKey` pointer to the previous surviving checkpoint. [3](#0-2) 

The VRank module persists checkpoints every `VRankEpoch/8` blocks under `scoreCheckpointKey(blockNum)` and a `lastCheckpointKey` pointer, all written to `ChainKv` (the misc DB). [4](#0-3) 

When `setHeadBeyondRoot` runs (either via `debug_setHead` or automatic startup repair), it calls `module.RewindDelete(hash, num)` and `module.RewindTo(newHeadBlock)` only for modules in `bc.rewindableModules`. [5](#0-4) 

Because `mVRank` is not registered, neither call ever reaches the VRank module. The stale checkpoint data and the stale `lastCheckpointKey` pointer remain in the database.

On the next node start (or immediately after the rewind), `Init` calls `catchUpScoreCaches`, which reads `ReadLastCheckpoint` and replays blocks from that checkpoint forward. [6](#0-5) 

If the last checkpoint pointer still points to a block that was rewound and re-executed with a different canonical history, the seed PFS/CFS values are wrong. The module accumulates new per-block deltas on top of a corrupted base, producing permanently incorrect scores for the entire epoch.

---

### Impact Explanation

PFS (Proposal Failure Score) and CFS (Candidate Failure Score) determine which candidates are in `CandTesting` state in the permissionless validator system. `VerifyHeader` uses `GetCandTesting(N-1)` to validate every address in `header(N).VRank`, blocking invalid cfReports. [7](#0-6) 

Stale scores after a rewind can:
1. Incorrectly demote or promote validators/candidates, corrupting the active validator set.
2. Cause `VerifyHeader` to accept or reject headers based on a wrong candidate set, leading to consensus divergence between nodes that rewound and those that did not.
3. Persist across restarts because the corruption is in the on-disk misc DB, not only in memory.

This matches the allowed impact gate: **invalid state transition / consensus divergence on honest nodes** and **validator privilege escalation that changes protected chain state**.

---

### Likelihood Explanation

`setHeadBeyondRoot` is triggered automatically at node startup whenever the head block's state trie is missing (the `repair=true` path). [8](#0-7) 

This is a normal operational event (crash recovery, state pruning, snapshot recovery). No privileged API call or attacker action is required; any node that restarts after a crash while the VRank module has written at least one checkpoint will silently corrupt its scores.

---

### Recommendation

Add `mVRank` to the `mRewindable` slice in `SetupKaiaxModules`:

```go
// node/cn/backend.go
mRewindable := []kaiax.RewindableModule{s.stakingModule, mSupply, s.govModule, mValset, mRandao, mVRank}
```

This mirrors the pattern used by every other module that holds block-number-keyed persistent state and ensures `RewindDelete` and `RewindTo` are called on the VRank module during any chain rewind. [9](#0-8) 

---

### Proof of Concept

1. Start a node with the permissionless fork enabled. Let it mine past at least one VRank checkpoint interval (`VRankEpoch / 8` blocks). The VRank module writes a checkpoint and updates `lastCheckpointKey` in the misc DB.

2. Stop the node. Delete the state trie for the head block (simulating a crash or pruning event).

3. Restart the node. `NewBlockChain` detects the missing head state and calls `setHeadBeyondRoot` with `repair=true`, rewinding the chain. Because `mVRank` is not in `rewindableModules`, `RewindDelete` is never called. The stale checkpoint and `lastCheckpointKey` remain in the misc DB.

4. The node re-mines the rewound blocks. `Init` calls `catchUpScoreCaches`, reads the stale `lastCheckpointKey`, and seeds PFS/CFS from the old checkpoint. New per-block deltas are accumulated on top of the stale base.

5. Query `kaia_getPFS` or `kaia_getCFS` for any block in the rewound range. The returned scores differ from a node that was never rewound, demonstrating persistent score corruption that affects `CandTesting` state and `VerifyHeader` outcomes. [6](#0-5)

### Citations

**File:** node/cn/backend.go (L596-603)
```go
	mBase := []kaiax.BaseModule{s.stakingModule, mReward, mSupply, s.govModule, mValset, mRandao, mSystem, mVRank}
	mExecution := []kaiax.ExecutionModule{s.stakingModule, mSupply, s.govModule, mValset, mRandao}
	mTxBundling := []kaiax.TxBundlingModule{}
	mTxPool := []kaiax.TxPoolModule{}
	mJsonRpc := []kaiax.JsonRpcModule{s.stakingModule, mReward, mSupply, s.govModule, mValset, mRandao}
	mRewindable := []kaiax.RewindableModule{s.stakingModule, mSupply, s.govModule, mValset, mRandao}
	mHeader := []kaiax.HeaderModule{mReward, s.govModule, mRandao, mValset, mVRank}
	mBlockState := []kaiax.BlockStateModule{mReward, mSystem, mValset}
```

**File:** kaiax/vrank/impl/rewind.go (L24-27)
```go
func (v *VRankModule) RewindTo(newBlock *types.Block) {
	v.pfsCache.Purge()
	v.cpMatrixCache.Purge()
}
```

**File:** kaiax/vrank/impl/rewind.go (L31-52)
```go
func (v *VRankModule) RewindDelete(hash common.Hash, num uint64) {
	pfs := ReadCheckpointPFS(v.ChainKv, num)
	if pfs == nil {
		return
	}
	DeleteCheckpoint(v.ChainKv, num)

	lastCP, ok := ReadLastCheckpoint(v.ChainKv)
	if !ok || lastCP != num {
		return
	}

	cpInterval := v.scoreCheckpointInterval()
	for cpNum := num; cpNum >= cpInterval; cpNum -= cpInterval {
		prevCP := cpNum - cpInterval
		prevPFS := ReadCheckpointPFS(v.ChainKv, prevCP)
		if prevPFS != nil {
			WriteLastCheckpoint(v.ChainKv, prevCP)
			return
		}
	}
	DeleteLastCheckpoint(v.ChainKv)
```

**File:** kaiax/vrank/impl/schema.go (L98-128)
```go
}

// DeleteCheckpoint removes the checkpoint stored at blockNum.
func DeleteCheckpoint(db database.Database, blockNum uint64) {
	if err := db.Delete(scoreCheckpointKey(blockNum)); err != nil {
		logger.Crit("Failed to delete checkpoint", "blockNum", blockNum, "err", err)
	}
}

func calcCheckpointBlock(blockNum, checkpointInterval uint64) uint64 {
	return blockNum - (blockNum % checkpointInterval)
}

// ReadLastCheckpoint returns the block number of the most recently written checkpoint and true,
// or (0, false) if no checkpoint pointer has been written.
// Note: 0 is a valid checkpoint block number, so callers must check the bool.
func ReadLastCheckpoint(db database.Database) (uint64, bool) {
	b, err := db.Get(lastCheckpointKey)
	if err != nil || len(b) == 0 {
		return 0, false
	}
	return binary.BigEndian.Uint64(b), true
}

// WriteLastCheckpoint records blockNum as the most recently written checkpoint.
func WriteLastCheckpoint(db database.Database, blockNum uint64) {
	if err := db.Put(lastCheckpointKey, common.Int64ToByteBigEndian(blockNum)); err != nil {
		logger.Crit("Failed to write last checkpoint", "blockNum", blockNum, "err", err)
	}
}

```

**File:** blockchain/blockchain.go (L308-336)
```go
	head := bc.CurrentBlock()
	if _, err := state.New(head.Root(), bc.stateCache, bc.snaps, nil); err != nil {
		// Head state is missing, before the state recovery, find out the
		// disk layer point of snapshot(if it's enabled). Make sure the
		// rewound point is lower than disk layer.
		var diskRoot common.Hash
		if bc.cacheConfig.SnapshotCacheSize > 0 {
			diskRoot = bc.db.ReadSnapshotRoot()
		}
		if diskRoot != (common.Hash{}) {
			logger.Warn("Head state missing, repairing", "number", head.Number(), "hash", head.Hash(), "snaproot", diskRoot)

			snapDisk, err := bc.setHeadBeyondRoot(head.NumberU64(), diskRoot, true)
			if err != nil {
				return nil, err
			}

			// Chain rewound, persist old snapshot number to indicate recovery procedure
			if snapDisk != 0 {
				bc.db.WriteSnapshotRecoveryNumber(snapDisk)
			}
		} else {
			// Dangling block without a state associated, init from scratch
			logger.Warn("Head state missing, repairing chain",
				"number", head.NumberU64(), "hash", head.Hash().String())
			if _, err := bc.setHeadBeyondRoot(head.NumberU64(), common.Hash{}, true); err != nil {
				return nil, err
			}
		}
```

**File:** blockchain/blockchain.go (L629-644)
```go
	// Rewind the header chain, deleting all block bodies until then
	delFn := func(hash common.Hash, num uint64) {
		// Remove relative body, receipts, header-governance database,
		// istanbul snapshot database, and staking info database from the active store.
		// The header, total difficulty and canonical hash will be
		// removed in the hc.SetHead function.
		bc.db.DeleteBody(hash, num)
		bc.db.DeleteReceipts(hash, num)
		bc.db.DeleteGovernance(num)
		if params.IsCheckpointInterval(num) {
			bc.db.DeleteIstanbulSnapshot(hash)
		}

		for _, module := range bc.rewindableModules {
			module.RewindDelete(hash, num)
		}
```

**File:** kaiax/vrank/impl/init.go (L122-131)
```go
func (v *VRankModule) Init(opts *InitOpts) error {
	if opts == nil || opts.Valset == nil || opts.Randao == nil || opts.RoundReader == nil || opts.NodeKey == nil || opts.BlsKey == nil || opts.ChainConfig == nil || opts.ChainConfig.ChainID == nil || opts.Chain == nil || opts.ChainKv == nil {
		return vrank.ErrInitUnexpectedNil
	}
	v.InitOpts = *opts
	v.nodeID = crypto.PubkeyToAddress(opts.NodeKey.PublicKey)
	if err := v.catchUpScoreCaches(); err != nil {
		logger.Warn("Failed to catch up score caches, starting cold", "err", err)
	}
	return nil
```

**File:** kaiax/vrank/README.md (L132-132)
```markdown
  - `VerifyHeader(N)` calls `GetCandTesting(N-1)` to confirm every address in `header(N).VRank` is an actual candidate for the reported block `N-1`, blocking malicious proposers from injecting arbitrary addresses to manipulate CFS scores.
```
