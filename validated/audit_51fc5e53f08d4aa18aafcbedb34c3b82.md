### Title
Stale `transitionResultCache` After Reorg Causes Invalid ABv2 State Write and Consensus Divergence — (`kaiax/valset/impl/transition.go`, `kaiax/valset/impl/execution.go`)

---

### Summary

`transitionResultCache` is keyed only by block number (`uint64`). After a chain reorganization, neither `RewindTo` nor `RewindDelete` invalidates this cache. When `postInsertBlockPermissionless` is called for the reorg's replacement block N (with a different state root), `getTransitionResult(N+1, newParentStatedb)` hits the stale cache entry populated from the old chain and returns it — silently ignoring the new `parentStatedb`. The stale `TransitionResult.Nodes` is then used by `writeTransitionToABv2` to write wrong validator lifecycle states to AddressBookV2 in the state being built for block N+1, producing a block with an incorrect state root that honest peers reject.

---

### Finding Description

**Cache key ignores parent state root.**

`getTransitionResult` caches results keyed only by block number: [1](#0-0) 

On a cache hit, the `parentStatedb` argument is completely ignored: [2](#0-1) 

**`postInsertBlockPermissionless` populates the cache for N+1 using the inserted block's state root:** [3](#0-2) 

**`RewindTo` and `RewindDelete` do not clear `transitionResultCache`:** [4](#0-3) 

`RewindTo` only clears `validatorVoteBlockNumsCache`. `RewindDelete` only removes a council DB entry. Neither touches `transitionResultCache`.

**The cache is an LRU keyed by `uint64`:** [5](#0-4) 

---

### Impact Explanation

**Reorg scenario (reachable via P2P sync):**

1. Block N from chain A (state root R_A) is inserted → `postInsertBlockPermissionless` populates `transitionResultCache[N+1]` by reading ABv2 from R_A's state.
2. A sync peer delivers chain B's block N (state root R_B ≠ R_A), triggering a reorg.
3. `RewindTo`/`RewindDelete` are called — `transitionResultCache` is **not** cleared.
4. `postInsertBlockPermissionless(blockN_chainB)` is called → `getTransitionResult(N+1, statedb_R_B)` → **cache hit** → returns stale `TransitionResult` derived from R_A.
5. During block N+1 production, `writeTransitionToABv2` calls `getTransitionResult(N+1, statedb_N+1)`: [6](#0-5) 

6. Cache hit returns the stale result. The stale `tr.Nodes` (chain A's validator states) is diffed against chain B's committed ABv2 state and written to ABv2 via `SystemTxCall`: [7](#0-6) 

7. Block N+1 is produced with a wrong state root. Honest nodes that did not experience the reorg compute the correct state root and reject the block. The affected node cannot produce valid blocks — consensus divergence.

The `applyTransition` function reads ABv2 from the parent state, so two different parent state roots produce different `TransitionResult.Nodes`. The cache conflates them under the same key: [8](#0-7) 

---

### Likelihood Explanation

Reorgs are rare in Kaia's BFT but are possible during network partitions, initial sync, or when a node receives a competing chain from a sync peer. No privileged access is required — any P2P sync peer can deliver a competing block at height N. The `PostInsertBlock` → `postInsertBlockPermissionless` path is called for every inserted block, including reorg blocks.

---

### Recommendation

Fix the cache key to include the parent state root, e.g. key by `(num, parentStateRoot)`. Alternatively, invalidate `transitionResultCache` entries for block numbers ≥ the rewind target inside `RewindTo`:

```go
func (v *ValsetModule) RewindTo(block *types.Block) {
    rewindNum := block.Header().Number.Uint64()
    trimValidatorVoteBlockNums(v.ChainKv, rewindNum)
    v.validatorVoteBlockNumsCache = nil
    // Purge all cached results at or above the rewind point
    v.transitionResultCache.Purge()
}
```

Purging the entire cache on rewind is safe because `Start()` already does a full `Purge()`: [9](#0-8) 

---

### Proof of Concept

The existing test `TestPostInsertBlock_PermissionlessIgnoresVote` already demonstrates that `transitionResultCache` is pre-populated and used on cache hit without re-reading state: [10](#0-9) 

An integration test demonstrating the reorg path:
1. Insert block N (chain A, state root R_A) → `transitionResultCache[N+1]` populated from R_A.
2. Simulate reorg: call `RewindTo(blockN-1)`, then insert block N (chain B, state root R_B ≠ R_A).
3. Assert `transitionResultCache[N+1]` still holds chain A's result (stale).
4. Call `writeTransitionToABv2` for block N+1 and assert the ABv2 state written reflects chain A's nodes, not chain B's — confirming the corruption.

### Citations

**File:** kaiax/valset/impl/transition.go (L85-103)
```go
func (v *ValsetModule) getTransitionResult(num uint64, parentStatedb *state.StateDB) (*TransitionResult, error) {
	if num == 0 {
		return nil, errParentHeaderNotFound(num)
	}
	if cached, ok := v.transitionResultCache.Get(num); ok {
		return cached.(*TransitionResult), nil
	}

	// Read ABv2(N-1) + apply transitions for block N
	parentHeader := v.Chain.GetHeaderByNumber(num - 1)
	if parentHeader == nil {
		return nil, errParentHeaderNotFound(num)
	}
	result, err := v.applyTransition(parentHeader, parentStatedb)
	if err != nil {
		return nil, err
	}
	v.transitionResultCache.Add(num, result)
	return result, nil
```

**File:** kaiax/valset/impl/transition.go (L114-124)
```go
func (v *ValsetModule) applyTransition(header *types.Header, statedb *state.StateDB) (*TransitionResult, error) {
	// ABv2 read from state(header.Root), i.e. ABv2(N).
	abv2result, err := system.ReadABv2Snapshot(statedb, v.Chain, header)
	if err != nil {
		return nil, err
	}
	abv2result.Nodes.MarkSuspended(abv2result.SuspendedValidators)

	ctx := v.newTransitionContext(header, abv2result)
	return ctx.ApplyAllTransitions(abv2result.Nodes), nil
}
```

**File:** kaiax/valset/impl/transition.go (L210-212)
```go
	num := header.Number.Uint64()
	tr, err := v.getTransitionResult(num, statedb)
	if err != nil {
```

**File:** kaiax/valset/impl/transition.go (L225-240)
```go
	diff := diffNodeStates(parentRes.Nodes, tr.Nodes)

	// Skip the call if no changes and not an epoch block (epoch blocks need
	// the epochVACount snapshot update regardless)
	if len(diff) == 0 && !v.isVrankEpoch(num) {
		return nil
	}

	config := v.Chain.Config()
	from, msg, err := system.EncodeProcessSystemTransition(config.Rules(header.Number), diff, tr.epochVACountForWrite)
	if err != nil {
		logger.Error("Failed to encode processSystemTransition", "number", header.Number.Uint64(), "err", err.Error(), "nodes", diff.String())
		return err
	}
	if ret, err := blockchain.SystemTxCall(msg, from, header, vmenv, statedb, config.Rules(header.Number)); err != nil {
		return fmt.Errorf("processSystemTransition failed: %w (ret=%s)", err, common.Bytes2Hex(ret))
```

**File:** kaiax/valset/impl/execution.go (L37-46)
```go
func (v *ValsetModule) postInsertBlockPermissionless(block *types.Block) error {
	header := block.Header()
	nextNum := header.Number.Uint64() + 1
	parentStatedb, err := v.Chain.StateAt(header.Root)
	if err != nil {
		return err
	}
	_, err = v.getTransitionResult(nextNum, parentStatedb) // to cache the transition result
	return err
}
```

**File:** kaiax/valset/impl/execution.go (L66-73)
```go
func (v *ValsetModule) RewindTo(block *types.Block) {
	trimValidatorVoteBlockNums(v.ChainKv, block.Header().Number.Uint64())
	v.validatorVoteBlockNumsCache = nil
}

func (v *ValsetModule) RewindDelete(hash common.Hash, num uint64) {
	deleteCouncil(v.ChainKv, num)
}
```

**File:** kaiax/valset/impl/init.go (L68-68)
```go
	transitionResultCache *lru.Cache // uint64 -> *TransitionResult (permissionless)
```

**File:** kaiax/valset/impl/init.go (L136-139)
```go
	// Reset all caches
	v.proposerListCache.Purge()
	v.removeVotesCache.Purge()
	v.transitionResultCache.Purge()
```

**File:** kaiax/valset/impl/execution_test.go (L85-113)
```go
func TestPostInsertBlock_PermissionlessIgnoresVote(t *testing.T) {
	var (
		governingNode = numToAddr(3)
		voteAdd6, _   = headergov.NewVoteData(governingNode, string(gov.AddValidator), numToAddr(6)).ToVoteBytes()
		block1        = types.NewBlockWithHeader(&types.Header{
			Number: big.NewInt(1),
			Vote:   voteAdd6,
		})
	)

	ctrl := gomock.NewController(t)

	db := database.NewMemDB()
	mockChain := chain_mock.NewMockBlockChain(ctrl)
	mockChain.EXPECT().Config().Return(testPermissionlessConfig(0, 10)).AnyTimes()
	mockChain.EXPECT().StateAt(gomock.Any()).Return(nil, nil)

	v := NewValsetModule()
	v.ChainKv = db
	v.Chain = mockChain
	v.transitionResultCache.Add(uint64(2), &TransitionResult{
		Nodes: NodeMap{numToAddr(1): {State: ValActive}},
	})

	writeValidatorVoteBlockNums(db, []uint64{0})
	assert.NoError(t, v.PostInsertBlock(block1))
	assert.Equal(t, []uint64{0}, ReadValidatorVoteBlockNums(db))
	assert.Nil(t, ReadCouncil(db, 1))
}
```
