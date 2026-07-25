### Title
Stale `transitionResultCache` After Reorg Corrupts Permissionless Validator Set — (`kaiax/valset/impl/execution.go`, `kaiax/valset/impl/transition.go`)

---

### Summary

`RewindTo` does not purge `transitionResultCache`. After a reorg, `getTransitionResult` returns a stale `*TransitionResult` keyed only by block number, ignoring the new fork's state root. This causes `writeTransitionToABv2` (called from `InitializeState`) to write incorrect node-state diffs into the on-chain ABv2 contract, corrupting the permissionless validator set used for consensus.

---

### Finding Description

`RewindTo` in `execution.go` only trims the validator-vote block-number list and resets `validatorVoteBlockNumsCache`. It never touches `transitionResultCache`: [1](#0-0) 

`transitionResultCache` is an LRU cache keyed by `uint64` block number only: [2](#0-1) [3](#0-2) 

`getTransitionResult` checks the cache purely by number and returns immediately on a hit, completely ignoring the `parentStatedb` argument passed by the caller: [4](#0-3) 

After a reorg to block N, the cache still holds the `TransitionResult` for key `N+1` that was computed from the old fork's state root. When `postInsertBlockPermissionless` is called for the new block at height N, it calls `getTransitionResult(N+1, parentStatedb_new_fork)`: [5](#0-4) 

The cache hit at line 89–91 returns the old-fork result. The `parentStatedb` from the new fork is silently discarded.

The same stale result is then consumed by `writeTransitionToABv2` during `InitializeState` for the next block produced on the new fork: [6](#0-5) [7](#0-6) 

`writeTransitionToABv2` calls `getTransitionResult(num, statedb)` and uses the returned `Nodes` to compute the diff written to the on-chain ABv2 contract via `SystemTxCall`. With a stale result, the wrong diff is committed to chain state.

---

### Impact Explanation

The on-chain ABv2 contract receives a `processSystemTransition` call with node-state diffs derived from the old fork's `NodeMap`. This permanently corrupts the canonical ABv2 state for all subsequent blocks on the new fork. Downstream effects:

- `getNodes(num)` returns the wrong `NodeMap`, so the qualified validator set used for consensus diverges across nodes that experienced the reorg at different times.
- `writeTransitionToABv2` propagates the corruption forward: each subsequent block's diff is computed against the wrong baseline, compounding the divergence.

This satisfies the **consensus divergence** and **persistent corruption of canonical execution** impact gates.

---

### Likelihood Explanation

Reorgs are a normal part of chain operation and require no attacker action — they occur naturally from network latency. The only precondition is that the reorged blocks are in the permissionless fork era and that the old-fork `TransitionResult` for the reorged height was already cached (which `postInsertBlockPermissionless` guarantees for every inserted block). No privileged access, governance keys, or validator collusion is required.

---

### Recommendation

In `RewindTo`, purge or selectively evict all `transitionResultCache` entries with keys `>= block.Header().Number.Uint64()`:

```go
func (v *ValsetModule) RewindTo(block *types.Block) {
    trimValidatorVoteBlockNums(v.ChainKv, block.Header().Number.Uint64())
    v.validatorVoteBlockNumsCache = nil
    v.transitionResultCache.Purge() // invalidate stale fork entries
}
```

Alternatively, key the cache by `(blockNumber, parentHash)` or `(blockNumber, stateRoot)` so hits from a different fork are never returned.

---

### Proof of Concept

1. Start a node with the permissionless fork enabled from genesis.
2. Mine a chain to height N. Verify `transitionResultCache` has an entry for key `N+1`.
3. Trigger a reorg: introduce a competing fork at height N with different transactions that alter ABv2 state (e.g., a validator registration/deregistration).
4. Observe that `RewindTo(block_{N-1})` is called but `transitionResultCache` still holds the old-fork entry for `N+1`.
5. Insert the new-fork block at height N. `postInsertBlockPermissionless` calls `getTransitionResult(N+1, new_parentStatedb)` and gets a cache hit returning the old-fork `TransitionResult`.
6. When the next block is produced, `InitializeState` → `writeTransitionToABv2` writes the stale diff to ABv2.
7. Assert that the on-chain ABv2 `NodeMap` differs from what a fresh computation from the new fork's state would produce — confirming validator-set corruption.

### Citations

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

**File:** kaiax/valset/impl/execution.go (L66-69)
```go
func (v *ValsetModule) RewindTo(block *types.Block) {
	trimValidatorVoteBlockNums(v.ChainKv, block.Header().Number.Uint64())
	v.validatorVoteBlockNumsCache = nil
}
```

**File:** kaiax/valset/impl/init.go (L68-68)
```go
	transitionResultCache *lru.Cache // uint64 -> *TransitionResult (permissionless)
```

**File:** kaiax/valset/impl/init.go (L80-80)
```go
	transitionResultCache, _ := lru.New(128)
```

**File:** kaiax/valset/impl/transition.go (L89-91)
```go
	if cached, ok := v.transitionResultCache.Get(num); ok {
		return cached.(*TransitionResult), nil
	}
```

**File:** kaiax/valset/impl/transition.go (L205-212)
```go
func (v *ValsetModule) writeTransitionToABv2(
	vmenv *vm.EVM,
	header *types.Header,
	statedb *state.StateDB,
) error {
	num := header.Number.Uint64()
	tr, err := v.getTransitionResult(num, statedb)
	if err != nil {
```

**File:** kaiax/valset/impl/blockstate.go (L29-38)
```go
func (v *ValsetModule) InitializeState(header *types.Header, statedb *state.StateDB) {
	config := v.Chain.Config()
	if !config.IsPermissionlessForkEnabled(header.Number) {
		return
	}
	context := blockchain.NewEVMBlockContext(header, v.Chain, nil)
	vmenv := vm.NewEVM(context, vm.TxContext{}, statedb, config, &vm.Config{})
	if err := v.WriteTransitionToABv2(vmenv, header, statedb); err != nil {
		logger.Error("Failed to apply node transition to ABv2", "number", header.Number.Uint64(), "err", err)
	}
```
