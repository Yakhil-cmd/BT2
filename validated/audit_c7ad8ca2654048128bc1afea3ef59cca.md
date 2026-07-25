### Title
Unlocked Map Iteration in `RemoveVotesAfter`/`RemoveGovAfter` Creates Data Race with Concurrent `AddVote`/`AddGov` — (`kaiax/gov/headergov/impl/rewind.go`)

### Summary

`RemoveVotesAfter` and `RemoveGovAfter` iterate over `h.groupedVotes` and `h.governances` respectively **without holding `h.mu`**, while acquiring and releasing the lock only for each individual `delete` call inside the loop. Concurrently, `AddVote` and `AddGov` (called from `PostInsertBlock` and the background `migrate()` goroutine) write to those same maps **while holding `h.mu`**. This is a classic Go data race: a map being ranged over without a lock while another goroutine writes to it under a lock is undefined behavior in Go's memory model.

### Finding Description

In `RemoveVotesAfter`:

```go
// rewind.go lines 20-31
for epochIdxIter, votes := range h.groupedVotes {   // ← NO LOCK held here
    for blockNumIter := range votes {                // ← NO LOCK held here
        if blockNumIter > blockNum {
            dirty = true
            h.mu.Lock()
            delete(h.groupedVotes[epochIdxIter], blockNumIter)
            if len(h.groupedVotes[epochIdxIter]) == 0 {
                delete(h.groupedVotes, epochIdxIter)
            }
            h.mu.Unlock()                            // ← released between iterations
        }
    }
}
``` [1](#0-0) 

The `range h.groupedVotes` at line 20 reads the map with no lock held. `AddVote` (called from `PostInsertBlock` and from the background `migrate()` goroutine) writes to `h.groupedVotes` under `h.mu.Lock()`: [2](#0-1) 

The same pattern exists in `RemoveGovAfter` for `h.governances`: [3](#0-2) 

The background `migrate()` goroutine is always running after `Start()` and continuously calls `accumulateVotesInEpoch` → `AddVote`, making the concurrent write path always live: [4](#0-3) 

There are **two distinct bugs**:

1. **Data race**: Concurrent map read (range, no lock) vs. map write (`AddVote`/`AddGov`, under lock) is undefined behavior in Go. The Go runtime can panic or silently corrupt memory.
2. **Semantic inconsistency**: Even if the data race were somehow benign, releasing the lock between iterations allows `PostInsertBlock` to insert a vote for a rewound block number between two delete iterations, leaving `h.groupedVotes` in a mixed pre-reorg/post-reorg state.

### Impact Explanation

`h.groupedVotes` drives epoch-end governance parameter computation. `h.governances` and `h.history` (rebuilt from `h.governances`) are the source for `GetParamSet`, which determines the `ParamSet` applied to every block: [5](#0-4) 

If `h.governances` or `h.groupedVotes` is left in a mixed pre-reorg/post-reorg state, the `ParamSet` returned for blocks after the reorg can be wrong — specifically the reward ratio, minting amount, or staking parameters — causing reward distribution divergence between nodes that experienced the race and those that did not.

### Likelihood Explanation

The background `migrate()` goroutine is always active, so the concurrent write path (`AddVote`) is always live. A reorg (triggering `RewindDelete`) is required to activate `RemoveVotesAfter`. In Kaia's BFT consensus, reorgs are rare but not impossible. The race window is narrow, making reliable exploitation difficult. However, the data race itself (undefined behavior) can manifest as a crash or silent corruption even without a deliberate attacker — any natural reorg during migration is sufficient.

### Recommendation

Hold `h.mu.Lock()` for the **entire** iteration in both `RemoveVotesAfter` and `RemoveGovAfter`, not just for each individual `delete`:

```go
func (h *headerGovModule) RemoveVotesAfter(blockNum uint64) {
    h.mu.Lock()
    defer h.mu.Unlock()
    dirty := false
    for epochIdxIter, votes := range h.groupedVotes {
        for blockNumIter := range votes {
            if blockNumIter > blockNum {
                dirty = true
                delete(h.groupedVotes[epochIdxIter], blockNumIter)
                if len(h.groupedVotes[epochIdxIter]) == 0 {
                    delete(h.groupedVotes, epochIdxIter)
                }
            }
        }
    }
    if dirty {
        WriteVoteDataBlockNums(h.ChainKv, h.VoteBlockNums())
    }
}
```

Note: `VoteBlockNums()` also acquires `h.mu.RLock()`, so it must be refactored to an unlocked internal helper when called under the write lock.

### Proof of Concept

Run the existing integration test suite with `-race` while injecting a concurrent reorg and block insertion:

```go
// Pseudocode integration test
go func() { module.RewindDelete(hash, reorgNum) }()
go func() { module.PostInsertBlock(newBlock) }()
// go test -race will report: concurrent map read and map write on h.groupedVotes
```

The race detector will fire on the `range h.groupedVotes` (no lock) vs. `h.groupedVotes[epochIdx] = ...` (under lock) pair, confirming the data race.

### Citations

**File:** kaiax/gov/headergov/impl/rewind.go (L18-38)
```go
func (h *headerGovModule) RemoveVotesAfter(blockNum uint64) {
	dirty := false
	for epochIdxIter, votes := range h.groupedVotes {
		for blockNumIter := range votes {
			if blockNumIter > blockNum {
				dirty = true
				h.mu.Lock()
				delete(h.groupedVotes[epochIdxIter], blockNumIter)

				// If all votes for this epoch have been removed, delete the epoch entry
				if len(h.groupedVotes[epochIdxIter]) == 0 {
					delete(h.groupedVotes, epochIdxIter)
				}
				h.mu.Unlock()
			}
		}
	}

	if dirty {
		WriteVoteDataBlockNums(h.ChainKv, h.VoteBlockNums())
	}
```

**File:** kaiax/gov/headergov/impl/rewind.go (L41-57)
```go
func (h *headerGovModule) RemoveGovAfter(blockNum uint64) {
	dirty := false
	for blockNumIter := range h.governances {
		if blockNumIter > blockNum {
			dirty = true
			h.mu.Lock()
			delete(h.governances, blockNumIter)
			h.mu.Unlock()
		}
	}

	if dirty {
		WriteGovDataBlockNums(h.ChainKv, h.GovBlockNums())
		h.mu.Lock()
		h.history = headergov.GovsToHistory(h.governances)
		h.mu.Unlock()
	}
```

**File:** kaiax/gov/headergov/impl/execution.go (L73-83)
```go
func (h *headerGovModule) AddVote(blockNum uint64, vote headergov.VoteData) {
	h.mu.Lock()
	defer h.mu.Unlock()

	epochIdx := calcEpochIdx(blockNum, h.epoch)

	if _, ok := h.groupedVotes[epochIdx]; !ok {
		h.groupedVotes[epochIdx] = make(headergov.VotesInEpoch)
	}
	h.groupedVotes[epochIdx][blockNum] = vote
}
```

**File:** kaiax/gov/headergov/impl/init.go (L151-177)
```go
func (h *headerGovModule) migrate() {
	defer h.wg.Done()

	// Scan all epochs in the background including 0th epoch
	pBorder := ReadLowestVoteScannedEpochIdx(h.ChainKv)
	if pBorder == nil {
		logger.Crit("Unexpected nil: lowest vote scanned epoch index")
		return
	}

	border := *pBorder

	for int64(border) > 0 {
		if h.quit.Load() == 1 {
			return
		}

		time.Sleep(migrationThrottlingDelay)

		border -= 1
		h.accumulateVotesInEpoch(border)
	}

	if border == 0 {
		logger.Info("HeaderGovModule migrate complete")
	}
}
```

**File:** kaiax/gov/headergov/impl/getter.go (L11-23)
```go
func (h *headerGovModule) GetParamSet(blockNum uint64) gov.ParamSet {
	h.mu.RLock()
	defer h.mu.RUnlock()

	prevEpochStart := PrevEpochStart(blockNum, h.epoch, h.isKoreHF(blockNum))
	gh := h.history
	gp, err := gh.Search(prevEpochStart)
	if err != nil {
		logger.Warn("No param set", "blockNum", blockNum, "prevEpochStart", prevEpochStart)
		return *gov.GetDefaultGovernanceParamSet()
	}
	return gp
}
```
