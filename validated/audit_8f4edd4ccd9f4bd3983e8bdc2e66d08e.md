### Title
Concurrent Map Data Race in `RemoveVotesAfter` — (`kaiax/gov/headergov/impl/rewind.go`)

### Summary

`RemoveVotesAfter` iterates over `h.groupedVotes` with `range` while holding no lock for the duration of the outer loop. The mutex is only acquired and released *inside* each inner-loop iteration. The background `migrate` goroutine (and `PostInsertBlock`) call `AddVote`, which writes to `h.groupedVotes` under the lock. This creates a concurrent map read (the `range`) and map write (`AddVote`), which is an undefined-behavior data race in Go — detectable by the race detector and capable of causing a runtime panic or silently corrupting the map.

### Finding Description

In `RemoveVotesAfter`:

```go
// rewind.go:18-39
for epochIdxIter, votes := range h.groupedVotes {   // ← no lock held here
    for blockNumIter := range votes {
        if blockNumIter > blockNum {
            dirty = true
            h.mu.Lock()
            delete(h.groupedVotes[epochIdxIter], blockNumIter)
            if len(h.groupedVotes[epochIdxIter]) == 0 {
                delete(h.groupedVotes, epochIdxIter)
            }
            h.mu.Unlock()                            // ← lock released between outer iterations
        }
    }
}
``` [1](#0-0) 

The outer `range h.groupedVotes` begins and continues without holding `h.mu`. Between outer iterations the lock is released, allowing `AddVote` to run:

```go
// execution.go:73-83
func (h *headerGovModule) AddVote(blockNum uint64, vote headergov.VoteData) {
    h.mu.Lock()
    defer h.mu.Unlock()
    epochIdx := calcEpochIdx(blockNum, h.epoch)
    if _, ok := h.groupedVotes[epochIdx]; !ok {
        h.groupedVotes[epochIdx] = make(headergov.VotesInEpoch)
    }
    h.groupedVotes[epochIdx][blockNum] = vote
}
``` [2](#0-1) 

The background `migrate` goroutine is started unconditionally in `Start()` and calls `accumulateVotesInEpoch` → `AddVote` in a tight loop: [3](#0-2) 

`PostInsertBlock` also calls `HandleVote` → `AddVote` on every inserted block: [4](#0-3) 

`RewindDelete` (which calls `RemoveVotesAfter`) is invoked during chain reorg while `migrate` is still running in the background — a concurrent map read (`range`) and map write (`AddVote`) with no mutual exclusion for the full iteration window. [5](#0-4) 

### Impact Explanation

Go's runtime treats a concurrent map read and write as undefined behavior. The two concrete outcomes are:

1. **Runtime panic** (`concurrent map read and map write`) — the node crashes, causing a denial of service during any reorg while migration is active.
2. **Silent map corruption** — the `range` iterator skips or double-visits entries; votes from the rewound chain are not removed from `groupedVotes`, or votes from the new canonical chain are lost. `getExpectedGovernance` then derives the wrong `GovData` for the next epoch block, causing `VerifyGov` to accept an incorrect governance header or `PrepareHeader` to embed wrong parameters — invalid governance state applied to the chain. [6](#0-5) 

### Likelihood Explanation

The `migrate` goroutine runs continuously from `Start()` until `Stop()`. Any chain reorg (a normal network event, not requiring attacker control) that triggers `RewindDelete` while `migrate` is scanning historical epochs produces the race. On a node that started recently (migration not yet complete), this window is large.

### Recommendation

Hold `h.mu` for the **entire** duration of the outer iteration in `RemoveVotesAfter`, not just around individual deletes. Acquire the write lock once before the outer `for range` and release it after the loop completes (and before the DB write). The same pattern should be applied to `RemoveGovAfter`.

### Proof of Concept

```go
func TestRemoveVotesAfterRace(t *testing.T) {
    h := setupHeaderGovModule(t)
    // pre-populate two epochs
    h.AddVote(100, makeVote(...))
    h.AddVote(200, makeVote(...))

    var wg sync.WaitGroup
    wg.Add(2)
    go func() { defer wg.Done(); h.RemoveVotesAfter(50) }()
    go func() { defer wg.Done(); h.AddVote(300, makeVote(...)) }()
    wg.Wait()
}
// Run with: go test -race ./kaiax/gov/headergov/impl/...
// Expected: race detector reports "concurrent map read and map write"
```

### Citations

**File:** kaiax/gov/headergov/impl/rewind.go (L13-16)
```go
func (h *headerGovModule) RewindDelete(hash common.Hash, num uint64) {
	h.RemoveVotesAfter(num)
	h.RemoveGovAfter(num)
}
```

**File:** kaiax/gov/headergov/impl/rewind.go (L18-39)
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
}
```

**File:** kaiax/gov/headergov/impl/execution.go (L44-55)
```go
func (h *headerGovModule) HandleVote(blockNum uint64, vote headergov.VoteData) error {
	// if governance vote (i.e., not validator vote), add to vote
	if _, ok := gov.Params[vote.Name()]; ok {
		h.AddVote(blockNum, vote)
		InsertVoteDataBlockNum(h.ChainKv, blockNum)
	}

	// if the vote was mine, remove it.
	h.removeMyVote(vote)

	return nil
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

**File:** kaiax/gov/headergov/impl/header.go (L118-153)
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
```
