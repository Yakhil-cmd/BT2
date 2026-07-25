### Title
Off-by-one in `RemoveVotesAfter` retains stale epoch-boundary vote after reorg, causing consensus divergence — (`kaiax/gov/headergov/impl/rewind.go`)

---

### Summary

`RemoveVotesAfter` uses a strict `>` comparison instead of `>=`, so a vote recorded at exactly the rewound block number is never deleted from `groupedVotes`. When the deleted block is an epoch boundary, the stale vote persists and is later consumed by `getExpectedGovernance`, causing nodes that experienced the reorg to compute a different expected governance than nodes that were always on the canonical chain. This is a consensus-divergence path.

---

### Finding Description

`RewindDelete(hash, num)` is the hook called by the blockchain during a chain reorganization to remove all state associated with block `num`. [1](#0-0) 

It delegates vote cleanup to `RemoveVotesAfter(num)`: [2](#0-1) 

The inner condition on line 22 is:

```go
if blockNumIter > blockNum {   // strict greater-than
```

This means a vote stored at `blockNumIter == blockNum` (i.e., the vote that was embedded in the header of the block being deleted) is **never removed**. The correct condition is `>=`.

The same off-by-one exists in `RemoveGovAfter` at line 44, but the governance-at-boundary case is less dangerous because `VerifyGov` already enforces that governance only appears in epoch blocks. [3](#0-2) 

---

### Impact Explanation

After `RewindDelete(hash, N)` where `N = epoch * k`:

1. The vote at block `N` remains in `h.groupedVotes[k]` (in-memory) and is re-persisted to the DB via `WriteVoteDataBlockNums` on line 37 (because `dirty` was set by other deleted blocks, or not set at all if N was the only vote — in which case the stale entry is simply never cleaned up).

2. When the next epoch boundary `N + epoch` is processed, `getExpectedGovernance(N + epoch)` computes `prevEpochIdx = k` and reads `groupedVotes[k]`: [4](#0-3) 

3. The stale vote from the deleted block N is included in `govs`, producing a non-empty `GovData`.

4. `VerifyGov` then **requires** the epoch block at `N + epoch` to carry that governance payload: [5](#0-4) 

5. Nodes that were always on the canonical chain (and never saw block N) have no vote in `groupedVotes[k]`, so they compute an empty expected governance and accept a block with no governance field. The two sets of nodes now disagree on block validity → **consensus divergence**.

If the stale vote changes `reward.mintingamount` or another economic parameter, the divergence also results in unauthorized governance ratification of a parameter that was never on the canonical chain.

---

### Likelihood Explanation

- A validator who is the proposer at an epoch boundary block can trivially include a vote in that block's header (via the `Vote` RPC, which is a permissionless governance-trigger flow for any validator in `none`/`ballot` mode, or the governing node in `single` mode).
- Reorgs at epoch boundaries are uncommon but not rare on a live network; a single-block reorg is sufficient.
- No majority-validator collusion or key compromise is required; the bug fires on any honest node that processes the reorg.

---

### Recommendation

Change the comparison in `RemoveVotesAfter` from strict `>` to `>=`:

```go
// kaiax/gov/headergov/impl/rewind.go
if blockNumIter >= blockNum {   // was: blockNumIter > blockNum
```

Apply the same fix to `RemoveGovAfter` for consistency:

```go
if blockNumIter >= blockNum {   // was: blockNumIter > blockNum
```

---

### Proof of Concept

```
epoch = 100

1. Node A and Node B are in sync at block 99.
2. Proposer casts a vote (e.g., reward.mintingamount = X) at block 100
   (epoch boundary). Both nodes call PostInsertBlock(100) →
   AddVote(100, vote) → groupedVotes[1][100] = vote.
3. A one-block reorg occurs. Both nodes call RewindDelete(hash100, 100).
4. RemoveVotesAfter(100): condition is blockNumIter > 100, so the vote
   at blockNumIter==100 is NOT deleted. groupedVotes[1][100] = vote
   still present on both nodes.
5. Canonical chain continues without block 100's vote.
   Node C (never saw block 100) has groupedVotes[1] = {}.
6. At block 200 (next epoch boundary):
   - Nodes A/B: getExpectedGovernance(200) → prevEpochIdx=1 →
     groupedVotes[1] = {100: vote} → expected = {mintingamount: X}
     → VerifyGov requires Governance field to be present.
   - Node C: getExpectedGovernance(200) → groupedVotes[1] = {} →
     expected = {} → VerifyGov accepts block with no Governance field.
7. Nodes A/B and Node C reject each other's blocks → consensus split.
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

**File:** kaiax/gov/headergov/impl/header.go (L129-137)
```go
	// (2), (3)
	expected := h.getExpectedGovernance(header.Number.Uint64())
	if len(header.Governance) == 0 {
		if len(expected.Items()) != 0 {
			return ErrGovVerification
		}

		return nil
	}
```

**File:** kaiax/gov/headergov/impl/header.go (L218-233)
```go
func (h *headerGovModule) getExpectedGovernance(blockNum uint64) headergov.GovData {
	prevEpochIdx := calcEpochIdx(blockNum, h.epoch) - 1
	prevEpochVotes := h.getVotesInEpoch(prevEpochIdx)
	govs := make(gov.PartialParamSet)

	sortedVoteBlocks := slices.Collect(maps.Keys(prevEpochVotes))
	slices.Sort(sortedVoteBlocks)

	for _, voteBlock := range sortedVoteBlocks {
		vote := prevEpochVotes[voteBlock]
		govs.Add(string(vote.Name()), vote.Value())
	}

	// assert(len(headergov.NewGovData(govs).Items()) == len(govs))
	return headergov.NewGovData(govs)
}
```
