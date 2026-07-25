### Title
Unauthenticated P2P StakingInfo Accepted and Persisted During Fast Sync, Corrupting Block Reward Distribution — (`datasync/downloader/queue.go`, `datasync/downloader/downloader.go`)

---

### Summary

During fast sync, a malicious peer can supply a `P2PStakingInfo` with attacker-controlled `CouncilRewardAddrs`. The delivery validation function is a no-op stub, and `commitFastSyncData` writes the staking info to the persistent DB without any cross-check against the pivot block's state root. After sync, `GetStakingInfo` reads from DB first and trusts it unconditionally, causing block rewards to be distributed to attacker-controlled addresses for the lifetime of the node.

---

### Finding Description

**Step 1 — No-op validation in `DeliverStakingInfos`**

In `datasync/downloader/queue.go`, the `validate` callback for staking info delivery is explicitly left empty with a TODO:

```go
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
``` [1](#0-0) 

Unlike receipts, which are validated against `header.ReceiptHash` before being accepted, staking info from any peer is accepted unconditionally. The `reconstruct` function then places the attacker-supplied `P2PStakingInfo` directly into the `fetchResult`: [2](#0-1) 

**Step 2 — Non-blocking state-sync check in `commitFastSyncData`**

The `select` in `commitFastSyncData` is non-blocking due to the `default` arm. If state sync is still in progress, execution falls through to `default` and the function proceeds: [3](#0-2) 

Even if state sync has completed, there is no check that the staking info content matches what the state trie encodes. The write to DB happens unconditionally: [4](#0-3) 

The same pattern exists in `commitPivotBlock`: [5](#0-4) 

**Step 3 — DB-first read in `GetStakingInfo` trusts poisoned data**

After fast sync, `GetStakingInfo` reads from the DB before falling back to state derivation. If a DB entry exists (which the attacker has poisoned), it is returned immediately without re-verification: [6](#0-5) 

`PostInsertBlock` calls `GetStakingInfo` for every new block before Kaia fork, so the poisoned `RewardAddrs` are used for every subsequent reward distribution: [7](#0-6) 

**Step 4 — `PutStakingInfoToDB` writes directly with no authentication** [8](#0-7) 

---

### Impact Explanation

An attacker who acts as a sync peer can redirect block rewards (`RewardAddrs` / `CouncilRewardAddrs`) to attacker-controlled addresses for all blocks processed after the victim completes fast sync. This is a persistent, durable corruption of the reward distribution mechanism — an explicit allowed impact ("unauthorized reward distribution affecting KAIA"). The poisoned DB entry survives node restarts because `GetStakingInfo` reads from DB first and caches the result.

---

### Likelihood Explanation

- The attacker only needs to be a reachable P2P peer — a fully public entrypoint.
- Fast sync is the default mode for new nodes joining the network.
- The attack applies to all pre-Kaia-fork staking intervals (the DB path is only used before Kaia fork, but that covers the entire historical range that fast-syncing nodes download).
- No cryptographic material, governance keys, or validator collusion is required.

---

### Recommendation

1. **Implement the missing validation** in `queue.go`'s `DeliverStakingInfos`. The staking info content should be verified against the canonical state trie at the corresponding block's state root before being accepted. The TODO comment acknowledges this gap explicitly.
2. **Do not write staking info to DB during fast sync** until after `FastSyncCommitHead` succeeds and the state root is confirmed. Defer the write to `PostInsertBlock` where the state is available for re-derivation.
3. **After fast sync**, invalidate any DB-cached staking info for the synced range and re-derive from state, rather than trusting peer-supplied data.

---

### Proof of Concept

```
1. Attacker runs a Kaia node and connects to a victim performing fast sync.
2. When the victim requests staking info for block N (a staking update interval block),
   the attacker returns a P2PStakingInfo with:
     BlockNum = N
     CouncilRewardAddrs = [attacker_address, attacker_address, ...]
3. queue.DeliverStakingInfos accepts it (validate is a no-op).
4. commitFastSyncData calls PutStakingInfoToDB(N, attacker_staking_info).
5. Fast sync completes; state root is verified for the pivot block's trie,
   but the staking info DB entry is never cross-checked.
6. Victim node starts processing new blocks. PostInsertBlock -> GetStakingInfo(M)
   -> sourceNum = N -> ReadStakingInfo(db, N) returns attacker's data.
7. Block rewards for all blocks in the staking interval are sent to attacker_address.
```

### Citations

**File:** datasync/downloader/queue.go (L956-958)
```go
	validate := func(index int, header *types.Header) error {
		// TODO-Kaia-Snapsync update validation logic
		return nil
```

**File:** datasync/downloader/queue.go (L961-964)
```go
	reconstruct := func(index int, result *fetchResult) {
		result.StakingInfo = stakingInfoList[index]
		result.SetStakingInfoDone()
	}
```

**File:** datasync/downloader/downloader.go (L1861-1869)
```go
	select {
	case <-d.quitCh:
		return errCancelContentProcessing
	case <-stateSync.done:
		if err := stateSync.Wait(); err != nil {
			return err
		}
	default:
	}
```

**File:** datasync/downloader/downloader.go (L1881-1884)
```go
		if result.StakingInfo != nil {
			d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
			logger.Info("Imported new staking information", "number", result.StakingInfo.BlockNum)
		}
```

**File:** datasync/downloader/downloader.go (L1896-1898)
```go
	if result.StakingInfo != nil {
		d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
		logger.Info("Imported new staking information on pivot block", "number", result.StakingInfo.BlockNum, "pivot", block.Number())
```

**File:** kaiax/staking/impl/getter.go (L57-63)
```go
	// Only before Kaia, try the database
	if !isKaia {
		if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
			s.stakingInfoCache.Add(sourceNum, si)
			return si, nil
		}
	}
```

**File:** kaiax/staking/impl/execution.go (L24-33)
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
```

**File:** kaiax/staking/impl/schema.go (L73-74)
```go
func (s *StakingModule) PutStakingInfoToDB(sourceNum uint64, stakingInfo *staking.StakingInfo) {
	WriteStakingInfo(s.ChainKv, sourceNum, stakingInfo)
```
