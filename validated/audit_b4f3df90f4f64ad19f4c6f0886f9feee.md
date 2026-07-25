I need to trace the full FastSync staking info delivery path carefully before rendering a verdict.

The code is clear enough to render a verdict. Let me trace the complete path:

**FastSync staking info delivery chain:**

1. `fetchStakingInfos` → `FetchStakingInfo` → `RequestStakingInfo(hashes)` — sends block hashes to the selected sync peer.
2. Peer responds → `handleStakingInfoMsg` → `pm.downloader.DeliverStakingInfos` → `d.deliver(id, d.stakingInfoCh, ...)` → `queue.DeliverStakingInfos`.
3. In `queue.DeliverStakingInfos`, `validate` is a confirmed no-op; `reconstruct` stores `stakingInfoList[accepted]` (with its attacker-controlled `BlockNum`) into `result.StakingInfo` with no cross-check against `header.Number.Uint64()`.
4. In `commitFastSyncData` / `commitPivotBlock`: `PutStakingInfoToDB(result.StakingInfo.BlockNum, ...)` — the DB key is the attacker-supplied `BlockNum`, not `result.Header.Number.Uint64()`.

**The `SyncStakingInfo` path** (admin RPC) does have a guard at line 673 (`if d.stakingInfoRecoveryBlocks[0] != stakingInfo.BlockNum { return }`), but the FastSync queue path has no equivalent guard.

**Fallback analysis:** `GetStakingInfo` falls back to state if the DB entry is missing, but during FastSync the node does not have state for pre-pivot blocks — the fallback fails, leaving the node with either missing or wrong staking info for the affected epoch.

**Impact scope:** The staking info DB is only used before the Kaia fork. After the Kaia fork, staking info is derived from state directly. So the corruption affects pre-Kaia-fork epoch reward distribution and validator selection. If the node later processes new blocks that are still in the pre-Kaia window, it would compute wrong rewards (wrong `RewardAddrs`, `KEFAddr`, `KIFAddr`), producing a divergent state root.

**Attack entry point:** Any P2P peer can connect to the victim. The `deliver` function's `pendPool[id]` check only requires the malicious peer to be the one selected for FastSync — achievable by any peer that connects and advertises a higher chain head.

---

### Title
No-op `validate` in `queue.DeliverStakingInfos` lets a malicious FastSync peer corrupt the staking info DB with an attacker-chosen epoch key — (`datasync/downloader/queue.go`)

### Summary
During FastSync, `queue.DeliverStakingInfos` accepts `P2PStakingInfo` responses from the sync peer without verifying that `P2PStakingInfo.BlockNum` matches the header number that triggered the request. The attacker-controlled `BlockNum` is then used verbatim as the database key in `PutStakingInfoToDB`, overwriting the staking info for an arbitrary pre-Kaia epoch and leaving the requested epoch's entry absent or wrong.

### Finding Description

`queue.DeliverStakingInfos` passes a no-op `validate` closure to the generic `deliver` function:

```go
// datasync/downloader/queue.go
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
``` [1](#0-0) 

The `reconstruct` closure then stores the raw peer-supplied `P2PStakingInfo` (including its `BlockNum`) into the result slot keyed by the *header*:

```go
reconstruct := func(index int, result *fetchResult) {
    result.StakingInfo = stakingInfoList[index]
    result.SetStakingInfoDone()
}
``` [2](#0-1) 

Later, `commitFastSyncData` and `commitPivotBlock` write to the DB using `result.StakingInfo.BlockNum` — the attacker-supplied value — not `result.Header.Number.Uint64()`:

```go
d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
``` [3](#0-2) [4](#0-3) 

`PutStakingInfoToDB` writes directly to the misc DB under key `"stakingInfo" || Uint64LE(sourceNum)`: [5](#0-4) 

By contrast, the `SyncStakingInfo` (admin RPC) path explicitly guards against this:

```go
if d.stakingInfoRecoveryBlocks[0] != stakingInfo.BlockNum {
    logger.Error("failed to receive expected block", ...)
    return
}
``` [6](#0-5) 

No equivalent guard exists in the FastSync queue path.

### Impact Explanation

The staking info DB is the authoritative source for pre-Kaia-fork epoch data:

```go
// Only before Kaia, try the database
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        return si, nil
    }
}
// Read from the state (fallback — unavailable for pre-pivot blocks during FastSync)
si, err := s.getFromStateByNumber(sourceNum)
``` [7](#0-6) 

A corrupted DB entry at epoch key K causes `GetStakingInfo` to return wrong `RewardAddrs`, `KEFAddr`, and `KIFAddr` for all blocks whose `SourceNum` resolves to K. This redirects validator block rewards and treasury fund allocations (KEF/KIF) to attacker-chosen addresses for the affected epoch. The state fallback is unavailable for pre-pivot blocks during FastSync, so there is no self-healing path.

### Likelihood Explanation

The attack requires only that the malicious node be a connected P2P peer selected as the FastSync source. Kaia's P2P network is permissionless; any node can connect and advertise a higher chain head to become the preferred sync peer. No keys, governance access, or validator collusion are needed. FastSync is the default mode for nodes catching up from genesis or after a long offline period.

### Recommendation

Replace the no-op `validate` closure in `queue.DeliverStakingInfos` with a check that enforces `stakingInfoList[index].BlockNum == header.Number.Uint64()`, mirroring the guard already present in `SyncStakingInfo`. Additionally, change `commitFastSyncData` and `commitPivotBlock` to use `result.Header.Number.Uint64()` as the DB key rather than the peer-supplied `result.StakingInfo.BlockNum`.

### Proof of Concept

1. Victim node enters FastSync from a malicious peer.
2. Malicious peer receives `RequestStakingInfo([hash_of_block_1000])`.
3. Malicious peer responds with `P2PStakingInfo{BlockNum: 999, CouncilRewardAddrs: [attacker_addr], ...}`.
4. `queue.DeliverStakingInfos` accepts it (no-op validate).
5. `commitFastSyncData` calls `PutStakingInfoToDB(999, ...)` — DB key 999 is overwritten with attacker data; key 1000 is never written.
6. When the node later calls `GetStakingInfo(sourceNum=999)`, it reads the corrupted entry and routes block rewards for that epoch to `attacker_addr`.

### Citations

**File:** datasync/downloader/queue.go (L956-959)
```go
	validate := func(index int, header *types.Header) error {
		// TODO-Kaia-Snapsync update validation logic
		return nil
	}
```

**File:** datasync/downloader/queue.go (L961-964)
```go
	reconstruct := func(index int, result *fetchResult) {
		result.StakingInfo = stakingInfoList[index]
		result.SetStakingInfoDone()
	}
```

**File:** datasync/downloader/downloader.go (L673-676)
```go
					if d.stakingInfoRecoveryBlocks[0] != stakingInfo.BlockNum {
						logger.Error("failed to receive expected block", "expected", d.stakingInfoRecoveryBlocks[0], "actual", stakingInfo.BlockNum)
						return
					}
```

**File:** datasync/downloader/downloader.go (L1882-1882)
```go
			d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
```

**File:** datasync/downloader/downloader.go (L1897-1897)
```go
		d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
```

**File:** kaiax/staking/impl/schema.go (L73-74)
```go
func (s *StakingModule) PutStakingInfoToDB(sourceNum uint64, stakingInfo *staking.StakingInfo) {
	WriteStakingInfo(s.ChainKv, sourceNum, stakingInfo)
```

**File:** kaiax/staking/impl/getter.go (L57-66)
```go
	// Only before Kaia, try the database
	if !isKaia {
		if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
			s.stakingInfoCache.Add(sourceNum, si)
			return si, nil
		}
	}

	// Read from the state
	si, err := s.getFromStateByNumber(sourceNum)
```
