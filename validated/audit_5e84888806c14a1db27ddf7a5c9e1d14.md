The code path is fully traceable. Here is the analysis:

## Full Code Path Trace

**Step 1 — Request scheduling**: During fast-sync, `newFetchResult` marks a `fetchResult` as needing staking info only when `header.Number % stakingUpdateInterval == 0 && !isKaiaFork`. The request is sent by block hash via `FetchStakingInfo`. [1](#0-0) 

**Step 2 — Delivery with no validation**: When the peer responds, `queue.DeliverStakingInfos` calls the generic `deliver` with a `validate` callback that is explicitly a no-op: [2](#0-1) 

The `validate` function returns `nil` unconditionally with a `// TODO-Kaia-Snapsync update validation logic` comment. There is no check that `stakingInfoList[index].BlockNum` equals `header.Number`. The `reconstruct` callback blindly assigns the peer-supplied `P2PStakingInfo` (including its attacker-controlled `BlockNum`) to `result.StakingInfo`.

**Step 3 — DB write uses attacker-controlled key**: Both `commitFastSyncData` and `commitPivotBlock` call `PutStakingInfoToDB` using `result.StakingInfo.BlockNum` as the key, not `result.Header.Number`: [3](#0-2) [4](#0-3) 

**Step 4 — DB key is the lookup key**: `GetStakingInfo` for pre-Kaia blocks computes `sourceNum` and reads from DB at that key. If the attacker has written fake staking info at that key, it is returned directly: [5](#0-4) [6](#0-5) [7](#0-6) 

---

### Title
Missing `P2PStakingInfo.BlockNum` validation during fast-sync allows malicious peer to corrupt staking DB at arbitrary block numbers — (`datasync/downloader/queue.go`, `datasync/downloader/downloader.go`)

### Summary
A malicious P2P peer responding to staking info requests during fast-sync can set `P2PStakingInfo.BlockNum` to any value. Because the `validate` callback in `DeliverStakingInfos` is a no-op, the attacker-controlled `BlockNum` is used directly as the DB key in `PutStakingInfoToDB`, writing fake staking info at an arbitrary block number. Subsequent calls to `GetStakingInfo` for pre-Kaia blocks will read and return the corrupted entry, causing wrong reward distribution and wrong validator set selection.

### Finding Description
In `queue.DeliverStakingInfos`, the `validate` function is explicitly stubbed out:

```go
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
```

The `header` parameter (which carries the canonical block number from the locally-verified header chain) is never compared against `stakingInfoList[index].BlockNum`. The `reconstruct` callback then stores the raw peer-supplied `P2PStakingInfo` into `result.StakingInfo`. Both `commitFastSyncData` and `commitPivotBlock` subsequently call:

```go
d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
```

using the attacker-controlled `BlockNum` as the DB key.

### Impact Explanation
`GetStakingInfo` for pre-Kaia blocks reads from the DB at `sourceNum = roundDown(num-1, interval) - interval`. If the attacker writes fake staking info at that key, the node will use attacker-controlled `RewardAddrs` and `NodeIds` for reward distribution and validator set selection. This constitutes unauthorized redirection of block rewards (KAIA) to attacker-controlled addresses and potential validator set manipulation. [8](#0-7) 

### Likelihood Explanation
Any peer that connects to a fast-syncing node can respond to staking info requests. Fast-sync is the standard mode for new nodes. The attack requires only a single malicious connected peer and no special privileges.

### Recommendation
In `queue.DeliverStakingInfos`, implement the missing validation:

```go
validate := func(index int, header *types.Header) error {
    if stakingInfoList[index].BlockNum != header.Number.Uint64() {
        return errInvalidStakingInfo
    }
    return nil
}
```

This mirrors the existing receipt validation pattern which checks `DeriveReceiptsRoot` against `header.ReceiptHash`. [9](#0-8) 

### Proof of Concept
1. Syncing node enters fast-sync mode and requests staking info for block N (a multiple of `stakingUpdateInterval`).
2. Malicious peer responds with a `P2PStakingInfo{BlockNum: M, CouncilRewardAddrs: [attacker_addr, ...]}` where M is a different interval boundary.
3. `DeliverStakingInfos` calls `validate` → returns nil (no check).
4. `reconstruct` sets `result.StakingInfo = P2PStakingInfo{BlockNum: M, ...}`.
5. `commitFastSyncData` calls `PutStakingInfoToDB(M, ...)` — DB entry at key M is now attacker-controlled.
6. Any future call to `GetStakingInfo(num)` where `sourceBlockNum(num) == M` returns the fake staking info with `RewardAddrs = [attacker_addr]`.
7. Block rewards for that epoch are distributed to the attacker's address.

### Citations

**File:** datasync/downloader/queue.go (L95-98)
```go
	if (fastSync || snapSync) && proposerPolicy == uint64(istanbul.WeightedRandom) &&
		(header.Number.Uint64()%stakingUpdateInterval == 0 && !isKaiaFork) {
		item.pending |= (1 << stakingInfoType)
	}
```

**File:** datasync/downloader/queue.go (L936-941)
```go
	validate := func(index int, header *types.Header) error {
		if types.DeriveReceiptsRoot(types.Receipts(receiptList[index]), header.Number) != header.ReceiptHash {
			return errInvalidReceipt
		}
		return nil
	}
```

**File:** datasync/downloader/queue.go (L953-965)
```go
func (q *queue) DeliverStakingInfos(id string, stakingInfoList []*staking.P2PStakingInfo) (int, error) {
	q.lock.Lock()
	defer q.lock.Unlock()
	validate := func(index int, header *types.Header) error {
		// TODO-Kaia-Snapsync update validation logic
		return nil
	}

	reconstruct := func(index int, result *fetchResult) {
		result.StakingInfo = stakingInfoList[index]
		result.SetStakingInfoDone()
	}
	return q.deliver(id, q.stakingInfoTaskPool, q.stakingInfoTaskQueue, q.stakingInfoPendPool, stakingInfoReqTimer, len(stakingInfoList), validate, reconstruct)
```

**File:** datasync/downloader/downloader.go (L1881-1883)
```go
		if result.StakingInfo != nil {
			d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
			logger.Info("Imported new staking information", "number", result.StakingInfo.BlockNum)
```

**File:** datasync/downloader/downloader.go (L1896-1898)
```go
	if result.StakingInfo != nil {
		d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
		logger.Info("Imported new staking information on pivot block", "number", result.StakingInfo.BlockNum, "pivot", block.Number())
```

**File:** kaiax/staking/impl/getter.go (L48-79)
```go
func (s *StakingModule) GetStakingInfo(num uint64) (*staking.StakingInfo, error) {
	isKaia := s.ChainConfig.IsKaiaForkEnabled(new(big.Int).SetUint64(num))
	sourceNum := sourceBlockNum(num, isKaia, s.stakingInterval)

	// Try cache first
	if si, ok := s.stakingInfoCache.Get(sourceNum); ok {
		return si.(*staking.StakingInfo), nil
	}

	// Only before Kaia, try the database
	if !isKaia {
		if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
			s.stakingInfoCache.Add(sourceNum, si)
			return si, nil
		}
	}

	// Read from the state
	si, err := s.getFromStateByNumber(sourceNum)
	if err != nil {
		return nil, err
	}

	// Only before Kaia, write to database
	if !isKaia {
		WriteStakingInfo(s.ChainKv, sourceNum, si)
	}

	// Cache it
	s.stakingInfoCache.Add(sourceNum, si)
	return si, nil
}
```

**File:** kaiax/staking/impl/schema.go (L73-74)
```go
func (s *StakingModule) PutStakingInfoToDB(sourceNum uint64, stakingInfo *staking.StakingInfo) {
	WriteStakingInfo(s.ChainKv, sourceNum, stakingInfo)
```
