### Title
Unvalidated Peer-Supplied Staking Info Accepted During Fast Sync Corrupts Reward Distribution — (`datasync/downloader/queue.go`)

### Summary

During fast sync, staking information received from remote peers is stored directly into the persistent database without any content validation. The `validate` callback in `DeliverStakingInfos` is an explicit stub that unconditionally returns `nil`, marked with a `TODO-Kaia-Snapsync update validation logic` comment. A malicious connected peer can respond to staking-info fetch requests with fabricated data (wrong reward addresses, staking amounts, or node IDs), which is then persisted and later consumed by the reward module to distribute KAIA block rewards.

---

### Finding Description

`queue.DeliverStakingInfos` in `datasync/downloader/queue.go` is the delivery point for staking info packets received from peers during fast sync. Every other data type delivered through the same `queue.deliver` machinery has a real content validator:

- **Receipts**: validated against `header.ReceiptHash` via `types.DeriveReceiptsRoot`.

Staking info has none:

```go
// datasync/downloader/queue.go  lines 953-965
func (q *queue) DeliverStakingInfos(id string, stakingInfoList []*staking.P2PStakingInfo) (int, error) {
    q.lock.Lock()
    defer q.lock.Unlock()
    validate := func(index int, header *types.Header) error {
        // TODO-Kaia-Snapsync update validation logic
        return nil          // ← always nil, no check
    }
    reconstruct := func(index int, result *fetchResult) {
        result.StakingInfo = stakingInfoList[index]
        result.SetStakingInfoDone()
    }
    return q.deliver(id, q.stakingInfoTaskPool, q.stakingInfoTaskQueue,
        q.stakingInfoPendPool, stakingInfoReqTimer, len(stakingInfoList), validate, reconstruct)
}
``` [1](#0-0) 

The accepted `result.StakingInfo` is then written unconditionally to the persistent database in `commitFastSyncData`:

```go
// datasync/downloader/downloader.go  lines 1881-1884
if result.StakingInfo != nil {
    d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum,
        staking.ToStakingInfo(result.StakingInfo))
}
``` [2](#0-1) 

After fast sync completes, `GetStakingInfo` for pre-Kaia blocks reads from this database first, before falling back to state:

```go
// kaiax/staking/impl/getter.go  lines 58-63
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        s.stakingInfoCache.Add(sourceNum, si)
        return si, nil
    }
}
``` [3](#0-2) 

The staking info returned here is used directly by the reward module to compute `RewardSpec` — specifically the per-validator staking amounts and reward addresses that determine how KAIA block rewards are split and where they are sent. [4](#0-3) 

---

### Impact Explanation

A malicious peer that is assigned a staking-info fetch request during fast sync can respond with a `P2PStakingInfo` struct containing:

- Substituted `RewardAddrs` — redirecting KAIA block rewards to attacker-controlled addresses for every block in the affected staking interval.
- Inflated or zeroed `StakingAmounts` — distorting the KIP-82 staker-reward split, causing some validators to receive more or less KAIA than entitled.
- Replaced `NodeIds` / `StakingContracts` — altering which validators are considered eligible, potentially excluding legitimate validators from rewards entirely.

Because the DB entry is cached and returned before the state is consulted, the corruption persists across restarts and is not self-healing.

---

### Likelihood Explanation

Any node that connects to a syncing peer and is selected by the downloader's peer-assignment logic can supply staking info responses. No special privilege is required beyond being a connected P2P peer. Fast sync is the default mode for nodes catching up from genesis or after a long offline period. The attack window is the entire fast-sync phase, which can span thousands of staking-interval blocks.

---

### Recommendation

Implement a real content validator in `DeliverStakingInfos`, analogous to the receipt validator. The canonical approach is to derive a deterministic commitment from the staking info (e.g., a Merkle root or hash of the sorted `(nodeId, stakingContract, rewardAddr, amount)` tuples) and include it in the block header, then verify the received data against that commitment inside the `validate` callback. Until a header commitment is available, the fallback should be to skip the DB write and always derive staking info from state (`getFromStateByNumber`) for any block whose DB entry was populated during fast sync, or to mark fast-synced entries as unverified and re-derive them on first use.

---

### Proof of Concept

1. Attacker node connects to a victim node that is fast-syncing pre-Kaia history.
2. The downloader assigns a `StakingInfoRequest` for block hash `H` (a staking-interval block) to the attacker peer.
3. Attacker responds with a `StakingInfoMsg` containing a `P2PStakingInfo` where `RewardAddrs[i]` is replaced with an attacker-controlled address and `StakingAmounts[i]` is set to a large value.
4. `handleStakingInfoMsg` → `pm.downloader.DeliverStakingInfos` → `queue.DeliverStakingInfos` — the stub `validate` returns `nil`.
5. `commitFastSyncData` calls `PutStakingInfoToDB(blockNum, fakeInfo)`.
6. After fast sync, when the node processes the next full-sync block whose `sourceBlockNum` resolves to `blockNum`, `GetStakingInfo` reads the fake entry from DB (cache miss → DB hit → returns without touching state).
7. `getDeferredRewardFull` uses the fake `RewardAddrs` to credit KAIA rewards to the attacker's address instead of the legitimate validator's reward address. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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

**File:** datasync/downloader/downloader.go (L1881-1884)
```go
		if result.StakingInfo != nil {
			d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
			logger.Info("Imported new staking information", "number", result.StakingInfo.BlockNum)
		}
```

**File:** datasync/downloader/downloader.go (L1936-1941)
```go
func (d *Downloader) DeliverStakingInfos(id string, stakingInfos []*staking.P2PStakingInfo) error {
	if d.isStakingInfoRecovery {
		d.stakingInfoRecoveryCh <- stakingInfos
	}
	return d.deliver(id, d.stakingInfoCh, &stakingInfoPack{id, stakingInfos}, stakingInfoInMeter, stakingInfoDropMeter)
}
```

**File:** kaiax/staking/impl/getter.go (L58-63)
```go
	if !isKaia {
		if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
			s.stakingInfoCache.Add(sourceNum, si)
			return si, nil
		}
	}
```

**File:** kaiax/reward/impl/getter.go (L62-84)
```go
func (r *RewardModule) loadBlockData(num uint64) (*reward.RewardConfig, *types.Header, *big.Int, error) {
	block := r.Chain.GetBlockByNumber(num)
	if block == nil {
		return nil, nil, nil, reward.ErrNoBlock
	}
	receipts := r.Chain.GetReceiptsByBlockHash(block.Hash())
	if receipts == nil {
		return nil, nil, nil, reward.ErrNoReceipts
	}
	header := block.Header()
	txs := block.Transactions()

	config, err := reward.NewRewardConfig(r.ChainConfig, r.GovModule, header)
	if err != nil {
		return nil, nil, nil, err
	}
	execFee, err := getExecFee(config, header, txs, receipts)
	if err != nil {
		return nil, nil, nil, err
	}

	return config, header, execFee, nil
}
```

**File:** node/cn/handler.go (L1198-1213)
```go
// handleStakingInfoMsg handles staking information response message.
func handleStakingInfoMsg(pm *ProtocolManager, p Peer, msg p2p.Msg) error {
	if pm.chainconfig.Istanbul == nil || pm.chainconfig.Istanbul.ProposerPolicy != uint64(istanbul.WeightedRandom) {
		return errResp(ErrUnsupportedEnginePolicy, "the engine is not istanbul or the policy is not weighted random")
	}

	// A batch of stakingInfos arrived to one of our previous requests
	var stakingInfos []*staking.P2PStakingInfo
	if err := msg.Decode(&stakingInfos); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	// Deliver all to the downloader
	if err := pm.downloader.DeliverStakingInfos(p.GetID(), stakingInfos); err != nil {
		logger.Debug("Failed to deliver staking information", "err", err)
	}
	return nil
```
