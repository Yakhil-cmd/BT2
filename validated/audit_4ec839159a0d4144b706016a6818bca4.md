Now I have a complete picture of the code. Let me verify the `SyncStakingInfo` call site and the `commitFastSyncData` path to confirm the full attack chain.

### Title
Unvalidated P2P-delivered `P2PStakingInfo` written to DB during fast-sync poisons `stakingInfoCache` for pre-Kaia blocks — (`datasync/downloader/queue.go`, `datasync/downloader/downloader.go`)

---

### Summary

During fast-sync, staking info fetched from a remote P2P peer is accepted with **no content validation** and written directly to the staking DB via `PutStakingInfoToDB`. `GetStakingInfo` for pre-Kaia blocks reads the DB before falling back to state, so the poisoned entry is returned and cached in `stakingInfoCache` without ever being verified against on-chain state.

---

### Finding Description

**Step 1 — No-op validation in the delivery queue.**

`queue.DeliverStakingInfos` explicitly skips all content validation:

```go
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
``` [1](#0-0) 

Compare this to bodies (validated against `header.TxHash`) and receipts (validated against `header.ReceiptHash`): staking info has no equivalent commitment in the block header, and the TODO was never resolved.

**Step 2 — Fabricated data written to DB unconditionally.**

`commitFastSyncData` and `commitPivotBlock` both call `PutStakingInfoToDB` on whatever the peer delivered, with no further checks: [2](#0-1) [3](#0-2) 

**Step 3 — `GetStakingInfo` trusts the DB for pre-Kaia blocks.**

For pre-Kaia block numbers, `GetStakingInfo` reads the DB *before* falling back to state. If the DB entry exists (poisoned), it is cached and returned immediately without re-deriving from state: [4](#0-3) 

**Step 4 — P2P entry point is permissionless.**

`handleStakingInfoMsg` decodes the peer's response and forwards it to the downloader with no authentication: [5](#0-4) 

Any peer speaking `kaia/65+` can respond to a `StakingInfoRequestMsg` with arbitrary content.

**Step 5 — `SyncStakingInfo` recovery path has the same flaw.**

The staking-info recovery loop also calls `PutStakingInfoToDB` on peer-supplied data after only checking `BlockNum` ordering, with no cryptographic verification: [6](#0-5) 

---

### Impact Explanation

A malicious peer can replace the staking info for any pre-Kaia staking interval with fabricated `NodeIds`, `RewardAddrs`, and `StakingAmounts`. Once cached, all subsequent `GetStakingInfo` calls for that `sourceNum` return the attacker's data. This directly corrupts:

- **Reward distribution**: `RewardAddrs` and `StakingAmounts` drive block reward allocation.
- **Proposer/validator selection**: `NodeIds` and `StakingAmounts` feed the weighted-random proposer algorithm.

The poisoned DB entry persists across restarts because `GetStakingInfo` re-reads the DB on cache miss and re-caches the same poisoned value.

---

### Likelihood Explanation

Fast-sync is the default mode for any new or resyncing node. A single malicious peer in the P2P network can serve fabricated staking info for all requested pre-Kaia intervals. The attack requires no privileged access — only a valid `kaia/65` P2P connection.

---

### Recommendation

1. **Add content validation in `queue.DeliverStakingInfos`**: Resolve the TODO. Staking info must be verified against a commitment anchored in the block header (e.g., a hash of the staking info stored in the header's extra data or a dedicated field), or re-derived from state after fast-sync completes.
2. **Re-derive from state on first use post-sync**: After fast-sync, delete all DB-cached staking info entries and re-populate them from state on demand, bypassing the DB-first path.
3. **Treat DB entries as a cache, not a source of truth**: `GetStakingInfo` should verify DB entries against state at least once after sync, similar to how receipts are re-validated.

---

### Proof of Concept

```go
// Integration test sketch
func TestStakingInfoCachePoisoning(t *testing.T) {
    // 1. Set up a StakingModule with a real ChainKv and a mock Chain
    //    that returns a canonical StakingInfo from state.

    // 2. Write a fabricated StakingInfo to the DB directly via PutStakingInfoToDB,
    //    simulating what commitFastSyncData does with a peer-supplied P2PStakingInfo.
    fabricated := &staking.StakingInfo{
        SourceBlockNum: sourceNum,
        RewardAddrs:    []common.Address{attackerAddr},
        StakingAmounts: []uint64{999999},
    }
    module.PutStakingInfoToDB(sourceNum, fabricated)

    // 3. Call GetStakingInfo for a pre-Kaia block whose sourceNum matches.
    result, err := module.GetStakingInfo(blockNum)
    require.NoError(t, err)

    // 4. Assert: result should match on-chain state, not the fabricated DB entry.
    //    This assertion FAILS — result equals fabricated, not canonical state.
    assert.Equal(t, canonicalRewardAddr, result.RewardAddrs[0],
        "cache poisoned: DB entry returned without state verification")
}
``` [7](#0-6) [8](#0-7)

### Citations

**File:** datasync/downloader/queue.go (L956-959)
```go
	validate := func(index int, header *types.Header) error {
		// TODO-Kaia-Snapsync update validation logic
		return nil
	}
```

**File:** datasync/downloader/downloader.go (L672-679)
```go
				for _, stakingInfo := range stakingInfos {
					if d.stakingInfoRecoveryBlocks[0] != stakingInfo.BlockNum {
						logger.Error("failed to receive expected block", "expected", d.stakingInfoRecoveryBlocks[0], "actual", stakingInfo.BlockNum)
						return
					}
					d.stakingModule.PutStakingInfoToDB(stakingInfo.BlockNum, staking.ToStakingInfo(stakingInfo))
					fixed++
					d.stakingInfoRecoveryBlocks = d.stakingInfoRecoveryBlocks[1:]
```

**File:** datasync/downloader/downloader.go (L1881-1884)
```go
		if result.StakingInfo != nil {
			d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
			logger.Info("Imported new staking information", "number", result.StakingInfo.BlockNum)
		}
```

**File:** datasync/downloader/downloader.go (L1896-1899)
```go
	if result.StakingInfo != nil {
		d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
		logger.Info("Imported new staking information on pivot block", "number", result.StakingInfo.BlockNum, "pivot", block.Number())
	}
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

**File:** kaiax/staking/impl/schema.go (L73-75)
```go
func (s *StakingModule) PutStakingInfoToDB(sourceNum uint64, stakingInfo *staking.StakingInfo) {
	WriteStakingInfo(s.ChainKv, sourceNum, stakingInfo)
}
```
