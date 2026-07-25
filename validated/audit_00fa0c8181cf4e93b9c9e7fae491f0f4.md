### Title
Unvalidated Peer-Supplied `StakingInfo.BlockNum` in FastSync Allows Arbitrary Staking DB Corruption — (`datasync/downloader/downloader.go`, `datasync/downloader/queue.go`)

---

### Summary

During FastSync/SnapSync, a malicious P2P peer can supply a `P2PStakingInfo` response whose `BlockNum` field is set to an arbitrary staking epoch boundary. Because `DeliverStakingInfos` performs no validation (explicitly marked `TODO`), and `commitPivotBlock`/`commitFastSyncData` blindly use `result.StakingInfo.BlockNum` as the DB write key, the attacker can overwrite any staking epoch entry in the local DB with forged validator addresses and treasury (KEF/KIF) addresses. After FastSync completes, `GetStakingInfo` reads the corrupted DB entry for pre-Kaia-fork blocks and uses it for block reward distribution, rerouting all rewards to attacker-controlled addresses.

---

### Finding Description

**Step 1 — No validation in `DeliverStakingInfos`**

In `queue.go`, the `validate` callback for staking info delivery is an explicit no-op stub:

```go
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
``` [1](#0-0) 

The `reconstruct` callback then blindly assigns the peer-supplied struct:

```go
reconstruct := func(index int, result *fetchResult) {
    result.StakingInfo = stakingInfoList[index]
    result.SetStakingInfoDone()
}
``` [2](#0-1) 

Neither the `BlockNum` field nor any content field (`CouncilRewardAddrs`, `KEFAddr`, `KIFAddr`) is checked against the header the staking info was requested for.

**Step 2 — `commitPivotBlock` uses peer-supplied `BlockNum` as DB key**

```go
if result.StakingInfo != nil {
    d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
``` [3](#0-2) 

`block.Number()` (the actual pivot block number) is never compared to `result.StakingInfo.BlockNum`. The same pattern exists in `commitFastSyncData`: [4](#0-3) 

**Step 3 — `PutStakingInfoToDB` writes to the attacker-chosen key**

```go
func (s *StakingModule) PutStakingInfoToDB(sourceNum uint64, stakingInfo *staking.StakingInfo) {
    WriteStakingInfo(s.ChainKv, sourceNum, stakingInfo)
}
``` [5](#0-4) 

The DB key is `"stakingInfo" || Uint64LE(sourceNum)`, so the attacker controls which epoch slot is overwritten.

**Step 4 — `GetStakingInfo` trusts the DB for pre-Kaia-fork blocks**

```go
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        s.stakingInfoCache.Add(sourceNum, si)
        return si, nil
    }
}
``` [6](#0-5) 

For pre-Kaia-fork blocks, the DB is the authoritative source. If the DB entry at epoch M is corrupted, `GetStakingInfo` returns the forged data without re-deriving from state. State re-derivation (`getFromStateByNumber`) would fail anyway for pre-pivot epochs because FastSync does not download historical state.

**Step 5 — Staking info is only fetched during FastSync for pre-Kaia-fork epoch boundaries**

```go
if (fastSync || snapSync) && proposerPolicy == uint64(istanbul.WeightedRandom) &&
    (header.Number.Uint64()%stakingUpdateInterval == 0 && !isKaiaFork) {
    item.pending |= (1 << stakingInfoType)
}
``` [7](#0-6) 

This confirms the attack surface is pre-Kaia-fork chains running FastSync/SnapSync with `WeightedRandom` proposer policy.

---

### Impact Explanation

A malicious peer can:
1. Respond to a `StakingInfoRequestMsg` for block hash H (epoch boundary N) with a `P2PStakingInfo` where `BlockNum = M` (a different epoch, e.g., `M = N - StakingInterval`, the epoch used as source for blocks just after the pivot).
2. Set `CouncilRewardAddrs`, `KEFAddr`, `KIFAddr` to attacker-controlled addresses.
3. The DB entry at key M is overwritten with forged data.
4. After FastSync, blocks processed in full sync mode whose `sourceBlockNum(num) == M` use the forged staking info.
5. All block rewards (validator rewards, KEF/KIF treasury distributions) for those blocks are sent to attacker-controlled addresses — unauthorized rerouting of KAIA block rewards.

---

### Likelihood Explanation

- Requires the victim node to be in FastSync/SnapSync mode on a pre-Kaia-fork chain with `WeightedRandom` proposer policy.
- The attacker only needs to be a connected P2P peer — no privileged access required.
- The `TODO` comment in `DeliverStakingInfos` confirms this is a known gap, not an intentional design choice.

---

### Recommendation

1. In `queue.go` `DeliverStakingInfos`, validate that `stakingInfoList[index].BlockNum` equals `header.Number.Uint64()` (the block number the staking info was requested for). Reject the delivery if they differ.
2. In `commitPivotBlock` and `commitFastSyncData`, assert `result.StakingInfo.BlockNum == result.Header.Number.Uint64()` before calling `PutStakingInfoToDB`.
3. Optionally, cross-check the staking info content against the block's state root after FastSync completes.

---

### Proof of Concept

```
Given: StakingInterval = 1000, pivot block P = 5000, pre-Kaia-fork chain.

1. Honest node starts FastSync, requests staking info for block 5000 (hash H5000).
2. Malicious peer responds with P2PStakingInfo{
       BlockNum: 4000,  // ← attacker-chosen epoch (source for blocks 5001-5999)
       CouncilRewardAddrs: [attacker_addr],
       KEFAddr: attacker_addr,
       KIFAddr: attacker_addr,
   }
3. DeliverStakingInfos: validate() returns nil (TODO stub), result.StakingInfo = forged.
4. commitPivotBlock: PutStakingInfoToDB(4000, forged_data) → DB["stakingInfo"||LE(4000)] = forged.
5. FastSync completes. Node begins full sync from block 5001.
6. For block 5001: sourceBlockNum(5001) = RoundDown(5000, 1000) - 1000 = 4000.
   GetStakingInfo(5001) → ReadStakingInfo(db, 4000) → returns forged data → cache hit.
7. Block rewards for 5001..5999 are distributed to attacker_addr.
```

### Citations

**File:** datasync/downloader/queue.go (L95-98)
```go
	if (fastSync || snapSync) && proposerPolicy == uint64(istanbul.WeightedRandom) &&
		(header.Number.Uint64()%stakingUpdateInterval == 0 && !isKaiaFork) {
		item.pending |= (1 << stakingInfoType)
	}
```

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

**File:** kaiax/staking/impl/schema.go (L73-74)
```go
func (s *StakingModule) PutStakingInfoToDB(sourceNum uint64, stakingInfo *staking.StakingInfo) {
	WriteStakingInfo(s.ChainKv, sourceNum, stakingInfo)
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
