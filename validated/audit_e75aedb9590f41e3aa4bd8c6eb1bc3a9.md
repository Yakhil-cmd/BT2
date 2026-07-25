### Title
Unvalidated Peer-Supplied Staking Info Written to DB During Fast Sync Corrupts KAIA Reward Distribution — (`datasync/downloader/queue.go`)

---

### Summary

During fast sync, staking information (`P2PStakingInfo`) received from a remote peer is accepted with a deliberately empty validation function (marked `// TODO-Kaia-Snapsync update validation logic`). The fabricated data is written directly to the persistent staking DB and is subsequently used as the authoritative source for KAIA reward distribution, redirecting block rewards and fund allocations to attacker-controlled addresses.

---

### Finding Description

`DeliverStakingInfos` in `datasync/downloader/queue.go` registers a `validate` callback that unconditionally returns `nil`:

```go
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
``` [1](#0-0) 

Every other data type downloaded during fast sync performs cryptographic validation against the block header (e.g., receipts are checked against `header.ReceiptHash`):

```go
validate := func(index int, header *types.Header) error {
    if types.DeriveReceiptsRoot(...) != header.ReceiptHash {
        return errInvalidReceipt
    }
    return nil
}
``` [2](#0-1) 

Staking info has no equivalent check — no hash, no state-root proof, no AddressBook re-execution. The accepted `P2PStakingInfo` is then written unconditionally to the persistent DB in both `commitFastSyncData` and `commitPivotBlock`:

```go
if result.StakingInfo != nil {
    d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
}
``` [3](#0-2) [4](#0-3) 

`GetStakingInfo` for pre-Kaia blocks reads the DB **before** falling back to state:

```go
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        s.stakingInfoCache.Add(sourceNum, si)
        return si, nil
    }
}
``` [5](#0-4) 

Once the fabricated entry is in the DB it is served from cache and never re-verified against the chain state.

The same unvalidated write path is also reachable via the `admin_syncStakingInfo` RPC, which calls `SyncStakingInfo` and writes peer-supplied data with only a block-number equality check:

```go
if d.stakingInfoRecoveryBlocks[0] != stakingInfo.BlockNum {
    ...
    return
}
d.stakingModule.PutStakingInfoToDB(stakingInfo.BlockNum, staking.ToStakingInfo(stakingInfo))
``` [6](#0-5) 

---

### Impact Explanation

`StakingInfo` carries `RewardAddrs`, `StakingAmounts`, `KEFAddr`, and `KIFAddr`. These fields are consumed directly by `assignStakingRewards` and `specWithProposerAndFunds` during `FinalizeState`: [7](#0-6) 

A malicious peer can substitute:
- **`RewardAddrs`** → redirect per-validator KAIA block rewards to attacker wallets.
- **`StakingAmounts`** → inflate one validator's share, deflating all others.
- **`KEFAddr` / `KIFAddr`** → redirect the KEF/KIF fund portions (up to 54 % of minting amount on mainnet) to attacker-controlled addresses.

The corrupted value is the KAIA balance credited to each recipient address in every block finalized after the node completes fast sync.

---

### Likelihood Explanation

Fast sync is the default mode for new nodes joining the network. Any peer that the syncing node connects to can supply staking info for the requested block hashes. The attacker only needs to be a reachable, registered P2P peer — no validator key, no majority collusion, no admin access required for the fast-sync path. The `admin_syncStakingInfo` path additionally requires admin RPC access but is exposed in the public web3 extension: [8](#0-7) 

---

### Recommendation

In `DeliverStakingInfos`, replace the no-op `validate` function with a check that re-derives the staking info from the block's state root and compares it against the peer-supplied data, or at minimum verifies a cryptographic commitment (e.g., a Merkle proof against the AddressBook storage root embedded in the block header). Until that is implemented, `PutStakingInfoToDB` should be called only after local re-derivation from the canonical state, not from peer-supplied data.

---

### Proof of Concept

1. Attacker runs a Kaia node and connects as a peer to a victim node that is performing fast sync.
2. When the victim requests staking info for block hashes via `RequestStakingInfo`, the attacker's node intercepts the response path and returns a `P2PStakingInfo` with:
   - `CouncilRewardAddrs` replaced with attacker-controlled addresses.
   - `KEFAddr` / `KIFAddr` replaced with attacker-controlled addresses.
   - `CouncilStakingAmounts` inflated for the attacker's validator entry.
3. The victim's `handleStakingInfoMsg` calls `pm.downloader.DeliverStakingInfos`, which routes through `queue.DeliverStakingInfos`. The no-op `validate` function accepts the data unconditionally.
4. `commitFastSyncData` / `commitPivotBlock` calls `PutStakingInfoToDB`, persisting the fabricated entry.
5. After fast sync completes, every call to `GetStakingInfo` for the affected pre-Kaia block numbers returns the fabricated entry from DB (cache hit, state never re-read).
6. `FinalizeState` uses the fabricated `RewardAddrs` and fund addresses; KAIA minting rewards and fee distributions are credited to the attacker's addresses instead of the legitimate validators and funds.

### Citations

**File:** datasync/downloader/queue.go (L936-941)
```go
	validate := func(index int, header *types.Header) error {
		if types.DeriveReceiptsRoot(types.Receipts(receiptList[index]), header.Number) != header.ReceiptHash {
			return errInvalidReceipt
		}
		return nil
	}
```

**File:** datasync/downloader/queue.go (L956-959)
```go
	validate := func(index int, header *types.Header) error {
		// TODO-Kaia-Snapsync update validation logic
		return nil
	}
```

**File:** datasync/downloader/downloader.go (L673-677)
```go
					if d.stakingInfoRecoveryBlocks[0] != stakingInfo.BlockNum {
						logger.Error("failed to receive expected block", "expected", d.stakingInfoRecoveryBlocks[0], "actual", stakingInfo.BlockNum)
						return
					}
					d.stakingModule.PutStakingInfoToDB(stakingInfo.BlockNum, staking.ToStakingInfo(stakingInfo))
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

**File:** kaiax/reward/impl/getter.go (L488-533)
```go
func assignStakingRewards(config *reward.RewardConfig, stakersReward *big.Int, si *staking.StakingInfo) (map[common.Address]*big.Int, *big.Int) {
	var (
		cns               = si.ConsolidatedNodes()
		minStake          = config.MinimumStake.Uint64()
		totalExcessInt    = uint64(0) // sum of excess stakes (the amount over minStake) over all stakers
		cnTotalStakingMap = make(map[common.Address]uint64)
		isPrague          = config.Rules.IsPrague
	)
	for _, cn := range cns {
		// If the CNStaking is less than minStake, skip it.
		if cn.StakingAmount >= minStake {
			// Calculate total staking amount once
			cnTotalStakingAmount := cn.StakingAmount
			if isPrague && cn.CLStakingInfo != nil {
				cnTotalStakingAmount += cn.CLStakingInfo.CLStakingAmount
			}
			totalExcessInt += cnTotalStakingAmount - minStake
			cnTotalStakingMap[cn.RewardAddr] = cnTotalStakingAmount
		}
	}

	var (
		totalExcess = new(big.Int).SetUint64(totalExcessInt)
		remaining   = new(big.Int).Set(stakersReward)
		alloc       = make(map[common.Address]*big.Int)
	)
	for _, cn := range cns {
		cnTotalStakingAmount := cnTotalStakingMap[cn.RewardAddr]
		if cnTotalStakingAmount > minStake {
			// The KAIA unit will cancel out:
			// reward (kei) = excess (KAIA) * stakersReward (kei) / totalExcess (KAIA)
			excess := new(big.Int).SetUint64(cnTotalStakingAmount - minStake)
			if reward := new(big.Int).Div(new(big.Int).Mul(excess, stakersReward), totalExcess); reward.Sign() > 0 {
				if isPrague && cn.CLStakingInfo != nil {
					// The remaining amount will be added to the cnAmount.
					cnAmount, clAmount := cn.Split(reward)
					alloc[cn.RewardAddr] = cnAmount
					alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
				} else {
					alloc[cn.RewardAddr] = reward
				}
				remaining.Sub(remaining, reward)
			}
		}
	}
	return alloc, remaining
```

**File:** console/web3ext/web3ext.go (L508-516)
```go
		new web3._extend.Method({
			name: 'syncStakingInfo',
			call: 'admin_syncStakingInfo',
			params: 3,
		}),
		new web3._extend.Method({
			name: 'syncStakingInfoStatus',
			call: 'admin_syncStakingInfoStatus',
		}),
```
