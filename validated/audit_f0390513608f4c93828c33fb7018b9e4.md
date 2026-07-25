### Title
Unverified P2P-Supplied `StakingInfo` Written Directly to Database Corrupts Reward-Address and Treasury-Fund Distribution — (`datasync/downloader/downloader.go`, `datasync/downloader/queue.go`)

---

### Summary

During fast-sync and the explicit staking-info recovery flow (`SyncStakingInfo`), `P2PStakingInfo` objects received from a remote peer are written verbatim to the local database via `PutStakingInfoToDB` without any cross-check against the on-chain AddressBook state. The queue-level validation callback is an acknowledged no-op. Because `GetStakingInfo` prefers the database over the state trie for all blocks before the Kaia hardfork, a malicious peer can permanently substitute arbitrary `RewardAddrs`, `KEFAddr`, `KIFAddr`, and `StakingAmounts` values. Those values are consumed directly by the reward-distribution engine, redirecting block rewards and treasury allocations to attacker-controlled addresses.

---

### Finding Description

**Persistent schema and priority**

`StakingInfo` is serialised as JSON and stored under the key `"stakingInfo" || Uint64LE(num)` in the misc database. [1](#0-0) 

`GetStakingInfo` reads the database first and returns immediately on a hit, bypassing any state-trie derivation:

```go
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        s.stakingInfoCache.Add(sourceNum, si)
        return si, nil   // ← returned without state verification
    }
}
``` [2](#0-1) 

**No-op validation in the fast-sync queue**

`queue.DeliverStakingInfos` contains an explicit placeholder that accepts every peer-supplied entry unconditionally:

```go
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
``` [3](#0-2) 

The reconstructed `fetchResult.StakingInfo` is then committed to the database in both `commitFastSyncData` and `commitPivotBlock`:

```go
if result.StakingInfo != nil {
    d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
}
``` [4](#0-3) [5](#0-4) 

**Staking-info recovery path (`SyncStakingInfo`)**

The recovery goroutine checks only that the returned `BlockNum` matches the expected sequence; it does not verify any address or amount field before persisting:

```go
if d.stakingInfoRecoveryBlocks[0] != stakingInfo.BlockNum {
    logger.Error(...)
    return
}
d.stakingModule.PutStakingInfoToDB(stakingInfo.BlockNum, staking.ToStakingInfo(stakingInfo))
``` [6](#0-5) 

**Downstream consumption in reward distribution**

`assignStakingRewards` iterates `si.ConsolidatedNodes()` and credits each `cn.RewardAddr` with a proportional share of staking rewards: [7](#0-6) 

`specWithProposerAndFunds` / `specWithProposerAndFundsFlex` credit `si.KIFAddr` and `si.KEFAddr` with treasury allocations; if either is empty the proposer absorbs the funds: [8](#0-7) 

All of these addresses originate from the `StakingInfo` that was read from the database — the same database that a peer can overwrite during fast-sync.

---

### Impact Explanation

A malicious peer that participates in fast-sync or responds to a `StakingInfoRequestMsg` can supply a `P2PStakingInfo` payload in which:

- `CouncilRewardAddrs` are replaced with attacker-controlled addresses → all staking rewards for the affected epoch interval are sent to the attacker.
- `KEFAddr` / `KIFAddr` are replaced with attacker-controlled addresses → KEF and KIF treasury allocations are redirected.
- `CouncilStakingAmounts` are inflated for one entry → that entry receives a disproportionate share of staking rewards.

Because the database entry takes priority over state-trie derivation, the corruption persists across node restarts and affects every block whose `sourceNum` maps to the poisoned entry. This constitutes an **unauthorized reward distribution** affecting KAIA and system-managed treasury funds.

---

### Likelihood Explanation

- **Fast-sync path**: triggered automatically whenever a node syncs from scratch or falls behind. Any peer the node connects to can supply crafted staking info. No special privilege is required beyond being a reachable P2P peer.
- **`SyncStakingInfo` path**: requires an operator to call the recovery API with a specific peer ID, but the peer itself is untrusted and can supply arbitrary content.
- The window is limited to pre-Kaia-hardfork blocks, but those blocks are still processed for historical reward accounting and proposer-weight calculations on nodes that have not yet reached the hardfork.

---

### Recommendation

1. **Validate against state in `queue.DeliverStakingInfos`**: replace the no-op `validate` callback with a call to `getFromStateByNumber(header.Number.Uint64())` and compare the peer-supplied fields against the state-derived result before accepting the entry.
2. **Validate in `SyncStakingInfo`**: after receiving each `P2PStakingInfo`, re-derive the staking info from the local state trie for that block and reject the peer-supplied data if it differs.
3. **Treat the database as a write-through cache, not a trusted source**: in `GetStakingInfo`, after a DB hit, optionally spot-check critical fields (at minimum `KEFAddr`, `KIFAddr`, and the length of `RewardAddrs`) against the state trie.
4. **Remove or resolve the `TODO-Kaia-Snapsync` placeholder** before the fast-sync path is used in production.

---

### Proof of Concept

1. Attacker runs a Kaia node and connects to a victim node that is performing fast-sync (or whose operator calls `governance_syncStakingInfo` targeting the attacker's peer).
2. When the victim sends a `StakingInfoRequestMsg` for block hash `H` (a staking-interval block before the Kaia hardfork), the attacker responds with a `StakingInfoMsg` containing a `P2PStakingInfo` where:
   - `CouncilRewardAddrs[0]` = attacker's address
   - `KEFAddr` = attacker's address
   - `KIFAddr` = attacker's address
   - `CouncilStakingAmounts[0]` = very large value
3. `handleStakingInfoMsg` → `DeliverStakingInfos` → `queue.DeliverStakingInfos` (validate is a no-op) → `commitFastSyncData` → `PutStakingInfoToDB` writes the crafted entry.
4. The victim node later calls `GetStakingInfo(num)` for any block whose `sourceNum` equals the poisoned block number. The DB hit is returned immediately.
5. `assignStakingRewards` and `specWithProposerAndFunds` distribute KAIA block rewards and treasury allocations to the attacker's addresses instead of the legitimate validators and treasury contracts. [9](#0-8) [10](#0-9) [11](#0-10) [12](#0-11) [13](#0-12)

### Citations

**File:** kaiax/staking/README.md (L50-53)
```markdown
- `StakingInfo(sourceNum)` The StakingInfo captured from the states at the block `sourceNum`. Persisted every StakingInterval before Kaia hardfork.
  ```
  "stakingInfo" || Uint64LE(num) => JSON.Marshal(StakingInfo)
  ```
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

**File:** datasync/downloader/downloader.go (L672-678)
```go
				for _, stakingInfo := range stakingInfos {
					if d.stakingInfoRecoveryBlocks[0] != stakingInfo.BlockNum {
						logger.Error("failed to receive expected block", "expected", d.stakingInfoRecoveryBlocks[0], "actual", stakingInfo.BlockNum)
						return
					}
					d.stakingModule.PutStakingInfoToDB(stakingInfo.BlockNum, staking.ToStakingInfo(stakingInfo))
					fixed++
```

**File:** datasync/downloader/downloader.go (L1856-1890)
```go
func (d *Downloader) commitFastSyncData(results []*fetchResult, stateSync *stateSync) error {
	// Check for any early termination requests
	if len(results) == 0 {
		return nil
	}
	select {
	case <-d.quitCh:
		return errCancelContentProcessing
	case <-stateSync.done:
		if err := stateSync.Wait(); err != nil {
			return err
		}
	default:
	}
	// Retrieve the a batch of results to import
	first, last := results[0].Header, results[len(results)-1].Header
	logger.Debug("Inserting fast-sync blocks", "items", len(results),
		"firstnum", first.Number, "firsthash", first.Hash(),
		"lastnumn", last.Number, "lasthash", last.Hash(),
	)
	blocks := make([]*types.Block, len(results))
	receipts := make([]types.Receipts, len(results))
	for i, result := range results {
		blocks[i] = types.NewBlockWithHeader(result.Header).WithBody(result.Transactions)
		receipts[i] = result.Receipts
		if result.StakingInfo != nil {
			d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
			logger.Info("Imported new staking information", "number", result.StakingInfo.BlockNum)
		}
	}
	if index, err := d.blockchain.InsertReceiptChain(blocks, receipts); err != nil {
		logger.Debug("Downloaded item processing failed", "number", results[index].Header.Number, "hash", results[index].Header.Hash(), "err", err)
		return fmt.Errorf("%w: %v", errInvalidChain, err)
	}
	return nil
```

**File:** datasync/downloader/downloader.go (L1896-1898)
```go
	if result.StakingInfo != nil {
		d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
		logger.Info("Imported new staking information on pivot block", "number", result.StakingInfo.BlockNum, "pivot", block.Number())
```

**File:** kaiax/reward/impl/getter.go (L486-533)
```go
// assignStakingRewards assigns staking rewards to stakers according to their staking amounts.
// Returns the allocation and the remainder.
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

**File:** kaiax/reward/impl/getter.go (L538-565)
```go
func specWithProposerAndFundsFlex(spec *reward.RewardSpec, config *reward.RewardConfig, proposer, kif, kef, kpf *big.Int, si *staking.StakingInfo) *reward.RewardSpec {
	newSpec := spec.Copy()

	// If KIF, KEF, or KPF address is not set, proposer takes it.
	if common.EmptyAddress(si.KIFAddr) {
		newSpec.KIF = common.Big0
		proposer.Add(proposer, kif)
	} else {
		newSpec.KIF = kif
		newSpec.IncRecipient(si.KIFAddr, kif)
	}

	if common.EmptyAddress(si.KEFAddr) {
		newSpec.KEF = common.Big0
		proposer.Add(proposer, kef)
	} else {
		newSpec.KEF = kef
		newSpec.IncRecipient(si.KEFAddr, kef)
	}

	if common.EmptyAddress(si.KPFAddr) {
		newSpec.KPF = common.Big0
		proposer.Add(proposer, kpf)
	} else {
		newSpec.KPF = kpf
		newSpec.IncRecipient(si.KPFAddr, kpf)
	}

```

**File:** kaiax/staking/impl/schema.go (L33-45)
```go
func ReadStakingInfo(db database.Database, num uint64) *staking.StakingInfo {
	b, err := db.Get(stakingInfoKey(num))
	if err != nil || len(b) == 0 {
		return nil
	}

	var sl staking.StakingInfoLegacy
	if err := json.Unmarshal(b, &sl); err != nil {
		logger.Error("Malformed staking info", "num", num, "err", err)
		return nil
	}
	return sl.ToStakingInfo()
}
```
