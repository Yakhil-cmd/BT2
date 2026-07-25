### Title
Unvalidated Peer-Supplied `StakingInfo` Written to DB During Fast Sync Corrupts KAIA Reward Distribution — (`datasync/downloader/queue.go`, `datasync/downloader/downloader.go`)

---

### Summary

During fast sync, staking information received from a remote peer is written directly to the local database without any cryptographic or state-root validation. A malicious peer can supply fabricated `StakingInfo` (inflated staking amounts, wrong reward addresses) that persists in the DB and is subsequently used for KAIA reward distribution and weighted-random proposer selection, causing unauthorized reward allocation and consensus divergence.

---

### Finding Description

The `DeliverStakingInfos` function in `datasync/downloader/queue.go` contains an explicit no-op validation callback:

```go
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
``` [1](#0-0) 

The result is that any `P2PStakingInfo` payload a peer sends is accepted unconditionally and stored in the `fetchResult`. Both `commitFastSyncData` and `commitPivotBlock` then write this unverified data directly to the persistent DB:

```go
if result.StakingInfo != nil {
    d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
}
``` [2](#0-1) [3](#0-2) 

`PutStakingInfoToDB` performs no validation before persisting: [4](#0-3) 

After fast sync completes, `GetStakingInfo` consults the DB **before** re-deriving from state (pre-Kaia hardfork path):

```go
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        s.stakingInfoCache.Add(sourceNum, si)
        return si, nil   // returns poisoned DB entry; state is never consulted
    }
}
``` [5](#0-4) 

`FinalizeState` calls `GetStakingInfo` to compute the deferred reward spec and then calls `state.AddBalance` for each recipient: [6](#0-5) 

If `StakingAmounts` in the DB are fabricated, `assignStakingRewards` distributes the wrong KAIA amounts to the wrong addresses. [7](#0-6) 

The weighted-random proposer list is also built from the same `StakingInfo`: [8](#0-7) 

---

### Impact Explanation

**Unauthorized KAIA reward distribution**: A malicious peer can inflate `StakingAmounts` for a chosen validator address. After fast sync, every block processed by the victim node distributes excess KAIA to that address via `state.AddBalance`, constituting an unauthorized reward transfer from the protocol's minting budget.

**Consensus divergence**: Because `FinalizeState` produces a different state root (wrong balances), the victim node's blocks are rejected by honest nodes that derive staking info correctly from state. The victim node forks off the canonical chain.

---

### Likelihood Explanation

Fast sync is the default mode for nodes syncing from scratch or after extended downtime. Any peer that successfully completes the P2P handshake can respond to `StakingInfoRequestMsg` with arbitrary content. No authentication of the peer's identity or the content of the staking payload is required. The attack window is the entire fast-sync session.

---

### Recommendation

1. **Validate staking info against the block state root**: After receiving `P2PStakingInfo` for block `N`, re-derive the staking info from `state.Root` of block `N` and compare. Replace the TODO in `DeliverStakingInfos`:

```go
validate := func(index int, header *types.Header) error {
    // Derive expected staking info from state and compare with received
    expected, err := stakingModule.getFromStateByNumber(header.Number.Uint64())
    if err != nil { return err }
    if !stakingInfoEqual(expected, stakingInfoList[index]) {
        return errInvalidStakingInfo
    }
    return nil
}
```

2. **Alternatively**, never trust DB-sourced staking info for reward computation; always re-derive from state (as is already done post-Kaia hardfork via `sourceBlockNum(num, isKaia=true, ...) = num-1`).

---

### Proof of Concept

1. Attacker runs a Kaia node and connects to a victim node that is performing fast sync.
2. When the victim sends `StakingInfoRequestMsg` for block hashes, the attacker responds with `StakingInfoMsg` containing a `P2PStakingInfo` where `StakingAmounts[attacker_idx]` is set to `math.MaxUint64`.
3. `handleStakingInfoMsg` → `DeliverStakingInfos` → `validate()` returns `nil` → `commitFastSyncData` → `PutStakingInfoToDB` writes the fabricated entry.
4. After fast sync, the victim node calls `GetStakingInfo(N)` for any block in the affected interval; the DB entry is returned without state verification.
5. `FinalizeState` calls `assignStakingRewards` with the inflated amounts; `state.AddBalance(attacker_reward_addr, inflated_amount)` is executed each block.
6. The victim's state root diverges from the canonical chain; its blocks are rejected by honest validators. [9](#0-8) [10](#0-9) [1](#0-0) [11](#0-10) [12](#0-11) [13](#0-12)

### Citations

**File:** datasync/downloader/queue.go (L953-966)
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
}
```

**File:** datasync/downloader/downloader.go (L1876-1885)
```go
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
```

**File:** datasync/downloader/downloader.go (L1896-1898)
```go
	if result.StakingInfo != nil {
		d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
		logger.Info("Imported new staking information on pivot block", "number", result.StakingInfo.BlockNum, "pivot", block.Number())
```

**File:** datasync/downloader/downloader.go (L1935-1941)
```go
// DeliverStakingInfos injects a new batch of staking information received from a remote node.
func (d *Downloader) DeliverStakingInfos(id string, stakingInfos []*staking.P2PStakingInfo) error {
	if d.isStakingInfoRecovery {
		d.stakingInfoRecoveryCh <- stakingInfos
	}
	return d.deliver(id, d.stakingInfoCh, &stakingInfoPack{id, stakingInfos}, stakingInfoInMeter, stakingInfoDropMeter)
}
```

**File:** kaiax/staking/impl/schema.go (L73-75)
```go
func (s *StakingModule) PutStakingInfoToDB(sourceNum uint64, stakingInfo *staking.StakingInfo) {
	WriteStakingInfo(s.ChainKv, sourceNum, stakingInfo)
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

**File:** kaiax/reward/impl/blockstate.go (L30-57)
```go
func (r *RewardModule) FinalizeState(header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) error {
	if r.GovModule.GetParamSet(header.Number.Uint64()).ProposerPolicy == uint64(istanbul.WeightedRandom) && common.EmptyHash(header.Root) {
		qualified, err := r.ValsetModule.GetQualifiedValidators(header.Number.Uint64())
		if err != nil {
			return err
		}
		useRewardAddress := valset.NewAddressSet(qualified).Contains(r.NodeAddress)

		if rewardAddr := r.GetRewardAddress(header.Number.Uint64(), r.NodeAddress); useRewardAddress && rewardAddr != (common.Address{}) {
			header.Rewardbase = rewardAddr
			logger.Trace("Use reward address for nodeValidator", "header.Number", header.Number.Uint64(), "nodeAddress", r.NodeAddress, "rewardbase", header.Rewardbase)
		} else {
			logger.Trace("No reward address for nodeValidator. Use node's rewardbase.", "header.Number", header.Number.Uint64(), "nodeAddress", r.NodeAddress, "rewardbase", header.Rewardbase)
		}
	}

	spec, err := r.GetDeferredReward(header, txs, receipts)
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
	return nil
}
```

**File:** kaiax/reward/impl/getter.go (L488-534)
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
}
```

**File:** kaiax/valset/impl/getter_proposers.go (L216-268)
```go
func generateProposerListWeighted(qualified *valset.AddressSet, si *staking.StakingInfo, useGini bool, blockHash common.Hash) []common.Address {
	var (
		addrs          = qualified.List()
		stakingAmounts = collectStakingAmounts(addrs, si)
		gini           = computeGini(stakingAmounts) // si.Gini is computed over every CN. But we want gini among validators, so we calculate here.
		exponent       = 1.0 / (1 + gini)
		totalStakes    = float64(0)
	)

	// Adjust staking amounts and calculate the sum
	if useGini {
		for addr, amount := range stakingAmounts {
			stakingAmounts[addr] = math.Round(math.Pow(float64(amount), exponent))
			totalStakes += stakingAmounts[addr]
		}
	} else {
		for _, amount := range stakingAmounts {
			totalStakes += amount
		}
	}

	// Calculate percentile weights
	weights := make(map[common.Address]uint64)
	if totalStakes > 0 {
		for _, addr := range addrs {
			weight := uint64(math.Round(stakingAmounts[addr] * 100 / totalStakes))
			if weight <= 0 {
				weight = 1
			}
			weights[addr] = weight
		}
	} else {
		for _, addr := range addrs {
			weights[addr] = 0
		}
	}

	// Generate weighted repeated list
	proposerList := make([]common.Address, 0)
	for _, addr := range addrs {
		for i := uint64(0); i < weights[addr]; i++ {
			proposerList = append(proposerList, addr)
		}
	}
	// If the list is empty (i.e. all weights are zero), list each validator once.
	if len(proposerList) == 0 {
		for _, addr := range addrs {
			proposerList = append(proposerList, addr)
		}
	}

	seed := valset.HashToSeedLegacy(blockHash)
	return valset.NewAddressSet(proposerList).ShuffledListLegacy(seed)
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
