### Title
Missing Content Validation for Peer-Delivered `P2PStakingInfo` During Fast Sync Allows Malicious Peer to Redirect KAIA Block Rewards — (`datasync/downloader/queue.go`)

---

### Summary

During fast sync, `P2PStakingInfo` objects delivered by a sync peer are accepted and persisted to the local database with **zero content validation**. The `validate` callback in `DeliverStakingInfos` is an explicit no-op (marked `TODO`). A malicious sync peer can inject arbitrary staking info — substituting attacker-controlled addresses for `RewardAddrs`, `KEFAddr`, and `KIFAddr` — which is then stored in the node's database. When the node subsequently processes blocks (before the Kaia hardfork), `GetStakingInfo` reads from the database first and feeds the corrupted data into `FinalizeState`, causing minted KAIA block rewards and treasury fund allocations to be credited to attacker-controlled addresses.

---

### Finding Description

**Step 1 — No-op validation in `DeliverStakingInfos` (queue)**

`DeliverReceipts` validates each receipt batch against `header.ReceiptHash` before accepting it:

```go
// datasync/downloader/queue.go:936-940
validate := func(index int, header *types.Header) error {
    if types.DeriveReceiptsRoot(types.Receipts(receiptList[index]), header.Number) != header.ReceiptHash {
        return errInvalidReceipt
    }
    return nil
}
```

`DeliverStakingInfos`, by contrast, always returns `nil`:

```go
// datasync/downloader/queue.go:956-958
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
``` [1](#0-0) [2](#0-1) 

The root cause is structural: the block `Header` type contains `ReceiptHash` but **no `StakingInfoHash` field**, so there is no on-chain commitment against which to verify peer-supplied staking data.

**Step 2 — Corrupted data written directly to DB**

After passing the no-op validator, the `fetchResult.StakingInfo` is committed to the persistent database in both `commitFastSyncData` and `commitPivotBlock` without any further check:

```go
// datasync/downloader/downloader.go:1881-1883
if result.StakingInfo != nil {
    d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
}
``` [3](#0-2) [4](#0-3) 

`PutStakingInfoToDB` calls `WriteStakingInfo`, which does a plain `json.Marshal` + `db.Put` with no schema or address validation: [5](#0-4) 

**Step 3 — Corrupted staking info used for reward distribution**

Before the Kaia hardfork, `GetStakingInfo` checks the database **before** falling back to on-chain state:

```go
// kaiax/staking/impl/getter.go:58-63
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        s.stakingInfoCache.Add(sourceNum, si)
        return si, nil
    }
}
``` [6](#0-5) 

`FinalizeState` calls `GetDeferredReward` (which calls `GetStakingInfo`) and then credits every address in `spec.Rewards` with `state.AddBalance`:

```go
// kaiax/reward/impl/blockstate.go:46-55
spec, err := r.GetDeferredReward(header, txs, receipts)
...
for addr, amount := range spec.Rewards {
    state.AddBalance(addr, amount)
}
``` [7](#0-6) 

The reward spec is built from `StakingInfo.RewardAddrs`, `KEFAddr`, and `KIFAddr`: [8](#0-7) 

**Step 4 — P2P message handler delivers peer data directly to the downloader**

Any connected peer can send a `StakingInfoMsg`. The handler decodes it and calls `DeliverStakingInfos` with no pre-filtering:

```go
// node/cn/handler.go:1205-1211
var stakingInfos []*staking.P2PStakingInfo
if err := msg.Decode(&stakingInfos); err != nil {
    return errResp(ErrDecode, "msg %v: %v", msg, err)
}
if err := pm.downloader.DeliverStakingInfos(p.GetID(), stakingInfos); err != nil { ... }
``` [9](#0-8) 

---

### Impact Explanation

A malicious fast-sync peer substitutes attacker-controlled addresses for `RewardAddrs`, `KEFAddr`, and `KIFAddr` in the `P2PStakingInfo` it serves. The victim node stores this data in its database. For every block processed before the Kaia hardfork, `FinalizeState` reads the corrupted staking info from DB and calls `state.AddBalance` on the attacker's addresses instead of the legitimate validators and treasury contracts. This constitutes **unauthorized redirection of minted KAIA block rewards and treasury fund allocations** — a direct asset-impact finding.

The `StakingInfo` also controls `StakingAmounts`, which determines the proportional split of staking rewards among validators. An attacker can set all amounts to zero for legitimate validators and assign large amounts to attacker-controlled nodes, capturing the entire staking reward pool.

---

### Likelihood Explanation

- **Attacker precondition**: Be a registered P2P peer of the victim node. No privileged keys, no admin access, no majority-validator collusion required. Any node can join the Kaia P2P network.
- **Trigger**: The victim node must be performing fast sync (the default mode for new nodes joining the network). The attacker must be selected as the sync peer, which is achievable by being the only or highest-scored peer available.
- **Scope**: Affects all nodes syncing pre-Kaia-hardfork chain segments in fast sync mode.

---

### Recommendation

1. **Add a staking info hash to the block header** (analogous to `ReceiptHash`) so that the content can be cryptographically committed and verified during sync.
2. **Until a header commitment exists**, implement a content-level sanity check in the `validate` callback: verify that `stakingInfoList[index].BlockNum` matches the header number, that address arrays have consistent lengths, and that addresses are non-zero where required.
3. **Cross-validate against on-chain state** after fast sync completes: re-derive staking info from the AddressBook contract state for each stored block and compare against the DB-persisted value, rejecting any mismatch.

---

### Proof of Concept

1. Attacker runs a Kaia node and connects to a victim node that is starting fast sync.
2. When the victim requests staking info for block `N` (a pre-Kaia-fork staking interval block), the attacker's node responds with a crafted `P2PStakingInfo`:
   ```json
   {
     "blockNum": N,
     "councilNodeAddrs": ["<legitimate_node>"],
     "councilStakingAddrs": ["<legitimate_staking>"],
     "councilRewardAddrs": ["<ATTACKER_ADDRESS>"],
     "kefAddr": "<ATTACKER_ADDRESS>",
     "kifAddr": "<ATTACKER_ADDRESS>",
     "councilStakingAmounts": [5000000]
   }
   ```
3. `handleStakingInfoMsg` → `DeliverStakingInfos` → `queue.DeliverStakingInfos` (validate returns `nil`) → `result.StakingInfo` set to crafted data.
4. `commitFastSyncData` calls `PutStakingInfoToDB(N, crafted_info)` — persisted to DB.
5. Victim node finishes fast sync and begins processing new blocks. For block `M` where `sourceBlockNum(M) == N`, `GetStakingInfo(M)` returns the crafted info from DB.
6. `FinalizeState` calls `state.AddBalance(ATTACKER_ADDRESS, mintedAmount)` for each block reward, and `state.AddBalance(ATTACKER_ADDRESS, kefShare)` / `state.AddBalance(ATTACKER_ADDRESS, kifShare)` for treasury allocations.
7. All minted KAIA and treasury funds for the affected epoch are credited to the attacker. [1](#0-0) [10](#0-9) [6](#0-5) [11](#0-10)

### Citations

**File:** datasync/downloader/queue.go (L933-947)
```go
func (q *queue) DeliverReceipts(id string, receiptList [][]*types.Receipt) (int, error) {
	q.lock.Lock()
	defer q.lock.Unlock()
	validate := func(index int, header *types.Header) error {
		if types.DeriveReceiptsRoot(types.Receipts(receiptList[index]), header.Number) != header.ReceiptHash {
			return errInvalidReceipt
		}
		return nil
	}

	reconstruct := func(index int, result *fetchResult) {
		result.Receipts = receiptList[index]
		result.SetReceiptsDone()
	}
	return q.deliver(id, q.receiptTaskPool, q.receiptTaskQueue, q.receiptPendPool, receiptReqTimer, len(receiptList), validate, reconstruct)
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

**File:** kaiax/staking/impl/schema.go (L47-57)
```go
func WriteStakingInfo(db database.Database, num uint64, si *staking.StakingInfo) {
	b, err := json.Marshal(si)
	if err != nil {
		logger.Error("Failed to marshal StakingInfo", "num", num, "err", err)
		return
	}

	if err := db.Put(stakingInfoKey(num), b); err != nil {
		logger.Crit("Failed to write StakingInfo", "num", num, "err", err)
	}
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

**File:** node/cn/handler.go (L1199-1213)
```go
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
