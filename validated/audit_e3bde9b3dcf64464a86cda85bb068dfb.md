### Title
Unvalidated Peer-Supplied Staking Info During Fast Sync Corrupts Reward Distribution — (`datasync/downloader/queue.go`, `datasync/downloader/downloader.go`)

---

### Summary

During fast sync, staking information (`P2PStakingInfo`) received from any connected peer is written directly to the node's persistent database without any cryptographic or state-root validation. A malicious peer can supply fabricated staking amounts, reward addresses, or fund addresses (KIF/KEF). These values are then used verbatim by `GetStakingInfo` → `FinalizeState` to distribute KAIA block rewards, permanently corrupting reward accounting for all pre-Kaia-hardfork blocks.

---

### Finding Description

The `DeliverStakingInfos` function in `datasync/downloader/queue.go` contains an explicit placeholder that skips all validation:

```go
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
``` [1](#0-0) 

The `header` parameter is available (and carries `header.Root`), but the function unconditionally returns `nil`. The validated (or rather, unvalidated) `fetchResult.StakingInfo` is then committed to the database in two places during fast sync:

```go
if result.StakingInfo != nil {
    d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
}
``` [2](#0-1) [3](#0-2) 

`PutStakingInfoToDB` writes directly to the key-value store with no further checks:

```go
func (s *StakingModule) PutStakingInfoToDB(sourceNum uint64, stakingInfo *staking.StakingInfo) {
    WriteStakingInfo(s.ChainKv, sourceNum, stakingInfo)
}
``` [4](#0-3) 

After fast sync, `GetStakingInfo` for pre-Kaia blocks reads the database **before** falling back to state:

```go
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        s.stakingInfoCache.Add(sourceNum, si)
        return si, nil  // poisoned value returned here
    }
}
``` [5](#0-4) 

This poisoned `StakingInfo` is then consumed by `FinalizeState` to distribute KAIA rewards:

```go
spec, err := r.GetDeferredReward(header, txs, receipts)
...
for addr, amount := range spec.Rewards {
    state.AddBalance(addr, amount)
}
``` [6](#0-5) 

The reward spec is built from `StakingInfo.RewardAddrs`, `StakingInfo.StakingAmounts`, `StakingInfo.KIFAddr`, and `StakingInfo.KEFAddr`: [7](#0-6) [8](#0-7) 

A parallel admin-triggered path (`SyncStakingInfo`) has the same defect — it only checks `stakingInfo.BlockNum` matches the expected block number, not the content:

```go
d.stakingModule.PutStakingInfoToDB(stakingInfo.BlockNum, staking.ToStakingInfo(stakingInfo))
``` [9](#0-8) 

---

### Impact Explanation

A malicious peer can supply a `P2PStakingInfo` with:
- Inflated `CouncilStakingAmounts` for its own validator → receives a disproportionate share of staking rewards
- Attacker-controlled `CouncilRewardAddrs` → redirects another validator's rewards
- Attacker-controlled `KIFAddr` / `KEFAddr` → redirects KIF/KEF fund rewards to attacker

These fabricated values are written to the persistent DB and cached, so they survive node restarts. Every subsequent call to `GetStakingInfo` for the affected source block returns the poisoned data, causing `FinalizeState` to credit wrong addresses with KAIA.

---

### Likelihood Explanation

Fast sync is the default mode for new nodes joining the network. Any peer the syncing node connects to can send a `StakingInfoMsg` response. The `handleStakingInfoMsg` P2P handler accepts staking info from any connected peer without authentication beyond protocol version: [10](#0-9) 

The `P2PStakingInfo` struct carries all fields needed to fabricate a complete, structurally valid staking record: [11](#0-10) 

The TODO comment in the validation function confirms this is a known, unresolved gap.

---

### Recommendation

In `queue.go`'s `DeliverStakingInfos`, implement the missing validation by re-deriving the staking info from the canonical state at `header.Root` and comparing it against the peer-supplied data, or by refusing to accept peer-supplied staking info and always deriving it from state. The `validate` closure already receives the `*types.Header` (with `header.Root`), so the fix is to call `getFromState(header, stateAt(header.Root))` and compare field-by-field, or simply reject the peer data and mark the fetch result as needing local derivation.

---

### Proof of Concept

1. Attacker runs a Kaia node with `istanbul.policy == 2` (WeightedRandom) and connects to a victim node that is fast-syncing.
2. When the victim sends a `StakingInfoRequestMsg` for block hash `H` (a staking-interval block before Kaia hardfork), the attacker responds with a `StakingInfoMsg` containing a `P2PStakingInfo` where:
   - `CouncilRewardAddrs[0]` is replaced with attacker's address
   - `CouncilStakingAmounts[0]` is set to `math.MaxUint64`
   - `KIFAddr` / `KEFAddr` are set to attacker's address
3. `handleStakingInfoMsg` decodes the message and calls `DeliverStakingInfos`.
4. `queue.DeliverStakingInfos` calls `validate(...)` which returns `nil` unconditionally.
5. `commitFastSyncData` calls `PutStakingInfoToDB(blockNum, fabricatedInfo)`.
6. After fast sync, the victim node processes new blocks. `GetStakingInfo(num)` for any `num` whose `sourceNum` maps to the poisoned block reads the fabricated record from DB (DB is checked before state for pre-Kaia blocks).
7. `FinalizeState` calls `GetDeferredReward` → `assignStakingRewards` using the fabricated staking amounts → `state.AddBalance(attackerAddr, inflatedReward)`. [12](#0-11) [13](#0-12)

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

**File:** datasync/downloader/downloader.go (L677-677)
```go
					d.stakingModule.PutStakingInfoToDB(stakingInfo.BlockNum, staking.ToStakingInfo(stakingInfo))
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

**File:** kaiax/staking/impl/schema.go (L73-75)
```go
func (s *StakingModule) PutStakingInfoToDB(sourceNum uint64, stakingInfo *staking.StakingInfo) {
	WriteStakingInfo(s.ChainKv, sourceNum, stakingInfo)
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

**File:** kaiax/reward/impl/blockstate.go (L46-55)
```go
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
```

**File:** kaiax/reward/impl/getter.go (L488-507)
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
```

**File:** kaiax/reward/impl/getter.go (L596-614)
```go
func specWithProposerAndFunds(spec *reward.RewardSpec, config *reward.RewardConfig, proposer, kif, kef *big.Int, si *staking.StakingInfo) *reward.RewardSpec {
	newSpec := spec.Copy()

	// If KIF or KEF address is not set, proposer takes it.
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

**File:** kaiax/staking/p2p_staking_info.go (L31-47)
```go
type P2PStakingInfo struct {
	BlockNum uint64 `json:"blockNum"` // Block number where staking information of Council is fetched

	// Information retrieved from AddressBook smart contract
	CouncilNodeAddrs    []common.Address `json:"councilNodeAddrs"`    // NodeIds of Council
	CouncilStakingAddrs []common.Address `json:"councilStakingAddrs"` // Address of Staking account which holds staking balance
	CouncilRewardAddrs  []common.Address `json:"councilRewardAddrs"`  // Address of Council account which will get block reward

	KEFAddr common.Address `json:"kefAddr"` // Address of KEF contract
	KIFAddr common.Address `json:"kifAddr"` // Address of KIF contract

	UseGini bool    `json:"useGini"` // configure whether Gini is used or not
	Gini    float64 `json:"gini"`    // gini coefficient

	// Derived from CouncilStakingAddrs
	CouncilStakingAmounts []uint64 `json:"councilStakingAmounts"` // Staking amounts of Council
}
```
