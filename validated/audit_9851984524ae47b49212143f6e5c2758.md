### Title
Missing Content Validation in `DeliverStakingInfos` Allows Malicious Peer to Corrupt Reward-Distribution State — (`datasync/downloader/queue.go`)

### Summary

The `DeliverStakingInfos` function in the fast-sync download queue accepts peer-supplied `StakingInfo` records and writes them directly to the persistent database with a deliberately empty `validate` callback (marked `// TODO-Kaia-Snapsync update validation logic`). No cryptographic or semantic check ties the received staking data to the block's state root or any on-chain commitment. A malicious connected peer can therefore inject fabricated validator node IDs, reward addresses, staking amounts, and treasury fund addresses (KEF/KIF/KPF) that are then used by `FinalizeState` to distribute block rewards.

### Finding Description

`DeliverStakingInfos` in `datasync/downloader/queue.go` is the counterpart to `DeliverReceipts`. Compare the two validate callbacks:

**Receipts** — cryptographic check against the header's `ReceiptHash`: [1](#0-0) 

**StakingInfos** — unconditional no-op: [2](#0-1) 

The accepted (unvalidated) record is then stored to the persistent database in two call sites:

1. **Fast-sync commit path** (`commitFastSyncData`): [3](#0-2) 

2. **Admin-triggered staking-info recovery** (`SyncStakingInfo`): [4](#0-3) 

`PutStakingInfoToDB` writes the record unconditionally: [5](#0-4) 

After storage, `GetStakingInfo` reads from the database first (before the Kaia hardfork), bypassing state re-derivation: [6](#0-5) 

`FinalizeState` then calls `GetDeferredReward` → `GetStakingInfo` and credits balances to whatever addresses the staking info contains: [7](#0-6) 

The `StakingInfo` struct holds the fields that directly control reward recipients: [8](#0-7) 

### Impact Explanation

A malicious peer that is assigned a staking-info fetch request during fast sync can return a `P2PStakingInfo` with:

- **Attacker-controlled `CouncilRewardAddrs`** — redirects all validator staking rewards to attacker wallets.
- **Inflated/deflated `CouncilStakingAmounts`** — skews the proportional reward split among validators.
- **Attacker-controlled `KEFAddr`/`KIFAddr`** — redirects KEF and KIF treasury fund distributions.

Because the database entry is cached and returned by `GetStakingInfo` for all pre-Kaia-fork blocks, the corruption persists across restarts and affects every subsequent call to `FinalizeState` for those blocks. If the node is a validator, it will produce blocks with wrong state roots (consensus divergence). Even for non-validator nodes, the persistent database corruption poisons `kaia_getStakingInfo` API responses and any downstream tooling that relies on them.

### Likelihood Explanation

- Any peer that successfully connects to a syncing node can be assigned staking-info fetch requests by the downloader's peer-selection logic.
- Fast sync is a standard, documented sync mode; nodes recovering from data loss or joining the network for the first time use it.
- The attack requires only a single connected malicious peer and no special privileges.
- The `// TODO-Kaia-Snapsync update validation logic` comment confirms the gap is known but unresolved.

### Recommendation

Implement content validation inside the `validate` callback of `DeliverStakingInfos`. The staking info for a block can be re-derived from the block's state root (via the `MultiCall` contract) and compared against the peer-supplied data before it is accepted into the fetch result and subsequently written to the database. At minimum, reject any record whose `BlockNum` does not match the header number of the corresponding fetch task, and cross-check the `CouncilNodeAddrs`/`CouncilRewardAddrs` against the AddressBook state at that block's root.

### Proof of Concept

1. Attacker runs a Kaia node and connects to a victim node that is performing fast sync (pre-Kaia-fork range).
2. Victim's downloader assigns the attacker peer a `FetchStakingInfo` request for block hash `H` (block number `N`).
3. Attacker's `handleStakingInfoRequestMsg` handler is bypassed; instead the attacker crafts a `P2PStakingInfo` with `BlockNum = N`, `CouncilRewardAddrs = [attackerAddr, ...]`, and sends it as a `StakingInfoMsg`.
4. `handleStakingInfoMsg` on the victim calls `pm.downloader.DeliverStakingInfos(peerId, fabricatedInfos)`.
5. `DeliverStakingInfos` → `queue.DeliverStakingInfos` → `validate(...)` returns `nil` unconditionally.
6. `commitFastSyncData` calls `d.stakingModule.PutStakingInfoToDB(N, fabricatedInfo)`.
7. Subsequent calls to `GetStakingInfo(num)` for any block whose `sourceBlockNum` resolves to `N` return the fabricated record from the database.
8. `FinalizeState` credits `state.AddBalance(attackerAddr, rewardAmount)` instead of the legitimate validator reward address, permanently redirecting KAIA block rewards. [9](#0-8) [10](#0-9) [11](#0-10) [12](#0-11)

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

**File:** datasync/downloader/downloader.go (L1881-1884)
```go
		if result.StakingInfo != nil {
			d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
			logger.Info("Imported new staking information", "number", result.StakingInfo.BlockNum)
		}
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

**File:** kaiax/staking/staking_info.go (L33-52)
```go
type StakingInfo struct {
	// The source block number where the staking info is captured.
	SourceBlockNum uint64 `json:"blockNum"`

	// The AddressBook triplets
	NodeIds          []common.Address `json:"councilNodeAddrs"`
	StakingContracts []common.Address `json:"councilStakingAddrs"`
	RewardAddrs      []common.Address `json:"councilRewardAddrs"`

	// Treasury fund addresses
	KEFAddr common.Address `json:"kefAddr"` // KEF contract address (or KCF, KIR)
	KIFAddr common.Address `json:"kifAddr"` // KIF contract address (or KFF, KGF, PoC)
	KPFAddr common.Address `json:"kpfAddr"` // KPF contract address

	// Staking amounts of each staking contracts, in KAIA, rounded down. Does not include CL staking amounts.
	StakingAmounts []uint64 `json:"councilStakingAmounts"`

	// Staking info from the consensus liquidity since Prague HF.
	CLStakingInfos CLStakingInfos `json:"clStakingInfos"`

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
