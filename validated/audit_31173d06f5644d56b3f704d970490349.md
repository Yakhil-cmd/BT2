### Title
Unauthenticated Staking Info Accepted from Malicious Peer During Fast Sync Corrupts Reward Distribution — (`datasync/downloader/queue.go`)

### Summary

During fast sync, staking information received from a remote peer is written to the local database with **no content validation**. The `DeliverStakingInfos` queue function contains an explicit TODO placeholder that always returns `nil`, meaning any peer can inject arbitrary staking info (validator reward addresses, staking amounts, fund addresses) that is persisted and later used to compute KAIA block reward distribution.

### Finding Description

In `datasync/downloader/queue.go`, the `DeliverStakingInfos` function registers a `validate` callback that is a permanent no-op: [1](#0-0) 

```go
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
```

Every other data type delivered during fast sync is validated against the block header (e.g., receipts are checked against `header.ReceiptHash`). Staking info has no such check. [2](#0-1) 

The accepted staking info is then unconditionally written to the persistent DB in both `commitFastSyncData` and `commitPivotBlock`, **before** `InsertReceiptChain` verifies the blocks: [3](#0-2) 

```go
if result.StakingInfo != nil {
    d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
}
// ...
if index, err := d.blockchain.InsertReceiptChain(blocks, receipts); err != nil {
```

The staking info written here is subsequently read by `GetStakingInfo` for pre-Kaia-hardfork blocks: [4](#0-3) 

```go
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        s.stakingInfoCache.Add(sourceNum, si)
        return si, nil
    }
}
```

This staking info is then consumed by `FinalizeState` to compute and distribute KAIA block rewards: [5](#0-4) 

The `StakingInfo` struct contains `RewardAddrs` (where KAIA rewards are sent), `StakingAmounts` (which determine proportional reward splits), and fund addresses (`KIFAddr`, `KEFAddr`, `KPFAddr`): [6](#0-5) 

### Impact Explanation

A malicious peer acting as the fast sync source can serve syntactically valid but semantically false staking info — e.g., replacing all `RewardAddrs` with attacker-controlled addresses or inflating its own `StakingAmounts`. This false data is written to the local DB without any cryptographic or state-root verification. When the synced node subsequently processes pre-Kaia-hardfork blocks, `FinalizeState` reads the poisoned DB entry and calls `state.AddBalance` on the attacker-controlled addresses instead of the legitimate validator reward addresses, constituting an unauthorized transfer of KAIA.

The secondary ordering impact: staking info is written to DB before `InsertReceiptChain` succeeds. If block insertion fails, the DB contains staking info for blocks that are not part of the canonical chain, creating a persistent inconsistency that survives restarts.

### Likelihood Explanation

The attacker only needs to run a publicly reachable Kaia node and wait for victim nodes to select it as a fast sync peer. No privileged keys are required. The attack is limited to pre-Kaia-hardfork blocks (after the Kaia hardfork, staking info is always read from state, not DB), which constrains mainnet impact to historical block processing and private/testnet chains that have not yet reached the Kaia hardfork.

### Recommendation

1. Implement the missing validation in `DeliverStakingInfos`: derive the expected staking info from the block's state root and compare it against the peer-supplied value before accepting it.
2. Reverse the write order in `commitFastSyncData` and `commitPivotBlock`: call `InsertReceiptChain` first, and only write staking info to the DB after the blocks are successfully committed to the canonical chain.
3. Until validation is implemented, consider deriving staking info on-demand from the local state trie rather than trusting peer-supplied data.

### Proof of Concept

1. Attacker runs a Kaia node and advertises it on the P2P network.
2. Victim node initiates fast sync and selects the attacker's node as a peer.
3. Attacker's node responds to `StakingInfoRequestMsg` with a crafted `P2PStakingInfo` payload where `RewardAddrs[i]` is replaced with attacker-controlled addresses and `StakingAmounts[i]` is inflated.
4. `handleStakingInfoMsg` → `DeliverStakingInfos` → `queue.DeliverStakingInfos` accepts the payload; the no-op `validate` function returns `nil`.
5. `commitFastSyncData` calls `PutStakingInfoToDB(blockNum, poisonedInfo)`.
6. On the next pre-Kaia block processed by the victim node, `GetStakingInfo(num)` reads the poisoned DB entry (cache miss path), `FinalizeState` calls `state.AddBalance(attackerAddr, rewardAmount)` instead of the legitimate validator reward address. [1](#0-0) [7](#0-6) [8](#0-7) [4](#0-3) [5](#0-4)

### Citations

**File:** datasync/downloader/queue.go (L930-947)
```go
// DeliverReceipts injects a receipt retrieval response into the results queue.
// The method returns the number of transaction receipts accepted from the delivery
// and also wakes any threads waiting for data delivery.
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

**File:** datasync/downloader/downloader.go (L1878-1889)
```go
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

**File:** kaiax/reward/impl/blockstate.go (L46-56)
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
	return nil
```

**File:** kaiax/staking/staking_info.go (L33-51)
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
