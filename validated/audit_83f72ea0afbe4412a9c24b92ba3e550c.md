### Title
Peer-supplied `StakingInfo` accepted without content validation in `DeliverStakingInfos`, enabling a malicious peer to corrupt the staking database and cause consensus divergence or reward-distribution errors — (`File: datasync/downloader/queue.go`)

---

### Summary

`DeliverStakingInfos` in `datasync/downloader/queue.go` contains a deliberately no-op `validate` callback (marked `TODO-Kaia-Snapsync update validation logic`), while the analogous `DeliverReceipts` validates every receipt batch against the header's `ReceiptHash`. Any peer that responds to a staking-info request during block sync can supply arbitrary `P2PStakingInfo` content — including fabricated node addresses, staking amounts, and treasury-fund addresses — which is written directly to the staking database without any cryptographic or state-derived check. The corrupted database is then consumed by reward distribution (`FinalizeState`) and validator-set selection (`GetQualifiedValidators`) for all pre-Kaia-hardfork blocks.

---

### Finding Description

**Root cause — missing validation in the delivery queue**

`DeliverReceipts` validates each receipt batch against the committed header hash:

```go
// datasync/downloader/queue.go  L936-941
validate := func(index int, header *types.Header) error {
    if types.DeriveReceiptsRoot(types.Receipts(receiptList[index]), header.Number) != header.ReceiptHash {
        return errInvalidReceipt
    }
    return nil
}
```

`DeliverStakingInfos`, immediately below, does nothing:

```go
// datasync/downloader/queue.go  L956-959
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
``` [1](#0-0) 

**Root cause — missing content check in the recovery path**

`SyncStakingInfo` checks only that the returned `BlockNum` matches the expected sequence; it never re-derives the staking info from the chain state to confirm the content:

```go
// datasync/downloader/downloader.go  L672-679
for _, stakingInfo := range stakingInfos {
    if d.stakingInfoRecoveryBlocks[0] != stakingInfo.BlockNum {
        ...
        return
    }
    d.stakingModule.PutStakingInfoToDB(stakingInfo.BlockNum, staking.ToStakingInfo(stakingInfo))
    ...
}
``` [2](#0-1) 

**Consumption path — staking database drives reward distribution and validator selection**

Before the Kaia hardfork, `GetStakingInfo` reads from the database first:

```go
// kaiax/staking/impl/getter.go  L58-63
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        s.stakingInfoCache.Add(sourceNum, si)
        return si, nil
    }
}
``` [3](#0-2) 

That `StakingInfo` is then used directly in `assignStakingRewards` / `assignStakingRewardsFlex` to compute per-validator KAIA allocations, and in `GetQualifiedValidators` / `GetProposer` to determine which nodes may seal blocks. [4](#0-3) 

**Attack flow**

1. During fast sync (or normal block sync), the victim node sends `GetStakingInfoMsg` for a set of pre-Kaia block hashes.
2. A malicious peer responds via `handleStakingInfoMsg` → `DeliverStakingInfos` with fabricated `P2PStakingInfo` objects: inflated `CouncilStakingAmounts`, substituted `CouncilRewardAddrs`, or altered `KEFAddr`/`KIFAddr`.
3. `DeliverStakingInfos` calls `q.deliver(...)` with the no-op `validate`; the fabricated records pass straight through to `result.StakingInfo`.
4. The downloader's block-processing loop calls `PutStakingInfoToDB`, persisting the fabricated data.
5. On subsequent full-sync or validator-set queries for those pre-Kaia blocks, `GetStakingInfo` returns the attacker-controlled values from the database. [5](#0-4) 

---

### Impact Explanation

| Consequence | Mechanism |
|---|---|
| **Reward-distribution corruption** | `assignStakingRewards` uses attacker-controlled `StakingAmounts` and `RewardAddrs`; a malicious peer can inflate its own share or redirect rewards to an arbitrary address for all pre-Kaia blocks the victim re-executes. |
| **Consensus divergence** | `GetQualifiedValidators` / `GetProposer` use the corrupted staking info to determine which nodes are eligible to seal blocks. A node with a poisoned database may accept blocks from unauthorized validators or reject blocks from legitimate ones, diverging from the canonical chain. |
| **Denial of service** | During full sync, the wrong staking info produces a wrong state root; the block is rejected and sync stalls permanently for the affected range. |
| **Treasury-fund redirection** | `KEFAddr` / `KIFAddr` in the fabricated record redirect the ecosystem-fund and infrastructure-fund portions of block rewards to attacker-controlled addresses in the victim's local computation. |

---

### Likelihood Explanation

The attack requires only that the victim node connects to the malicious peer during block sync — a standard, unprivileged P2P role. No keys, governance access, or majority-validator collusion is needed. The `fetchStakingInfos` goroutine runs automatically during every sync cycle for pre-Kaia chains, and the malicious peer simply needs to respond to the `GetStakingInfoMsg` with crafted data. [6](#0-5) 

---

### Recommendation

1. **Derive a commitment from chain state**: After receiving `P2PStakingInfo`, re-derive the staking info from the block state via `getFromStateByNumber(sourceNum)` and compare it field-by-field (or by hashing the canonical JSON) before calling `PutStakingInfoToDB`. This is the same approach used by `DeliverReceipts` (compare against `header.ReceiptHash`).

2. **Remove the TODO stub**: Replace the no-op `validate` closure in `DeliverStakingInfos` with a real check, consistent with `DeliverReceipts` and `DeliverBodies`.

3. **Harden `SyncStakingInfo`**: After writing each recovered record, immediately read it back via `getFromStateByNumber` and assert equality; abort and drop the peer on mismatch.

---

### Proof of Concept

```go
// Malicious peer handler: respond to GetStakingInfoMsg with fabricated data
func (p *maliciousPeer) handleGetStakingInfoMsg(msg p2p.Msg) {
    // Decode the requested block hashes (legitimate)
    var hashes []common.Hash
    msg.Decode(&hashes)

    // Build a fabricated P2PStakingInfo for each requested hash
    var fakeInfos []rlp.RawValue
    for _, h := range hashes {
        header := victim.GetHeaderByHash(h)
        fake := &staking.P2PStakingInfo{
            BlockNum:              header.Number.Uint64(),
            CouncilNodeAddrs:      legitimateNodes,
            CouncilStakingAddrs:   legitimateStakingAddrs,
            CouncilRewardAddrs:    []common.Address{attackerAddr, ...}, // redirect rewards
            KEFAddr:               attackerAddr,                         // redirect KEF
            KIFAddr:               attackerAddr,                         // redirect KIF
            CouncilStakingAmounts: []uint64{999_999_999, ...},           // inflate attacker stake
        }
        encoded, _ := rlp.EncodeToBytes(fake)
        fakeInfos = append(fakeInfos, encoded)
    }
    p.SendStakingInfoRLP(fakeInfos)
    // Victim calls DeliverStakingInfos → no-op validate → PutStakingInfoToDB
    // Corrupted data is now in the victim's staking database
}
```

The victim node will subsequently use the attacker-controlled `CouncilStakingAmounts` and `CouncilRewardAddrs` in `assignStakingRewards`, and the attacker-controlled `KEFAddr`/`KIFAddr` in `specWithProposerAndFunds`, for every pre-Kaia block it processes. [7](#0-6) [8](#0-7)

### Citations

**File:** datasync/downloader/queue.go (L930-966)
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
}

// DeliverStakingInfos injects a stakinginfo retrieval response into the results queue.
// The method returns the number of staking information accepted from the delivery
// and also wakes any threads waiting for data delivery.
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

**File:** datasync/downloader/downloader.go (L670-680)
```go
			case stakingInfos := <-d.stakingInfoRecoveryCh:
				logger.Info("received stakinginfos", "len", len(stakingInfos))
				for _, stakingInfo := range stakingInfos {
					if d.stakingInfoRecoveryBlocks[0] != stakingInfo.BlockNum {
						logger.Error("failed to receive expected block", "expected", d.stakingInfoRecoveryBlocks[0], "actual", stakingInfo.BlockNum)
						return
					}
					d.stakingModule.PutStakingInfoToDB(stakingInfo.BlockNum, staking.ToStakingInfo(stakingInfo))
					fixed++
					d.stakingInfoRecoveryBlocks = d.stakingInfoRecoveryBlocks[1:]
				}
```

**File:** datasync/downloader/downloader.go (L1259-1284)
```go
// fetchStakingInfos iteratively downloads the scheduled staking information, taking any
// available peers, reserving a chunk of staking information for each, waiting for delivery
// and also periodically checking for timeouts.
func (d *Downloader) fetchStakingInfos(from uint64) error {
	logger.Debug("Downloading staking information", "origin", from)

	start := time.Now()
	var (
		deliver = func(packet dataPack) (int, error) {
			pack := packet.(*stakingInfoPack)
			return d.queue.DeliverStakingInfos(pack.peerId, pack.stakingInfos)
		}
		expire   = func() map[string]int { return d.queue.ExpireStakingInfos(d.requestTTL()) }
		fetch    = func(p *peerConnection, req *fetchRequest) error { return p.FetchStakingInfo(req) }
		capacity = func(p *peerConnection) int { return p.StakingInfoCapacity(d.requestRTT()) }
		setIdle  = func(p *peerConnection, accepted int, deliveryTime time.Time) {
			p.SetStakingInfoIdle(accepted, deliveryTime)
		}
	)
	err := d.fetchParts(d.stakingInfoCh, deliver, d.stakingInfoWakeCh, expire,
		d.queue.PendingStakingInfos, d.queue.InFlightStakingInfos, d.queue.ReserveStakingInfos,
		d.stakingInfoFetchHook, fetch, d.queue.CancelStakingInfo, capacity, d.peers.StakingInfoIdlePeers, setIdle, "stakingInfos")

	logger.Debug("Staking information download terminated", "err", err, "elapsed", time.Since(start))
	return err
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

**File:** kaiax/reward/impl/getter.go (L486-534)
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
}
```

**File:** node/cn/handler.go (L1198-1214)
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
}
```

**File:** kaiax/staking/impl/schema.go (L73-75)
```go
func (s *StakingModule) PutStakingInfoToDB(sourceNum uint64, stakingInfo *staking.StakingInfo) {
	WriteStakingInfo(s.ChainKv, sourceNum, stakingInfo)
}
```

**File:** kaiax/staking/p2p_staking_info.go (L30-47)
```go
// P2PStakingInfo contains staking information which is a wrapped version of StakingInfo.
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
