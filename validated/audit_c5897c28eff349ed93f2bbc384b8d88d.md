### Title
Unvalidated P2P StakingInfo Delivery Allows Persistent Corruption of Validator Set, Proposer Selection, and Reward Distribution During FastSync/SnapSync — (`datasync/downloader/queue.go`)

---

### Summary

During FastSync and SnapSync, the Kaia downloader fetches `P2PStakingInfo` objects from peers and writes them directly to the local database without any cryptographic validation against the corresponding block header's state root or any other on-chain commitment. The `validate` callback in `queue.DeliverStakingInfos` is a permanent stub that unconditionally returns `nil`. A malicious peer can serve fabricated staking info containing attacker-chosen validator node addresses, staking amounts, reward addresses, and treasury fund addresses. After sync completes, the corrupted database entries are used for proposer selection (WeightedRandom policy), validator demotion decisions, and reward distribution — all of which are protected-state operations affecting KAIA token flow and consensus integrity.

---

### Finding Description

In `datasync/downloader/queue.go`, the `DeliverStakingInfos` function is the delivery endpoint for staking info received from a remote peer during sync:

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
``` [1](#0-0) 

The `validate` function is a stub that always returns `nil`. The `TODO-Kaia-Snapsync update validation logic` comment confirms this is a known gap. Compare this to the analogous functions for bodies and receipts, which perform cryptographic validation:

- `DeliverBodies` checks `types.DeriveTransactionsRoot(txLists[index], header.Number) != header.TxHash`
- `DeliverReceipts` checks `types.DeriveReceiptsRoot(receiptList[index], header.Number) != header.ReceiptHash` [2](#0-1) [3](#0-2) 

No equivalent commitment exists for staking info — `P2PStakingInfo` contains `CouncilNodeAddrs`, `CouncilStakingAddrs`, `CouncilRewardAddrs`, `KEFAddr`, `KIFAddr`, and `CouncilStakingAmounts`, none of which are committed to in any block header field. [4](#0-3) 

The accepted (unvalidated) staking info is then written unconditionally to the persistent database in `commitFastSyncData` and `commitPivotBlock`:

```go
if result.StakingInfo != nil {
    d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
}
``` [5](#0-4) [6](#0-5) 

The same vulnerability exists in the `SyncStakingInfo` recovery path, which only checks that `stakingInfo.BlockNum` matches the expected block number but performs no content validation before calling `PutStakingInfoToDB`: [7](#0-6) 

The `handleStakingInfoMsg` handler in the protocol manager decodes the message and forwards it directly to `DeliverStakingInfos` with no additional checks: [8](#0-7) 

---

### Impact Explanation

`StakingInfo` is the authoritative source for three protected-state operations:

**1. Validator demotion / qualified validator set (WeightedRandom policy)**

`getDemotedValidatorsPermissioned` calls `GetStakingInfo` to determine which council members are demoted. Corrupted `CouncilStakingAmounts` can cause honest validators to be demoted (excluded from proposer/committee selection) and attacker-controlled addresses to be qualified. [9](#0-8) 

**2. Proposer list generation (WeightedRandom before Kore hardfork)**

`generateProposerListWeighted` uses staking amounts to compute per-validator weights (W_i = max(1, round(100·S_i/TS))). Fabricated amounts directly control how frequently each validator appears in the proposer list, enabling an attacker to bias or monopolize block proposal rights. [10](#0-9) 

**3. Reward distribution**

`CouncilRewardAddrs`, `KEFAddr`, and `KIFAddr` from `StakingInfo` determine where block rewards and treasury funds are sent. Corrupted reward addresses redirect KAIA token distributions to attacker-controlled accounts. [11](#0-10) 

The corrupted data is written to the persistent database (`WriteStakingInfo`) and survives node restarts: [12](#0-11) 

---

### Likelihood Explanation

- **Trigger condition**: The victim node must be performing FastSync or SnapSync (the default for new nodes joining the network), with `istanbul.ProposerPolicy == WeightedRandom`, and syncing blocks before the Kaia hardfork (where staking info is fetched at interval boundaries).
- **Attacker position**: Any peer that the syncing node connects to can serve the `StakingInfoMsg` response. The attacker does not need to be a validator or hold any stake. A single malicious peer in the peer set is sufficient.
- **Staking info is only fetched at interval boundaries** (`header.Number % stakingUpdateInterval == 0`), which limits the number of requests but does not prevent exploitation — each corrupted entry covers an entire staking interval. [13](#0-12) 

---

### Recommendation

1. **Add cryptographic binding**: Staking info is derived from the AddressBook contract state at a specific block. During FastSync/SnapSync, the syncing node already has the verified block header (including `Root`). The staking info should be re-derived from the state trie at the source block number after state sync completes, rather than trusted from a peer. Alternatively, a Merkle proof against the verified state root should be required.

2. **Remove the stub**: Replace the `// TODO-Kaia-Snapsync update validation logic` stub in `queue.DeliverStakingInfos` with actual validation. At minimum, verify that the `BlockNum` field in the delivered `P2PStakingInfo` matches the header's block number for the corresponding task slot.

3. **Post-sync re-derivation**: After FastSync/SnapSync completes and the state trie is available locally, re-derive and overwrite all staking info entries from the local state rather than relying on peer-supplied data.

4. **Apply the same fix to `SyncStakingInfo`**: The recovery path at `downloader.go:670-679` must also validate content, not just block number.

---

### Proof of Concept

**Setup**: Two nodes — an honest syncing node (FastSync mode, WeightedRandom policy) and a malicious peer.

**Malicious peer modification** (conceptual patch to the peer's `handleStakingInfoRequestMsg` response):

```go
// In the malicious peer's handler, instead of serving real staking info,
// return fabricated data with attacker-controlled reward addresses:
result = &staking.P2PStakingInfo{
    BlockNum:              header.Number.Uint64(),
    CouncilNodeAddrs:      []common.Address{attackerNodeAddr},
    CouncilStakingAddrs:   []common.Address{attackerStakingAddr},
    CouncilRewardAddrs:    []common.Address{attackerRewardAddr}, // all rewards go here
    KEFAddr:               attackerAddr,                          // treasury redirected
    KIFAddr:               attackerAddr,
    CouncilStakingAmounts: []uint64{999999999},                  // monopolize proposer list
}
```

**Attack flow**:

1. Honest node starts FastSync and connects to the malicious peer.
2. Headers and receipts are validated normally (cryptographic checks pass).
3. For each staking interval block, the honest node sends `StakingInfoRequestMsg`.
4. The malicious peer responds with fabricated `P2PStakingInfo`.
5. `handleStakingInfoMsg` → `DeliverStakingInfos` → `validate()` returns `nil` → `PutStakingInfoToDB` writes the fabricated data.
6. After sync completes, `GetStakingInfo` reads the corrupted database entries.
7. `getDemotedValidatorsPermissioned` demotes all honest validators (zero staking amounts).
8. `generateProposerListWeighted` generates a proposer list containing only the attacker's node.
9. Block rewards flow to `attackerRewardAddr`; treasury funds flow to `attackerAddr`.

**Corrupted value**: `StakingInfo.RewardAddrs[i]`, `StakingInfo.StakingAmounts[i]`, `StakingInfo.KEFAddr`, `StakingInfo.KIFAddr` — all set to attacker-controlled values, persisted at `"stakingInfo" || Uint64LE(sourceNum)` in the chain database.

### Citations

**File:** datasync/downloader/queue.go (L391-399)
```go
		if (q.mode == FastSync || q.mode == SnapSync) && q.proposerPolicy == uint64(istanbul.WeightedRandom) &&
			(header.Number.Uint64()%q.stakingUpdateInterval == 0 && !q.IsKaiaFork(header.Number)) {
			if _, ok := q.stakingInfoTaskPool[hash]; ok {
				logger.Trace("Header already scheduled for staking info fetch", "number", header.Number, "hash", hash)
			} else {
				q.stakingInfoTaskPool[hash] = header
				q.stakingInfoTaskQueue.Push(header, -int64(header.Number.Uint64()))
			}
		}
```

**File:** datasync/downloader/queue.go (L884-927)
```go
	validate := func(index int, header *types.Header) error {
		if types.DeriveTransactionsRoot(types.Transactions(txLists[index]), header.Number) != header.TxHash {
			return errInvalidBody
		}
		// Blocks must have a number of blobs corresponding to the header gas usage,
		// and zero before the Osaka hardfork.
		var blobs int
		for _, tx := range txLists[index] {
			// Validate the data blobs individually too
			if tx.Type() == types.TxTypeEthereumBlob {
				// Count the number of blobs to validate against the header's blobGasUsed
				txBlobHashCount := len(tx.BlobHashes())
				if txBlobHashCount == 0 {
					return errInvalidBody
				}
				blobs += txBlobHashCount

				for _, hash := range tx.BlobHashes() {
					if !kzg4844.IsValidVersionedHash(hash[:]) {
						return errInvalidBody
					}
				}
				if tx.BlobTxSidecar() != nil {
					return errInvalidBody
				}
			}
		}
		if header.BlobGasUsed != nil {
			if want := *header.BlobGasUsed / params.BlobTxBlobGasPerBlob; uint64(blobs) != want { // div because the header is surely good vs the body might be bloated
				return errInvalidBody
			}
		} else {
			if blobs != 0 {
				return errInvalidBody
			}
		}
		return nil
	}

	reconstruct := func(index int, result *fetchResult) {
		result.Transactions = txLists[index]
		result.SetBodyDone()
	}
	return q.deliver(id, q.blockTaskPool, q.blockTaskQueue, q.blockPendPool, bodyReqTimer, len(txLists), validate, reconstruct)
```

**File:** datasync/downloader/queue.go (L933-948)
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

**File:** datasync/downloader/downloader.go (L670-679)
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
```

**File:** datasync/downloader/downloader.go (L1881-1884)
```go
		if result.StakingInfo != nil {
			d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
			logger.Info("Imported new staking information", "number", result.StakingInfo.BlockNum)
		}
```

**File:** datasync/downloader/downloader.go (L1896-1898)
```go
	if result.StakingInfo != nil {
		d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
		logger.Info("Imported new staking information on pivot block", "number", result.StakingInfo.BlockNum, "pivot", block.Number())
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

**File:** kaiax/valset/impl/getter_demote.go (L42-56)
```go
	case istanbul.WeightedRandom:
		// All council members are qualified for WeightedRandom before Istanbul hardfork.
		if !rules.IsIstanbul {
			return valset.NewAddressSet(nil), nil
		}
		// Otherwise, filter out based on staking amounts.
		si, err := v.StakingModule.GetStakingInfo(num)
		if err != nil {
			return nil, err
		}
		return getDemotedValidatorsIstanbul(council, si, pset), nil
	default:
		return nil, errInvalidProposerPolicy
	}
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

**File:** kaiax/staking/staking_info.go (L33-57)
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

	// Computed fields
	consolidatedNodes  *[]consolidatedNode
	cachedGini         *float64
	cachedGiniMinStake uint64 // The minimum staking amount used to compute Gini coefficient.
}
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
