### Title
Unvalidated Staking Info Accepted from Malicious Peer During Fast Sync Corrupts Reward Distribution — (`File: datasync/downloader/queue.go`)

---

### Summary

`queue.DeliverStakingInfos` in `datasync/downloader/queue.go` accepts peer-supplied staking information during fast sync with a deliberately empty validation function (`// TODO-Kaia-Snapsync update validation logic`). Every other data type delivered during fast sync — block bodies and receipts — is cryptographically validated against the corresponding block header before being accepted. Staking info is not. A malicious peer can therefore inject arbitrary staking records for any requested block, which are written unconditionally to the node's database and subsequently used to drive KAIA reward distribution and validator-set selection for all pre-Kaia-hardfork blocks.

---

### Finding Description

During fast sync the downloader fetches staking info from peers via `FetchStakingInfo` / `RequestStakingInfo` and delivers the response through `queue.DeliverStakingInfos`. The `deliver` helper accepts a `validate` callback that is supposed to verify the delivered data against the canonical block header before the data is committed to the result cache.

For block bodies the validation is:

```go
// datasync/downloader/queue.go  DeliverBodies
validate := func(index int, header *types.Header) error {
    if types.DeriveTransactionsRoot(types.Transactions(txLists[index]), header.Number) != header.TxHash {
        return errInvalidBody
    }
    return nil
}
```

For receipts:

```go
// datasync/downloader/queue.go  DeliverReceipts
validate := func(index int, header *types.Header) error {
    if types.DeriveReceiptsRoot(types.Receipts(receiptList[index]), header.Number) != header.ReceiptHash {
        return errInvalidReceipt
    }
    return nil
}
```

For staking info:

```go
// datasync/downloader/queue.go  DeliverStakingInfos  (lines 956-959)
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
```

The validate function is a permanent no-op. Any staking payload a peer sends is accepted, placed in the result cache, and then committed to the database in `commitFastSyncData` and `commitPivotBlock`:

```go
// datasync/downloader/downloader.go  commitFastSyncData  (lines 1881-1884)
if result.StakingInfo != nil {
    d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
    logger.Info("Imported new staking information", "number", result.StakingInfo.BlockNum)
}
```

The staking info stored in the database is the authoritative source for all pre-Kaia-hardfork blocks. `StakingModule.GetStakingInfo` reads from the database first for those blocks:

```go
// kaiax/staking/impl/getter.go  (lines 57-63)
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        s.stakingInfoCache.Add(sourceNum, si)
        return si, nil
    }
}
```

The staking info drives both reward distribution (KIF/KEF/KPF fund addresses, per-validator KAIA amounts) and qualified-validator selection. Corrupted staking info therefore directly corrupts both.

---

### Impact Explanation

A malicious peer connected during fast sync can supply fabricated `P2PStakingInfo` records for any requested block. Because no field of the delivered struct is checked against the block header, the attacker can:

1. **Redirect KAIA rewards** — replace `KIFAddr`, `KEFAddr`, `KPFAddr`, or individual `RewardAddrs` with attacker-controlled addresses. Every subsequent call to `getDeferredRewardFullKore` / `getDeferredRewardFullFlex` that reads the corrupted staking info will send minted KAIA and fee shares to the attacker's addresses instead of the legitimate fund and validator addresses.

2. **Manipulate the validator set** — replace `NodeIds` and `StakingAmounts` to demote legitimate validators or promote illegitimate ones, affecting `GetQualifiedValidators` and therefore proposer selection and committed-seal verification for historical blocks.

Both effects persist in the database across restarts and affect every consumer of `GetStakingInfo` for the corrupted block range.

---

### Likelihood Explanation

- The attacker only needs to be a connected P2P peer at the time the victim node performs fast sync — a standard, semi-trusted network position.
- No cryptographic material or privileged access is required.
- The attack window is the entire fast-sync phase, which can last minutes to hours on a fresh node.
- The `SyncStakingInfo` recovery path (used by operators to repair missing staking info) has the same missing validation and is also reachable by a single named peer.

---

### Recommendation

Implement a deterministic commitment of staking info into the block header (e.g., a hash of the canonical staking info stored in `header.Extra` or a dedicated field), and validate the delivered staking info against that commitment inside the `validate` callback in `DeliverStakingInfos`, mirroring the pattern used by `DeliverBodies` and `DeliverReceipts`. Until a header commitment exists, at minimum verify that `stakingInfoList[index].BlockNum` matches `header.Number.Uint64()` and that the node IDs and amounts are within expected bounds.

---

### Proof of Concept

1. Attacker runs a Kaia node and connects to a victim node that is performing fast sync.
2. When the victim requests staking info for block `N` via `RequestStakingInfo([hash_of_N])`, the attacker responds with a `P2PStakingInfo` where `BlockNum = N` but `KIFAddr`, `KEFAddr`, and all `RewardAddrs` are replaced with attacker-controlled addresses.
3. `handleStakingInfoMsg` → `pm.downloader.DeliverStakingInfos` → `queue.DeliverStakingInfos` accepts the payload without any validation (the `validate` callback returns `nil` unconditionally).
4. `commitFastSyncData` calls `d.stakingModule.PutStakingInfoToDB(N, ...)`, writing the fabricated record to the database.
5. After sync completes, any call to `GetStakingInfo(num)` for a block whose source block is `N` returns the fabricated staking info.
6. `FinalizeState` → `getDeferredRewardFullKore` reads `si.KIFAddr` (attacker address) and transfers the KIF portion of every block reward to the attacker.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** datasync/downloader/queue.go (L884-921)
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
```

**File:** datasync/downloader/queue.go (L936-947)
```go
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
