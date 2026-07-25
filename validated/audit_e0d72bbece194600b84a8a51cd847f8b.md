### Title
Auction Bid Replacement Without Sender Balance Check Enables Griefing of Block Proposers and Legitimate Searchers — (File: `kaiax/auction/impl/bid_pool.go`)

---

### Summary

The `insertBid` function in the KIP-249 auction bid pool permanently evicts a legitimate bid whenever a higher bid for the same target transaction arrives, without verifying that the new bidder actually holds the claimed KAIA amount. A malicious searcher can obtain an auctioneer-signed bid while holding the required KAIA, submit it to displace a legitimate bid, then immediately drain their balance. When the block is built the generated bid transaction reverts, the block proposer loses the expected KAIA bid revenue, and the legitimate searcher's bid is permanently destroyed with no recovery path.

---

### Finding Description

**Replacement without balance check — `insertBid`**

`kaiax/auction/impl/bid_pool.go` lines 291–299 permanently delete the existing bid the moment a higher bid arrives:

```go
if existingBid, ok := bp.bidTargetMap[blockNumber][targetTxHash]; ok {
    if existingBid.Bid.Cmp(bid.Bid) >= 0 {
        return auction.ErrLowBid
    }
    delete(bp.bidMap, existingBid.Hash())
    delete(bp.bidWinnerMap[blockNumber], existingBid.Sender)
}
``` [1](#0-0) 

The evicted bid is removed from all three maps (`bidMap`, `bidTargetMap`, `bidWinnerMap`) and is never restored.

**No balance check in `validateBid`**

`validateBid` (lines 341–391) enforces six rules: duplicate detection, sender-winner conflict, block-number range, `bid.Bid > 0`, data-size cap, call-gas-limit cap, and signature validity. There is no check that `bid.Sender` actually holds `bid.Bid` KAIA at submission time. [2](#0-1) 

**Bid transaction is signed by the CN, not the searcher**

`GetBidTxGenerator` (getter.go lines 27–69) generates a transaction signed by the CN's own node key that calls `AuctionEntryPoint.call(auctionTx)`. The `AuctionEntryPoint` contract is responsible for pulling `bid.Bid` KAIA from `auctionTx.sender` at execution time. If the sender has drained their balance after bid submission, this call reverts and the proposer receives nothing. [3](#0-2) 

**Block builder has no fallback**

`ExtractTxBundles` (builder.go lines 31–70) reads only the current winner from `bidTargetMap`. Because the legitimate bid was already deleted at replacement time, there is no fallback bid to use if the winning bid transaction fails. [4](#0-3) 

---

### Impact Explanation

- **Block proposer loses KAIA bid revenue.** The proposer would have received the legitimate bid amount (e.g., 100 KAIA) from searcher A. After the griefing attack the bid transaction reverts and the proposer receives 0 KAIA for that slot.
- **Legitimate searcher permanently loses their MEV opportunity.** Searcher A's bid is irrecoverably deleted from all pool maps; there is no re-insertion or recovery mechanism.
- **Attacker's cost is negligible.** The only on-chain cost is the gas for a single KAIA transfer to drain the balance after bid submission.

---

### Likelihood Explanation

- Any party that can obtain an auctioneer-signed bid (by holding the required KAIA at signing time) can execute this attack.
- The `allowFutureBlock = 2` constant gives the attacker up to two full blocks to drain their balance after the bid is accepted into the pool. [5](#0-4) 

- The attack is repeatable: the malicious searcher can grief every auction slot for any target transaction at the cost of gas fees only.

---

### Recommendation

1. **Add a balance check in `validateBid`**: verify that `bid.Sender` holds at least `bid.Bid` KAIA at submission time using the current state.
2. **Require a lock-in deposit**: force the sender to lock `bid.Bid` KAIA in the pool (or in a system contract) at submission time, releasing it only when the block is finalized or the bid expires. This makes griefing economically costly.
3. **Restore the displaced bid on failure**: if the winning bid transaction reverts during block execution, re-insert the previously displaced bid so the proposer still has a chance to collect revenue.

---

### Proof of Concept

1. Legitimate searcher **A** (sender=`addrA`) submits a bid for `targetTxHash` with `bid = 100 KAIA`. `insertBid` stores it: `bidTargetMap[blockN][targetTxHash] = A's bid`.
2. Malicious searcher **B** holds 101 KAIA, obtains an auctioneer-signed bid for the same `targetTxHash` with `bid = 101 KAIA` (sender=`addrB`).
3. B calls `auction_submitBid`. `validateBid` passes (no balance check). `insertBid` executes:
   - `delete(bp.bidMap, A's bid hash)` — A's bid is gone.
   - `delete(bp.bidWinnerMap[blockN], addrA)` — A is removed from the winner list.
   - B's bid is stored as the new winner.
4. B immediately sends 101 KAIA to another address. `addrB` balance = 0.
5. Block N is built. `ExtractTxBundles` finds B's bid for `targetTxHash`. `GetBidTxGenerator` generates a CN-signed transaction calling `AuctionEntryPoint.call(B's auctionTx)`.
6. `AuctionEntryPoint` attempts to pull 101 KAIA from `addrB`. Balance is 0. The bid transaction **reverts**.
7. **Result**: block proposer receives 0 KAIA bid revenue (instead of 100 KAIA from A). A's bid is permanently lost. B's total cost: gas for one transfer transaction. [6](#0-5) [7](#0-6)

### Citations

**File:** kaiax/auction/impl/bid_pool.go (L39-39)
```go
	allowFutureBlock = 2
```

**File:** kaiax/auction/impl/bid_pool.go (L272-319)
```go
func (bp *BidPool) insertBid(bid *auction.Bid) error {
	bp.bidMu.Lock()
	defer bp.bidMu.Unlock()

	var (
		blockNumber  = bid.BlockNumber
		targetTxHash = bid.TargetTxHash
		sender       = bid.Sender
	)

	// Re-check bidWinnerMap here — two concurrent bids can pass validateBid together.
	if _, ok := bp.bidMap[bid.Hash()]; ok {
		return auction.ErrBidAlreadyExists
	}
	if bp.senderHasDifferentWinner(bid) {
		return auction.ErrBidSenderExists
	}

	// If same block number, same target tx hash exists, replace it if it's better
	if existingBid, ok := bp.bidTargetMap[blockNumber][targetTxHash]; ok {
		// FCFS if the bid is the same.
		if existingBid.Bid.Cmp(bid.Bid) >= 0 {
			return auction.ErrLowBid
		}

		logger.Trace("Replace bid", "old", existingBid.Hash(), "new", bid.Hash())
		delete(bp.bidMap, existingBid.Hash())
		delete(bp.bidWinnerMap[blockNumber], existingBid.Sender)
	} else {
		if int64(len(bp.bidMap)) >= bp.maxBidPoolSize {
			logger.Info("Bid pool is full", "maxBidPoolSize", bp.maxBidPoolSize, "bid", bid.Hash())
			return auction.ErrBidPoolFull
		}
	}

	hash := bid.Hash()

	bp.initializeBidMap(blockNumber)

	bp.bidMap[hash] = bid
	bp.bidTargetMap[blockNumber][targetTxHash] = bid
	bp.bidWinnerMap[blockNumber][sender] = hash

	numBidsGauge.Update(int64(len(bp.bidMap)))

	logger.Trace("Add bid", "bid", hash)

	return nil
```

**File:** kaiax/auction/impl/bid_pool.go (L341-391)
```go
func (bp *BidPool) validateBid(bid *auction.Bid) error {
	blockNumber := bid.BlockNumber

	bp.bidMu.RLock()

	// Check if the auction tx is already in the pool.
	if _, ok := bp.bidMap[bid.Hash()]; ok {
		bp.bidMu.RUnlock()
		return auction.ErrBidAlreadyExists
	}

	// 1. The `bid.Sender` must not be in the winner list of the same block number if the new bid isn't equal to the previous bid.
	if bp.senderHasDifferentWinner(bid) {
		bp.bidMu.RUnlock()
		return auction.ErrBidSenderExists
	}
	bp.bidMu.RUnlock()

	curBlock := bp.Chain.CurrentBlock()
	if curBlock == nil {
		return auction.ErrBlockNotFound
	}

	// 2. The `bid.BlockNumber` must be in range of `[currentBlockNumber + 1, currentBlockNumber + allowFutureBlock]`.
	curNum := curBlock.NumberU64()
	if blockNumber <= curNum || blockNumber > curNum+allowFutureBlock {
		return auction.ErrInvalidBlockNumber
	}

	// 3. The `bid.Bid` must be greater than 0.
	if bid.Bid.Sign() <= 0 {
		return auction.ErrZeroBid
	}

	// 4. The data size must be less than the maximum limit.
	if uint64(len(bid.Data)) > BidTxMaxDataSize {
		return auction.ErrExceedMaxDataSize
	}

	// 5. The gas limit must be less than the maximum limit.
	if bid.CallGasLimit > BidTxMaxCallGasLimit {
		return auction.ErrExceedMaxCallGasLimit
	}

	// 6. The `bid.SearcherSig` and `bid.AuctioneerSig` must be valid.
	if err := bp.validateBidSigs(bid); err != nil {
		return err
	}

	return nil
}
```

**File:** kaiax/auction/impl/getter.go (L27-69)
```go
func (a *AuctionModule) GetBidTxGenerator(tx *types.Transaction, bid *auction.Bid) *builder.TxOrGen {
	gen := func(nonce uint64) (*types.Transaction, error) {
		var (
			chainId           = a.InitOpts.ChainConfig.ChainID
			signer            = types.LatestSignerForChainID(chainId)
			auctionEntryPoint = a.bidPool.GetAuctionEntryPoint()
			key               = a.InitOpts.NodeKey
		)

		data, err := system.EncodeAuctionCallData(bid, a.bidPool.GetAuctionEntryPointVersion())
		if err != nil {
			return nil, err
		}

		if bid.GetGasLimit() == 0 {
			gasLimit, err := a.bidPool.getBidTxGasLimit(bid)
			if err != nil {
				return nil, err
			}
			bid.SetGasLimit(gasLimit)
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeEthereumDynamicFee, map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      nonce,
			types.TxValueKeyTo:         &auctionEntryPoint,
			types.TxValueKeyAmount:     common.Big0,
			types.TxValueKeyData:       data,
			types.TxValueKeyGasLimit:   bid.GetGasLimit(),
			types.TxValueKeyGasFeeCap:  tx.GasFeeCap(),
			types.TxValueKeyGasTipCap:  tx.GasTipCap(),
			types.TxValueKeyAccessList: types.AccessList{},
			types.TxValueKeyChainID:    chainId,
		})
		if err != nil {
			return nil, err
		}

		err = tx.Sign(signer, key)

		return tx, err
	}

	return builder.NewTxOrGenFromGen(gen, bid.Hash())
```

**File:** kaiax/auction/impl/builder.go (L44-67)
```go
	for _, tx := range txs {
		txHash := tx.Hash()
		bid, ok := bidTargetMap[txHash]
		if !ok {
			continue
		}
		b := builder.NewBundle(
			builder.NewTxOrGenList(a.GetBidTxGenerator(tx, bid)),
			txHash,
			true,
		)

		isConflict := false
		for _, prev := range append(prevBundles, bundles...) {
			if prev.IsConflict(b) {
				isConflict = true
				break
			}
		}
		if isConflict {
			continue
		}
		bundles = append(bundles, b)
	}
```

**File:** kaiax/auction/impl/api.go (L118-141)
```go
func (api *AuctionAPI) SubmitBid(ctx context.Context, bidInput BidInput) RPCOutput {
	numBidRequestCounter.Inc(1)
	if api.a.IsDisabled() {
		return makeRPCOutput(EMPTY_HASH, auction.ErrAuctionDisabled)
	}

	//  1. directly send target transaction
	targetTx, errTxDecode := toTx(bidInput.TargetTxRaw)
	if errTxDecode != nil {
		return makeRPCOutput(EMPTY_HASH, errTxDecode)
	}
	if targetTx.Hash() != bidInput.TargetTxHash {
		return makeRPCOutput(EMPTY_HASH, auction.ErrInvalidTargetTxHash)
	}
	errTargetTxSend := api.a.Backend.SendTx(ctx, targetTx)
	// ignore known transaction related errors against target tx validation
	if errTargetTxSend != nil && !(strings.HasPrefix(errTargetTxSend.Error(), "known transaction:") || errors.Is(errTargetTxSend, gasless_impl.ErrUnableToAddKnownBundleTx)) {
		return makeRPCOutput(EMPTY_HASH, errTargetTxSend)
	}

	// 2. add bid
	bid := ToBid(bidInput)
	bidHash, errValidateBid := api.a.bidPool.AddBid(bid)
	return makeRPCOutput(bidHash, errValidateBid)
```
