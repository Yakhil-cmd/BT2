### Title
Static `ChainConfig.ChainID` in EIP-712 Domain Separator Enables Bid Signature Replay on Forked Chains - (`kaiax/auction/impl/bid_pool.go`)

---

### Summary

The auction module's bid signature validation uses `bp.ChainConfig.ChainID` — a static value set at node initialization — as the `chainId` field in the EIP-712 domain separator. In the event of a contentious hard fork where both chains share the same chain ID (the common case for Kaia protocol upgrades), a bid signed and auctioneer-countersigned on one chain can be replayed verbatim on the other chain within the 2-block acceptance window, causing unauthorized KAIA-denominated bid execution and fee consumption on the forked chain.

---

### Finding Description

`BidPool.validateBidSigs` calls `bid.ValidateSearcherSig` with the static `bp.ChainConfig.ChainID`: [1](#0-0) 

`ValidateSearcherSig` delegates to `GetHashTypedData`, which builds the EIP-712 domain separator using the caller-supplied `chainId`: [2](#0-1) 

The domain separator encodes `chainId` as a 32-byte big-endian word: [3](#0-2) 

`bp.ChainConfig.ChainID` is assigned once at `BidPool` construction from the genesis `params.ChainConfig` and never refreshed: [4](#0-3) 

The auctioneer's countersignature (`ValidateAuctioneerSig`) signs only over the raw bytes of `b.SearcherSig` with no chain-ID binding whatsoever: [5](#0-4) 

Because neither the static `ChainConfig.ChainID` nor the auctioneer signature changes across a fork, a fully-formed `(SearcherSig, AuctioneerSig)` pair from chain A is cryptographically indistinguishable from a legitimate bid on chain B.

---

### Impact Explanation

A replayed bid that passes `validateBid` is inserted into the `BidPool` and forwarded to `GetBidTxGenerator`, which signs and submits a real on-chain transaction from the auctioneer's node key: [6](#0-5) 

Consequences on the forked chain:
- **Unauthorized KAIA fee consumption**: the auctioneer's node pays gas for every replayed bid transaction.
- **Unauthorized MEV execution**: the auction entry-point contract executes the replayed bid's `calldata` against the forked chain's state, potentially transferring KAIA or ERC-20 tokens to the searcher.
- **Nonce consumption**: each replayed bid increments the auctioneer's on-chain nonce, potentially blocking legitimate bids.

---

### Likelihood Explanation

The attack window is bounded by the `allowFutureBlock = 2` check in `validateBid`: [7](#0-6) 

Immediately after a fork at block N, bids signed for blocks N+1 and N+2 on the original chain are valid on the fork. An attacker monitoring the P2P network can collect signed bids and replay them on the fork within this 2-block window. Because Kaia's chain ID (8217 mainnet / 1001 testnet) does not change during protocol upgrades, any upgrade-triggered fork creates this window without any additional attacker capability.

---

### Recommendation

Replace the static `bp.ChainConfig.ChainID` with the chain ID read from the current block header at validation time. The `BidPool` already holds a reference to the chain (`bp.Chain`), so the current block's chain ID can be retrieved dynamically:

```go
// In validateBidSigs, replace:
bid.ValidateSearcherSig(bp.ChainConfig.ChainID, bp.auctionEntryPoint, bp.auctionEntryPointVersion)

// With:
curBlock := bp.Chain.CurrentBlock()
chainID := bp.ChainConfig.ChainIDAt(curBlock.Number())
bid.ValidateSearcherSig(chainID, bp.auctionEntryPoint, bp.auctionEntryPointVersion)
```

If `ChainConfig` does not expose a per-block chain ID accessor, read `curBlock.Header().ChainID` (if available) or derive it from the signer. For gas efficiency, cache the chain ID and recompute the domain separator only when the chain ID changes — mirroring the EIP-712 reference implementation pattern.

Additionally, bind the auctioneer's countersignature to the chain ID (include `chainId` in the data signed by `GetEthSignedMessageHash`) so that both signatures are fork-resistant independently.

---

### Proof of Concept

1. At block N on Kaia mainnet (chain ID 8217), a searcher submits a bid targeting block N+1. The auctioneer validates and countersigns it. The bid `(SearcherSig, AuctioneerSig)` is broadcast over P2P.

2. A contentious hard fork occurs at block N. Both chains continue with chain ID 8217 and block numbers N+1, N+2, …

3. An attacker captures the bid from chain A's P2P traffic and injects it into chain B's P2P layer.

4. Chain B's `BidPool.validateBid` runs:
   - Block number N+1 satisfies `curNum < N+1 <= curNum+2` ✓
   - `validateBidSigs` recomputes the EIP-712 digest with `bp.ChainConfig.ChainID = 8217` — identical to chain A — and recovers `bid.Sender` correctly ✓
   - `ValidateAuctioneerSig` verifies the auctioneer's signature over the unchanged `SearcherSig` bytes ✓

5. The bid is accepted, `GetBidTxGenerator` fires, and the auctioneer's node on chain B submits a signed transaction to the auction entry-point, executing the replayed bid and consuming KAIA from the auctioneer's balance.

### Citations

**File:** kaiax/auction/impl/bid_pool.go (L78-98)
```go
func NewBidPool(chainConfig *params.ChainConfig, chain backends.BlockChainForCaller, auctionConfig *auction.AuctionConfig) *BidPool {
	if chainConfig == nil || chain == nil || auctionConfig == nil {
		return nil
	}

	bp := &BidPool{
		ChainConfig:     chainConfig,
		Chain:           chain,
		bidMap:          make(map[common.Hash]*auction.Bid),
		bidTargetMap:    make(map[uint64]map[common.Hash]*auction.Bid),
		bidWinnerMap:    make(map[uint64]map[common.Address]common.Hash),
		peerRateLimiter: make(map[string]*rate.Limiter),
		bidMsgCh:        make(chan *auction.Bid, bidChSize),
		newBidCh:        make(chan *auction.Bid, bidChSize),
		maxBidPoolSize:  auctionConfig.MaxBidPoolSize,
		running:         0, // not running yet
		stopped:         0, // not stopped
	}

	return bp
}
```

**File:** kaiax/auction/impl/bid_pool.go (L364-368)
```go
	// 2. The `bid.BlockNumber` must be in range of `[currentBlockNumber + 1, currentBlockNumber + allowFutureBlock]`.
	curNum := curBlock.NumberU64()
	if blockNumber <= curNum || blockNumber > curNum+allowFutureBlock {
		return auction.ErrInvalidBlockNumber
	}
```

**File:** kaiax/auction/impl/bid_pool.go (L404-407)
```go
	// Verify the EIP712 signature.
	if err := bid.ValidateSearcherSig(bp.ChainConfig.ChainID, bp.auctionEntryPoint, bp.auctionEntryPointVersion); err != nil {
		return err
	}
```

**File:** kaiax/auction/eip712.go (L62-68)
```go
func (d EIP712Domain) EncodeData() []byte {
	encoded := make([]byte, 0)
	encoded = append(encoded, d.NameHash.Bytes()...)
	encoded = append(encoded, d.VersionHash.Bytes()...)
	encoded = append(encoded, common.LeftPadBytes(d.ChainId.Bytes(), 32)...)
	encoded = append(encoded, common.LeftPadBytes(d.VerifyingContract.Bytes(), 32)...)
	return encoded
```

**File:** kaiax/auction/eip712.go (L124-137)
```go
func (b *Bid) GetHashTypedData(chainId *big.Int, verifyingContract common.Address, version string) []byte {
	if chainId == nil {
		return nil
	}

	domain := EIP712Domain{
		EIP712DomainTypeHash: eip712TypeHash,
		NameHash:             auctionNameHash,
		VersionHash:          crypto.Keccak256Hash([]byte(version)),
		ChainId:              chainId,
		VerifyingContract:    verifyingContract,
	}

	domainSeparator := EncodeEIP712(domain)
```

**File:** kaiax/auction/bid.go (L52-55)
```go
func (b *Bid) GetEthSignedMessageHash() []byte {
	data := b.SearcherSig
	return crypto.Keccak256(fmt.Appendf(nil, "\x19Ethereum Signed Message:\n%d%s", len(data), data))
}
```

**File:** kaiax/auction/impl/getter.go (L27-67)
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
```
