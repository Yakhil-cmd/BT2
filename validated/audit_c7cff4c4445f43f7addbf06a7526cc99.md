### Title
Single `MAX_REF_STALENESS` Applied to Both Legs of a Synthetic Feed Pair Allows Stale Quote-Leg Price to Reach Pool Swaps — (`smart-contracts-poc/contracts/AnchoredPriceProvider.sol`)

---

### Summary

`AnchoredPriceProvider` supports a two-feed synthetic ratio mode (e.g. BTC/USD ÷ ETH/USD = BTC/ETH). Both legs are staleness-checked against the **same** immutable `MAX_REF_STALENESS`. That value is envelope-validated at deployment only against the **base feed's** class; the quote feed's own heartbeat is never independently constrained. When the quote feed has a shorter heartbeat than `MAX_REF_STALENESS`, a stale quote-leg price passes the check and a corrupted synthetic mid reaches the pool's swap math.

---

### Finding Description

`_readLeg()` applies `MAX_REF_STALENESS` identically to every feed it is called with: [1](#0-0) 

`_getBidAndAskPrice()` calls `_readLeg` for both `baseFeedId` and `quoteFeedId` without any per-leg staleness override: [2](#0-1) 

`MAX_REF_STALENESS` is a single immutable set at construction: [3](#0-2) 

In `AnchoredProviderFactory.createAnchoredProvider()`, the envelope lookup is keyed exclusively on `baseFeedId`: [4](#0-3) 

The factory NatSpec explicitly acknowledges this gap — "The envelope is keyed on `baseFeedId` (the provider's class); the ref feed only contributes its uncertainty and is validated for existence at provider construction" — but provides no staleness bound for the quote leg: [5](#0-4) 

**Concrete scenario:**

| Feed | Real heartbeat | `MAX_REF_STALENESS` applied |
|---|---|---|
| BTC/USD (`baseFeedId`) | 3 600 s | 3 600 s ✓ |
| ETH/USD (`quoteFeedId`) | 60 s | 3 600 s ✗ |

A creator deploys a BTC/ETH provider with `maxRefStaleness = 3600`, which is within the BTC class envelope. The ETH/USD feed is updated every 60 s on-chain. If the ETH/USD pusher misses updates for, say, 1 800 s, `_readLeg(quoteFeedId)` still returns `ok = true` because `1800 <= 3600`. The synthetic mid `BTC/USD_stale / ETH/USD_stale` is then fed into `_computeBidAsk` and ultimately into the pool's swap math as a valid anchor price.

---

### Impact Explanation

A stale quote-leg price corrupts the synthetic mid used to compute the bid/ask band. Depending on the direction of ETH price drift during the stale window:

- **Overvalued synthetic**: the pool's ask is too low → a trader swaps in token0 and receives more token1 than the current market rate permits (pool loses token1 in excess of what the oracle-derived curve allows).
- **Undervalued synthetic**: the pool's bid is too high → a trader swaps in token1 and receives more token0 than warranted.

Both cases constitute **bad-price execution** (stale bid/ask quote reaches a pool swap), which is an allowed impact under the contest gate.

---

### Likelihood Explanation

- Synthetic (two-feed) providers are an explicitly supported and documented deployment mode.
- The factory is permissionless: any curator can deploy a synthetic provider with `maxRefStaleness` calibrated to the base feed's class envelope, unaware that the same value is applied to the quote leg.
- Quote feeds (e.g. ETH/USD on Pyth/Chainlink Data Streams) commonly have heartbeats of 1–60 s, far shorter than a typical base-feed envelope of minutes-to-hours.
- No on-chain guard prevents the mismatch; the only protection is off-chain curator diligence.

---

### Recommendation

Introduce a separate `maxQuoteStaleness` parameter for the quote leg, validated against the quote feed's own class envelope in `createAnchoredProvider`. Pass it as a second immutable to `AnchoredPriceProvider` and use it exclusively inside `_readLeg` when called for `quoteFeedId`. This mirrors the fix described in the external report: set a unique threshold per feed rather than sharing one across feeds with different heartbeats.

---

### Proof of Concept

1. Admin sets envelope for BTC class: `stalenessMin = 1800`, `stalenessMax = 7200`.
2. Curator calls `createAnchoredProvider(oracle, BTC_USD_feedId, ETH_USD_feedId, ..., maxRefStaleness=3600, ...)`.
3. Factory validates `3600` against BTC class envelope — passes.
4. ETH/USD pusher goes offline; ETH/USD `refTime` falls 1 800 s behind `block.timestamp`.
5. Pool calls `getBidAndAskPrice()` → `_getBidAndAskPrice()` → `_readLeg(ETH_USD_feedId)`.
6. `_isStale(refTime, block.timestamp, 3600)` → `1800 <= 3600` → `false` → `ok = true`.
7. Stale ETH/USD mid is used to compute `BTC/ETH` synthetic mid; corrupted bid/ask band is returned to the pool.
8. Trader executes a swap at the stale price, extracting value from the pool's LPs.

### Citations

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L75-77)
```text
    /// @notice Reference older than this (seconds) halts quoting — never clamp to a stale anchor.
    ///         Zero means the reference must be in the current block (refTime == block.timestamp).
    uint256 public immutable MAX_REF_STALENESS;
```

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L258-272)
```text
    function _getBidAndAskPrice() internal returns (uint128, uint128) {
        (uint256 mid, uint256 spreadBps, , bool ok) = _readLeg(baseFeedId);
        if (!ok) return (0, type(uint128).max);

        bytes32 _quote = quoteFeedId;
        if (_quote != bytes32(0)) {
            (uint256 mid2, uint256 spreadBps2, , bool ok2) = _readLeg(_quote);
            if (!ok2 || mid2 == 0) return (0, type(uint128).max);
            // Synthetic ratio (8-decimal): mid1 / mid2. Relative uncertainties of a ratio add.
            mid = Math.mulDiv(mid, ORACLE_DECIMALS, mid2);
            spreadBps += spreadBps2;
        }

        return _computeBidAsk(mid, spreadBps);
    }
```

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L277-283)
```text
    function _readLeg(bytes32 feedId)
        internal returns (uint256 mid, uint256 spreadBps, uint256 refTime, bool ok)
    {
        (mid, spreadBps, , refTime) = IPricedOracle(address(offchainOracle)).price(feedId, msg.sender);

        // Stale reference → not ok. Clamping to a stale anchor is the one false-safety case.
        if (_isStale(refTime, block.timestamp, MAX_REF_STALENESS)) return (mid, spreadBps, refTime, false);
```

**File:** smart-contracts-poc/contracts/AnchoredProviderFactory.sol (L153-155)
```text
    /// @param quoteFeedId optional second feed for synthetic ratio quoting (zero = single-feed). The
    ///        envelope is keyed on `baseFeedId` (the provider's class); the ref feed only contributes its
    ///        uncertainty and is validated for existence at provider construction.
```

**File:** smart-contracts-poc/contracts/AnchoredProviderFactory.sol (L170-180)
```text
        // Feeds without an explicit class fall back to the admin-configured DEFAULT_CLASS envelope.
        bytes32 classId = feedClass[baseFeedId];
        if (classId == bytes32(0)) classId = DEFAULT_CLASS;

        Envelope storage env = envelopes[classId];
        if (!env.exists) revert EnvelopeNotFound(classId);
        if (
            minMargin < env.minMarginMin || minMargin > env.minMarginMax
            || maxRefStaleness < env.stalenessMin || maxRefStaleness > env.stalenessMax
            || maxSpreadBps < env.maxSpreadMin || maxSpreadBps > env.maxSpreadMax
        ) revert ParamsOutOfEnvelope();
```
