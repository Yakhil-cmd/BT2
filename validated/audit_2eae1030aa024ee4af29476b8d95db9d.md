The key finding is in `AnchoredPriceProvider.sol`. In synthetic (two-feed) mode, both `baseFeedId` and `quoteFeedId` are validated through `_readLeg`, which applies the single immutable `MAX_REF_STALENESS` to both feeds. This is the direct analog of the JOJO M-12 bug.

---

### Title
Single `MAX_REF_STALENESS` Applied to Both Legs of Synthetic Feed Pair Causes Downtime or Stale-Price Execution — (`smart-contracts-poc/contracts/AnchoredPriceProvider.sol`)

### Summary

`AnchoredPriceProvider` supports a synthetic ratio mode where `baseFeedId` and `quoteFeedId` (e.g., BTC/USD ÷ ETH/USD = BTC/ETH) are read and combined. Both legs are validated through `_readLeg`, which applies the single immutable `MAX_REF_STALENESS` to both feeds. Because different oracle feeds have different native heartbeats, a single threshold cannot be simultaneously correct for both legs: it either causes near-constant downtime or permits stale prices from the faster-updating feed to reach pool swaps.

### Finding Description

`_getBidAndAskPrice` calls `_readLeg(baseFeedId)` and, when `quoteFeedId != bytes32(0)`, `_readLeg(quoteFeedId)`: [1](#0-0) 

Inside `_readLeg`, the staleness check is: [2](#0-1) 

The single `MAX_REF_STALENESS` immutable is set once at construction from a single `_maxRefStaleness` parameter: [3](#0-2) 

There is no per-leg staleness parameter. Both feeds are checked against the same threshold regardless of their individual oracle heartbeats.

### Impact Explanation

Consider a synthetic BTC/ETH pool backed by BTC/USD (1-hour Chainlink heartbeat) and USDC/USD (24-hour Chainlink heartbeat):

- **If `MAX_REF_STALENESS` = 1 hour**: The USDC/USD feed is valid for 24 hours between updates, so `_readLeg` will return `ok = false` for ~23 out of every 24 hours. The pool is non-functional the vast majority of the time — broken core swap/liquidity functionality.
- **If `MAX_REF_STALENESS` = 24 hours**: The BTC/USD feed can be up to 24 hours stale before rejection. A stale BTC/USD price (e.g., from a market crash) reaches `_computeBidAsk` and produces a bad bid/ask that pool swaps execute against — direct loss of LP principal via mispriced swaps.

Both outcomes match the allowed impact gate: broken core pool functionality and bad-price execution reaching swaps.

### Likelihood Explanation

The synthetic (two-feed) mode is an explicitly supported and documented deployment path. Any pool pairing a crypto asset feed (1-hour heartbeat) with a stablecoin or RWA feed (24-hour heartbeat) triggers this condition. The deployer has no way to set a single `MAX_REF_STALENESS` that is simultaneously correct for both legs — the structural limitation is inherent to the single-parameter design.

### Recommendation

Add a separate `maxQuoteStaleness` immutable for the quote leg. Pass it as a distinct constructor parameter and apply it only in `_readLeg` when processing `quoteFeedId`:

```solidity
uint256 public immutable MAX_REF_STALENESS;      // base leg
uint256 public immutable MAX_QUOTE_STALENESS;    // quote leg (synthetic mode)
```

In `_readLeg`, accept the applicable threshold as a parameter rather than always reading `MAX_REF_STALENESS`, and pass `MAX_REF_STALENESS` for the base leg and `MAX_QUOTE_STALENESS` for the quote leg at the call sites in `_getBidAndAskPrice`.

### Proof of Concept

1. Deploy `AnchoredPriceProvider` in synthetic mode with `baseFeedId = BTC/USD` (1-hour heartbeat), `quoteFeedId = USDC/USD` (24-hour heartbeat), and `MAX_REF_STALENESS = 3600` (1 hour).
2. Advance time by 3601 seconds without updating the USDC/USD feed (normal behavior for a 24-hour feed).
3. Call `getBidAndAskPrice()` — `_readLeg(quoteFeedId)` returns `ok = false` because `(nowTs - refTime) > MAX_REF_STALENESS`, causing `FeedStalled` revert.
4. The pool is non-functional for ~23 hours out of every 24 despite the USDC/USD feed being perfectly healthy.

Alternatively, set `MAX_REF_STALENESS = 86400` (24 hours): the BTC/USD feed can now be 24 hours stale, and a swap executes against yesterday's BTC price — direct LP loss. [4](#0-3)

### Citations

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L150-151)
```text
        if (_maxRefStaleness > 7 days) revert MaxRefStalenessOutOfBounds(); // 0 allowed = same-block reference
        MAX_REF_STALENESS = _maxRefStaleness;
```

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L258-271)
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
```

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L277-295)
```text
    function _readLeg(bytes32 feedId)
        internal returns (uint256 mid, uint256 spreadBps, uint256 refTime, bool ok)
    {
        (mid, spreadBps, , refTime) = IPricedOracle(address(offchainOracle)).price(feedId, msg.sender);

        // Stale reference → not ok. Clamping to a stale anchor is the one false-safety case.
        if (_isStale(refTime, block.timestamp, MAX_REF_STALENESS)) return (mid, spreadBps, refTime, false);

        // Basic validity — mid positive, spreadBps not the stalled/off-hours marker (the Chainlink oracle
        // writes spreadBps = ORACLE_BPS when an RWA market is closed).
        if (mid == 0 || spreadBps >= ORACLE_BPS) return (mid, spreadBps, refTime, false);

        // Per-leg price guard.
        (uint128 guardMin, uint128 guardMax) = offchainOracle.priceGuard(feedId);
        guardMax = guardMax == 0 ? type(uint128).max : guardMax;
        if (mid < guardMin || mid > guardMax) return (mid, spreadBps, refTime, false);

        ok = true;
    }
```
