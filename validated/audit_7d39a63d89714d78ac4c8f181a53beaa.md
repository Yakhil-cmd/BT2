The key finding is in `AnchoredPriceProvider.sol`. In the synthetic ratio mode, `_getBidAndAskPrice` calls `_readLeg` for both the base and quote feeds, but **discards the `refTime` return value from both legs** — meaning the two feeds' timestamps are never compared against each other.

### Title
Synthetic Ratio Price in `AnchoredPriceProvider` Uses Temporally Mismatched Feed Timestamps, Enabling Bad-Price Swap Execution Against LPs - (File: smart-contracts-poc/contracts/AnchoredPriceProvider.sol)

### Summary

`AnchoredPriceProvider._getBidAndAskPrice()` in synthetic ratio mode reads two independent oracle feeds (`baseFeedId` and `quoteFeedId`) and divides their prices to produce a synthetic mid (e.g., BTC/USD ÷ ETH/USD = BTC/ETH). Each leg is individually checked for staleness against `block.timestamp`, but the two legs' `refTime` values are **never compared against each other**. The `refTime` return value from `_readLeg` is explicitly discarded at both call sites. The two feeds can therefore be up to `MAX_REF_STALENESS` seconds apart in time (up to 7 days by the constructor cap), and the resulting ratio price — which drives live swap bid/ask quotes — reflects prices from materially different market moments.

### Finding Description

In `_getBidAndAskPrice()`, the synthetic ratio path is:

```solidity
(uint256 mid,  uint256 spreadBps,  , bool ok)  = _readLeg(baseFeedId);   // refTime discarded
...
(uint256 mid2, uint256 spreadBps2, , bool ok2) = _readLeg(_quote);        // refTime discarded
mid = Math.mulDiv(mid, ORACLE_DECIMALS, mid2);
spreadBps += spreadBps2;
```

`_readLeg` returns `(mid, spreadBps, uint256 refTime, bool ok)` and checks:

```solidity
if (_isStale(refTime, block.timestamp, MAX_REF_STALENESS)) return (..., false);
```

Each leg passes its own staleness gate independently. The caller discards `refTime` (the blank `,` in the destructuring) and never computes `|refTime1 − refTime2|`. The two feeds can therefore be up to `MAX_REF_STALENESS` apart — a value the constructor allows up to 7 days:

```solidity
if (_maxRefStaleness > 7 days) revert MaxRefStalenessOutOfBounds();
MAX_REF_STALENESS = _maxRefStaleness;
```

The corrupted ratio `mid1/mid2` is passed directly to `_computeBidAsk`, which produces the bid/ask quotes consumed by the pool's swap engine.

### Impact Explanation

The bid/ask quote delivered to the pool's swap is computed from prices at two different points in time. During volatile periods, the ratio can be materially wrong in either direction:

- **Ratio too low** (base feed stale-low, quote feed fresh-high): the ask price is below true market. Traders buy the base token at a discount, extracting value from LPs who receive less quote token than the true market rate.
- **Ratio too high** (base feed fresh-high, quote feed stale-low): the bid price is above true market. Traders sell the base token at a premium, again extracting value from LPs who pay more quote token than the true market rate.

In both cases LP principal is directly drained through swap settlement at a wrong price. This is a direct loss of LP assets, satisfying the contest's "Bad-price execution: stale, inverted, unbounded, or unclamped bid/ask quote reaches a pool swap" impact gate.

### Likelihood Explanation

The trigger requires only that one feed updates while the other does not — a routine occurrence on any chain where Pyth or Chainlink feeds update at different cadences or during congestion. No privileged action is required; any swap through a synthetic-ratio pool during such a window is sufficient. The window is as wide as `MAX_REF_STALENESS`, which can be configured up to 7 days.

### Recommendation

After both legs pass their individual staleness checks, compare their `refTime` values and halt if the discrepancy exceeds a configurable `MAX_LEG_SKEW` threshold:

```solidity
(uint256 mid,  uint256 spreadBps,  uint256 refTime1, bool ok)  = _readLeg(baseFeedId);
if (!ok) return (0, type(uint128).max);

bytes32 _quote = quoteFeedId;
if (_quote != bytes32(0)) {
    (uint256 mid2, uint256 spreadBps2, uint256 refTime2, bool ok2) = _readLeg(_quote);
    if (!ok2 || mid2 == 0) return (0, type(uint128).max);

    // Cross-leg timestamp coherence check
    uint256 skew = refTime1 > refTime2 ? refTime1 - refTime2 : refTime2 - refTime1;
    if (skew > MAX_LEG_SKEW) return (0, type(uint128).max);

    mid = Math.mulDiv(mid, ORACLE_DECIMALS, mid2);
    spreadBps += spreadBps2;
}
```

`MAX_LEG_SKEW` should be an immutable set at construction, bounded to a small fraction of `MAX_REF_STALENESS` (e.g., 60–300 seconds for typical price feeds).

### Proof of Concept

1. Deploy `AnchoredPriceProvider` in synthetic mode with `MAX_REF_STALENESS = 3600` (1 hour), `baseFeedId = BTC/USD`, `quoteFeedId = ETH/USD`.
2. At `t = 0`: set both feeds to `BTC/USD = 60_000e8`, `ETH/USD = 3_000e8` → synthetic BTC/ETH mid = 20.
3. Advance time by 3599 seconds. Update only `BTC/USD` to `60_000e8` (unchanged price, fresh timestamp). Leave `ETH/USD` at its `t=0` data (refTime = 1 second old relative to `MAX_REF_STALENESS`, still valid).
4. Now update `ETH/USD` price in the oracle storage to `2_000e8` (a 33% ETH price drop) but keep its `refTime` at `t=0` (3599 seconds ago — still within `MAX_REF_STALENESS`).
5. Call `getBidAndAskPrice()`: both legs pass `_isStale` independently. The synthetic mid is computed as `60_000e8 / 2_000e8 = 30` instead of the true `60_000e8 / 3_000e8 = 20`.
6. The pool's ask is now ~30 Q64 units. A trader swaps, buying BTC at a 50% discount relative to the true BTC/ETH rate, draining LP funds. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L150-151)
```text
        if (_maxRefStaleness > 7 days) revert MaxRefStalenessOutOfBounds(); // 0 allowed = same-block reference
        MAX_REF_STALENESS = _maxRefStaleness;
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
