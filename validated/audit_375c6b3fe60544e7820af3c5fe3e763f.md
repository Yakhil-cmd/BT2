### Title
Immutable `MAX_SPREAD_BPS` circuit breaker in `AnchoredPriceProvider` freezes all pool swaps during oracle volatility with no timely recovery path — (`smart-contracts-poc/contracts/AnchoredPriceProvider.sol`)

### Summary

`AnchoredPriceProvider` contains an immutable circuit-breaker (`MAX_SPREAD_BPS`) that halts all price quotes when the oracle's reported confidence interval exceeds the threshold. During high market volatility, Pyth's spread can legitimately widen beyond any fixed threshold, causing every `swap()` call on the pool to revert. The only recovery path — deploying a new price provider and executing the timelock — can take days to weeks, leaving the pool non-functional exactly when trading activity is highest.

### Finding Description

**Step 1 — Circuit breaker in `_computeBidAsk`** [1](#0-0) 

When `spreadBps > MAX_SPREAD_BPS`, `_computeBidAsk` returns the sentinel `(0, type(uint128).max)`.

**Step 2 — `MAX_SPREAD_BPS` is immutable** [2](#0-1) 

It is set once at construction and can never be changed: [3](#0-2) 

**Step 3 — Sentinel propagates to a revert**

`getBidAndAskPrice()` converts the sentinel into a hard revert: [4](#0-3) 

**Step 4 — Pool catches and re-reverts, blocking every swap** [5](#0-4) 

`swap()` calls `_getBidAndAskPriceX64()` unconditionally before any state change, so every swap reverts with `PriceProviderFailed` for as long as the oracle spread exceeds `MAX_SPREAD_BPS`.

**Step 5 — Recovery requires a timelock that cannot be shortened**

The only recourse is `proposePoolPriceProvider` + `executePoolPriceProviderUpdate`. The timelock is stored at pool creation and is never updated: [6](#0-5) [7](#0-6) 

If the timelock is set to days or weeks (a normal security posture), swaps remain frozen for that entire duration.

**Step 6 — Staleness and `priceGuard` create additional immutable halt conditions**

`_readLeg` also returns `ok = false` (→ halt) on staleness or price-guard violation, both of which are immutable: [8](#0-7) 

### Impact Explanation

All `swap()` calls on any pool using `AnchoredPriceProvider` revert for the entire duration that the oracle spread exceeds `MAX_SPREAD_BPS`. LPs cannot rebalance, arbitrageurs cannot trade, and the pool accumulates stale inventory risk. This is broken core pool functionality — the swap flow is completely unusable — satisfying the allowed impact gate.

### Likelihood Explanation

Pyth's confidence interval is a first-class output that widens materially during flash crashes, depegs, and high-volatility events. A `MAX_SPREAD_BPS` value that is safe under normal conditions (e.g., 100–300 bps) can be exceeded during a 5–10% intraday move. Because the parameter is immutable and the timelock cannot be shortened, the freeze persists for the full timelock window — potentially days — after the oracle recovers.

### Recommendation

Mirror the M-08 mitigation: instead of halting entirely when `spreadBps > MAX_SPREAD_BPS`, fall back to quoting the band at `MAX_SPREAD_BPS` (i.e., clamp `spreadBps = MAX_SPREAD_BPS` and continue). This preserves the circuit-breaker's protection against a genuinely broken feed while allowing the pool to continue operating with a wider, more conservative spread during volatility. Alternatively, allow the factory owner to update `priceProviderTimelock` for a pool in an emergency, so the recovery path is not permanently gated by the original timelock.

### Proof of Concept

1. Deploy `AnchoredPriceProvider` with `MAX_SPREAD_BPS = 200` (2%) and `MAX_REF_STALENESS = 60`.
2. Create a pool using this provider; `priceProviderTimelock[pool] = 7 days`.
3. A market stress event occurs; Pyth reports `spreadBps = 250` (2.5%) for the feed.
4. `_readLeg` returns `ok = true` (staleness and guard pass), `spreadBps = 250`.
5. `_computeBidAsk`: `250 > 200` → returns `(0, type(uint128).max)`.
6. `getBidAndAskPrice()` reverts with `FeedStalled`.
7. `MetricOmmPool.swap()` catches and reverts with `PriceProviderFailed`.
8. Pool admin calls `proposePoolPriceProvider` with a new provider; `executeAfter = block.timestamp + 7 days`.
9. Swaps remain frozen for 7 days even after the oracle spread normalises within hours.

### Citations

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L79-81)
```text
    ///         Below it, growing `spreadBps` only widens the band (widen, don't halt).
    uint16  public immutable MAX_SPREAD_BPS;

```

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L153-154)
```text
        if (_maxSpreadBps == 0 || _maxSpreadBps >= ORACLE_BPS) revert MaxSpreadOutOfBounds();
        MAX_SPREAD_BPS = _maxSpreadBps;
```

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L214-217)
```text
    function getBidAndAskPrice() external override returns (uint128 bid, uint128 ask) {
        (bid, ask) = _getBidAndAskPrice();
        if (bid == 0 || ask == type(uint128).max) revert FeedStalled();
    }
```

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L282-294)
```text
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
```

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L302-305)
```text
        // Circuit breaker: extreme (combined) uncertainty means the feed is clearly broken.
        if (spreadBps > MAX_SPREAD_BPS) {
            return (0, type(uint128).max);
        }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L804-813)
```text
  function _getBidAndAskPriceX64() internal returns (uint128 bidPriceX64, uint128 askPriceX64) {
    address activePriceProvider = _resolvedPriceProvider();
    try IPriceProvider(activePriceProvider).getBidAndAskPrice() returns (uint128 bid, uint128 ask) {
      if (bid >= ask) revert BidGreaterThanAsk();
      if (bid == 0) revert BidIsZero();
      return (bid, ask);
    } catch (bytes memory reason) {
      revert PriceProviderFailed(reason);
    }
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L487-490)
```text
    uint256 executeAfter = block.timestamp + timelock;
    pendingPriceProvider[pool] = newPriceProvider;
    pendingPriceProviderExecuteAfter[pool] = executeAfter;
    emit PoolPriceProviderChangeProposed(pool, current, newPriceProvider, executeAfter);
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L497-499)
```text
    uint256 execAfter = pendingPriceProviderExecuteAfter[pool];
    // forge-lint: disable-next-line(block-timestamp) -- timelock enforcement legitimately relies on `block.timestamp`.
    if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(execAfter, block.timestamp);
```
