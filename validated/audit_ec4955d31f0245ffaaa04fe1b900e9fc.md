### Title
Missing Sequencer Uptime Check in L2 Price Providers Allows Stale-Price Swaps After Sequencer Recovery — (`smart-contracts-poc/contracts/PriceProviderL2.sol`, `smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol`)

---

### Summary

`PriceProviderL2` and `ProtectedPriceProviderL2` are explicitly designed for L2 deployment and handle clock skew via `FUTURE_TOLERANCE`, but neither contract checks the Chainlink Sequencer Uptime Feed. After an L2 sequencer outage, oracle data published before the downtime can still pass the `_isStale` check if the outage duration is shorter than `MAX_TIME_DELTA`. Swaps execute immediately at the pre-downtime price, exposing LPs to directional losses equal to the price movement that occurred during the outage.

---

### Finding Description

Both L2 price providers implement a staleness check in `_isStale`:

```solidity
function _isStale(
    uint256 refTime,
    uint256 nowTs,
    uint256 maxDelta,
    uint256 futureTol
) internal pure returns (bool) {
    if (refTime == 0) return true;
    if (refTime > nowTs) {
        return (refTime - nowTs) > futureTol;
    }
    return (nowTs - refTime) > maxDelta;
}
``` [1](#0-0) 

This check compares the oracle's `refTime` against `block.timestamp` with a configurable `MAX_TIME_DELTA` (allowed up to 7 days at construction): [2](#0-1) 

The identical pattern exists in `ProtectedPriceProviderL2`: [3](#0-2) 

Neither contract queries a Chainlink Sequencer Uptime Feed, nor enforces a minimum grace period after sequencer recovery. The entire price validation path in `_getBidAndAskPrice` / `_computeBidAsk` proceeds directly to swap execution once the age check passes: [4](#0-3) [5](#0-4) 

---

### Impact Explanation

When the L2 sequencer resumes after downtime, `block.timestamp` continues from where it left off. Oracle data published just before the outage has a `refTime` that is `(outage_duration)` seconds old. If `outage_duration < MAX_TIME_DELTA`, the staleness check passes and the pre-downtime price is used for swap settlement.

The pool is oracle-anchored: the bid/ask returned by `getBidAndAskPrice()` directly determines the price at which every bin executes. A stale bid/ask that does not reflect real-world price movement during the outage means:

- Traders can buy at a price lower than the true market price (if the asset appreciated during downtime), draining LP token0 reserves at a discount.
- Traders can sell at a price higher than the true market price (if the asset depreciated), draining LP token1 reserves at a premium.

LPs bear the full directional loss. This is a direct loss of LP principal, matching the "bad-price execution" and "direct loss of LP assets" impact categories.

---

### Likelihood Explanation

L2 sequencer outages are documented, recurring events on Arbitrum and Optimism. `MAX_TIME_DELTA` is a deployment-time immutable that can be set up to 7 days; even a conservative 1-hour setting leaves a 59-minute window after a 1-minute outage where stale prices are accepted. The attack requires no special privilege — any EOA can submit a swap transaction the moment the sequencer resumes. On Arbitrum, the delayed inbox feature additionally allows pre-staging forced transactions during the outage for guaranteed inclusion at sequencer restart, exactly as described in the external report.

---

### Recommendation

1. Add an immutable `sequencerUptimeFeed` address (Chainlink's L2 Sequencer Uptime Feed) to both `PriceProviderL2` and `ProtectedPriceProviderL2`.
2. In `_getBidAndAskPrice` / `_computeBidAsk`, before the staleness check, query the feed:
   ```solidity
   (, int256 answer, uint256 startedAt,,) = sequencerUptimeFeed.latestRoundData();
   if (answer != 0) return (0, type(uint128).max); // sequencer is down
   if (block.timestamp - startedAt < GRACE_PERIOD) return (0, type(uint128).max); // too soon after recovery
   ```
3. Set `GRACE_PERIOD` to at least `MAX_TIME_DELTA` so that no oracle data published before the outage can pass the staleness check during the grace window.
4. If `sequencerUptimeFeed` is `address(0)` (L1 deployment), skip the check — this preserves backward compatibility with `PriceProvider` / `ProtectedPriceProvider`.

---

### Proof of Concept

1. Deploy `PriceProviderL2` with `MAX_TIME_DELTA = 3600` (1 hour) on Arbitrum.
2. Oracle publishes price $P_0$ at `t=0`; `refTime = t`.
3. Sequencer goes offline at `t=60s`. Real market price moves from $P_0$ to $P_1$ ($P_1 > P_0$, +5%).
4. Sequencer resumes at `t=120s`. `block.timestamp = 120`.
5. Attacker calls `pool.swap(...)`. `_isStale(60, 120, 3600, ...)` → `(120-60)=60 < 3600` → **not stale**.
6. Pool quotes bid/ask derived from $P_0$. Attacker buys token0 at $P_0$ and immediately sells at true market price $P_1$, extracting 5% of the swapped notional from LP reserves.
7. LPs suffer a direct principal loss proportional to the price gap and swap volume. [6](#0-5) [7](#0-6)

### Citations

**File:** smart-contracts-poc/contracts/PriceProviderL2.sol (L92-95)
```text
        if (_maxTimeDelta == 0 || _maxTimeDelta > 7 days) revert MaxTimeDeltaOutOfBounds();
        if (_futureTolerance > 1 hours) revert FutureToleranceOutOfBounds();
        MAX_TIME_DELTA   = _maxTimeDelta;
        FUTURE_TOLERANCE = _futureTolerance;
```

**File:** smart-contracts-poc/contracts/PriceProviderL2.sol (L123-128)
```text
    function getBidAndAskPrice()
        external override returns (uint128 bid, uint128 ask)
    {
        (bid, ask) = _getBidAndAskPrice();
        if (bid == 0 || ask == type(uint128).max) revert FeedStalled();
    }
```

**File:** smart-contracts-poc/contracts/PriceProviderL2.sol (L135-150)
```text
    function _isStale(
        uint256 refTime,
        uint256 nowTs,
        uint256 maxDelta,
        uint256 futureTol
    ) internal pure returns (bool) {
        if (refTime == 0) return true;

        if (refTime > nowTs) {
            // refTime in the future: tolerate only within futureTol
            return (refTime - nowTs) > futureTol;
        }

        // refTime in the past or equal: check age
        return (nowTs - refTime) > maxDelta;
    }
```

**File:** smart-contracts-poc/contracts/PriceProviderL2.sol (L208-217)
```text
    function _getBidAndAskPrice() internal returns (uint128, uint128) {
        // 1. Read via the unified price(feedId, pool) path, forwarding the pool (msg.sender).
        //    refTime is already in seconds.
        (uint256 mid, uint256 spread, , uint256 refTime) =
            IPricedOracle(address(offchainOracle)).price(offchainFeedId, msg.sender);

        // 2. Staleness check
        if (_isStale(refTime, block.timestamp, MAX_TIME_DELTA, FUTURE_TOLERANCE)) {
            return (0, type(uint128).max);
        }
```

**File:** smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol (L130-133)
```text
    function getBidAndAskPrice() external override returns (uint128 bid, uint128 ask) {
        (bid, ask) = _getBidAndAskPrice();
        if (bid == 0 || ask == type(uint128).max) revert FeedStalled();
    }
```

**File:** smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol (L138-153)
```text
    function _isStale(
        uint256 refTime,
        uint256 nowTs,
        uint256 maxDelta,
        uint256 futureTol
    ) internal pure returns (bool) {
        if (refTime == 0) return true;

        if (refTime > nowTs) {
            // refTime in the future: tolerate only within futureTol
            return (refTime - nowTs) > futureTol;
        }

        // refTime in the past or equal: check age
        return (nowTs - refTime) > maxDelta;
    }
```

**File:** smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol (L196-209)
```text
    function _getBidAndAskPrice() internal returns (uint128, uint128) {
        (uint256 mid, uint256 spread, , uint256 refTime) =
            IPricedOracle(address(offchainOracle)).price(offchainFeedId, msg.sender);
        return _computeBidAsk(mid, spread, refTime);
    }

    /// @dev Downstream pricing: staleness, price guard, confidence spread, marginStep.
    function _computeBidAsk(uint256 price, uint256 spread, uint256 refTime)
        internal view returns (uint128, uint128)
    {
        // 1. Staleness check
        if (_isStale(refTime, block.timestamp, MAX_TIME_DELTA, FUTURE_TOLERANCE)) {
            return (0, type(uint128).max);
        }
```
