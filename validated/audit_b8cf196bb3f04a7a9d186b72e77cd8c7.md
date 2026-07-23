### Title
`PriceProviderL2` and `ProtectedPriceProviderL2` Do Not Check L2 Sequencer Uptime, Violating the Documented Oracle-Integrity Invariant — (`smart-contracts-poc/contracts/PriceProviderL2.sol`, `smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol`)

---

### Summary

Both L2 price-provider contracts rely exclusively on a data-age staleness check (`_isStale`) to guard oracle freshness. Neither contract queries a Chainlink sequencer-uptime feed or enforces a post-restart grace period. The protocol's own README documents the invariant *"Swaps revert if the oracle price is stale or if L2 sequencers are down"*, but the code only implements the first half. During the grace window after a sequencer restart — when the sequencer is live but the last pushed oracle report predates the outage — the staleness check passes and swaps execute on stale prices.

---

### Finding Description

`PriceProviderL2._getBidAndAskPrice()` and `ProtectedPriceProviderL2._computeBidAsk()` both call `_isStale(refTime, block.timestamp, MAX_TIME_DELTA, FUTURE_TOLERANCE)`:

```solidity
// PriceProviderL2.sol  lines 214-217
if (_isStale(refTime, block.timestamp, MAX_TIME_DELTA, FUTURE_TOLERANCE)) {
    return (0, type(uint128).max);
}
```

```solidity
// ProtectedPriceProviderL2.sol  lines 207-209
if (_isStale(refTime, block.timestamp, MAX_TIME_DELTA, FUTURE_TOLERANCE)) {
    return (0, type(uint128).max);
}
```

`_isStale` only measures the age of the stored `refTime` against `MAX_TIME_DELTA` (constructor-bounded to `[1, 7 days]`):

```solidity
// PriceProviderL2.sol  lines 135-150
function _isStale(uint256 refTime, uint256 nowTs, uint256 maxDelta, uint256 futureTol)
    internal pure returns (bool)
{
    if (refTime == 0) return true;
    if (refTime > nowTs) return (refTime - nowTs) > futureTol;
    return (nowTs - refTime) > maxDelta;
}
```

Neither contract:
- reads a Chainlink sequencer-uptime feed (`AggregatorV3Interface.latestRoundData()` on the uptime feed),
- checks `answer == 1` (sequencer down), or
- enforces a grace period (e.g., 3600 s) after `startedAt` when the sequencer last restarted.

The oracle layer is push-based: keepers call `updateReport()` to store data. While the sequencer is down, no new reports can be pushed. When the sequencer restarts, the last pre-outage report remains in storage with its original `refTime`. If the outage lasted less than `MAX_TIME_DELTA`, `_isStale` returns `false`, and `getBidAndAskPrice()` returns the pre-outage bid/ask as if it were live.

The registry ABI confirms the protocol is aware of this concern — a `ChainlinkVerifierL2` artifact exposes `sequencerUptimeFeed` and `GRACE_PERIOD` — but those fields are not wired into the price-provider read path.

---

### Impact Explanation

Any public swap routed through a pool whose provider is `PriceProviderL2` or `ProtectedPriceProviderL2` can execute against a stale bid/ask during the post-restart grace window. The pool's swap math treats the returned `bid`/`ask` as the authoritative oracle price; if those values are stale by minutes-to-hours (depending on `MAX_TIME_DELTA` and outage length), traders can extract value from LPs at prices that no longer reflect the market, or LPs can be forced to fill at unfavorable rates. This directly breaks the "Quote Sanity" and "Oracle Integrity" invariants documented in the README.

---

### Likelihood Explanation

Arbitrum, Base, and other L2s targeted by the protocol have experienced sequencer outages. The trigger requires only:
1. A sequencer outage shorter than `MAX_TIME_DELTA` (e.g., 30 min outage with `MAX_TIME_DELTA = 1 h`).
2. A public `swap()` call in the first blocks after restart.

No privileged role is needed; any trader can call `swap()`.

---

### Recommendation

Add a sequencer-uptime check at the top of `_getBidAndAskPrice()` / `_computeBidAsk()` in both L2 providers, following Chainlink's documented pattern:

```solidity
// store sequencerUptimeFeed as an immutable in the constructor
(, int256 answer, uint256 startedAt,,) = sequencerUptimeFeed.latestRoundData();
if (answer != 0) return (0, type(uint128).max);          // sequencer is down
if (block.timestamp - startedAt < GRACE_PERIOD) return (0, type(uint128).max); // grace window
```

`GRACE_PERIOD` should be at least 3600 seconds (matching Chainlink's recommendation). The check should be the first thing executed before the oracle read, so that a down or recently-restarted sequencer causes `getBidAndAskPrice()` to revert with `FeedStalled`, leaving withdrawals unaffected.

---

### Proof of Concept

```
Setup:
  MAX_TIME_DELTA = 1 hour
  Oracle last pushed at T=0 (refTime = 0)

Timeline:
  T=0      keeper pushes report; refTime stored = 0
  T=1800   L2 sequencer goes down (no txs possible)
  T=3600   sequencer restarts; first blocks processed
  T=3601   attacker calls pool.swap()
              → ProtectedPriceProviderL2.getBidAndAskPrice()
              → _isStale(0, 3601, 3600, futureTol)
                  nowTs - refTime = 3601 < MAX_TIME_DELTA=3600? NO → stale
              (edge case; use T=3599 outage end for clear pass)

Cleaner scenario:
  T=0      keeper pushes report; refTime = 0
  T=1200   sequencer goes down
  T=2400   sequencer restarts
  T=2401   attacker calls swap()
              → _isStale(0, 2401, 3600, futureTol)
              → 2401 < 3600 → NOT stale → returns pre-outage bid/ask
              → swap settles at 40-minute-old price
              → LP receives less than fair value if price moved during outage
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol (L38-42)
```text
    uint256 public immutable MAX_TIME_DELTA;

    /// @dev L2 sequencer timestamp can lag behind oracle publication time.
    ///      Allows refTime up to FUTURE_TOLERANCE seconds ahead of block.timestamp.
    uint256 public immutable FUTURE_TOLERANCE;
```

**File:** smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol (L202-209)
```text
    /// @dev Downstream pricing: staleness, price guard, confidence spread, marginStep.
    function _computeBidAsk(uint256 price, uint256 spread, uint256 refTime)
        internal view returns (uint128, uint128)
    {
        // 1. Staleness check
        if (_isStale(refTime, block.timestamp, MAX_TIME_DELTA, FUTURE_TOLERANCE)) {
            return (0, type(uint128).max);
        }
```
