### Title
`AnchoredPriceProvider` Uses L1-Only Staleness Check With No Sequencer Uptime Guard on L2 Deployments, Enabling Stale-Price Execution Against LPs — (`smart-contracts-poc/contracts/AnchoredPriceProvider.sol`)

---

### Summary

`AnchoredPriceProvider` — described as "the one standard provider for public pools" and deployed on Base (L2) — contains only an L1 staleness check and no sequencer uptime verification. After an L2 sequencer outage, if the downtime is shorter than `MAX_REF_STALENESS`, the last pre-downtime oracle price passes the staleness check immediately upon sequencer recovery, before any fresh oracle update can be pushed. A swapper can execute against this stale bid/ask, extracting value from LPs.

---

### Finding Description

`AnchoredPriceProvider._isStale` is explicitly labeled "L1" in its NatDoc and implements the L1 rule: any `refTime > block.timestamp` is unconditionally stale, and any `refTime` older than `MAX_REF_STALENESS` is stale.

```solidity
// AnchoredPriceProvider.sol L221-230
/// @dev Pure staleness check (L1). Any future refTime is stale.
function _isStale(
    uint256 refTime,
    uint256 nowTs,
    uint256 maxDelta
) internal pure returns (bool) {
    if (refTime == 0) return true;
    if (refTime > nowTs) return true;
    return (nowTs - refTime) > maxDelta;
}
``` [1](#0-0) 

This check is called in `_readLeg`, which is the sole gate before a price is used to compute bid/ask:

```solidity
// AnchoredPriceProvider.sol L282-283
if (_isStale(refTime, block.timestamp, MAX_REF_STALENESS)) return (mid, spreadBps, refTime, false);
``` [2](#0-1) 

There is **no sequencer uptime feed check** anywhere in `AnchoredPriceProvider` or `AnchoredProviderFactory`. The grep across all contract sources confirms `sequencerUptimeFeed` appears only in ABI artifacts (`registry.json`), not in any live Solidity source. [3](#0-2) 

The codebase does have L2-aware variants for the simpler providers (`PriceProviderL2`, `ProtectedPriceProviderL2`), both of which add a `FUTURE_TOLERANCE` parameter and a 4-argument `_isStale`. There is **no `AnchoredPriceProviderL2`**. [4](#0-3) 

`AnchoredProviderFactory` enforces `stalenessMax <= 7 days` via the envelope system, meaning `MAX_REF_STALENESS` can be configured anywhere from `stalenessMin` to 7 days. A value of even 1 hour means any sequencer outage shorter than 1 hour leaves the pre-downtime price accepted immediately on recovery. [5](#0-4) 

---

### Impact Explanation

After sequencer recovery, the oracle's stored `refTime` reflects the last pre-downtime push. If `block.timestamp − refTime < MAX_REF_STALENESS`, `_isStale` returns `false` and the stale mid-price is used to compute `refBid`/`refAsk`. The pool executes swaps at these stale quotes. If the real market price moved during downtime (e.g., a 5% drop), a swapper can buy the base token at the pre-crash ask, receiving more value than the current market price, with the loss borne by LPs whose liquidity is consumed at the wrong price.

This is a direct bad-price execution impact: a stale bid/ask quote reaches a pool swap, satisfying the allowed impact gate.

---

### Likelihood Explanation

Base (an explicit deployment target) has experienced sequencer outages. The oracle system is push-based (Pyth Lazer / Chainlink Data Streams): during downtime no new data lands on-chain. On recovery, the window between sequencer restart and the first fresh oracle push is the attack window. An attacker monitoring the sequencer status can submit a swap transaction as the first transaction after recovery, before the oracle keeper's update. The `MAX_REF_STALENESS` envelope allows up to 7 days, so even a generous staleness setting does not close this window — it only determines how long the window lasts.

---

### Recommendation

1. Introduce an `AnchoredPriceProviderL2` variant (mirroring `PriceProviderL2`) that:
   - Accepts a `sequencerUptimeFeed` (Chainlink L2 Sequencer Uptime Feed) at construction.
   - In `_readLeg`, checks that the sequencer is `UP` and that it has been up for at least `MAX_REF_STALENESS` seconds (or a configurable grace period) before accepting any oracle price.
   - Uses the 4-argument `_isStale` with `FUTURE_TOLERANCE` to tolerate sequencer clock skew.

2. `AnchoredProviderFactory` should enforce, for L2 deployments, that `stalenessMax` is bounded tightly (e.g., ≤ 60 seconds) to minimize the stale-price window even without a sequencer uptime feed.

---

### Proof of Concept

1. Deploy `AnchoredPriceProvider` on Base with `MAX_REF_STALENESS = 3600` (1 hour).
2. Oracle keeper pushes a price at `T=0` (`refTime = T`). Pool quotes correctly.
3. Base sequencer goes offline at `T=60`. No new oracle data can be pushed.
4. Sequencer recovers at `T=1800` (30 minutes of downtime). Real market price has dropped 8%.
5. Attacker submits a swap immediately. `block.timestamp = 1800`, `refTime = 60`, `1800 − 60 = 1740 < 3600 = MAX_REF_STALENESS` → `_isStale` returns `false`.
6. `_readLeg` returns `ok = true` with the pre-crash mid price.
7. `_computeBidAsk` produces `refBid`/`refAsk` based on the stale (8% too high) mid.
8. Attacker buys base token at the stale ask, receiving ~8% more value than the current market price. LPs absorb the loss.
9. Oracle keeper's fresh update arrives at `T=1801` — one block too late.

### Citations

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L221-230)
```text
    /// @dev Pure staleness check (L1). Any future refTime is stale.
    function _isStale(
        uint256 refTime,
        uint256 nowTs,
        uint256 maxDelta
    ) internal pure returns (bool) {
        if (refTime == 0) return true;
        if (refTime > nowTs) return true;
        return (nowTs - refTime) > maxDelta;
    }
```

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L258-295)
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

    /// @dev Reads one feed and runs its per-leg guards. ok=false (→ caller halts, fail closed) on:
    ///      stale reference, mid == 0, spreadBps == the off-hours/stall marker (spreadBps >= ORACLE_BPS), or a
    ///      priceGuard violation. Each leg is read through the attributed path independently.
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

**File:** smart-contracts-poc/contracts/AnchoredProviderFactory.sol (L101-110)
```text
        if (
            classId == bytes32(0)
            || envelope.minMarginMin > envelope.minMarginMax
            || envelope.stalenessMax > MAX_STALENESS
            || envelope.stalenessMin > envelope.stalenessMax
            || envelope.maxSpreadMin == 0
            || envelope.maxSpreadMax >= ORACLE_BPS
            || envelope.maxSpreadMin > envelope.maxSpreadMax
            || uint256(envelope.maxSpreadMax) * ONE_BPS_E18 + envelope.minMarginMax >= BPS_BASE_U
        ) revert BadEnvelope();
```
