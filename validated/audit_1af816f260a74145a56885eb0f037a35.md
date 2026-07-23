### Title
`AnchoredPriceProvider` uses an L1-only staleness check with no L2 variant, causing `FeedStalled` reverts on Base when oracle `refTime` exceeds `block.timestamp` — (`smart-contracts-poc/contracts/AnchoredPriceProvider.sol`)

---

### Summary

`AnchoredPriceProvider` is the designated standard provider for public pools. Its `_isStale` helper is explicitly L1-only: it treats any oracle `refTime` strictly greater than `block.timestamp` as stale. On L2 networks (Base is a confirmed deployment target), the sequencer's clock can lag behind the oracle publisher's clock by a few seconds, making valid, fresh oracle data appear stale. Because there is no `AnchoredPriceProviderL2` or `AnchoredProviderFactoryL2`, every public pool on Base that uses an `AnchoredPriceProvider` will intermittently revert with `FeedStalled` during swaps.

---

### Finding Description

The protocol is deployed on **Ethereum, Base, and HyperEVM** (README line 10). `AnchoredPriceProvider` is described as "the one standard provider for public pools."

Its staleness check is:

```solidity
/// @dev Pure staleness check (L1). Any future refTime is stale.
function _isStale(
    uint256 refTime,
    uint256 nowTs,
    uint256 maxDelta
) internal pure returns (bool) {
    if (refTime == 0) return true;
    if (refTime > nowTs) return true;   // ← hard L1 assumption
    return (nowTs - refTime) > maxDelta;
}
``` [1](#0-0) 

This is called inside `_readLeg`:

```solidity
if (_isStale(refTime, block.timestamp, MAX_REF_STALENESS)) return (mid, spreadBps, refTime, false);
``` [2](#0-1) 

When `ok == false`, `_getBidAndAskPrice` returns the stall sentinel `(0, type(uint128).max)`, and `getBidAndAskPrice` reverts:

```solidity
if (bid == 0 || ask == type(uint128).max) revert FeedStalled();
``` [3](#0-2) 

The codebase already recognises this L2 clock-skew problem for every other provider variant. `PriceProviderL2` and `ProtectedPriceProviderL2` both carry a `FUTURE_TOLERANCE` immutable and an L2-aware staleness check:

```solidity
/// @dev Pure staleness check. L2-aware: tolerates oracle refTime slightly
///      ahead of block.timestamp (sequencer clock skew).
if (refTime > nowTs) {
    return (refTime - nowTs) > futureTol;
}
``` [4](#0-3) [5](#0-4) 

`AnchoredPriceProvider` has no such tolerance and no L2 sibling. `AnchoredProviderFactory` deploys only the L1 variant and is deployed across all chains via the root-level `DeployAnchorFactory.s.sol` / `deploy-anchor-factory.sh` scripts. [6](#0-5) 

---

### Impact Explanation

Every swap through a pool whose price provider is an `AnchoredPriceProvider` calls `getBidAndAskPrice()`. On Base, whenever the Pyth/Chainlink oracle's `refTime` is even one second ahead of `block.timestamp` (a routine sequencer clock-skew condition), `_isStale` returns `true`, the provider reverts with `FeedStalled`, and the swap fails. This breaks the core swap flow for all public pools on L2 that use the standard provider, matching the "broken core pool functionality" impact gate.

---

### Likelihood Explanation

Base is a confirmed deployment chain. L2 sequencer clock skew causing oracle `refTime > block.timestamp` by a few seconds is a well-documented, regularly occurring condition — it is precisely why `PriceProviderL2` and `ProtectedPriceProviderL2` were introduced with `FUTURE_TOLERANCE`. The absence of an equivalent for `AnchoredPriceProvider` means the failure mode is not hypothetical; it will occur in normal operation.

---

### Recommendation

Introduce `AnchoredPriceProviderL2` (and a matching `AnchoredProviderFactoryL2`) that accepts a `FUTURE_TOLERANCE` constructor parameter and replaces the L1 `_isStale` with the L2-aware version already used in `PriceProviderL2`:

```solidity
function _isStale(uint256 refTime, uint256 nowTs, uint256 maxDelta, uint256 futureTol)
    internal pure returns (bool)
{
    if (refTime == 0) return true;
    if (refTime > nowTs) return (refTime - nowTs) > futureTol;
    return (nowTs - refTime) > maxDelta;
}
```

Deploy `AnchoredProviderFactoryL2` on Base (and HyperEVM if it exhibits the same sequencer behaviour) and use it exclusively for L2 public-pool providers.

---

### Proof of Concept

1. Deploy `AnchoredProviderFactory` on Base (as currently done).
2. Call `createAnchoredProvider(...)` to create a provider for a WETH/USDC pool.
3. The Pyth oracle pushes a price update; the oracle's `refTime` is `block.timestamp + 2` (sequencer lag).
4. A user calls `swap(...)` on the pool.
5. The pool calls `provider.getBidAndAskPrice()`.
6. `_readLeg` calls `_isStale(refTime=T+2, nowTs=T, maxDelta=...)` → `refTime > nowTs` → returns `true` → `ok = false`.
7. `_getBidAndAskPrice` returns `(0, type(uint128).max)`.
8. `getBidAndAskPrice` reverts with `FeedStalled`.
9. The swap reverts; the pool is unusable until `block.timestamp` catches up to the oracle's `refTime`.

### Citations

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L214-217)
```text
    function getBidAndAskPrice() external override returns (uint128 bid, uint128 ask) {
        (bid, ask) = _getBidAndAskPrice();
        if (bid == 0 || ask == type(uint128).max) revert FeedStalled();
    }
```

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

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L282-283)
```text
        // Stale reference → not ok. Clamping to a stale anchor is the one false-safety case.
        if (_isStale(refTime, block.timestamp, MAX_REF_STALENESS)) return (mid, spreadBps, refTime, false);
```

**File:** smart-contracts-poc/contracts/PriceProviderL2.sol (L132-150)
```text
    /// @dev Pure staleness check. L2-aware: tolerates oracle refTime slightly
    ///      ahead of block.timestamp (sequencer clock skew).
    ///      Uses subtraction only — no addition that could theoretically overflow.
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

**File:** smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol (L135-153)
```text
    // ── Staleness ───────────────────────────────────────────────────────

    /// @dev Pure staleness check. L2-aware: tolerates oracle refTime slightly ahead of block.timestamp.
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

**File:** smart-contracts-poc/contracts/AnchoredProviderFactory.sol (L182-194)
```text
        AnchoredPriceProvider p = new AnchoredPriceProvider(
            address(this),
            oracle,
            baseFeedId,
            quoteFeedId,
            minMargin,
            maxRefStaleness,
            maxSpreadBps,
            mutableParams,
            marginStep,
            baseToken,
            quoteToken
        );
```
