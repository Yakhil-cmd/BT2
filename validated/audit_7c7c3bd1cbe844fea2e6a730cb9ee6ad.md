### Title
Zero `priceProviderTimelock` Bypasses Oracle Rotation Delay, Enabling Same-Block Oracle Swap by Pool Admin — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`PoolParameters.priceProviderTimelock` is a `uint256` field whose Solidity default is `0`. The factory's `_validatePoolParameters` never checks that this value is non-zero for mutable-oracle pools. When `priceProviderTimelock = 0`, the pool admin can propose and execute an oracle replacement in the same block with no delay, bypassing the timelock protection that is the only constraint on the semi-trusted admin role for oracle changes.

---

### Finding Description

`PoolParameters` is a calldata struct with a `uint256 priceProviderTimelock` field. [1](#0-0) 

In `createPool`, the factory stores this value directly into `priceProviderTimelock[pool]` without any lower-bound check: [2](#0-1) [3](#0-2) 

`_validatePoolParameters` validates tokens, admin, price provider, fees, and initial amounts — but never touches `priceProviderTimelock`: [4](#0-3) 

When `priceProviderTimelock[pool] == 0`, `proposePoolPriceProvider` computes:

```
executeAfter = block.timestamp + 0  →  executeAfter == block.timestamp
``` [5](#0-4) 

`executePoolPriceProviderUpdate` then checks:

```solidity
if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(...)
``` [6](#0-5) 

Because `block.timestamp < block.timestamp` is always `false`, the guard never fires. The pool admin can call `proposePoolPriceProvider` in transaction N and `executePoolPriceProviderUpdate` in transaction N+1 of the **same block**, replacing the oracle with zero observable delay.

The analog to the external bug is exact: just as `rollable = true` is the Solidity default for a `bool` field in the Cooler `Loan` struct (giving borrowers an immediate extension right the lender must separately revoke), `priceProviderTimelock = 0` is the Solidity default for a `uint256` field in `PoolParameters` (giving the pool admin an immediate oracle-swap right that LPs cannot prevent).

---

### Impact Explanation

After the oracle is swapped to a manipulated feed, the pool's `_getBidAndAskPriceX64` reads the new provider on the very next swap: [7](#0-6) 

A malicious oracle can return an arbitrarily skewed bid/ask, allowing the admin (or a colluding swapper) to drain LP token balances through bad-price swaps. This is a direct loss of LP principal — a Critical/High impact under the Allowed Impact Gate ("bad-price execution: stale, inverted, unbounded, or unclamped bid/ask quote reaches a pool swap" and "admin-boundary break: pool admin … bypasses timelocks").

---

### Likelihood Explanation

`createPool` is permissionless. Any integrator who constructs a `PoolParameters` struct without explicitly setting `priceProviderTimelock` will produce a zero-timelock mutable-oracle pool. The documentation describes `type(uint256).max` as the immutable sentinel and any other value as a delay in seconds, but does not warn that `0` is the struct default and that it collapses the two-step rotation into a single-block operation. Pools deployed via scripts or front-ends that omit this field are silently vulnerable.

---

### Recommendation

Add a lower-bound check in `_validatePoolParameters` (or inline in `createPool`) for the mutable-oracle case:

```solidity
if (params.priceProviderTimelock != type(uint256).max) {
    if (params.priceProviderTimelock == 0) revert InvalidPriceProviderTimelock();
}
```

Alternatively, enforce a protocol-wide minimum timelock constant (e.g., `MIN_PRICE_PROVIDER_TIMELOCK = 1 hours`) and revert if the caller supplies a value below it for mutable-oracle pools.

---

### Proof of Concept

```
1. Alice (pool creator / admin) calls createPool({
       priceProviderTimelock: 0,   // Solidity default — no explicit assignment
       ...
   })
   → priceProviderTimelock[pool] = 0

2. LPs deposit liquidity, trusting the registered oracle.

3. Alice calls proposePoolPriceProvider(pool, maliciousOracle)
   → executeAfter = block.timestamp + 0 = block.timestamp
   → pendingPriceProvider[pool] = maliciousOracle

4. Alice calls executePoolPriceProviderUpdate(pool) in the SAME BLOCK
   → block.timestamp < block.timestamp  →  false  →  no revert
   → pool's active oracle is now maliciousOracle

5. Alice (or accomplice) calls swap() on the pool.
   → _getBidAndAskPriceX64() reads maliciousOracle.getBidAndAskPrice()
   → maliciousOracle returns bid/ask that prices token0 at near-zero
   → swapper drains token0 from LP bins at a fraction of fair value

6. LPs suffer direct principal loss; no on-chain mechanism allows them
   to react between steps 3 and 4 because both occur in the same block.
```

### Citations

**File:** metric-core/contracts/types/FactoryOperation.sol (L17-18)
```text
  /// @notice Delay for mutable provider rotation; `type(uint256).max` means immutable provider.
  uint256 priceProviderTimelock;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L164-164)
```text
    bool immutablePriceProvider = params.priceProviderTimelock == type(uint256).max;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L213-213)
```text
    priceProviderTimelock[pool] = params.priceProviderTimelock;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L487-490)
```text
    uint256 executeAfter = block.timestamp + timelock;
    pendingPriceProvider[pool] = newPriceProvider;
    pendingPriceProviderExecuteAfter[pool] = executeAfter;
    emit PoolPriceProviderChangeProposed(pool, current, newPriceProvider, executeAfter);
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L498-499)
```text
    // forge-lint: disable-next-line(block-timestamp) -- timelock enforcement legitimately relies on `block.timestamp`.
    if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(execAfter, block.timestamp);
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L548-563)
```text
  function _validatePoolParameters(PoolParameters calldata params) internal view {
    if (params.token0 == address(0) || params.token1 == address(0) || params.token0 == params.token1) {
      revert InvalidTokenConfig();
    }
    if (params.admin == address(0)) revert InvalidAdmin();
    _validatePriceProvider(params.token0, params.token1, params.priceProvider);
    if (params.adminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    if (spreadProtocolFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    if (protocolNotionalFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();
    if (params.adminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (params.adminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
    if (params.initialAmount0PerShareE18 == 0 || params.initialAmount1PerShareE18 == 0) {
      revert InvalidInitialAmount();
    }
    if (params.minimalMintableLiquidity == 0) revert InvalidMinimalMintableLiquidity();
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L804-810)
```text
  function _getBidAndAskPriceX64() internal returns (uint128 bidPriceX64, uint128 askPriceX64) {
    address activePriceProvider = _resolvedPriceProvider();
    try IPriceProvider(activePriceProvider).getBidAndAskPrice() returns (uint128 bid, uint128 ask) {
      if (bid >= ask) revert BidGreaterThanAsk();
      if (bid == 0) revert BidIsZero();
      return (bid, ask);
    } catch (bytes memory reason) {
```
