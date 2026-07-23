### Title
Zero `priceProviderTimelock` Allows Pool Admin to Swap Price Provider Atomically, Enabling Same-Block Oracle Manipulation - (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.createPool` accepts `priceProviderTimelock = 0` without any minimum-value validation. When the timelock is zero, `proposePoolPriceProvider` sets `pendingPriceProviderExecuteAfter[pool] = block.timestamp + 0 = block.timestamp`, and `executePoolPriceProviderUpdate` immediately passes the guard `block.timestamp < execAfter` (false when equal). The pool admin can therefore propose and execute a price-provider swap in the same block — or even the same transaction via a wrapper contract — with no delay whatsoever, defeating the entire timelock mechanism that was introduced to fix the prior audit finding M01.

---

### Finding Description

`_validatePoolParameters` enforces caps on fees, non-zero tokens, admin, and fee destination, but contains **no lower-bound check on `priceProviderTimelock`**:

```solidity
// MetricOmmPoolFactory.sol _validatePoolParameters — no check on priceProviderTimelock
if (params.adminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (params.adminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
// priceProviderTimelock is never validated
``` [1](#0-0) 

`createPool` then stores the raw value directly:

```solidity
priceProviderTimelock[pool] = params.priceProviderTimelock;
``` [2](#0-1) 

`proposePoolPriceProvider` computes the deadline as:

```solidity
uint256 executeAfter = block.timestamp + timelock;   // = block.timestamp when timelock == 0
``` [3](#0-2) 

`executePoolPriceProviderUpdate` enforces:

```solidity
if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(...);
``` [4](#0-3) 

When `execAfter == block.timestamp`, the strict-less-than check is `false`, so execution proceeds immediately. Both functions carry `nonReentrant` but that only prevents re-entrant calls within a single call frame; sequential calls in the same transaction (via a wrapper/multicall contract) are unrestricted.

The project's own `AuditFindings.md` documents that M01 — "Admin can arbitrarily change the pool priceProvider" — was fixed by introducing this timelock. The fix is incomplete: a zero timelock restores the original vulnerability. [5](#0-4) 

---

### Impact Explanation

A pool admin controlling a pool with `priceProviderTimelock = 0` can:

1. Deploy a malicious `IPriceProvider` that returns an arbitrarily skewed bid/ask (e.g., bid ≈ 0, ask ≈ ∞).
2. In a single transaction via a wrapper contract:
   - Call `proposePoolPriceProvider(pool, maliciousProvider)` → `executeAfter = block.timestamp`.
   - Call `executePoolPriceProviderUpdate(pool)` → guard passes, `setPriceProvider` is called on the pool.
   - Call `swap(...)` → pool reads the malicious bid/ask, executes at the manipulated price, draining LP reserves.
   - Optionally restore the original provider to obscure the attack.

The pool's `swap` function reads the price provider at call time with no snapshot or caching across the block: [6](#0-5) 

LP principal is directly at risk. The surplus-based spread-fee accounting means any token balance above `binTotals.scaledToken*` is treated as fee surplus and can be swept, and the manipulated price allows the attacker to extract the bin reserves themselves.

---

### Likelihood Explanation

- `createPool` is **permissionless** — any address can deploy a pool with `priceProviderTimelock = 0`.
- The pool admin is the same address that chose the timelock at creation; no external governance vote is required.
- LPs who join after creation have no on-chain signal that the timelock is zero (the value is stored in factory storage, not in the pool's immutables or a prominent view).
- The attack requires only two sequential factory calls plus one swap, executable atomically.

Likelihood is **medium**: it requires the pool admin to act maliciously, but the admin is only semi-trusted and the protocol's own timelock mechanism is the stated guard against this class of abuse.

---

### Recommendation

Enforce a minimum timelock in `_validatePoolParameters` for mutable-provider pools:

```solidity
if (params.priceProviderTimelock != type(uint256).max) {
    if (params.priceProviderTimelock < MIN_PRICE_PROVIDER_TIMELOCK)
        revert PriceProviderTimelockTooShort();
}
```

`MIN_PRICE_PROVIDER_TIMELOCK` should be set to a value that gives LPs sufficient time to observe a pending change and exit (e.g., 24–48 hours), consistent with the recommendation in the original Bancor report. [1](#0-0) 

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

contract ZeroTimelockExploit {
    IMetricOmmPoolFactory factory;
    address pool;
    address maliciousProvider;

    constructor(address _factory, address _pool, address _maliciousProvider) {
        factory = IMetricOmmPoolFactory(_factory);
        pool = _pool;
        maliciousProvider = _maliciousProvider;
    }

    function exploit() external {
        // Step 1: propose malicious provider — execAfter = block.timestamp (timelock == 0)
        factory.proposePoolPriceProvider(pool, maliciousProvider);

        // Step 2: execute immediately — block.timestamp < block.timestamp is false, passes
        factory.executePoolPriceProviderUpdate(pool);

        // Step 3: swap at manipulated price, draining LP reserves
        IMetricOmmPool(pool).swap(
            address(this), true, type(int128).max, 0, ""
        );
    }
}
```

Pool creation that enables this:

```solidity
PoolParameters memory params = PoolParameters({
    priceProviderTimelock: 0,   // ← zero: no delay enforced
    priceProvider: legitimateProvider,
    admin: attacker,
    // ... other fields
});
factory.createPool(params);
``` [7](#0-6)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L213-213)
```text
    priceProviderTimelock[pool] = params.priceProviderTimelock;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L474-507)
```text
  function proposePoolPriceProvider(address pool, address newPriceProvider)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    PoolImmutables memory p = IMetricOmmPool(pool).getImmutables();
    uint256 timelock = priceProviderTimelock[pool];
    if (p.immutablePriceProvider != address(0)) revert PriceProviderImmutable();
    _validatePriceProvider(p.token0, p.token1, newPriceProvider);

    address mutableProvider = PoolStateLibrary._slot3(pool);
    address current = mutableProvider != address(0) ? mutableProvider : p.immutablePriceProvider;
    uint256 executeAfter = block.timestamp + timelock;
    pendingPriceProvider[pool] = newPriceProvider;
    pendingPriceProviderExecuteAfter[pool] = executeAfter;
    emit PoolPriceProviderChangeProposed(pool, current, newPriceProvider, executeAfter);
  }

  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
  function executePoolPriceProviderUpdate(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    address pending = pendingPriceProvider[pool];
    if (pending == address(0)) revert NoPriceProviderChangeProposed();
    uint256 execAfter = pendingPriceProviderExecuteAfter[pool];
    // forge-lint: disable-next-line(block-timestamp) -- timelock enforcement legitimately relies on `block.timestamp`.
    if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(execAfter, block.timestamp);
    PoolImmutables memory p = IMetricOmmPool(pool).getImmutables();
    if (p.immutablePriceProvider != address(0)) revert PriceProviderImmutable();
    _validatePriceProvider(p.token0, p.token1, pending);
    IMetricOmmPoolFactoryActions(pool).setPriceProvider(pending);
    delete pendingPriceProvider[pool];
    delete pendingPriceProviderExecuteAfter[pool];
    emit PoolPriceProviderUpdated(pool, pending);
  }
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

**File:** metric-core/docs/AuditFindings.md (L45-69)
```markdown
## M01 - Admin can arbitrarily change the pool priceProvider

### Finding summary

`setPriceProvider()` allowed admin to replace oracle at runtime, and `priceProvider` was returned by `getImmutables()`.

### Resolution

Fixed.

Changes:

- Added constructor config `priceProviderTimelock`.
- Added admin flow:
  - `proposePriceProvider(address newPriceProvider)`
  - `executePriceProviderUpdate()`
- Added events:
  - `PriceProviderChangeProposed(currentPriceProvider, newPriceProvider, executeAfter)`
  - `PriceProviderUpdated(newPriceProvider)`

Behavior now:

- `priceProviderTimelock == type(uint256).max` => immutable mode (admin updates disabled).
- `priceProviderTimelock < type(uint256).max` => mutable mode with delayed execution.
- Price provider used by swaps/reports resolves through timelock mode; active provider is read via `MetricOmmPoolStateView.priceProvider(pool)`.
```

**File:** metric-core/contracts/MetricOmmPool.sol (L333-339)
```text
    (uint256 midPriceX64, uint256 baseFeeX64) = SwapMath.midAndSpreadFeeX64FromBidAsk(bidPriceX64, askPriceX64);

    SwapMath.InternalSwapParams memory params =
      SwapMath.InternalSwapParams({midPriceX64: midPriceX64, baseFeeX64: baseFeeX64, priceLimitX64: priceLimitX64});

    (int256 amount0Delta, int256 amount1Delta, uint256 protocolFeeAmount) =
      _executeSwap(zeroForOne, amountSpecified, params);
```
