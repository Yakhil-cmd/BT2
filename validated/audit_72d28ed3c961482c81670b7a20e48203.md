Now I have enough context. Let me check the swap math to understand how a stale oracle impacts LP funds, and verify the `priceProviderTimelock` overflow path.

### Title
Unbounded `priceProviderTimelock` permanently blocks oracle rotation, trapping pool with a stale or compromised price provider — (`File: metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`createPool` accepts any `priceProviderTimelock` value without an upper-bound check. A value that is not exactly `type(uint256).max` (the immutable sentinel) but is astronomically large permanently prevents oracle rotation on a pool that is nominally in mutable mode, with no on-chain recovery path.

### Finding Description

`createPool` distinguishes immutable from mutable oracle mode with a single sentinel comparison: [1](#0-0) 

Any value other than `type(uint256).max` is stored verbatim in `priceProviderTimelock[pool]` and treated as a finite delay in seconds: [2](#0-1) 

`_validatePoolParameters` performs no upper-bound check on this field: [3](#0-2) 

When `proposePoolPriceProvider` is later called, it computes: [4](#0-3) 

Two failure modes arise depending on the magnitude of `timelock`:

1. **Overflow revert** — if `timelock > type(uint256).max - block.timestamp` (e.g. `type(uint256).max - 1`), Solidity 0.8 checked arithmetic reverts the `+` operation, so `proposePoolPriceProvider` always reverts and no rotation can ever be scheduled.
2. **Unreachable deadline** — if `timelock` is large but non-overflowing (e.g. `10**60` seconds ≈ 3 × 10^52 years), `proposePoolPriceProvider` succeeds but `executePoolPriceProviderUpdate` always reverts because `block.timestamp < execAfter` is permanently true: [5](#0-4) 

In both cases the pool is permanently locked to its initial price provider with no recovery path, despite being in nominally mutable mode.

### Impact Explanation

If the bound price provider later becomes stale or returns wrong prices (e.g. feed deprecation, oracle compromise, or a `CompressedOracleV1` codebook update that shifts the price), the pool admin cannot rotate to a correct provider. Swaps continue to execute against the bad oracle, causing LP principal loss through mispriced trades. This matches the allowed impact gate: **bad-price execution — stale or wrong bid/ask quote reaches a pool swap** and **broken core pool functionality causing loss of funds**.

### Likelihood Explanation

Likelihood is low but non-zero. A pool creator may confuse units (e.g. intending to set a 1-year timelock in days but supplying raw seconds), or may set `type(uint256).max - 1` believing it means "very long but not immutable." The M-06 precedent explicitly recognises this class of accidental misconfiguration as a valid medium-severity finding. No malicious intent is required; the absence of a reasonable upper bound is the root cause.

### Recommendation

Add an upper-bound check on `priceProviderTimelock` inside `_validatePoolParameters` (or directly in `createPool`) for all values that are not the immutable sentinel:

```solidity
uint256 MAX_PRICE_PROVIDER_TIMELOCK = 365 days; // or another protocol-chosen ceiling

if (
    params.priceProviderTimelock != type(uint256).max &&
    params.priceProviderTimelock > MAX_PRICE_PROVIDER_TIMELOCK
) {
    revert PriceProviderTimelockTooLong();
}
```

This mirrors the pattern already applied to fee caps (`HARD_MAX_SPREAD_FEE_E6`, `HARD_MAX_NOTIONAL_FEE_E8`) and drift bounds (`maxDriftE8 < 50_000_000`) elsewhere in the factory. [6](#0-5) 

### Proof of Concept

```solidity
// Pool created with a near-max timelock (not the immutable sentinel)
params.priceProviderTimelock = type(uint256).max - 1;
address pool = factory.createPool(params);

// Pool is in mutable mode (IMMUTABLE_PRICE_PROVIDER == address(0))
assert(IMetricOmmPool(pool).getImmutables().immutablePriceProvider == address(0));

// Oracle becomes compromised; admin tries to rotate
vm.prank(admin);
// Case 1: reverts with arithmetic overflow (Solidity 0.8 checked math)
// block.timestamp (~1.7e9) + (type(uint256).max - 1) overflows uint256
factory.proposePoolPriceProvider(pool, address(newOracle)); // REVERTS

// Pool is permanently stuck with the compromised oracle.
// All subsequent swaps execute against wrong bid/ask prices.
```

For the non-overflowing variant (`timelock = 1e60`), `proposePoolPriceProvider` succeeds but `executePoolPriceProviderUpdate` always reverts with `PriceProviderTimelockNotElapsed`, achieving the same permanent lock. [7](#0-6) [8](#0-7)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L164-164)
```text
    bool immutablePriceProvider = params.priceProviderTimelock == type(uint256).max;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L213-213)
```text
    priceProviderTimelock[pool] = params.priceProviderTimelock;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L284-295)
```text
  function setFeeCaps(
    uint24 newMaxProtocolSpreadFeeE6,
    uint24 newMaxAdminSpreadFeeE6,
    uint24 newMaxProtocolNotionalFeeE8,
    uint24 newMaxAdminNotionalFeeE8
  ) external override onlyOwner {
    if (
      newMaxProtocolSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6 || newMaxAdminSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6
        || newMaxProtocolNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8 || newMaxAdminNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8
    ) {
      revert FeeCapsExceedHardLimit();
    }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L474-491)
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
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L494-507)
```text
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
