### Title
`MetricOmmPoolFactory.createPool()` accepts arbitrary price providers without verifying they originate from an official factory — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.createPool()` validates a caller-supplied `priceProvider` only by checking that its `token0()` and `token1()` return values match the pool's token pair. It never verifies that the provider was deployed by the official `PriceProviderFactory` or `AnchoredProviderFactory`. Any actor can deploy a contract that trivially satisfies the two-field check while returning arbitrarily manipulated bid/ask prices, attach it to an officially-registered pool, and cause bad-price execution for every swap in that pool.

---

### Finding Description

`_validatePriceProvider` performs exactly two checks: [1](#0-0) 

```solidity
function _validatePriceProvider(address token0, address token1, address priceProvider) internal view {
    if (priceProvider == address(0)) revert InvalidPriceProvider();
    if (IPriceProvider(priceProvider).token0() != token0 || IPriceProvider(priceProvider).token1() != token1) {
      revert PriceProviderTokenMismatch();
    }
}
```

Both checks are trivially satisfied by any contract that stores and returns the correct token addresses. The official oracle layer exposes an `isProvider(address)` predicate that is explicitly documented as **"the machine-checkable predicate"** for public-pool eligibility: [2](#0-1) 

```
/// @notice ... public-pool eligibility is then the machine-checkable predicate
///         `recognizedFactory.isProvider(p)`.
```

`MetricOmmPoolFactory` never calls `isProvider()` on either `PriceProviderFactory` or `AnchoredProviderFactory`. The same gap is present in the provider-change path: [3](#0-2) 

`proposePoolPriceProvider` calls `_validatePriceProvider` with the same insufficient check, meaning a pool admin can also swap in a non-official provider after the timelock elapses.

The `createPool` call site that invokes this validation: [4](#0-3) 

The pool is then registered as canonical: [5](#0-4) 

```solidity
idxToPool[poolIdx] = pool;
poolToIdx[pool] = poolIdx;
```

So `factory.isPool(pool)` returns `true` for a pool backed by a malicious price provider.

The price provider is consumed at swap time without any re-validation: [6](#0-5) 

```solidity
function _getBidAndAskPriceX64() internal returns (uint128 bidPriceX64, uint128 askPriceX64) {
    address activePriceProvider = _resolvedPriceProvider();
    try IPriceProvider(activePriceProvider).getBidAndAskPrice() returns (uint128 bid, uint128 ask) {
      if (bid >= ask) revert BidGreaterThanAsk();
      if (bid == 0) revert BidIsZero();
      return (bid, ask);
    } ...
}
```

The only runtime guards are `bid < ask` and `bid > 0` — both trivially satisfied by a malicious provider.

---

### Impact Explanation

A pool created via the official factory with a malicious price provider:

- Appears canonical to any on-chain or off-chain tool calling `factory.isPool(pool)` → `true`
- Executes every swap against prices returned by the malicious provider
- A provider returning `bid = 1, ask = type(uint128).max` passes all runtime checks and causes swappers to receive near-zero output; arbitrageurs can drain LP positions at the manipulated price

This matches the allowed impact: **"Bad-price execution: stale, inverted, unbounded, or unclamped bid/ask quote reaches a pool swap."**

---

### Likelihood Explanation

`createPool` is permissionless. The only barrier is deploying a contract that implements `token0()` and `token1()` returning the correct addresses. No privileged role is required. The attack is reachable by any external actor.

---

### Recommendation

Add a reference to the official price provider factory (or a set of approved factories) in `MetricOmmPoolFactory`, and extend `_validatePriceProvider` to require `officialPriceProviderFactory.isProvider(priceProvider)`. The `AnchoredProviderFactory.isProvider()` and `PriceProviderFactory.isProvider()` functions already exist for this purpose: [7](#0-6) [8](#0-7) 

Alternatively, follow the Timeswap mitigation pattern: accept only token addresses in `createPool` and derive the price provider address deterministically from the official factory.

---

### Proof of Concept

```solidity
// Step 1: Deploy a malicious price provider that passes the token check
contract MaliciousPriceProvider {
    address public token0;
    address public token1;
    constructor(address t0, address t1) { token0 = t0; token1 = t1; }

    // Passes bid < ask and bid > 0 checks; prices are arbitrarily far from market
    function getBidAndAskPrice() external pure returns (uint128, uint128) {
        return (1, type(uint128).max);
    }
}

// Step 2: Create an officially-registered pool with the malicious provider
MaliciousPriceProvider mp = new MaliciousPriceProvider(address(tokenA), address(tokenB));
address pool = factory.createPool(PoolParameters({
    token0: address(tokenA),
    token1: address(tokenB),
    priceProvider: address(mp),
    // ... other valid params
}));

// Step 3: factory.isPool(pool) == true — pool appears canonical
assert(factory.isPool(pool));

// Step 4: Every swap executes at the manipulated price
// Swapper calling pool.swap() receives near-zero token1 output for any token0 input
// Arbitrageurs drain LP positions at the extreme price
```

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L222-225)
```text
    uint256 poolIdx = nextPoolIdx;
    nextPoolIdx++;
    idxToPool[poolIdx] = pool;
    poolToIdx[pool] = poolIdx;
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L541-546)
```text
  function _validatePriceProvider(address token0, address token1, address priceProvider) internal view {
    if (priceProvider == address(0)) revert InvalidPriceProvider();
    if (IPriceProvider(priceProvider).token0() != token0 || IPriceProvider(priceProvider).token1() != token1) {
      revert PriceProviderTokenMismatch();
    }
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

**File:** smart-contracts-poc/contracts/AnchoredProviderFactory.sol (L11-13)
```text
///         reference oracles, with clamp parameters validated against multisig-tuned pair-class
///         envelopes. createAnchoredProvider names which allow-listed oracle to anchor to; public-pool
///         eligibility is then the machine-checkable predicate `recognizedFactory.isProvider(p)`.
```

**File:** smart-contracts-poc/contracts/AnchoredProviderFactory.sol (L281-283)
```text
    function isProvider(address provider) external view returns (bool) {
        return _providers.contains(provider);
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

**File:** smart-contracts-poc/contracts/PriceProviderFactory.sol (L148-150)
```text
    function isProvider(address provider) external view returns (bool) {
        return _providers.contains(provider);
    }
```
