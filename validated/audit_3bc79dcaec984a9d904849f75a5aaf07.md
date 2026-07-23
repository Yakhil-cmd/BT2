### Title
Zero `priceProviderTimelock` Allows Pool Admin to Atomically Sandwich a Price-Provider Swap Against LPs — (`File: metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory._validatePoolParameters` imposes no lower bound on `priceProviderTimelock`. When a pool is created with `priceProviderTimelock = 0`, the admin can call `proposePoolPriceProvider` and `executePoolPriceProviderUpdate` in the same transaction, atomically replacing the live oracle. Sandwiching that replacement between two swaps is a risk-free arbitrage that drains LP reserves — the exact class of attack described in the external report.

---

### Finding Description

`_validatePoolParameters` validates fees, tokens, admin address, and initial amounts, but never checks that `priceProviderTimelock` is above a minimum value: [1](#0-0) 

`priceProviderTimelock == type(uint256).max` is the immutable sentinel; any other value — including `0` — is accepted as "mutable with delayed execution." The value is stored verbatim: [2](#0-1) 

`proposePoolPriceProvider` computes the execution deadline as:

```solidity
uint256 executeAfter = block.timestamp + timelock;   // = block.timestamp when timelock == 0
``` [3](#0-2) 

`executePoolPriceProviderUpdate` enforces:

```solidity
if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(...);
``` [4](#0-3) 

When `timelock == 0`, `execAfter == block.timestamp`, so `block.timestamp < block.timestamp` is always `false`. The guard never fires. Both functions carry `nonReentrant` from `ReentrancyGuardTransient`, but that modifier only blocks *nested* re-entry; sequential calls within the same transaction are unaffected. An admin-controlled contract can therefore call `propose` → `execute` back-to-back in a single transaction, atomically replacing the price provider with no delay.

The pool reads the oracle exactly once per swap at the top of `swap()`:

```solidity
(uint128 bidPriceX64, uint128 askPriceX64) = _getBidAndAskPriceX64();
``` [5](#0-4) 

`_getBidAndAskPriceX64` calls the *currently active* provider: [6](#0-5) 

Because the provider is resolved fresh on every swap call, swapping before and after the provider replacement yields two different oracle prices in the same block.

---

### Impact Explanation

An admin who created the pool with `priceProviderTimelock = 0` can execute the following atomically:

1. **Swap A → B at providerOld price** (e.g., 1.00 token1 per token0).
2. **`proposePoolPriceProvider(pool, providerNew)`** — sets `executeAfter = block.timestamp`.
3. **`executePoolPriceProviderUpdate(pool)`** — guard passes; pool now uses providerNew (e.g., 1.10 token1 per token0).
4. **Swap B → A at providerNew price** — receives more token0 than was spent in step 1.

The profit comes entirely from LP reserves. The attack can be amplified with a flash loan for step 1. This is a direct, quantifiable loss of LP principal — pool insolvency if repeated or scaled.

---

### Likelihood Explanation

- Any pool deployed with `priceProviderTimelock = 0` is permanently vulnerable for its lifetime.
- The factory imposes no minimum; the value is caller-supplied and stored without validation.
- The admin is the pool creator, so the malicious configuration is set at deployment — no subsequent governance action is required.
- The attack requires only a single contract call sequence; no mempool timing or gas-price manipulation is needed (unlike the external report's two-transaction sandwich).

---

### Recommendation

Enforce a minimum timelock in `_validatePoolParameters`. For example:

```solidity
uint256 internal constant MIN_PRICE_PROVIDER_TIMELOCK = 1 hours;

// inside _validatePoolParameters:
if (
    params.priceProviderTimelock != type(uint256).max &&
    params.priceProviderTimelock < MIN_PRICE_PROVIDER_TIMELOCK
) revert PriceProviderTimelockTooShort();
```

This ensures that even a semi-trusted admin cannot atomically replace the oracle within a single transaction, preserving the LP protection the timelock was designed to provide.

---

### Proof of Concept

```solidity
contract AdminSandwich {
    MetricOmmPoolFactory factory;
    address pool;

    // providerOld: bid=1.00, ask=1.01
    // providerNew: bid=1.09, ask=1.10
    IPriceProvider providerOld;
    IPriceProvider providerNew;

    function attack() external {
        // Step 1: buy token1 cheaply at providerOld price
        pool.swap(/*zeroForOne=*/true, largeAmount, ...);

        // Step 2+3: atomically replace oracle — succeeds because timelock == 0
        factory.proposePoolPriceProvider(pool, address(providerNew));
        factory.executePoolPriceProviderUpdate(pool);
        // block.timestamp < block.timestamp == false → no revert

        // Step 4: sell token1 expensively at providerNew price
        pool.swap(/*zeroForOne=*/false, largeAmount, ...);
        // profit = (1.09 - 1.01) * largeAmount, paid by LPs
    }
}
```

The pool was created with `params.priceProviderTimelock = 0` — a value the factory accepts without error. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L164-164)
```text
    bool immutablePriceProvider = params.priceProviderTimelock == type(uint256).max;
```

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

**File:** metric-core/contracts/MetricOmmPool.sol (L217-228)
```text
  function swap(
    address recipient,
    bool zeroForOne,
    int128 amountSpecified,
    uint128 priceLimitX64,
    bytes calldata callbackData,
    bytes calldata extensionData
  ) external whenNotPaused nonReentrant(PoolActions.SWAP) returns (int128, int128) {
    require(amountSpecified != 0, InvalidAmount());

    uint256 packedSlot0Initial = Slot0Library.loadPackedSlot0();
    (uint128 bidPriceX64, uint128 askPriceX64) = _getBidAndAskPriceX64();
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
