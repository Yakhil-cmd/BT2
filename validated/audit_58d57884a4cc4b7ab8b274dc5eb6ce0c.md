### Title
Pool Admin Can Instantly Set Uncapped Bin Additional Fees Without Timelock, Enabling Front-Running of Swaps — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolBinAdditionalFees` in `MetricOmmPoolFactory` allows the pool admin to change per-bin additional fees (`addFeeBuyE6`, `addFeeSellE6`) to any value up to `uint16.max` (65 535 = 6.5535 % in E6 units) **instantly and without any cap check or timelock**. This is structurally inconsistent with the rest of the admin surface: `setPoolAdminFees` enforces `maxAdminSpreadFeeE6` / `maxAdminNotionalFeeE8` caps, and `proposePoolPriceProvider` enforces a per-pool configurable timelock. The absence of both guards on the bin-fee path breaks the protocol's stated invariant that the pool admin is "semi-trusted only inside caps and timelocks."

---

### Finding Description

`MetricOmmPoolFactory.setPoolBinAdditionalFees` passes the caller-supplied `addFeeBuyE6` / `addFeeSellE6` values directly to the pool with no validation beyond the bin-index range check: [1](#0-0) 

The pool's `setBinAdditionalFees` similarly performs no cap check on the fee values: [2](#0-1) 

These per-bin fees are added directly to the base spread fee during every swap in the affected bin: [3](#0-2) 

By contrast, `setPoolAdminFees` enforces explicit caps before writing: [4](#0-3) 

And `proposePoolPriceProvider` enforces a per-pool timelock before any provider change takes effect: [5](#0-4) 

The bin-fee path has neither protection.

---

### Impact Explanation

A pool admin who also holds LP positions (or who acts in concert with an LP) can execute the following atomic sequence in a single block:

1. Observe a large pending swap targeting the current bin in the mempool.
2. Call `setPoolBinAdditionalFees(pool, curBinIdx, 65535, 65535)` — raising the per-bin buy/sell fee to 6.5535 % with no cap or delay.
3. The victim's swap executes against the inflated fee; the extra fee accrues to LP shares (which the admin controls).
4. Call `setPoolBinAdditionalFees(pool, curBinIdx, 0, 0)` to restore normal fees.

The trader receives materially fewer output tokens than the price quoted by `getSellAndBuyPrices()` in the same block, constituting bad-price execution and a direct loss of user value. The loss magnitude is bounded only by `uint16.max` (6.5535 %) per bin, which is large relative to any reasonable spread fee.

---

### Likelihood Explanation

The pool admin is a semi-trusted role that is explicitly in scope per the audit pivot ("pool admin is semi-trusted only inside caps and timelocks"). The attack requires no external oracle manipulation, no flash loan, and no special token behavior — only the admin's existing on-chain authority and standard MEV infrastructure (e.g., a private mempool relay). Any pool whose admin is compromised, economically incentivised, or simply malicious can execute this immediately.

---

### Recommendation

Apply the same two-layer protection to `setPoolBinAdditionalFees` that already exists on the other admin-fee path:

1. **Cap check** — add a `maxAdminBinFeeE6` constant (or reuse `maxAdminSpreadFeeE6`) and revert if either `addFeeBuyE6` or `addFeeSellE6` exceeds it, mirroring the guard in `setPoolAdminFees`.
2. **Timelock** — either reuse the existing `priceProviderTimelock[pool]` mechanism (propose + execute after delay) or introduce a dedicated `binFeeTimelock` so that bin-fee changes cannot be applied in the same block they are proposed.

---

### Proof of Concept

```solidity
// Pool admin front-runs a victim swap in the same block.
// Step 1: raise bin fee to maximum (no cap, no timelock)
factory.setPoolBinAdditionalFees(pool, curBinIdx, 65535, 65535);

// Step 2: victim's swap executes — pays 6.5535% extra fee on top of spread
// (fee accrues to LP shares held by admin)
pool.swap(victim, zeroForOne, amount, priceLimit, callbackData, "");

// Step 3: restore normal fees
factory.setPoolBinAdditionalFees(pool, curBinIdx, 0, 0);
```

The victim's effective execution price is worse than the price returned by `getSellAndBuyPrices()` in the same block, with no on-chain mechanism to detect or prevent the manipulation.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-435)
```text
  function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();

    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );

    c.adminSpreadFeeE6 = newAdminSpreadFeeE6;
    c.adminNotionalFeeE8 = newAdminNotionalFeeE8;
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
    emit PoolAdminSpreadFeeUpdated(pool, newAdminSpreadFeeE6);
    emit PoolAdminNotionalFeeUpdated(pool, newAdminNotionalFeeE8);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L450-457)
```text
  function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
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

**File:** metric-core/contracts/MetricOmmPool.sol (L464-474)
```text
  function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external
    onlyFactory
    nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
  {
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L906-915)
```text
          (curPosInBinCache, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) = SwapMath.buyToken0InBinSpecifiedOut(
            binState,
            curPosInBinCache,
            state,
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
            lowerPriceX64,
            upperPriceX64,
            params.priceLimitX64,
            spreadFeeE6
          );
```
