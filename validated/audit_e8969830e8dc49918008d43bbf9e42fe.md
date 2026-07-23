### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

The factory enforces `maxAdminSpreadFeeE6` to bound the admin's spread fee, but `setPoolBinAdditionalFees` passes per-bin additional fees to the pool with **no analogous cap check**. A pool admin can set `addFeeBuyE6` / `addFeeSellE6` up to `uint16.max` (65 535 ≈ 6.55 %) on any bin, stacking that fee on top of the already-capped global spread fee and exceeding the factory owner's intended limit.

---

### Finding Description

`setPoolAdminFees` correctly validates the admin spread fee against `maxAdminSpreadFeeE6`:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees`, callable by the same pool admin, forwards values directly to the pool with **no cap check**:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees` only validates the bin index, not the fee magnitudes: [3](#0-2) 

During swap execution, the per-bin additional fee is added directly on top of the base spread fee:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) 

The same additive pattern applies in `getSellAndBuyPrices` and all four swap-direction helpers. The bin additional fee is therefore a **direct surcharge on every swap through that bin**, not a separate accounting bucket.

---

### Impact Explanation

A pool admin who has been capped at, say, 1 % (`maxAdminSpreadFeeE6 = 10 000`) can still set `addFeeBuyE6 = 65 535` on every bin, charging an extra ≈ 6.55 % per swap. Users receive fewer output tokens than the factory owner's cap was designed to guarantee. For large swaps the excess fee constitutes direct loss of user principal routed through the pool.

---

### Likelihood Explanation

The trigger is a valid, non-timelocked call by the pool admin — a semi-trusted role. No privileged escalation or malicious setup is required beyond the admin's existing authority. The factory owner's cap mechanism gives LPs and users a false assurance that admin fees are bounded, making exploitation plausible whenever a pool admin acts adversarially or is compromised.

---

### Recommendation

Add a cap check inside `setPoolBinAdditionalFees` (or inside the pool's `setBinAdditionalFees`) before forwarding to the pool:

```solidity
if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` state variable so the factory owner can set a separate, explicit ceiling for per-bin surcharges.

---

### Proof of Concept

1. Factory owner calls `setFeeCaps(…, newMaxAdminSpreadFeeE6 = 10_000, …)` — capping admin spread fee at 1 %.
2. Pool admin calls `setPoolAdminFees(pool, 10_000, 0)` — sets admin spread fee to the 1 % cap (passes validation).
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` — sets bin-0 buy/sell additional fees to 6.5535 % (**no cap check, call succeeds**).
4. User swaps token1 → token0 through bin 0. Effective admin-controlled fee = 1 % (spread) + 6.5535 % (bin additional) = **7.5535 %**, exceeding the factory owner's 1 % cap by 6.5535 %.
5. The excess fee accrues as surplus in the pool and is collected by the admin via `collectPoolFees`, draining value from the user beyond the intended limit. [2](#0-1) [5](#0-4)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L910-914)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
            lowerPriceX64,
            upperPriceX64,
            params.priceLimitX64,
            spreadFeeE6
```
