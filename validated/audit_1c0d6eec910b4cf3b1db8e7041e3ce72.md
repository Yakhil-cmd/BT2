### Title
Pool Admin Bypasses Factory Fee Caps via Uncapped `setPoolBinAdditionalFees` — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolAdminFees` enforces `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8` caps before updating pool fees. `MetricOmmPoolFactory.setPoolBinAdditionalFees`, callable by the same pool admin role, forwards bin additional fees to the pool with **no factory-level cap check**. A pool admin can set per-bin buy/sell fees to `uint16.max` (65,535 E6 = 6.5535%) for every bin, regardless of what the factory owner has configured as the admin fee ceiling, fully bypassing the cap system that is supposed to bound semi-trusted admin power.

---

### Finding Description

`setPoolAdminFees` enforces caps before writing fees:

```solidity
// MetricOmmPoolFactory.sol lines 414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees`, guarded by the identical `onlyPoolAdmin` modifier, performs **no such check**:

```solidity
// MetricOmmPoolFactory.sol lines 450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees` only validates the bin index, not the fee magnitude:

```solidity
// MetricOmmPool.sol lines 464-474
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

During a swap, the bin additional fee is added directly on top of the base spread fee:

```solidity
// MetricOmmPool.sol (swap path)
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) 

The factory owner's hard cap `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%) and the configurable `maxAdminSpreadFeeE6` are enforced only on the base spread component. The bin additional fee path is entirely outside this enforcement boundary. [5](#0-4) 

---

### Impact Explanation

A pool admin can set `addFeeBuyE6 = addFeeSellE6 = 65535` (6.5535%) on every bin. This fee is charged on top of the base spread fee for every swap through those bins. Traders receive fewer output tokens than the factory-owner-capped fee schedule implies. If the factory owner has set `maxAdminSpreadFeeE6 = 0` to protect traders from admin extraction, the pool admin can still extract up to 6.5535% per swap via bin additional fees — a complete bypass of the cap. For a $1 M swap this is $65,535 extracted per transaction, constituting direct loss of user principal above Sherlock Medium thresholds. The loss is permanent (tokens transferred out as fees) and affects every trader in every bin of the pool.

---

### Likelihood Explanation

The pool admin is a semi-trusted role that is explicitly bounded by factory caps. The factory owner's ability to set `maxAdminSpreadFeeE6` is the primary protection mechanism. Any pool admin who is malicious, compromised, or simply misconfigured can trigger this bypass without any additional privilege escalation. The call is a single transaction with no timelock. Likelihood is **Medium**: it requires a bad-acting pool admin, but the factory owner's cap provides no actual protection against it.

---

### Recommendation

Add a factory-level cap check in `setPoolBinAdditionalFees`, mirroring the pattern in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
+   if (addFeeBuyE6  > maxAdminBinFeeE6) revert AdminFeeTooHigh();
+   if (addFeeSellE6 > maxAdminBinFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Introduce a `maxAdminBinFeeE6` state variable settable by the factory owner via `setFeeCaps`, subject to the same `HARD_MAX_SPREAD_FEE_E6` hard limit. Alternatively, enforce that `adminSpreadFeeE6 + addFeeBuyE6 ≤ maxAdminSpreadFeeE6` at the time of the bin fee update.

---

### Proof of Concept

1. Factory owner deploys factory, sets `maxAdminSpreadFeeE6 = 0` to guarantee zero admin spread extraction.
2. Pool creator calls `createPool(...)` with `adminSpreadFeeE6 = 0` (forced by cap) and `admin = attacker`.
3. Attacker (pool admin) calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — no revert, no cap check.
4. Trader calls `swap(...)` routing through bin 0. The effective buy fee is `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` — 6.5535% extracted on top of the oracle spread, despite the factory owner's 0% admin fee cap.
5. Attacker calls `collectPoolFees(pool)` — the surplus (spread fees) flows to the factory; the bin additional fee is embedded in the LP accounting and accrues to the pool, but the trader has already paid 6.5535% more than the factory-owner-capped schedule permits. [2](#0-1) [1](#0-0)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

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
