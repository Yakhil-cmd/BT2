### Title
Pool Admin Bypasses Factory Fee Caps via `setPoolBinAdditionalFees` Missing Cap Check — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolAdminFees` enforces `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8` caps before updating global pool fees. The parallel function `setPoolBinAdditionalFees` — which also lets the pool admin impose fees on swappers — has **no cap check at all**, allowing the pool admin to set per-bin fees that, when added to the global spread fee, exceed the factory's hard-coded fee ceiling.

---

### Finding Description

`setPoolAdminFees` guards against the admin exceeding the factory-enforced caps:

```solidity
// MetricOmmPoolFactory.sol lines 414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

`setPoolBinAdditionalFees`, callable by the same pool admin, passes the values straight through with **zero cap validation**:

```solidity
// MetricOmmPoolFactory.sol lines 450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool's `setBinAdditionalFees` also performs no cap check:

```solidity
// MetricOmmPool.sol lines 464-474
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
}
```

During a swap, the bin additional fee is **added on top of** the global spread fee:

```solidity
// MetricOmmPool.sol lines 540-541
uint256 buyFeeX64  = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6,  ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

`baseFeeX64` already encodes the full global spread fee (protocol + admin portions). The bin additional fee is therefore **uncapped additive overhead** on every swap that crosses that bin.

`uint16` allows values up to 65 535, which in E6 units equals **6.5535 %**. The factory's `HARD_MAX_SPREAD_FEE_E6 = 200 000` (20 %) is the ceiling the owner intends to enforce for admin-controlled fees. Because bin additional fees are not subject to this ceiling, the pool admin can push the effective per-bin fee to **≈ 46.5 %** (protocol max 20 % + admin max 20 % + bin additional max 6.55 %) — more than double the hard cap.

---

### Impact Explanation

Every swap routed through a bin with an inflated `addFeeBuyE6` / `addFeeSellE6` pays fees above the factory-enforced ceiling. The excess fee accrues as surplus in the pool and is collected by the admin via `collectFees`. This is a **direct loss of user principal** (swap output is reduced by the uncapped fee) that the factory's cap system is explicitly designed to prevent. Repeated across all bins and all swaps, the pool admin can extract far more than the factory owner authorised.

---

### Likelihood Explanation

The pool admin is a **semi-trusted** role: trusted only within the caps and timelocks the factory enforces. The bypass requires only a single call to `setPoolBinAdditionalFees` — no timelock, no co-signer, no special precondition. Any pool admin who turns adversarial (or whose key is compromised) can immediately exploit this on any bin.

---

### Recommendation

Add the same cap guard in `setPoolBinAdditionalFees` that exists in `setPoolAdminFees`. Because bin additional fees are additive to the global spread fee, the correct bound is the remaining headroom under the admin cap:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

A stricter variant would also verify that `poolFeeConfig[pool].adminSpreadFeeE6 + addFeeBuyE6 ≤ maxAdminSpreadFeeE6`.

---

### Proof of Concept

1. Factory owner sets `maxAdminSpreadFeeE6 = 200_000` (20 %) — the hard cap.
2. Pool admin calls `setPoolAdminFees(pool, 200_000, 0)` — accepted, at the cap.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` — **no revert**, accepted.
4. A user swaps through bin 0. The effective buy fee is `baseFeeX64` (≈ 20 % spread) **plus** 6.5535 % bin additional fee ≈ **26.5 %** total — 33 % above the factory's hard cap.
5. The excess fee accumulates as pool surplus and is collected by the admin via `collectPoolFees`, draining user value above the authorised ceiling. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```
