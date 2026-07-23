### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

The factory enforces `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8` caps on pool admin fees through `setPoolAdminFees`, but `setPoolBinAdditionalFees` forwards `addFeeBuyE6`/`addFeeSellE6` directly to the pool with **no cap validation**. Because per-bin additional fees are added on top of the base spread during every swap, a pool admin can charge effective fees that exceed the factory owner's intended cap, causing traders to lose more funds than the protocol's fee governance allows.

---

### Finding Description

`setPoolAdminFees` correctly enforces the factory owner's caps:

```solidity
// MetricOmmPoolFactory.sol lines 414–415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

But `setPoolBinAdditionalFees` passes the caller-supplied values straight through with no cap check:

```solidity
// MetricOmmPoolFactory.sol lines 450–457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees` also performs no cap check — it only validates the bin index:

```solidity
// MetricOmmPool.sol lines 464–474
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
}
``` [3](#0-2) 

During every swap, the per-bin additional fee is **added on top of** the base spread fee:

```solidity
// MetricOmmPool.sol line 540
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
``` [4](#0-3) 

`addFeeBuyE6` and `addFeeSellE6` are `uint16`, so the maximum settable value is **65 535 in E6 units = 6.5535%**. The factory owner can lower `maxAdminSpreadFeeE6` to any value (including 0), but the pool admin can always set per-bin additional fees up to 6.5535% regardless, bypassing the cap entirely.

The hard cap constants confirm the intended governance boundary:

```solidity
// MetricOmmPoolFactory.sol lines 44–45
uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;   // 20%
uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
``` [5](#0-4) 

The factory owner can set `maxAdminSpreadFeeE6` well below 20% (e.g., 500 = 0.05%) to protect users, but the per-bin path is a completely uncapped side-door.

---

### Impact Explanation

Every swap through an affected bin pays `addFeeBuyE6` or `addFeeSellE6` on top of the base spread. A pool admin who sets `addFeeBuyE6 = 65535` extracts up to 6.5535% extra from every buy-side swap in that bin, directly reducing the token output received by traders. This is a **direct loss of user principal** on every swap, not a theoretical or dust-level loss. The factory owner's fee governance — the only mechanism protecting users from admin overreach — is silently bypassed.

---

### Likelihood Explanation

The trigger is a single call to `setPoolBinAdditionalFees` by the pool admin, which is a **valid semi-trusted role action** with no timelock or multi-step requirement. Any pool admin on any pool can exploit this immediately after deployment. The factory owner's cap setting provides no protection because the per-bin path is never checked against it.

---

### Recommendation

Add a cap check inside `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, enforce the cap inside `MetricOmmPool.setBinAdditionalFees` by reading the factory's current `maxAdminSpreadFeeE6` via a factory call, or store a per-pool bin-fee cap at deploy time.

---

### Proof of Concept

1. Factory owner calls `setFeeCaps(500, 500, ...)` — sets `maxAdminSpreadFeeE6 = 500` (0.05%) to protect users.
2. Pool admin calls `setPoolAdminFees(pool, 501, 0)` → **reverts** with `AdminFeeTooHigh`. Cap is enforced.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)` → **succeeds**. No cap check.
4. Every buy-side swap through bin 0 now pays an additional 6.5535% fee on top of the base spread — 131× the intended cap.
5. Traders receive significantly less output than the protocol's fee governance was designed to guarantee.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L414-415)
```text
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-540)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
```
