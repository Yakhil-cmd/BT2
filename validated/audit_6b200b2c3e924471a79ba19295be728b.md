### Title
`maxAdminSpreadFeeE6` / `maxAdminNotionalFeeE8` caps not enforced in `setPoolBinAdditionalFees` — (File: metric-core/contracts/MetricOmmPoolFactory.sol)

---

### Summary

The factory stores `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8` as owner-configurable caps on pool-admin-controlled fees and enforces them in `setPoolAdminFees`. However, `setPoolBinAdditionalFees` forwards per-bin additional fees directly to the pool with no cap check, allowing a pool admin to set bin-level buy/sell fees up to `uint16.max` (65 535 = 6.5535 % in E6 units) regardless of what the factory owner configured as the admin fee ceiling.

---

### Finding Description

The factory declares and exposes two admin fee caps:

```solidity
uint24 public override maxAdminSpreadFeeE6;
uint24 public override maxAdminNotionalFeeE8;
``` [1](#0-0) 

These are set (and can be lowered) by the factory owner via `setFeeCaps`:

```solidity
maxAdminSpreadFeeE6 = newMaxAdminSpreadFeeE6;
maxAdminNotionalFeeE8 = newMaxAdminNotionalFeeE8;
``` [2](#0-1) 

They are correctly enforced in `setPoolAdminFees`:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [3](#0-2) 

And in `_validatePoolParameters` at pool creation:

```solidity
if (params.adminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (params.adminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [4](#0-3) 

But `setPoolBinAdditionalFees` passes the caller-supplied values straight through to the pool with **no cap check at all**:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [5](#0-4) 

These bin-level fees are then added directly to the effective swap fee inside the pool:

```solidity
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [6](#0-5) 

Because `addFeeBuyE6` and `addFeeSellE6` are `uint16`, their maximum value is 65 535, which in E6 units equals **6.5535 %**. The factory owner can lower `maxAdminSpreadFeeE6` to, say, 500 (0.05 %) to protect users, but the pool admin can still call `setPoolBinAdditionalFees` and write 65 535 into every bin — the cap variable has no effect on this path.

---

### Impact Explanation

A pool admin can impose per-bin buy/sell fees up to 6.5535 % on every bin, completely bypassing the `maxAdminSpreadFeeE6` ceiling the factory owner configured. Every swap through an affected bin pays a higher effective fee than the cap system was designed to permit. Accumulated excess fees are extracted from traders and credited to the admin fee destination, constituting a direct loss of user funds above the intended protocol-enforced limit. This is an admin-boundary break: the pool admin exceeds the cap set by the factory owner.

---

### Likelihood Explanation

The trigger is a valid semi-trusted actor (pool admin) calling a publicly accessible factory function (`setPoolBinAdditionalFees`) with no preconditions beyond holding the pool admin role. No special setup or external dependency is required. The factory owner's `setFeeCaps` call — the intended protection — has no effect on this code path.

---

### Recommendation

Add cap enforcement inside `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap if bin-level fees are intended to have a separate ceiling.

---

### Proof of Concept

1. Factory owner calls `setFeeCaps(_, 500, _, _)` — setting `maxAdminSpreadFeeE6 = 500` (0.05 %).
2. Pool admin calls `setPoolAdminFees(pool, 500, 0)` — accepted, at the cap.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — **no revert**; `maxAdminSpreadFeeE6` is never read.
4. A user swaps through bin 0: effective fee = base spread fee + 6.5535 % bin additional fee + notional fee — far above the 0.05 % ceiling the factory owner intended.
5. The excess fee accrues as spread surplus and is paid out to the admin fee destination on the next `collectPoolFees` call, draining value from the user beyond the protocol-enforced limit.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L62-68)
```text
  uint24 public override maxAdminSpreadFeeE6;

  /// @inheritdoc IMetricOmmPoolFactory
  uint24 public override maxProtocolNotionalFeeE8;

  /// @inheritdoc IMetricOmmPoolFactory
  uint24 public override maxAdminNotionalFeeE8;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L296-299)
```text
    maxProtocolSpreadFeeE6 = newMaxProtocolSpreadFeeE6;
    maxAdminSpreadFeeE6 = newMaxAdminSpreadFeeE6;
    maxProtocolNotionalFeeE8 = newMaxProtocolNotionalFeeE8;
    maxAdminNotionalFeeE8 = newMaxAdminNotionalFeeE8;
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L557-558)
```text
    if (params.adminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (params.adminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```
