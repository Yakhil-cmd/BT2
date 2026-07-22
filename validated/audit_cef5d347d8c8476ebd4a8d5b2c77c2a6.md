### Title
Pool Admin Bypasses Hard Fee Cap via Unchecked `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` passes `addFeeBuyE6` and `addFeeSellE6` directly to the pool with no cap validation. The protocol enforces a hard spread-fee ceiling of 20% (`HARD_MAX_SPREAD_FEE_E6 = 200_000`) on every other admin fee path, but the bin-additional-fee path is entirely unchecked. A pool admin can set per-bin fees up to the `uint16` maximum (65 535 / 1e6 ≈ 6.55 %) on top of an already-maxed base spread fee, causing traders to pay an effective fee of up to ≈ 26.55 % — well above the protocol's stated hard limit.

---

### Finding Description

The factory enforces fee caps consistently on the two main admin fee setters:

`setPoolAdminFees` validates both components before writing: [1](#0-0) 

`setPoolProtocolFee` (owner path) similarly validates: [2](#0-1) 

The hard ceiling itself is: [3](#0-2) 

However, `setPoolBinAdditionalFees` performs **no fee-value validation** — it only checks the bin index range on the pool side:

```solidity
// MetricOmmPoolFactory.sol L450-456
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [4](#0-3) 

On the pool, `setBinAdditionalFees` only validates the bin index, not the fee values: [5](#0-4) 

The bin additional fee is then **added on top of** the base spread fee in the swap math:

```solidity
// MetricOmmPool.sol L1177
params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6)
``` [6](#0-5) 

The `BinState` struct stores these as `uint16`: [7](#0-6) 

`uint16` max = 65 535, which in E6 units = **6.5535 %**. With a base spread fee already at the 20 % hard cap, the total effective per-bin fee reaches **≈ 26.55 %**, a 33 % relative overshoot of the protocol's hard limit.

---

### Impact Explanation

Traders executing swaps through a bin with a maxed additional fee pay up to ≈ 6.55 percentage points more than the protocol's hard ceiling permits. The excess fee accrues inside the pool as LP/protocol surplus, meaning the pool admin cannot pocket it directly, but traders suffer a direct, quantifiable loss of principal on every swap routed through the affected bin. This breaks the **Swap Conservation** and **Admin-boundary** invariants: the pool receives more input than the oracle/bin curve permits under the stated fee cap, and the pool admin exceeds the cap without any privileged factory-owner action.

---

### Likelihood Explanation

The trigger is a single call by the pool admin — a semi-trusted role that is explicitly scoped to operate *within* caps and timelocks. No additional privileges, no malicious setup, and no non-standard tokens are required. Any pool admin can call `setPoolBinAdditionalFees(pool, bin, 65535, 65535)` immediately after pool creation.

---

### Recommendation

Add a cap check inside `setPoolBinAdditionalFees` before forwarding to the pool, mirroring the pattern used in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
+   if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
+   if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, enforce the cap on the pool side inside `setBinAdditionalFees` by reading `spreadFeeE6` and rejecting values that would push the total above the hard limit.

---

### Proof of Concept

1. Factory is deployed with `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %).
2. Pool is created with `adminSpreadFeeE6 = 200_000` (already at the hard cap).
3. Pool admin calls:
   ```solidity
   factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);
   ```
   No revert occurs — the call succeeds.
4. A trader swaps through bin 0. The effective sell fee applied is:
   ```
   baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)
   ≈ 20% + 6.55% = 26.55%
   ```
5. The trader pays ≈ 6.55 % more than the protocol's hard ceiling on every unit of input routed through that bin, with the excess locked in the pool as surplus beyond what the fee cap was designed to allow.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L324-325)
```text
    if (newProtocolSpreadFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    if (newProtocolNotionalFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();
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

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1178)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
              lowerPriceX64,
```

**File:** metric-core/contracts/types/PoolStorage.sol (L19-25)
```text
struct BinState {
  uint104 token0BalanceScaled;
  uint104 token1BalanceScaled;
  uint16 lengthE6;
  uint16 addFeeBuyE6;
  uint16 addFeeSellE6;
}
```
