### Title
Pool Admin Bypasses Hard Spread-Fee Cap via Uncapped Per-Bin Additional Fees in `setPoolBinAdditionalFees` — (File: metric-core/contracts/MetricOmmPoolFactory.sol)

---

### Summary

`setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` to the pool with **no cap validation**, while every other admin-controlled fee component is bounded by `maxAdminSpreadFeeE6 ≤ HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %). A pool admin can set per-bin additional fees to `type(uint16).max = 65 535` (≈ 6.55 % in E6 units) on every active bin, silently exceeding the hard cap and extracting excess fees from swappers.

---

### Finding Description

The factory enforces a hard ceiling on the global admin spread fee:

```
HARD_MAX_SPREAD_FEE_E6 = 200_000   // 20 %
maxAdminSpreadFeeE6    ≤ HARD_MAX_SPREAD_FEE_E6
adminSpreadFeeE6       ≤ maxAdminSpreadFeeE6      // checked in setPoolAdminFees
``` [1](#0-0) [2](#0-1) 

However, `setPoolBinAdditionalFees` passes the caller-supplied values straight through to the pool with **only a bin-index range check**:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [3](#0-2) 

The pool stores them without any cap:

```solidity
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6) external onlyFactory {
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    ...
}
``` [4](#0-3) 

During every swap the per-bin additional fee is added directly to the oracle-derived base fee before the swap math executes:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [5](#0-4) [6](#0-5) 

The same gap exists at pool creation: `_unpackAndValidateBinStates` unpacks `addFeeBuyE6` / `addFeeSellE6` from the packed bin arrays but discards them without any cap check (only `length` is validated):

```solidity
(uint256 length,,) = binData.unpack();   // addFeeBuyE6, addFeeSellE6 silently ignored
``` [7](#0-6) 

The `BinState` struct confirms both fields are `uint16`, giving a maximum of 65 535 (≈ 6.55 % in E6 units): [8](#0-7) 

---

### Impact Explanation

A pool admin who has already complied with `maxAdminSpreadFeeE6` can call `setPoolBinAdditionalFees(pool, bin, 65535, 65535)` on every bin. Every subsequent swap through those bins pays an additional ≈ 6.55 % on top of the already-capped global spread fee, silently exceeding the hard cap. The excess accrues as pool surplus and is swept to the admin (and protocol) via `collectPoolFees`. Swappers suffer a direct, unannounced loss proportional to swap size; for a $1 M swap the overcharge is ≈ $65 000.

---

### Likelihood Explanation

The trigger is a single `onlyPoolAdmin` call with no timelock. Any pool admin — a role that is explicitly semi-trusted "only inside caps" — can execute this immediately after pool creation or at any later time. No special conditions are required.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` (and in `_unpackAndValidateBinStates` at creation time) that ensures the per-bin additional fee does not exceed `maxAdminSpreadFeeE6` (or a dedicated `maxBinAdditionalFeeE6` constant):

```solidity
if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

Apply the same guard inside `_unpackAndValidateBinStates` when unpacking the packed bin arrays at `createPool` time.

---

### Proof of Concept

1. Deploy factory + deployer; create a pool with `adminSpreadFeeE6 = maxAdminSpreadFeeE6` (at the hard cap).
2. Pool admin calls:
   ```solidity
   factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);
   ```
   No revert — `65535` passes through unchecked.
3. A user calls `pool.swap(...)` routing through bin 0. The effective buy fee applied inside `SwapMath.buyToken0InBinSpecifiedIn` is:
   ```
   baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)   // ≈ oracle_spread + 6.55 %
   ```
   plus the global `spreadFeeE6` — total exceeds `HARD_MAX_SPREAD_FEE_E6`.
4. The excess surplus is collected by the admin via `factory.collectPoolFees(pool)`, draining value from swappers beyond the protocol-intended ceiling. [3](#0-2) [4](#0-3) [9](#0-8)

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L581-581)
```text
        (uint256 length,,) = binData.unpack();
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

**File:** metric-core/contracts/MetricOmmPool.sol (L994-1004)
```text
          (curPosInBinCache, outToken0AmountScaled, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) =
            SwapMath.buyToken0InBinSpecifiedIn(
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

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1177)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
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
