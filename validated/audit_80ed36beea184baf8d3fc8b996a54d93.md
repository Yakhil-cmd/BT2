### Title
Pool admin can set per-bin additional fees with no upper-bound cap, bypassing the protocol's hard fee limits — (`File: metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolBinAdditionalFees` passes `addFeeBuyE6` / `addFeeSellE6` directly to the pool with zero validation against any fee cap. Every other fee-setting path in the factory enforces explicit caps (`maxAdminSpreadFeeE6`, `maxAdminNotionalFeeE8`, `HARD_MAX_SPREAD_FEE_E6`), but the per-bin additional fee path has no analogous bound check. This is the direct Metric OMM analog of the external report's "value passes partial validation (bin-index range) but the actual bound (fee cap) is never enforced."

---

### Finding Description

**Invariant class:** Admin-boundary break — pool admin exceeds caps.

**Root cause — `setPoolBinAdditionalFees` (factory, line 450–457):**

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

No cap check on `addFeeBuyE6` or `addFeeSellE6` before forwarding to the pool. [1](#0-0) 

Compare with `setPoolAdminFees`, which explicitly enforces caps before any state change:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [2](#0-1) 

**Root cause — `_unpackAndValidateBinStates` (factory, lines 567–651):**

The validation loop unpacks `(length, buyFee, sellFee)` from each packed bin word but only validates `length` (non-zero, cumulative distance) and bin count. `buyFee` and `sellFee` are silently accepted at any value up to `type(uint16).max = 65 535`. [3](#0-2) [4](#0-3) 

**How the uncapped value reaches swap execution:**

In every swap direction the effective per-bin fee is:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

`baseFeeX64` is the oracle half-spread. `addFeeX64` is the uncapped per-bin component. The total fee charged to the trader is `feeAmountScaled = amountInScaled × currBinFeeX64 / ONE_X64`, and the protocol/admin share is `feeAmountScaled × spreadFeeE6 / 1e6`. [9](#0-8) 

**Hard caps that are bypassed:**

```solidity
uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;   // 20 %
uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000; // 1 %
``` [10](#0-9) 

`addFeeBuyE6` / `addFeeSellE6` are `uint16`, so their maximum is 65 535 (≈ 6.55 % in E6 units). A pool admin can set this on every bin simultaneously, adding up to 6.55 % on top of whatever `spreadFeeE6` is already configured, with no factory-level enforcement.

---

### Impact Explanation

Traders swapping through any bin where the pool admin has set `addFeeBuyE6` or `addFeeSellE6` to an uncapped value pay a higher effective fee than the protocol's hard-capped rate permits. The excess fee accrues inside the pool (LP balances grow beyond what the oracle curve alone would produce), and the protocol/admin receives a proportional share of the inflated fee. This constitutes:

1. **Direct loss of user principal** — traders pay more input tokens than the capped fee schedule allows.
2. **Admin-boundary break** — the pool admin exceeds the hard fee cap (`HARD_MAX_SPREAD_FEE_E6 = 200 000`) for specific bins without any factory check preventing it.

The same uncapped path exists at pool creation time (`_unpackAndValidateBinStates`), so a pool can be deployed with maximum bin additional fees from block 0.

---

### Likelihood Explanation

- The pool admin is a semi-trusted role that is explicitly constrained to operate "only inside caps." The `setPoolBinAdditionalFees` path is a normal operational function the admin is expected to call.
- No timelock or multi-step proposal is required; the admin can raise bin fees to `type(uint16).max` in a single transaction.
- The factory already validates the bin index range (`LOWEST_BIN` / `HIGHEST_BIN`) inside `setBinAdditionalFees` on the pool, giving the false impression that full validation has occurred. [11](#0-10) 

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Apply the same check inside `_unpackAndValidateBinStates` when unpacking `buyFee` / `sellFee` from the packed bin arrays at pool creation time.

---

### Proof of Concept

1. Deploy a pool with any valid parameters.
2. As pool admin, call `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)`.
3. No revert occurs; `addFeeBuyE6 = 65535` (6.5535 %) is stored on bin 0.
4. A trader swaps through bin 0. The effective fee is `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)`, which exceeds the hard-capped `HARD_MAX_SPREAD_FEE_E6 = 200 000` (20 %) by 6.5535 percentage points.
5. The trader pays more input tokens than the protocol's fee cap permits; the factory's `setPoolAdminFees` cap check is entirely bypassed for this fee vector.

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L580-592)
```text
        BinDataLibrary.BinData binData = BinDataLibrary.toBinData(packed, j);
        (uint256 length,,) = binData.unpack();
        if (length == 0) {
          if (j == 0) revert BinLengthZero(posBinCount);
          break;
        }

        cumulativeDistance += length.toInt256();
        if (cumulativeDistance >= 1e6) {
          revert BinDistanceOutOfRange(posBinCount, cumulativeDistance);
        }
        posBinCount++;
      }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L626-630)
```text
          (uint16 length, uint16 buyFee, uint16 sellFee) = binData.unpack();
          if (length == 0) break;
          nonNegativeBinStates[k] = BinState({
            token0BalanceScaled: 0, token1BalanceScaled: 0, lengthE6: length, addFeeBuyE6: buyFee, addFeeSellE6: sellFee
          });
```

**File:** metric-core/contracts/MetricOmmPool.sol (L469-473)
```text
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L999-999)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1177)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/libraries/SwapMath.sol (L409-411)
```text
      uint256 feeAmountScaled = Math.ceilDiv(amountInScaled * currBinBuyFeeX64, ONE_X64);
      amountInScaled += feeAmountScaled;
      uint256 protocolFeeAmountScaled = (feeAmountScaled * spreadFeeE6) / 1e6;
```
