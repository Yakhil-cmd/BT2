### Title
Pool Admin Bypasses Fee Cap via Uncapped `setPoolBinAdditionalFees` — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolBinAdditionalFees` allows the pool admin to set per-bin additional fees (`addFeeBuyE6`, `addFeeSellE6`) to any value up to `type(uint16).max` (65 535, i.e. 6.5535 % in E6 units) with no cap check, while every other admin fee path is bounded by `maxAdminSpreadFeeE6`. The extra fee is applied directly to the effective swap price and a portion flows to the admin through the `spreadFeeE6` split, making this a concrete admin-boundary break with direct trader-principal loss.

---

### Finding Description

The factory enforces hard caps on admin-controlled fees in two places:

**`setPoolAdminFees`** — explicit cap check before updating the base spread: [1](#0-0) 

**`_validatePoolParameters`** — same cap check at pool creation: [2](#0-1) 

**`setPoolBinAdditionalFees`** — no cap check at all; the values are forwarded verbatim: [3](#0-2) 

**`setBinAdditionalFees`** on the pool — only validates the bin index, never the fee magnitude: [4](#0-3) 

`addFeeBuyE6` and `addFeeSellE6` are `uint16` fields in `BinState`: [5](#0-4) 

In every swap iteration these values are added directly to `baseFeeX64` (the oracle half-spread) before computing the price the trader pays:

```
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [6](#0-5) [7](#0-6) [8](#0-7) 

Inside `SwapMath`, the total fee (`feeAmountScaled`) is then split: a fraction `spreadFeeE6 / 1e6` goes to protocol+admin, the rest stays in the bin as LP fee: [9](#0-8) 

Because `spreadFeeE6` includes the admin component (`adminSpreadFeeE6`), the admin receives a proportional share of the inflated fee — extracting value beyond what `maxAdminSpreadFeeE6` was designed to permit.

The hard cap constants are: [10](#0-9) 

`HARD_MAX_SPREAD_FEE_E6 = 200 000` (20 %). `type(uint16).max = 65 535` adds another 6.5535 % per bin, unchecked.

---

### Impact Explanation

Every trader who swaps through a bin where the pool admin has set `addFeeBuyE6` or `addFeeSellE6` to `type(uint16).max` pays up to **6.5535 %** more than the oracle-anchored price (on top of the already-capped base spread). The admin's share of that surplus is `65535 * adminSpreadFeeE6 / (spreadFeeE6 * 1e6)` of the swap notional — a direct, per-swap extraction of trader principal that bypasses the `maxAdminSpreadFeeE6` cap. This matches the **admin-boundary break** and **direct loss of user principal** impact gates.

---

### Likelihood Explanation

The pool admin is semi-trusted and holds a live, single-call privilege (`setPoolBinAdditionalFees`) that can be exercised at any time after pool creation, including after LPs have deposited. No timelock, no two-step confirmation, and no factory-owner co-signature is required. A compromised or malicious admin can silently raise per-bin fees on the active bin in a single transaction, affecting the very next swap.

---

### Recommendation

Add a cap check inside `setPoolBinAdditionalFees` (and mirror it in `setBinAdditionalFees` as a defence-in-depth guard):

```solidity
function setPoolBinAdditionalFees(
    address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6
) external override nonReentrant onlyPoolAdmin(pool) {
    if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap that the factory owner can configure independently of the base spread cap.

---

### Proof of Concept

```
// Setup: pool with maxAdminSpreadFeeE6 = 10_000 (1 %)
// Admin calls:
factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);
// No revert — 65535 > 10_000 but no check exists.

// Trader calls swap through bin 0:
// effectiveBuyFeeX64 = baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)
//                    = baseFeeX64 + ~6.55 % in Q64
// Trader pays 6.55 % above oracle mid on top of the oracle half-spread.
// Admin receives adminSpreadFeeE6 / spreadFeeE6 fraction of that 6.55 % fee,
// exceeding the 1 % cap the factory owner intended.
```

The uncapped path is confirmed by the absence of any `AdminFeeTooHigh` revert in `setPoolBinAdditionalFees`: [3](#0-2) 

compared with the guarded path for the base spread: [11](#0-10)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-415)
```text
  function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
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

**File:** metric-core/contracts/MetricOmmPool.sol (L1084-1093)
```text
          (curPosInBinCache, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) = SwapMath.buyToken1InBinSpecifiedOut(
            binState,
            curPosInBinCache,
            state,
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
            lowerPriceX64,
            upperPriceX64,
            params.priceLimitX64,
            spreadFeeE6
          );
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1172-1182)
```text
          (curPosInBinCache, outToken1AmountScaled, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) =
            SwapMath.buyToken1InBinSpecifiedIn(
              binState,
              curPosInBinCache,
              state,
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
              lowerPriceX64,
              upperPriceX64,
              params.priceLimitX64,
              spreadFeeE6
            );
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

**File:** metric-core/contracts/libraries/SwapMath.sol (L409-415)
```text
      uint256 feeAmountScaled = Math.ceilDiv(amountInScaled * currBinBuyFeeX64, ONE_X64);
      amountInScaled += feeAmountScaled;
      uint256 protocolFeeAmountScaled = (feeAmountScaled * spreadFeeE6) / 1e6;

      binState.token0BalanceScaled -= amountOutScaled.toUint104();
      binState.token1BalanceScaled =
        (uint256(binState.token1BalanceScaled) + amountInScaled - protocolFeeAmountScaled).toUint104();
```
