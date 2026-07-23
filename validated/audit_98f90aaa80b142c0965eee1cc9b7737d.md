### Title
Pool Admin Can Set Per-Bin Additional Fees Without Any Cap, Bypassing the Factory's `maxAdminSpreadFeeE6` Guard - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` applies no cap check on `addFeeBuyE6` / `addFeeSellE6`, while the sibling function `setPoolAdminFees` explicitly enforces `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8`. A pool admin can therefore set per-bin additional fees to the `uint16` maximum (65 535 ≙ 6.5535 % in E6 units) for any bin, instantly and without a timelock, and front-run large swaps to extract excess cost from traders.

### Finding Description

`setPoolAdminFees` enforces governance caps before writing new fee values:

```solidity
// MetricOmmPoolFactory.sol L414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees`, by contrast, passes the caller-supplied values straight through to the pool with zero validation:

```solidity
// MetricOmmPoolFactory.sol L450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees` also performs no cap check — it only validates the bin index: [3](#0-2) 

During every swap the per-bin additional fee is added directly to the oracle spread before the LP-fee calculation:

```solidity
// MetricOmmPool.sol L999  (buy token0, specified-in path)
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)

// MetricOmmPool.sol L1088 (buy token1, specified-out path)
params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6)
``` [4](#0-3) [5](#0-4) 

Because neither `setPoolBinAdditionalFees` nor `setBinAdditionalFees` has a timelock, the change takes effect in the same block it is submitted.

### Impact Explanation

A malicious pool admin can:

1. Monitor the mempool for a large swap targeting a specific bin.
2. Front-run it with `setPoolBinAdditionalFees(pool, targetBin, 65535, 65535)` — raising the effective fee rate for that bin by up to **6.5535 %** on top of the oracle spread and the base admin spread fee.
3. Let the victim's swap execute at the inflated rate (the extra fee accrues to LPs, of which the admin may be one, and the admin also receives the `adminSpreadFeeE6` fraction of the enlarged LP fee).
4. Back-run with `setPoolBinAdditionalFees(pool, targetBin, 0, 0)` to restore normal conditions.

The victim pays materially more than the publicly visible fee configuration implied. This is a direct loss of user principal on every sandwiched swap. The factory owner's cap system (`maxAdminSpreadFeeE6`, `maxAdminNotionalFeeE8`) is entirely bypassed for this fee dimension. [6](#0-5) 

### Likelihood Explanation

- `createPool` is **permissionless** — any address can deploy a pool and designate itself as pool admin.
- The pool admin role is explicitly described as "semi-trusted only inside caps and timelocks"; this path has neither.
- No on-chain signal (event, timelock proposal) precedes the fee change, so off-chain monitoring cannot reliably protect users.
- The attack requires only two additional transactions (front-run + back-run) and is profitable whenever the sandwiched swap is large enough to cover gas.

### Recommendation

Add the same cap enforcement to `setPoolBinAdditionalFees` that exists in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(
    address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6
) external override nonReentrant onlyPoolAdmin(pool) {
    // Mirror the cap guard used in setPoolAdminFees
    if (uint24(addFeeBuyE6) + uint24(addFeeSellE6) > maxAdminSpreadFeeE6)
        revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Additionally, consider introducing a timelock (analogous to `priceProviderTimelock`) for all fee-changing pool-admin actions so that users can observe and react to pending fee increases before they take effect.

### Proof of Concept

```solidity
// Attacker is pool admin of `pool`; victim Bob has a large swap pending.

// Step 1 – front-run Bob's swap
factory.setPoolBinAdditionalFees(pool, currentBin, 65535, 65535);
// addFeeBuyE6 = 65535 → +6.5535 % on top of oracle spread for this bin

// Step 2 – Bob's swap executes; he pays ~6.5 % more than the advertised fee

// Step 3 – back-run: restore fees to avoid detection
factory.setPoolBinAdditionalFees(pool, currentBin, 0, 0);
```

The pool's swap loop reads `binState.addFeeBuyE6` / `addFeeSellE6` at execution time:

```solidity
// MetricOmmPool.sol L999
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

so the inflated value is applied to Bob's swap without any slippage-limit protection specific to the additional-fee dimension.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L62-68)
```text
  uint24 public override maxAdminSpreadFeeE6;

  /// @inheritdoc IMetricOmmPoolFactory
  uint24 public override maxProtocolNotionalFeeE8;

  /// @inheritdoc IMetricOmmPoolFactory
  uint24 public override maxAdminNotionalFeeE8;
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
