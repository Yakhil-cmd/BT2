### Title
Pool Admin Bypasses Fee Cap via `setPoolBinAdditionalFees` — No Cap Validation on Per-Bin Additional Fees - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`setPoolAdminFees` enforces `maxAdminSpreadFeeE6` / `maxAdminNotionalFeeE8` caps on the pool admin's base fee components, but the sibling function `setPoolBinAdditionalFees` passes `addFeeBuyE6` / `addFeeSellE6` directly to the pool with **no cap check at all**. A pool admin can set per-bin additional fees up to `uint16` max (65 535, i.e. 6.5535 %) on every bin, stacking on top of the already-capped base spread and the oracle-derived spread, and the factory's cap invariant is silently violated.

### Finding Description

`setPoolAdminFees` (factory line 408–435) validates both fee components before writing them:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

`setPoolBinAdditionalFees` (factory line 450–457) performs no such check:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool's `setBinAdditionalFees` (pool line 464–474) also performs no cap check — it only validates the bin index range. The values are stored directly in `BinState.addFeeBuyE6` / `addFeeSellE6`.

During every swap the per-bin additional fee is added to the oracle-derived `baseFeeX64` before the bin math runs:

```solidity
// buy token0 (specified-in, line 999):
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)

// buy token1 (specified-out, line 1088):
params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6)
```

`uint16` max is 65 535, so the admin can add up to **6.5535 %** of additional effective fee per bin, on top of the base spread fee (capped at `HARD_MAX_SPREAD_FEE_E6 = 200 000`, i.e. 20 %) and the oracle spread. The combined effective fee for a targeted bin can therefore exceed the hard cap the protocol intends to enforce.

The same gap exists at pool creation: `_unpackAndValidateBinStates` (factory line 567–650) validates `lengthE6` and cumulative distance but never validates `addFeeBuyE6` / `addFeeSellE6` from the packed bin data against any cap.

### Impact Explanation

Traders swapping through a bin whose `addFeeBuyE6` or `addFeeSellE6` has been set to the maximum value pay up to 6.5535 % more than the oracle-anchored price permits. The excess is retained by the pool as LP-side spread, so it is a direct loss of trader principal on every swap touching that bin. The factory's cap system — the only mechanism that bounds what a semi-trusted pool admin can extract from users — is silently bypassed for the per-bin fee path.

### Likelihood Explanation

The pool admin is a semi-trusted role that is explicitly constrained to act "only inside caps." The cap bypass requires only a single call to `setPoolBinAdditionalFees` with `addFeeBuyE6 = type(uint16).max` (65 535). No special preconditions, no timelock, no protocol-owner involvement. Any pool admin can trigger this at any time after pool creation.

### Recommendation

Add a cap check inside `setPoolBinAdditionalFees` in `MetricOmmPoolFactory.sol`, analogous to the check in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Additionally, validate `addFeeBuyE6` / `addFeeSellE6` inside `_unpackAndValidateBinStates` at pool creation time so the same cap applies to the initial bin configuration.

### Proof of Concept

1. Factory is deployed; `maxAdminSpreadFeeE6 = 200 000` (20 %).
2. Pool admin calls `setPoolAdminFees(pool, 200_000, 0)` — accepted, at the cap.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` — **no revert**; bin 0 now carries an additional 6.5535 % fee in both directions.
4. A trader calls `swap(…, zeroForOne=true, …)` routing through bin 0. The effective fee applied is `baseFeeX64 + mulDiv(65_535, ONE_X64, 1e6)`, i.e. oracle spread + 6.5535 %, exceeding the 20 % hard cap the protocol advertises.
5. The trader receives fewer tokens than the oracle-anchored price and the factory's cap system would permit; the difference is retained in the pool as LP spread, constituting a direct loss of trader principal. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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
