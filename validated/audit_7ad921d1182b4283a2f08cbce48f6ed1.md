### Title
Pool Admin Can Set Uncapped Per-Bin Additional Fees, Bypassing the `maxAdminSpreadFeeE6` Admin Boundary - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary
`setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` directly to the pool with no cap validation, while every other admin fee setter enforces `maxAdminSpreadFeeE6`. A pool admin can set per-bin fees to `type(uint16).max` (65 535 E6 ≈ 6.55 %) on any bin, charging traders an uncapped additional spread on top of the oracle-derived base fee and the global spread fee, in direct violation of the factory's fee-cap invariant.

### Finding Description
The factory maintains four fee caps (`maxProtocolSpreadFeeE6`, `maxAdminSpreadFeeE6`, `maxProtocolNotionalFeeE8`, `maxAdminNotionalFeeE8`) and enforces them on every fee-setting path:

- `setPoolAdminFees` checks `newAdminSpreadFeeE6 > maxAdminSpreadFeeE6` and reverts with `AdminFeeTooHigh`.
- `setPoolProtocolFee` checks `newProtocolSpreadFeeE6 > maxProtocolSpreadFeeE6` and reverts with `ProtocolFeeTooHigh`.
- `createPool` validates `params.adminSpreadFeeE6 > maxAdminSpreadFeeE6`. [1](#0-0) 

However, `setPoolBinAdditionalFees` performs **no cap check** and passes the caller-supplied values straight through: [2](#0-1) 

The pool's `setBinAdditionalFees` also performs no cap check beyond a bin-index range guard: [3](#0-2) 

These per-bin values are consumed directly in every swap iteration as an additive term on top of the oracle-derived `baseFeeX64`: [4](#0-3) [5](#0-4) [6](#0-5) 

The same uncapped path is visible in `getSellAndBuyPrices`, which is the quote surface used by routers and aggregators: [7](#0-6) 

### Impact Explanation
`addFeeBuyE6` and `addFeeSellE6` are `uint16`, so the maximum settable value is 65 535 E6 ≈ **6.55 %** per bin per direction. This fee is charged to every trader whose swap touches that bin, on top of the oracle spread and the global spread fee. The pool admin can silently raise the effective swap cost on any bin to an amount that far exceeds what the `maxAdminSpreadFeeE6` cap (hard-limited to 20 %) was designed to permit for the admin-controlled component. Traders lose the excess input tokens; the surplus accrues as spread revenue to LPs (not to the admin directly, but the admin controls the pool's attractiveness and can use this to drain value from traders).

The hard cap `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %) is the absolute ceiling the factory owner can set for any admin fee: [8](#0-7) 

Per-bin fees bypass this ceiling entirely.

### Likelihood Explanation
Any pool admin — a role that is explicitly described as **semi-trusted** and bounded by caps — can call `setPoolBinAdditionalFees` at any time with no timelock, no prior collection step, and no cap guard. The call requires only `onlyPoolAdmin(pool)`. The admin can target the bin currently active (`curBinIdx`) to maximise immediate impact on live swaps.

### Recommendation
Add a cap check in `setPoolBinAdditionalFees` (factory side) mirroring the guard already present in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(
    address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6
) external override nonReentrant onlyPoolAdmin(pool) {
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Apply the same guard to the initial bin data unpacked in `_unpackAndValidateBinStates` at pool creation, where `addFeeBuyE6` / `addFeeSellE6` are also accepted without a cap check: [9](#0-8) 

### Proof of Concept

1. Factory is deployed with `maxAdminSpreadFeeE6 = 200_000` (20 %).
2. Pool admin calls:
   ```solidity
   factory.setPoolBinAdditionalFees(pool, 0, 65_535, 65_535);
   ```
   No revert occurs; `_binStates[0].addFeeBuyE6 = 65_535`, `addFeeSellE6 = 65_535`.
3. A trader calls `swap` with `zeroForOne = false` (buy token0). The swap loop enters bin 0 and computes:
   ```
   currBinBuyFeeX64 = baseFeeX64 + mulDiv(65_535, ONE_X64, 1e6)
                    = baseFeeX64 + ~6.55% in Q64.64
   ```
4. The trader pays ≈ 6.55 % more token1 input than the oracle spread alone would require, with no factory-level guard having fired.
5. The same effect applies to `getSellAndBuyPrices`, so any router or aggregator quoting through this pool will quote a price that includes the uncapped per-bin fee, causing traders to unknowingly accept worse execution.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L413-415)
```text
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L626-630)
```text
          (uint16 length, uint16 buyFee, uint16 sellFee) = binData.unpack();
          if (length == 0) break;
          nonNegativeBinStates[k] = BinState({
            token0BalanceScaled: 0, token1BalanceScaled: 0, lengthE6: length, addFeeBuyE6: buyFee, addFeeSellE6: sellFee
          });
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

**File:** metric-core/contracts/MetricOmmPool.sol (L910-911)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
            lowerPriceX64,
```

**File:** metric-core/contracts/MetricOmmPool.sol (L999-1000)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
              lowerPriceX64,
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1178)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
              lowerPriceX64,
```
