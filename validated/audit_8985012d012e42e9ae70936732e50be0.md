### Title
Pool Admin Can Set Uncapped Per-Bin Additional Fees, Bypassing the Protocol Fee Cap System — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`setPoolBinAdditionalFees` in `MetricOmmPoolFactory` forwards `addFeeBuyE6` / `addFeeSellE6` directly to `setBinAdditionalFees` on the pool with **no upper-bound cap check**, while the analogous `setPoolAdminFees` enforces `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8`. A pool admin (semi-trusted, valid trigger) can set per-bin additional fees to `type(uint16).max` = 65 535 (≈ 6.55 % in E6 units) on any bin, causing the effective swap fee for that bin to silently exceed the protocol's governance-enforced fee cap system and overcharge traders.

### Finding Description

The factory enforces fee caps on the admin spread and notional components:

```solidity
// MetricOmmPoolFactory.sol – setPoolAdminFees
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

But the parallel pool-admin entrypoint for per-bin fees performs **no cap check at all**:

```solidity
// MetricOmmPoolFactory.sol – setPoolBinAdditionalFees
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool-level `setBinAdditionalFees` only validates the bin index range, not the fee magnitudes:

```solidity
// MetricOmmPool.sol – setBinAdditionalFees
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;   // no cap
s.addFeeSellE6 = addFeeSellE6; // no cap
``` [3](#0-2) 

These per-bin fees are **additive** to the oracle-derived base spread fee in every swap path:

```solidity
uint256 buyFeeX64  = baseFeeX64 + Math.mulDiv(uint256(addFeeBuyE6),  Q64, ONE_E6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(uint256(addFeeSellE6), Q64, ONE_E6);
``` [4](#0-3) 

The same additive pattern is used in the live swap math (`currBinBuyFeeX64` / `currBinSellFeeX64` passed into `buyToken0InBinSpecifiedIn` / `buyToken1InBinSpecifiedIn`). [5](#0-4) 

The same gap exists at **pool creation time**: `_unpackAndValidateBinStates` validates only `lengthE6` (bin distance) and ignores `buyFee` / `sellFee` entirely, so a pool creator can embed `type(uint16).max` bin fees in the packed arrays with no revert. [6](#0-5) 

### Impact Explanation

`type(uint16).max` = 65 535 in E6 units = **6.5535 %** additional fee per bin direction. The hard cap for the total admin spread fee is 20 % (`HARD_MAX_SPREAD_FEE_E6 = 200_000`). A pool admin can therefore push the effective per-bin swap fee to base spread + 6.55 %, silently exceeding the protocol's intended maximum. Traders receive less output than the oracle/bin curve permits — a direct, quantifiable loss of user principal on every swap routed through the affected bin. The excess fee accrues to LPs, not to the admin, but the trader's loss is real and unbounded by governance. [7](#0-6) 

### Likelihood Explanation

The pool admin is explicitly semi-trusted "only inside caps." The `setPoolBinAdditionalFees` entrypoint is callable at any time by the pool admin with no timelock. The contest scope explicitly lists `setBinAdditionalFees` as an admin-path target for cap-bypass analysis. No existing guard prevents the admin from supplying `type(uint16).max`. [2](#0-1) 

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` mirroring the pattern in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(
    address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6
) external override nonReentrant onlyPoolAdmin(pool) {
    if (addFeeBuyE6  > maxAdminBinFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminBinFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Apply the same check inside `_unpackAndValidateBinStates` when unpacking `buyFee` / `sellFee` from the packed bin arrays at pool creation time. [8](#0-7) 

### Proof of Concept

```solidity
// 1. Deploy pool normally (admin = attacker-controlled EOA)
address pool = factory.createPool(params);

// 2. Pool admin sets bin 0 additional fees to uint16 max — no revert
vm.prank(admin);
factory.setPoolBinAdditionalFees(pool, 0, type(uint16).max, type(uint16).max);
// addFeeBuyE6 = addFeeSellE6 = 65_535  (≈ 6.55 % extra per direction)

// 3. Any trader swapping through bin 0 now pays base_spread + 6.55%
//    The factory's maxAdminSpreadFeeE6 cap (20%) is silently bypassed.
//    Excess fee is retained by LPs; trader receives less than oracle price allows.
``` [9](#0-8) [2](#0-1)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L284-295)
```text
  function setFeeCaps(
    uint24 newMaxProtocolSpreadFeeE6,
    uint24 newMaxAdminSpreadFeeE6,
    uint24 newMaxProtocolNotionalFeeE8,
    uint24 newMaxAdminNotionalFeeE8
  ) external override onlyOwner {
    if (
      newMaxProtocolSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6 || newMaxAdminSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6
        || newMaxProtocolNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8 || newMaxAdminNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8
    ) {
      revert FeeCapsExceedHardLimit();
    }
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L577-593)
```text
    for (uint256 i = 0; i < nonNegativeBinDataArray.length; i++) {
      uint256 packed = nonNegativeBinDataArray[i];
      for (uint8 j = 0; j < 5; j++) {
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
    }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L620-630)
```text
    {
      uint256 k = 0;
      for (uint256 i = 0; i < nonNegativeBinDataArray.length; i++) {
        uint256 packed = nonNegativeBinDataArray[i];
        for (uint8 j = 0; j < 5; j++) {
          BinDataLibrary.BinData binData = BinDataLibrary.toBinData(packed, j);
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

**File:** metric-periphery/contracts/lens/MetricOmmPoolDataProvider.sol (L295-296)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(uint256(addFeeBuyE6), Q64, ONE_E6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(uint256(addFeeSellE6), Q64, ONE_E6);
```

**File:** metric-core/contracts/libraries/SwapMath.sol (L532-544)
```text
  function buyToken0InBinSpecifiedIn(
    BinState memory binState,
    uint256 currBinPos,
    SwapState memory state,
    uint256 currBinBuyFeeX64,
    uint256 lowerPriceX64,
    uint256 upperPriceX64,
    uint256 priceLimitX64,
    uint256 spreadFeeE6
  )
    internal
    pure
    returns (uint256 finalBinPos, uint256 out0Scaled, int256 delta0Scaled, int256 delta1Scaled, uint256 binLpFeeAmount)
```
