### Title
Pool Admin Bypasses Fee Cap via `setPoolBinAdditionalFees` Without Cap Validation — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

The factory enforces `maxAdminSpreadFeeE6` on the global admin spread fee in `setPoolAdminFees`, but the parallel admin path `setPoolBinAdditionalFees` forwards per-bin additional fees directly to the pool with no cap check. A pool admin can therefore push the effective per-bin swap fee above the hard ceiling that the protocol intends to enforce.

### Finding Description

The factory defines hard fee caps and enforces them on the global admin spread fee path:

`setPoolAdminFees` checks both caps before updating: [1](#0-0) 

`setPoolBinAdditionalFees` performs no such check and passes values straight through: [2](#0-1) 

The pool's `setBinAdditionalFees` likewise contains no cap guard — it only validates the bin index: [3](#0-2) 

At swap time, the per-bin additional fee is added on top of the base spread fee to form the effective buy/sell fee: [4](#0-3) 

`addFeeBuyE6` and `addFeeSellE6` are `uint16` fields (max value 65 535, i.e. ≈ 6.55 % in E6 units): [5](#0-4) 

The hard cap for the total spread fee is `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %): [6](#0-5) 

With a base `spreadFeeE6` already at the 20 % hard cap, a pool admin can call `setPoolBinAdditionalFees` with `addFeeBuyE6 = 65535` on every active bin, raising the effective per-bin fee to ≈ 26.55 % — 6.55 percentage points above the hard ceiling — with no revert.

The same gap exists at pool creation: `_unpackAndValidateBinStates` validates only `lengthE6` (distance bounds) and never checks `addFeeBuyE6`/`addFeeSellE6` against any cap: [7](#0-6) 

### Impact Explanation

Traders executing swaps in bins where the pool admin has set elevated per-bin fees pay a higher effective spread than the protocol's hard cap permits. The excess fee accrues inside the bin as LP balance (not separately tracked), meaning it is not split between protocol and admin via `collectFees` — it silently inflates LP balances at the trader's expense. This is a direct loss of trader principal above the protocol-guaranteed ceiling.

### Likelihood Explanation

The pool admin is explicitly described as "semi-trusted only inside caps and timelocks." `setPoolBinAdditionalFees` is callable by the pool admin at any time with no timelock, no cap guard, and no event that would distinguish a legitimate fine-tuning from a cap-bypass. Any pool whose admin is compromised or acts adversarially can exploit this immediately.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` (and in `_unpackAndValidateBinStates` at pool creation) to ensure that `addFeeBuyE6` and `addFeeSellE6` do not exceed `maxAdminSpreadFeeE6` (or a dedicated per-bin hard cap). For example:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Apply the same guard inside `_unpackAndValidateBinStates` when unpacking `buyFee`/`sellFee` from the packed bin arrays.

### Proof of Concept

1. Deploy factory with `maxAdminSpreadFeeE6 = 200_000` (20 %).
2. Create a pool with `adminSpreadFeeE6 = 200_000` (at the cap). Total `spreadFeeE6 = 200_000`.
3. As pool admin, call:
   ```solidity
   factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);
   ```
   No revert occurs.
4. Observe that `_binState(pool, 0)` now returns `addFeeBuyE6 = 65535`, `addFeeSellE6 = 65535`.
5. A swap routed through bin 0 now pays an effective spread of `200_000 + 65_535 = 265_535` (≈ 26.55 %), exceeding the 20 % hard cap by 6.55 percentage points. The excess is extracted from the trader and retained in the bin as inflated LP balance.

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L626-631)
```text
          (uint16 length, uint16 buyFee, uint16 sellFee) = binData.unpack();
          if (length == 0) break;
          nonNegativeBinStates[k] = BinState({
            token0BalanceScaled: 0, token1BalanceScaled: 0, lengthE6: length, addFeeBuyE6: buyFee, addFeeSellE6: sellFee
          });
          k++;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L539-544)
```text

    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);

    uint256 askBeforeNotional = Math.mulDiv(marginalPriceX64, ONE_X64 + buyFeeX64, ONE_X64, Math.Rounding.Ceil);
    uint256 bidAfterSpread = Math.mulDiv(marginalPriceX64, ONE_X64, ONE_X64 + sellFeeX64, Math.Rounding.Floor);
```

**File:** metric-core/contracts/types/PoolStorage.sol (L22-24)
```text
  uint16 lengthE6;
  uint16 addFeeBuyE6;
  uint16 addFeeSellE6;
```
