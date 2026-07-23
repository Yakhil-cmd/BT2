### Title
Pool Admin Bypasses Fee Caps via Uncapped Per-Bin Additional Fees in `setPoolBinAdditionalFees` - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` and `addFeeSellE6` directly to the pool with no cap validation, while every other admin fee setter (`setPoolAdminFees`, `setPoolProtocolFee`, `setFeeCaps`) enforces hard limits. A pool admin — who is explicitly semi-trusted "only inside caps and timelocks" — can therefore set per-bin additional spread fees up to `type(uint16).max = 65 535` (≈ 6.55 % in E6 units) on any bin, on top of the already-capped base spread, causing traders to receive worse prices than the protocol's hard-cap system is designed to allow.

### Finding Description

The factory enforces a layered fee-cap system:

- `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %) is the absolute ceiling for both protocol and admin spread components.
- `setPoolAdminFees` reverts with `AdminFeeTooHigh` when `newAdminSpreadFeeE6 > maxAdminSpreadFeeE6`.
- `setFeeCaps` reverts with `FeeCapsExceedHardLimit` when any cap exceeds the hard ceiling. [1](#0-0) [2](#0-1) 

However, `setPoolBinAdditionalFees` performs **no cap check** at all:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [3](#0-2) 

The pool's `setBinAdditionalFees` also performs no cap check — it only validates the bin index: [4](#0-3) 

These per-bin fees are then added directly to the effective swap fee inside every swap loop iteration:

```solidity
buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [5](#0-4) 

The same pattern appears in the live swap path: [6](#0-5) 

### Impact Explanation

With `addFeeBuyE6 = 65535` the additional fee component is `65535 / 1e6 ≈ 6.55 %`. When the base spread is already at the hard cap (20 % admin + 20 % protocol = 40 %), the effective per-bin fee reaches **≈ 46.55 %**, exceeding the hard cap the protocol is designed to enforce. Traders executing swaps through that bin receive a materially worse price than the protocol's published maximum allows. The surplus captured by the pool is then split between admin and protocol via the `spreadFeeE6` ratio, so the admin extracts a proportional share of the uncapped additional fee revenue — a direct loss of user principal above the intended ceiling. [7](#0-6) 

### Likelihood Explanation

The pool admin is a semi-trusted role. The factory's entire cap architecture exists precisely because the pool admin is **not** fully trusted. Any pool admin — including one who accepted the role legitimately but later acts adversarially — can call `setPoolBinAdditionalFees` with `addFeeBuyE6 = 65535` immediately, with no timelock and no protocol-owner approval. The call requires only `onlyPoolAdmin(pool)`.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` (and mirror it in `setBinAdditionalFees` on the pool) analogous to the check in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(
    address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6
) external override nonReentrant onlyPoolAdmin(pool) {
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxBinAdditionalFeeE6` cap that the factory owner can configure, keeping per-bin fees subject to the same governance as all other admin fee parameters.

### Proof of Concept

1. Pool is deployed with `adminSpreadFeeE6 = 200_000` (20 %, at the hard cap) and `spreadProtocolFeeE6 = 200_000` (20 %, at the hard cap). Total base spread = 40 %.
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)`. No revert — no cap check exists.
3. A trader calls `swap(…, zeroForOne=true, …)` routing through bin 0.
4. Inside the swap loop: `buyFeeX64 = baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)`, adding ≈ 6.55 % on top of the 40 % base spread.
5. The trader's effective execution price is ≈ 46.55 % worse than the oracle mid-price — exceeding the protocol's hard-capped maximum by 6.55 percentage points.
6. The surplus is collected and split between admin and protocol; the admin extracts fee revenue beyond what the cap system permits. [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L543-548)
```text
    uint256 askBeforeNotional = Math.mulDiv(marginalPriceX64, ONE_X64 + buyFeeX64, ONE_X64, Math.Rounding.Ceil);
    uint256 bidAfterSpread = Math.mulDiv(marginalPriceX64, ONE_X64, ONE_X64 + sellFeeX64, Math.Rounding.Floor);

    uint256 nf = notionalFeeE8;
    buyPriceX64 = Math.mulDiv(askBeforeNotional, 1e8, 1e8 - nf, Math.Rounding.Ceil).toUint128();
    sellPriceX64 = Math.mulDiv(bidAfterSpread, 1e8 - nf, 1e8, Math.Rounding.Floor).toUint128();
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1178)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
              lowerPriceX64,
```
