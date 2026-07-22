### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`setPoolAdminFees` enforces `maxAdminSpreadFeeE6` before updating the global admin spread component, but `setPoolBinAdditionalFees` forwards per-bin additional fees directly to the pool with no cap check. A pool admin can therefore impose per-bin spread fees that exceed the protocol-owner-enforced cap, including when the owner has set the cap to zero.

### Finding Description

`setPoolAdminFees` in `MetricOmmPoolFactory` enforces two cap checks before writing new fee values: [1](#0-0) 

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

`setPoolBinAdditionalFees`, callable by the same pool admin role, performs no equivalent check and passes the caller-supplied values directly to the pool: [2](#0-1) 

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

`setBinAdditionalFees` on the pool also performs no cap check — it only validates the bin index: [3](#0-2) 

The per-bin additional fees are added directly to the base fee in every swap step through the active bin: [4](#0-3) 

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

The `addFeeBuyE6` / `addFeeSellE6` fields are `uint16`, so the maximum per-bin additional fee is 65,535 (≈ 6.55% in E6 units). The factory hard cap `HARD_MAX_SPREAD_FEE_E6` is 200,000 (20%): [5](#0-4) 

The factory owner can lower `maxAdminSpreadFeeE6` to any value down to 0 via `setFeeCaps`: [6](#0-5) 

When the owner lowers `maxAdminSpreadFeeE6` below 65,535 (or to 0), `setPoolAdminFees` correctly reverts for any non-zero admin spread fee, but `setPoolBinAdditionalFees` still accepts up to 65,535 per bin, bypassing the cap entirely.

### Impact Explanation

Traders swapping through the affected bin pay a higher effective spread than the protocol-owner-enforced cap permits. The excess fee amount is retained in the bin as LP balance (via `binState.token1BalanceScaled` or `token0BalanceScaled` increment net of protocol portion): [7](#0-6) 

This is a direct financial loss to traders — they pay more than the cap allows — and constitutes an admin-boundary break: the pool admin exceeds the fee cap set by the factory owner.

### Likelihood Explanation

The bypass is always reachable by the pool admin via a single call to `setPoolBinAdditionalFees`. The cap bypass is material whenever the factory owner has set `maxAdminSpreadFeeE6` below 65,535 (e.g., to enforce a low-fee regime or to zero out admin spread entirely). The default cap is 200,000, so the bypass is latent in default deployments but becomes active the moment the owner tightens the cap — a documented and expected owner action.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` analogous to the one in `setPoolAdminFees`. Since per-bin fees are additive on top of the global spread, the check should ensure each bin's additional fee does not exceed `maxAdminSpreadFeeE6`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The same check should be applied to the bin data unpacked at pool creation time in `_unpackAndValidateBinStates`, since `addFeeBuyE6`/`addFeeSellE6` packed into the bin arrays are also written to pool state without a cap check. [8](#0-7) 

### Proof of Concept

1. Factory owner calls `setFeeCaps(200_000, 0, 1_000_000, 1_000_000)` — setting `maxAdminSpreadFeeE6 = 0` to prohibit any admin spread fee.
2. Pool admin calls `setPoolAdminFees(pool, 1, 0)` → reverts with `AdminFeeTooHigh`. Cap is enforced.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)` → **succeeds**. No cap check.
4. `_binStates[0].addFeeBuyE6 = 65535` and `addFeeSellE6 = 65535` are now live on the pool.
5. Any trader swapping through bin 0 pays an additional ≈ 6.55% spread fee on top of the oracle-derived base fee, despite the owner having set the admin spread cap to 0. [2](#0-1) [3](#0-2)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L284-299)
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
    maxProtocolSpreadFeeE6 = newMaxProtocolSpreadFeeE6;
    maxAdminSpreadFeeE6 = newMaxAdminSpreadFeeE6;
    maxProtocolNotionalFeeE8 = newMaxProtocolNotionalFeeE8;
    maxAdminNotionalFeeE8 = newMaxAdminNotionalFeeE8;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L999-999)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
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
