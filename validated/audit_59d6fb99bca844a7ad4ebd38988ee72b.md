Now I have a complete picture. Let me verify the swap math to confirm how per-bin fees interact with the cap system.

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped Per-Bin Additional Fees in `setPoolBinAdditionalFees` — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`setPoolBinAdditionalFees` in `MetricOmmPoolFactory.sol` forwards `addFeeBuyE6` and `addFeeSellE6` directly to the pool's `setBinAdditionalFees` with no validation against `maxAdminSpreadFeeE6`. The pool admin can set per-bin additional fees up to `uint16.max` = 65,535 (≈6.55% in E6 units) on any bin, bypassing the factory owner's fee cap entirely. These per-bin fees are added on top of the base spread fee during every swap through the affected bin, widening the effective bid/ask spread beyond the cap the factory owner intended to enforce.

### Finding Description

The factory enforces a two-layer fee cap system. The factory owner sets `maxAdminSpreadFeeE6` (bounded by `HARD_MAX_SPREAD_FEE_E6 = 200_000`, i.e. 20%). The pool admin's global spread fee is checked against this cap in `setPoolAdminFees`:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

However, the pool admin's other fee-setting path — `setPoolBinAdditionalFees` — passes values straight through with no cap check:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

On the pool side, `setBinAdditionalFees` only validates the bin index range, not the fee magnitude:

```solidity
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

During every swap, the per-bin additional fee is added directly on top of the oracle-derived base spread fee:

```solidity
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [4](#0-3) 

The same uncapped path also exists at pool creation time: `_unpackAndValidateBinStates` validates only bin distances and counts, never the `addFeeBuyE6`/`addFeeSellE6` fields packed into the bin arrays. [5](#0-4) 

### Impact Explanation

The per-bin additional fees widen the effective bid/ask spread seen by every swapper in the affected bin. The extra spread creates pool surplus that is collected as protocol/admin fees via `collectFees`. A pool admin who sets `addFeeBuyE6 = addFeeSellE6 = 65535` (≈6.55%) on the active bin imposes that additional cost on every swap, regardless of what `maxAdminSpreadFeeE6` the factory owner has configured. If the factory owner lowers `maxAdminSpreadFeeE6` to 0 to freeze admin fee increases, the pool admin can still impose up to 6.55% per-bin fee — a direct loss of trader principal that the cap system was designed to prevent.

### Likelihood Explanation

The pool admin is a semi-trusted role that is explicitly constrained to operate "inside caps." The bypass requires only a single call to `setPoolBinAdditionalFees` with `addFeeBuyE6 = type(uint16).max`. No timelock, no special precondition, and no factory-owner cooperation is needed. The trigger is valid and reachable by the pool admin at any time the pool is active.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` (and symmetrically in `_unpackAndValidateBinStates` at creation time) to ensure per-bin additional fees do not exceed `maxAdminSpreadFeeE6`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Apply the same guard when unpacking bin arrays in `_unpackAndValidateBinStates`.

### Proof of Concept

```solidity
// Factory owner lowers the admin spread cap to 1% (10_000 in E6)
factory.setFeeCaps(200_000, 10_000, 1_000_000, 1_000_000);

// Pool admin cannot raise the global admin spread fee above 1%
vm.prank(admin);
vm.expectRevert(AdminFeeTooHigh.selector);
factory.setPoolAdminFees(pool, 20_000, 0); // reverts correctly

// But pool admin CAN set per-bin additional fees to uint16.max = 65535 (~6.55%)
// with no revert — bypassing the 1% cap entirely
vm.prank(admin);
factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535); // succeeds

// Every swap through bin 0 now pays baseFee + 6.55% additional spread,
// far exceeding the factory owner's intended 1% admin cap.
``` [6](#0-5) [2](#0-1) [7](#0-6) [4](#0-3)

### Citations

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L567-593)
```text
  function _unpackAndValidateBinStates(
    int24 curBinDistFromProvidedPriceE6,
    uint256[] calldata nonNegativeBinDataArray,
    uint256[] calldata negativeBinDataArray
  ) internal pure returns (BinState[] memory nonNegativeBinStates, BinState[] memory negativeBinStates) {
    int256 cumulativeDistance = int256(curBinDistFromProvidedPriceE6);
    if (cumulativeDistance >= 1e6 || cumulativeDistance <= -1e6) revert BinDistanceOutOfRange(0, cumulativeDistance);
    if (nonNegativeBinDataArray.length == 0) revert BinArraysEmpty();

    int256 posBinCount = int256(0);
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
