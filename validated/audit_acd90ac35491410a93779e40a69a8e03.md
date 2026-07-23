### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6`/`addFeeSellE6` (both `uint16`, max 65535) directly to `MetricOmmPool.setBinAdditionalFees` with no validation against `maxAdminSpreadFeeE6`. The parallel path `setPoolAdminFees` explicitly enforces the cap; this path does not. A pool admin can therefore set per-bin additional fees to 65535 (6.5535%) on any bin regardless of what `maxAdminSpreadFeeE6` is configured to, directly causing traders to pay fees far exceeding the factory-configured bound on every swap through that bin.

---

### Finding Description

`setPoolAdminFees` enforces the cap:

```solidity
// MetricOmmPoolFactory.sol:414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` has no such check — it passes values straight through:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`MetricOmmPool.setBinAdditionalFees` also has no cap check — it stores the raw values:

```solidity
// MetricOmmPool.sol:464-474
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    ...
}
``` [3](#0-2) 

During every swap, the per-bin additional fee is added on top of the oracle-derived base fee:

```solidity
// MetricOmmPool.sol:910
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) 

The same pattern applies to the sell direction (line 1088) and to `getSellAndBuyPrices` (lines 540–541). [5](#0-4) 

---

### Impact Explanation

A pool admin can set `addFeeBuyE6 = addFeeSellE6 = 65535` (6.5535%) on any bin. Every trader swapping through that bin pays 6.5535% additional spread on top of the oracle-derived base fee, regardless of the factory's `maxAdminSpreadFeeE6` cap. This is a direct, per-swap loss of user principal with no on-chain mechanism to prevent or detect the cap violation at execution time.

---

### Likelihood Explanation

The pool admin role is semi-trusted and is explicitly bounded by `maxAdminSpreadFeeE6`. The bypass requires only a single call to `setPoolBinAdditionalFees` with `uint16` max values — no special conditions, no timelock, no co-signer. Any pool admin (including one who has been granted the role by a legitimate deployer) can execute this immediately.

---

### Recommendation

Add a cap check in `MetricOmmPoolFactory.setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
if (uint256(addFeeBuyE6) + uint256(addFeeSellE6) > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
// or, if each direction is independently bounded:
if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

The exact semantics (per-direction vs. combined) should match the intended invariant. The same guard should be applied at pool creation time when `nonNegativeBinDataArray`/`negativeBinDataArray` are unpacked and stored as initial `BinState` values. [6](#0-5) 

---

### Proof of Concept

1. Deploy factory with `maxAdminSpreadFeeE6 = 1000` (0.1%).
2. Create a pool; pool admin is `admin`.
3. `vm.prank(admin); factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);`
4. Read `BinState` for bin 0: `addFeeBuyE6 == 65535`, `addFeeSellE6 == 65535` — both stored unchecked.
5. Execute a swap through bin 0; the effective fee applied is `baseFeeX64 + 65535/1e6` — 6.5535% additional spread, 65× the configured cap.

### Citations

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L628-631)
```text
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

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```
