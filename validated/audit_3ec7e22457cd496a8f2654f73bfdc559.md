Based on my thorough analysis of the codebase, I have identified a valid analog to the EIP-4626 `maxMint`/`maxDeposit` cap-bypass bug.

---

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`setPoolBinAdditionalFees` forwards `addFeeBuyE6` and `addFeeSellE6` directly to the pool with **no cap validation**, while every other admin fee setter enforces `maxAdminSpreadFeeE6` / `maxAdminNotionalFeeE8`. A pool admin can set per-bin additional fees up to `uint16.max` (65 535 E6 = 6.5535%) on any bin, causing the total effective spread charged to traders to exceed the protocol's hard cap of `HARD_MAX_SPREAD_FEE_E6 = 200 000` (20%).

### Finding Description

The factory enforces fee caps on every admin-controlled fee path **except** the per-bin additional fee path.

`setPoolAdminFees` (lines 414–415) correctly validates:
```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` (lines 450–457) performs **no such check**:
```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

In the swap pricing path, the per-bin additional fee is added directly on top of the oracle-derived base fee:
```solidity
uint256 buyFeeX64  = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6,  ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [3](#0-2) 

The same uncapped addition appears in all four swap variants: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

The hard cap constants are:
```solidity
uint24 internal constant HARD_MAX_SPREAD_FEE_E6   = 200_000;   // 20 %
uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000; // 1 %
``` [8](#0-7) 

`uint16.max = 65 535` in E6 units equals **6.5535 %**. Combined with a base spread already at the 20 % hard cap, the total effective spread reaches **26.5535 %**, exceeding the hard cap by more than 30 %.

The pool-on-chain `setBinAdditionalFees` also performs no cap check — it only validates the bin index:
```solidity
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    ...
}
``` [9](#0-8) 

### Impact Explanation

Every trader who swaps through a bin with elevated `addFeeBuyE6` / `addFeeSellE6` pays a higher effective price than the protocol's hard cap permits. The excess spread stays in the pool as LP liquidity — it is not collected as a named fee — so it is invisible to the fee-collection accounting and cannot be reversed. Traders suffer a direct, permanent loss of swap output proportional to the excess fee on every affected swap.

### Likelihood Explanation

The pool admin is explicitly described as "semi-trusted only inside caps." The trigger requires only a single call to `setPoolBinAdditionalFees` by the pool admin — no special market conditions, no multi-step setup, and no privileged protocol-owner involvement. Any pool whose admin is malicious, compromised, or mistaken can exploit this immediately after pool creation.

### Recommendation

Add cap validation inside `setPoolBinAdditionalFees` before forwarding to the pool, mirroring the pattern used in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(
    address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6
) external override nonReentrant onlyPoolAdmin(pool) {
    // addFee values are E6; maxAdminSpreadFeeE6 is also E6 — safe to compare directly
    if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap so the protocol can tune the per-bin ceiling independently of the base spread cap.

### Proof of Concept

1. Factory is deployed; `HARD_MAX_SPREAD_FEE_E6 = 200_000`, `maxAdminSpreadFeeE6 = 200_000`.
2. Pool admin creates a pool with `adminSpreadFeeE6 = 200_000` (at the hard cap).
3. Pool admin calls:
   ```solidity
   factory.setPoolBinAdditionalFees(pool, 0, 65_535, 65_535);
   ```
   No revert occurs — no cap check exists.
4. A trader calls `swap` routing through bin 0. The effective buy fee applied is:
   ```
   buyFeeX64 = baseFeeX64 + mulDiv(65_535, ONE_X64, 1e6)
             = baseFeeX64 + ~6.5535% in Q64
   ```
   on top of the already-capped 20 % base spread, yielding a total effective spread of ~26.5535 %.
5. The trader receives ~6.5535 % less output than the protocol's hard cap of 20 % would permit, with no on-chain mechanism to detect or reverse the overcharge.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L464-473)
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
```

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L999-999)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1177)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```
