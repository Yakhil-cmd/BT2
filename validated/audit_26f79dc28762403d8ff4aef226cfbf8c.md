### Title
Pool Admin Can Set Bin Additional Fees Without Cap Validation, Bypassing Protocol Hard Cap — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

The external bug's class is **partial validation of untrusted input fields**: some fields of a struct are checked while critical payload fields are passed unchecked into a downstream function that crashes. The native analog in Metric OMM is `setPoolBinAdditionalFees`: the factory validates the bin index but passes `addFeeBuyE6` / `addFeeSellE6` to the pool with **zero cap enforcement**, allowing a pool admin to push the total effective swap fee above the protocol's hard cap.

---

### Finding Description

`MetricOmmPoolFactory.setPoolBinAdditionalFees` is the only path through which per-bin additional fees are written to pool state. The function body is:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [1](#0-0) 

The factory performs **no validation** on `addFeeBuyE6` or `addFeeSellE6` before forwarding them. The pool's `setBinAdditionalFees` only validates the bin index:

```solidity
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external
    onlyFactory
    nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    ...
}
``` [2](#0-1) 

The bin index is checked (analogous to checking `shred_cnt <= 34` in the external bug), but the fee payload fields are written directly to storage unchecked (analogous to the unvalidated `pkts[]` contents).

During a swap, the additional fee is added on top of `baseFeeX64` (which already encodes the spread fee):

```solidity
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [3](#0-2) 

The protocol enforces a hard cap on the spread fee component:

```solidity
uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;   // 20 %
uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
``` [4](#0-3) 

`setPoolAdminFees` enforces `maxAdminSpreadFeeE6` on the spread component:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [5](#0-4) 

But `setPoolBinAdditionalFees` has **no equivalent guard**. A `uint16` value can reach `65 535`, which in E6 units is **6.5535 %**. Combined with the maximum spread fee of 20 %, the total effective fee a trader faces on a given bin can reach **26.5535 %**, exceeding the hard cap by more than 6 percentage points.

---

### Impact Explanation

- **Bad-price execution / admin-boundary break.** The pool admin is semi-trusted only within the caps the factory enforces. By setting `addFeeBuyE6 = 65535` on the active bin, the admin silently raises the effective buy price above what the oracle/bin curve permits under the protocol's own hard cap, causing traders to receive less output than the protocol guarantees.
- The excess fee accrues inside the bin as LP balance, so it is not recoverable by the trader. This is a direct loss of user principal on every swap through that bin.

---

### Likelihood Explanation

- Trigger requires a pool admin (semi-trusted, not fully privileged). The admin can act unilaterally with no timelock on `setBinAdditionalFees`.
- Any pool whose admin is compromised or acts adversarially can exploit this immediately.
- Likelihood is **medium**: the admin role is semi-trusted and the cap bypass is not obvious to LPs or traders inspecting the pool.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool, mirroring the guard already present in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
{
    // Enforce that per-bin additional fees cannot push total fee above the admin spread cap
    if (uint256(addFeeBuyE6) + poolFeeConfig[pool].adminSpreadFeeE6 > maxAdminSpreadFeeE6)
        revert AdminFeeTooHigh();
    if (uint256(addFeeSellE6) + poolFeeConfig[pool].adminSpreadFeeE6 > maxAdminSpreadFeeE6)
        revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap that the factory owner can set, analogous to `maxAdminSpreadFeeE6`.

---

### Proof of Concept

1. Deploy a pool with `adminSpreadFeeE6 = 0` and `spreadProtocolFeeE6 = 0` (total `spreadFeeE6 = 0`).
2. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)`.
3. No revert occurs — the factory forwards the call directly.
4. A trader calls `swap(...)` on bin 0. Inside `_swapToken0ForToken1SpecifiedInput`, the effective buy fee becomes `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` — a 6.5535 % additional fee with zero spread fee, or up to 26.5535 % total when the spread fee is also at its maximum.
5. The trader receives materially less token1 than the oracle price and the protocol's hard cap would permit, with the difference locked in the bin as LP balance.

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
