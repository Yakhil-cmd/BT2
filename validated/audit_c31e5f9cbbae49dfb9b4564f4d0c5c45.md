### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`, `metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

`setPoolAdminFees` enforces `maxAdminSpreadFeeE6` on the pool-level spread fee, but `setPoolBinAdditionalFees` sets per-bin `addFeeBuyE6`/`addFeeSellE6` with **no cap check at all**. Because both components are additively combined in the swap execution path, a pool admin can exceed the protocol-intended fee ceiling by routing extra fee extraction through the bin-additional-fee path.

---

### Finding Description

The factory enforces a hard fee ceiling via two state variables:

- `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%)
- `maxAdminSpreadFeeE6` (≤ `HARD_MAX_SPREAD_FEE_E6`)

`setPoolAdminFees` correctly checks against this cap:

```solidity
// MetricOmmPoolFactory.sol
function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    ...
}
``` [1](#0-0) 

However, `setPoolBinAdditionalFees` — also callable by the pool admin — passes values directly to the pool with **no cap enforcement**:

```solidity
// MetricOmmPoolFactory.sol
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

And the pool-level function also performs no cap check:

```solidity
// MetricOmmPool.sol
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
}
``` [3](#0-2) 

In the swap execution path, both the base spread fee and the bin additional fee are **additively combined**:

```solidity
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [4](#0-3) 

The `addFeeBuyE6`/`addFeeSellE6` fields are typed as `uint16`, allowing values up to 65,535 (≈ 6.55% in E6 units). A pool admin who has already set `adminSpreadFeeE6 = maxAdminSpreadFeeE6` (20%) can additionally set `addFeeBuyE6 = 65535` on every bin, making the effective per-bin fee ≈ 26.55% — well above the 20% cap the protocol intends to enforce.

---

### Impact Explanation

Traders executing swaps in bins with elevated `addFeeBuyE6`/`addFeeSellE6` receive less output (or pay more input) than the protocol-intended fee ceiling permits. The excess fee accrues to LPs in those bins. This is a direct loss of swap output value to traders, caused by a pool admin exceeding the cap the protocol explicitly designed to constrain them.

---

### Likelihood Explanation

The pool admin is a semi-trusted role that is explicitly expected to be constrained by fee caps. The bypass requires only two sequential admin calls — `setPoolAdminFees` at the cap, then `setPoolBinAdditionalFees` at `uint16` max — with no timelock, no additional privilege, and no external condition. Any pool admin can execute this at will on any bin in their pool.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` (factory level) against `maxAdminSpreadFeeE6`, or introduce a dedicated `maxAdminBinAdditionalFeeE6` cap. The simplest fix:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, enforce the cap on the **combined** effective fee (pool spread + bin additional) to prevent any additive bypass path.

---

### Proof of Concept

1. Factory owner sets `maxAdminSpreadFeeE6 = 200_000` (20%).
2. Pool admin calls `setPoolAdminFees(pool, 200_000, 0)` — sets spread fee to the cap.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — no revert, no cap check.
4. A trader calls `swap(...)` routing through bin 0. The effective buy fee is `baseFeeX64 + 65535/1e6 * ONE_X64`, i.e., the oracle spread fee plus an additional ≈ 6.55%, totalling ≈ 26.55% effective fee.
5. The trader receives materially less output than the 20% cap would permit. The excess LP fee stays in the bin, benefiting LPs at the trader's expense — a direct loss of user funds beyond the protocol-sanctioned ceiling. [5](#0-4) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L41-46)
```text
  // ============ Constants ============

  /// @dev Owner `setFeeCaps` values cannot exceed these (spread: 1e6 = 100%; notional: 1e8 = 100%)
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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```
