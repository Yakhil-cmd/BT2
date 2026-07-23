### Title
Pool Admin Bypasses Protocol Fee Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` passes `addFeeBuyE6`/`addFeeSellE6` directly to the pool with no upper-bound check, while the parallel `setPoolAdminFees` path enforces `maxAdminSpreadFeeE6`. A pool admin can set `addFeeBuyE6 = type(uint16).max = 65535` (6.5535% in E6) on any bin, causing buy swaps in that bin to pay fees above the protocol-enforced hard cap.

---

### Finding Description

`setPoolAdminFees` correctly enforces the cap:

```solidity
// MetricOmmPoolFactory.sol:414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

But `setPoolBinAdditionalFees` has no such check — it passes the caller-supplied values straight through:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`MetricOmmPool.setBinAdditionalFees` only validates the bin index, not the fee magnitude:

```solidity
// MetricOmmPool.sol:464-474
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

During every buy swap, the per-bin additional fee is added directly on top of the oracle-derived base fee:

```solidity
// MetricOmmPool.sol:910
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) 

The same additive pattern appears in `getSellAndBuyPrices` and all four swap directions. [5](#0-4) 

The factory hard cap is `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%). `type(uint16).max = 65535` in E6 is 6.5535%. A pool admin who has already set the global spread fee to the maximum 20% can additionally set `addFeeBuyE6 = 65535` on any bin, making the effective buy fee for that bin **26.5535%** — 6.5535 percentage points above the protocol-advertised ceiling. [6](#0-5) 

---

### Impact Explanation

Traders executing buy swaps through the affected bin pay up to 6.5535% more than the protocol-enforced maximum. The excess fee is taken from the trader's input (reduced output), constituting a direct loss of user principal above the protocol-advertised cap. The pool admin controls the destination of admin fees, so the excess accrues to the admin.

---

### Likelihood Explanation

The pool admin is a designated, semi-trusted role explicitly bounded by caps per the contest's admin-boundary rules. The attack requires no external conditions: the pool admin calls `setPoolBinAdditionalFees(pool, bin, 65535, 65535)` in a single transaction with no timelock. Any pool whose admin is malicious or compromised is immediately exploitable.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` mirroring the one in `setPoolAdminFees`. A reasonable bound is `maxAdminSpreadFeeE6` (or a dedicated `maxBinAdditionalFeeE6` constant), reverting with `AdminFeeTooHigh` if either `addFeeBuyE6` or `addFeeSellE6` exceeds it:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

---

### Proof of Concept

1. Deploy factory with `maxAdminSpreadFeeE6 = HARD_MAX_SPREAD_FEE_E6 = 200_000`.
2. Pool admin calls `factory.setPoolAdminFees(pool, 200_000, 0)` — succeeds (at cap).
3. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — **does not revert**.
4. Read `_binStates[0].addFeeBuyE6` — equals `65535`.
5. Execute a buy swap through bin 0; observe that the effective fee applied is `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)`, i.e., the oracle spread plus 6.5535%, exceeding the 20% hard cap by 6.5535 percentage points.
6. Compare output to a swap with `addFeeBuyE6 = 0` — the trader receives measurably less output, confirming direct fund loss.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-44)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L469-473)
```text
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
