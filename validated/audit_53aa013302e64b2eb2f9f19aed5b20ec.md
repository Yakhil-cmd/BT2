### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped Per-Bin Additional Fees — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

The factory enforces `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8` caps on the pool admin's LP spread fee via `setPoolAdminFees`, but the parallel `setPoolBinAdditionalFees` path sets per-bin additional fees (`addFeeBuyE6`, `addFeeSellE6`) with **no cap validation at all**. A pool admin can therefore charge traders more than the protocol owner intended to allow, breaking the admin-boundary invariant.

---

### Finding Description

The factory defines hard fee caps:

```
HARD_MAX_SPREAD_FEE_E6  = 200_000  (20%)
HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000 (100%)
``` [1](#0-0) 

`setPoolAdminFees` enforces these caps before updating the pool:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [2](#0-1) 

But `setPoolBinAdditionalFees` passes the values straight through with **no cap check**:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [3](#0-2) 

The pool's `setBinAdditionalFees` also performs no cap check — it only validates the bin index range: [4](#0-3) 

During every swap, the bin additional fee is added directly to the oracle-derived base fee and applied to the swap price:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [5](#0-4) 

The same uncapped path exists at pool creation time: `_unpackAndValidateBinStates` validates only bin lengths and distances, never `buyFee`/`sellFee` values: [6](#0-5) 

---

### Impact Explanation

The `addFeeBuyE6` / `addFeeSellE6` fields are `uint16`, so the pool admin can set them up to **65 535** (≈ 6.55 % in E6 units). This fee is **additive** to both the oracle spread (`baseFeeX64`) and the LP spread fee (`spreadFeeE6`). Because it is applied to the swap price rather than to the LP fee pool, it directly widens the bid/ask spread seen by traders, causing them to receive less output (or pay more input) than the protocol owner's caps were designed to allow. The protocol owner has no mechanism to clamp or override per-bin additional fees after the fact without removing the pool admin entirely.

---

### Likelihood Explanation

Any pool admin — a role that is semi-trusted only within caps — can call `setPoolBinAdditionalFees` at any time with no timelock and no cap. The trigger is a single transaction by the pool admin. The protocol owner's `setFeeCaps` call has no effect on this path.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` (and in `_unpackAndValidateBinStates` at pool creation) analogous to the check in `setPoolAdminFees`. For example, introduce a `maxAdminBinAdditionalFeeE6` constant or factory state variable and enforce:

```solidity
if (addFeeBuyE6 > maxAdminBinAdditionalFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminBinAdditionalFeeE6) revert AdminFeeTooHigh();
```

in `MetricOmmPoolFactory.setPoolBinAdditionalFees` before forwarding to the pool.

---

### Proof of Concept

1. Protocol owner deploys factory with `maxAdminSpreadFeeE6 = 50_000` (5 %).
2. Pool admin calls `setPoolAdminFees(pool, 50_000, 0)` — accepted (at cap).
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` — **no revert**.
4. A trader swaps through bin 0. The effective buy fee applied to the price is `baseFeeX64 + 65_535 * ONE_X64 / 1e6`, i.e. the oracle spread plus an extra ≈ 6.55 % — well above the 5 % cap the protocol owner set.
5. The trader receives fewer tokens than the protocol-owner-enforced cap would permit, with the excess accruing to the pool (benefiting LPs or the admin indirectly), and the protocol owner has no on-chain recourse short of replacing the pool admin.

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
