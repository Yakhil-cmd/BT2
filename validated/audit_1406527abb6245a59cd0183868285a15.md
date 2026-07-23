### Title
Missing Upper-Bound Check on Bin Additional Fees Allows Pool Admin to Exceed Protocol Fee Caps — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolBinAdditionalFees` in `MetricOmmPoolFactory` forwards `addFeeBuyE6` and `addFeeSellE6` directly to the pool with no factory-level cap check. Every other admin-settable fee parameter (`adminSpreadFeeE6`, `adminNotionalFeeE8`) is bounded by a factory-enforced maximum, but the bin-level additional fees are bounded only by the `uint16` type (`max = 65 535`, i.e. 6.5535 % in E6 units). The factory owner has no mechanism to constrain these values, so a pool admin can push the effective per-bin fee above the protocol's intended ceiling.

---

### Finding Description

The factory enforces hard caps on every fee dimension it controls:

```
HARD_MAX_SPREAD_FEE_E6   = 200_000   // 20 %
HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000 //  1 %
``` [1](#0-0) 

`setPoolAdminFees` enforces those caps before writing:

```solidity
if (newAdminSpreadFeeE6  > maxAdminSpreadFeeE6)  revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [2](#0-1) 

`setPoolBinAdditionalFees`, however, performs **no cap check** — it passes the caller-supplied values straight through to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [3](#0-2) 

The pool's `setBinAdditionalFees` likewise applies no bound:

```solidity
s.addFeeBuyE6  = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [4](#0-3) 

The same gap exists at pool creation: `_unpackAndValidateBinStates` validates bin length and distance but never checks `buyFee`/`sellFee`: [5](#0-4) 

At swap time the bin additional fee is **added on top of** the oracle spread fee:

```solidity
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
``` [6](#0-5) 

---

### Impact Explanation

`uint16` caps `addFeeBuyE6` / `addFeeSellE6` at **65 535** (6.5535 % in E6 units). Because this fee is additive to the spread fee (capped at 20 %), the effective per-bin fee ceiling becomes **≈ 26.5 %**, well above the protocol's intended 20 % hard limit. Users swapping through the affected bin pay the excess silently; the factory owner has no `maxAdminBinAdditionalFeeE6` knob to prevent it. The pool admin can apply this to every bin simultaneously, making the pool economically unusable for traders while still appearing registered and valid.

---

### Likelihood Explanation

The pool admin is explicitly semi-trusted "only inside caps and timelocks." Because no cap exists for bin additional fees, any pool admin — including one acting adversarially or one whose key is compromised — can set `addFeeBuyE6 = addFeeSellE6 = 65535` on all bins with a single transaction per bin, with no timelock and no factory-owner veto.

---

### Recommendation

1. Add a `maxAdminBinAdditionalFeeE6` state variable (or reuse `maxAdminSpreadFeeE6`) in `MetricOmmPoolFactory`.
2. Enforce it in `setPoolBinAdditionalFees`:
   ```solidity
   if (addFeeBuyE6  > maxAdminBinAdditionalFeeE6) revert AdminFeeTooHigh();
   if (addFeeSellE6 > maxAdminBinAdditionalFeeE6) revert AdminFeeTooHigh();
   ```
3. Apply the same check inside `_unpackAndValidateBinStates` during pool creation.

---

### Proof of Concept

```solidity
// Pool admin sets max bin additional fees on bin 0
factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);
// addFeeBuyE6 = 65535 → 6.5535 % additional fee
// Combined with max adminSpreadFeeE6 = 200_000 (20 %):
// effective buy fee ≈ 26.5 % — exceeds the 20 % hard cap
// No revert; factory owner has no mechanism to block this.
```

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

**File:** metric-core/contracts/MetricOmmPool.sol (L471-472)
```text
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
```

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```
