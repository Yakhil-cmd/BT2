### Title
Pool Admin Bypasses Factory Fee Caps via Uncapped `setBinAdditionalFees` — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

The factory enforces explicit upper-bound caps on admin-controlled spread and notional fees (`maxAdminSpreadFeeE6`, `maxAdminNotionalFeeE8`). However, `setPoolBinAdditionalFees` passes pool-admin-supplied `addFeeBuyE6` / `addFeeSellE6` values directly to the pool with **no cap validation**, allowing the pool admin to charge up to 6.5535 % additional fee per bin on every swap, regardless of what the factory owner has set as the admin fee ceiling.

---

### Finding Description

The factory defines two hard-enforced admin fee caps: [1](#0-0) 

These caps are checked in every fee-setting path: [2](#0-1) 

However, the bin-level additional fee setter performs **no analogous cap check**: [3](#0-2) 

The pool-side handler likewise applies no bound: [4](#0-3) 

The values are `uint16`, so the implicit maximum is 65 535 (= 6.5535 % in E6 units). These fees are then added directly to the base fee used in every swap computation: [5](#0-4) 

---

### Impact Explanation

A pool admin can call `setPoolBinAdditionalFees` on every bin and set `addFeeBuyE6 = addFeeSellE6 = 65535`. Every subsequent swap through those bins pays up to 6.5535 % more than the oracle-derived price, with the excess accruing inside the bin (benefiting LPs the admin controls). This is a **direct, quantifiable loss of trader principal** on every swap, and it is reachable even when the factory owner has set `maxAdminSpreadFeeE6 = 0` specifically to prevent the admin from charging any additional spread.

---

### Likelihood Explanation

The pool admin is a **specific, named role** set at pool creation. Exploitation requires a malicious or compromised pool admin. However, the factory's cap system exists precisely because the admin is only *semi-trusted*; the bypass is unconditional once the admin decides to exploit it, requires no timelock, and can be applied to all bins in a single block. Any pool whose factory owner has tightened `maxAdminSpreadFeeE6` below 65 535 is silently exposed.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` analogous to the checks already present for spread and notional fees. Introduce a `maxAdminBinAdditionalFeeE6` state variable (owner-settable, hard-capped at `HARD_MAX_SPREAD_FEE_E6`) and revert if either `addFeeBuyE6` or `addFeeSellE6` exceeds it:

```solidity
if (addFeeBuyE6 > maxAdminBinAdditionalFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminBinAdditionalFeeE6) revert AdminFeeTooHigh();
```

---

### Proof of Concept

1. Factory owner deploys factory and sets `maxAdminSpreadFeeE6 = 0` (no admin spread fee allowed).
2. Pool is created with a pool admin address controlled by an attacker.
3. Attacker calls `factory.setPoolBinAdditionalFees(pool, bin, 65535, 65535)` for every bin — no revert occurs.
4. A trader calls `swap(…)`. Inside `_swapToken0ForToken1SpecifiedInput`, the effective fee becomes `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)`, i.e., the oracle spread plus 6.5535 %.
5. The trader receives 6.5535 % fewer tokens than the oracle price warrants; the surplus remains in the bin, claimable by the attacker's LP position. [6](#0-5) [7](#0-6)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-435)
```text
  function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();

    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );

    c.adminSpreadFeeE6 = newAdminSpreadFeeE6;
    c.adminNotionalFeeE8 = newAdminNotionalFeeE8;
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
    emit PoolAdminSpreadFeeUpdated(pool, newAdminSpreadFeeE6);
    emit PoolAdminNotionalFeeUpdated(pool, newAdminNotionalFeeE8);
  }
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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-548)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);

    uint256 askBeforeNotional = Math.mulDiv(marginalPriceX64, ONE_X64 + buyFeeX64, ONE_X64, Math.Rounding.Ceil);
    uint256 bidAfterSpread = Math.mulDiv(marginalPriceX64, ONE_X64, ONE_X64 + sellFeeX64, Math.Rounding.Floor);

    uint256 nf = notionalFeeE8;
    buyPriceX64 = Math.mulDiv(askBeforeNotional, 1e8, 1e8 - nf, Math.Rounding.Ceil).toUint128();
    sellPriceX64 = Math.mulDiv(bidAfterSpread, 1e8 - nf, 1e8, Math.Rounding.Floor).toUint128();
```

**File:** metric-core/contracts/MetricOmmPool.sol (L910-915)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
            lowerPriceX64,
            upperPriceX64,
            params.priceLimitX64,
            spreadFeeE6
          );
```
