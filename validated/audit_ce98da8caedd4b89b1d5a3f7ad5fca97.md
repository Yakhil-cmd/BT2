### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Governance Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

The factory owner sets `maxAdminSpreadFeeE6` to bound the pool admin's spread-fee authority. `setPoolAdminFees` correctly enforces this cap. However, `setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` directly to the pool's `setBinAdditionalFees` with **no check against `maxAdminSpreadFeeE6`**, allowing the pool admin to impose per-bin additional spread fees up to `uint16.max` (65 535 = 6.5535 % in E6) on any bin, regardless of what the governance cap permits.

---

### Finding Description

`setPoolAdminFees` enforces the cap:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` performs **no such check**:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees` also performs no cap check — it only validates the bin index:

```solidity
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

These per-bin fees are then added directly to the effective buy/sell fee used in every swap through that bin:

```solidity
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [4](#0-3) 

The same uncapped values are applied inside every swap iteration:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
``` [5](#0-4) 

The hard cap on the base admin spread fee is `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %): [6](#0-5) 

But per-bin additional fees are only constrained by the `uint16` type (max 65 535 = 6.5535 %), with **no governance-controlled cap at all**.

---

### Impact Explanation

The factory owner's `maxAdminSpreadFeeE6` is the governance boundary on pool-admin fee authority. A pool admin can silently circumvent it:

- Factory owner sets `maxAdminSpreadFeeE6 = 500` (0.05 % max admin spread).
- Pool admin calls `setPoolAdminFees(pool, 500, 0)` — within cap, passes.
- Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — no revert; per-bin fee is now 6.5535 %.
- Every swap routed through bin 0 pays 0.05 % + 6.5535 % = 6.6035 % effective spread, 132× the governance-intended ceiling.

The excess fee is extracted from traders immediately on the next swap, with no timelock and no mechanism for users to detect the change before execution (the `BinAdditionalFeesUpdated` event is emitted on-chain but there is no front-end slippage guard against per-bin fee spikes). The pool admin can also set the fee back to 0 after draining, making the attack transient and hard to attribute.

---

### Likelihood Explanation

The pool admin is a semi-trusted role explicitly scoped to operate "only inside caps and timelocks." The bypass requires a single permissioned call with no preconditions beyond holding the pool admin role. Any pool admin — including one who accepted the role after a legitimate transfer — can execute it. The factory owner has no on-chain mechanism to prevent or detect it before funds are lost.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` against `maxAdminSpreadFeeE6` (or introduce a dedicated `maxAdminBinAdditionalFeeE6` governance variable):

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

1. Factory owner deploys factory; `maxAdminSpreadFeeE6 = 500` (0.05 %).
2. Pool is created with `adminSpreadFeeE6 = 500`.
3. Pool admin calls:
   ```solidity
   factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);
   ```
   No revert. `_binStates[0].addFeeBuyE6 = 65535`, `addFeeSellE6 = 65535`.
4. Next swap through bin 0 applies effective fee:
   ```
   baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)
   ```
   which is `baseFeeX64 + 6.5535 %` — far above the 0.05 % governance ceiling.
5. Excess fee accrues as spread surplus in the pool, collectible by the pool admin via `collectPoolFees`. [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```
