### Title
Pool Admin Can Set Uncapped Per-Bin Additional Fees via `setPoolBinAdditionalFees`, Bypassing the Factory Fee Cap System — (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards per-bin additional fees to the pool with **no cap validation**, while every other admin fee setter enforces `maxAdminSpreadFeeE6` / `maxAdminNotionalFeeE8`. A pool admin can set `addFeeBuyE6` or `addFeeSellE6` to the full `uint16` maximum (65 535 = 6.5535 % in E6) on any bin, stacking that uncapped surcharge on top of the already-capped global spread fee and causing traders to pay effective fees that exceed the protocol's documented 20 % hard ceiling.

### Finding Description

The factory enforces fee caps on every other admin-controlled fee path:

```solidity
// setPoolAdminFees — MetricOmmPoolFactory.sol:414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

But `setPoolBinAdditionalFees` passes the caller-supplied values straight through with **no bounds check**:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees` only validates the bin index, not the fee values:

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

During every swap step the per-bin fee is **added** to the oracle-derived base spread fee:

```solidity
// MetricOmmPool.sol:540-541
uint256 buyFeeX64  = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6,  ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [4](#0-3) 

The same additive pattern appears in every swap direction (`buyToken1InBinSpecifiedIn`, `buyToken1InBinSpecifiedOut`, etc.): [5](#0-4) 

The factory hard-caps the global spread fee at `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %): [6](#0-5) 

`uint16` allows values up to 65 535, which in E6 units equals **6.5535 %**. With the global spread fee already at its 20 % ceiling, a pool admin can push the effective per-bin fee to **26.5535 %** — 6.5535 percentage points above the protocol's documented hard limit — with a single, immediately-effective, no-timelock call.

### Impact Explanation

Every swap routed through the affected bin pays the uncapped surcharge. The extra fee is extracted from the trader's input token and credited to the pool's LP surplus, from which it is later collected by the admin fee destination. This is a direct, quantifiable loss of trader principal: up to 6.5535 % of notional per swap, per bin, with no on-chain guard preventing it. The pool admin can apply the maximum value to all bins simultaneously, making the pool effectively unusable at fair prices.

This satisfies the allowed impact gate: **admin-boundary break** (pool admin exceeds the factory-enforced fee cap) and **bad-price execution** (the effective ask/bid quote delivered to the swap math is unclamped beyond the protocol ceiling).

### Likelihood Explanation

The pool admin is explicitly semi-trusted "only inside caps." The call requires only `onlyPoolAdmin(pool)` — no timelock, no protocol-owner co-signature, no delay. Any pool whose admin key is compromised, or any pool whose admin acts adversarially, can exploit this immediately. The asymmetry with `setPoolAdminFees` (which does check caps) makes this a reachable, single-step trigger.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool, mirroring the pattern in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(
    address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6
) external override nonReentrant onlyPoolAdmin(pool) {
    // addFeeBuyE6 and addFeeSellE6 are E6; maxAdminSpreadFeeE6 is uint24 (E6).
    // Cast is safe: uint16 max (65535) < uint24 max.
    if (uint24(addFeeBuyE6)  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (uint24(addFeeSellE6) > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap so the protocol can tune per-bin limits independently of the global spread cap.

### Proof of Concept

1. Factory is deployed; `maxAdminSpreadFeeE6 = 200_000` (20 %).
2. Pool is created with `adminSpreadFeeE6 = 200_000` (global spread at hard cap).
3. Pool admin calls:
   ```solidity
   factory.setPoolBinAdditionalFees(pool, 0, 65_535, 65_535);
   ```
   No revert — the call succeeds.
4. A trader calls `exactInputSingle` routing through bin 0. The swap math computes:
   ```
   buyFeeX64 = baseFeeX64 + mulDiv(65_535, ONE_X64, 1e6)
             = (20% oracle spread) + 6.5535%
             = ~26.5535% effective fee
   ```
5. The trader receives ~6.5535 % fewer output tokens than the oracle price warrants, with the surplus accruing to the pool's LP balance and ultimately swept to `adminFeeDestination` — a direct loss of principal exceeding the protocol's 20 % hard ceiling. [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1086-1092)
```text
            curPosInBinCache,
            state,
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
            lowerPriceX64,
            upperPriceX64,
            params.priceLimitX64,
            spreadFeeE6
```
