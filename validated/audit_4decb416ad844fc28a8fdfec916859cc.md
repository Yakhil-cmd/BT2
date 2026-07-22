### Title
Pool Admin Can Set Uncapped Per-Bin Additional Fees, Bypassing `maxAdminSpreadFeeE6` Governance - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`setPoolBinAdditionalFees` in `MetricOmmPoolFactory` applies no cap validation on `addFeeBuyE6` / `addFeeSellE6`, while the analogous base-spread setter `setPoolAdminFees` enforces `maxAdminSpreadFeeE6`. A pool admin (semi-trusted only inside caps) can therefore set per-bin additional fees up to the `uint16` maximum (65 535 E6 ≈ 6.55 %) on any bin, bypassing the protocol's fee-cap governance and directly overcharging traders.

---

### Finding Description

The factory maintains a cap system for spread fees:

- `maxAdminSpreadFeeE6` (owner-controlled, hard-capped at `HARD_MAX_SPREAD_FEE_E6 = 200_000` = 20 %)
- `setPoolAdminFees` enforces this cap before writing to the pool [1](#0-0) 

However, `setPoolBinAdditionalFees` passes `addFeeBuyE6` / `addFeeSellE6` directly to the pool with **no cap check**: [2](#0-1) 

The pool-level `setBinAdditionalFees` only validates the bin index, not the fee magnitude: [3](#0-2) 

During every swap, the per-bin additional fee is added directly to the effective trading fee used in swap math: [4](#0-3) 

The same additive pattern appears in `getSellAndBuyPrices` and the data-provider lens: [5](#0-4) 

---

### Impact Explanation

A pool admin can call `setPoolBinAdditionalFees(pool, bin, 65535, 65535)` — the `uint16` maximum — setting an additional fee of ≈ 6.55 % on any bin. This is additive to the oracle-derived base fee, so the effective buy/sell fee for that bin becomes `baseFeeX64 + 6.55 %`. Traders swapping through that bin pay this inflated fee; the excess accrues to LPs (not the admin), but the trader suffers a direct, quantifiable loss of principal on every swap routed through the affected bin. If the owner has lowered `maxAdminSpreadFeeE6` to, say, 0.1 % (1 000 E6), the admin can still impose a 6.55 % per-bin fee — 65× the intended cap — on any bin at will.

This is an **admin-boundary break**: the pool admin exceeds the fee cap the protocol owner established, which is explicitly out-of-scope for semi-trusted admin power.

---

### Likelihood Explanation

The call requires only `poolAdmin[pool] == msg.sender`. Any pool admin can trigger this at any time with a single transaction. No timelock, no co-signer, no precondition beyond holding the admin role.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool, mirroring the pattern in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(
    address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6
) external override nonReentrant onlyPoolAdmin(pool) {
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap so the protocol owner can tune the per-bin ceiling independently.

---

### Proof of Concept

1. Factory owner sets `maxAdminSpreadFeeE6 = 1_000` (0.1 %) via `setFeeCaps`.
2. Pool admin calls:
   ```solidity
   factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);
   ```
   No revert — `setPoolBinAdditionalFees` performs no cap check.
3. `_binStates[0].addFeeBuyE6 = 65535` is now stored on the pool.
4. A trader swaps through bin 0. The effective fee applied is:
   ```
   currBinBuyFeeX64 = baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)
   ```
   The trader pays ≈ 6.55 % additional fee on top of the oracle spread — 65× the 0.1 % cap the owner intended.
5. The excess fee accrues to LPs; the trader receives fewer tokens than the protocol's fee-cap governance permits. [6](#0-5) [7](#0-6) [8](#0-7) [2](#0-1)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L284-299)
```text
  function setFeeCaps(
    uint24 newMaxProtocolSpreadFeeE6,
    uint24 newMaxAdminSpreadFeeE6,
    uint24 newMaxProtocolNotionalFeeE8,
    uint24 newMaxAdminNotionalFeeE8
  ) external override onlyOwner {
    if (
      newMaxProtocolSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6 || newMaxAdminSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6
        || newMaxProtocolNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8 || newMaxAdminNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8
    ) {
      revert FeeCapsExceedHardLimit();
    }
    maxProtocolSpreadFeeE6 = newMaxProtocolSpreadFeeE6;
    maxAdminSpreadFeeE6 = newMaxAdminSpreadFeeE6;
    maxProtocolNotionalFeeE8 = newMaxProtocolNotionalFeeE8;
    maxAdminNotionalFeeE8 = newMaxAdminNotionalFeeE8;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L910-911)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
            lowerPriceX64,
```
