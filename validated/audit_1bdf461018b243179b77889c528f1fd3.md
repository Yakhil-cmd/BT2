### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6`/`addFeeSellE6` directly to the pool with no validation against `maxAdminSpreadFeeE6`. The parallel path `setPoolAdminFees` enforces the cap, but the per-bin path does not. A pool admin can therefore set per-bin additional fees up to `uint16` max (65,535 E6 ≈ 6.55%) on any bin, including boundary bins, even when the factory owner has lowered `maxAdminSpreadFeeE6` below that value.

---

### Finding Description

`setPoolAdminFees` enforces the cap:

```solidity
// MetricOmmPoolFactory.sol:414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` has no such check — it passes the caller-supplied values straight through:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool-level `setBinAdditionalFees` only validates the bin index range, not the fee values:

```solidity
// MetricOmmPool.sol:469-473
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

These stored values are consumed directly in every swap path. For the `zeroForOne` (buy-token1) direction:

```solidity
// MetricOmmPool.sol:999
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
``` [4](#0-3) 

And for the `oneForZero` (buy-token0) direction:

```solidity
// MetricOmmPool.sol:1088 / 1177
params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
``` [5](#0-4) 

The `uint16` type bounds the per-bin fee to at most 65,535 E6 (≈ 6.55%). The hard cap `HARD_MAX_SPREAD_FEE_E6 = 200,000` (20%) is above this, so at the factory's default configuration there is no bypass. However, the factory owner can lower `maxAdminSpreadFeeE6` to any value down to 0 via `setFeeCaps`:

```solidity
// MetricOmmPoolFactory.sol:284-315
function setFeeCaps(...) external override onlyOwner { ... }
``` [6](#0-5) 

Once `maxAdminSpreadFeeE6` is set below 65,535 (e.g., to 1,000 = 0.1%), the pool admin can still write `addFeeBuyE6 = 65535` or `addFeeSellE6 = 65535` on any bin — including `LOWEST_BIN` and `HIGHEST_BIN` — bypassing the configured cap entirely.

---

### Impact Explanation

Traders who swap through a bin with an inflated per-bin additional fee pay a fee above the protocol-configured maximum. The excess fee accrues to LPs (it is part of the LP fee component in `SwapMath`), not to the admin directly, but the trader suffers direct principal loss above the cap. This is an admin-boundary break: the pool admin exceeds the cap set by the factory owner, violating the invariant that `maxAdminSpreadFeeE6` bounds all admin-controlled fees.

---

### Likelihood Explanation

Requires two conditions: (1) the factory owner has lowered `maxAdminSpreadFeeE6` below 65,535, and (2) the pool admin exploits the unchecked path. Condition (1) is a normal governance action. Condition (2) is available to any pool admin at any time with no timelock. The combination is plausible in a production deployment where the factory owner tightens fee caps to protect users.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

This mirrors the existing guard in `setPoolAdminFees` and closes the bypass.

---

### Proof of Concept

1. Factory owner calls `setFeeCaps(200_000, 1_000, 1_000_000, 1_000_000)` — lowering `maxAdminSpreadFeeE6` to 1,000 (0.1%).
2. Pool admin calls `setPoolBinAdditionalFees(pool, HIGHEST_BIN, 65535, 65535)` — no revert, values stored.
3. A trader performs a `zeroForOne` swap that reaches `HIGHEST_BIN`. The effective fee applied is `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` ≈ base + 6.55%, far above the 0.1% cap.
4. The trader pays ~65× the configured maximum additional fee, losing principal above Sherlock thresholds on any non-trivial swap size.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L284-315)
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

    if (spreadProtocolFeeE6 > newMaxProtocolSpreadFeeE6) {
      uint24 oldFeeE6 = spreadProtocolFeeE6;
      spreadProtocolFeeE6 = newMaxProtocolSpreadFeeE6;
      emit SpreadProtocolFeeDefaultUpdated(oldFeeE6, newMaxProtocolSpreadFeeE6);
    }
    if (protocolNotionalFeeE8 > newMaxProtocolNotionalFeeE8) {
      uint24 oldFeeE8 = protocolNotionalFeeE8;
      protocolNotionalFeeE8 = newMaxProtocolNotionalFeeE8;
      emit ProtocolNotionalFeeDefaultUpdated(oldFeeE8, newMaxProtocolNotionalFeeE8);
    }

    emit FeeCapsUpdated(
      newMaxProtocolSpreadFeeE6, newMaxAdminSpreadFeeE6, newMaxProtocolNotionalFeeE8, newMaxAdminNotionalFeeE8
    );
  }
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

**File:** metric-core/contracts/MetricOmmPool.sol (L999-999)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```
