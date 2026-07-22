The code path is clear. Let me verify the swap math integration and the cap enforcement for the global admin fee path to confirm the asymmetry.

The vulnerability is confirmed. Here is the complete analysis:

---

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` directly to the pool with no cap check, while the parallel admin fee setter `setPoolAdminFees` enforces `maxAdminSpreadFeeE6`. A pool admin can set per-bin additional fees to `uint16` max (65535 = 6.5535%) on every bin, pushing the effective per-swap fee above the factory-enforced ceiling and extracting excess fees from traders.

### Finding Description

The factory enforces a hard ceiling on admin spread fees through `setPoolAdminFees`:

```solidity
// MetricOmmPoolFactory.sol:414
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

The parallel pool-admin entrypoint `setPoolBinAdditionalFees` has **no equivalent check**:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`MetricOmmPool.setBinAdditionalFees` only validates the bin index, not the fee values:

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

During every swap, the bin additional fee is added on top of the base fee:

```solidity
// MetricOmmPool.sol:910
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
``` [4](#0-3) 

The same additive pattern applies to all four swap directions (buy/sell × specifiedIn/specifiedOut). [5](#0-4) 

The hard cap `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%) is the absolute ceiling the protocol intends to enforce: [6](#0-5) 

`maxAdminSpreadFeeE6` defaults to this hard cap at construction: [7](#0-6) 

A pool admin can set `addFeeBuyE6 = 65535` on every bin. Since `uint16` max = 65535 and the E6 denominator is 1,000,000, this adds **6.5535%** per bin on top of whatever global spread fee is already active. If the global admin spread fee is already at `maxAdminSpreadFeeE6`, the total effective fee per swap exceeds the hard cap.

### Impact Explanation

- **Direct fund loss for traders**: every swap through an affected bin pays an additional fee up to 6.5535% with no factory-level ceiling, beyond the cap the protocol guarantees.
- **Admin-boundary break**: the pool admin exceeds the `maxAdminSpreadFeeE6` cap that the factory is supposed to enforce, violating the invariant that admin fee extraction is bounded.
- The excess fee accrues inside the pool's fee accumulators and is collected by the admin via `collectPoolFees`, constituting real token extraction from traders.

### Likelihood Explanation

The pool admin is a semi-trusted role. The protocol's cap mechanism (`maxAdminSpreadFeeE6`) is the only on-chain guarantee traders have that admin fee extraction is bounded. A malicious or compromised pool admin can exploit this gap immediately after pool creation with a single transaction, with no timelock or protocol-owner approval required.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap that the factory owner can configure independently.

### Proof of Concept

```solidity
// Foundry test sketch
function test_binAdditionalFee_bypassesCap() public {
    address pool = _createPool(); // maxAdminSpreadFeeE6 = 200_000 (20%)

    // Pool admin sets bin additional fee to uint16 max — no revert
    vm.prank(admin);
    factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);

    // Verify BinState is corrupted with uncapped value
    (,,, uint16 buyFee, uint16 sellFee) = PoolStateLibrary._binState(pool, 0);
    assertEq(buyFee, 65535);  // 6.5535% — no factory cap enforced
    assertEq(sellFee, 65535);

    // A swap through bin 0 now pays baseFee + 6.5535% additional,
    // exceeding the maxAdminSpreadFeeE6 boundary the protocol guarantees.
}
```

The `setPoolAdminFees` path reverts with `AdminFeeTooHigh` at 200,001 E6, but `setPoolBinAdditionalFees` accepts 65535 silently, confirming the asymmetric enforcement. [2](#0-1) [8](#0-7)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L105-108)
```text
    maxProtocolSpreadFeeE6 = HARD_MAX_SPREAD_FEE_E6;
    maxAdminSpreadFeeE6 = HARD_MAX_SPREAD_FEE_E6;
    maxProtocolNotionalFeeE8 = HARD_MAX_NOTIONAL_FEE_E8;
    maxAdminNotionalFeeE8 = HARD_MAX_NOTIONAL_FEE_E8;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L999-999)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```
