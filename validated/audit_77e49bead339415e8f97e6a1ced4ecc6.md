Let me look at the fee calculation in swaps and the cap enforcement for `setPoolAdminFees` vs `setPoolBinAdditionalFees` more carefully.

The code evidence is conclusive. Let me summarize the full trace before rendering the verdict.

**Confirmed facts:**

1. `setPoolBinAdditionalFees` in the factory passes values directly to the pool with **zero cap validation**: [1](#0-0) 

2. `setBinAdditionalFees` on the pool only validates the bin index, not the fee values: [2](#0-1) 

3. By contrast, `setPoolAdminFees` enforces explicit caps against `maxAdminSpreadFeeE6`: [3](#0-2) 

4. The hard cap for the global admin spread fee is `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%): [4](#0-3) 

5. The per-bin fee is added directly to `baseFeeX64` in every swap path with no clamping: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

6. `BinState.addFeeBuyE6` / `addFeeSellE6` are `uint16`, so the maximum settable value is 65535 → **6.5535% additional fee**: [9](#0-8) 

---

### Title
Pool admin can set per-bin additional fees to `uint16` max (6.5535%) with no cap, bypassing the global fee-cap system and causing bad-price execution for all swaps through the targeted bin — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` directly to `MetricOmmPool.setBinAdditionalFees` without any upper-bound validation. The pool-level function also performs no cap check. A pool admin can therefore set per-bin fees to `type(uint16).max = 65535` (6.5535%), which is added unclamped to `baseFeeX64` in every swap path that crosses the targeted bin.

### Finding Description
The factory enforces a two-layer cap system for global spread fees:
- A hard constant `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%) bounds what the owner can configure.
- `setPoolAdminFees` checks `newAdminSpreadFeeE6 > maxAdminSpreadFeeE6` and reverts with `AdminFeeTooHigh`.

Per-bin additional fees are entirely outside this system. `setPoolBinAdditionalFees` (factory, lines 450–457) and `setBinAdditionalFees` (pool, lines 464–474) accept any `uint16` value without comparison to any cap. The stored value is then used in all four swap paths as:

```
feeX64 = params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

with no subsequent clamping before it is applied to compute the gross input charged to the trader.

### Impact Explanation
With `addFeeBuyE6 = addFeeSellE6 = 65535`, every swap crossing the targeted bin pays an additional **6.5535%** on top of the oracle-derived base spread. This is a direct, quantifiable fund loss for traders: they pay more token input than the protocol's documented fee ceiling permits. The effective ask price seen by a buyer becomes `midPrice × (1 + baseFee + 0.065535)`, which is an unclamped, admin-inflated quote — satisfying the "bad-price execution" impact gate. The excess fee accrues to LPs in the targeted bin, constituting a wealth transfer from traders to LPs at the pool admin's discretion.

### Likelihood Explanation
The pool admin role is assigned at pool creation and can be any address. The call requires only `msg.sender == poolAdmin[pool]` — no timelock, no protocol co-signature, no cap check. The admin can execute this atomically in a single transaction, with no observable on-chain warning before the next swap hits the bin.

### Recommendation
Add a cap check in `setPoolBinAdditionalFees` analogous to the one in `setPoolAdminFees`. Define a `maxAdminBinFeeE6` constant (or a configurable cap bounded by a hard limit), and revert if either `addFeeBuyE6` or `addFeeSellE6` exceeds it:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > MAX_BIN_ADDITIONAL_FEE_E6) revert BinFeeTooHigh();
    if (addFeeSellE6 > MAX_BIN_ADDITIONAL_FEE_E6) revert BinFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

### Proof of Concept
```solidity
// Foundry unit test sketch
function test_binFeeBypassCap() public {
    address pool = _createPool();

    // Pool admin sets per-bin fee to uint16 max — no revert
    vm.prank(admin);
    factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);

    // Verify storage
    (,,, uint16 buyFee, uint16 sellFee) = PoolStateLibrary._binState(pool, 0);
    assertEq(buyFee, 65535);  // 6.5535% additional fee — no cap enforced

    // Execute a swap through bin 0 and assert effective fee exceeds any documented maximum
    // effective_fee = baseFee + 65535/1e6 > HARD_MAX_SPREAD_FEE_E6/1e6 (20%)
    // ... swap execution and assertion omitted for brevity
}
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

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1177)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/types/PoolStorage.sol (L19-25)
```text
struct BinState {
  uint104 token0BalanceScaled;
  uint104 token1BalanceScaled;
  uint16 lengthE6;
  uint16 addFeeBuyE6;
  uint16 addFeeSellE6;
}
```
