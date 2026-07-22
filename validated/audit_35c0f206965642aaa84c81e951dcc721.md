The vulnerability is real. Here is the complete analysis:

---

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Unchecked `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` directly to the pool with no validation against `maxAdminSpreadFeeE6`, while the sibling function `setPoolAdminFees` explicitly enforces that cap. A pool admin can therefore write any `uint16` value (up to 65 535, i.e. ≈ 6.55 % in E6 units) into `BinState.addFeeBuyE6` / `addFeeSellE6` and those values are applied additively on every swap through the affected bin, causing traders to pay fees that exceed the factory-owner-imposed ceiling.

---

### Finding Description

`setPoolAdminFees` enforces the factory cap before touching any fee state:

```solidity
// MetricOmmPoolFactory.sol L414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees`, callable by the same pool-admin role, performs no such check and passes the caller-supplied values straight through:

```solidity
// MetricOmmPoolFactory.sol L450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`MetricOmmPool.setBinAdditionalFees` only validates the bin index, then writes the values unconditionally:

```solidity
// MetricOmmPool.sol L469-472
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

During every swap the per-bin fee is added directly on top of the oracle-derived base fee:

```solidity
// MetricOmmPool.sol L910
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) 

and for the sell direction:

```solidity
// MetricOmmPool.sol L1088
params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6)
``` [5](#0-4) 

`BinState.addFeeBuyE6` / `addFeeSellE6` are `uint16`, so the maximum settable value is 65 535 (≈ 6.5535 % in E6 units). With `maxAdminSpreadFeeE6 = 200 000` (20 %), the per-bin fee alone can reach 6.5535 % with zero factory-level resistance, and it stacks on top of whatever global spread fee is already active. [6](#0-5) 

---

### Impact Explanation

Every swap routed through the manipulated bin pays the uncapped additional fee. The excess fee is extracted from trader principal on each trade. Because the per-bin fee is applied inside the swap math before settlement, traders receive less output (or pay more input) than the factory-owner-sanctioned cap permits. This is a direct, per-swap loss of trader funds with no recovery path.

---

### Likelihood Explanation

The pool admin is a semi-trusted role that can act unilaterally and immediately — no timelock, no protocol co-signature. Any pool whose admin is adversarial (or compromised) can exploit this on any live pool at any time. The call requires no special conditions beyond holding the `poolAdmin[pool]` role.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` mirroring the one in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap so the factory owner can tune the per-bin ceiling independently.

---

### Proof of Concept

```solidity
// 1. Deploy pool with maxAdminSpreadFeeE6 = 200_000 (20 %)
address pool = factory.createPool(params);

// 2. Pool admin sets per-bin fee to uint16 max — no revert
vm.prank(admin);
factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);

// 3. Confirm BinState stores the uncapped value
(,,, uint16 buyFee, uint16 sellFee) = PoolStateLibrary._binState(pool, 0);
assertEq(buyFee,  65535); // 6.5535 % — exceeds no factory check
assertEq(sellFee, 65535);

// 4. Any subsequent swap through bin 0 pays baseFee + 6.5535 %
//    regardless of maxAdminSpreadFeeE6 = 200_000
```

### Citations

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

**File:** metric-core/contracts/MetricOmmPool.sol (L469-472)
```text
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
```

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
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
