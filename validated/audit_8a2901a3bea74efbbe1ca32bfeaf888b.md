### Title
Accrued Admin Fees Are Not Collected Before `setPoolAdminFeeDestination` Changes the Destination — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first flushing accrued fees to the old destination. Every other fee-configuration mutator in the factory (`setPoolAdminFees`, `setPoolProtocolFee`) calls `collectFees` with the **old** destination before writing new state. `setPoolAdminFeeDestination` skips this step, so all fees that accrued while the old destination was active are silently redirected to the new destination on the next `collectPoolFees` call.

### Finding Description

`setPoolAdminFees` and `setPoolProtocolFee` both follow the same safe pattern:

1. Read the current `PoolFeeConfig` and `poolAdminFeeDestination`.
2. Call `pool.collectFees(…, poolAdminFeeDestination[pool])` — draining accrued fees to the **current** destination.
3. Write the new configuration. [1](#0-0) 

`setPoolAdminFeeDestination` omits step 2 entirely:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;          // ← no collectFees first
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
``` [2](#0-1) 

After this call, `poolAdminFeeDestination[pool]` points to the new address. The next invocation of `collectPoolFees` (or any fee-changing call) passes the **new** destination to `pool.collectFees`, which transfers both the accumulated notional-fee balances (`notionalFeeToken0Scaled`, `notionalFeeToken1Scaled`) and the spread-fee surplus to the new address. [3](#0-2) 

The two fee streams that are misdirected:

- **Notional fees** — stored on-chain in `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`; they are zeroed only inside `collectFees`.
- **Spread fees** — computed as `balance - binTotals - notionalFees` at collection time; they represent all swap spread revenue since the last collection. [4](#0-3) 

### Impact Explanation

All admin-share fees that accrued under the old destination are permanently redirected to the new destination. If `poolAdminFeeDestination` is a revenue-sharing contract, a DAO treasury, or any address distinct from the pool admin's own wallet, the beneficiaries of the old destination lose their owed fees with no recourse. The loss scales with the volume traded and the time elapsed since the last `collectPoolFees` call.

### Likelihood Explanation

The pool admin is a semi-trusted role that legitimately calls `setPoolAdminFeeDestination` during normal operations (e.g., rotating a treasury address). No special precondition beyond being the pool admin is required. The inconsistency with `setPoolAdminFees` and `setPoolProtocolFee` — both of which collect first — makes an accidental or deliberate omission plausible.

### Recommendation

Mirror the collect-before-update pattern used by every other fee-configuration mutator:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Flush accrued fees to the OLD destination before switching.
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool).collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]   // old destination
    );

    poolAdminFeeDestination[pool] = newAdminFeeDestination;
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

### Proof of Concept

1. Pool is created; `poolAdminFeeDestination[pool] = addressA`.
2. Swaps occur; `notionalFeeToken0Scaled` accumulates 1 000 USDC-equivalent; spread surplus also grows.
3. Pool admin calls `setPoolAdminFeeDestination(pool, addressB)` — no fees collected.
4. Anyone calls `collectPoolFees(pool)`.
5. `collectFees` is invoked with `adminFeeDestination_ = addressB`; all 1 000 USDC-equivalent of admin fees are transferred to `addressB`.
6. `addressA` receives nothing despite being the rightful destination for the entire accrual period. [5](#0-4)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L379-389)
```text
  function collectPoolFees(address pool) external override nonReentrant {
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L417-425)
```text
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L438-447)
```text
  function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L382-433)
```text
    uint256 notionalFee0AmountScaled = notionalFeeToken0Scaled;
    uint256 notionalFee1AmountScaled = notionalFeeToken1Scaled;

    uint256 surplus0Scaled =
      balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
    uint256 surplus1Scaled =
      balance1() * TOKEN_1_SCALE_MULTIPLIER - uint256(binTotals.scaledToken1) - notionalFee1AmountScaled;

    unchecked {
      uint256 spreadFee0ToAdminScaled = spreadSumE6 == 0 ? 0 : (surplus0Scaled * adminSpreadFeeE6_) / spreadSumE6;
      uint256 spreadFee1ToAdminScaled = spreadSumE6 == 0 ? 0 : (surplus1Scaled * adminSpreadFeeE6_) / spreadSumE6;

      uint256 spreadFee0ToProtocolScaled = spreadSumE6 == 0 ? 0 : (surplus0Scaled * protocolSpreadFeeE6_) / spreadSumE6;
      uint256 spreadFee1ToProtocolScaled = spreadSumE6 == 0 ? 0 : (surplus1Scaled * protocolSpreadFeeE6_) / spreadSumE6;

      uint256 notionalFee0ToAdminScaled =
        notionalSumE8 == 0 ? 0 : (notionalFee0AmountScaled * adminNotionalFeeE8_) / notionalSumE8;
      uint256 notionalFee1ToAdminScaled =
        notionalSumE8 == 0 ? 0 : (notionalFee1AmountScaled * adminNotionalFeeE8_) / notionalSumE8;

      uint256 notionalFee0ToProtocolScaled = notionalFee0AmountScaled - notionalFee0ToAdminScaled;
      uint256 notionalFee1ToProtocolScaled = notionalFee1AmountScaled - notionalFee1ToAdminScaled;

      uint256 totalFee0ToAdminScaled = spreadFee0ToAdminScaled + notionalFee0ToAdminScaled;
      uint256 totalFee1ToAdminScaled = spreadFee1ToAdminScaled + notionalFee1ToAdminScaled;

      uint256 totalFee0ToProtocolScaled = spreadFee0ToProtocolScaled + notionalFee0ToProtocolScaled;
      uint256 totalFee1ToProtocolScaled = spreadFee1ToProtocolScaled + notionalFee1ToProtocolScaled;

      (uint256 totalFee0ToAdmin, uint256 totalFee1ToAdmin) =
        deltasScaledToExternal(totalFee0ToAdminScaled, totalFee1ToAdminScaled, Math.Rounding.Floor);
      (uint256 totalFee0ToProtocol, uint256 totalFee1ToProtocol) =
        deltasScaledToExternal(totalFee0ToProtocolScaled, totalFee1ToProtocolScaled, Math.Rounding.Floor);

      if (totalFee0ToAdmin > 0) {
        transferToken0(adminFeeDestination_, totalFee0ToAdmin);
      }
      if (totalFee1ToAdmin > 0) {
        transferToken1(adminFeeDestination_, totalFee1ToAdmin);
      }
      if (totalFee0ToProtocol > 0) {
        transferToken0(FACTORY, totalFee0ToProtocol);
      }
      if (totalFee1ToProtocol > 0) {
        transferToken1(FACTORY, totalFee1ToProtocol);
      }

      notionalFeeToken0Scaled = 0;
      notionalFeeToken1Scaled = 0;

      emit ProtocolFeesCollected(totalFee0ToProtocol, totalFee1ToProtocol, totalFee0ToAdmin, totalFee1ToAdmin);
    }
```
