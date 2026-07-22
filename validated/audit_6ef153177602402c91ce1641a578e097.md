### Title
Admin Fee Destination Change Without Prior Fee Settlement Redirects All Accrued Fees to New Destination — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first calling `collectFees` to settle outstanding fees at the old destination. Every other fee-parameter mutator in the factory (`setPoolAdminFees`, `setPoolProtocolFee`) explicitly collects fees before changing rates. The omission here means all previously accrued spread surplus and notional fees are silently redirected to the new destination on the next `collectPoolFees` call, depriving the old destination of fees it earned.

---

### Finding Description

`setPoolAdminFees` and `setPoolProtocolFee` both follow the same safe pattern: collect at old rates/destination first, then update state. [1](#0-0) [2](#0-1) 

`setPoolAdminFeeDestination` performs no such settlement: [3](#0-2) 

After the destination is overwritten, `collectPoolFees` passes the **new** `poolAdminFeeDestination[pool]` directly to `collectFees`: [4](#0-3) 

Inside `collectFees`, the admin share of both fee types is transferred to whatever `adminFeeDestination_` is at call time:

- **Spread fees** (surplus = pool balance minus LP claims minus notional reserve) are split proportionally and sent to `adminFeeDestination_`: [5](#0-4) 

- **Notional fees** (`notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`) are also split and sent to `adminFeeDestination_`, then zeroed: [6](#0-5) 

Neither fee type is checkpointed per-destination. All value accumulated while the old destination was active is swept to the new destination on the next collection.

---

### Impact Explanation

The old `adminFeeDestination` (e.g., a DAO treasury, a previous partner address, or any address the admin set at pool creation) loses 100% of its accrued admin fees — both spread surplus and notional — with no recourse. The new destination receives fees it never earned. This is a direct, quantifiable loss of protocol-fee assets already sitting in the pool, proportional to trading volume since the last `collectPoolFees` call.

---

### Likelihood Explanation

- `setPoolAdminFeeDestination` has no timelock, no cap check, and no guard beyond `onlyPoolAdmin`.
- `collectPoolFees` is permissionless — anyone can trigger it after the destination is changed.
- The pool admin is explicitly classified as semi-trusted "only inside caps and timelocks." This operation has neither, and the task scope explicitly flags "fee collection destinations" as an admin-boundary bypass surface.
- The attack requires only two transactions from the pool admin key, executable in the same block.

---

### Recommendation

Collect outstanding fees at the old destination before updating `poolAdminFeeDestination`, mirroring the pattern already used in `setPoolAdminFees` and `setPoolProtocolFee`:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Settle fees owed to the current destination before rotating.
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

---

### Proof of Concept

1. Pool is created; `adminFeeDestination` = `Treasury` (a DAO multisig the admin does not fully control).
2. Swaps occur over time; spread surplus and `notionalFeeToken0/1Scaled` accumulate on the pool.
3. Pool admin calls `setPoolAdminFeeDestination(pool, adminOwnWallet)`. No fees are collected; `poolAdminFeeDestination[pool]` is now `adminOwnWallet`.
4. Pool admin (or any keeper) calls `collectPoolFees(pool)`. The factory passes `adminOwnWallet` as `adminFeeDestination_` to `collectFees`.
5. All accrued admin spread and notional fees are transferred to `adminOwnWallet`. `Treasury` receives nothing.
6. `Treasury` has permanently lost its share of all fees earned since the last collection.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L327-335)
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

**File:** metric-core/contracts/MetricOmmPool.sol (L385-430)
```text
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
```
