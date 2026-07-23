### Title
`collectFees` Double-Counts Notional Fee Accumulator Against Spread-Fee Surplus, Draining LP Principal — (`metric-core/contracts/MetricOmmPool.sol`)

### Summary

When a pool has both a non-zero spread fee (`spreadFeeE6 > 0`) and a non-zero notional fee (`notionalFeeE8 > 0`) active simultaneously, the `collectFees` function in `MetricOmmPool.sol` over-allocates payouts. The notional fee accumulator (`notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`) is already embedded inside the pool's token surplus (pool balance minus LP-owned bin balances), yet `collectFees` distributes the **entire surplus** as spread-fee payouts and then distributes the notional accumulator **again** as a separate payout. The combined transfer exceeds the available surplus, causing the shortfall to be drawn from LP principal. The protocol's own test suite explicitly documents this over-allocation.

### Finding Description

**Root cause — surplus composition:**

When a swap executes with a notional fee, the fee is withheld from the trader's output and left in the pool. It is never credited to any bin balance, so it accumulates as part of the pool's token surplus:

```
surplus0Scaled = (pool.balanceOf(token0) × token0Mul) − Σ binState.token0BalanceScaled
```

The spread fee (protocol portion of the LP fee) is similarly withheld from bin balances and also accumulates in the same surplus. Therefore:

```
surplus0Scaled = spread_fee_surplus + notional_fee_surplus
```

**Root cause — collectFees math:**

`collectFees` receives the admin and protocol component rates and computes:

```solidity
uint256 spreadFee0ToAdminScaled    = (surplus0Scaled * adminSpreadFeeE6_)    / spreadSumE6;
uint256 spreadFee0ToProtocolScaled = (surplus0Scaled * protocolSpreadFeeE6_) / spreadSumE6;
```

Because `adminSpreadFeeE6_ + protocolSpreadFeeE6_ == spreadSumE6`, the two lines together pay out exactly `surplus0Scaled` — the **entire surplus**, including the notional portion.

Then, separately:

```solidity
uint256 notionalFee0ToAdminScaled    = (notionalFee0AmountScaled * adminNotionalFeeE8_)    / notionalSumE8;
uint256 notionalFee0ToProtocolScaled = notionalFee0AmountScaled − notionalFee0ToAdminScaled;
```

These lines pay out `notionalFee0AmountScaled` a **second time**.

Total attempted payout = `surplus0Scaled + notionalFee0AmountScaled > surplus0Scaled`.

The excess is drawn from LP principal because the pool's ERC-20 balance includes LP-deposited tokens.

**Protocol acknowledgement in test suite:**

The test `test_collectProtocolFees_math_overallocates_whenSpreadAndNotionalBothActive` explicitly asserts this invariant violation:

```solidity
assertGt(total0Attempted, surplus0Scaled, "token0 attempted payout exceeds computed surplus");
assertGt(total1Attempted, surplus1Scaled, "token1 attempted payout exceeds computed surplus");
``` [1](#0-0) 

**Permissionless trigger:**

`collectPoolFees` in the factory is callable by anyone with no access control:

```solidity
function collectPoolFees(address pool) external override nonReentrant {
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool).collectFees(...);
}
``` [2](#0-1) 

Any caller can drain LP principal from any pool that has both fee types enabled.

**Fee collection code (the double-count):** [3](#0-2) 

### Impact Explanation

When `collectPoolFees` is called on a pool with both `spreadFeeE6 > 0` and `notionalFeeE8 > 0`:

1. The full surplus (which already contains the notional accumulator) is transferred out as spread fees.
2. The notional accumulator is transferred out again.
3. The shortfall (`notionalFee0AmountScaled` + `notionalFee1AmountScaled` in scaled units) is drawn from LP-deposited principal.
4. LP redemptions (`removeLiquidity`) will fail or return less than owed, causing direct, permanent loss of LP principal.
5. The pool becomes insolvent: `Σ binState.tokenXBalanceScaled > pool.balanceOf(tokenX) × tokenXMul`.

This matches the **pool insolvency** and **direct loss of user principal** impact gates.

### Likelihood Explanation

- The trigger is **permissionless** — any EOA can call `MetricOmmPoolFactory.collectPoolFees(pool)`.
- The condition (both fee types active) is the **intended production configuration** for pools that charge both a spread fee and a notional fee; the factory's `createPool` path accepts both parameters simultaneously.
- No flash-loan or price manipulation is required; a single transaction suffices.
- The protocol's own test suite confirms the over-allocation occurs, meaning it is reproducible deterministically. [4](#0-3) 

### Recommendation

Exclude the notional fee accumulator from the base used for spread-fee payouts. The spread-fee surplus is only the portion of the surplus that is **not** already tracked by the notional accumulator:

```solidity
uint256 spreadSurplus0Scaled = surplus0Scaled > notionalFee0AmountScaled
    ? surplus0Scaled - notionalFee0AmountScaled
    : 0;

uint256 spreadFee0ToAdminScaled    = spreadSumE6 == 0 ? 0 : (spreadSurplus0Scaled * adminSpreadFeeE6_)    / spreadSumE6;
uint256 spreadFee0ToProtocolScaled = spreadSumE6 == 0 ? 0 : (spreadSurplus0Scaled * protocolSpreadFeeE6_) / spreadSumE6;
```

Apply the same correction for token1. This ensures the total payout never exceeds the available surplus.

### Proof of Concept

The existing test `test_collectProtocolFees_math_overallocates_whenSpreadAndNotionalBothActive` in `metric-core/test/MetricOmmPool.notionalFee.t.sol` is a direct PoC. It:

1. Deploys a pool with both `protocolSpreadFeeE6 = PROTOCOL_FEE` and `protocolNotionalFeeE8 = FEE_1_PCT_E8` active.
2. Executes several swaps to accumulate both fee types.
3. Computes the attempted payout using the same arithmetic as `collectFees`.
4. Asserts `total0Attempted > surplus0Scaled` and `total1Attempted > surplus1Scaled`. [5](#0-4) 

The over-allocation amount equals `notionalFee0AmountScaled` (token0) and `notionalFee1AmountScaled` (token1) — exactly the notional accumulator values — which are transferred from LP principal rather than from fee surplus.

### Citations

**File:** metric-core/test/MetricOmmPool.notionalFee.t.sol (L211-266)
```text
  function test_collectProtocolFees_math_overallocates_whenSpreadAndNotionalBothActive() public {
    pool.collectFees(PROTOCOL_FEE, ADMIN_FEE, 0, 0, adminFeeDestination);
    poolFeeConfig[address(pool)] = PoolFeeConfig({
      protocolSpreadFeeE6: PROTOCOL_FEE,
      adminSpreadFeeE6: ADMIN_FEE,
      protocolNotionalFeeE8: FEE_1_PCT_E8,
      adminNotionalFeeE8: 0
    });
    pool.setPoolFees(PROTOCOL_FEE + ADMIN_FEE, FEE_1_PCT_E8);

    _addLiquidity(1, -5, 4, 100_000, 0);
    for (uint256 i = 0; i < 8; i++) {
      _swap(0, users[0], false, int128(50_000), type(uint128).max);
      _swap(0, users[0], true, int128(10_000), 0);
    }

    (uint128 totalScaledToken0InBins, uint128 totalScaledToken1InBins) = PoolStateLibrary._slot1(_poolAddr());
    (uint128 notional0, uint128 notional1) = PoolStateLibrary._slot2(_poolAddr());
    assertGt(uint256(notional0) + uint256(notional1), 10, "notional accumulators should be non-zero");

    address adminAddr = IMetricOmmPoolFactory(factory).poolAdmin(_poolAddr());
    (uint24 protocolSpreadFeeE6, uint24 adminSpreadFeeE6,,) = IMetricOmmPoolFactory(factory).poolFeeConfig(_poolAddr());
    assertEq(adminAddr, admin);
    PoolFeeConfig memory feeConfig = poolFeeConfig[address(pool)];
    uint24 protocolNotionalFeeE8 = feeConfig.protocolNotionalFeeE8;
    uint24 adminNotionalFeeE8 = feeConfig.adminNotionalFeeE8;

    uint24 spreadFeeE6 = protocolSpreadFeeE6 + adminSpreadFeeE6;
    uint24 notionalFeeE8 = protocolNotionalFeeE8 + adminNotionalFeeE8;

    PoolImmutables memory immutables = IMetricOmmPool(address(pool)).getImmutables();
    address token0Addr = immutables.token0;
    address token1Addr = immutables.token1;
    uint256 token0Mul = immutables.token0ScaleMultiplier;
    uint256 token1Mul = immutables.token1ScaleMultiplier;

    uint256 surplus0Scaled = (MockERC20(token0Addr).balanceOf(address(pool)) * token0Mul) - totalScaledToken0InBins;
    uint256 surplus1Scaled = (MockERC20(token1Addr).balanceOf(address(pool)) * token1Mul) - totalScaledToken1InBins;

    // Mirror collect fee-split math for scaled amounts (rates passed into collectFees).
    uint256 spread0ToAdmin = spreadFeeE6 == 0 ? 0 : (surplus0Scaled * adminSpreadFeeE6) / spreadFeeE6;
    uint256 spread1ToAdmin = spreadFeeE6 == 0 ? 0 : (surplus1Scaled * adminSpreadFeeE6) / spreadFeeE6;
    uint256 spread0ToProtocol = spreadFeeE6 == 0 ? 0 : (surplus0Scaled * protocolSpreadFeeE6) / spreadFeeE6;
    uint256 spread1ToProtocol = spreadFeeE6 == 0 ? 0 : (surplus1Scaled * protocolSpreadFeeE6) / spreadFeeE6;

    uint256 notional0ToAdmin = notionalFeeE8 == 0 ? 0 : (uint256(notional0) * adminNotionalFeeE8) / notionalFeeE8;
    uint256 notional1ToAdmin = notionalFeeE8 == 0 ? 0 : (uint256(notional1) * adminNotionalFeeE8) / notionalFeeE8;
    uint256 notional0ToProtocol = uint256(notional0) - notional0ToAdmin;
    uint256 notional1ToProtocol = uint256(notional1) - notional1ToAdmin;

    uint256 total0Attempted = spread0ToAdmin + spread0ToProtocol + notional0ToAdmin + notional0ToProtocol;
    uint256 total1Attempted = spread1ToAdmin + spread1ToProtocol + notional1ToAdmin + notional1ToProtocol;

    assertGt(total0Attempted, surplus0Scaled, "token0 attempted payout exceeds computed surplus");
    assertGt(total1Attempted, surplus1Scaled, "token1 attempted payout exceeds computed surplus");
  }
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

**File:** metric-core/contracts/MetricOmmPool.sol (L391-414)
```text
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
```
