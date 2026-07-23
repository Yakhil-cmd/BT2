### Title
Notional Fees Double-Counted in `collectFees`: LP Principal Drained When Both Spread and Notional Fees Are Active — (`metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

`MetricOmmPool.collectFees()` computes spread-fee payouts using `surplus0Scaled` / `surplus1Scaled`, which is the raw difference between the pool's token balance and its bin totals. Because notional fees are held inside the pool balance but outside bins, they are already embedded in that surplus. The function then distributes the notional fees a second time as an explicit separate line item. The result is that the total payout exceeds the actual fee surplus by exactly the notional-fee amount, and the shortfall is silently taken from LP principal.

---

### Finding Description

`collectFees` (called permissionlessly via `MetricOmmPoolFactory.collectPoolFees`) computes two independent payouts and sums them:

```
spreadFee0ToAdminScaled    = surplus0Scaled * adminSpreadFeeE6  / spreadSumE6
spreadFee0ToProtocolScaled = surplus0Scaled * protocolSpreadFeeE6 / spreadSumE6

notionalFee0ToAdminScaled    = notionalFee0AmountScaled * adminNotionalFeeE8 / notionalSumE8
notionalFee0ToProtocolScaled = notionalFee0AmountScaled - notionalFee0ToAdminScaled

totalFee0ToAdmin    = spreadFee0ToAdminScaled    + notionalFee0ToAdminScaled
totalFee0ToProtocol = spreadFee0ToProtocolScaled + notionalFee0ToProtocolScaled
```

`surplus0Scaled` is defined as:

```
surplus0Scaled = pool.balanceOf(token0) * token0ScaleMultiplier − binTotals.scaledToken0
```

Notional fees accumulate in `notionalFeeToken0Scaled` during swaps. They are held in the pool's ERC-20 balance but are **not** added to `binTotals.scaledToken0`. Therefore:

```
surplus0Scaled = spreadFeesAccumulated + notionalFee0AmountScaled
```

The spread-fee payout distributes the **entire** surplus (≈ `spreadFeesAccumulated + notionalFee0AmountScaled`), and then the notional-fee payout distributes `notionalFee0AmountScaled` again. The total attempted payout is:

```
total ≈ surplus0Scaled + notionalFee0AmountScaled
      = spreadFeesAccumulated + 2 × notionalFee0AmountScaled
```

This exceeds the available surplus by `notionalFee0AmountScaled`. The excess is drawn from LP-deposited principal because the pool's ERC-20 balance covers it.

The protocol's own test explicitly confirms this: [1](#0-0) 

```solidity
uint256 total0Attempted = spread0ToAdmin + spread0ToProtocol + notional0ToAdmin + notional0ToProtocol;
assertGt(total0Attempted, surplus0Scaled, "token0 attempted payout exceeds computed surplus");
assertGt(total1Attempted, surplus1Scaled, "token1 attempted payout exceeds computed surplus");
```

The double-counting originates in the spread-fee lines: [2](#0-1) 

---

### Impact Explanation

Every `collectFees` call on a pool where both `spreadFeeE6 > 0` and `notionalFeeE8 > 0` transfers `notionalFee0AmountScaled` (and `notionalFee1AmountScaled`) worth of tokens that belong to LPs. Over time this silently drains LP principal, making the pool insolvent: LP positions cannot be fully redeemed because the pool's token balances no longer cover `binTotals`. This is a direct loss of user principal and constitutes pool insolvency under the allowed impact gate.

---

### Likelihood Explanation

`collectPoolFees` is permissionless: [3](#0-2) 

Any address can call it at any time. The condition (both spread and notional fees active) is the standard production configuration — pools are deployed with `spreadFeeE6 = protocolSpreadFeeE6 + adminSpreadFeeE6` and `notionalFeeE8 = protocolNotionalFeeE8 + adminNotionalFeeE8`, both non-zero by default. The bug triggers on every fee collection cycle.

---

### Recommendation

Before computing spread-fee payouts, subtract the notional-fee accumulator from the surplus so the two fee streams do not overlap:

```solidity
uint256 spreadSurplus0Scaled = surplus0Scaled > notionalFee0AmountScaled
    ? surplus0Scaled - notionalFee0AmountScaled
    : 0;
uint256 spreadSurplus1Scaled = surplus1Scaled > notionalFee1AmountScaled
    ? surplus1Scaled - notionalFee1AmountScaled
    : 0;

uint256 spreadFee0ToAdminScaled    = spreadSumE6 == 0 ? 0 : (spreadSurplus0Scaled * adminSpreadFeeE6_)    / spreadSumE6;
uint256 spreadFee0ToProtocolScaled = spreadSumE6 == 0 ? 0 : (spreadSurplus0Scaled * protocolSpreadFeeE6_) / spreadSumE6;
// ... same for token1
```

This mirrors the fix in the ArtGobblers report: remove the explicit re-addition of a value that is already counted by a sub-routine.

---

### Proof of Concept

1. Deploy a pool with `spreadProtocolFeeE6 = 10_000` (1%) and `protocolNotionalFeeE8 = 1_000_000` (1%).
2. Add liquidity across several bins.
3. Execute multiple swaps to accumulate both spread surplus and notional fees (`notionalFeeToken0Scaled > 0`).
4. Record LP token balances and `binTotals.scaledToken0`.
5. Call `factory.collectPoolFees(pool)` (permissionless).
6. Observe that `pool.balanceOf(token0) * token0Mul < binTotals.scaledToken0` — the pool can no longer cover LP claims.

The protocol's own test `test_collectProtocolFees_math_overallocates_whenSpreadAndNotionalBothActive` already demonstrates step 6 by asserting `total0Attempted > surplus0Scaled`. [4](#0-3)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L391-403)
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
