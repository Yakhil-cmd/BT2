Based on my investigation, I found a direct analog to the external bug's "cumulative accumulation inflates a critical value" pattern in the fee-collection path.

---

### Title
Double-Counting of Notional Fees in `collectFees` Causes Over-Allocation Beyond Pool Surplus — (`metric-core/contracts/MetricOmmPool.sol`)

### Summary

When both spread fees and notional fees are active simultaneously, `collectFees` distributes the full pool surplus as spread fees **and** distributes the notional accumulator separately. Because the notional accumulator amounts are already embedded in the surplus (they are part of the pool balance but not in bins), the total attempted payout exceeds the actual surplus, analogous to the external bug where `collaterals_values` was accumulated across loop iterations instead of being reset, inflating `max_loan_to_value`.

### Finding Description

The pool tracks two distinct fee streams:

1. **Spread fees** — protocol fee deducted from the input token before it enters bins; these tokens sit in the pool balance but are not reflected in `binTotals`.
2. **Notional fees** — charged on the output notional and added to the trader's payment; these tokens also sit in the pool balance but are tracked separately in `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`.

The surplus available for fee collection is:

```
surplus = pool.balance × scaleMultiplier − binTotals.scaledToken
```

Because **both** spread fees and notional fees accumulate outside `binTotals`, the surplus already contains both components:

```
surplus = spread_fee_balance + notional_fee_balance
```

However, `collectFees` distributes:
- The **full surplus** as spread fees (to protocol and admin destinations), AND
- The **notional accumulator** (`notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`) as a separate payout.

This means notional fees are paid out **twice**: once embedded in the surplus distributed as spread fees, and once from the notional accumulator. The total attempted payout is:

```
total_payout = surplus + notional_accumulator > surplus
```

The test `test_collectProtocolFees_math_overallocates_whenSpreadAndNotionalBothActive` explicitly confirms this invariant break: [1](#0-0) 

```solidity
uint256 total0Attempted = spread0ToAdmin + spread0ToProtocol + notional0ToAdmin + notional0ToProtocol;
uint256 total1Attempted = spread1ToAdmin + spread1ToProtocol + notional1ToAdmin + notional1ToProtocol;

assertGt(total0Attempted, surplus0Scaled, "token0 attempted payout exceeds computed surplus");
assertGt(total1Attempted, surplus1Scaled, "token1 attempted payout exceeds computed surplus");
```

The surplus computation used in the test mirrors the actual `collectFees` math: [2](#0-1) 

The notional accumulators are stored in slot 2 of the pool: [3](#0-2) 

The `collectPoolFees` entry point is permissionless — any address can trigger it: [4](#0-3) 

### Impact Explanation

When `collectFees` is called with both `spreadFeeE6 > 0` and `notionalFeeE8 > 0`, the function attempts to transfer more tokens than the actual fee surplus. The excess comes from LP principal held in bins. This causes **pool insolvency**: LP claims on their deposited liquidity are undercollateralized after fee collection, and subsequent `removeLiquidity` calls will fail or drain other LPs' principal.

### Likelihood Explanation

- `collectPoolFees` is **permissionless** — any address (keeper, bot, attacker) can call it at any time.
- The condition requires both spread and notional fees to be non-zero simultaneously, which is a normal and documented production configuration.
- No timelock or access control prevents repeated calls.

### Recommendation

The surplus must be partitioned before distribution. The notional accumulator amounts should be **subtracted from the surplus** before computing the spread fee payout, so the two streams are mutually exclusive:

```solidity
uint256 spreadSurplus0 = surplus0 - notionalFeeToken0Scaled;
uint256 spreadSurplus1 = surplus1 - notionalFeeToken1Scaled;
// distribute spreadSurplus as spread fees
// distribute notionalFeeToken*Scaled as notional fees
// clear notional accumulators
```

### Proof of Concept

1. Deploy a pool with `adminSpreadFeeE6 > 0` and `adminNotionalFeeE8 > 0` (both fee types active).
2. Execute several swaps to accumulate both spread surplus and notional accumulator balances.
3. Record `surplus0 = pool.balance × multiplier − binTotals.scaledToken0` and `notional0 = notionalFeeToken0Scaled`.
4. Call `collectPoolFees(pool)`.
5. Observe that the function attempts to transfer `surplus0 + notional0` worth of token0, exceeding the actual surplus by `notional0`.
6. If the transfer does not revert (no balance guard), LP principal is drained; if it reverts, fee collection is broken for all pools with both fee types active.

The test at `metric-core/test/MetricOmmPool.notionalFee.t.sol:211-266` already encodes steps 1–5 and asserts the over-allocation holds. [5](#0-4)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L83-87)
```text
  // Slot 2 ordering (from left to right):
  //   [16bytes notionalFeeToken1Scaled] [16bytes notionalFeeToken0Scaled]
  uint128 internal notionalFeeToken0Scaled;
  uint128 internal notionalFeeToken1Scaled;

```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L378-389)
```text
  /// @inheritdoc IMetricOmmPoolFactory
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
