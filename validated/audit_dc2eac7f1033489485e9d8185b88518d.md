### Title
Double-Counting of Notional Fee Accumulator in `collectFees` Causes Pool Insolvency When Both Spread and Notional Fees Are Active — (`metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

When a pool has both `spreadFeeE6 > 0` and `notionalFeeE8 > 0` configured, the `collectFees` function double-counts the notional fee accumulator: it is included once inside `surplus0Scaled` (the spread fee base) and paid out again as a separate notional leg. The total attempted transfer exceeds the actual fee surplus by exactly `notionalFee0AmountScaled`, draining that amount from LP principal.

---

### Finding Description

`collectFees` in `MetricOmmPool.sol` computes the fee surplus as:

```
surplus0Scaled = pool.balance * TOKEN_0_SCALE_MULTIPLIER − totalScaledToken0InBins
```

This surplus contains **both** the accumulated spread-fee residual **and** the notional-fee accumulator (`notionalFeeToken0Scaled`), because both are held in the pool's token balance above the bin total.

The function then allocates:

```
spreadFee0ToAdmin   = surplus0Scaled * adminSpreadFeeE6   / spreadSumE6
spreadFee0ToProtocol= surplus0Scaled * protocolSpreadFeeE6/ spreadSumE6
```

Because `adminSpreadFeeE6 + protocolSpreadFeeE6 == spreadSumE6`, these two lines together consume **100 % of `surplus0Scaled`**, including the notional portion.

Immediately after, the notional leg is paid out again:

```
notionalFee0ToAdmin   = notionalFee0AmountScaled * adminNotionalFeeE8 / notionalSumE8
notionalFee0ToProtocol= notionalFee0AmountScaled − notionalFee0ToAdmin
```

Total attempted transfer = `surplus0Scaled + notionalFee0AmountScaled`, but only `surplus0Scaled` exists as fee surplus. The shortfall of `notionalFee0AmountScaled` is taken from LP principal.

The project's own test suite documents this invariant break explicitly:

```solidity
assertGt(total0Attempted, surplus0Scaled,
    "token0 attempted payout exceeds computed surplus");
assertGt(total1Attempted, surplus1Scaled,
    "token1 attempted payout exceeds computed surplus");
``` [1](#0-0) 

The root cause in production: [2](#0-1) 

---

### Impact Explanation

- **Pool insolvency**: LP shares become under-collateralised by `notionalFee0AmountScaled` (token0) and `notionalFee1AmountScaled` (token1) on every `collectFees` call while both fee types are non-zero.
- **Direct LP principal loss**: the shortfall is transferred out of the bin-backing balance, so LPs who remove liquidity after a collection receive less than their entitlement.
- **Permissionless trigger**: `collectPoolFees` is callable by anyone; no privileged action is required after the pool admin has legitimately set both fee components. [3](#0-2) 

---

### Likelihood Explanation

- Any pool where the admin sets `adminSpreadFeeE6 > 0` **and** `adminNotionalFeeE8 > 0` (or the protocol owner sets both protocol components) is permanently vulnerable.
- `setPoolAdminFees` enforces only cap checks (`maxAdminSpreadFeeE6`, `maxAdminNotionalFeeE8`); enabling both simultaneously is a normal, documented configuration.
- Once the pool accumulates notional fees through swaps, the next `collectPoolFees` call (by anyone) drains LP funds. [4](#0-3) 

---

### Recommendation

Exclude the notional accumulator from the spread-fee base before computing spread allocations:

```solidity
// In collectFees, before spread allocation:
uint256 spreadSurplus0Scaled = surplus0Scaled - notionalFee0AmountScaled;
uint256 spreadSurplus1Scaled = surplus1Scaled - notionalFee1AmountScaled;

uint256 spreadFee0ToAdminScaled =
    spreadSumE6 == 0 ? 0 : (spreadSurplus0Scaled * adminSpreadFeeE6_) / spreadSumE6;
// ... use spreadSurplus* throughout spread allocation
```

This ensures the two fee legs are computed on disjoint portions of the pool balance, eliminating the double-count.

---

### Proof of Concept

The existing test `test_collectProtocolFees_math_overallocates_whenSpreadAndNotionalBothActive` in `metric-core/test/MetricOmmPool.notionalFee.t.sol` already demonstrates the invariant break end-to-end:

1. Pool is configured with both `PROTOCOL_FEE` (spread) and `FEE_1_PCT_E8` (notional).
2. Swaps accumulate both spread surplus and notional accumulator.
3. The test mirrors the `collectFees` split math and asserts:

```solidity
assertGt(total0Attempted, surplus0Scaled,
    "token0 attempted payout exceeds computed surplus");
assertGt(total1Attempted, surplus1Scaled,
    "token1 attempted payout exceeds computed surplus");
``` [5](#0-4) 

The excess `notionalFee0AmountScaled` transferred beyond `surplus0Scaled` is sourced from LP bin balances, directly reducing LP redemption value.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L391-409)
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-435)
```text
  function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();

    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );

    c.adminSpreadFeeE6 = newAdminSpreadFeeE6;
    c.adminNotionalFeeE8 = newAdminNotionalFeeE8;
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
    emit PoolAdminSpreadFeeUpdated(pool, newAdminSpreadFeeE6);
    emit PoolAdminNotionalFeeUpdated(pool, newAdminNotionalFeeE8);
  }
```
