### Title
`collectFees` Double-Counts Notional Fees Against LP Surplus, Draining LP Principal — (File: metric-core/contracts/MetricOmmPool.sol)

---

### Summary

When both spread fees and notional fees are simultaneously active, `collectFees` in `MetricOmmPool.sol` computes the spread-fee split against the full balance surplus — which already contains accumulated notional fees — and then **additionally** pays out the notional fee accumulator as a separate line item. This double-counts every notional token, causing the total attempted payout to exceed the real fee surplus by exactly the notional accumulator amount. The excess is drawn from LP principal held in bin totals, directly analogous to the HashflowHelper pattern where a silently-capped amount leaves funds stranded with an intermediary.

---

### Finding Description

`collectFees` (called by the permissionless `collectPoolFees` factory entry-point) computes the distributable surplus as:

```
surplus0Scaled = balance0 * token0ScaleMultiplier − binTotals.scaledToken0
```

Because notional fees are charged to swappers (added to `amount0DeltaScaled` / `amount1DeltaScaled`) but **not** credited to `binTotals`, they accumulate in the pool balance. Therefore:

```
surplus0Scaled = spread_fee_surplus + notional_fee_surplus
```

The function then distributes:

1. **Spread split** — the entire `surplus0Scaled` is split admin/protocol:
   `spreadFee0ToAdminScaled + spreadFee0ToProtocolScaled = surplus0Scaled`

2. **Notional split** — the notional accumulator `notionalFee0AmountScaled` is split admin/protocol and added on top.

Total attempted payout:

```
= surplus0Scaled + notionalFee0AmountScaled
= (spread_surplus + notional_surplus) + notional_surplus
= spread_surplus + 2 × notional_surplus
```

Available balance above bin totals: `spread_surplus + notional_surplus`.

**Over-payment = notional_surplus ≈ notionalFee0AmountScaled.** [1](#0-0) 

The codebase's own test explicitly asserts this over-allocation occurs:

```solidity
assertGt(total0Attempted, surplus0Scaled,
    "token0 attempted payout exceeds computed surplus");
assertGt(total1Attempted, surplus1Scaled,
    "token1 attempted payout exceeds computed surplus");
``` [2](#0-1) 

Because the pool holds LP principal in `binTotals` and the ERC-20 balance covers both LP funds and fees, the over-allocated transfer succeeds — it does not revert — and the shortfall is silently drawn from LP principal.

---

### Impact Explanation

Every call to `collectPoolFees` (or any path that triggers `collectFees`) when both `spreadFeeE6 > 0` and `notionalFeeE8 > 0` drains LP principal by the full accumulated notional fee amount. LPs who later withdraw find their share of `binTotals` backed by fewer real tokens than the accounting records, causing direct, measurable loss of deposited principal. This is pool insolvency: balances fail to cover LP claims.

---

### Likelihood Explanation

`collectPoolFees` is **permissionless** — any address may call it at any time. [3](#0-2) 

The triggering conditions — both fee types active and at least one swap executed — are the normal operating state of any production pool configured with both spread and notional fees. No special role, malicious setup, or non-standard token is required.

---

### Recommendation

The notional fee accumulator must not be paid out in addition to the full surplus split. Two correct approaches:

1. **Exclude notional fees from the surplus before the spread split:**
   ```solidity
   uint256 spreadSurplus0 = surplus0Scaled > notionalFee0AmountScaled
       ? surplus0Scaled - notionalFee0AmountScaled : 0;
   // use spreadSurplus0 for the spread split, notionalFee0AmountScaled for the notional split
   ```

2. **Treat the notional accumulator as the sole source of notional payouts and zero the surplus split for the notional portion** — i.e., do not include notional tokens in `surplus0Scaled` by crediting them to a separate storage slot rather than leaving them in the raw balance.

Either fix ensures `totalFee0ToAdmin + totalFee0ToProtocol ≤ surplus0Scaled` at all times.

---

### Proof of Concept

1. Deploy a pool with `spreadFeeE6 = 5000` (0.5 %) and `notionalFeeE8 = 1_000_000` (1 %).
2. Add liquidity so `binTotals.scaledToken0 = L`.
3. Execute several swaps; let `notionalFeeToken0Scaled` accumulate to `N`.
4. Pool balance is now `L + S + N` where `S` = spread surplus.
5. Call the permissionless `collectPoolFees(pool)`.
6. `collectFees` computes `surplus = S + N`, pays out `S + N` as spread split **plus** `N` as notional split — total `S + 2N`.
7. The ERC-20 transfer of `S + 2N` succeeds because the pool holds `L + S + N ≥ S + 2N` whenever `L ≥ N`.
8. After collection, pool balance = `L + S + N − (S + 2N) = L − N`.
9. `binTotals.scaledToken0` is still `L`, but the real balance is only `L − N`: LPs are short `N` tokens on withdrawal. [4](#0-3) [5](#0-4)

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L391-433)
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
