### Title
`setPoolAdminFeeDestination` Omits Pre-Collection of Accrued Fees, Allowing Pool Admin to Redirect Owed Admin Fees to a New Destination — (`File: metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

Both `setPoolAdminFees` and `setPoolProtocolFee` flush accrued fees to the current `poolAdminFeeDestination` before mutating any fee-related state. `setPoolAdminFeeDestination` — the function that changes that very destination — performs no such flush. Any fees that have accrued since the last collection are therefore silently redirected to the new address when `collectPoolFees` is next called, depriving the previous destination of funds it was owed.

---

### Finding Description

The factory enforces a consistent pattern for every function that changes how fees are split or rated: collect first, then update state.

`setPoolAdminFees` (pool-admin role): [1](#0-0) 

`setPoolProtocolFee` (owner role): [2](#0-1) 

Both call `pool.collectFees(...)` with the **current** `poolAdminFeeDestination[pool]` before writing any new value.

`setPoolAdminFeeDestination` does not: [3](#0-2) 

It overwrites `poolAdminFeeDestination[pool]` immediately. All subsequent calls to `collectPoolFees` — which reads `poolAdminFeeDestination[pool]` at call time — will route the previously accrued admin share to the new address: [4](#0-3) 

The accrued admin fees consist of two components that are tracked on the pool:

- **Spread fees**: the surplus of `balance * scaleMultiplier − binTotals − notionalFeeAccumulator`, proportioned by the admin spread rate.
- **Notional fees**: `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` accumulated during swaps, proportioned by the admin notional rate. [5](#0-4) 

Neither component is zeroed or transferred until `collectFees` is called. Changing the destination before that call silently reassigns ownership of those amounts.

---

### Impact Explanation

The previous `poolAdminFeeDestination` — which may be a DAO treasury, a revenue-sharing contract, or any address distinct from the pool admin — loses all fees that accrued between the last collection and the destination change. Those tokens are transferred to the new destination instead. This is a direct, quantifiable loss of protocol fees owed to the prior recipient, matching the "direct loss of protocol fees" criterion in the allowed impact gate.

---

### Likelihood Explanation

The pool admin is a semi-trusted role with no timelock or cap on `setPoolAdminFeeDestination`. The admin can execute the redirect atomically (change destination → call `collectPoolFees` in the same block) with no on-chain warning. The only friction is that the admin must be willing to act against the prior destination's interests. In deployments where the pool admin and the fee destination are different entities (e.g., a pool creator vs. a protocol treasury), this is a realistic scenario.

---

### Recommendation

Mirror the pattern used by `setPoolAdminFees` and `setPoolProtocolFee`: flush accrued fees to the **current** destination before overwriting it.

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Flush accrued fees to the current destination before changing it
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

1. Pool is live; `poolAdminFeeDestination[pool] = treasury`. Swaps accumulate `notionalFeeToken0Scaled = X` and spread surplus `S` on the pool. Neither has been collected.
2. Pool admin calls `setPoolAdminFeeDestination(pool, attacker)`. No collection occurs; `poolAdminFeeDestination[pool]` is now `attacker`.
3. Anyone (including the pool admin) calls `collectPoolFees(pool)`. The factory reads `poolAdminFeeDestination[pool] == attacker` and passes it to `pool.collectFees(...)`.
4. Inside `collectFees`, the admin share of `X` (notional) and `S` (spread) is transferred to `attacker`.
5. `treasury` receives nothing for the fees it was owed. The loss equals the admin-rate fraction of all fees accrued since the last collection.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L382-403)
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
```
