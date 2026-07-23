### Title
`setPoolAdminFeeDestination` Silently Redirects All Accrued Admin Fees to New Destination Without Prior Collection, Causing Old Destination to Lose Owed Fees - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary
`setPoolAdminFeeDestination` changes `poolAdminFeeDestination[pool]` immediately without first collecting accrued fees at the old destination. Every other fee-mutating function in the factory (`setPoolAdminFees`, `setPoolProtocolFee`) calls `collectFees` before making its change. The destination function skips this step, so all spread-surplus and notional fees that accrued under the old destination are silently redirected to the new one on the next `collectPoolFees` call.

### Finding Description
`setPoolAdminFees` (lines 408–435) and `setPoolProtocolFee` (lines 318–360) both call `collectFees` with the current `poolAdminFeeDestination[pool]` before updating any state. This ensures the old destination receives every token it earned before the configuration changes.

`setPoolAdminFeeDestination` (lines 438–447) performs no such collection:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
  external override nonReentrant onlyPoolAdmin(pool)
{
  if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
  poolAdminFeeDestination[pool] = newAdminFeeDestination;          // ← no collectFees first
  emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

After this call, `collectPoolFees` (permissionless, line 379) reads the updated `poolAdminFeeDestination[pool]` and sends the entire accumulated admin share — both the spread surplus and the `notionalFeeToken0/1Scaled` balance — to the new address.

The two fee components that are lost:
1. **Spread fees**: `surplus0/1Scaled` (pool balance − bin totals − notional reserves) proportioned by `adminSpreadFeeE6 / spreadSumE6`.
2. **Notional fees**: `notionalFeeToken0/1Scaled` proportioned by `adminNotionalFeeE8 / notionalSumE8`.

Both are computed at collection time using the then-current `adminFeeDestination_` parameter passed by the factory, which is now the new address.

### Impact Explanation
The old admin fee destination — which may be a separate treasury, revenue-sharing contract, or DAO vault distinct from the pool admin — permanently loses all fees that accrued since the last collection. The tokens are not destroyed; they are transferred to the new destination. The loss is a direct, quantifiable transfer of owed protocol-fee revenue away from the rightful recipient. Magnitude scales with swap volume and time elapsed since the last `collectPoolFees` call.

### Likelihood Explanation
The pool admin is a semi-trusted role that legitimately calls `setPoolAdminFeeDestination` during normal treasury rotations (multisig upgrades, new vault deployments, etc.). No special precondition is required beyond the admin role. Because `collectPoolFees` is permissionless, the old destination could self-protect by front-running the change, but only if it has advance knowledge of the transaction — which is not guaranteed and is trivially defeated by the admin bundling the destination change with other operations in a single block.

### Recommendation
Mirror the pattern used by `setPoolAdminFees` and `setPoolProtocolFee`: collect accrued fees at the current destination before updating the storage slot.

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
  external override nonReentrant onlyPoolAdmin(pool)
{
  if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

  // Flush accrued fees to the current destination before rotating.
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
1. Pool has been active; `notionalFeeToken0Scaled = N` and a spread surplus `S` have accumulated since the last collection.
2. Pool admin calls `setPoolAdminFeeDestination(pool, newTreasury)`. No fees are collected; `poolAdminFeeDestination[pool]` is now `newTreasury`.
3. Anyone calls `collectPoolFees(pool)`. The factory reads `poolAdminFeeDestination[pool] == newTreasury` and passes it to `collectFees`.
4. Inside `collectFees`, `adminFeeDestination_` is `newTreasury`; `transferToken0/1(newTreasury, ...)` sends the full admin share of `S` and `N` to `newTreasury`.
5. `oldTreasury` receives zero, despite having earned those fees during its tenure. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L318-335)
```text
  function setPoolProtocolFee(address pool, uint24 newProtocolSpreadFeeE6, uint24 newProtocolNotionalFeeE8)
    external
    override
    onlyOwner
    nonReentrant
  {
    if (newProtocolSpreadFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    if (newProtocolNotionalFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-425)
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

**File:** metric-core/contracts/MetricOmmPool.sol (L382-432)
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
```
