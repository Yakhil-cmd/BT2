Looking at the Metric OMM codebase for an analog to the "cleanup without returning funds" bug class, I need to examine the fee collection, admin, and provider-change paths.

The key analog is in `MetricOmmPoolFactory.sol`. The `setPoolAdminFees` function (lines 408–435) correctly calls `collectFees` with the current config **before** updating fee rates, ensuring accrued fees reach the current destination. However, `setPoolAdminFeeDestination` (lines 438–447) changes the destination **without** first collecting accrued fees — directly parallel to the `cancelOrder` pattern of mutating state without returning owed funds.

---

### Title
`setPoolAdminFeeDestination` Redirects Accrued Fees Without Prior Collection, Causing Loss for Old Fee Destination — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
The pool admin can change the admin fee destination at any time without first flushing accrued spread-fee surplus and notional fees to the old destination. Any fees earned under the old destination are silently redirected to the new one on the next `collectFees` call.

### Finding Description
`setPoolAdminFees` establishes the correct pattern: before mutating fee state, it calls `collectFees` with the current `poolFeeConfig` so that all accrued fees are distributed to the current `poolAdminFeeDestination`. [1](#0-0) 

`setPoolAdminFeeDestination` breaks this invariant. It overwrites `poolAdminFeeDestination[pool]` with no prior fee flush: [2](#0-1) 

After the call, the next invocation of `collectFees` (or `setPoolAdminFees`, `setPoolProtocolFee`) computes the spread-fee surplus and notional-fee balances and routes the **admin share** to the new destination: [3](#0-2) 

The two quantities that are silently redirected are:
- **Spread-fee surplus**: `balance0/1 * scaleMultiplier − binTotals.scaledToken0/1 − notionalFeeToken0/1Scaled`, pro-rated by `adminSpreadFeeE6 / spreadSumE6`.
- **Notional fees**: `notionalFeeToken0/1Scaled`, pro-rated by `adminNotionalFeeE8 / notionalSumE8`.

Both are zeroed/consumed on the next `collectFees` call and sent entirely to the new destination.

### Impact Explanation
The old `adminFeeDestination` (which may be a separate treasury, DAO, or LP-fee-sharing contract distinct from the pool admin EOA) permanently loses all fees accrued since the last `collectFees` call. These are real ERC-20 token amounts already sitting in the pool and owed to the old destination. The loss scales with swap volume and time elapsed since the last collection.

### Likelihood Explanation
The pool admin is a valid, semi-trusted actor with explicit authority over the fee destination. No exploit setup is required beyond a normal admin key action. The admin may change the destination legitimately (e.g., rotating a treasury address) and inadvertently — or deliberately — redirect uncollected fees. Because `collectPoolFees` is permissionless and callable by anyone, an attacker who controls the pool admin key can front-run any pending `collectPoolFees` transaction with a `setPoolAdminFeeDestination` call to a self-controlled address.

### Recommendation
Mirror the pattern used in `setPoolAdminFees`: call `collectFees` with the current `poolFeeConfig` and the **current** `poolAdminFeeDestination` before overwriting the destination.

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    // Flush accrued fees to the old destination first
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool).collectFees(
        c.protocolSpreadFeeE6, c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8, c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]   // old destination
    );
    poolAdminFeeDestination[pool] = newAdminFeeDestination;
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

### Proof of Concept
1. Pool is created; `adminFeeDestination = Alice` (a separate treasury contract).
2. Swaps occur; spread-fee surplus accumulates to 1 000 USDC and notional fees to 500 USDC in the pool.
3. Pool admin (Bob) calls `setPoolAdminFeeDestination(pool, Bob_wallet)`.
4. `poolAdminFeeDestination[pool]` is now `Bob_wallet`; no fees are collected.
5. Anyone calls `collectPoolFees(pool)`.
6. `collectFees` computes the surplus and notional balances and transfers the admin share (1 500 USDC) to `Bob_wallet`.
7. Alice receives nothing despite having earned those fees; Bob has extracted 1 500 USDC that belonged to Alice. [4](#0-3)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L382-428)
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

```
