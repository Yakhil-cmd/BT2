### Title
Blacklisted `adminFeeDestination` Freezes All Fee Collection and Blocks Fee-Config Admin Operations - (File: metric-core/contracts/MetricOmmPool.sol)

### Summary
`MetricOmmPool.collectFees` uses a push-based pattern to transfer accrued fees to two recipients in sequence. If the `adminFeeDestination` address is blacklisted by USDC (or any token with transfer-level blacklisting), the first push reverts and the entire function reverts — permanently blocking `collectPoolFees`, `setPoolAdminFees`, and `setPoolProtocolFee` until the pool admin manually rotates the destination.

### Finding Description
`collectFees` pushes tokens to `adminFeeDestination_` first, then to `FACTORY`, and only resets the notional fee accumulators (`notionalFeeToken0Scaled`, `notionalFeeToken1Scaled`) **after** both transfers succeed:

```
// MetricOmmPool.sol lines 416-430
if (totalFee0ToAdmin > 0) {
    transferToken0(adminFeeDestination_, totalFee0ToAdmin);   // ← reverts if blacklisted
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
notionalFeeToken0Scaled = 0;   // ← never reached on revert
notionalFeeToken1Scaled = 0;
``` [1](#0-0) 

Three factory-level entry points all call `collectFees` as a mandatory first step before updating state:

- `collectPoolFees` (permissionless) — [2](#0-1) 
- `setPoolAdminFees` (pool admin) — [3](#0-2) 
- `setPoolProtocolFee` (protocol owner) — [4](#0-3) 

All three revert atomically if any single token transfer inside `collectFees` fails.

### Impact Explanation
When `adminFeeDestination` is blacklisted by USDC:

1. **Protocol and admin fee revenue is frozen.** Fees continue to accrue in the pool's internal accounting (`notionalFeeToken0Scaled`, `notionalFeeToken1Scaled`, and the spread surplus) but cannot be distributed. Neither the protocol owner nor the pool admin can extract earned fees.
2. **`setPoolAdminFees` is blocked.** The pool admin cannot update their fee rates because the mandatory `collectFees` call reverts first.
3. **`setPoolProtocolFee` is blocked.** The protocol owner cannot update protocol fee rates for the affected pool.

The only recovery path is for the pool admin to call `setPoolAdminFeeDestination` (which does **not** call `collectFees`) to rotate to a non-blacklisted address. [5](#0-4)  If the admin is slow to respond, fees remain frozen and fee-rate governance is paralyzed for the duration.

### Likelihood Explanation
USDC blacklisting is an active, real-world mechanism exercised by Circle against sanctioned or compromised addresses. The `adminFeeDestination` is a pool-creation parameter that can be any address — a DAO treasury, a multisig, or an EOA — all of which are realistic blacklisting targets. The pool is explicitly designed to support USDC (6-decimal token with `TOKEN_0_SCALE_MULTIPLIER` / `TOKEN_1_SCALE_MULTIPLIER` scaling). No on-chain guard prevents setting `adminFeeDestination` to an address that later becomes blacklisted.

### Recommendation
Adopt a pull-based fee accounting pattern: instead of pushing tokens to `adminFeeDestination_` and `FACTORY` inside `collectFees`, credit owed amounts to per-address claimable mappings and let each recipient withdraw independently. This isolates a single recipient's transfer failure from the other recipient and from all admin operations that currently depend on `collectFees` succeeding atomically.

Alternatively, at minimum, separate the accounting reset from the transfers: zero out `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` and record the owed amounts before any external call, so that a failed transfer does not leave the pool in an inconsistent state that permanently blocks re-entry.

### Proof of Concept
1. Deploy a pool with USDC as `token0` and a non-zero `adminSpreadFeeE6` / `adminNotionalFeeE8`.
2. Set `adminFeeDestination` to address `A` at pool creation.
3. Execute several swaps so that spread surplus and `notionalFeeToken0Scaled` accumulate.
4. Circle blacklists address `A` on the USDC contract.
5. Call `MetricOmmPoolFactory.collectPoolFees(pool)` → reverts at `transferToken0(A, ...)` inside `collectFees`.
6. Call `MetricOmmPoolFactory.setPoolAdminFees(pool, newFee, newFee)` → same revert; pool admin cannot update fees.
7. Call `MetricOmmPoolFactory.setPoolProtocolFee(pool, newFee, newFee)` (as owner) → same revert; protocol owner cannot update protocol fees.
8. Fees remain frozen in the pool. `notionalFeeToken0Scaled` is non-zero and cannot be cleared. [6](#0-5) [2](#0-1)

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L365-434)
```text
  function collectFees(
    uint256 protocolSpreadFeeE6_,
    uint256 adminSpreadFeeE6_,
    uint256 protocolNotionalFeeE8_,
    uint256 adminNotionalFeeE8_,
    address adminFeeDestination_
  ) external onlyFactory nonReentrant(PoolActions.COLLECT_FEES) {
    uint256 spreadSumE6;
    uint256 notionalSumE8;
    unchecked {
      spreadSumE6 = protocolSpreadFeeE6_ + adminSpreadFeeE6_;
      notionalSumE8 = protocolNotionalFeeE8_ + adminNotionalFeeE8_;
      if (spreadSumE6 == 0 && notionalSumE8 == 0) {
        return;
      }
    }

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
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L328-335)
```text
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L418-425)
```text
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
