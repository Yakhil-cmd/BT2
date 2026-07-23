Now I have all the information needed. Let me trace the full path precisely.

**Key facts from the code:**

1. `setPoolAdminFeeDestination` only rejects `address(0)` — no check for `address(pool)`: [1](#0-0) 

2. `collectPoolFees` is permissionless and passes `poolAdminFeeDestination[pool]` directly: [2](#0-1) 

3. `collectFees` computes `surplus0Scaled` from live `balance0()`, then calls `transferToken0(adminFeeDestination_, totalFee0ToAdmin)`: [3](#0-2) 

4. `transferToken0` is a plain `safeTransfer` — if `to == address(this)`, the pool's balance is unchanged: [4](#0-3) 

5. After the transfer, `notionalFeeToken0Scaled` is zeroed: [5](#0-4) 

**Arithmetic of the re-deposit:**

Let `B` = `balance0()`, `L` = `binTotals.scaledToken0`, `N` = `notionalFeeToken0Scaled`.

- Collection 1 surplus: `S = B·scale − L − N`
- Admin gets `A_amount`, protocol gets `P_amount` (both from `S`)
- After collection: `balance0 = B − P_amount` (admin tokens stayed in pool), `N = 0`
- Collection 2 surplus: `(B − P_amount)·scale − L − 0 = S + N − P_amount·scale`
- Normal case surplus: `(B − P_amount − A_amount)·scale − L − 0 = S + N − P_amount·scale − A_amount·scale`

The second collection surplus is inflated by exactly `A_amount·scale`. That excess is collected again as fees — split between admin and protocol — eating into LP principal. Each subsequent collection compounds this.

**Role-boundary assessment:**

The scope rules explicitly call out "fee collection destinations" under the admin path as an area to look for bypasses. The pool admin is semi-trusted only within caps and timelocks. The fee destination has no cap and no timelock — the admin can set it to `address(pool)` immediately and without limit. This is an admin-boundary break: the pool admin gains the ability to drain LP principal through repeated fee collections, which is outside the semi-trusted boundary.

---

### Title
Pool admin can set `adminFeeDestination = address(pool)`, recycling admin fees back into the pool and inflating surplus for subsequent collections, draining LP principal — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`setPoolAdminFeeDestination` only rejects `address(0)` but does not reject `address(pool)`. When the admin fee destination is the pool itself, `collectFees` transfers admin fees back to the pool via a plain `safeTransfer`, leaving `balance0()` unchanged while zeroing `notionalFeeToken0Scaled`. Every subsequent `collectPoolFees` call sees an inflated `surplus0Scaled` equal to the previously "collected" admin fees, and collects them again — eating into LP principal.

### Finding Description
`MetricOmmPoolFactory.setPoolAdminFeeDestination` enforces only one guard:

```solidity
if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
``` [6](#0-5) 

There is no check that `newAdminFeeDestination != pool`. A pool admin can therefore store `poolAdminFeeDestination[pool] = address(pool)`.

`collectPoolFees` (permissionless) then calls `collectFees` with that destination: [2](#0-1) 

Inside `collectFees`, the surplus is computed from the live ERC-20 balance: [7](#0-6) 

Admin fees are then transferred to `adminFeeDestination_`: [8](#0-7) 

`transferToken0` is `IERC20(TOKEN0).safeTransfer(to, amount)`: [4](#0-3) 

When `to == address(pool)`, the ERC-20 balance of the pool does not decrease. The notional accumulator is then zeroed: [5](#0-4) 

On the next call, `surplus0Scaled` is computed from the same (un-reduced) `balance0()` with `notionalFeeToken0Scaled = 0`, so it is inflated by the full admin fee amount from the previous round. That inflated surplus is collected again, with the protocol share leaving the pool and the admin share staying — compounding with each call.

### Impact Explanation
LP principal is drained. The surplus is supposed to represent only accumulated spread fees above LP positions and notional fees. Recycling admin fees back into the pool causes the surplus to grow beyond actual accrued fees, so subsequent collections take tokens that belong to LPs. The protocol fee share (which does leave the pool) is the direct drain vector; it is extracted from tokens that should be redeemable by LPs. Severity: **Medium** — requires a malicious or misconfigured pool admin, but the admin-boundary break is uncapped and untimelocked, and the fund loss is real and compounding.

### Likelihood Explanation
The pool admin is a semi-trusted role. The scope rules explicitly list "fee collection destinations" as an admin-path bypass area. The action (`setPoolAdminFeeDestination`) requires only `onlyPoolAdmin`, has no timelock, and `collectPoolFees` is permissionless — any keeper or bot can trigger the drain after the destination is set. The pool admin could be a compromised multisig or a malicious actor who accepted an admin transfer.

### Recommendation
Add a guard in `setPoolAdminFeeDestination` rejecting the pool address itself:

```solidity
if (newAdminFeeDestination == address(0) || newAdminFeeDestination == pool)
    revert InvalidAdminFeeDestination();
```

Apply the same check to `adminFeeDestination` in `createPool` / `_validatePoolParameters` so the invariant holds from deployment.

### Proof of Concept
```solidity
// Foundry test sketch
function test_adminFeeDestinationSelfDrainsLP() public {
    // 1. Pool admin sets destination to pool itself
    vm.prank(admin);
    factory.setPoolAdminFeeDestination(pool, address(pool));

    // 2. Generate spread fees via swaps
    _swap(0, users[0], true,  int128(50_000), 0);
    _swap(0, users[0], false, int128(50_000), type(uint128).max);

    uint256 lpToken0Before = token0.balanceOf(address(pool));

    // 3. First collection — admin fees stay in pool, protocol fees leave
    factory.collectPoolFees(address(pool));

    // 4. Second collection — inflated surplus re-collected; protocol gets more than accrued
    uint256 protocolBefore = token0.balanceOf(address(factory));
    factory.collectPoolFees(address(pool));
    uint256 protocolAfter = token0.balanceOf(address(factory));

    // Protocol collected in round 2 despite no new swaps — sourced from LP principal
    assertGt(protocolAfter - protocolBefore, 0, "protocol drained LP principal in round 2");

    // LP balance decreased beyond what swaps alone explain
    assertLt(token0.balanceOf(address(pool)), lpToken0Before - expectedProtocolFee,
        "LP principal drained");
}
```

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

**File:** metric-core/contracts/MetricOmmPool.sol (L385-418)
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
```

**File:** metric-core/contracts/MetricOmmPool.sol (L429-430)
```text
      notionalFeeToken0Scaled = 0;
      notionalFeeToken1Scaled = 0;
```

**File:** metric-core/contracts/MetricOmmPool.sol (L565-567)
```text
  function transferToken0(address to, uint256 amount) internal {
    IERC20(TOKEN0).safeTransfer(to, amount);
  }
```
