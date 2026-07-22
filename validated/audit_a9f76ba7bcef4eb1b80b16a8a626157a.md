### Title
Push-Transfer in `collectFees` Bricks Fee Management When `adminFeeDestination` Is USDC-Blacklisted — (`File: metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

`MetricOmmPool.collectFees()` uses push-style `safeTransfer` to send accrued fees to `adminFeeDestination_`. Three factory-level operations — `collectPoolFees`, `setPoolAdminFees`, and `setPoolProtocolFee` — all call `collectFees` as a mandatory prerequisite. If the stored `adminFeeDestination` is USDC-blacklisted by Circle, every one of those calls reverts, permanently freezing accrued protocol and admin fees inside the pool and blocking the factory owner from updating protocol fee rates.

---

### Finding Description

`MetricOmmPool.collectFees` performs two push transfers before clearing the notional-fee accumulators:

```solidity
if (totalFee0ToAdmin > 0) {
    transferToken0(adminFeeDestination_, totalFee0ToAdmin);   // push to admin dest
}
if (totalFee1ToAdmin > 0) {
    transferToken1(adminFeeDestination_, totalFee1ToAdmin);   // push to admin dest
}
if (totalFee0ToProtocol > 0) {
    transferToken0(FACTORY, totalFee0ToProtocol);
}
if (totalFee1ToProtocol > 0) {
    transferToken1(FACTORY, totalFee1ToProtocol);
}
notionalFeeToken0Scaled = 0;
notionalFeeToken1Scaled = 0;
``` [1](#0-0) 

`transferToken0/1` resolve to `IERC20.safeTransfer`, which reverts if the recipient is USDC-blacklisted. [2](#0-1) 

All three factory entry-points that touch fees call `collectFees` unconditionally before making any state change:

**`collectPoolFees`** (callable by anyone): [3](#0-2) 

**`setPoolAdminFees`** (pool admin): [4](#0-3) 

**`setPoolProtocolFee`** (factory owner): [5](#0-4) 

If `adminFeeDestination` is blacklisted, all three revert at the `collectFees` call, before any storage is updated.

The only escape hatch is `setPoolAdminFeeDestination`, which updates the destination without calling `collectFees`: [6](#0-5) 

However, this requires the pool admin to be reachable and responsive. If the pool admin's own address is also blacklisted or the admin key is lost, there is no recovery path and fees are permanently frozen.

---

### Impact Explanation

- **Protocol and admin fees are frozen** inside the pool for the duration of the blacklisting. `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` are never zeroed, so the surplus accounting diverges from actual balances over time.
- **Factory owner cannot update protocol fee rates** for the affected pool via `setPoolProtocolFee` — a governance operation is blocked by an external token-level condition.
- **Pool admin cannot update admin fee rates** via `setPoolAdminFees`.
- Swaps, liquidity add/remove, and pausing are unaffected; only fee management is bricked.

---

### Likelihood Explanation

USDC is explicitly listed as a pool token in the protocol's target deployment context. Circle's blacklisting is an external, non-malicious event (e.g., a treasury address flagged by OFAC). The `adminFeeDestination` is a long-lived address set at pool creation and changed infrequently, making it a realistic target. The trigger requires no attacker — only an external regulatory action against the destination address.

---

### Recommendation

Decouple fee collection from fee-rate updates. Use a pull model: accumulate owed amounts per recipient in storage and let each party withdraw independently. Alternatively, split `collectFees` into two independent transfers so a failure on the admin leg does not block the protocol leg or the fee-rate update.

---

### Proof of Concept

1. Pool is created with `adminFeeDestination = 0xTreasury` (a USDC-holding address).
2. Swaps accrue spread and notional fees; `notionalFeeToken0Scaled > 0`.
3. Circle blacklists `0xTreasury` (e.g., OFAC action).
4. Anyone calls `factory.collectPoolFees(pool)`:
   - Factory calls `pool.collectFees(..., 0xTreasury)`.
   - Pool computes `totalFee1ToAdmin > 0`, calls `IERC20(USDC).safeTransfer(0xTreasury, amount)`.
   - USDC reverts with "Blacklisted".
   - `collectPoolFees` reverts; fees remain frozen.
5. Factory owner calls `factory.setPoolProtocolFee(pool, newFee, 0)`:
   - Same `collectFees` call → same revert.
   - Protocol fee rate cannot be updated.
6. Pool admin calls `factory.setPoolAdminFees(pool, newFee, 0)`:
   - Same revert.
7. Pool admin calls `factory.setPoolAdminFeeDestination(pool, 0xNewTreasury)` → succeeds (no `collectFees` call).
8. After step 7, all operations in steps 4–6 succeed again, but all fees accrued during the blacklisting window were inaccessible and the protocol fee rate was frozen for that period.

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L416-430)
```text
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
```

**File:** metric-core/contracts/MetricOmmPool.sol (L565-571)
```text
  function transferToken0(address to, uint256 amount) internal {
    IERC20(TOKEN0).safeTransfer(to, amount);
  }

  function transferToken1(address to, uint256 amount) internal {
    IERC20(TOKEN1).safeTransfer(to, amount);
  }
```

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
