I now have enough context to analyze the analog. Let me verify the exact `collectFees` transfer logic and the `setPoolAdminFeeDestination` validation.### Title
Pool Admin Can Permanently Block Protocol Fee Collection and Updates via USDC/USDT-Blacklisted `adminFeeDestination` — (File: metric-core/contracts/MetricOmmPoolFactory.sol)

---

### Summary

`setPoolProtocolFee` and `collectPoolFees` in `MetricOmmPoolFactory` both call `pool.collectFees(…, poolAdminFeeDestination[pool])` before executing their state changes. The pool admin controls `poolAdminFeeDestination` with no validation beyond non-zero. If the pool admin sets this address to one that is USDC/USDT-blacklisted, every `safeTransfer` to that address inside `collectFees` reverts, permanently bricking the factory owner's ability to update protocol fees and blocking all fee collection for the pool.

---

### Finding Description

`setPoolAdminFeeDestination` accepts any non-zero address: [1](#0-0) 

`setPoolProtocolFee` (factory owner, `onlyOwner`) unconditionally calls `collectFees` with the stored destination **before** it can update any fee state: [2](#0-1) 

`collectPoolFees` (callable by anyone) has the same dependency: [3](#0-2) 

Inside `MetricOmmPool.collectFees`, when accumulated admin fees are non-zero, `safeTransfer` is called directly to `adminFeeDestination_`: [4](#0-3) 

USDC and USDT revert on `transfer` to a blacklisted address. Because `safeTransfer` propagates that revert, the entire call stack — `collectFees` → `setPoolProtocolFee` / `collectPoolFees` — reverts. There is no try/catch and no alternative code path.

The factory owner has no mechanism to override `poolAdminFeeDestination`; only the pool admin can change it via `setPoolAdminFeeDestination`. The pool's `FACTORY` immutable is set at construction and cannot be changed, so no new factory can rescue the locked fees. [5](#0-4) 

---

### Impact Explanation

**Protocol fee loss / admin-boundary break (Medium–High).**

1. **Protocol fees permanently locked.** Spread and notional fees accumulate in the pool (`notionalFeeToken0Scaled`, `notionalFeeToken1Scaled`, and the surplus balance) but `collectFees` always reverts, so neither the factory owner nor anyone else can extract them. The factory's `collectTokens` / `collectEth` helpers only drain the factory contract itself, not the pool.
2. **Factory owner cannot update protocol fee rates.** `setPoolProtocolFee` reverts before it reaches `poolFeeConfig[pool] = c` or `pool.setPoolFees(…)`. The factory owner is permanently unable to adjust the protocol's share of fees for this pool.
3. **`setPoolAdminFees` is also bricked** for the same reason, though the pool admin controls both the attack and the remedy for that path.

This satisfies the allowed impact gate: direct loss of owed protocol fees and broken core fee-management functionality caused by a semi-trusted actor exceeding their intended authority boundary.

---

### Likelihood Explanation

- The pool admin is explicitly semi-trusted; the audit scope calls out "fee collection destinations" as an area to examine for bypasses.
- The only guard on `setPoolAdminFeeDestination` is `newAdminFeeDestination != address(0)` — no allowlist, no token-compatibility check.
- USDC and USDT are explicitly in scope for non-standard ERC20 behavior. Both maintain on-chain blacklists; any address can be blacklisted by the token issuer or the pool admin can choose an already-blacklisted address.
- The attack requires a single transaction from the pool admin and is irreversible without the pool admin's cooperation.

---

### Recommendation

Decouple fee collection from fee-rate updates. `setPoolProtocolFee` and `setPoolAdminFees` should update `poolFeeConfig` and call `pool.setPoolFees` without first forcing a `collectFees`. Fee collection should remain a separate, independently callable operation (`collectPoolFees`).

If the forced-collection pattern must be kept, wrap the `collectFees` call in a try/catch and emit an event on failure rather than reverting the entire fee-update transaction:

```solidity
try IMetricOmmPoolCollectFees(pool).collectFees(
    c.protocolSpreadFeeE6, c.adminSpreadFeeE6,
    c.protocolNotionalFeeE8, c.adminNotionalFeeE8,
    poolAdminFeeDestination[pool]
) {} catch {
    emit FeeCollectionSkipped(pool);
}
```

Additionally, consider allowing the factory owner to override `poolAdminFeeDestination` in an emergency, or validate at `setPoolAdminFeeDestination` time that the destination is not a known-blacklisted address (though the latter is impractical on-chain).

---

### Proof of Concept

1. Pool is deployed with USDC as `token0` and non-zero `adminSpreadFeeE6`.
2. Pool accumulates spread fees through normal swap activity (`surplus0Scaled > 0`).
3. Pool admin calls `factory.setPoolAdminFeeDestination(pool, blacklistedUsdcAddress)`.
   - Passes the only guard: `blacklistedUsdcAddress != address(0)`.
4. Factory owner calls `factory.setPoolProtocolFee(pool, newFee, newFee)`.
5. Execution enters `pool.collectFees(…, blacklistedUsdcAddress)`.
6. `totalFee0ToAdmin > 0` → `IERC20(TOKEN0).safeTransfer(blacklistedUsdcAddress, amount)` → USDC reverts with `"Blacklistable: account is blacklisted"`.
7. Entire `setPoolProtocolFee` call reverts. Fee config is unchanged; protocol fees remain locked in the pool indefinitely.
8. `factory.collectPoolFees(pool)` fails identically. [1](#0-0) [6](#0-5) [4](#0-3)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L318-360)
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

    uint24 aSpread = c.adminSpreadFeeE6;
    uint24 aNotional = c.adminNotionalFeeE8;
    if (aSpread > maxAdminSpreadFeeE6) {
      aSpread = maxAdminSpreadFeeE6;
      emit PoolAdminSpreadFeeUpdated(pool, aSpread);
    }
    if (aNotional > maxAdminNotionalFeeE8) {
      aNotional = maxAdminNotionalFeeE8;
      emit PoolAdminNotionalFeeUpdated(pool, aNotional);
    }

    c = PoolFeeConfig({
      protocolSpreadFeeE6: newProtocolSpreadFeeE6,
      adminSpreadFeeE6: aSpread,
      protocolNotionalFeeE8: newProtocolNotionalFeeE8,
      adminNotionalFeeE8: aNotional
    });
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
    emit PoolProtocolSpreadFeeUpdated(pool, newProtocolSpreadFeeE6);
    emit PoolProtocolNotionalFeeUpdated(pool, newProtocolNotionalFeeE8);
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

**File:** metric-core/contracts/MetricOmmPool.sol (L44-44)
```text
  address internal immutable FACTORY;
```

**File:** metric-core/contracts/MetricOmmPool.sol (L416-421)
```text
      if (totalFee0ToAdmin > 0) {
        transferToken0(adminFeeDestination_, totalFee0ToAdmin);
      }
      if (totalFee1ToAdmin > 0) {
        transferToken1(adminFeeDestination_, totalFee1ToAdmin);
      }
```
