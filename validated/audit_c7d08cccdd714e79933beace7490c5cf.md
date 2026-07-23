### Title
`collectFees` Bundles Admin and Protocol Transfers Atomically — USDC/USDT Blacklisted `adminFeeDestination` Permanently Blocks Protocol Fee Collection and Fee-Rate Updates - (File: metric-core/contracts/MetricOmmPool.sol)

### Summary

`MetricOmmPool.collectFees` executes four sequential `safeTransfer` calls — two to `adminFeeDestination_` and two to `FACTORY` — inside a single atomic function. If the first admin-leg transfer reverts (e.g., USDC/USDT blacklists the `adminFeeDestination`), the entire call reverts: protocol fees are never sent to `FACTORY`, `notionalFeeToken0Scaled`/`notionalFeeToken1Scaled` are never cleared, and every factory path that calls `collectFees` as a prerequisite (`collectPoolFees`, `setPoolAdminFees`, `setPoolProtocolFee`) is permanently bricked for that pool until the pool admin voluntarily rotates the destination.

### Finding Description

`MetricOmmPool.collectFees` (lines 416–430) performs four sequential token transfers with no independent failure isolation:

```solidity
if (totalFee0ToAdmin > 0) {
    transferToken0(adminFeeDestination_, totalFee0ToAdmin);   // ← reverts here
}
if (totalFee1ToAdmin > 0) {
    transferToken1(adminFeeDestination_, totalFee1ToAdmin);
}
if (totalFee0ToProtocol > 0) {
    transferToken0(FACTORY, totalFee0ToProtocol);             // ← never reached
}
if (totalFee1ToProtocol > 0) {
    transferToken1(FACTORY, totalFee1ToProtocol);
}
notionalFeeToken0Scaled = 0;   // ← never cleared
notionalFeeToken1Scaled = 0;
```

USDC and USDT revert on transfers to blacklisted addresses. If `adminFeeDestination_` (sourced from `poolAdminFeeDestination[pool]`) is blacklisted at the time of the call, the first `safeTransfer` reverts and the entire function reverts.

Three factory entry points call `collectFees` as a mandatory first step before updating state:

- `collectPoolFees` — callable by anyone, permanently fails.
- `setPoolAdminFees` — pool admin cannot change fee rates.
- `setPoolProtocolFee` — protocol owner cannot update protocol fees for this pool.

The protocol owner has no path to override `poolAdminFeeDestination`; only the pool admin can call `setPoolAdminFeeDestination`. If the pool admin is unwilling or unable (e.g., lost multisig key, compromised contract), the DoS is indefinite.

### Impact Explanation

- **Protocol fees are frozen in the pool.** Accrued spread and notional fees cannot be extracted to `FACTORY` for any amount of time the destination remains blacklisted.
- **`setPoolProtocolFee` is bricked for the affected pool.** The protocol owner cannot adjust protocol fee rates, losing the ability to respond to market conditions or governance decisions for that pool.
- **`setPoolAdminFees` is bricked.** The pool admin cannot lower or raise their own fee rates.
- **`notionalFeeToken0Scaled`/`notionalFeeToken1Scaled` are never reset**, so subsequent `collectFees` attempts will re-compute fees on the same accumulated notional balance, compounding the accounting inconsistency.

No LP principal is at risk and swaps/liquidity operations are unaffected, placing this at **Medium** severity.

### Likelihood Explanation

USDC and USDT are the most common pool tokens in DeFi. USDC's blacklist is actively maintained by Circle. A pool admin fee destination that is a smart contract (e.g., a yield aggregator, a DAO treasury) can be blacklisted after pool creation without any action by the pool admin. The pool admin's only recourse is `setPoolAdminFeeDestination`, which does not call `collectFees` and is therefore always executable — but requires the pool admin to act. If the pool admin is a lost or compromised multisig, the DoS is permanent.

### Recommendation

Decouple admin and protocol fee transfers so that a failure on one leg does not block the other. Two approaches:

1. **Split into independent transfers with try/catch or separate functions.** Wrap each `safeTransfer` in a try/catch and record uncollected amounts for a pull-based fallback, analogous to `returnPostponedCollateral` in the Frankencoin reference.

2. **Collect protocol fees first, then admin fees.** Reorder the transfers so protocol fees to `FACTORY` are sent before admin fees to `adminFeeDestination_`. A revert on the admin leg will still block the call, but at least the protocol leg can be separated into a dedicated `collectProtocolFees` function callable by the owner independently of the admin destination.

3. **Add a factory-owner escape hatch** — a `collectProtocolFeesOnly(address pool)` function callable by `onlyOwner` that bypasses the admin transfer entirely, sending only the protocol share to `FACTORY` and recording the admin share for later pull.

### Proof of Concept

1. Deploy a USDC/USDT pool with `adminFeeDestination = 0xAlice`.
2. Swaps accrue spread and notional fees; `notionalFeeToken0Scaled > 0`.
3. USDC blacklists `0xAlice` (e.g., due to sanctions).
4. Anyone calls `collectPoolFees(pool)` → calls `collectFees(...)` → `safeTransfer(USDC, 0xAlice, amount)` reverts → entire call reverts.
5. Protocol owner calls `setPoolProtocolFee(pool, newFee, newFee)` → same revert path → protocol cannot update fees.
6. Pool admin calls `setPoolAdminFees(pool, newFee, newFee)` → same revert path → admin cannot update fees.
7. `notionalFeeToken0Scaled` remains non-zero; protocol fees remain locked in the pool indefinitely. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
