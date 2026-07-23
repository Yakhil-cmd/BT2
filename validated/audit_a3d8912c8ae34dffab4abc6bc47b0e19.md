### Title
`collectFees()` push-transfer to `adminFeeDestination_` is blocked by USDC blacklist, permanently freezing protocol and admin fee collection — (`metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

`collectFees()` in `MetricOmmPool` uses a push-payment pattern to send accrued fees directly to `adminFeeDestination_` via `safeTransfer`. If that address is added to the USDC (or any blacklist-capable token) blacklist, every call to `collectFees()` reverts. Because `setPoolProtocolFee()` and `setPoolAdminFees()` in the factory both call `collectFees()` as a mandatory first step before updating fee rates, those management functions are also bricked for the affected pool.

---

### Finding Description

`collectFees()` in `MetricOmmPool.sol` pushes tokens directly to `adminFeeDestination_`:

```solidity
if (totalFee0ToAdmin > 0) {
    transferToken0(adminFeeDestination_, totalFee0ToAdmin);   // line 417
}
if (totalFee1ToAdmin > 0) {
    transferToken1(adminFeeDestination_, totalFee1ToAdmin);   // line 420
}
``` [1](#0-0) 

The state update that zeros out the notional fee accumulators only executes **after** both transfers succeed:

```solidity
notionalFeeToken0Scaled = 0;
notionalFeeToken1Scaled = 0;
``` [2](#0-1) 

If `adminFeeDestination_` is USDC-blacklisted, `safeTransfer` reverts, the entire `collectFees()` call reverts, and the accumulators are never cleared. All three factory entry-points that invoke `collectFees()` are then blocked:

1. **`collectPoolFees()`** — permissionless, callable by anyone: [3](#0-2) 

2. **`setPoolProtocolFee()`** — called by the factory owner to update protocol fee rates; calls `collectFees()` before applying the new rates: [4](#0-3) 

3. **`setPoolAdminFees()`** — called by the pool admin to update admin fee rates; also calls `collectFees()` first: [5](#0-4) 

`setPoolAdminFeeDestination()` does **not** call `collectFees()` first, so the pool admin can update the destination address to recover — but only after the damage window has passed: [6](#0-5) 

---

### Impact Explanation

While the pool admin can eventually recover by calling `setPoolAdminFeeDestination()` to point to a non-blacklisted address, during the blacklisting window:

- All accrued spread fees (surplus balance above bin totals) and notional fees (`notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`) are frozen in the pool and cannot be extracted by either the protocol or the admin.
- The factory owner cannot execute `setPoolProtocolFee()` to adjust protocol fee rates for the affected pool.
- The pool admin cannot execute `setPoolAdminFees()` to adjust their own fee rates.

This constitutes a direct, quantifiable loss of protocol fees and a broken fee-management flow for the pool.

---

### Likelihood Explanation

USDC and USDT both maintain on-chain blacklists. An `adminFeeDestination` address can be blacklisted if it is associated with a sanctioned entity (e.g., OFAC designation, exchange hack proceeds). The pool admin sets `adminFeeDestination` at creation and can update it, but there is no validation that the address is not already blacklisted, and no guard against future blacklisting. The scenario is realistic for any pool whose admin fee destination is a hot wallet or exchange address.

---

### Recommendation

Replace the push-payment pattern in `collectFees()` with a pull-payment (claimable balance) pattern: instead of transferring directly to `adminFeeDestination_` and `FACTORY`, credit internal balance mappings and let each party withdraw separately. Alternatively, wrap each transfer in a `try/catch` and emit an event on failure so that fees can be re-attempted after the destination is updated.

---

### Proof of Concept

1. Deploy a pool with `token0 = USDC`, `adminFeeDestination = 0xABCD` (a normal address).
2. Execute swaps so that `notionalFeeToken0Scaled > 0` and spread surplus accumulates.
3. USDC/Circle blacklists `0xABCD`.
4. Call `collectPoolFees(pool)` → reverts at `transferToken0(adminFeeDestination_, totalFee0ToAdmin)` because USDC's `transfer` reverts for blacklisted recipients.
5. Factory owner calls `setPoolProtocolFee(pool, newFee, newFee)` → also reverts at the same point inside `collectFees()`.
6. Pool admin calls `setPoolAdminFees(pool, 0, 0)` (attempting to zero out admin fees to unblock) → also reverts.
7. All accrued fees remain frozen in the pool until the pool admin separately calls `setPoolAdminFeeDestination(pool, newAddress)` and then re-triggers fee collection.

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L416-421)
```text
      if (totalFee0ToAdmin > 0) {
        transferToken0(adminFeeDestination_, totalFee0ToAdmin);
      }
      if (totalFee1ToAdmin > 0) {
        transferToken1(adminFeeDestination_, totalFee1ToAdmin);
      }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L429-430)
```text
      notionalFeeToken0Scaled = 0;
      notionalFeeToken1Scaled = 0;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L318-336)
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
