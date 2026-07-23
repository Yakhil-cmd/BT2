### Title
USDC/USDT Blacklisted `adminFeeDestination` Permanently Blocks `collectFees`, `setPoolAdminFees`, and `setPoolProtocolFee` — (`metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

`collectFees()` in `MetricOmmPool` pushes tokens directly to `adminFeeDestination_` and `FACTORY` via `safeTransfer`. If either address is on the USDC or USDT blacklist, every call to `collectFees` reverts. Because `setPoolAdminFees` and `setPoolProtocolFee` in the factory both call `collectFees` as a mandatory first step before updating fee rates, those management functions are also bricked for as long as the blacklisted address remains the destination.

---

### Finding Description

`collectFees` in `MetricOmmPool.sol` performs four sequential `safeTransfer` calls — two to `adminFeeDestination_` and two to the immutable `FACTORY` address:

```solidity
// MetricOmmPool.sol lines 416-427
if (totalFee0ToAdmin > 0) {
    transferToken0(adminFeeDestination_, totalFee0ToAdmin);   // safeTransfer
}
if (totalFee1ToAdmin > 0) {
    transferToken1(adminFeeDestination_, totalFee1ToAdmin);   // safeTransfer
}
if (totalFee0ToProtocol > 0) {
    transferToken0(FACTORY, totalFee0ToProtocol);             // safeTransfer
}
if (totalFee1ToProtocol > 0) {
    transferToken1(FACTORY, totalFee1ToProtocol);             // safeTransfer
}
notionalFeeToken0Scaled = 0;   // only reached if all transfers succeed
notionalFeeToken1Scaled = 0;
```

USDC and USDT implement a blacklist that causes `transfer`/`transferFrom` to revert for blacklisted addresses. If `adminFeeDestination_` is blacklisted, the first non-zero admin transfer reverts, rolling back the entire call before `notionalFeeToken0Scaled`/`notionalFeeToken1Scaled` are zeroed.

Three factory entry-points are affected:

| Factory function | Who calls it | Effect when blocked |
|---|---|---|
| `collectPoolFees` (line 379) | Anyone | Fee distribution permanently reverts |
| `setPoolAdminFees` (line 408) | Pool admin | Cannot update admin fee rates |
| `setPoolProtocolFee` (line 318) | Protocol owner | Cannot update protocol fee rates |

Both `setPoolAdminFees` and `setPoolProtocolFee` call `collectFees` unconditionally before writing new fee values. A blacklisted `adminFeeDestination` therefore prevents the protocol owner from adjusting protocol fees on that pool, even though the protocol owner has no control over the admin's fee destination.

`setPoolAdminFeeDestination` (line 438) does **not** call `collectFees`, so the pool admin retains the ability to rotate the destination address. However, until that rotation is executed, all three functions above are bricked and accrued fees remain locked in the pool.

---

### Impact Explanation

- **Accrued protocol and admin fees are locked** in the pool for the duration of the blacklisting. `notionalFeeToken0Scaled`/`notionalFeeToken1Scaled` are never zeroed, so the surplus accounting is correct but the tokens cannot leave the pool.
- **Fee rate management is broken**: neither the pool admin (`setPoolAdminFees`) nor the protocol owner (`setPoolProtocolFee`) can update fee parameters while the destination is blacklisted, because both functions gate on a successful `collectFees` call first.
- The protocol owner has **no independent recovery path** — they cannot override `adminFeeDestination`; only the pool admin can call `setPoolAdminFeeDestination`.

---

### Likelihood Explanation

- USDC and USDT are the most common pool tokens in DeFi and are explicitly in scope per the allowed-impact gate.
- `adminFeeDestination` is a treasury or multisig address chosen by the pool admin. Such addresses can be sanctioned (OFAC, Circle blacklist) without any malicious intent by the admin.
- The pool admin may not immediately notice the blacklisting, leaving fee collection and fee management blocked for an extended period.
- No privileged or malicious setup is required; the blacklisting is an external action by Circle/Tether.

---

### Recommendation

Decouple token delivery from the fee-accounting state update. Zero `notionalFeeToken0Scaled`/`notionalFeeToken1Scaled` and credit internal balance variables **before** attempting transfers, then allow the admin and protocol to claim their respective shares in separate pull-based calls. Alternatively, if push semantics are kept, catch transfer failures per-leg and record uncollected amounts for later retry, so a single blacklisted address cannot block the other leg or the fee-rate update path.

---

### Proof of Concept

1. Deploy a pool with USDC as `token0`.
2. Set `adminFeeDestination` to address `A`.
3. Conduct swaps so that `notionalFeeToken0Scaled > 0` and spread surplus accumulates.
4. USDC blacklists address `A` (e.g., via Circle's compliance process).
5. Call `factory.collectPoolFees(pool)` → reverts at `transferToken0(adminFeeDestination_, ...)` because USDC's `transfer` reverts for blacklisted recipients.
6. Call `factory.setPoolAdminFees(pool, newSpread, newNotional)` → same revert; admin fee rates cannot be updated.
7. Call `factory.setPoolProtocolFee(pool, newSpread, newNotional)` (as protocol owner) → same revert; protocol fee rates cannot be updated.
8. Fees remain locked in the pool. The protocol owner cannot act unilaterally; only the pool admin can unblock by calling `setPoolAdminFeeDestination(pool, nonBlacklistedAddress)` first.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-435)
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

    c.adminSpreadFeeE6 = newAdminSpreadFeeE6;
    c.adminNotionalFeeE8 = newAdminNotionalFeeE8;
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
    emit PoolAdminSpreadFeeUpdated(pool, newAdminSpreadFeeE6);
    emit PoolAdminNotionalFeeUpdated(pool, newAdminNotionalFeeE8);
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
