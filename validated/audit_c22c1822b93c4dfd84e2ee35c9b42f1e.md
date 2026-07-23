### Title
Blacklisted `adminFeeDestination` Permanently Bricks Protocol Fee Collection and Fee-Rate Updates - (File: `metric-core/contracts/MetricOmmPool.sol`, `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`collectFees` in `MetricOmmPool` atomically pushes tokens to both `adminFeeDestination_` and `FACTORY` in a single transaction. If the pool token is USDC/USDT and `adminFeeDestination` is a blacklisted address, every call to `collectFees` reverts. Because `setPoolAdminFees` (pool admin) and `setPoolProtocolFee` (factory owner) both unconditionally invoke `collectFees` before writing new fee rates, a blacklisted destination permanently blocks all fee collection and all fee-rate governance for that pool.

---

### Finding Description

`MetricOmmPool.collectFees` performs four sequential `safeTransfer` calls:

```solidity
if (totalFee0ToAdmin > 0) {
    transferToken0(adminFeeDestination_, totalFee0ToAdmin);   // ← reverts if blacklisted
}
if (totalFee1ToAdmin > 0) {
    transferToken1(adminFeeDestination_, totalFee1ToAdmin);   // ← reverts if blacklisted
}
if (totalFee0ToProtocol > 0) {
    transferToken0(FACTORY, totalFee0ToProtocol);
}
if (totalFee1ToProtocol > 0) {
    transferToken1(FACTORY, totalFee1ToProtocol);
}
``` [1](#0-0) 

`transferToken0/1` use `safeTransfer`, which reverts on failure. [2](#0-1) 

Every factory-level path that needs to collect or change fees calls `collectFees` first with no bypass:

- **`collectPoolFees`** (permissionless): calls `collectFees` directly.
- **`setPoolAdminFees`** (pool admin): calls `collectFees` before writing new rates.
- **`setPoolProtocolFee`** (factory owner): calls `collectFees` before writing new rates. [3](#0-2) [4](#0-3) [5](#0-4) 

`poolAdminFeeDestination` is set at pool creation and can be updated by the pool admin via `setPoolAdminFeeDestination`, which only checks `!= address(0)` — no blacklist guard exists. [6](#0-5) 

If `adminFeeDestination` is a USDC-blacklisted address (set at creation or later by the pool admin), every call to `collectFees` reverts, which means:

1. `collectPoolFees` (permissionless keeper path) is permanently DoS'd.
2. `setPoolAdminFees` is permanently DoS'd — the pool admin cannot change their own fee rates.
3. `setPoolProtocolFee` is permanently DoS'd — the factory owner cannot update protocol fee rates for this pool.

Protocol fees (spread surplus and notional accumulator) continue to accrue inside the pool but can never be extracted. The factory owner has no alternative path to collect protocol fees or update fee rates without the pool admin first calling `setPoolAdminFeeDestination` to a valid address.

---

### Impact Explanation

- **Protocol fee loss**: Accrued spread surplus and `notionalFeeToken0/1Scaled` accumulate indefinitely in the pool with no extraction path. This is a direct loss of owed protocol fee revenue.
- **Governance freeze**: The factory owner's `setPoolProtocolFee` — the primary mechanism for adjusting protocol revenue per pool — is blocked. The pool admin's `setPoolAdminFees` is equally blocked.
- **Permissionless collection DoS**: `collectPoolFees` is a documented keeper/bot path; its failure means protocol fees are never swept to the factory for treasury use.

---

### Likelihood Explanation

- USDC and USDT are the most common pool tokens on the target chains (Base, Ethereum, HyperEVM) and both implement address blacklists.
- `adminFeeDestination` can be any address set at pool creation or later by the pool admin. A multisig or smart contract wallet used as the destination could be blacklisted by USDC at any time (e.g., OFAC compliance action).
- The pool admin is semi-trusted; a malicious admin can deliberately set a known-blacklisted address as the destination to freeze protocol fee collection and block the factory owner from adjusting protocol fees.
- The only recovery path is the pool admin calling `setPoolAdminFeeDestination` to a valid address — if the admin is unresponsive or malicious, the factory owner has no unilateral remedy.

---

### Recommendation

Decouple fee collection from fee-rate updates. Two options:

1. **Pull pattern for admin fees**: Instead of pushing tokens to `adminFeeDestination_` inside `collectFees`, credit an internal balance mapping (`adminFeeBalance[token]`) and let the admin pull separately. This mirrors the Teller fix (escrow/pull pattern) and ensures a blacklisted destination cannot block protocol fee collection or rate changes.

2. **Separate collect from update**: Allow `setPoolAdminFees` and `setPoolProtocolFee` to skip the `collectFees` call (or make it a best-effort `try/catch`) so fee-rate governance is never gated on a successful token transfer.

---

### Proof of Concept

1. Deploy a USDC/WETH pool with `adminFeeDestination = 0xDeadBeef` (a USDC-blacklisted address).
2. Execute several swaps so spread surplus and `notionalFeeToken0Scaled` accumulate.
3. Call `collectPoolFees(pool)` → reverts because `transferToken0(0xDeadBeef, ...)` fails USDC blacklist check.
4. Factory owner calls `setPoolProtocolFee(pool, newFee, newFee)` → same revert at the mandatory `collectFees` call on line 328–335.
5. Pool admin calls `setPoolAdminFees(pool, newFee, newFee)` → same revert at the mandatory `collectFees` call on line 418–425.
6. Protocol fees remain locked in the pool; fee rates cannot be changed until the pool admin calls `setPoolAdminFeeDestination` to a non-blacklisted address. [7](#0-6) [8](#0-7) [9](#0-8)

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
