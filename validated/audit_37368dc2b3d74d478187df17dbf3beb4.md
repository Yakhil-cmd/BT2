Looking at the codebase for an analog to the "whitelist entry cannot be removed" bug class, I need to examine the `registeredPool` mapping in `OracleBase.sol` and its interaction with the blacklist mechanism.

**Key findings:**

1. `registeredPool[feedId][pool]` can only be set to `true` via `register()` — there is no function to set it to `false`.
2. The only intended mitigation is `setBlacklist(pool, true)` (ADMIN-only).
3. The permissionless `register()` function **clears the blacklist** when called with a valid factory and pool. [1](#0-0) [2](#0-1) 

---

### Title
Permissionless `register()` Clears Oracle Blacklist, Permanently Defeating Admin's Emergency Pool-Removal Mitigation — (File: `smart-contracts-poc/contracts/oracles/providers/OracleBase.sol`)

---

### Summary

`OracleBase.registeredPool[feedId][pool]` can only be set to `true` and never to `false`. The sole admin mitigation for a compromised pool is `setBlacklist(pool, true)`, but the permissionless `register()` function unconditionally clears the blacklist for any pool that is still recognized by an approved factory. Any actor paying as little as 1 wei (the default `registrationFee`) can restore a blacklisted pool's oracle read access.

---

### Finding Description

`OracleBase` gates on-chain oracle price reads through two checks in `price()`:

```solidity
require(!blacklisted[pool], Blacklisted(pool));
require(registeredPool[feedId][pool], NotRegistered(feedId, pool));
``` [3](#0-2) 

The `register()` function is permissionless and explicitly clears the blacklist before writing `registeredPool[feedId][pool] = true`:

```solidity
if (blacklisted[pool]) {
    blacklisted[pool] = false;
    emit BlacklistUpdated(pool, false);
}
registeredPool[feedId][pool] = true;
``` [4](#0-3) 

There is no function anywhere in `OracleBase` that sets `registeredPool[feedId][pool] = false`. The only targeted per-pool mitigation is the blacklist, which is bypassable by anyone who calls `register()` with:
- A factory still present in `approvedFactories`
- A pool still recognized by `IPoolFactory(factory).isPool(pool)`
- `msg.value >= registrationFee` (default: 1 wei)

The admin's only alternative — removing the factory from `approvedFactories` via `removeApprovedFactory()` — is a nuclear option that blocks all pools from that factory, not just the compromised one. [5](#0-4) 

---

### Impact Explanation

During a live exploit of a compromised pool, the oracle admin's only targeted response is to blacklist the pool, cutting off its oracle price feed and halting swaps. Because `register()` clears the blacklist for any pool still in a valid factory, an attacker (or anyone) can restore oracle access for 1 wei, allowing the compromised pool to continue calling `price()` through its price provider, executing swaps, and draining LP assets. The pool calls `IPriceProvider.getBidAndAskPrice()` which calls `OracleBase.price(feedId, pool)` on every swap: [6](#0-5) 

This breaks the admin-boundary invariant: an oracle admin action (blacklist) is bypassed by an unprivileged path, leading to continued loss of LP principal.

---

### Likelihood Explanation

- Requires a pool to be actively exploited (not routine), but once exploitation begins, the bypass costs 1 wei and is callable by anyone — including the attacker themselves.
- The factory remains approved and `isPool()` returns `true` for the compromised pool throughout the attack window, so all preconditions for `register()` are satisfied.

---

### Recommendation

1. **Add a deregistration function** (ADMIN-only) that sets `registeredPool[feedId][pool] = false`, mirroring the pattern already used for `approvedFactories` (`addApprovedFactory` / `removeApprovedFactory`) and `integrators` (`addIntegrator` / `removeIntegrator`):

```solidity
function deregister(bytes32 feedId, address pool) external onlyRole(ADMIN_ROLE) {
    registeredPool[feedId][pool] = false;
    emit PoolDeregistered(feedId, pool, msg.sender);
}
```

2. **Prevent `register()` from clearing the blacklist.** If a pool is blacklisted, `register()` should revert rather than silently clearing the flag:

```solidity
require(!blacklisted[pool], Blacklisted(pool));
```

---

### Proof of Concept

1. Pool `P` is compromised; attacker begins draining LP funds via swaps.
2. Oracle ADMIN calls `setBlacklist(P, true)` — pool's price reads now revert with `Blacklisted`.
3. Attacker calls `register(feedId, P, factory)` with `msg.value = 1 wei`.
   - `approvedFactories.contains(factory)` → `true` (factory not yet removed).
   - `IPoolFactory(factory).isPool(P)` → `true` (pool still registered in factory).
   - `blacklisted[P]` is cleared to `false`.
   - `registeredPool[feedId][P]` is set to `true`.
4. Pool `P` can again call `price(feedId, P)` through its price provider; swaps resume; LP drain continues. [1](#0-0)

### Citations

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L160-172)
```text
    function price(bytes32 feedId, address pool)
        external
        feedExists(feedId)
        notBlacklisted
        returns (uint256 mid, uint256 spread, uint16 spread1, uint256 refTime)
    {
        require(pool != address(0) && IPool(pool).inSwap() == msg.sender, InvalidInSwap());
        require(!blacklisted[pool], Blacklisted(pool));
        require(registeredPool[feedId][pool], NotRegistered(feedId, pool));

        (mid, spread, spread1, refTime) = _readPrice(feedId);
        emit PriceRead(pool, feedId);
    }
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L201-214)
```text
    function register(bytes32 feedId, address pool, address factory) external payable {
        require(msg.value >= registrationFee, InsufficientFee(msg.value, registrationFee));
        require(pool != address(0));
        require(approvedFactories.contains(factory), FactoryNotApproved(factory));
        require(IPoolFactory(factory).isPool(pool), NotAPool(pool));

        if (blacklisted[pool]) {
            blacklisted[pool] = false;
            emit BlacklistUpdated(pool, false);
        }

        registeredPool[feedId][pool] = true;
        emit PoolRegistered(feedId, pool, msg.sender, msg.value);
    }
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L260-268)
```text
    function addApprovedFactory(address factory) external onlyRole(ADMIN_ROLE) {
        require(factory != address(0));
        require(approvedFactories.add(factory), FactoryAlreadyApproved(factory));
        emit ApprovedFactoryAdded(factory);
    }

    function removeApprovedFactory(address factory) external onlyRole(ADMIN_ROLE) {
        require(approvedFactories.remove(factory), FactoryNotApproved(factory));
        emit ApprovedFactoryRemoved(factory);
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L271-276)
```text
    function setBlacklist(address account, bool value) external onlyRole(ADMIN_ROLE) {
        require(account != address(0));
        if (blacklisted[account] == value) return;
        blacklisted[account] = value;
        emit BlacklistUpdated(account, value);
    }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L804-813)
```text
  function _getBidAndAskPriceX64() internal returns (uint128 bidPriceX64, uint128 askPriceX64) {
    address activePriceProvider = _resolvedPriceProvider();
    try IPriceProvider(activePriceProvider).getBidAndAskPrice() returns (uint128 bid, uint128 ask) {
      if (bid >= ask) revert BidGreaterThanAsk();
      if (bid == 0) revert BidIsZero();
      return (bid, ask);
    } catch (bytes memory reason) {
      revert PriceProviderFailed(reason);
    }
  }
```
