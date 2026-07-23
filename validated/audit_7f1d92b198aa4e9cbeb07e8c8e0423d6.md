The code is clear. Let me trace the exact path:

**`register()` at line 201** is `external payable` with zero role restriction. The only guards are:
1. `msg.value >= registrationFee` — default **1 wei** [1](#0-0) 
2. `approvedFactories.contains(factory)` — factory must be ADMIN-approved [2](#0-1) 
3. `IPoolFactory(factory).isPool(pool)` — pool must be recognized by that factory [3](#0-2) 

Then unconditionally, if the pool is blacklisted, it is **cleared**:

```solidity
if (blacklisted[pool]) {
    blacklisted[pool] = false;
    emit BlacklistUpdated(pool, false);
}
``` [4](#0-3) 

A pool that was blacklisted was, by definition, previously registered — meaning it came from an approved factory and `isPool()` still returns `true` for it. Both guards pass trivially. The NatDoc on `register` even documents this: *"Paying also clears any blacklist on the pool."* [5](#0-4) 

The `price()` function enforces `!blacklisted[pool]` at line 167, which is the sole enforcement point of the blacklist for pool reads. [6](#0-5) 

This is a real, direct bypass of an ADMIN security control by an unprivileged path — fitting the contest's "Admin-boundary break: factory/oracle role checks are bypassed by an unprivileged path" criterion.

---

### Title
Unprivileged `register()` caller can clear ADMIN blacklist for 1 wei, re-enabling oracle reads for any blacklisted pool — (`smart-contracts-poc/contracts/oracles/providers/OracleBase.sol`)

### Summary
`OracleBase.register()` is a permissionless payable function that unconditionally clears `blacklisted[pool]` when the pool is blacklisted. Because a blacklisted pool was already registered from an approved factory, all guards in `register()` pass trivially, letting any attacker pay 1 wei to nullify the ADMIN's blacklist decision.

### Finding Description
`OracleBase.setBlacklist()` is `onlyRole(ADMIN_ROLE)` and is the intended mechanism for the ADMIN to revoke oracle-read access from an abusive pool. [7](#0-6) 

However, `register()` has no role check and explicitly clears the blacklist flag as a side-effect of re-registration. [4](#0-3) 

Since a blacklisted pool:
- originated from an approved factory (guard at line 204 passes),
- is still recognized by `isPool()` (guard at line 205 passes),
- and `registrationFee` defaults to 1 wei,

any EOA can call `register(feedId, blacklistedPool, approvedFactory)` with 1 wei and immediately restore the pool's ability to call `price(feedId, pool)`.

### Impact Explanation
The blacklist is the oracle's sole mechanism to cut off an abusive or compromised pool from reading prices. Once bypassed, the pool can resume calling `price()` during swaps. If the pool was blacklisted because it was causing bad-price execution (e.g., reading prices outside normal swap context, or a pool whose admin was manipulating parameters), it can immediately resume doing so. This constitutes an **admin-boundary break** — an unprivileged path nullifies an ADMIN-only security control — and can lead to bad-price execution reaching live swaps.

### Likelihood Explanation
Likelihood is **high**: the attacker needs only 1 wei and a standard EOA. No special role, no privileged access, no complex setup. The blacklisted pool's factory is already approved and `isPool()` still returns `true`. The attack is repeatable every time the ADMIN re-blacklists the pool.

### Recommendation
Remove the blacklist-clearing side-effect from `register()`. Blacklist management must remain exclusively in `setBlacklist()` (ADMIN-only). If re-registration of a blacklisted pool should be allowed, it must require explicit ADMIN approval, not a 1-wei payment.

```solidity
// Remove lines 207-210 entirely:
// if (blacklisted[pool]) {
//     blacklisted[pool] = false;
//     emit BlacklistUpdated(pool, false);
// }

// Optionally, add an explicit guard:
require(!blacklisted[pool], Blacklisted(pool));
```

### Proof of Concept
```solidity
// 1. ADMIN blacklists pool
oracle.setBlacklist(pool, true);
assert(oracle.blacklisted(pool) == true);

// 2. Attacker (any EOA) calls register with 1 wei
oracle.register{value: 1 wei}(feedId, pool, approvedFactory);

// 3. Blacklist is cleared
assert(oracle.blacklisted(pool) == false);

// 4. Pool can now read prices again during swap
// pool.inSwap() == priceProvider (msg.sender in price())
(uint256 mid,,,) = oracle.price(feedId, pool); // succeeds
```

### Citations

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L167-168)
```text
        require(!blacklisted[pool], Blacklisted(pool));
        require(registeredPool[feedId][pool], NotRegistered(feedId, pool));
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L196-200)
```text
    /// @notice Permissionless paid registration: whitelist `pool` for `feedId` (required to use the
    ///         on-chain price(feedId, factory) path). `factory` must be approved and recognize `pool`
    ///         via isPool. Paying also clears any blacklist on the pool.
    /// @dev    Overpayment is NOT refunded: any msg.value above registrationFee is kept and is
    ///         withdrawable by ADMIN via withdrawEth. This is intentional.
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L202-202)
```text
        require(msg.value >= registrationFee, InsufficientFee(msg.value, registrationFee));
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L204-204)
```text
        require(approvedFactories.contains(factory), FactoryNotApproved(factory));
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L205-205)
```text
        require(IPoolFactory(factory).isPool(pool), NotAPool(pool));
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L207-210)
```text
        if (blacklisted[pool]) {
            blacklisted[pool] = false;
            emit BlacklistUpdated(pool, false);
        }
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
