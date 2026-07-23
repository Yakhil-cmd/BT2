### Title
Blacklisted Pool Can Self-Clear Its Blacklist via Permissionless `register()` — (`File: smart-contracts-poc/contracts/oracles/providers/OracleBase.sol`)

---

### Summary

The `OracleBase` abuse-protection system allows an `ADMIN_ROLE` holder to blacklist pools from reading oracle prices. However, the permissionless `register()` function unconditionally clears the blacklist for any pool that pays the `registrationFee` (default: **1 wei**). A blacklisted pool can trivially bypass the blacklist by calling `register()` with 1 wei, restoring its ability to read oracle prices and execute swaps.

---

### Finding Description

`OracleBase` implements a blacklist to prevent abusive or malicious pools from reading oracle prices: [1](#0-0) 

The `price()` function enforces this blacklist on both the caller (price provider) and the pool: [2](#0-1) 

Only `ADMIN_ROLE` can set the blacklist: [3](#0-2) 

However, the permissionless `register()` function explicitly clears the blacklist for any pool that pays the registration fee: [4](#0-3) 

The registration fee defaults to **1 wei** at construction: [5](#0-4) 

The test suite explicitly validates this bypass path under the name `test_register_clearsBlacklist_redemption`, confirming it is an implemented (but insecure) design choice: [6](#0-5) 

The only preconditions for the bypass are that the pool belongs to an approved factory (`approvedFactories.contains(factory)`) and is recognized by it (`IPoolFactory(factory).isPool(pool)`). Both conditions are already satisfied for any legitimately deployed pool — the same pools the admin would blacklist for abuse.

---

### Impact Explanation

A blacklisted pool (blacklisted for oracle abuse, regulatory reasons, or malicious swap behavior) can:

1. Call `register(feedId, pool, approvedFactory)` with 1 wei.
2. `blacklisted[pool]` is set to `false` inside `register()`.
3. The pool is now re-registered for `feedId` and can call `price()` again.
4. The pool resumes reading oracle prices and executing swaps as if it was never blacklisted.

The entire abuse-protection system — the primary security boundary preventing malicious pools from consuming oracle data — is rendered ineffective. Any blacklisting action by the admin can be reversed by the blacklisted pool itself within a single transaction for 1 wei.

---

### Likelihood Explanation

- **Trivially cheap**: The default `registrationFee` is 1 wei. Even if the admin raises it, the pool can still pay and bypass.
- **No privileged access required**: `register()` is fully permissionless for any valid pool from an approved factory.
- **Immediate**: The bypass takes one transaction with no timelock or delay.
- **Repeatable**: The admin can re-blacklist, but the pool can re-register indefinitely.

---

### Recommendation

Remove the automatic blacklist-clearing logic from `register()`. Blacklist state should only be modifiable by `ADMIN_ROLE` via `setBlacklist()`. If a "redemption" path is desired, it should require explicit admin approval, not a permissionless payment.

```solidity
// Remove these lines from register():
if (blacklisted[pool]) {
    blacklisted[pool] = false;
    emit BlacklistUpdated(pool, false);
}
```

Additionally, add an explicit check to prevent blacklisted pools from registering at all:

```solidity
require(!blacklisted[pool], Blacklisted(pool));
```

---

### Proof of Concept

```solidity
// 1. Admin blacklists a malicious pool
oracle.setBlacklist(maliciousPool, true);
assertTrue(oracle.blacklisted(maliciousPool));

// 2. Malicious pool bypasses blacklist via register() with 1 wei
// (factory is already approved; pool is already recognized by factory)
oracle.register{value: 1}(FEED, maliciousPool, approvedFactory);

// 3. Blacklist is cleared — pool can read prices again
assertFalse(oracle.blacklisted(maliciousPool));
assertTrue(oracle.registeredPool(FEED, maliciousPool));

// 4. Pool's price provider can now call price() successfully
vm.prank(priceProvider);
oracle.price(FEED, maliciousPool); // succeeds — blacklist bypassed
```

### Citations

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L53-53)
```text
        registrationFee = 1 wei; // very cheap default; ADMIN tunes via setRegistrationFee
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L76-80)
```text
    modifier notBlacklisted() {
        require(!blacklisted[msg.sender], Blacklisted(msg.sender));

        _;
    }
```

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

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L271-276)
```text
    function setBlacklist(address account, bool value) external onlyRole(ADMIN_ROLE) {
        require(account != address(0));
        if (blacklisted[account] == value) return;
        blacklisted[account] = value;
        emit BlacklistUpdated(account, value);
    }
```

**File:** smart-contracts-poc/test/oracles/OracleBaseAbuseProtection.t.sol (L158-170)
```text
    function test_register_clearsBlacklist_redemption() public {
        address pool = makeAddr("pool");
        factory.setPool(pool, true);
        oracle.setBlacklist(pool, true);
        assertTrue(oracle.blacklisted(pool));

        vm.expectEmit(true, false, false, true);
        emit IOffchainOracle.BlacklistUpdated(pool, false);
        oracle.register{value: 1}(FEED, pool, address(factory));

        assertFalse(oracle.blacklisted(pool));
        assertTrue(oracle.registeredPool(FEED, pool));
    }
```
