After thorough analysis of the Metric OMM codebase, I found a valid analog.

---

### Title
Permissionless `register()` Unconditionally Clears Admin Blacklist, Making Oracle Access Irrevocable — (`smart-contracts-poc/contracts/oracles/providers/OracleBase.sol`)

### Summary

`OracleBase.register()` is permissionless and unconditionally clears `blacklisted[pool]` whenever called with the minimum fee. Because `registeredPool[feedId][pool]` can only ever be set to `true` (there is no `unregister()` path), the blacklist is the sole documented emergency mechanism to stop a pool from reading oracle prices. However, any actor can pay 1 wei to call `register()` and immediately restore oracle access to a pool the admin intentionally blacklisted, making the emergency control ineffective.

### Finding Description

`OracleBase` maintains two state variables relevant to pool oracle access:

```
mapping(bytes32 => mapping(address => bool)) public registeredPool;
mapping(address => bool) public blacklisted;
```

`register()` is the only function that writes to `registeredPool`: [1](#0-0) 

It sets `registeredPool[feedId][pool] = true` and, critically, **unconditionally clears the blacklist** on the pool if it is set. There is no `unregister()` function anywhere in `OracleBase` — once `registeredPool[feedId][pool]` is `true`, it can never be set back to `false`.

The `price()` read path enforces both checks: [2](#0-1) 

The protocol's own documentation acknowledges the blacklist as the intended emergency response: *"Misuse → maintainer blacklists the pool (observed via PriceRead events) → recovery requires paying the fee again."* [3](#0-2) 

The flaw is that `register()` has no access control and no check for whether the caller is authorized to clear a blacklist. The `registrationFee` defaults to 1 wei: [4](#0-3) 

**Attack path:**
1. Pool `P` is registered for `feedId` via `register()`.
2. Pool `P` is being exploited (e.g., oracle prices are being consumed to execute bad-price swaps draining LP funds).
3. Admin calls `setBlacklist(P, true)` to stop `P` from reading prices.
4. Attacker calls `register(feedId, P, approvedFactory)` with 1 wei.
5. `blacklisted[P]` is set back to `false`; `P` can read prices again immediately.
6. Exploitation continues.

The `register()` function has no `notBlacklisted` modifier on `msg.sender` and no guard preventing it from clearing an admin-set blacklist: [5](#0-4) 

### Impact Explanation

The admin's only on-chain lever to stop a live pool from consuming oracle prices is the blacklist. Because `register()` clears it permissionlessly for 1 wei, the admin cannot reliably halt oracle access for a pool that is actively being exploited. Swaps in the pool continue to execute at oracle-derived bid/ask prices, and LP principal continues to be drained for as long as the attacker keeps re-registering. This is a direct loss of user principal (LP assets) caused by a broken admin-boundary control.

### Likelihood Explanation

Medium. The precondition is an active exploitation scenario where the admin has blacklisted a pool. The attacker's cost to bypass the blacklist is 1 wei (the default `registrationFee`). The factory and pool addresses are public on-chain, so the attacker can construct the `register()` call trivially. The admin has no on-chain way to prevent re-registration short of removing the factory from `approvedFactories` (which blocks all new registrations, not just the attacker's) or raising `registrationFee` to an economically prohibitive level — neither of which is a targeted, surgical fix.

### Recommendation

1. **Add an admin-only `unregister()` function** that sets `registeredPool[feedId][pool] = false`, giving the admin a direct, irrevocable way to revoke oracle access without relying on the blacklist.

2. **Separate blacklist-clearing from `register()`**: do not clear `blacklisted[pool]` inside `register()` if the blacklist was set by an admin. One approach is a separate `clearBlacklist(pool)` function that requires admin approval, or a flag distinguishing admin-set blacklists from automatic ones.

3. **Alternatively**, gate `register()` so that it reverts if `blacklisted[pool]` is currently `true`, forcing the admin to explicitly clear the blacklist before re-registration is allowed.

### Proof of Concept

```solidity
// 1. Admin blacklists pool P after detecting exploitation
oracle.setBlacklist(poolP, true);
// oracle.price(feedId, poolP) now reverts with Blacklisted(poolP)

// 2. Attacker re-registers P for 1 wei — no access control, no blacklist guard
oracle.register{value: 1}(feedId, poolP, approvedFactory);
// blacklisted[poolP] == false again

// 3. Pool P can now read prices and continue swapping
// oracle.price(feedId, poolP) succeeds — exploitation resumes
```

The test suite confirms `register()` clears the blacklist unconditionally: [6](#0-5)

### Citations

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L53-53)
```text
        registrationFee = 1 wei; // very cheap default; ADMIN tunes via setRegistrationFee
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

**File:** smart-contracts-poc/contracts/oracles/providers/docs/en/abuse-protection-integration.md (L217-219)
```markdown
- **Economic deterrent.** `registrationFee` defaults to a token `1 wei` — intentionally minimal for
  now; raise it via `setRegistrationFee` if abusers appear. Misuse → maintainer blacklists the pool
  (observed via `PriceRead` events) → recovery requires paying the fee again.
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
