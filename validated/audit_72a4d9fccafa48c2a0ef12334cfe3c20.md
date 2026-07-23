### Title
`msg.value` Reused Across All `Multicall` Iterations Allows Multi-Pool Registration with a Single Fee Payment — (`smart-contracts-poc/contracts/oracles/providers/OracleBase.sol`)

---

### Summary

`OracleBase` inherits OpenZeppelin's `Multicall`, whose `multicall()` dispatches each sub-call via `address(this).delegatecall(...)`. Because `delegatecall` preserves the caller's `msg.value` in every iteration, a user can batch N calls to the `payable` `register()` function while supplying only one `registrationFee` worth of ETH, registering N pools for the price of one.

---

### Finding Description

`OracleBase` is declared as:

```solidity
contract OracleBase is AccessControl, Multicall, IOffchainOracle {
``` [1](#0-0) 

OpenZeppelin's `Multicall.multicall()` iterates over an array of calldata payloads and executes each one with `address(this).delegatecall(data[i])`. `delegatecall` does **not** consume `msg.value`; it forwards the same `msg.value` from the outer transaction into every inner call.

The `register` function is `payable` and enforces the fee with a single `>=` check:

```solidity
function register(bytes32 feedId, address pool, address factory) external payable {
    require(msg.value >= registrationFee, InsufficientFee(msg.value, registrationFee));
    ...
    registeredPool[feedId][pool] = true;
    emit PoolRegistered(feedId, pool, msg.sender, msg.value);
}
``` [2](#0-1) 

Because the ETH is never transferred out or decremented per iteration — it simply accumulates in the contract — the `msg.value >= registrationFee` guard passes identically on every delegatecall in the batch. An attacker calls:

```
multicall([
    register(feedId1, pool1, factory),
    register(feedId2, pool2, factory),
    ...
    register(feedIdN, poolN, factory)
])
```

with `msg.value = registrationFee` (one fee). All N registrations succeed; the contract receives only one fee instead of N.

---

### Impact Explanation

The `registrationFee` is the protocol's sole on-chain revenue mechanism for oracle read-access control. Bypassing it allows unlimited pool registrations at the cost of a single fee, causing direct loss of protocol fee revenue proportional to `(N − 1) × registrationFee` per exploit transaction. The ADMIN comment explicitly states the fee is tunable upward (`ADMIN tunes via setRegistrationFee`), so the loss scales with the configured fee. [3](#0-2) 

Additionally, the blacklist-clearing side-effect inside `register` (lines 207–210) can be triggered for multiple pools in a single fee payment, undermining the abuse-protection mechanism. [4](#0-3) 

---

### Likelihood Explanation

**High.** The exploit requires no special role, no privileged access, and no unusual token behavior. Any EOA or contract that can call `multicall` with a valid factory and pool addresses can execute it. The `Multicall` function is public and inherited without restriction. [5](#0-4) 

---

### Recommendation

Replace the inherited `Multicall` with a `payable`-safe variant that splits `msg.value` across sub-calls, or — more simply — make `register` non-`payable` and pull the fee via `transferFrom` on a wrapped-ETH or ERC-20 token. Alternatively, track cumulative ETH consumed within a single transaction and revert if the total supplied is less than `N × registrationFee`.

---

### Proof of Concept

```solidity
// Attacker registers 5 pools for the price of 1 fee
bytes[] memory calls = new bytes[](5);
for (uint i = 0; i < 5; i++) {
    calls[i] = abi.encodeCall(
        OracleBase.register,
        (feedIds[i], pools[i], factory)
    );
}
// msg.value == registrationFee (one fee only)
oracle.multicall{value: registrationFee}(calls);
// All 5 registeredPool[feedId][pool] == true
// Contract received only 1× registrationFee instead of 5×
```

Each `delegatecall` inside `multicall` sees `msg.value == registrationFee`, passes the `>=` check, and sets `registeredPool[feedId][pool] = true`. The contract balance increases by only `registrationFee` total, not `5 × registrationFee`. [2](#0-1)

### Citations

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L4-6)
```text
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { Multicall } from "@openzeppelin/contracts/utils/Multicall.sol";
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L18-18)
```text
contract OracleBase is AccessControl, Multicall, IOffchainOracle {
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L53-53)
```text
        registrationFee = 1 wei; // very cheap default; ADMIN tunes via setRegistrationFee
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
