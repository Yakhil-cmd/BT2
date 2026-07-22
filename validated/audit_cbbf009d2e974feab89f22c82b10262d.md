The vulnerability claim is valid. Here is the analysis:

**Core mechanism:** `OracleBase` inherits OpenZeppelin's `Multicall` (line 6, 18), whose `multicall` function executes each sub-call via `delegatecall`. Under EVM semantics, `delegatecall` preserves the outer call's `msg.value` in every sub-call's context. The `register` function checks `msg.value >= registrationFee` (line 202), but since all N delegatecalls share the same `msg.value`, the check passes N times while only `registrationFee` ETH was actually transferred.

---

### Title
`msg.value` Reuse Across `multicall` Delegatecalls Allows Bypassing `registrationFee` in `OracleBase.register` — (`smart-contracts-poc/contracts/oracles/providers/OracleBase.sol`)

### Summary
`OracleBase` inherits OpenZeppelin's `Multicall`, which executes sub-calls via `delegatecall`. Because `delegatecall` preserves `msg.value` from the outer call, an attacker can batch N calls to `register` inside a single `multicall` invocation, paying `registrationFee` only once while registering N pools.

### Finding Description
`OracleBase` inherits `Multicall` from OpenZeppelin: [1](#0-0) 

The `register` function is `payable` and enforces a fee check: [2](#0-1) 

OpenZeppelin's `Multicall.multicall` dispatches each call via `delegatecall`. Under EVM rules, `delegatecall` does **not** transfer ETH — it only inherits the caller context including `msg.value`. So when an attacker calls:

```solidity
oracle.multicall{value: registrationFee}([
    abi.encodeCall(oracle.register, (feedId, pool1, factory)),
    abi.encodeCall(oracle.register, (feedId, pool2, factory)),
    // ... × N
]);
```

Each delegatecall'd `register` sees `msg.value == registrationFee` and passes the check, but the contract only received `registrationFee` ETH total. The result: N pools are registered, `registeredPool[feedId][pool_i] == true` for all i, but `address(oracle).balance` increases by only `registrationFee` instead of `N * registrationFee`.

### Impact Explanation
- **Protocol fee revenue is drained**: the economic deterrent against oracle abuse (the registration fee) is completely bypassed. An attacker registers arbitrarily many pools for the cost of one.
- **Pools gain oracle read access without paying**: all N pools can now call `price(feedId, pool_i)` through the on-chain swap path, undermining the abuse-protection model.
- **Direct loss of protocol ETH**: `(N-1) * registrationFee` ETH that should have been collected is never received. When `registrationFee` is set to a meaningful value (e.g., 1 ETH via `setRegistrationFee`), the loss scales linearly with N. [3](#0-2) 

### Likelihood Explanation
- `register` is permissionless — any EOA or contract can call it.
- `multicall` is public and inherited without restriction.
- No special setup is required beyond having N valid pool addresses recognized by an approved factory.
- The attack is a single transaction with no preconditions beyond `msg.value == registrationFee`.

### Recommendation
Remove the `Multicall` inheritance from `OracleBase`, or make `register` non-payable and use a pull-payment pattern (e.g., require a prior `approve` + `transferFrom` of a fee token, or track cumulative ETH received vs. expected). Alternatively, track the ETH balance before and after each sub-call and revert if the balance did not increase by at least `registrationFee` per registration.

A minimal fix: replace the `msg.value` check with a balance-delta check inside `register`:

```solidity
// Before the registration logic:
uint256 _before = address(this).balance - msg.value; // balance before this call
// After: require(address(this).balance - _before >= registrationFee)
```

But the cleanest fix is to remove `Multicall` from `OracleBase` entirely, since `register` is the only payable function and batching it is the attack vector.

### Proof of Concept
```solidity
// Foundry test sketch
function test_multicall_fee_bypass() public {
    uint256 FEE = 1 ether;
    oracle.setRegistrationFee(FEE);

    // Register 100 pools via multicall, paying only 1 × FEE
    bytes[] memory calls = new bytes[](100);
    for (uint i = 0; i < 100; i++) {
        address pool = makeAddr(string(abi.encode(i)));
        factory.setPool(pool, true);
        calls[i] = abi.encodeCall(oracle.register, (FEED, pool, address(factory)));
    }

    oracle.multicall{value: FEE}(calls); // only 1 ETH sent

    // All 100 pools are registered
    for (uint i = 0; i < 100; i++) {
        address pool = makeAddr(string(abi.encode(i)));
        assertTrue(oracle.registeredPool(FEED, pool));
    }

    // But oracle only received 1 ETH, not 100 ETH
    assertEq(address(oracle).balance, FEE);       // 1 ETH
    // Expected: 100 * FEE = 100 ETH — protocol lost 99 ETH
}
``` [4](#0-3)

### Citations

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L6-18)
```text
import { Multicall } from "@openzeppelin/contracts/utils/Multicall.sol";

import { IOffchainOracle } from "../../interfaces/IOffchainOracle.sol";
import { IPoolFactory, IPool } from "../../interfaces/IPoolFactory.sol";
import { TimeMs, toTimeMs } from "../utils/TimeMs.sol";

/// @notice Registrationless base for the provider oracles (Pyth Lazer, Chainlink Data
///         Streams). There is no feed registry and no token metadata: the trust anchor
///         is the provider's own signature verified on every push, so any feed id that
///         arrives in a verified payload is stored. A feed "exists" once it has data
///         (`timestampMs != 0`) — for readers that is indistinguishable from the old
///         "registered" state.
contract OracleBase is AccessControl, Multicall, IOffchainOracle {
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L35-39)
```text
    uint256 public registrationFee;
    EnumerableSet.AddressSet internal approvedFactories;
    EnumerableSet.AddressSet internal integrators;
    mapping(address => bool) public blacklisted;
    mapping(bytes32 => mapping(address => bool)) public registeredPool;
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

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L254-258)
```text
    function setRegistrationFee(uint256 newFee) external onlyRole(ADMIN_ROLE) {
        uint256 oldFee = registrationFee;
        registrationFee = newFee;
        emit RegistrationFeeUpdated(oldFee, newFee);
    }
```
