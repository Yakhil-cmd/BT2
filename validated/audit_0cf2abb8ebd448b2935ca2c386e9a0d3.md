The vulnerability claim is technically valid. Here is the analysis:

**Core mechanism:** OpenZeppelin's `Multicall` (which `OracleBase` inherits) implements `multicall` using `delegatecall`. Under `delegatecall`, `msg.value` is **not decremented** between sub-calls — every sub-call in the batch sees the same original `msg.value`. The `register` function checks `msg.value >= registrationFee` on each sub-call, but only one `registrationFee` worth of ETH was actually sent.

---

### Title
`msg.value` reuse via `Multicall` delegatecall allows N pool registrations for the price of one — (`smart-contracts-poc/contracts/oracles/providers/OracleBase.sol`)

### Summary
`OracleBase` inherits OpenZeppelin's `Multicall`, which dispatches sub-calls via `delegatecall`. Because `delegatecall` preserves `msg.value` across all sub-calls without decrementing it, an attacker can batch N calls to `register` in a single `multicall` transaction, paying only one `registrationFee` while registering N pools.

### Finding Description
`OracleBase` inherits `Multicall` from OpenZeppelin: [1](#0-0) 

The `register` function is `external payable` and enforces the fee with a single `msg.value` check: [2](#0-1) 

OpenZeppelin's `Multicall.multicall` loops over calldata entries and dispatches each via `delegatecall`. Under `delegatecall`, `msg.value` is inherited from the outer call and is **not consumed or decremented** per sub-call. Therefore, if an attacker sends `multicall([register(f,p1,fac), register(f,p2,fac), ..., register(f,pN,fac)])` with `msg.value = registrationFee`, every sub-call passes the `msg.value >= registrationFee` check, all N `registeredPool[feedId][p_i] = true` writes succeed, and the contract's ETH balance increases by only `registrationFee` instead of `N * registrationFee`. [3](#0-2) 

### Impact Explanation
Protocol registration-fee revenue is drained: N pools gain oracle read access while the contract collects only 1× the fee. The `registrationFee` is explicitly designed as an economic deterrent and revenue source: [4](#0-3) 

When the admin raises `registrationFee` to a meaningful amount (e.g., 1 ETH) to deter abusers, the bypass becomes directly profitable: an attacker registers 100 pools for 1 ETH instead of 100 ETH, draining (N−1)×fee from protocol revenue. The `withdrawEth` sweep collects far less than owed: [5](#0-4) 

### Likelihood Explanation
The attack is permissionless and requires no privileged role. The only precondition is that the attacker controls or knows N valid pool addresses recognized by an approved factory (`IPoolFactory(factory).isPool(pool)` must return `true`). Since pool creation is itself permissionless in the AMM, this is a realistic precondition. The attack is a single transaction.

### Recommendation
Override `multicall` in `OracleBase` to reject any batch that includes `register` calls, or remove the `Multicall` inheritance entirely from `OracleBase`. Alternatively, track cumulative ETH consumed within a transaction using a transient storage counter and deduct from it per `register` call, reverting if the running total exceeds `msg.value`.

The simplest fix: do not inherit `Multicall` on a contract with `payable` functions that check `msg.value` per-call.

### Proof of Concept
```solidity
// Foundry test sketch
function test_multicall_fee_bypass() public {
    // Setup: 100 valid pools in approved factory
    address[] memory pools = new address[](100);
    for (uint i; i < 100; i++) {
        pools[i] = makeAddr(string(abi.encode(i)));
        factory.setPool(pools[i], true);
    }

    bytes[] memory calls = new bytes[](100);
    for (uint i; i < 100; i++) {
        calls[i] = abi.encodeCall(OracleBase.register, (FEED, pools[i], address(factory)));
    }

    uint256 fee = oracle.registrationFee(); // e.g. 1 ether after admin raises it
    oracle.multicall{value: fee}(calls);    // pays only 1× fee

    // All 100 pools registered
    for (uint i; i < 100; i++) {
        assertTrue(oracle.registeredPool(FEED, pools[i]));
    }
    // Contract holds only 1× fee, not 100×
    assertEq(address(oracle).balance, fee);  // not 100 * fee
}
```

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

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L53-53)
```text
        registrationFee = 1 wei; // very cheap default; ADMIN tunes via setRegistrationFee
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L201-202)
```text
    function register(bytes32 feedId, address pool, address factory) external payable {
        require(msg.value >= registrationFee, InsufficientFee(msg.value, registrationFee));
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L212-213)
```text
        registeredPool[feedId][pool] = true;
        emit PoolRegistered(feedId, pool, msg.sender, msg.value);
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L292-296)
```text
    function withdrawEth() external onlyRole(ADMIN_ROLE) {
        uint256 amount = address(this).balance;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok);
        emit EthWithdrawn(msg.sender, amount);
```
