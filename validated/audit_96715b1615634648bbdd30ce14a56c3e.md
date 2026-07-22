The vulnerability claim is valid. Here is the full analysis:

`OracleBase` inherits OpenZeppelin's `Multicall` at line 6/18, which implements `multicall()` using `delegatecall`. Because `delegatecall` preserves `msg.value` across every sub-call in the batch, and `register()` is `external payable` with only a `msg.value >= registrationFee` check (line 202), an attacker can send a single `F` wei and pass that check N times — receiving N registrations for the cost of one.

---

### Title
Multicall `msg.value` Re-use Allows N Pool Registrations for the Price of One — (`smart-contracts-poc/contracts/oracles/providers/OracleBase.sol`)

### Summary
`OracleBase` inherits OpenZeppelin's `Multicall`, which dispatches each call via `delegatecall`. Because `delegatecall` preserves `msg.value` in every frame, a caller who sends exactly `registrationFee` ETH can batch N `register()` calls and satisfy the fee check N times, while only paying once.

### Finding Description
`OracleBase` inherits `Multicall` from OpenZeppelin: [1](#0-0) [2](#0-1) 

OpenZeppelin's `Multicall.multicall()` dispatches each encoded call via `Address.functionDelegateCall`, which preserves `msg.value` in every delegated frame. The `register()` function is `external payable` and its only ETH guard is: [3](#0-2) 

Because `msg.value` is not consumed or decremented between sub-calls, every call in the batch sees the same original `msg.value`. An attacker batching N `register()` calls with a single `msg.value == registrationFee` passes the check N times and receives N registrations while paying for one.

### Impact Explanation
- **Direct protocol fee loss**: the protocol receives `F` ETH but grants N registrations; it loses `(N-1)*F` per batch. With a non-trivial `registrationFee` (e.g., 1 ETH) and a large batch, this is a material loss of protocol revenue.
- **Abuse-protection bypass**: the registration fee is the primary spam/abuse deterrent for the oracle whitelist. Bypassing it at near-zero marginal cost undermines the entire abuse-protection model, allowing an attacker to cheaply populate `registeredPool` for many pools.

### Likelihood Explanation
The attack requires no special role, no malicious pool setup, and no off-chain oracle data. Any EOA with `registrationFee` ETH and access to valid factory-registered pools can execute it. The `multicall()` function is public and payable.

### Recommendation
Either:
1. Remove `payable` from `register()` and use a pull-payment or ERC-20 fee model, or
2. Track cumulative ETH consumed within the `multicall` execution context and revert if `address(this).balance` did not increase by at least `N * registrationFee`, or
3. Override `multicall()` to disallow batching of `register()` calls, or
4. Replace the `msg.value >= registrationFee` check with a pattern that deducts from a per-transaction allowance (e.g., a transient-storage counter).

The simplest fix is to make `register()` non-payable and accept fees via a separate ERC-20 transfer or a pre-deposited balance.

### Proof of Concept
```solidity
// registrationFee = 1 ether
// pool1, pool2 are both valid factory-registered pools

bytes[] memory calls = new bytes[](2);
calls[0] = abi.encodeCall(oracle.register, (feedId, pool1, factory));
calls[1] = abi.encodeCall(oracle.register, (feedId, pool2, factory));

oracle.multicall{value: 1 ether}(calls); // sends only 1 ether

// Both registrations succeed:
assert(oracle.registeredPool(feedId, pool1)); // true
assert(oracle.registeredPool(feedId, pool2)); // true
assert(address(oracle).balance == 1 ether);  // only 1 ether received, not 2
```

The contract receives 1 ETH but grants 2 registrations. Scaling to N calls, the protocol loses `(N-1) * registrationFee` per transaction. [4](#0-3)

### Citations

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L6-6)
```text
import { Multicall } from "@openzeppelin/contracts/utils/Multicall.sol";
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L18-18)
```text
contract OracleBase is AccessControl, Multicall, IOffchainOracle {
```

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L196-214)
```text
    /// @notice Permissionless paid registration: whitelist `pool` for `feedId` (required to use the
    ///         on-chain price(feedId, factory) path). `factory` must be approved and recognize `pool`
    ///         via isPool. Paying also clears any blacklist on the pool.
    /// @dev    Overpayment is NOT refunded: any msg.value above registrationFee is kept and is
    ///         withdrawable by ADMIN via withdrawEth. This is intentional.
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
