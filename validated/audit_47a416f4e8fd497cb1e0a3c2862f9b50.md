The `register` function in `OracleBase.sol` is the exact structural analog to the TokensFarm bug. Let me confirm the details.

### Title
Excess ETH Sent to `register()` Is Permanently Captured by the Oracle Contract, Not Refunded to the Caller — (`smart-contracts-poc/contracts/oracles/providers/OracleBase.sol`)

---

### Summary

`OracleBase.register()` accepts ETH with a `>=` fee check but never returns the surplus to the caller. Any ETH above `registrationFee` is silently absorbed by the contract and is only recoverable by the ADMIN via `withdrawEth()`. This is the structural twin of the TokensFarm `>=`-instead-of-`==` bug.

---

### Finding Description

`OracleBase.register()` is a permissionless, payable function that whitelists a pool for a given feed ID:

```solidity
// OracleBase.sol line 201-202
function register(bytes32 feedId, address pool, address factory) external payable {
    require(msg.value >= registrationFee, InsufficientFee(msg.value, registrationFee));
``` [1](#0-0) 

The check is `>=`, not `==`. After the require passes, no refund path exists. The function ends at line 213 with an event emission; the surplus `msg.value - registrationFee` stays in the contract. [2](#0-1) 

The NatSpec on lines 199–200 explicitly acknowledges this:

> *Overpayment is NOT refunded: any msg.value above registrationFee is kept and is withdrawable by ADMIN via withdrawEth. This is intentional.* [3](#0-2) 

The only ETH egress is `withdrawEth()`, which sweeps the full balance to the ADMIN caller — not to the original payer:

```solidity
// OracleBase.sol line 292-297
function withdrawEth() external onlyRole(ADMIN_ROLE) {
    uint256 amount = address(this).balance;
    (bool ok, ) = payable(msg.sender).call{value: amount}("");
    require(ok);
    emit EthWithdrawn(msg.sender, amount);
}
``` [4](#0-3) 

The `registrationFee` starts at 1 wei but is tunable by ADMIN to any value: [5](#0-4) 

---

### Impact Explanation

Any caller of `register()` who sends `msg.value > registrationFee` permanently loses the surplus. The funds are not returned and are not attributable back to the sender — `withdrawEth()` sweeps the entire balance to ADMIN with no per-sender accounting. The loss is bounded only by the overpayment amount, which can be arbitrarily large (e.g., a script that hardcodes 1 ETH when the fee is 1 wei, or a fee that drops between the caller's estimation and execution). This is a direct, irreversible loss of user ETH principal with no recovery path for the payer.

---

### Likelihood Explanation

`register()` is permissionless and is the mandatory on-chain step for any pool to use the oracle price path. Callers must estimate the fee off-chain and send ETH. Race conditions (ADMIN calls `setRegistrationFee` to lower the fee between estimation and execution), scripting errors, or wallet UX rounding all produce overpayment. The `registrationFee` is explicitly designed to be tunable, making fee-change races a realistic scenario. Likelihood is **Medium**.

---

### Recommendation

Replace the `>=` check with `==` to enforce exact payment, mirroring the fix applied in the TokensFarm re-audit:

```solidity
require(msg.value == registrationFee, IncorrectFee(msg.value, registrationFee));
```

Alternatively, if flexible overpayment is desired for UX reasons, add an explicit refund of the surplus after the registration logic completes, with a reentrancy guard:

```solidity
if (msg.value > registrationFee) {
    uint256 excess = msg.value - registrationFee;
    (bool ok,) = payable(msg.sender).call{value: excess}("");
    require(ok);
}
```

---

### Proof of Concept

1. ADMIN sets `registrationFee = 0.001 ether` via `setRegistrationFee`.
2. Caller estimates fee off-chain, constructs a transaction with `msg.value = 1 ether` (e.g., a script with a hardcoded buffer).
3. `register(feedId, pool, factory)` executes: `require(1 ether >= 0.001 ether)` passes.
4. Pool is registered. No refund is issued. `0.999 ether` remains in `OracleBase`.
5. Caller has no mechanism to recover the surplus. ADMIN can call `withdrawEth()` and receive the full balance including the caller's `0.999 ether`.

### Citations

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L53-53)
```text
        registrationFee = 1 wei; // very cheap default; ADMIN tunes via setRegistrationFee
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

**File:** smart-contracts-poc/contracts/oracles/providers/OracleBase.sol (L292-297)
```text
    function withdrawEth() external onlyRole(ADMIN_ROLE) {
        uint256 amount = address(this).balance;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok);
        emit EthWithdrawn(msg.sender, amount);
    }
```
