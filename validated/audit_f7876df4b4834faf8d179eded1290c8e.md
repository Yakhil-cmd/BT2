### Title
Unchecked Return Value of Exit Precompile `call()` in `withdrawToNear` and `withdrawToEthereum` Causes Permanent Token Loss - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` burn the caller's tokens before invoking the Aurora exit precompile via inline assembly `call()`. The return value of that `call()` is stored in a local variable `res` but is never inspected. If the precompile call fails for any reason, the burn is not reverted, the transaction succeeds from the EVM perspective, and the user's tokens are permanently destroyed with no corresponding NEAR-side release.

---

### Finding Description

In both `withdrawToNear()` and `withdrawToEthereum()` in `EvmErc20.sol` and `EvmErc20V2.sol`, the pattern is:

1. `_burn(_msgSender(), amount)` — irreversibly destroys the user's ERC-20 tokens.
2. An inline assembly block calls the exit precompile (`ExitToNear` at `0xe921...124f` or `ExitToEthereum` at `0xb0bd...8eab`).
3. The return value `res` of the `call()` opcode is captured but **never checked**.

```solidity
// EvmErc20.sol – withdrawToNear (lines 53–63)
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is never checked — no `if iszero(res) { revert(0, 0) }`
    }
}
```

The identical pattern appears in `withdrawToEthereum()` in both contracts, and in `EvmErc20V2.sol` for both functions.

The `ExitToNear` and `ExitToEthereum` precompiles can return failure (`res == 0`) in several reachable conditions:
- The precompile is **paused** via `pause_precompiles` (a legitimate operational action by the admin, not a compromise).
- The ERC-20 contract is not registered in the NEP-141 mapping (e.g., during a migration or misconfiguration).
- The precompile encounters an internal error (e.g., `ERR_INVALID_RECEIVER_ACCOUNT_ID`, `ERR_INVALID_RECIPIENT_ADDRESS`).

In all these cases, the EVM `call()` returns `0`, but because `res` is never checked, the Solidity function does not revert. The `_burn()` has already executed and is not rolled back.

---

### Impact Explanation

**Permanent freezing / theft of user funds.**

When the precompile call fails silently:
- The user's ERC-20 tokens are burned on the Aurora EVM side (supply reduced, balance zeroed).
- No NEAR-side promise (`ft_transfer` / `withdraw`) is ever created.
- The NEP-141 tokens remain locked in the Aurora engine contract on NEAR with no mechanism to release them to the user.
- The user has no recourse: the EVM transaction succeeded, the tokens are gone.

This matches the **Critical: Permanent freezing of funds** impact category.

---

### Likelihood Explanation

**Medium.** The most realistic trigger is the precompile being paused. Aurora Engine exposes `pause_precompiles` / `resume_precompiles` contract methods that can pause `ExitToNear` and `ExitToEthereum`. Pausing is a normal operational action (e.g., during an upgrade or incident response). Any user who calls `withdrawToNear()` or `withdrawToEthereum()` while the precompile is paused will have their tokens permanently burned. The user has no way to know the precompile is paused before submitting the transaction, and the transaction will appear to succeed.

---

### Recommendation

Check the return value of the assembly `call()` and revert if it is zero:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures that if the precompile call fails for any reason, the entire transaction (including the `_burn()`) is reverted, preserving the user's token balance.

---

### Proof of Concept

**`EvmErc20.sol` — `withdrawToNear` (lines 53–63):** [1](#0-0) 

**`EvmErc20.sol` — `withdrawToEthereum` (lines 65–76):** [2](#0-1) 

**`EvmErc20V2.sol` — `withdrawToNear` (lines 53–64):** [3](#0-2) 

**`EvmErc20V2.sol` — `withdrawToEthereum` (lines 66–77):** [4](#0-3) 

The `ExitToNear` precompile is pausable via the engine's `pause_precompiles` method: [5](#0-4) 

Attack path:
1. Admin pauses `ExitToNear` (legitimate operational action).
2. User calls `EvmErc20.withdrawToNear(recipient, 1000)`.
3. `_burn(msg.sender, 1000)` executes — 1000 tokens destroyed.
4. Assembly `call()` to `ExitToNear` precompile returns `0` (paused → `ERR_PAUSED`).
5. `res` is never checked; function returns without reverting.
6. Transaction succeeds. User has lost 1000 tokens permanently. No NEAR-side transfer was created.

### Citations

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-63)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L65-76)
```text
    function withdrawToEthereum(address recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes20 recipient_b = bytes20(recipient);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient_b);
        uint input_size = 1 + 32 + 20;

        assembly {
            let res := call(gas(), 0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-64)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        address sender = _msgSender();
        _burn(sender, amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
        uint input_size = 1 + 20 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L66-77)
```text
    function withdrawToEthereum(address recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes20 recipient_b = bytes20(recipient);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient_b);
        uint input_size = 1 + 32 + 20;

        assembly {
            let res := call(gas(), 0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** engine/src/pausables.rs (L9-16)
```rust
bitflags! {
    /// Wraps unsigned integer where each bit identifies a different precompile.
    #[derive(BorshSerialize, BorshDeserialize, Default)]
    #[borsh(crate = "aurora_engine_types::borsh")]
    pub struct PrecompileFlags: u32 {
        const EXIT_TO_NEAR        = 0b01;
        const EXIT_TO_ETHEREUM    = 0b10;
    }
```
