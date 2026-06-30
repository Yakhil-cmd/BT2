### Title
Unchecked Return Value of Exit Precompile `call()` After Token Burn Causes Permanent Fund Loss - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` burn a user's ERC-20 tokens **before** making a low-level `call()` to the Aurora exit precompile. The return value of that `call()` is captured into a local variable `res` but is **never checked**. If the precompile call fails (returns `0`), execution continues silently, the tokens are already destroyed, and the user receives nothing on the NEAR side — resulting in permanent, irrecoverable loss of funds.

---

### Finding Description

In `withdrawToNear()` and `withdrawToEthereum()` of both `EvmErc20` and `EvmErc20V2`, the sequence is:

1. `_burn(_msgSender(), amount)` — tokens are permanently destroyed from the EVM state.
2. An inline assembly `call()` is made to the exit precompile address.
3. The result `res` is assigned but **never inspected**.

```solidity
// EvmErc20.sol, withdrawToNear(), lines 53–63
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);                          // tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked
    }
}
```

The identical pattern appears in `withdrawToEthereum()` (calling `0xb0bd02f6...`) in both contracts. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

The `ExitToNear` precompile (`0xe9217bc7...`) and `ExitToEthereum` precompile (`0xb0bd02f6...`) are implemented in `engine-precompiles/src/native.rs` and can return failure (`ExitError`) under several conditions:

- The ERC-20 token has no registered NEP-141 mapping (`ERR_TARGET_TOKEN_NOT_FOUND`).
- The precompile is paused or called in an invalid context.
- Input parsing fails (e.g., invalid recipient account ID, amount overflow).
- Insufficient gas forwarded to the precompile.

When the EVM `call()` opcode invokes a precompile that returns an `ExitError`, the `call()` returns `0` (failure). Since `res` is never checked, the Solidity function returns normally — but the tokens are already gone. [5](#0-4) [6](#0-5) 

---

### Impact Explanation

**Critical — Permanent freezing / destruction of user funds.**

A user calls `withdrawToNear(recipient, amount)` or `withdrawToEthereum(recipient, amount)`. Their ERC-20 tokens are burned unconditionally. If the subsequent precompile call fails for any reason, the tokens are gone from the EVM with no corresponding credit on NEAR or Ethereum. There is no refund path and no recovery mechanism. The loss is permanent and total for the withdrawn amount. [7](#0-6) 

---

### Likelihood Explanation

**Medium.** Under normal operation with a correctly registered token, the precompile succeeds. However, the failure condition is reachable by any unprivileged user in realistic scenarios:

- A user calls `withdrawToNear` on an ERC-20 whose NEP-141 mapping has been removed or was never set — the precompile returns `ERR_TARGET_TOKEN_NOT_FOUND`, `res = 0`, tokens burned.
- A user passes a malformed or oversized `recipient` byte string exceeding `MAX_INPUT_SIZE` (1024 bytes) — the precompile returns `ERR_INVALID_INPUT`, `res = 0`, tokens burned.
- The precompile is paused at the engine level — `res = 0`, tokens burned.

All of these are user-triggerable without any privileged access. [8](#0-7) 

---

### Recommendation

Check the return value of the precompile `call()` in the assembly block and revert if it fails, **before** burning tokens — or restructure to burn only after confirming the precompile call succeeded. The safest fix is to check `res` and revert:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Apply the same fix to `withdrawToEthereum()` in both `EvmErc20.sol` and `EvmErc20V2.sol`.

---

### Proof of Concept

1. Deploy an `EvmErc20` token whose NEP-141 mapping is not registered in the engine (or use a token whose mapping is removed after deployment).
2. Mint tokens to a test address.
3. Call `withdrawToNear(recipient, amount)` from that address.
4. Observe: `_burn()` executes, the user's balance drops to zero. The precompile call returns `0` (`ERR_TARGET_TOKEN_NOT_FOUND`). The assembly block does not revert. The function returns successfully.
5. The user has lost `amount` tokens permanently — no NEP-141 tokens are credited on NEAR.

The same scenario applies to `withdrawToEthereum()` with a malformed recipient or paused precompile. [9](#0-8) [10](#0-9)

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

**File:** engine-precompiles/src/native.rs (L37-40)
```rust
const MIN_INPUT_SIZE: usize = 3;
#[cfg(feature = "error_refund")]
const MIN_INPUT_SIZE: usize = 21;
const MAX_INPUT_SIZE: usize = 1_024;
```

**File:** engine-precompiles/src/native.rs (L295-300)
```rust
fn validate_input_size(input: &[u8], min: usize, max: usize) -> Result<(), ExitError> {
    if input.len() < min || input.len() > max {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_INPUT")));
    }
    Ok(())
}
```

**File:** engine-precompiles/src/native.rs (L302-309)
```rust
fn get_nep141_from_erc20<I: IO>(erc20_token: &[u8], io: &I) -> Result<AccountId, ExitError> {
    AccountId::try_from(
        io.read_storage(bytes_to_key(KeyPrefix::Erc20Nep141Map, erc20_token).as_slice())
            .map(|s| s.to_vec())
            .ok_or(ExitError::Other(Cow::Borrowed(ERR_TARGET_TOKEN_NOT_FOUND)))?,
    )
    .map_err(|_| ExitError::Other(Cow::Borrowed("ERR_INVALID_NEP141_ACCOUNT")))
}
```
