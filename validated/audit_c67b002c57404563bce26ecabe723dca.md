### Title
Unchecked Precompile Call Return Value After Irreversible Token Burn Causes Permanent Fund Loss - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

In `EvmErc20.sol` and `EvmErc20V2.sol`, both `withdrawToNear` and `withdrawToEthereum` burn the caller's ERC-20 tokens **before** calling the exit precompile, and the assembly `call` return value is **never checked**. If the precompile call fails for any reason (invalid recipient, unregistered token, gas exhaustion), the burn is already committed and irreversible, permanently destroying the user's funds with no recourse.

---

### Finding Description

In `EvmErc20.sol` `withdrawToNear` (lines 53–63):

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← irreversible burn happens first

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is assigned but NEVER checked — no `if iszero(res) { revert(...) }`
    }
}
```

The same pattern appears in:
- `EvmErc20.sol` `withdrawToEthereum` (lines 65–76)
- `EvmErc20V2.sol` `withdrawToNear` (lines 53–63)
- `EvmErc20V2.sol` `withdrawToEthereum` (lines 66–77)

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) returns an `ExitError` (causing the EVM `call` opcode to return `0`) in multiple reachable conditions:

1. **Invalid recipient account ID** — `parse_recipient` rejects bytes containing invalid NEAR account characters (e.g. `@`, non-UTF-8 bytes). A user supplying `test@.near` as recipient causes `ExitToNearParams::try_from` to fail.
2. **Unregistered ERC-20** — `get_nep141_from_erc20` returns `ERR_TARGET_TOKEN_NOT_FOUND` if the ERC-20 → NEP-141 mapping is absent.
3. **Gas exhaustion** — if `target_gas < EXIT_TO_NEAR_GAS`, the precompile returns `OutOfGas`.

In all these cases the EVM `call` returns `0`, but because `res` is never checked, the Solidity function returns normally. The burn is already finalized; no NEAR-side transfer is ever scheduled.

---

### Impact Explanation

**Critical — Permanent freezing/destruction of user funds.**

The user's ERC-20 tokens are burned (supply reduced, balance zeroed) and no corresponding NEP-141 tokens are minted on NEAR. The funds are unrecoverable: there is no re-mint path, no refund callback, and no on-chain record of the failed exit. The `error_refund` feature only schedules a re-mint callback when the precompile itself succeeds in parsing the input and scheduling the NEAR promise — it does not protect against the precompile returning an EVM-level error before that point.

---

### Likelihood Explanation

**Medium.** Any EVM user holding bridged ERC-20 tokens can call `withdrawToNear` directly. A typo in the recipient account ID (e.g. an `@` character, a trailing space, or a non-UTF-8 byte sequence) is a realistic user error. The function accepts an arbitrary `bytes memory recipient` with no pre-validation, making silent failure easy to trigger accidentally or deliberately (self-griefing). The same path is reachable for `withdrawToEthereum` via the `ExitToEth` precompile at `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`.

---

### Recommendation

Add a revert on precompile call failure in both functions in both contracts:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures the `_burn` is atomically rolled back if the precompile rejects the call, preserving the user's balance. Alternatively, move the precompile call **before** the burn and only burn on success.

---

### Proof of Concept

1. Alice holds 100 units of a bridged ERC-20 on Aurora.
2. Alice calls `withdrawToNear(bytes("test@.near"), 100)`.
3. `_burn(alice, 100)` executes — Alice's balance is now 0, total supply reduced.
4. The assembly `call` to the `ExitToNear` precompile is made with `recipient = "test@.near"`.
5. Inside the precompile, `parse_recipient(b"test@.near")` returns `Err` (confirmed by `test_parse_invalid_recipient` in `engine-precompiles/src/native.rs:1136–1139`), so the precompile returns `ExitError`.
6. The EVM `call` opcode returns `res = 0`.
7. `res` is never checked; the Solidity function returns normally.
8. No NEAR promise is scheduled; Alice's 100 tokens are permanently destroyed.

**Root cause lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Precompile failure paths:** [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-63)
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

**File:** engine-precompiles/src/native.rs (L406-410)
```rust
        if let Some(target_gas) = target_gas
            && required_gas > target_gas
        {
            return Err(ExitError::OutOfGas);
        }
```

**File:** engine-precompiles/src/native.rs (L1136-1140)
```rust
    fn test_parse_invalid_recipient() {
        assert!(parse_recipient(b"test@.near").is_err());
        assert!(parse_recipient(b"test@.near:msg").is_err());
        assert!(parse_recipient(&[0xc2]).is_err());
    }
```
