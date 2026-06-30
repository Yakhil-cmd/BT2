### Title
Unchecked Precompile Call Return Value After `_burn` Enables Permanent Token Loss - (File: `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20V2.sol` and `EvmErc20.sol` implement `withdrawToNear` and `withdrawToEthereum` by first burning the caller's ERC-20 tokens with `_burn`, then invoking the exit precompile via an inline assembly `call`. The return value `res` of that `call` is captured but **never checked**. If the precompile reverts for any reason, the burn is not rolled back, the tokens are permanently destroyed on the EVM side, and the corresponding NEP-141 tokens remain locked in Aurora's NEAR account — unreachable by the user.

---

### Finding Description

In `EvmErc20V2.sol`, `withdrawToNear`:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    address sender = _msgSender();
    _burn(sender, amount);                          // tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
    uint input_size = 1 + 20 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is never checked — no require(res), no revert on failure
    }
}
``` [1](#0-0) 

The same pattern appears in `withdrawToEthereum` in `EvmErc20V2.sol`: [2](#0-1) 

And identically in both functions of `EvmErc20.sol`: [3](#0-2) [4](#0-3) 

The `ExitToNear` precompile enforces multiple hard-failure conditions in `native.rs`. Specifically, `validate_input_size` rejects any input exceeding `MAX_INPUT_SIZE = 1024` bytes: [5](#0-4) [6](#0-5) 

The `ExitToNear` precompile also fails when the recipient bytes do not parse as a valid NEAR `AccountId` (via `parse_recipient`), when the ERC-20 is not registered as a NEP-141 mirror (`ERR_TARGET_TOKEN_NOT_FOUND`), or when called in static/delegate context: [7](#0-6) [8](#0-7) 

The `ExitToEthereum` precompile similarly validates input size and rejects malformed input: [9](#0-8) [10](#0-9) 

When any of these conditions trigger, the precompile returns an `ExitError`, the EVM `call` opcode returns `0` into `res`, but because `res` is never tested, the outer transaction does not revert. The `_burn` that already executed is committed permanently.

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

The ERC-20 mirror tokens represent NEP-141 tokens custodied by the Aurora contract on NEAR. When `_burn` succeeds but the precompile call fails silently:

- The user's ERC-20 balance is reduced to zero (tokens destroyed).
- No `ft_transfer` or `ft_transfer_call` promise is ever scheduled on NEAR.
- The NEP-141 tokens remain locked in Aurora's NEAR account with no mechanism to recover them.

The user has permanently lost the full `amount` of bridged tokens. There is no admin recovery path — the NEP-141 tokens are not attributable to any pending withdrawal and cannot be re-claimed.

---

### Likelihood Explanation

**Medium-High.** Any unprivileged token holder can trigger this by calling `withdrawToNear` with a `recipient` byte array that:

- Exceeds `MAX_INPUT_SIZE - 53` bytes (causing `validate_input_size` to fail), or
- Contains bytes that do not form a valid NEAR account ID (causing `parse_recipient` to fail).

Both conditions are trivially reachable from a standard EVM wallet or contract call. A user making a typo in the recipient account ID, or a contract passing an oversized message, will silently lose funds. No special privilege or coordination is required.

---

### Recommendation

Add a `require` check on the return value of every precompile `call` in both contracts, for both `withdrawToNear` and `withdrawToEthereum`:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures that if the precompile rejects the call for any reason, the entire transaction reverts, the `_burn` is rolled back, and the user retains their tokens.

---

### Proof of Concept

1. Alice holds 1000 units of an ERC-20 mirror token on Aurora (backed by NEP-141 tokens in Aurora's NEAR account).
2. Alice calls `withdrawToNear(recipient, 1000)` where `recipient` is a byte array of length 1000 (total input size = 1 + 20 + 32 + 1000 = 1053 bytes, exceeding `MAX_INPUT_SIZE = 1024`).
3. `_burn(alice, 1000)` executes — Alice's ERC-20 balance drops to 0.
4. The assembly `call` to the `ExitToNear` precompile (`0xe921...`) is made. Inside the precompile, `validate_input_size` returns `Err(ExitError::Other("ERR_INVALID_INPUT_SIZE"))`. The precompile reverts; the EVM `call` returns `res = 0`.
5. `res` is never checked. The Solidity function returns normally. The outer transaction succeeds.
6. Alice's 1000 ERC-20 tokens are gone. No NEAR-side `ft_transfer` was ever scheduled. The NEP-141 tokens remain locked in Aurora's NEAR account permanently. [1](#0-0) [5](#0-4) [6](#0-5)

### Citations

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

**File:** engine-precompiles/src/native.rs (L40-40)
```rust
const MAX_INPUT_SIZE: usize = 1_024;
```

**File:** engine-precompiles/src/native.rs (L413-417)
```rust
        if is_static {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_STATIC")));
        } else if context.address != exit_to_near::ADDRESS.raw() {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_DELEGATE")));
        }
```

**File:** engine-precompiles/src/native.rs (L730-737)
```rust
    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        // The first byte of the input is a flag, selecting the behavior to be triggered:
        // 0x00 -> Eth(base) token withdrawal
        // 0x01 -> ERC-20 token withdrawal
        let flag = input
            .first()
            .copied()
            .ok_or_else(|| ExitError::Other(Cow::from("ERR_MISSING_FLAG")))?;
```

**File:** engine-precompiles/src/native.rs (L787-791)
```rust
#[cfg(not(feature = "error_refund"))]
fn parse_input(input: &[u8]) -> Result<&[u8], ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    Ok(&input[1..])
}
```

**File:** engine-precompiles/src/native.rs (L864-864)
```rust
        validate_input_size(input, 21, 53)?;
```

**File:** engine-precompiles/src/native.rs (L966-968)
```rust
                } else {
                    return Err(ExitError::Other(Cow::from("ERR_INVALID_RECIPIENT_ADDRESS")));
                }
```
