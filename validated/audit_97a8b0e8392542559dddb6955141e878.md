### Title
Unchecked Precompile Call Return Value in `withdrawToNear` / `withdrawToEthereum` Causes Permanent Token Loss - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` burn the caller's ERC-20 tokens **before** invoking the Aurora exit precompile via inline assembly. The `call` opcode's return value (`res`) is captured but **never checked**. If the precompile call fails for any reason, the burn is not reverted, the function returns successfully, and the user's tokens are permanently destroyed with no corresponding NEP-141 transfer on NEAR.

---

### Finding Description

In both `withdrawToNear` and `withdrawToEthereum` in `EvmErc20.sol` and `EvmErc20V2.sol`, the pattern is:

1. `_burn(_msgSender(), amount)` — irreversibly destroys the caller's ERC-20 balance in the current EVM execution context.
2. An inline assembly `call` is made to the `ExitToNear` precompile (`0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`) or `ExitToEthereum` precompile (`0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`).
3. The return value `res` of the `call` opcode is stored in a local variable but is **never inspected**. No `if iszero(res) { revert(0, 0) }` guard exists.

```solidity
// EvmErc20.sol lines 53-63 (withdrawToNear)
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // <-- burn is irreversible in this context
    ...
    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked
    }
}
```

The same unchecked pattern appears in `withdrawToEthereum` (lines 65–76) and identically in `EvmErc20V2.sol` (lines 53–77).

When the EVM `call` opcode invokes a precompile and the precompile returns an `ExitError` (e.g., invalid recipient account ID, malformed input, out-of-gas in the precompile), the opcode returns `0`. Because `res` is never checked and no `revert` is issued, the outer function returns successfully. The `_burn` that already executed in the parent context is **not rolled back** — only state changes within the failed sub-call would be rolled back, and the precompile had none to roll back.

---

### Impact Explanation

**Critical — Permanent freezing/destruction of funds.**

The user's ERC-20 tokens (representing bridged NEP-141 assets) are burned on the Aurora EVM side. No `ft_transfer` or `ft_transfer_call` promise is ever scheduled on NEAR because the precompile call failed silently. The NEP-141 tokens remain locked in the Aurora engine contract on NEAR with no mechanism to recover them. The user suffers a total, permanent loss of the withdrawn amount.

---

### Likelihood Explanation

**Medium.** The `ExitToNear` precompile validates its input and returns `ExitError` for:
- A recipient `bytes` argument that is not a valid NEAR account ID (e.g., too long, contains invalid characters).
- Malformed input length (the precompile enforces size bounds).
- Out-of-gas conditions inside the precompile.

Any user who calls `withdrawToNear` with a recipient that fails precompile validation will silently lose their tokens. This is reachable by any unprivileged EVM user with no special preconditions beyond holding a token balance. The `ExitToNear` precompile's `run` function explicitly returns `Err(ExitError::Other(...))` for multiple input conditions, all of which cause the EVM `call` to return `0`.

---

### Recommendation

Check the return value of the assembly `call` and revert if it is zero, so that the `_burn` is also rolled back:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Apply the same fix to `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`. Alternatively, restructure the functions to call the precompile first and only burn on success.

---

### Proof of Concept

1. Deploy `EvmErc20` with a NEP-141 token registered in Aurora.
2. Mint tokens to address `A`.
3. From address `A`, call `withdrawToNear(invalidRecipient, amount)` where `invalidRecipient` is a byte string that fails NEAR account ID validation (e.g., `"!@#$%"`).
4. The `ExitToNear` precompile returns `ExitError::Other("ERR_INVALID_RECEIVER_ACCOUNT_ID")`, causing the EVM `call` to return `0`.
5. `res` is never checked; the function returns without reverting.
6. `A`'s ERC-20 balance is reduced by `amount` (burned).
7. No NEP-141 `ft_transfer` promise is created on NEAR.
8. The NEP-141 tokens remain locked in the Aurora contract permanently with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
