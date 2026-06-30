### Title
Unchecked Return Value of Exit Precompile `call()` in `withdrawToNear` and `withdrawToEthereum` Causes Permanent Token Loss — (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` implement bridge-exit functions (`withdrawToNear`, `withdrawToEthereum`) that first burn the caller's ERC-20 tokens and then invoke the Aurora exit precompile via a low-level assembly `call()`. The return value of that `call()` — which is `0` on failure and `1` on success — is captured in a local variable `res` but is **never inspected or acted upon**. If the precompile call fails for any reason, the tokens are permanently destroyed with no corresponding release on the NEAR or Ethereum side.

---

### Finding Description

In `EvmErc20.sol`, `withdrawToNear` (lines 53–63) and `withdrawToEthereum` (lines 65–76):

```solidity
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

The identical pattern appears in `withdrawToEthereum` (calling `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`) and in both functions of `EvmErc20V2.sol` (lines 53–64 and 66–77).

The EVM `call()` opcode returns `0` on failure (out-of-gas, revert, invalid input, precompile error). Because `res` is never tested, the Solidity function returns normally regardless of whether the precompile succeeded. The `_burn()` has already executed and is not rolled back.

---

### Impact Explanation

**Critical — Permanent freezing / destruction of user funds.**

When the precompile call fails silently:
- The user's ERC-20 tokens are irreversibly burned on the Aurora EVM side.
- No NEP-141 `ft_transfer` is issued on the NEAR side (for `withdrawToNear`), and no Ethereum withdrawal event is emitted (for `withdrawToEthereum`).
- The tokens are gone from both sides of the bridge — they cannot be recovered.

This satisfies the "Permanent freezing of funds" critical impact criterion.

---

### Likelihood Explanation

Any token holder can trigger this path by calling `withdrawToNear` or `withdrawToEthereum` directly. Failure conditions for the precompile include:

- Passing a malformed or oversized `recipient` that causes the `ExitToNear` precompile to return an error.
- Providing a `recipient` that is not a valid NEAR account ID (the precompile validates this and returns `ExitError`).
- Insufficient gas forwarded to the precompile (the `gas()` opcode forwards remaining gas, but if the outer transaction is gas-constrained, the inner call may run out).
- Any future precompile-level validation change that causes a rejection.

Because the function is `external` and callable by any token holder with no access control, the attack surface is fully unprivileged and reachable on every deployed `EvmErc20` / `EvmErc20V2` instance.

---

### Recommendation

Check the return value of the assembly `call()` and revert if it is zero, so that the `_burn()` is rolled back atomically:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Apply the same fix to `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`.

---

### Proof of Concept

1. Deploy `EvmErc20` with a valid NEP-141 mapping.
2. Mint tokens to `alice`.
3. `alice` calls `withdrawToNear(invalidRecipient, amount)` where `invalidRecipient` is a byte string that fails the NEAR account-ID validation inside the `ExitToNear` precompile.
4. The precompile call returns `0` (failure). `res` is `0` but is never checked.
5. The function returns without reverting.
6. `alice`'s balance is now zero (tokens burned), but no NEP-141 transfer was issued.
7. Tokens are permanently lost.

**Root cause lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
