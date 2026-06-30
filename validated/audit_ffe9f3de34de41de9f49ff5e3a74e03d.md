### Title
Unchecked Low-Level Precompile Call Return Value in `withdrawToNear`/`withdrawToEthereum` Causes Permanent Token Burn Without Bridge Release — (`etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` — the production ERC-20 bridge token contracts deployed by Aurora Engine for every bridged NEP-141 token — burn the caller's tokens **before** calling the exit precompile via inline assembly, and **never check the return value** of that call. If the precompile call fails for any reason (e.g., invalid NEAR recipient, precompile error), the tokens are permanently destroyed while the corresponding NEAR or Ethereum assets are never released.

---

### Finding Description

`setup_deploy_erc20_input` in `engine/src/engine.rs` embeds either `EvmErc20.bin` or `EvmErc20V2.bin` as the bytecode for every bridged ERC-20 token deployed on Aurora:

```rust
#[cfg(feature = "error_refund")]
let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20V2.bin");
#[cfg(not(feature = "error_refund"))]
let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20.bin");
``` [1](#0-0) 

In `EvmErc20.sol`, `withdrawToNear` and `withdrawToEthereum` both follow the same pattern:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked
    }
}
``` [2](#0-1) [3](#0-2) 

`EvmErc20V2.sol` contains the identical unchecked pattern in both `withdrawToNear` and `withdrawToEthereum`: [4](#0-3) [5](#0-4) 

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) can return a failure (EVM call returns `0`) in multiple conditions: invalid NEAR recipient account ID, token not registered in the NEP-141 mapping, `ERR_INVALID_IN_STATIC`, `ERR_INVALID_IN_DELEGATE`, etc. Because `res` is captured but never tested, Solidity does not revert — the function returns successfully with the tokens already burned and no bridge release scheduled. [6](#0-5) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

Any user who calls `withdrawToNear` or `withdrawToEthereum` under conditions that cause the precompile to fail will have their ERC-20 tokens permanently burned. The corresponding NEP-141 tokens locked in the bridge are never released, and no NEAR or Ethereum assets are returned. The loss is irreversible because the burn is committed before the precompile is invoked and there is no rollback path.

---

### Likelihood Explanation

**Medium.** The `recipient` parameter in `withdrawToNear` is a raw `bytes` value supplied entirely by the caller. Any byte sequence that does not parse as a valid NEAR account ID causes the `ExitToNear` precompile to return an error. A user who mistypes a recipient, passes an empty byte array, or passes a string that exceeds NEAR's account-ID length limit will silently lose their tokens. No special privilege is required; any token holder can trigger this path.

---

### Recommendation

Move `_burn` to **after** a successful precompile call, or check `res` and revert on failure:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
_burn(_msgSender(), amount);
```

Apply the same fix to `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`.

---

### Proof of Concept

1. User holds 100 units of a bridged ERC-20 token (e.g., USDC bridged from NEAR).
2. User calls `withdrawToNear(bytes("invalid!!account"), 100)`.
3. `_burn(_msgSender(), 100)` executes — balance drops to 0, tokens destroyed.
4. The assembly `call` to the `ExitToNear` precompile fails because `"invalid!!account"` is not a valid NEAR account ID; the precompile returns `0`.
5. `res` is never checked; no `revert` is issued.
6. `withdrawToNear` returns successfully.
7. The user's 100 ERC-20 tokens are gone. The 100 NEP-141 tokens remain locked in the Aurora bridge contract forever.
8. The same outcome occurs in `withdrawToEthereum` with an invalid Ethereum recipient encoding, and in `EvmErc20V2.sol` which contains the identical unchecked assembly block.

### Citations

**File:** engine/src/engine.rs (L1321-1324)
```rust
    #[cfg(feature = "error_refund")]
    let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20V2.bin");
    #[cfg(not(feature = "error_refund"))]
    let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20.bin");
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

**File:** engine-precompiles/src/native.rs (L413-416)
```rust
        if is_static {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_STATIC")));
        } else if context.address != exit_to_near::ADDRESS.raw() {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_DELEGATE")));
```
