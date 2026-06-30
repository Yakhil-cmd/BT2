### Title
Unchecked Low-Level Call Return Value After `_burn()` in `withdrawToNear`/`withdrawToEthereum` Causes Permanent Fund Loss - (`etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` implement `withdrawToNear()` and `withdrawToEthereum()` by first calling `_burn()` to destroy the caller's ERC-20 tokens, then making a low-level assembly `call()` to the Aurora exit precompile. The return value `res` of that `call()` is captured but never checked. If the precompile call fails (returns `0`), the EVM does not revert the calling context, so the burn is permanent while no corresponding NEP-141 tokens are ever released on the NEAR side.

### Finding Description

In `EvmErc20.sol`, both exit functions follow the same pattern:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← tokens destroyed here, irreversibly

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is never checked — if call returns 0, execution continues silently
    }
}
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) returns `Err(ExitError::...)` — which the EVM translates to a failed call (return value `0`) — in several reachable conditions:

- `ERR_INVALID_RECEIVER_ACCOUNT_ID`: triggered when `parse_recipient` cannot parse the caller-supplied `recipient` bytes as a valid NEAR account ID.
- `ERR_INVALID_AMOUNT`: triggered when the amount exceeds `u128::MAX`.
- `ERR_MISSING_FLAG` / `ERR_INVALID_FLAG`: triggered on malformed input.
- `get_nep141_from_erc20` failure: if the ERC-20 address is not registered in the bridge mapping. [5](#0-4) [6](#0-5) 

When any of these errors occur, the low-level `call()` returns `0`. Because the Solidity code does not check `res` and does not revert, the `_burn()` that already executed is final. The user's ERC-20 tokens are permanently destroyed, and no NEAR-side `ft_transfer` promise is ever scheduled.

The `error_refund` feature only handles the case where the precompile itself succeeds but the subsequent asynchronous NEAR promise fails. It does not protect against synchronous precompile failures. [7](#0-6) 

### Impact Explanation

**Critical — Permanent freezing of funds.**

When the precompile call fails silently:
1. The user's ERC-20 tokens are burned and permanently destroyed on the Aurora EVM side.
2. The corresponding NEP-141 tokens remain locked in the Aurora contract on NEAR, with no mechanism to release them.

The result is a double loss: the ERC-20 representation is gone, and the underlying NEP-141 tokens are frozen in the bridge contract forever.

### Likelihood Explanation

**High.** The `recipient` parameter in `withdrawToNear` is a raw `bytes` value supplied directly by the caller. Any user can pass an invalid NEAR account ID (e.g., containing illegal characters, exceeding length limits, or being empty). The precompile's `parse_recipient` will reject it, the `call()` will return `0`, and the burn will be irreversible. No special privileges or unusual conditions are required — this is a normal user-facing function on every deployed `EvmErc20`/`EvmErc20V2` bridge token. [8](#0-7) 

### Recommendation

Check the return value of the low-level `call()` and revert if it indicates failure. Apply this fix to all four affected assembly blocks in both `EvmErc20.sol` and `EvmErc20V2.sol`:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures that if the exit precompile rejects the call for any reason, the entire transaction reverts — including the `_burn()` — so the user's tokens are never destroyed without a corresponding NEAR-side release.

### Proof of Concept

1. Deploy an `EvmErc20` token (as Aurora does for every bridged NEP-141).
2. Acquire a balance of the ERC-20 token (e.g., via `ft_transfer_call` bridging).
3. Call `withdrawToNear(bytes("!!!invalid near account!!!"), amount)`.
4. Observe: `_burn` executes, ERC-20 balance drops to zero.
5. The precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` returns an error for `ERR_INVALID_RECEIVER_ACCOUNT_ID` because `!!!invalid near account!!!` is not a valid NEAR account ID.
6. The assembly `call()` returns `0`; `res` is never checked; the function returns normally.
7. The user's ERC-20 tokens are permanently gone. No NEP-141 tokens are transferred on NEAR. The NEP-141 balance of the Aurora contract on NEAR is unchanged — those tokens are now permanently frozen. [9](#0-8) [1](#0-0)

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

**File:** engine-precompiles/src/native.rs (L359-378)
```rust
fn parse_recipient(recipient: &[u8]) -> Result<Recipient<'_>, ExitError> {
    let recipient = str::from_utf8(recipient)
        .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECEIVER_ACCOUNT_ID")))?;
    let (receiver_account_id, message) = recipient.split_once(':').map_or_else(
        || (recipient, None),
        |(recipient, msg)| {
            if msg == UNWRAP_WNEAR_MSG {
                (recipient, Some(Message::UnwrapWnear))
            } else {
                (recipient, Some(Message::Omni(msg)))
            }
        },
    );

    Ok(Recipient {
        receiver_account_id: receiver_account_id
            .parse()
            .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECEIVER_ACCOUNT_ID")))?,
        message,
    })
```

**File:** engine-precompiles/src/native.rs (L404-417)
```rust
        let required_gas = Self::required_gas(input)?;

        if let Some(target_gas) = target_gas
            && required_gas > target_gas
        {
            return Err(ExitError::OutOfGas);
        }

        // It's not allowed to call exit precompiles in static mode
        if is_static {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_STATIC")));
        } else if context.address != exit_to_near::ADDRESS.raw() {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_DELEGATE")));
        }
```

**File:** engine-precompiles/src/native.rs (L449-455)
```rust
        let callback_args = ExitToNearPrecompileCallbackArgs {
            #[cfg(feature = "error_refund")]
            refund: refund_call_args(&exit_to_near_params, &exit_event),
            #[cfg(not(feature = "error_refund"))]
            refund: None,
            transfer_near: transfer_near_args,
        };
```

**File:** etc/eth-contracts/contracts/IExit.sol (L4-7)
```text
interface IExit {
    function withdrawToNear(bytes memory recipient, uint256 amount) external;

    function withdrawToEthereum(address recipient, uint256 amount) external;
```
