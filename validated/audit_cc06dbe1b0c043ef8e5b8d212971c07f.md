The code is clear. Let me verify the exact assembly lines and the `error_refund` feature interaction.

### Title
Unchecked Precompile Return Value Causes Silent Token Burn Without Exit — (`etc/eth-contracts/contracts/EvmErc20.sol`)

---

### Summary

Both `withdrawToNear` and `withdrawToEthereum` in `EvmErc20.sol` burn the caller's tokens **before** invoking the exit precompile, and the assembly `call` return value (`res`) is captured but **never checked**. If the precompile call fails for any reason, the function returns successfully with tokens already burned and no exit ever scheduled — permanently destroying the user's bridged value.

---

### Finding Description

In `EvmErc20.sol`, both withdrawal functions follow this pattern:

```solidity
// withdrawToNear (lines 53-63)
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER CHECKED — no `if iszero(res) { revert(0,0) }`
    }
}
``` [1](#0-0) 

```solidity
// withdrawToEthereum (lines 65-76)
function withdrawToEthereum(address recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← tokens destroyed here
    ...
    assembly {
        let res := call(gas(), 0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER CHECKED
    }
}
``` [2](#0-1) 

The same pattern is present in `EvmErc20V2.sol`: [3](#0-2) 

The precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` (`exitToNear`) returns `ExitError` — which the EVM translates to a `call` return value of `0` — in multiple reachable conditions:

- `ERR_INVALID_RECEIVER_ACCOUNT_ID`: recipient bytes are not valid UTF-8 or not a valid NEAR account ID (`parse_recipient` fails)
- `ERR_TARGET_TOKEN_NOT_FOUND`: the ERC-20 contract address has no NEP-141 mapping in storage
- `ERR_KEY_NOT_FOUND`: the eth-connector account key is absent from storage
- `ERR_INVALID_AMOUNT`: amount exceeds `u128::MAX` [4](#0-3) [5](#0-4) [6](#0-5) 

Because `res` is never tested, the Solidity function returns `success` regardless of the precompile outcome. The `_burn` is already committed; there is no revert path.

---

### Impact Explanation

- The caller's ERC-20 balance is permanently reduced (tokens burned).
- The corresponding NEP-141 tokens remain locked inside Aurora's connector contract on NEAR with no recovery path.
- Total bridged value on NEAR side does not decrease; EVM-side supply does. The accounting is permanently out of sync.
- This constitutes **permanent freezing of funds** for the affected user.

---

### Likelihood Explanation

The most directly user-triggerable path is `withdrawToNear` with a `recipient` argument containing non-UTF-8 bytes (e.g., `bytes("\xff\xfe")`). The user fully controls this parameter. No special privilege, admin access, or external dependency failure is required. The call succeeds at the Solidity level, tokens are burned, and the exit silently never happens.

---

### Recommendation

After the assembly `call`, check `res` and revert on failure in both functions:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures the burn is atomically rolled back whenever the exit precompile rejects the call.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IEvmErc20 {
    function withdrawToNear(bytes memory recipient, uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}

contract PoC {
    function exploit(address token, uint256 amount) external {
        IEvmErc20 erc20 = IEvmErc20(token);

        uint256 balanceBefore = erc20.balanceOf(address(this));

        // Pass invalid UTF-8 bytes as recipient — precompile will return ExitError
        // but EvmErc20 never checks the return value, so no revert occurs.
        bytes memory invalidRecipient = hex"fffefdfc";
        erc20.withdrawToNear(invalidRecipient, amount);

        uint256 balanceAfter = erc20.balanceOf(address(this));

        // balanceBefore - balanceAfter == amount  (tokens burned)
        // but no ExitToNear event was scheduled and no NEP-141 transfer occurred
        assert(balanceBefore - balanceAfter == amount);
        // Funds are permanently frozen in the NEAR connector.
    }
}
```

The `_burn` at line 54 reduces `balanceBefore` by `amount`; the precompile at `0xe9217bc7...` rejects the malformed recipient and returns `0`; `res` is discarded; the function exits cleanly. The NEP-141 tokens remain locked with no recourse. [7](#0-6) [8](#0-7)

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

**File:** engine-precompiles/src/native.rs (L295-309)
```rust
fn validate_input_size(input: &[u8], min: usize, max: usize) -> Result<(), ExitError> {
    if input.len() < min || input.len() > max {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_INPUT")));
    }
    Ok(())
}

fn get_nep141_from_erc20<I: IO>(erc20_token: &[u8], io: &I) -> Result<AccountId, ExitError> {
    AccountId::try_from(
        io.read_storage(bytes_to_key(KeyPrefix::Erc20Nep141Map, erc20_token).as_slice())
            .map(|s| s.to_vec())
            .ok_or(ExitError::Other(Cow::Borrowed(ERR_TARGET_TOKEN_NOT_FOUND)))?,
    )
    .map_err(|_| ExitError::Other(Cow::Borrowed("ERR_INVALID_NEP141_ACCOUNT")))
}
```

**File:** engine-precompiles/src/native.rs (L337-345)
```rust
fn parse_amount(input: &[u8]) -> Result<U256, ExitError> {
    let amount = U256::from_big_endian(input);

    if amount > U256::from(u128::MAX) {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_AMOUNT")));
    }

    Ok(amount)
}
```

**File:** engine-precompiles/src/native.rs (L359-379)
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
}
```

**File:** engine-precompiles/src/native.rs (L413-417)
```rust
        if is_static {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_STATIC")));
        } else if context.address != exit_to_near::ADDRESS.raw() {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_DELEGATE")));
        }
```
