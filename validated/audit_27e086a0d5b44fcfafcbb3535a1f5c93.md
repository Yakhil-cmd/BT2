### Title
Silent Precompile Call Failure After Token Burn Causes Permanent Fund Loss - (File: `etc/eth-contracts/contracts/EvmErc20.sol`)

### Summary
`EvmErc20.sol` burns a user's ERC-20 tokens **before** calling the `ExitToNear` or `ExitToEthereum` precompile via inline assembly. The assembly block captures the call return value in a local variable but never checks it. If the precompile call fails for any reason (e.g., an invalid NEAR recipient account ID supplied by the caller), the tokens are permanently destroyed with no corresponding NEAR or Ethereum transfer, causing irreversible fund loss.

### Finding Description

In `etc/eth-contracts/contracts/EvmErc20.sol`, both `withdrawToNear` and `withdrawToEthereum` follow the same unsafe pattern:

1. `_burn(_msgSender(), amount)` is called first — tokens are destroyed from the caller's balance.
2. An inline assembly `call` is made to the precompile address.
3. The return value `res` is assigned but **never checked**. A return value of `0` (failure) is silently ignored.

```solidity
// EvmErc20.sol lines 53-63
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);                          // tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is never checked — silent failure
    }
}
```

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) returns `ExitError` (causing the `call` opcode to return `0`) in multiple reachable conditions:

- `ERR_INVALID_RECEIVER_ACCOUNT_ID` — if the caller-supplied `recipient` bytes do not form a valid NEAR account ID.
- `ERR_TARGET_TOKEN_NOT_FOUND` — if the ERC-20 contract is not yet mapped to a NEP-141 token.
- `ERR_INVALID_INPUT` — if the input length is outside the accepted range. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

**Critical — Permanent freezing/destruction of funds.**

When the precompile call fails silently, the ERC-20 tokens are already burned (supply reduced, balance zeroed). There is no rollback, no escrow, and no retry mechanism. The user's funds are permanently destroyed with no corresponding credit on NEAR or Ethereum. This matches the "Permanent freezing of funds" impact category. [4](#0-3) 

### Likelihood Explanation

**High.** The `recipient` parameter in `withdrawToNear` is a raw `bytes` value supplied entirely by the caller. Any caller who provides a byte sequence that does not parse as a valid NEAR account ID (e.g., an empty string, a string with illegal characters, or a string exceeding NEAR's 64-character account ID limit) will trigger the silent failure. This is a realistic user error and requires no special privileges — any token holder can trigger it on their own funds. [1](#0-0) [5](#0-4) 

### Recommendation

Reorder operations so the precompile call is made **before** the burn, and revert if the call fails. Alternatively, check the assembly return value and revert on failure:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures tokens are only burned when the precompile call succeeds, preventing permanent fund loss on precompile failure. [6](#0-5) 

### Proof of Concept

1. Deploy `EvmErc20` and mint tokens to a test address `alice`.
2. `alice` calls `withdrawToNear(invalidRecipient, amount)` where `invalidRecipient` is a byte sequence that is not a valid NEAR account ID (e.g., `bytes("!!invalid!!")`).
3. `_burn(alice, amount)` executes — `alice`'s balance is reduced to zero, total supply decreases.
4. The assembly `call` to the `ExitToNear` precompile returns `0` because `parse_recipient` returns `ERR_INVALID_RECEIVER_ACCOUNT_ID`.
5. The assembly block does not check `res`; the function returns normally.
6. `alice` has lost `amount` tokens permanently: no NEAR transfer was scheduled, no refund was issued, and the tokens cannot be recovered. [1](#0-0) [7](#0-6)

### Citations

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-76)
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
