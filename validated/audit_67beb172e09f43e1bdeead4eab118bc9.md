The code path is fully confirmed. Here is the complete analysis:

---

### Title
Unchecked Precompile Return Value After `_burn` in `withdrawToNear` Allows Permanent Token Loss — (`etc/eth-contracts/contracts/EvmErc20.sol`)

### Summary

`withdrawToNear` burns ERC-20 tokens before calling the `ExitToNear` precompile, and never checks the return value of that call. If the precompile rejects the recipient (e.g., invalid NEAR `AccountId`), the burn is committed but no NEP-141 transfer promise is created, permanently destroying the user's tokens.

### Finding Description

In `EvmErc20.sol`, `withdrawToNear` executes `_burn` unconditionally before invoking the `ExitToNear` precompile via a raw assembly `call`:

```solidity
// etc/eth-contracts/contracts/EvmErc20.sol, lines 53-63
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← burn committed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                        0, add(input, 32), input_size, 0, 32)
        // res is never read or checked
    }
}
``` [1](#0-0) 

The precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` is `ExitToNear`. Its `run` method calls `ExitToNearParams::try_from(input)`, which calls `parse_recipient`, which calls `receiver_account_id.parse()` — a full `AccountId::validate` check:

```rust
// engine-precompiles/src/native.rs, lines 359-378
fn parse_recipient(recipient: &[u8]) -> Result<Recipient<'_>, ExitError> {
    let recipient = str::from_utf8(recipient)
        .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECEIVER_ACCOUNT_ID")))?;
    ...
    Ok(Recipient {
        receiver_account_id: receiver_account_id
            .parse()
            .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECEIVER_ACCOUNT_ID")))?,
        ...
    })
}
``` [2](#0-1) 

`AccountId::validate` rejects uppercase letters, strings starting/ending with separators, strings exceeding 64 characters, and other patterns — all of which can be valid UTF-8: [3](#0-2) 

When `parse_recipient` returns `Err(ExitError::Other(...))`, `process_precompile` maps it to `PrecompileFailure::Error` (not `Fatal`):

```rust
// engine-precompiles/src/lib.rs, lines 164-175
fn process_precompile(...) -> Result<PrecompileOutput, PrecompileFailure> {
    p.run(input, gas_limit.map(EthGas::new), context, is_static)
        .map_err(|exit_status| PrecompileFailure::Error { exit_status })
}
``` [4](#0-3) 

`PrecompileFailure::Error` is standard EVM call-failure semantics: the `call` opcode returns `0` to the caller, but the **calling frame's state is not reverted**. Because `res` is never read, `withdrawToNear` returns successfully with the burn already committed and no NEP-141 transfer promise ever emitted.

### Impact Explanation

The user's ERC-20 balance is reduced to zero. No corresponding NEP-141 `ft_transfer` or `ft_transfer_call` promise is created. The tokens are permanently destroyed with no recovery path. This satisfies **Critical — Permanent freezing of funds**.

### Likelihood Explanation

Any unprivileged EVM user can trigger this by passing a `recipient` byte string that is valid UTF-8 but fails NEAR `AccountId` rules. The `AccountId` ruleset rejects a large class of common strings (uppercase letters, leading/trailing hyphens or underscores, strings over 64 bytes, `@` characters, etc.). No special privilege, admin key, or infrastructure compromise is required — only a standard ERC-20 `withdrawToNear` call with a crafted `recipient` argument.

### Recommendation

Move `_burn` to **after** a successful precompile call, or check `res` and revert on failure:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                    0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Alternatively, restructure so that `_burn` is only called after the precompile confirms the recipient is valid (e.g., by performing a dry-run validation before burning).

### Proof of Concept

1. Deploy `EvmErc20` on a local Aurora sandbox.
2. Mint tokens to address `A`.
3. From `A`, call `withdrawToNear("UPPERCASE.NEAR", amount)` — valid UTF-8, invalid `AccountId` (uppercase).
4. Observe: `balanceOf(A)` is now `0`; no NEP-141 `ft_transfer` promise was emitted in the transaction logs; NEP-141 balance of any NEAR account is unchanged.
5. Repeat with `"-invalid"` (leading hyphen), `"a"` (too short), and a 65-character lowercase string (too long) — all produce the same result.

The invariant "recipient validation failure must revert the entire operation including the burn" is violated in every case.

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

**File:** engine-types/src/account_id.rs (L32-64)
```rust
    pub fn validate(account_id: &str) -> Result<(), ParseAccountError> {
        if account_id.len() < MIN_ACCOUNT_ID_LEN {
            Err(ParseAccountError::TooShort)
        } else if account_id.len() > MAX_ACCOUNT_ID_LEN {
            Err(ParseAccountError::TooLong)
        } else {
            // Adapted from https://github.com/near/near-sdk-rs/blob/fd7d4f82d0dfd15f824a1cf110e552e940ea9073/near-sdk/src/environment/env.rs#L819

            // NOTE: We don't want to use Regex here, because it requires extra time to compile it.
            // The valid account ID regex is /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/
            // Instead the implementation is based on the previous character checks.

            // We can safely assume that last char was a separator.
            let mut last_char_is_separator = true;

            for c in account_id.bytes() {
                let current_char_is_separator = match c {
                    b'a'..=b'z' | b'0'..=b'9' => false,
                    b'-' | b'_' | b'.' => true,
                    _ => {
                        return Err(ParseAccountError::Invalid);
                    }
                };
                if current_char_is_separator && last_char_is_separator {
                    return Err(ParseAccountError::Invalid);
                }
                last_char_is_separator = current_char_is_separator;
            }

            (!last_char_is_separator)
                .then_some(())
                .ok_or(ParseAccountError::Invalid)
        }
```

**File:** engine-precompiles/src/lib.rs (L164-175)
```rust
fn process_precompile(
    p: &dyn Precompile,
    handle: &impl PrecompileHandle,
) -> Result<PrecompileOutput, PrecompileFailure> {
    let input = handle.input();
    let gas_limit = handle.gas_limit();
    let context = handle.context();
    let is_static = handle.is_static();

    p.run(input, gas_limit.map(EthGas::new), context, is_static)
        .map_err(|exit_status| PrecompileFailure::Error { exit_status })
}
```
