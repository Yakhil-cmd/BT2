### Title
Unchecked Exit Precompile Return Value Burns ERC-20 Tokens Without Guaranteeing NEP-141 Transfer — (`File: etc/eth-contracts/contracts/EvmErc20.sol`)

---

### Summary

`EvmErc20.sol` burns a user's ERC-20 tokens **before** calling the `exitToNear` precompile via inline assembly, and **never checks the return value** of that call. If the precompile call fails for any reason, the ERC-20 tokens are permanently destroyed while no NEP-141 transfer is ever scheduled. This creates an irreversible accounting mismatch between the ERC-20 supply on Aurora and the NEP-141 balance held by the connector on NEAR, directly analogous to the reported pattern of a bridge contract accepting a promised amount without guaranteeing the backing balance is sufficient or the transfer will succeed.

---

### Finding Description

In `EvmErc20.sol`, `withdrawToNear` executes the following sequence:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← tokens destroyed here, unconditionally

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                        0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked
    }
}
``` [1](#0-0) 

The `exitToNear` precompile (`engine-precompiles/src/native.rs`) can return failure (`ExitError`) for several reasons reachable from user-supplied input:

- `recipient` bytes are not valid UTF-8 → `ERR_INVALID_RECEIVER_ACCOUNT_ID`
- `recipient` is not a parseable NEAR account ID → `ERR_INVALID_RECEIVER_ACCOUNT_ID`
- The connector account key is absent from storage → `ERR_KEY_NOT_FOUND`
- The NEP-141 ↔ ERC-20 mapping is missing → `ERR_TARGET_TOKEN_NOT_FOUND` [2](#0-1) 

When the precompile returns failure, the EVM reverts only the precompile's own sub-call state. The `_burn` in the caller frame has already committed. Because `EvmErc20.sol` does not check `res` and does not revert, the outer transaction succeeds with the user's tokens gone and no promise ever created.

The `EvmErc20V2.sol` variant was introduced precisely to carry a `sender` refund address in the input so the `error_refund` callback path can re-mint tokens on failure. `EvmErc20.sol` predates this and has no such protection. [3](#0-2) 

The `error_refund` callback path in the Rust engine (`exit_to_near_precompile_callback`) only fires when the precompile itself successfully schedules a promise with a callback attached. If the precompile never returns `Ok(...)` (i.e., it fails before emitting the promise log), no callback is ever registered and no refund occurs. [4](#0-3) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

A user's ERC-20 tokens are irreversibly burned. The corresponding NEP-141 balance held by the connector on NEAR is never reduced. The ERC-20 total supply decreases while the NEP-141 backing balance does not, creating a permanent accounting deficit: the remaining ERC-20 holders collectively hold claims against a NEP-141 pool that is now larger than the ERC-20 supply, but the affected user's share is gone with no recourse.

---

### Likelihood Explanation

**Medium.**

The `recipient` parameter is a raw `bytes` argument. Any caller who passes bytes that are not valid UTF-8 or not a valid NEAR account ID (e.g., bytes containing `0x80`–`0xFF`, an account ID exceeding 64 characters, or an empty slice) will trigger the failure path. This is reachable by any unprivileged EVM user interacting with any `EvmErc20`-based bridged token. No special privilege or contract compromise is required. [2](#0-1) 

---

### Recommendation

Check the assembly `call` return value and revert on failure, mirroring the pattern already adopted in `EvmErc20V2.sol`:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                    0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures `_burn` is atomically rolled back whenever the precompile cannot schedule the exit promise, preserving the ERC-20 ↔ NEP-141 accounting invariant.

---

### Proof of Concept

1. Deploy an `EvmErc20` contract on Aurora (or use an existing bridged token).
2. Mint tokens to address `A`.
3. From address `A`, call `withdrawToNear(bytes("\x80\x81\x82"), amount)` — `\x80\x81\x82` is invalid UTF-8.
4. The `_burn` reduces `A`'s ERC-20 balance by `amount`.
5. The `exitToNear` precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` returns `ExitError::Other("ERR_INVALID_RECEIVER_ACCOUNT_ID")` because `str::from_utf8` fails.
6. The assembly `call` returns `0`; `res` is discarded; the function returns normally.
7. `A`'s ERC-20 tokens are permanently destroyed. No NEP-141 transfer is ever scheduled. The connector's NEP-141 balance on NEAR is unchanged. [1](#0-0) [5](#0-4)

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

**File:** engine-precompiles/src/native.rs (L419-420)
```rust
        let exit_to_near_params = ExitToNearParams::try_from(input)?;

```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-60)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        address sender = _msgSender();
        _burn(sender, amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
        uint input_size = 1 + 20 + 32 + recipient.length;

```

**File:** engine/src/contract_methods/connector.rs (L231-239)
```rust
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
```
