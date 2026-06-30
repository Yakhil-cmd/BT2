### Title
Unchecked Precompile Call Return Value in `withdrawToNear`/`withdrawToEthereum` Causes Permanent Token Loss - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` burn the caller's ERC-20 tokens before invoking the Aurora exit precompile via a low-level assembly `call()`. The return value of that `call()` is stored in a local assembly variable `res` but is **never checked**. If the precompile call fails and returns 0 (a non-reverting `ExitError`), the burn is permanent and no withdrawal is ever issued, resulting in irreversible loss of user funds.

---

### Finding Description

In `EvmErc20.sol`, both `withdrawToNear` and `withdrawToEthereum` follow the same pattern:

1. `_burn(_msgSender(), amount)` — permanently destroys the caller's tokens.
2. An inline assembly block issues a low-level `call()` to the exit precompile.
3. The return value `res` is captured but never inspected; no `require(res != 0)` or equivalent guard exists. [1](#0-0) 

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);                          // tokens destroyed here
    ...
    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, ...)
        // res is never checked — silent failure is possible
    }
}
```

The same pattern appears in `withdrawToEthereum`: [2](#0-1) 

And identically in `EvmErc20V2.sol`: [3](#0-2) [4](#0-3) 

The exit precompile's `run()` method returns `EvmPrecompileResult = Result<PrecompileOutput, ExitError>`: [5](#0-4) 

When `run()` returns `Err(ExitError::...)`, the SputnikVM executor wraps it in `PrecompileFailure::Error` — which causes the `call()` opcode to return **0** (failure) without reverting the parent execution context. This is distinct from `PrecompileFailure::Fatal`, which is only used for the explicitly paused case: [6](#0-5) 

The `ExitToNear::run()` function has multiple code paths that return `Err(ExitError::...)`:

- `parse_recipient` returns `ExitError::Other("ERR_INVALID_RECEIVER_ACCOUNT_ID")` for invalid UTF-8 or invalid NEAR account IDs — **directly user-controlled via the `recipient` parameter**.
- `get_nep141_from_erc20` returns `ExitError::Other("ERR_TARGET_TOKEN_NOT_FOUND")` if the ERC-20→NEP-141 mapping is absent.
- `parse_amount` returns `ExitError::Other("ERR_INVALID_AMOUNT")` for amounts exceeding `u128::MAX`. [7](#0-6) [8](#0-7) [9](#0-8) 

---

### Impact Explanation

When the precompile call fails silently:
- `_burn()` has already executed and is irreversible within the transaction.
- No NEAR cross-contract promise is scheduled (the promise log is only emitted on `Ok(...)` from `run()`).
- The user's ERC-20 tokens are permanently destroyed with no corresponding NEP-141 or Ethereum token release.

This constitutes **permanent freezing/destruction of user funds** — a Critical-severity impact.

---

### Likelihood Explanation

The `recipient` parameter in `withdrawToNear` is a raw `bytes memory` value supplied directly by the caller. Any caller passing a recipient that is not valid UTF-8 or not a valid NEAR account ID (e.g., containing forbidden characters, exceeding length limits, or being empty in an unexpected way) will trigger `ERR_INVALID_RECEIVER_ACCOUNT_ID` from `parse_recipient`. This is a realistic accidental or adversarial trigger requiring no special privilege — any token holder can call `withdrawToNear` directly.

---

### Recommendation

After the assembly `call()`, revert if `res` is zero:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Apply the same fix to `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`. Alternatively, validate the `recipient` argument before calling `_burn()` so that the burn only occurs after confirming the precompile will accept the input.

---

### Proof of Concept

1. Deploy `EvmErc20` on Aurora (standard production deployment).
2. Mint tokens to `attacker` address.
3. `attacker` calls `withdrawToNear(bytes("\xff\xfe"), amount)` — `\xff\xfe` is invalid UTF-8.
4. `_burn(attacker, amount)` executes; attacker's balance drops to zero.
5. The precompile's `parse_recipient` fails with `ERR_INVALID_RECEIVER_ACCOUNT_ID`, returning `ExitError` → `PrecompileFailure::Error` → `call()` returns 0.
6. Since `res` is never checked, the transaction succeeds with status OK.
7. No NEAR promise is scheduled; no NEP-141 tokens are released.
8. Attacker's ERC-20 tokens are permanently destroyed with no corresponding withdrawal. [1](#0-0) [9](#0-8)

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

**File:** engine-precompiles/src/lib.rs (L66-66)
```rust
pub type EvmPrecompileResult = Result<PrecompileOutput, ExitError>;
```

**File:** engine-precompiles/src/lib.rs (L140-144)
```rust
        if self.is_paused(&address) {
            return Some(Err(PrecompileFailure::Fatal {
                exit_status: ExitFatal::Other(prelude::Cow::Borrowed("ERR_PAUSED")),
            }));
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
