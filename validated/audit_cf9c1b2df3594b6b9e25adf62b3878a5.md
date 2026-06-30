### Title
Unchecked Exit-Precompile Return Value in `withdrawToNear`/`withdrawToEthereum` Causes Permanent Token Loss — (File: `etc/eth-contracts/contracts/EvmErc20.sol`)

---

### Summary

`EvmErc20` and `EvmErc20V2` burn ERC-20 tokens **before** calling the Aurora exit precompile, but never check the precompile's return value. If the precompile call fails at the EVM level (returning `0`), the ERC-20 tokens are permanently destroyed while no NEAR-side NEP-141 transfer is ever scheduled. The two accounting systems — the ERC-20 balance ledger and the NEP-141 ledger held by Aurora — diverge irreversibly, permanently freezing the corresponding NEP-141 funds inside Aurora.

---

### Finding Description

In both `EvmErc20.withdrawToNear` and `EvmErc20V2.withdrawToNear`, the contract executes `_burn(_msgSender(), amount)` first, permanently reducing the caller's ERC-20 balance and the token's total supply. It then calls the `exitToNear` precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` via inline assembly:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
}
``` [1](#0-0) [2](#0-1) 

The variable `res` is captured but **never checked**. The function does not contain any `if iszero(res) { revert(0, 0) }` guard. The same pattern is present in `withdrawToEthereum` in both contracts. [3](#0-2) [4](#0-3) 

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) returns `ExitError::Other(...)` — a **non-fatal** EVM error — in several reachable cases. In SputnikVM (Aurora's EVM), a non-fatal precompile error causes the sub-`call` to return `0` while the calling contract's execution continues uninterrupted. The `_burn` that already executed is **not rolled back**.

The precompile fails with `ExitError::Other(...)` when:

1. **`ERR_INVALID_RECEIVER_ACCOUNT_ID`** — the `recipient` bytes are not valid UTF-8 or do not form a valid NEAR account ID (e.g., contain `\xff\xfe`, exceed 64 characters, or contain forbidden characters). [5](#0-4) 

2. **`ERR_INVALID_AMOUNT`** — the `amount` field exceeds `u128::MAX` (a valid `uint256` but rejected by the precompile). [6](#0-5) 

3. **`ERR_TARGET_TOKEN_NOT_FOUND`** — the calling ERC-20 contract's address is absent from the `Erc20Nep141Map` storage. [7](#0-6) 

When any of these conditions is met, the precompile returns `0` from the `call` opcode, `withdrawToNear` does not revert, and the state diverges:

| Layer | State after failed call |
|---|---|
| ERC-20 (`_balances`) | Tokens burned — total supply reduced |
| NEP-141 (Aurora's holding) | Unchanged — tokens remain locked in Aurora |

The NEP-141 tokens are now permanently stranded inside Aurora with no ERC-20 tokens left to redeem them.

---

### Impact Explanation

**Permanent freezing of funds.** The user's ERC-20 tokens are irreversibly destroyed. The corresponding NEP-141 tokens remain locked inside the Aurora engine contract with no on-chain mechanism to recover them, because the only redemption path (holding ERC-20 tokens and calling `withdrawToNear`) has been severed. This is a direct, permanent loss of bridged user assets.

---

### Likelihood Explanation

Any token holder can trigger this by calling `withdrawToNear` with a `recipient` argument that is not a valid NEAR account ID — for example, arbitrary bytes, a string longer than 64 characters, or bytes containing characters outside the NEAR account ID character set. No special privilege is required. The function is `external` with no access control or `pausable` modifier. [8](#0-7) 

Users unfamiliar with NEAR account ID constraints (lowercase alphanumeric, `_`, `-`, `.`, max 64 chars) can easily supply an invalid value, especially when interacting programmatically or through a third-party interface.

---

### Recommendation

Add a revert guard immediately after the precompile `call` in both `withdrawToNear` and `withdrawToEthereum` in both `EvmErc20` and `EvmErc20V2`:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures that if the precompile rejects the call for any reason, the entire transaction (including the `_burn`) is atomically reverted, keeping the ERC-20 and NEP-141 ledgers in sync.

---

### Proof of Concept

1. Deploy `EvmErc20` with a registered NEP-141 mapping (normal bridge deployment).
2. Mint `1000` tokens to address `Alice`.
3. Alice calls:
   ```solidity
   evmErc20.withdrawToNear(
       hex"fffedeadbeef",   // invalid UTF-8 — not a valid NEAR account ID
       1000
   );
   ```
4. Inside `withdrawToNear`:
   - `_burn(Alice, 1000)` executes — Alice's ERC-20 balance drops to 0, total supply decreases by 1000.
   - The precompile is called with the invalid recipient bytes.
   - The precompile's `parse_recipient` fails with `ERR_INVALID_RECEIVER_ACCOUNT_ID` and returns `ExitError::Other(...)`.
   - The `call` opcode returns `0`.
   - `res` is never checked; the function returns normally.
5. **Result**: Alice has 0 ERC-20 tokens. Aurora still holds 1000 NEP-141 tokens. No NEAR-side transfer was ever scheduled. The 1000 NEP-141 tokens are permanently frozen inside Aurora. [1](#0-0) [9](#0-8) [10](#0-9)

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

**File:** engine-precompiles/src/native.rs (L419-447)
```rust
        let exit_to_near_params = ExitToNearParams::try_from(input)?;

        let (nep141_address, args, exit_event, method, transfer_near_args) =
            match exit_to_near_params {
                // ETH(base) token transfer
                //
                // Input slice format:
                //  recipient_account_id (bytes) - the NEAR recipient account which will receive
                //  NEP-141 (base) tokens, or also can contain the `:unwrap` suffix in case of
                //  withdrawing wNEAR, or another message of JSON in case of OMNI, or address of
                //  receiver in case of transfer tokens to another engine contract.
                ExitToNearParams::BaseToken(ref exit_params) => {
                    let eth_connector_account_id = self.get_eth_connector_contract_account()?;
                    exit_base_token_to_near(eth_connector_account_id, context, exit_params)?
                }
                // ERC-20 token transfer
                //
                // This precompile branch is expected to be called from the ERC-20 burn function.
                //
                // Input slice format:
                //  amount (U256 big-endian bytes) - the amount that was burned
                //  recipient_account_id (bytes) - the NEAR recipient account which will receive
                //  NEP-141 tokens, or also can contain the `:unwrap` suffix in case of withdrawing
                //  wNEAR, or another message of JSON in case of OMNI, or address of receiver in case
                //  of transfer tokens to another engine contract.
                ExitToNearParams::Erc20TokenParams(ref exit_params) => {
                    exit_erc20_token_to_near(context, exit_params, &self.io)?
                }
            };
```

**File:** engine-precompiles/src/native.rs (L558-583)
```rust
fn exit_erc20_token_to_near<I: IO>(
    context: &Context,
    exit_params: &Erc20TokenParams,
    io: &I,
) -> Result<
    (
        AccountId,
        String,
        events::ExitToNear,
        String,
        Option<TransferNearArgs>,
    ),
    ExitError,
> {
    // In case of withdrawing ERC-20 tokens, the `apparent_value` should be zero. In opposite way
    // the funds will be locked in the address of the precompile without any possibility
    // to withdraw them in the future. So, in case if the `apparent_value` is not zero, the error
    // will be returned to prevent that.
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
    }

    let erc20_address = context.caller; // because ERC-20 contract calls the precompile.
    let nep141_account_id = get_nep141_from_erc20(erc20_address.as_bytes(), io)?;
```
