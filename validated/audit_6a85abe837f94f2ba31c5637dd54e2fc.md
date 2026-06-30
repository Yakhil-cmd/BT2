### Title
Unchecked Precompile Call Return Value in `withdrawToNear` / `withdrawToEthereum` Causes Permanent Token Destruction - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` burn the caller's ERC-20 tokens before making a low-level `call()` to the Aurora exit precompile. The return value of that `call()` is captured in a local variable `res` but is **never checked**. If the precompile call fails for any reason, the tokens are permanently destroyed with no corresponding NEAR-side withdrawal promise ever scheduled.

---

### Finding Description

In `EvmErc20.withdrawToNear` and `EvmErc20.withdrawToEthereum`, the sequence is:

1. `_burn(_msgSender(), amount)` — tokens are irreversibly destroyed in EVM state.
2. A low-level `call()` is made to the exit precompile address (`ExitToNear` at `0xe9217bc7...` or `ExitToEthereum` at `0xb0bd02f6...`).
3. The return value `res` is assigned but **never inspected**; there is no `require(res != 0)` or equivalent revert.

```solidity
// EvmErc20.sol withdrawToNear (lines 53–63)
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked — no revert on failure
    }
}
```

The same pattern appears in `withdrawToEthereum` (lines 65–76) and is identically reproduced in `EvmErc20V2.sol` (lines 53–77).

The `ExitToNear` and `ExitToEthereum` precompiles (`engine-precompiles/src/native.rs`) return `Err(ExitError::...)` — which the EVM translates to a `call()` return value of `0` — in multiple reachable conditions:

- `ERR_TARGET_TOKEN_NOT_FOUND`: the ERC-20 address is not present in the `Erc20Nep141Map` storage (e.g., token deregistered or mapping corrupted).
- `ERR_KEY_NOT_FOUND`: the eth-connector account ID key is absent from storage.
- `ERR_INVALID_AMOUNT`: amount exceeds `u128::MAX` (guarded in the precompile, not in Solidity).
- `ERR_INVALID_RECEIVER_ACCOUNT_ID`: the recipient bytes are not a valid NEAR account ID (validated only inside the precompile, not in Solidity).
- `ERR_INVALID_IN_DELEGATE`: the precompile is invoked via `delegatecall`.

When any of these errors occur, the EVM `call()` returns `0`, the Solidity function does not revert, and the `_burn()` that already executed is **not rolled back**. No NEAR-side promise is ever scheduled. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

**Critical — Permanent freezing / destruction of user funds.**

When the precompile call fails silently, the user's ERC-20 tokens are burned on the Aurora (EVM) side with no corresponding `ft_transfer` or `withdraw` promise dispatched on the NEAR side. The NEP-141 tokens remain locked in the Aurora engine contract forever. There is no recovery path: the ERC-20 supply is reduced, the NEAR-side balance is not released, and no refund mechanism is triggered (the `error_refund` feature in `EvmErc20V2` only handles the case where the precompile succeeds but the downstream NEAR promise fails — it does not help when the precompile call itself returns `0`). [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

**Medium.** The most realistic trigger is a recipient bytes value that passes Solidity-level encoding but is rejected by `parse_recipient` inside the precompile as an invalid NEAR account ID. A user can supply arbitrary `recipient` bytes to `withdrawToNear`; the Solidity function performs no validation. The precompile's `parse_recipient` will return `ERR_INVALID_RECEIVER_ACCOUNT_ID`, the `call()` returns `0`, and the burn is not reverted. Any ERC-20 token holder can trigger this unintentionally (e.g., by passing a recipient string that is too long, contains invalid characters, or is otherwise malformed). A secondary trigger is the `ERR_TARGET_TOKEN_NOT_FOUND` path, reachable if the NEP-141 mapping is ever absent for a deployed ERC-20. [7](#0-6) [8](#0-7) 

---

### Recommendation

In both `EvmErc20.sol` and `EvmErc20V2.sol`, check the return value of the low-level `call()` and revert if it is `0`:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures that if the exit precompile rejects the call for any reason, the entire transaction (including the `_burn`) is reverted, preserving the user's token balance. [9](#0-8) [10](#0-9) 

---

### Proof of Concept

1. Deploy `EvmErc20` (or `EvmErc20V2`) on Aurora with a valid NEP-141 mapping.
2. Mint tokens to `alice` (EVM address).
3. `alice` calls `withdrawToNear(invalidRecipient, amount)` where `invalidRecipient` is a byte string that is not a valid NEAR account ID (e.g., `"!!invalid!!"` or a 65-byte string exceeding NEAR's account ID length limit).
4. Inside the EVM execution:
   - `_burn(alice, amount)` executes — alice's balance is reduced to zero.
   - The `call()` to `ExitToNear` precompile executes; `parse_recipient` returns `ERR_INVALID_RECEIVER_ACCOUNT_ID`; the precompile returns `Err(ExitError::Other(...))`.
   - The EVM `call()` opcode returns `0`.
   - `res` is never checked; the Solidity function returns normally.
5. The transaction succeeds on-chain. Alice's ERC-20 tokens are gone. No NEAR-side `ft_transfer` promise was scheduled. The NEP-141 tokens remain locked in the Aurora engine contract with no recovery path. [1](#0-0) [7](#0-6) [11](#0-10)

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

**File:** engine-precompiles/src/native.rs (L311-319)
```rust
fn get_eth_connector_contract_account<I: IO>(io: &I) -> Result<AccountId, ExitError> {
    io.read_storage(&construct_contract_key(
        EthConnectorStorageId::EthConnectorAccount,
    ))
    .ok_or(ExitError::Other(Cow::Borrowed("ERR_KEY_NOT_FOUND")))
    .and_then(|x| {
        x.to_value()
            .map_err(|_| ExitError::Other(Cow::Borrowed("ERR_DESERIALIZE")))
    })
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

**File:** engine-precompiles/src/native.rs (L484-500)
```rust
        let promise_log = Log {
            address: exit_to_near::ADDRESS.raw(),
            topics: Vec::new(),
            data: borsh::to_vec(&promise).unwrap(),
        };
        let ethabi::RawLog { topics, data } = exit_event.encode();
        let exit_event_log = Log {
            address: exit_to_near::ADDRESS.raw(),
            topics: topics.into_iter().map(|h| H256::from(h.0)).collect(),
            data,
        };

        Ok(PrecompileOutput {
            logs: vec![promise_log, exit_event_log],
            cost: required_gas,
            output: Vec::new(),
        })
```
