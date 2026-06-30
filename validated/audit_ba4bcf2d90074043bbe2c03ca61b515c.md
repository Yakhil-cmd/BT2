Let me look at the `FtTransferMessageData` parsing and the `EvmErc20V2.sol` mint function to confirm the full picture before writing the report.

### Title
Missing Zero-Address Validation in `receive_base_tokens` Allows Permanent Loss of Bridged ETH - (File: `engine/src/engine.rs`)

---

### Summary

The `receive_base_tokens` function in `engine/src/engine.rs` mints bridged ETH (base tokens) to a recipient address parsed from the `msg` field of `FtOnTransferArgs` without ever validating that the recipient is not the zero address (`0x0000000000000000000000000000000000000000`). Any user who calls `ft_transfer_call` on the ETH connector with `msg = "0000000000000000000000000000000000000000"` will have their ETH permanently credited to the zero address on Aurora, from which it can never be recovered. No privileged access is required.

---

### Finding Description

The bridge deposit flow for ETH works as follows:

1. A user calls `ft_transfer_call` on the ETH connector contract with `receiver_id = aurora` and `msg = <recipient_address_hex>`.
2. The ETH connector calls `ft_on_transfer` on the Aurora engine contract.
3. `ft_on_transfer` in `engine/src/contract_methods/connector.rs` dispatches to `engine.receive_base_tokens(&args)` when `predecessor_account_id == get_connector_account_id(&io)`.
4. `receive_base_tokens` in `engine/src/engine.rs` calls `FtTransferMessageData::try_from(args.msg.as_str())` to parse the recipient.
5. `FtTransferMessageData::try_from` in `engine-types/src/parameters/connector.rs` decodes the 40-character hex string into an `Address` with no zero-address check.
6. Back in `receive_base_tokens`, `set_balance` is called unconditionally to credit the ETH to whatever address was parsed.

Neither `FtTransferMessageData::try_from` nor `receive_base_tokens` contains any guard against the zero address. The `is_zero()` method exists on `Address` (confirmed by 29 uses elsewhere in `engine/src/engine.rs`) but is absent from this path. There is also no `ERR_ZERO_ADDRESS` constant in `engine/src/errors.rs`, confirming the check was never added.

Contrast this with the ERC-20 path: `receive_erc20_tokens` ultimately calls the Solidity `_mint` function in `EvmErc20V2.sol`, which inherits OpenZeppelin's `ERC20._mint` that reverts on `address(0)`. The base-ETH path has no equivalent guard.

**Root cause**: `FtTransferMessageData::try_from` (lines 40–104, `engine-types/src/parameters/connector.rs`) and `receive_base_tokens` (lines 773–789, `engine/src/engine.rs`) both accept the zero address as a valid recipient without error.

---

### Impact Explanation

When ETH is minted to `Address::zero()`, the balance is written to the engine's internal storage under the zero address key. No private key for the zero address exists; the funds are permanently inaccessible. This constitutes **permanent freezing of bridged user funds**. The total supply accounting on the NEAR side is decremented (the ETH connector burns the NEP-141 tokens), while the corresponding ETH on the Aurora side is locked forever at the zero address — a permanent, irrecoverable loss.

---

### Likelihood Explanation

The `ft_transfer_call` entry point is callable by any NEAR account holder with no special permissions. The zero address is a syntactically valid 40-character hex string (`"0000000000000000000000000000000000000000"`). A user could supply it accidentally (e.g., a buggy frontend, a copy-paste error, or a misconfigured integration script). The bridge is a high-traffic, high-value path, making accidental misuse realistic over time.

---

### Recommendation

Add a zero-address guard in `receive_base_tokens` immediately after parsing the recipient:

```rust
pub fn receive_base_tokens(
    &mut self,
    args: &FtOnTransferArgs,
) -> Result<Option<SubmitResult>, ContractError> {
    let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
    let amount = Wei::new_u128(args.amount.as_u128());
    let receipient = message_data.recipient;

    // ADD: reject zero address to prevent permanent fund loss
    if receipient.is_zero() {
        return Err(errors::ERR_INVALID_RECIPIENT.into());
    }

    let balance = get_balance(&self.io, &receipient);
    // ...
}
```

Alternatively (or additionally), reject the zero address inside `FtTransferMessageData::try_from` so the protection applies to all callers of that parser.

---

### Proof of Concept

1. User holds 1 ETH worth of NEP-141 tokens on the NEAR side (e.g., obtained via the standard bridge deposit).
2. User calls `ft_transfer_call` on the ETH connector contract:
   - `receiver_id = "aurora"`
   - `amount = "1000000000000000000"` (1 ETH in wei)
   - `msg = "0000000000000000000000000000000000000000"` (zero address)
3. ETH connector calls `ft_on_transfer` on Aurora with `predecessor_account_id = <connector_account>`.
4. `ft_on_transfer` (connector.rs line 81) matches the connector branch and calls `engine.receive_base_tokens(&args)`.
5. `receive_base_tokens` (engine.rs line 777) calls `FtTransferMessageData::try_from("0000000000000000000000000000000000000000")`.
6. `try_from` (connector.rs line 41–56) decodes the string to `[0u8; 20]` and returns `Address::from_array([0u8; 20])` — the zero address — with no error.
7. `set_balance` (engine.rs line 785) writes 1 ETH to the zero address in engine storage.
8. `ft_on_transfer` returns `Ok(None)`, signalling success; the ETH connector does **not** refund the tokens.
9. The 1 ETH is permanently frozen at the zero address. The user's NEP-141 balance is gone and the ETH is unrecoverable. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** engine/src/engine.rs (L773-789)
```rust
    pub fn receive_base_tokens(
        &mut self,
        args: &FtOnTransferArgs,
    ) -> Result<Option<SubmitResult>, ContractError> {
        let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
        let amount = Wei::new_u128(args.amount.as_u128());
        let receipient = message_data.recipient;
        let balance = get_balance(&self.io, &receipient);
        let new_balance = balance
            .checked_add(amount)
            .ok_or(errors::ERR_BALANCE_OVERFLOW)?;

        set_balance(&mut self.io, &receipient, &new_balance);

        sdk::log!("Mint {amount} base tokens for: {}", receipient.encode());

        Ok(None)
```

**File:** engine-types/src/parameters/connector.rs (L40-56)
```rust
    fn try_from(message: &str) -> Result<Self, Self::Error> {
        if message.len() == 40 {
            // Parse message to determine recipient
            let recipient = {
                // Message format:
                // Recipient of the transaction - 40 characters (Address in hex)
                let mut address_bytes = [0; 20];
                hex::decode_to_slice(message, &mut address_bytes)
                    .map_err(|_| errors::ParseOnTransferMessageError::InvalidHexData)?;
                Address::from_array(address_bytes)
            };

            #[allow(deprecated)]
            return Ok(Self {
                recipient,
                fee: None,
            });
```

**File:** engine/src/contract_methods/connector.rs (L61-108)
```rust
#[named]
pub fn ft_on_transfer<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<Option<SubmitResult>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let current_account_id = env.current_account_id();
        let predecessor_account_id = env.predecessor_account_id();
        let mut engine: Engine<_, _> = Engine::new(
            predecessor_address(&predecessor_account_id),
            current_account_id.clone(),
            io,
            env,
        )?;

        sdk::log!("Call ft_on_transfer");

        let args: FtOnTransferArgs = read_json_args(&io)?;
        let result = if predecessor_account_id == get_connector_account_id(&io)? {
            engine.receive_base_tokens(&args)
        } else {
            engine.receive_erc20_tokens(
                &predecessor_account_id,
                &args,
                &current_account_id,
                handler,
            )
        };

        #[allow(clippy::used_underscore_binding)]
        let amount_to_return = if let Err(_err) = &result {
            sdk::log!("Error in ft_on_transfer: {_err:?}");
            // An error occurred, so we need to return the amount of tokens to the sender.
            args.amount.as_u128()
        } else {
            // Everything is ok, so return 0.
            0
        };

        let output = crate::prelude::format!("\"{amount_to_return}\"");
        io.return_output(output.as_bytes());

        // In case of an error, we just return Ok(None) to avoid a panic in the contract. It's ok
        // because in case of an error, we already returned the amount of tokens to the sender.
        Ok(result.unwrap_or(None))
    })
```

**File:** engine/src/errors.rs (L1-51)
```rust
pub use aurora_engine_types::parameters::engine::errors::{
    ERR_CALL_TOO_DEEP, ERR_CREATE_COLLISION, ERR_CREATE_CONTRACT_LIMIT, ERR_CREATE_EMPTY,
    ERR_DESIGNATED_INVALID, ERR_INVALID_CODE, ERR_INVALID_JUMP, ERR_INVALID_RANGE,
    ERR_MAX_FEE_PER_GAS_LESS_THAN_BASE_FEE, ERR_MAX_NONCE, ERR_NOT_ALLOWED, ERR_OUT_OF_FUND,
    ERR_OUT_OF_GAS, ERR_OUT_OF_OFFSET, ERR_REVERT, ERR_STACK_OVERFLOW, ERR_STACK_UNDERFLOW,
};

pub const ERR_BALANCE_OVERFLOW: &[u8] = b"ERR_BALANCE_OVERFLOW";
pub const ERR_CONNECTOR_STORAGE_KEY_NOT_FOUND: &[u8] = b"ERR_CONNECTOR_STORAGE_KEY_NOT_FOUND";
pub const ERR_DECODING_TOKEN: &[u8] = b"ERR_DECODING_TOKEN";
pub const ERR_FIXED_GAS_OVERFLOW: &[u8] = b"ERR_FIXED_GAS_OVERFLOW";
pub const ERR_FUNCTION_CALL_KEY_NOT_FOUND: &[u8] = b"ERR_FUNCTION_CALL_KEY_NOT_FOUND";
pub const ERR_GAS_ETH_AMOUNT_OVERFLOW: &[u8] = b"ERR_GAS_ETH_AMOUNT_OVERFLOW";
pub const ERR_GAS_OVERFLOW: &[u8] = b"ERR_GAS_OVERFLOW";
pub const ERR_GETTING_ERC20_FROM_NEP141: &[u8] = b"ERR_GETTING_ERC20_FROM_NEP141";
pub const ERR_INCORRECT_NONCE: &[u8] = b"ERR_INCORRECT_NONCE";
pub const ERR_INTRINSIC_GAS: &[u8] = b"ERR_INTRINSIC_GAS";
pub const ERR_INVALID_ACCOUNT_ID: &[u8] = b"ERR_INVALID_ACCOUNT_ID";
pub const ERR_INVALID_AMOUNT: &[u8] = b"ERR_INVALID_AMOUNT";
pub const ERR_INVALID_CHAIN_ID: &[u8] = b"ERR_INVALID_CHAIN_ID";
pub const ERR_INVALID_ECDSA_SIGNATURE: &[u8] = b"ERR_INVALID_ECDSA_SIGNATURE";
pub const ERR_INVALID_NEP141_ACCOUNT_ID: &[u8] = b"ERR_INVALID_NEP141_ACCOUNT_ID";
pub const ERR_INVALID_SENDER: &[u8] = b"ERR_INVALID_SENDER";
pub const ERR_INVALID_UPGRADE: &[u8] = b"ERR_INVALID_UPGRADE";
pub const ERR_KEY_MANAGER_IS_NOT_SET: &[u8] = b"ERR_KEY_MANAGER_IS_NOT_SET";
pub const ERR_MAX_PRIORITY_FEE_GREATER: &[u8] = b"ERR_MAX_PRIORITY_FEE_GREATER";
pub const ERR_NEP141_NOT_FOUND: &[u8] = b"ERR_NEP141_NOT_FOUND";
pub const ERR_NEP141_TOKEN_ALREADY_REGISTERED: &[u8] = b"ERR_NEP141_TOKEN_ALREADY_REGISTERED";
pub const ERR_NO_AVAILABLE_BALANCE: &[u8] = b"ERR_NO_AVAILABLE_BALANCE";
pub const ERR_NO_UPGRADE: &[u8] = b"ERR_NO_UPGRADE";
pub const ERR_NOT_ALLOWED_TOO_EARLY: &[u8] = b"ERR_NOT_ALLOWED:TOO_EARLY";
pub const ERR_NOT_ENOUGH_BALANCE: &[u8] = b"ERR_NOT_ENOUGH_BALANCE";
pub const ERR_NOT_OWNER: &[u8] = b"ERR_NOT_OWNER";
pub const ERR_NOT_SUPPORTED: &[u8] = b"ERR_NOT_SUPPORTED";
pub const ERR_OVERFLOW_NUMBER: &[u8] = b"ERR_OVERFLOW_NUMBER";
pub const ERR_PARSE_ADDRESS: &[u8] = b"ERR_PARSE_ADDRESS";
pub const ERR_PAUSED: &[u8] = b"ERR_PAUSED";
pub const ERR_PROMISE_COUNT: &[u8] = b"ERR_PROMISE_COUNT";
pub const ERR_REFUND_FAILURE: &[u8] = b"ERR_REFUND_FAILURE";
pub const ERR_REJECT_CALL_WITH_CODE: &[u8] = b"ERR_REJECT_CALL_WITH_CODE";
pub const ERR_RUNNING: &[u8] = b"ERR_RUNNING";
pub const ERR_SAME_KEY_MANAGER: &[u8] = b"ERR_SAME_KEY_MANAGER";
pub const ERR_SAME_OWNER: &[u8] = b"ERR_SAME_OWNER";
pub const ERR_TOKEN_NO_VALUE: &[u8] = b"ERR_TOKEN_NO_VALUE";
pub const ERR_UNHANDLED_INTERRUPT: &[u8] = b"ERR_UNHANDLED_INTERRUPT";
pub const ERR_WRONG_TOKEN_TYPE: &[u8] = b"ERR_WRONG_TOKEN_TYPE";

pub const ERR_ARGS: &str = "ERR_ARGS";
pub const ERR_BORSH_DESERIALIZE: &str = "ERR_BORSH_DESERIALIZE";
pub const ERR_JSON_DESERIALIZE: &str = "ERR_JSON_DESERIALIZE";
pub const ERR_SERIALIZE: &str = "ERR_SERIALIZE";
```
