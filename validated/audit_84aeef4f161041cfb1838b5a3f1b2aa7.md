### Title
Silo `Address` Whitelist for ERC-20 Token Receipt Is Silently Bypassed When No Fallback Address Is Configured - (`engine/src/engine.rs`)

---

### Summary

In Aurora Engine's Silo mode, the `Address` whitelist is supposed to restrict which EVM addresses can receive ERC-20 tokens via the bridge (`ft_on_transfer`). However, the whitelist check in `receive_erc20_tokens` is only evaluated when an ERC-20 fallback address is configured. When no fallback address is set, the check is skipped entirely, and any EVM address — including those explicitly removed from the whitelist — can receive ERC-20 tokens.

---

### Finding Description

In `engine/src/engine.rs`, the `receive_erc20_tokens` function contains the following logic:

```rust
if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
    && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
{
    recipient = fallback_address;
}
``` [1](#0-0) 

This is a combined `if let` + `&&` guard. The whitelist check `is_allow_receive_erc20_tokens` is only reached when `get_erc20_fallback_address` returns `Some(...)`. When no fallback address is configured (returns `None`), the entire branch is skipped and the original `recipient` is used unconditionally — regardless of whether the `Address` whitelist is enabled and whether the recipient is in it.

The `is_allow_receive_erc20_tokens` function itself correctly checks the `Address` whitelist:

```rust
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}
``` [2](#0-1) 

```rust
fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}
``` [3](#0-2) 

The check is sound in isolation, but it is never called when no fallback address is set.

The `ft_on_transfer` entrypoint has no caller restriction — any NEP-141 token contract can invoke it:

```rust
pub extern "C" fn ft_on_transfer() {
    let io = Runtime;
    let env = Runtime;
    let mut handler = Runtime;
    contract_methods::connector::ft_on_transfer(io, &env, &mut handler)
        .map_err(ContractError::msg)
        .sdk_unwrap();
}
``` [4](#0-3) 

---

### Impact Explanation

**High — Temporary freezing of funds.**

When a Silo operator enables the `Address` whitelist (to restrict which EVM addresses may receive ERC-20 tokens) but does not configure a fallback address, the whitelist is silently not enforced for ERC-20 receipt. Any user can call `ft_transfer_call` on a NEP-141 token with Aurora as the receiver and a non-whitelisted EVM address in the message. The tokens are minted to that non-whitelisted address.

Because the same `Address` whitelist also gates transaction submission (`is_allow_submit`), the non-whitelisted address cannot submit EVM transactions to move or exit the tokens:

```rust
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}
``` [5](#0-4) 

The result is ERC-20 tokens frozen at an address that cannot use them, until the operator manually adds the address to the whitelist or removes the whitelist restriction.

---

### Likelihood Explanation

**Medium.** The vulnerable configuration — `Address` whitelist enabled, no fallback address set — is plausible in at least two realistic scenarios:

1. An operator enables the whitelist during initial Silo setup before configuring the fallback address.
2. An operator calls `set_erc20_fallback_address` with `None` to remove the fallback (e.g., to change it) without first disabling the whitelist. [6](#0-5) 

In both cases, the operator believes the whitelist is protecting ERC-20 receipt, but it is not.

---

### Recommendation

Decouple the whitelist enforcement from the fallback address configuration. The whitelist check should be applied unconditionally when the `Address` whitelist is enabled. If the recipient is not allowed and no fallback address is configured, the function should return an error (causing the NEP-141 tokens to be returned to the sender), rather than silently minting to the non-whitelisted address.

```rust
// Proposed fix
if !silo::is_allow_receive_erc20_tokens(&self.io, &recipient) {
    match silo::get_erc20_fallback_address(&self.io) {
        Some(fallback) => recipient = fallback,
        None => return Err(/* ERR_NOT_ALLOWED or similar */),
    }
}
```

---

### Proof of Concept

1. Silo operator calls `set_whitelist_status` with `WhitelistKind::Address, active: true` — the `Address` whitelist is now enforced.
2. Operator does **not** call `set_erc20_fallback_address` (or calls it with `None`).
3. A NEP-141 token is registered with Aurora via `deploy_erc20_token`.
4. An attacker calls `ft_transfer_call` on the NEP-141 token, targeting Aurora, with `msg` set to the hex-encoded address of a non-whitelisted EVM address `victim_addr`.
5. Aurora's `ft_on_transfer` is triggered; `receive_erc20_tokens` is called.
6. `get_erc20_fallback_address` returns `None` → the `if let Some(...)` branch is not entered → `is_allow_receive_erc20_tokens` is never called.
7. ERC-20 tokens are minted to `victim_addr`.
8. `victim_addr` is not in the `Address` whitelist, so `is_allow_submit` returns `false` for any transaction from that address.
9. The ERC-20 tokens are frozen at `victim_addr` until the operator intervenes. [7](#0-6) [8](#0-7)

### Citations

**File:** engine/src/engine.rs (L796-843)
```rust
    pub fn receive_erc20_tokens<P: PromiseHandler>(
        &mut self,
        token: &AccountId,
        args: &FtOnTransferArgs,
        current_account_id: &AccountId,
        handler: &mut P,
    ) -> Result<Option<SubmitResult>, ContractError> {
        let amount = args.amount.as_u128();
        // Parse message to determine recipient
        let mut recipient = {
            // The message should contain the recipient EOA address.
            let message = args.msg.strip_prefix("0x").unwrap_or(&args.msg);
            // Recipient - 40 characters (Address in hex without '0x' prefix)
            if message.len() < 40 {
                return Err(ParseOnTransferMessageError::WrongMessageFormat.into());
            }
            let mut address_bytes = [0; 20];
            hex::decode_to_slice(&message[..40], &mut address_bytes)
                .map_err(|_| ParseOnTransferMessageError::WrongMessageFormat)?;
            Address::from_array(address_bytes)
        };

        if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
            && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
        {
            recipient = fallback_address;
        }

        let erc20_token = get_erc20_from_nep141(&self.io, token)?;
        let erc20_admin_address = current_address(current_account_id);
        let result = self
            .call(
                &erc20_admin_address,
                &erc20_token,
                Wei::zero(),
                setup_receive_erc20_tokens_input(&recipient, amount),
                u64::MAX,
                Vec::new(), // TODO: are there values we should put here?
                Vec::new(),
                handler,
            )
            .and_then(submit_result_or_err)?;

        sdk::log!("Mint {amount} ERC-20 tokens for: {}", recipient.encode());

        // Return SubmitResult so that it can be accessed in standalone engine.
        // This is used to help with the indexing of bridge transactions.
        Ok(Some(result))
```

**File:** engine/src/contract_methods/silo/mod.rs (L64-73)
```rust
/// Set ERC-20 fallback address.
pub fn set_erc20_fallback_address<I: IO>(io: &mut I, address: Option<Address>) {
    let key = erc20_fallback_address_key();

    if let Some(address) = address {
        io.write_storage(&key, address.as_bytes());
    } else {
        io.remove_storage(&key);
    }
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L135-138)
```rust
/// Check if a user has the right to submit transactions.
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L140-143)
```rust
/// Check if a user has the right to receive erc20 tokens.
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L155-158)
```rust
fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}
```

**File:** engine/src/lib.rs (L602-610)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn ft_on_transfer() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::ft_on_transfer(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine/src/contract_methods/connector.rs (L61-109)
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
}
```
