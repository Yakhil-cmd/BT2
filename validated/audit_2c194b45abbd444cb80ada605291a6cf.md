### Title
Silo `Address` Whitelist for ERC-20 Token Receipt Is Silently Bypassed When No Fallback Address Is Configured - (`engine/src/engine.rs`)

### Summary

In Aurora Engine's Silo mode, the `receive_erc20_tokens` function in `engine/src/engine.rs` only enforces the `Address` whitelist check when a fallback address is simultaneously configured. When no fallback address is set, the whitelist check is short-circuited entirely, allowing any non-whitelisted EVM address to receive bridged ERC-20 tokens. Because non-whitelisted addresses are blocked from submitting EVM transactions by `assert_access`, any tokens minted to such an address become permanently frozen.

### Finding Description

The guard in `receive_erc20_tokens` is:

```rust
// engine/src/engine.rs:818-822
if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
    && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
{
    recipient = fallback_address;
}
``` [1](#0-0) 

The compound condition requires **both** a fallback address to exist **and** the recipient to be non-whitelisted before any enforcement occurs. When `get_erc20_fallback_address` returns `None`, the `&&` short-circuits and the whitelist check (`!is_allow_receive_erc20_tokens`) is never evaluated. The non-whitelisted `recipient` is used as-is and tokens are minted to it.

The whitelist check itself is correct in isolation:

```rust
// engine/src/contract_methods/silo/mod.rs:141-143
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}

// engine/src/contract_methods/silo/mod.rs:155-158
fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}
``` [2](#0-1) [3](#0-2) 

When the `Address` whitelist is enabled and the recipient is absent from it, `is_allow_receive_erc20_tokens` correctly returns `false`. But this result is only acted upon when a fallback address exists. The whitelist is therefore rendered ineffective whenever the fallback address is absent.

The fallback address can be independently cleared by the owner via `set_erc20_fallback_address` with `None`:

```rust
// engine/src/contract_methods/silo/mod.rs:65-73
pub fn set_erc20_fallback_address<I: IO>(io: &mut I, address: Option<Address>) {
    let key = erc20_fallback_address_key();
    if let Some(address) = address {
        io.write_storage(&key, address.as_bytes());
    } else {
        io.remove_storage(&key);
    }
}
``` [4](#0-3) 

This means the `Address` whitelist and the fallback address are independently configurable, and the whitelist enforcement for ERC-20 receipt is silently disabled whenever the fallback is absent.

### Impact Explanation

Once tokens are minted to a non-whitelisted EVM address, they cannot be moved. The `assert_access` function blocks all EVM transaction submission from non-whitelisted addresses:

```rust
// engine/src/engine.rs:1756-1774
fn assert_access<I: IO + Copy, E: Env>(
    io: &I,
    env: &E,
    transaction: &NormalizedEthTransaction,
) -> Result<(), EngineError> {
    let allowed = if transaction.to.is_some() {
        silo::is_allow_submit(io, &env.predecessor_account_id(), &transaction.address)
    } else {
        silo::is_allow_deploy(io, &env.predecessor_account_id(), &transaction.address)
    };
    if !allowed {
        return Err(EngineError { kind: EngineErrorKind::NotAllowed, gas_used: 0 });
    }
    Ok(())
}
``` [5](#0-4) 

`is_allow_submit` uses the same `Address` whitelist:

```rust
// engine/src/contract_methods/silo/mod.rs:136-138
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}
``` [6](#0-5) 

A non-whitelisted address that receives ERC-20 tokens cannot call `transfer`, `approve`, or any other ERC-20 function, nor can it invoke the `ExitToNear` precompile. The tokens are permanently frozen in that address. Additionally, `ft_on_transfer` returns `0` on success, meaning the NEP-141 tokens are **not** returned to the sender:

```rust
// engine/src/contract_methods/connector.rs:93-100
let amount_to_return = if let Err(_err) = &result {
    args.amount.as_u128()
} else {
    // Everything is ok, so return 0.
    0
};
``` [7](#0-6) 

**Impact: Permanent freezing of bridged ERC-20 funds. Critical.**

### Likelihood Explanation

The `Address` whitelist and the fallback address are independently managed. A silo operator who:
- Enables the `Address` whitelist to restrict token recipients, but
- Has not yet set a fallback address, or
- Clears the fallback address via `set_erc20_fallback_address(None)` while the whitelist remains active

will silently lose whitelist enforcement for all incoming `ft_on_transfer` calls. Any user who bridges NEP-141 tokens to a non-whitelisted EVM address during this window will have their tokens frozen. The operator has no on-chain indication that enforcement has been disabled.

### Recommendation

Decouple the whitelist enforcement from the fallback address existence. If the recipient is not allowed and no fallback address is configured, the function should return an error so that `ft_on_transfer` refunds the sender:

```rust
// engine/src/engine.rs:818-822 — suggested fix
if !silo::is_allow_receive_erc20_tokens(&self.io, &recipient) {
    match silo::get_erc20_fallback_address(&self.io) {
        Some(fallback) => recipient = fallback,
        None => return Err(/* RecipientNotAllowed error */),
    }
}
```

This ensures the `Address` whitelist is always enforced regardless of fallback address configuration, and that the sender's tokens are returned when no fallback is available.

### Proof of Concept

1. Deploy Aurora Engine in Silo mode.
2. Enable the `Address` whitelist (`WhitelistKind::Address`).
3. Do **not** set an ERC-20 fallback address (or call `set_erc20_fallback_address` with `None` to clear it).
4. From any NEAR account, call `ft_transfer_call` on a registered NEP-141 token contract, specifying Aurora as `receiver_id` and a non-whitelisted EVM address as the `msg` recipient.
5. Observe: `ft_on_transfer` succeeds, ERC-20 tokens are minted to the non-whitelisted address, and `0` tokens are returned to the sender.
6. Attempt to submit any EVM transaction from the non-whitelisted address — it is rejected with `NotAllowed`.
7. The bridged ERC-20 tokens are permanently frozen.

### Citations

**File:** engine/src/engine.rs (L818-822)
```rust
        if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
            && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
        {
            recipient = fallback_address;
        }
```

**File:** engine/src/engine.rs (L1756-1774)
```rust
fn assert_access<I: IO + Copy, E: Env>(
    io: &I,
    env: &E,
    transaction: &NormalizedEthTransaction,
) -> Result<(), EngineError> {
    let allowed = if transaction.to.is_some() {
        silo::is_allow_submit(io, &env.predecessor_account_id(), &transaction.address)
    } else {
        silo::is_allow_deploy(io, &env.predecessor_account_id(), &transaction.address)
    };

    if !allowed {
        return Err(EngineError {
            kind: EngineErrorKind::NotAllowed,
            gas_used: 0,
        });
    }

    Ok(())
```

**File:** engine/src/contract_methods/silo/mod.rs (L65-73)
```rust
pub fn set_erc20_fallback_address<I: IO>(io: &mut I, address: Option<Address>) {
    let key = erc20_fallback_address_key();

    if let Some(address) = address {
        io.write_storage(&key, address.as_bytes());
    } else {
        io.remove_storage(&key);
    }
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L136-138)
```rust
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L141-143)
```rust
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

**File:** engine/src/contract_methods/connector.rs (L93-100)
```rust
        let amount_to_return = if let Err(_err) = &result {
            sdk::log!("Error in ft_on_transfer: {_err:?}");
            // An error occurred, so we need to return the amount of tokens to the sender.
            args.amount.as_u128()
        } else {
            // Everything is ok, so return 0.
            0
        };
```
