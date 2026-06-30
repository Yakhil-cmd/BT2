### Title
ERC-20 Tokens Permanently Frozen When Silo Address Whitelist Is Active and No Fallback Address Is Configured - (`engine/src/engine.rs`)

---

### Summary

In Silo mode with the `Address` whitelist enabled and no ERC-20 fallback address set, `receive_erc20_tokens` silently mints ERC-20 tokens to a non-whitelisted recipient without reverting. Because non-whitelisted addresses are blocked from submitting any EVM transaction (including `exit_to_near`), the minted tokens are permanently inaccessible. The sender's NEP-141 tokens are simultaneously consumed with no refund path.

---

### Finding Description

`receive_erc20_tokens` in `engine/src/engine.rs` implements a conditional redirect:

```rust
if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
    && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
{
    recipient = fallback_address;
}
``` [1](#0-0) 

This is a Rust `if let` chain: both sub-conditions must be true for the redirect to fire. When `get_erc20_fallback_address` returns `None` (no fallback configured), the entire block is skipped regardless of whether the recipient is whitelisted. The original non-whitelisted `recipient` is then passed directly into the ERC-20 mint call:

```rust
let result = self
    .call(
        &erc20_admin_address,
        &erc20_token,
        Wei::zero(),
        setup_receive_erc20_tokens_input(&recipient, amount),
        u64::MAX,
        ...
    )
    .and_then(submit_result_or_err)?;
``` [2](#0-1) 

The ERC-20 contract (`EvmErc20.sol`) has no silo whitelist check of its own, so the mint succeeds. `ft_on_transfer` then returns `0` to the NEP-141 contract, signalling success and causing the NEP-141 tokens to be permanently transferred to Aurora rather than refunded:

```rust
let amount_to_return = if let Err(_err) = &result {
    args.amount.as_u128()   // refund on error
} else {
    0                        // no refund on success
};
``` [3](#0-2) 

The non-whitelisted address now holds ERC-20 tokens but is blocked from submitting any EVM transaction by `assert_access`:

```rust
let allowed = if transaction.to.is_some() {
    silo::is_allow_submit(io, &env.predecessor_account_id(), &transaction.address)
} else {
    silo::is_allow_deploy(io, &env.predecessor_account_id(), &transaction.address)
};
if !allowed {
    return Err(EngineError { kind: EngineErrorKind::NotAllowed, gas_used: 0 });
}
``` [4](#0-3) 

`is_allow_submit` delegates to `is_address_allowed`, which returns `false` for any address not in the `Address` whitelist when that whitelist is enabled:

```rust
fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}
``` [5](#0-4) 

Because `exit_to_near` is invoked via an EVM transaction (the ERC-20 `withdrawToNear` call), the non-whitelisted address cannot call it either. There is no alternative withdrawal path. The tokens are permanently frozen.

The same structural gap exists in `receive_base_tokens`, which mints ETH (base tokens) to any address with **no whitelist check whatsoever**, making ETH bridged to a non-whitelisted address equally unrecoverable in Silo mode:

```rust
pub fn receive_base_tokens(
    &mut self,
    args: &FtOnTransferArgs,
) -> Result<Option<SubmitResult>, ContractError> {
    let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
    let receipient = message_data.recipient;
    ...
    set_balance(&mut self.io, &receipient, &new_balance);
``` [6](#0-5) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

The sender's NEP-141 tokens are irrevocably transferred to Aurora (the `ft_on_transfer` success response prevents any NEP-141 refund). The ERC-20 tokens minted to the non-whitelisted address are permanently inaccessible because every EVM execution path that could move them (`submit`, `call`, `exit_to_near`) is gated behind the same whitelist check. There is no admin-callable rescue function for frozen ERC-20 balances.

---

### Likelihood Explanation

**Medium.**

Silo mode is an explicitly supported production feature of Aurora Engine. The fallback address is an optional configuration: `set_erc20_fallback_address` accepts `None` and `set_silo_params` can be called without ever setting a fallback. Any deployment that enables the `Address` whitelist without also configuring a fallback address is vulnerable. An unprivileged user triggers the freeze simply by calling `ft_transfer_call` on any bridged NEP-141 token and specifying a non-whitelisted EVM address in the `msg` field — a standard bridge operation. No special privileges or timing are required.

---

### Recommendation

In `receive_erc20_tokens`, when the `Address` whitelist is enabled and the recipient is not whitelisted and no fallback address is configured, the function must return an `Err(...)` rather than proceeding with the mint. Returning an error causes `ft_on_transfer` to return the full token amount to the sender, preventing the freeze:

```rust
if !silo::is_allow_receive_erc20_tokens(&self.io, &recipient) {
    if let Some(fallback) = silo::get_erc20_fallback_address(&self.io) {
        recipient = fallback;
    } else {
        // No fallback: refuse the transfer so NEP-141 tokens are refunded.
        return Err(/* ERR_RECIPIENT_NOT_WHITELISTED */);
    }
}
```

Apply the same guard to `receive_base_tokens`, which currently has no whitelist check at all.

---

### Proof of Concept

1. Deploy Aurora Engine in Silo mode: enable the `Address` whitelist (`set_whitelist_status` with `WhitelistKind::Address, active: true`). Do **not** call `set_erc20_fallback_address` (or call it with `None`).
2. Deploy a NEP-141 token and its corresponding ERC-20 on Aurora via `deploy_erc20_token`.
3. As an unprivileged user, call `ft_transfer_call` on the NEP-141 contract with `receiver_id = aurora`, `amount = X`, and `msg = <hex of non-whitelisted EVM address>`.
4. The NEP-141 contract calls `ft_on_transfer` on Aurora → `receive_erc20_tokens` executes → `get_erc20_fallback_address` returns `None` → the `if let Some(...)` block is skipped → ERC-20 mint to the non-whitelisted address succeeds.
5. `ft_on_transfer` returns `"0"` → NEP-141 `ft_resolve_transfer` keeps the transfer → sender's NEP-141 balance is permanently reduced.
6. Attempt to call `submit` or `call` from the non-whitelisted address → `EngineErrorKind::NotAllowed` is returned.
7. The ERC-20 tokens at the non-whitelisted address are permanently frozen with no recovery path.

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

**File:** engine/src/engine.rs (L818-822)
```rust
        if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
            && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
        {
            recipient = fallback_address;
        }
```

**File:** engine/src/engine.rs (L826-837)
```rust
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

**File:** engine/src/contract_methods/silo/mod.rs (L155-158)
```rust
fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}
```
