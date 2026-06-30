### Title
Silo Address Whitelist Bypass in `receive_base_tokens` Allows ETH to Be Minted to Non-Whitelisted Addresses, Permanently Freezing Funds - (File: `engine/src/engine.rs`)

---

### Summary

In Silo mode, `receive_erc20_tokens` enforces the Address whitelist and redirects tokens to the configured `erc20_fallback_address` when the recipient is not whitelisted. The parallel function `receive_base_tokens`, which handles bridged native ETH arriving via the ETH connector, performs **no whitelist check at all**, allowing any caller to mint ETH directly to a non-whitelisted EVM address. Because that address cannot submit transactions (the `submit` path does enforce the whitelist), the minted ETH is permanently frozen.

---

### Finding Description

Aurora Silo mode exposes an `Address` whitelist that restricts which EVM addresses may interact with the Silo. The enforcement is applied in `is_allow_submit` (called during `submit`) and in `receive_erc20_tokens` (called during `ft_on_transfer` for NEP-141 tokens).

`receive_erc20_tokens` explicitly checks `is_allow_receive_erc20_tokens` and, when the recipient is not whitelisted, silently redirects the mint to the `erc20_fallback_address`:

```rust
// engine/src/engine.rs  lines 818-822
if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
    && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
{
    recipient = fallback_address;
}
```

`receive_base_tokens`, which handles ETH bridged from the official ETH connector, contains **no equivalent check**:

```rust
// engine/src/engine.rs  lines 773-789
pub fn receive_base_tokens(
    &mut self,
    args: &FtOnTransferArgs,
) -> Result<Option<SubmitResult>, ContractError> {
    let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
    let amount = Wei::new_u128(args.amount.as_u128());
    let receipient = message_data.recipient;          // ← no whitelist check
    let balance = get_balance(&self.io, &receipient);
    let new_balance = balance
        .checked_add(amount)
        .ok_or(errors::ERR_BALANCE_OVERFLOW)?;
    set_balance(&mut self.io, &receipient, &new_balance);
    Ok(None)
}
```

The `ft_on_transfer` dispatcher in `contract_methods/connector.rs` routes to `receive_base_tokens` whenever the caller is the registered ETH connector account, and to `receive_erc20_tokens` for all other NEP-141 tokens:

```rust
// engine/src/contract_methods/connector.rs  lines 81-90
let result = if predecessor_account_id == get_connector_account_id(&io)? {
    engine.receive_base_tokens(&args)
} else {
    engine.receive_erc20_tokens(...)
};
```

Because the ETH connector is a public contract, any NEAR account can call `ft_transfer_call` on it, specifying an arbitrary EVM address as the recipient in the `msg` field. The Aurora Engine will mint the corresponding ETH balance to that address with no whitelist validation.

The `is_allow_receive_erc20_tokens` helper used by the ERC-20 path simply delegates to `is_address_allowed`, which reads the `WhitelistKind::Address` list:

```rust
// engine/src/contract_methods/silo/mod.rs  lines 141-143
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}
```

No analogous call exists in `receive_base_tokens`.

---

### Impact Explanation

**Permanent freezing of funds (Critical).**

ETH minted to a non-whitelisted address is irrecoverable without admin intervention:

- The `submit` entrypoint enforces `is_allow_submit`, which calls `is_address_allowed`. A non-whitelisted address cannot sign any EVM transaction that the engine will accept.
- There is no on-chain self-service recovery path for the trapped ETH.
- The funds remain locked in the non-whitelisted address's EVM balance indefinitely unless the Silo admin explicitly whitelists the address or the Silo operator manually intervenes.

The asymmetry is exact: ERC-20 tokens sent to a non-whitelisted address are safely redirected to the `erc20_fallback_address`; base ETH is not, and is lost.

---

### Likelihood Explanation

**High.**

- The ETH connector is a public NEAR contract; no special role or permission is required to call `ft_transfer_call`.
- The `msg` field that specifies the EVM recipient is fully attacker-controlled.
- The Silo Address whitelist is the primary access-control mechanism for Silo deployments; any Silo operator who enables it is exposed.
- No complex preconditions are needed beyond the Silo being configured with the Address whitelist enabled.

---

### Recommendation

Apply the same whitelist-and-fallback logic in `receive_base_tokens` that already exists in `receive_erc20_tokens`. If the recipient is not whitelisted and a fallback address is configured (i.e., Silo mode is active), redirect the ETH mint to the `erc20_fallback_address`:

```rust
pub fn receive_base_tokens(
    &mut self,
    args: &FtOnTransferArgs,
) -> Result<Option<SubmitResult>, ContractError> {
    let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
    let amount = Wei::new_u128(args.amount.as_u128());
    let mut recipient = message_data.recipient;

    // Mirror the whitelist check from receive_erc20_tokens
    if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
        && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
    {
        recipient = fallback_address;
    }

    let balance = get_balance(&self.io, &recipient);
    let new_balance = balance
        .checked_add(amount)
        .ok_or(errors::ERR_BALANCE_OVERFLOW)?;
    set_balance(&mut self.io, &recipient, &new_balance);
    Ok(None)
}
```

---

### Proof of Concept

1. Silo is deployed with `SiloParamsArgs` set (enabling the `erc20_fallback_address`) and the `Address` whitelist enabled.
2. `victim_address` (an EVM address) is **not** in the Address whitelist.
3. An attacker (any NEAR account) calls `ft_transfer_call` on the ETH connector, specifying `aurora` as the receiver and encoding `victim_address` in the `msg` field.
4. The ETH connector calls `ft_on_transfer` on the Aurora Engine.
5. Because `predecessor_account_id == eth_connector`, `receive_base_tokens` is invoked.
6. `receive_base_tokens` parses `victim_address` from `msg` and calls `set_balance` with no whitelist check — ETH is minted to `victim_address`.
7. `victim_address` now holds ETH but cannot call `submit` (blocked by `is_allow_submit` → `is_address_allowed`).
8. The ETH is permanently frozen; the `erc20_fallback_address` mechanism that would have protected ERC-20 tokens was never consulted.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** engine/src/engine.rs (L773-790)
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
    }
```

**File:** engine/src/engine.rs (L818-822)
```rust
        if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
            && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
        {
            recipient = fallback_address;
        }
```

**File:** engine/src/contract_methods/connector.rs (L81-90)
```rust
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
