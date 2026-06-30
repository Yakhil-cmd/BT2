### Title
Non-Whitelisted EVM Address Can Receive Base Tokens (ETH) via `receive_base_tokens`, Bypassing the Silo `Address` Whitelist - (File: `engine/src/engine.rs`)

---

### Summary

In Silo mode, the `Address` whitelist is intended to restrict which EVM addresses can receive tokens. The `receive_erc20_tokens` path correctly enforces this check and redirects tokens to a fallback address when the recipient is not whitelisted. However, the `receive_base_tokens` path — triggered when the ETH connector calls `ft_on_transfer` — performs **no whitelist check at all**, allowing any EVM address, including those explicitly excluded from the `Address` whitelist, to receive ETH (base tokens) via the bridge.

---

### Finding Description

In `engine/src/contract_methods/connector.rs`, `ft_on_transfer` branches on whether the caller is the ETH connector account: [1](#0-0) 

When the caller is the ETH connector, `engine.receive_base_tokens(&args)` is called. That function directly mints ETH to the recipient address parsed from `args.msg` with no whitelist check: [2](#0-1) 

By contrast, the ERC-20 path (`receive_erc20_tokens`) explicitly checks `silo::is_allow_receive_erc20_tokens` and redirects to the fallback address if the recipient is not whitelisted: [3](#0-2) 

The `is_allow_receive_erc20_tokens` function checks the `Address` whitelist: [4](#0-3) 

The `Address` whitelist is documented to control which EVM addresses can "submit transactions or receive tokens": [5](#0-4) 

The asymmetry is clear: ERC-20 token receipt is gated by the whitelist; ETH (base token) receipt is not.

---

### Impact Explanation

In a Silo deployment where the operator has enabled the `Address` whitelist to restrict which EVM addresses may receive tokens, any EVM address — including those intentionally excluded — can still receive ETH by having anyone bridge ETH through the ETH connector and specifying the excluded address as the recipient in the `msg` field. This violates the intended access control invariant of the Silo whitelist system and allows unauthorized addresses to accumulate ETH inside the Silo.

**Impact: High — Whitelist bypass enabling unauthorized fund receipt by excluded addresses.**

---

### Likelihood Explanation

The ETH connector is a standard, always-available part of the Aurora system. Any NEAR account can initiate an ETH bridge transfer and specify an arbitrary EVM address as the recipient. No special privileges are required. The `Address` whitelist is only enforced on the ERC-20 path, so the bypass is unconditional whenever the ETH connector is the `ft_on_transfer` caller. Likelihood is **High** for any Silo deployment that relies on the `Address` whitelist to restrict token receipt.

---

### Recommendation

Apply the same whitelist check in `receive_base_tokens` that is applied in `receive_erc20_tokens`. If a fallback address is configured and the recipient is not in the `Address` whitelist, redirect the ETH mint to the fallback address (or reject the transfer). Specifically, add a call to `silo::is_allow_receive_erc20_tokens` (or an equivalent `is_allow_receive_base_tokens` helper) before `set_balance` in `receive_base_tokens`, mirroring the guard at lines 818–822 of `engine/src/engine.rs`.

---

### Proof of Concept

1. Operator deploys Aurora in Silo mode, enables the `Address` whitelist, and adds only `0xWhitelisted` to it. `0xExcluded` is intentionally not whitelisted.
2. Attacker (or any NEAR account) calls the ETH connector's `ft_transfer_call` targeting the Aurora contract, with `msg` encoding `0xExcluded` as the recipient.
3. The ETH connector calls `ft_on_transfer` on Aurora. Since `predecessor_account_id == get_connector_account_id`, `receive_base_tokens` is invoked.
4. `receive_base_tokens` parses `0xExcluded` from `args.msg` and calls `set_balance` directly — no whitelist check occurs.
5. `0xExcluded` now holds ETH inside the Silo, bypassing the operator's `Address` whitelist restriction, in direct contrast to the ERC-20 path which would have redirected tokens to the fallback address. [6](#0-5)

### Citations

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

**File:** engine/src/contract_methods/silo/mod.rs (L140-143)
```rust
/// Check if a user has the right to receive erc20 tokens.
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}
```

**File:** engine-types/src/parameters/silo.rs (L76-79)
```rust
    Account = 0x2,
    /// The whitelist of this type is for storing EVM addresses. Addresses included in this
    /// whitelist can submit transactions.
    Address = 0x3,
```
