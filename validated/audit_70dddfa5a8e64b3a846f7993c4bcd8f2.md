### Title
`receive_base_tokens` Bypasses Silo Address Whitelist, Permanently Freezing ETH - (`engine/src/engine.rs`)

### Summary

In Silo mode, `receive_erc20_tokens` correctly redirects ERC-20 token mints to a fallback address when the intended recipient is not on the `Address` whitelist. The analogous function `receive_base_tokens` — which mints native ETH (base tokens) — performs no such whitelist check. Any caller can mint ETH directly to any non-whitelisted EVM address, bypassing the silo's access control. Because non-whitelisted addresses cannot submit EVM transactions, the minted ETH is permanently frozen.

### Finding Description

Aurora Engine's Silo mode enforces an `Address` whitelist (`WhitelistKind::Address`) that restricts which EVM addresses may submit transactions. When Silo params are set (including an `erc20_fallback_address`), the intent is that tokens sent to non-whitelisted addresses are redirected to the fallback address instead.

`receive_erc20_tokens` implements this correctly:

```rust
// engine/src/engine.rs:818-822
if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
    && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
{
    recipient = fallback_address;
}
``` [1](#0-0) 

`receive_base_tokens` has no equivalent check:

```rust
// engine/src/engine.rs:773-790
pub fn receive_base_tokens(
    &mut self,
    args: &FtOnTransferArgs,
) -> Result<Option<SubmitResult>, ContractError> {
    let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
    let amount = Wei::new_u128(args.amount.as_u128());
    let receipient = message_data.recipient;
    // ... no whitelist check ...
    set_balance(&mut self.io, &receipient, &new_balance);
    Ok(None)
}
``` [2](#0-1) 

The dispatch between the two paths is in `ft_on_transfer`:

```rust
// engine/src/contract_methods/connector.rs:81-90
let result = if predecessor_account_id == get_connector_account_id(&io)? {
    engine.receive_base_tokens(&args)   // ← no whitelist check
} else {
    engine.receive_erc20_tokens(...)    // ← has whitelist check
};
``` [3](#0-2) 

The `is_allow_receive_erc20_tokens` function used by the ERC-20 path delegates to `is_address_allowed`, which checks the `Address` whitelist: [4](#0-3) 

The same `Address` whitelist is enforced on transaction submission via `assert_access` → `is_allow_submit`: [5](#0-4) 

So any EVM address not on the `Address` whitelist cannot submit transactions, meaning ETH minted to it is unspendable.

### Impact Explanation

**Critical — Permanent freezing of funds.**

When Silo mode is active with the `Address` whitelist enabled:

1. An attacker calls `ft_transfer_call` on the ETH connector NEP-141 contract, specifying any non-whitelisted EVM address in the `msg` field.
2. The ETH connector calls `ft_on_transfer` on Aurora Engine.
3. `receive_base_tokens` mints ETH to the attacker-specified address with no whitelist check.
4. The non-whitelisted address cannot submit EVM transactions (`assert_access` blocks it), so the ETH is permanently frozen.

Additionally, the silo operator's fallback address — intended to capture tokens sent to non-whitelisted addresses — never receives the ETH, breaking the silo's accounting invariant. For ERC-20 tokens the fallback works; for base ETH it does not. [6](#0-5) 

### Likelihood Explanation

**Medium.** This requires Silo mode to be active with both the `Address` whitelist enabled and a fallback address configured — the intended production configuration for a Silo deployment. Any unprivileged NEAR account can trigger this by calling `ft_transfer_call` on the ETH connector with an arbitrary recipient address in the message. No special permissions are required beyond holding ETH connector NEP-141 tokens.

### Recommendation

Apply the same whitelist-and-fallback redirect logic to `receive_base_tokens` that already exists in `receive_erc20_tokens`:

```rust
pub fn receive_base_tokens(
    &mut self,
    args: &FtOnTransferArgs,
) -> Result<Option<SubmitResult>, ContractError> {
    let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
    let amount = Wei::new_u128(args.amount.as_u128());
    let mut receipient = message_data.recipient;

    // Apply the same silo whitelist redirect as receive_erc20_tokens
    if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
        && !silo::is_allow_receive_erc20_tokens(&self.io, &receipient)
    {
        receipient = fallback_address;
    }

    let balance = get_balance(&self.io, &receipient);
    let new_balance = balance
        .checked_add(amount)
        .ok_or(errors::ERR_BALANCE_OVERFLOW)?;
    set_balance(&mut self.io, &receipient, &new_balance);
    Ok(None)
}
```

### Proof of Concept

**Setup**: Silo mode enabled with `Address` whitelist active and a fallback address set. No EVM addresses are whitelisted.

**Attack**:
1. Attacker holds ETH connector NEP-141 tokens.
2. Attacker calls `ft_transfer_call` on the ETH connector contract:
   - `receiver_id`: Aurora Engine account ID
   - `amount`: any amount
   - `msg`: hex-encoded non-whitelisted EVM address (e.g., attacker's own EVM address)
3. ETH connector calls `ft_on_transfer` on Aurora Engine.
4. `ft_on_transfer` routes to `receive_base_tokens` (predecessor is the ETH connector).
5. `receive_base_tokens` mints ETH to the non-whitelisted address — no whitelist check, no fallback redirect.
6. The non-whitelisted address now holds ETH but cannot call `submit` (blocked by `assert_access` → `is_allow_submit` → `is_address_allowed` returns false).
7. ETH is permanently frozen. The fallback address receives nothing. [2](#0-1) [7](#0-6) [8](#0-7)

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

**File:** engine/src/engine.rs (L1756-1775)
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

**File:** engine/src/contract_methods/silo/mod.rs (L140-158)
```rust
/// Check if a user has the right to receive erc20 tokens.
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}

fn is_account_allowed_deploy<I: IO + Copy>(io: &I, account_id: &AccountId) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Admin);
    !list.is_enabled() || list.is_exist(account_id)
}

fn is_address_allowed_deploy<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::EvmAdmin);
    !list.is_enabled() || list.is_exist(address)
}

fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}
```

**File:** engine-types/src/parameters/silo.rs (L15-24)
```rust
#[derive(Debug, Default, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SiloParamsArgs {
    /// Fixed amount of gas per transaction.
    pub fixed_gas: EthGas,
    /// EVM address, which is used for withdrawing ERC-20 base tokens in case
    /// a recipient of the tokens is not in the silo white list.
    /// Note: the logic described above works only if the fallback address
    /// is set by `set_silo_params` function. In other words, in Silo mode.
    pub erc20_fallback_address: Address,
}
```
