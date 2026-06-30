### Title
Missing Whitelist Fallback for Base-Token (ETH) Deposits in Silo Mode Causes Permanent Fund Freeze — (File: `engine/src/engine.rs`)

### Summary
In Silo mode with the `Address` whitelist enabled, `receive_erc20_tokens` redirects ERC-20 tokens to a configured `erc20_fallback_address` when the intended recipient is not whitelisted. The analogous function `receive_base_tokens` — which handles ETH (base token) deposits — performs no such check and has no fallback redirect. ETH minted to a non-whitelisted EVM address that has no associated NEAR account cannot be exited, because the only exit path (`ExitToNear` precompile) requires submitting an EVM transaction, which is blocked by the whitelist. The funds are permanently frozen.

### Finding Description

`receive_erc20_tokens` in `engine/src/engine.rs` explicitly checks the `Address` whitelist and silently redirects tokens to the fallback address when the recipient is not allowed: [1](#0-0) 

`receive_base_tokens`, called on the same `ft_on_transfer` code path when the predecessor is the ETH connector, performs no equivalent check: [2](#0-1) 

The recipient address is taken directly from the transfer message and written to storage with no whitelist validation and no fallback redirect. Any EVM address — including smart-contract addresses that have no associated NEAR account — can receive ETH this way.

To exit ETH, the holder must call the `ExitToNear` precompile (address `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`) with `apparent_value > 0`, which requires submitting an EVM transaction. In Silo mode the `submit` path enforces: [3](#0-2) [4](#0-3) 

A non-whitelisted address is rejected. The NEAR `call` entrypoint derives the EVM caller from the NEAR predecessor account; for a pure EVM smart-contract address (no NEAR account mapping), no NEAR account can produce that caller, so `call` cannot be used as an escape hatch either.

The `erc20_fallback_address` is set as part of `SiloParamsArgs` and is only consulted by `receive_erc20_tokens`: [5](#0-4) [6](#0-5) 

There is no equivalent storage key or code path consulted by `receive_base_tokens`.

### Impact Explanation
ETH deposited to a non-whitelisted EVM address (e.g., a deployed smart-contract address) in a Silo deployment with the `Address` whitelist active is permanently unrecoverable. The deposit succeeds; every exit attempt is rejected by the whitelist. This is a **permanent freezing of funds** (Critical).

### Likelihood Explanation
The condition requires: (a) Silo mode deployed with the `Address` whitelist enabled, and (b) a caller who sends ETH to Aurora specifying a non-whitelisted EVM address as recipient. Both conditions are normal operational states for a Silo deployment. Any unprivileged NEAR account can trigger `ft_on_transfer` on the ETH connector with an arbitrary recipient address in the message field, making this externally reachable without any special privilege.

### Recommendation
Add the same whitelist-and-fallback guard to `receive_base_tokens` that already exists in `receive_erc20_tokens`:

```rust
if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
    && !silo::is_allow_receive_erc20_tokens(&self.io, &receipient)
{
    receipient = fallback_address;
}
```

Alternatively, introduce a dedicated base-token fallback address and apply the same redirect logic before calling `set_balance`.

### Proof of Concept

1. Deploy Aurora Engine in Silo mode; enable the `Address` whitelist; configure an `erc20_fallback_address`.
2. Deploy an EVM smart contract inside Aurora — its address is not whitelisted and has no NEAR account mapping.
3. From any NEAR account, call `ft_transfer_call` on the ETH connector with `msg` encoding the smart-contract address as recipient. The ETH connector calls `ft_on_transfer` on Aurora.
4. `ft_on_transfer` routes to `receive_base_tokens` (predecessor == connector account). `receive_base_tokens` mints ETH to the smart-contract address with no whitelist check.
5. Attempt to exit: submit an EVM transaction from the smart-contract address calling the `ExitToNear` precompile (`0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`) with `value > 0`. The `submit` path calls `is_allow_submit` → `is_address_allowed` → address not in whitelist → `ERR_NOT_ALLOWED`.
6. No NEAR account maps to the smart-contract EVM address, so the `call` entrypoint cannot produce the required caller either.
7. ETH is permanently frozen. [7](#0-6) [2](#0-1) [8](#0-7) [9](#0-8)

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

**File:** engine/src/engine.rs (L796-844)
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
    }
```

**File:** engine/src/contract_methods/silo/mod.rs (L59-62)
```rust
pub fn get_erc20_fallback_address<I: IO>(io: &I) -> Option<Address> {
    let key = erc20_fallback_address_key();
    io.read_storage(&key)?.to_value().ok()
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L136-143)
```rust
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}

/// Check if a user has the right to receive erc20 tokens.
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}
```

**File:** engine/src/contract_methods/silo/whitelist.rs (L40-47)
```rust
    /// Check if the whitelist is enabled.
    pub fn is_enabled(&self) -> bool {
        // White list is disabled by default. So return `false` if the key doesn't exist.
        let key = self.key(STATUS);
        self.io
            .read_storage(&key)
            .is_some_and(|value| value.to_vec() == [1])
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
