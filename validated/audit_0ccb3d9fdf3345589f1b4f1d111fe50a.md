### Title
Unbacked ERC-20 Token Minting via Unauthenticated `ft_on_transfer` - (File: engine/src/contract_methods/connector.rs)

### Summary
The `ft_on_transfer` function in the Aurora Engine has no access control on the caller. Any NEAR account that is registered as a NEP-141 token on Aurora can call this function directly to mint arbitrary amounts of the corresponding ERC-20 token without transferring any actual NEP-141 tokens, creating unbacked supply and enabling bridge insolvency.

### Finding Description
The `ft_on_transfer` function is a public NEAR contract method that processes incoming NEP-141 token transfers and mints corresponding ERC-20 tokens on Aurora. It uses `predecessor_account_id` to identify which NEP-141 token is being transferred, then calls `engine.receive_erc20_tokens()` to mint ERC-20 tokens to the specified recipient. [1](#0-0) 

The function performs no verification that:
1. The caller is a legitimate NEP-141 token contract executing a `ft_transfer_call` callback
2. An actual token transfer occurred before this call
3. The `args.amount` corresponds to any real locked tokens

The only conditional is whether `predecessor_account_id == get_connector_account_id()` (to distinguish base ETH from ERC-20 tokens), but there is no check that the caller is a trusted entity. [2](#0-1) 

In stark contrast, every other sensitive callback in the same file — `deploy_erc20_token_callback`, `exit_to_near_precompile_callback`, and `mirror_erc20_token_callback` — all call `env.assert_private_call()` as their first security gate: [3](#0-2) [4](#0-3) [5](#0-4) 

`assert_private_call` enforces that `predecessor_account_id == current_account_id`, i.e., only the contract itself can call those functions: [6](#0-5) 

The `receive_erc20_tokens` path mints ERC-20 tokens by calling the ERC-20 contract's mint function with `erc20_admin_address` (the Aurora Engine's own EVM address) as the caller, which always has admin rights: [7](#0-6) 

Additionally, `deploy_erc20_token` (the function that registers a NEP-141 → ERC-20 mapping) has no `require_owner_only` check, meaning any NEAR account can register any NEP-141 token: [8](#0-7) 

### Impact Explanation
An attacker who controls a NEAR account registered as a NEP-141 on Aurora can call `ft_on_transfer` directly with an arbitrary `amount` and their own EVM address as the recipient. Aurora will mint ERC-20 tokens to the attacker without any actual token transfer having occurred. The ERC-20 supply on Aurora then exceeds the actual NEP-141 tokens locked in the bridge. Legitimate users who hold the ERC-20 token cannot exit because there are insufficient backing NEP-141 tokens — this is bridge insolvency and direct theft of user funds.

**Impact: Critical — Direct theft of user funds / Insolvency**

### Likelihood Explanation
The attack requires the attacker to control a NEAR account registered as a NEP-141 on Aurora. This is trivially achievable: the attacker creates a NEAR account, calls `deploy_erc20_token` on Aurora (no access control), and the mapping is established. The attacker can then attract users to bridge the token (e.g., by listing it on a DEX), accumulate legitimate deposits, and then call `ft_on_transfer` directly to mint unbacked tokens and drain the bridge. No privileged access is required.

### Recommendation
Add a caller verification to `ft_on_transfer` analogous to the `assert_private_call()` pattern used in other callbacks. Since `ft_on_transfer` must be callable by external NEP-141 contracts (not just the engine itself), the appropriate fix is to maintain a whitelist of approved NEP-141 token account IDs and reject calls from any account not in that whitelist. Alternatively, require that `ft_on_transfer` can only be reached as a callback of a verified `ft_transfer_call` promise result, using NEAR's promise result mechanism.

### Proof of Concept
1. Attacker creates NEAR account `attacker-token.near`.
2. Attacker calls `deploy_erc20_token` on Aurora with `attacker-token.near` as the NEP-141 argument — no access control, succeeds. ERC-20 deployed at address `0xABC`.
3. Attacker markets the token; legitimate users call `ft_transfer_call` on `attacker-token.near`, which legitimately calls `ft_on_transfer` on Aurora and mints ERC-20 tokens. Bridge now holds real NEP-141 tokens.
4. Attacker calls `ft_on_transfer` **directly** on Aurora from `attacker-token.near` with `amount = 1_000_000_000_000` and `msg = <attacker_evm_address>`.
5. `predecessor_account_id` = `attacker-token.near` → `get_erc20_from_nep141` returns `0xABC` → `receive_erc20_tokens` mints 1 trillion ERC-20 tokens to attacker's EVM address with no token transfer.
6. Attacker swaps/sells these tokens on Aurora DeFi.
7. Legitimate users attempt to exit their ERC-20 tokens back to NEAR; the bridge is insolvent — there are insufficient backing NEP-141 tokens. Funds are permanently frozen. [9](#0-8) [10](#0-9)

### Citations

**File:** engine/src/contract_methods/connector.rs (L62-109)
```rust
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

**File:** engine/src/contract_methods/connector.rs (L117-126)
```rust
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let bytes = io.read_input().to_vec();
        let args =
            DeployErc20TokenArgs::deserialize(&bytes).map_err(|_| errors::ERR_BORSH_DESERIALIZE)?;

        match args {
            DeployErc20TokenArgs::Legacy(nep141) => {
                let address = engine::deploy_erc20_token(nep141, None, io, env, handler)?;

```

**File:** engine/src/contract_methods/connector.rs (L168-169)
```rust
        require_running(&state::get_state(&io)?)?;
        env.assert_private_call()?;
```

**File:** engine/src/contract_methods/connector.rs (L203-204)
```rust
        require_running(&state)?;
        env.assert_private_call()?;
```

**File:** engine/src/contract_methods/connector.rs (L515-516)
```rust
        require_running(&state)?;
        env.assert_private_call()?;
```

**File:** engine-sdk/src/env.rs (L58-64)
```rust
    fn assert_private_call(&self) -> Result<(), PrivateCallError> {
        if self.predecessor_account_id() == self.current_account_id() {
            Ok(())
        } else {
            Err(PrivateCallError)
        }
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
