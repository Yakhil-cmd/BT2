### Title
`receive_erc20_tokens` Assumes 1:1 NEP-141-to-ERC-20 Ratio, Enabling Insolvency with Fee-on-Transfer NEP-141 Tokens — (`engine/src/engine.rs`)

---

### Summary

The `receive_erc20_tokens` function in `engine/src/engine.rs` mints ERC-20 tokens equal to the nominal `args.amount` reported in the `ft_on_transfer` callback, without verifying that Aurora's actual NEP-141 balance increased by that same amount. For any NEP-141 token that implements a fee-on-transfer (i.e., the receiver's balance increases by less than the transferred amount), this creates a permanent accounting imbalance: the ERC-20 total supply grows faster than Aurora's NEP-141 reserve, eventually making it impossible for all holders to withdraw — a classic insolvency condition.

---

### Finding Description

**Root cause — `engine/src/engine.rs`, `receive_erc20_tokens`:** [1](#0-0) 

```rust
pub fn receive_erc20_tokens<P: PromiseHandler>(
    &mut self,
    token: &AccountId,
    args: &FtOnTransferArgs,
    ...
) -> Result<Option<SubmitResult>, ContractError> {
    let amount = args.amount.as_u128();   // ← nominal transfer amount, not actual received
    ...
    setup_receive_erc20_tokens_input(&recipient, amount),  // ← mints `amount` ERC-20 tokens
```

The `amount` field in `FtOnTransferArgs` is the value the NEP-141 contract reports it transferred — not the value Aurora's balance actually increased by. The NEP-141 standard does not prohibit fee-on-transfer tokens; a conforming NEP-141 implementation may deduct a fee from the receiver's credited balance while still calling `ft_on_transfer` with the full nominal `amount`.

**Entry path — `ft_on_transfer` dispatcher:** [2](#0-1) 

The dispatcher routes any call from a non-ETH-connector predecessor to `receive_erc20_tokens`. The only guard inside that function is `get_erc20_from_nep141`, which checks that the NEP-141 token has a registered ERC-20 counterpart.

**Registration is open to all callers — `deploy_erc20_token`:** [3](#0-2) 

`deploy_erc20_token` contains only `require_running` — no `require_owner_only` or allowlist check. Any NEAR account can register any NEP-141 token, including a fee-on-transfer token, giving it a corresponding ERC-20 on Aurora.

**Withdrawal path uses the same 1:1 assumption — `exit_erc20_token_to_near`:** [4](#0-3) 

When a user burns ERC-20 tokens and exits to NEAR, the burned amount is forwarded verbatim as the NEP-141 `ft_transfer` amount. If Aurora's NEP-141 reserve is already short (due to fee-on-transfer deposits), this transfer will fail or drain other users' reserves.

---

### Impact Explanation

**Insolvency (Critical).** For every deposit of a fee-on-transfer NEP-141 token, Aurora mints `amount` ERC-20 tokens but holds only `amount − fee` NEP-141 tokens. The deficit compounds with each deposit. Eventually, Aurora's NEP-141 balance is insufficient to honour all outstanding ERC-20 redemptions. The last users to withdraw permanently lose their funds; there is no recovery path because the ERC-20 supply cannot be reduced without burning tokens that users legitimately hold.

---

### Likelihood Explanation

**Medium.** Fee-on-transfer tokens are a well-known pattern in DeFi (e.g., tokens with protocol fees, reflection tokens). Because `deploy_erc20_token` is callable by any NEAR account with no access control, any such token can be registered without operator approval. Once registered, ordinary users bridging tokens in good faith trigger the imbalance. No privileged access or key compromise is required.

---

### Recommendation

1. **Measure the actual balance delta.** Before minting ERC-20 tokens, read Aurora's NEP-141 balance before and after the transfer and mint only the difference. Because `ft_on_transfer` is a callback (the transfer has already occurred), the post-transfer balance is already available via a storage read.

2. **Alternatively, gate `deploy_erc20_token` with an allowlist.** Require owner or governance approval before a NEP-141 token can be registered, so only audited, non-fee-bearing tokens are accepted. This is a defence-in-depth measure and does not fix the root accounting assumption.

---

### Proof of Concept

1. Deploy a NEP-141 token `fee_token.near` that charges a 1 % fee on every transfer (receiver is credited `amount × 0.99`).
2. Call `deploy_erc20_token` on Aurora (no access control) to register `fee_token.near` → ERC-20 `FEE` is deployed.
3. **User A** calls `ft_transfer_call` on `fee_token.near` with `amount = 1000`, `receiver_id = aurora`.
   - Aurora's NEP-141 balance increases by **990**.
   - `ft_on_transfer` is called with `amount = 1000`.
   - `receive_erc20_tokens` mints **1000** `FEE` ERC-20 tokens for User A.
   - **Deficit after step 3: −10 tokens.**
4. **User B** repeats the same deposit.
   - Aurora's NEP-141 balance: **1980**. ERC-20 supply: **2000**. Deficit: **−20**.
5. User A calls `withdrawToNear(1000)` → burns 1000 ERC-20, Aurora calls `ft_transfer(amount=1000)` → succeeds (1980 − 1000 = 980 remaining).
6. User B calls `withdrawToNear(1000)` → burns 1000 ERC-20, Aurora calls `ft_transfer(amount=1000)` → **fails**: Aurora only holds 980 NEP-141 tokens. User B's 1000 ERC-20 tokens are burned but the NEP-141 transfer reverts; User B loses funds permanently. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** engine/src/contract_methods/connector.rs (L111-158)
```rust
#[named]
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
```

**File:** engine-precompiles/src/native.rs (L627-646)
```rust
        _ => {
            // There is no way to inject json, given the encoding of both arguments
            // as decimal and valid account id respectively.
            (
                nep141_account_id,
                format!(
                    r#"{{"receiver_id":"{}","amount":"{}"}}"#,
                    exit_params.receiver_account_id,
                    exit_params.amount.as_u128()
                ),
                "ft_transfer",
                None,
                events::ExitToNear::Legacy(ExitToNearLegacy {
                    sender: Address::new(erc20_address),
                    erc20_address: Address::new(erc20_address),
                    dest: exit_params.receiver_account_id.to_string(),
                    amount: exit_params.amount,
                }),
            )
        }
```
