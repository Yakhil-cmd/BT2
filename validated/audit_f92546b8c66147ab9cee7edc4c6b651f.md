### Title
`receive_erc20_tokens` Mints ERC-20 Tokens Based on Caller-Reported `args.amount` Without Verifying Actual NEP-141 Balance Received — (`engine/src/engine.rs`)

---

### Summary

`ft_on_transfer` → `receive_erc20_tokens` unconditionally mints ERC-20 tokens equal to `args.amount` as reported by the calling NEP-141 contract, without verifying that Aurora's actual NEP-141 balance increased by that amount. Because `deploy_erc20_token` is permissionless (no owner check), any actor can register a fee-on-transfer NEP-141 token. Each bridge-in via such a token inflates the ERC-20 supply beyond Aurora's real NEP-141 holdings, causing insolvency and permanent fund freezing for the last users to exit.

---

### Finding Description

`ft_on_transfer` is the NEAR entry point called by a NEP-141 token contract after `ft_transfer_call` moves tokens to Aurora. Inside, it dispatches to `receive_erc20_tokens`:

```rust
// engine/src/contract_methods/connector.rs:80-90
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
```

`receive_erc20_tokens` takes `args.amount` at face value and immediately encodes it as the mint quantity:

```rust
// engine/src/engine.rs:803, 831
let amount = args.amount.as_u128();
// ...
setup_receive_erc20_tokens_input(&recipient, amount),
```

`setup_receive_erc20_tokens_input` encodes a call to `EvmErc20.mint(recipient, amount)`. No balance snapshot is taken before or after; the function never queries Aurora's actual NEP-141 balance to confirm the reported amount arrived.

The precondition for exploitation is that the NEP-141 token is registered in Aurora's `nep141_erc20_map`. Registration happens through `deploy_erc20_token`, which is a public, permissionless NEAR method — it only checks `require_running`, not any owner or admin role:

```rust
// engine/src/contract_methods/connector.rs:117-118
with_hashchain(io, env, function_name!(), |mut io| {
    require_running(&state::get_state(&io)?)?;
    // no require_owner_only here
```

```rust
// engine/src/lib.rs:614-620
pub extern "C" fn deploy_erc20_token() {
    let io = Runtime;
    let env = Runtime;
    let mut handler = Runtime;
    contract_methods::connector::deploy_erc20_token(io, &env, &mut handler)
        .map_err(ContractError::msg)
        .sdk_unwrap();
}
```

Therefore, any unprivileged actor can register a fee-on-transfer NEP-141 token and immediately begin exploiting the accounting gap.

---

### Impact Explanation

Each `ft_transfer_call` of `X` units of a fee-on-transfer NEP-141 token to Aurora results in:
- Aurora's NEP-141 balance increases by `X − fee`
- Aurora mints `X` ERC-20 tokens (the full reported amount)

The ERC-20 total supply grows faster than Aurora's NEP-141 reserve. When users later call `withdrawToNear` (burning ERC-20 to reclaim NEP-141), Aurora issues `ft_transfer` for the full burn amount. Once the cumulative shortfall exceeds Aurora's reserve, the final cohort of users cannot exit — their ERC-20 tokens are permanently frozen with no backing NEP-141 to redeem. This is **insolvency** and **permanent freezing of funds**.

---

### Likelihood Explanation

- `deploy_erc20_token` requires no privilege — any NEAR account can register any NEP-141 token.
- Fee-on-transfer NEP-141 tokens are a known, deployed pattern on NEAR.
- The attacker only needs to register such a token and initiate a single `ft_transfer_call` to begin the accounting divergence.
- No admin compromise, oracle error, or governance capture is required.

Likelihood is **High** given the permissionless registration path and the straightforward exploit sequence.

---

### Recommendation

1. **Verify actual balance change in `receive_erc20_tokens`**: Before minting, read Aurora's NEP-141 balance for the calling token (`predecessor_account_id`). After the NEP-141 contract's `ft_transfer_call` completes, the actual credited amount is `post_balance − pre_balance`. Mint only that delta, not `args.amount`. Because NEAR's cross-contract call model makes synchronous balance reads non-trivial here, the safest approach is to use a promise-based callback pattern: record the pre-balance, let the transfer settle, then mint in the callback using the observed delta.

2. **Add access control to `deploy_erc20_token`**: Restrict NEP-141 registration to the contract owner or a governance-approved whitelist, so only audited, standard-compliant tokens can be bridged.

---

### Proof of Concept

**Setup:**
1. Deploy a fee-on-transfer NEP-141 token `fee_token.near` that deducts 10% on every transfer.
2. Call `deploy_erc20_token` on Aurora (permissionless) to register `fee_token.near` → ERC-20 `0xFEE...`.

**Exploit loop (repeat N times):**
3. Call `fee_token.near::ft_transfer_call({ receiver_id: "aurora", amount: "1000", msg: "<evm_address>" })`.
4. `fee_token.near` credits Aurora with 900 tokens (10% fee deducted), then calls `aurora::ft_on_transfer({ sender_id: attacker, amount: "1000", msg: "<evm_address>" })`.
5. Aurora's `receive_erc20_tokens` reads `args.amount = 1000` and mints 1000 ERC-20 tokens to `<evm_address>`.

**Result after N iterations:**
- Aurora holds `N × 900` NEP-141 tokens.
- ERC-20 total supply is `N × 1000`.
- Shortfall: `N × 100` tokens.

**Exit failure:**
6. All ERC-20 holders attempt `withdrawToNear`. Aurora can only satisfy the first `N × 900 / 1000 = 0.9N` users. The remaining `0.1N` users' ERC-20 tokens are permanently frozen.

**Relevant code locations:**
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 
- [5](#0-4)

### Citations

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

**File:** engine/src/contract_methods/connector.rs (L80-90)
```rust
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
```

**File:** engine/src/contract_methods/connector.rs (L111-159)
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
}
```

**File:** engine/src/lib.rs (L614-621)
```rust
    pub extern "C" fn deploy_erc20_token() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::deploy_erc20_token(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```
