### Title
Unchecked `ft_on_transfer` Amount Causes ERC-20 Mirror Over-Minting for Fee-on-Transfer NEP-141 Tokens - (`engine/src/engine.rs`)

---

### Summary

`receive_erc20_tokens` in `engine/src/engine.rs` unconditionally trusts the `amount` field supplied in the `FtOnTransferArgs` callback and mints exactly that many ERC-20 mirror tokens. It never verifies the actual NEP-141 balance change Aurora received. For any fee-on-transfer or deflationary NEP-141 token, Aurora will mint more ERC-20 tokens than the NEP-141 tokens it actually holds, making the bridge insolvent for that token.

---

### Finding Description

The `ft_on_transfer` entrypoint in `engine/src/contract_methods/connector.rs` is the NEAR callback invoked by a NEP-141 token contract after a `ft_transfer_call`. When the predecessor is not the ETH connector, it delegates to `receive_erc20_tokens`: [1](#0-0) 

Inside `receive_erc20_tokens`, the amount to mint is taken directly from the callback argument with no balance-before/after check: [2](#0-1) 

That value is then forwarded verbatim to `setup_receive_erc20_tokens_input`, which encodes an ERC-20 `mint(recipient, amount)` call: [3](#0-2) 

The full `receive_erc20_tokens` function that performs the mint without any balance verification: [4](#0-3) 

The NEP-141 standard allows the token contract to supply any `amount` value in the `ft_on_transfer` callback. For a fee-on-transfer NEP-141 token, the contract deducts a fee before crediting Aurora, but still reports the pre-fee `amount` in the callback. Aurora has no mechanism to detect this discrepancy.

---

### Impact Explanation

**Critical — Bridge insolvency / permanent freezing of funds.**

Every deposit of a fee-on-transfer NEP-141 token causes Aurora to hold fewer NEP-141 tokens than the total ERC-20 mirror supply it has minted. The withdrawal path (`exit_erc20_token_to_near` in `engine-precompiles/src/native.rs`) issues an `ft_transfer` on the NEP-141 contract for the full ERC-20 burn amount: [5](#0-4) 

Because Aurora's actual NEP-141 balance is less than the aggregate ERC-20 supply, the last users to attempt withdrawal will find Aurora cannot satisfy the `ft_transfer` call. Their ERC-20 tokens are burned but the NEP-141 transfer fails, permanently freezing those funds.

---

### Likelihood Explanation

Any NEP-141 token with a transfer fee that is registered via `deploy_erc20_token` and then deposited via `ft_transfer_call` triggers this path. The entry point is fully unprivileged: any token holder can call `ft_transfer_call` on the NEP-141 contract. No admin action is required beyond the initial token registration (which is itself permissionless in the current codebase). The discrepancy accumulates silently with every deposit, making detection difficult until withdrawals begin failing.

---

### Recommendation

After the NEP-141 `ft_transfer_call` completes and `ft_on_transfer` is invoked, Aurora should query its own NEP-141 balance before and after (or use a cross-contract callback pattern) to determine the actual tokens received, and mint only that delta. Alternatively, the protocol should explicitly document and enforce that only standard (non-fee-on-transfer) NEP-141 tokens may be registered, and add a guard in `deploy_erc20_token` or `ft_on_transfer` to reject known non-standard tokens.

---

### Proof of Concept

1. Deploy a NEP-141 token `fee_token.near` that deducts a 10% fee on every transfer (i.e., a transfer of 100 credits the receiver with 90).
2. Call `deploy_erc20_token` on Aurora to register `fee_token.near`, creating a mirror ERC-20.
3. Alice calls `ft_transfer_call` on `fee_token.near` with `amount = 1000`, `receiver_id = aurora`, `msg = <alice_evm_address>`.
4. `fee_token.near` transfers 900 tokens to Aurora (deducting 10%) and calls `aurora.ft_on_transfer` with `amount = 1000`.
5. Aurora's `receive_erc20_tokens` reads `args.amount = 1000` at line 803 and mints 1000 ERC-20 mirror tokens to Alice's EVM address.
6. Aurora's actual NEP-141 balance is 900, but the ERC-20 total supply is 1000.
7. Alice calls the `ExitToNear` precompile to burn 1000 ERC-20 tokens and withdraw. Aurora attempts `ft_transfer` of 1000 on `fee_token.near`, which fails because Aurora only holds 900.
8. Alice's ERC-20 tokens are burned; she receives nothing. Funds are permanently frozen. [6](#0-5) [7](#0-6)

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

**File:** engine/src/engine.rs (L1305-1313)
```rust
#[must_use]
pub fn setup_receive_erc20_tokens_input(recipient: &Address, amount: u128) -> Vec<u8> {
    let selector = ERC20_MINT_SELECTOR;
    let tail = ethabi::encode(&[
        ethabi::Token::Address(recipient.raw().0.into()),
        ethabi::Token::Uint(amount.into()),
    ]);

    [selector, tail.as_slice()].concat()
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
