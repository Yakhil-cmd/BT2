### Title
Fee-on-Transfer NEP-141 Token Accounting Discrepancy Allows ERC-20 Over-Minting Leading to Insolvency - (File: engine/src/engine.rs)

### Summary

When a NEP-141 token that charges a transfer fee is bridged into Aurora via the `ft_on_transfer` callback, the engine blindly trusts the `amount` field supplied by the NEP-141 contract rather than verifying the actual balance change. This causes Aurora to mint more ERC-20 tokens than the NEP-141 tokens it actually holds, creating an unbacked surplus that leads to insolvency for later withdrawers.

### Finding Description

The NEP-141 bridge entry point is `ft_on_transfer` in `engine/src/contract_methods/connector.rs`. When the predecessor is not the ETH connector, it routes to `engine.receive_erc20_tokens`: [1](#0-0) 

Inside `receive_erc20_tokens`, the amount to mint is taken directly from `args.amount` — the value the NEP-141 contract itself reported: [2](#0-1) 

That amount is then passed verbatim to `setup_receive_erc20_tokens_input`, which encodes it as the mint quantity for the ERC-20 contract: [3](#0-2) [4](#0-3) 

The NEP-141 standard's `ft_transfer_call` flow passes the originally-requested `amount` to `ft_on_transfer`, not the amount actually credited to the receiver. If the NEP-141 token deducts a fee from the receiver's side (i.e., Aurora's balance increases by `amount - fee` rather than `amount`), Aurora's internal accounting never detects the shortfall. There is no pre/post balance check anywhere in this path.

### Impact Explanation

Every deposit of a fee-on-transfer NEP-141 token inflates the ERC-20 supply on Aurora beyond the actual NEP-141 backing held by the Aurora contract account. For example, if the fee is 10% and a user deposits 100 tokens:

- Aurora's NEP-141 balance increases by **90**
- Aurora mints **100** ERC-20 tokens

After repeated deposits the cumulative deficit grows. When users attempt to exit (burn ERC-20 → receive NEP-141 via `ft_transfer`), the last users to exit find Aurora's NEP-141 balance insufficient. This is **insolvency** and **permanent fund freeze** for those users.

### Likelihood Explanation

- Any NEP-141 token with a fee-on-transfer mechanism triggers this; no special privileges are required.
- The attacker-controlled entry path is fully unprivileged: any token holder calls `ft_transfer_call` on the NEP-141 contract with `receiver_id = aurora`.
- The NEP-141 standard does not prohibit fee-on-transfer tokens, and several real-world tokens implement this pattern.
- The vulnerability is triggered on every deposit, not just a one-time exploit.

### Recommendation

After the NEP-141 contract calls `ft_on_transfer`, Aurora should verify the actual balance change rather than trusting `args.amount`. Concretely, before and after the NEP-141 transfer settles, query Aurora's own NEP-141 balance (e.g., via a cross-contract `ft_balance_of` call in a callback) and use `balance_after - balance_before` as the mint amount. Alternatively, maintain a whitelist of NEP-141 tokens permitted to bridge into Aurora, excluding any token with non-standard transfer semantics.

### Proof of Concept

1. Deploy a NEP-141 token contract that charges a 10% fee on every transfer (deducted from the receiver).
2. Register it with Aurora via `deploy_erc20_token`.
3. Call `ft_transfer_call` on the NEP-141 contract:
   - `receiver_id`: Aurora engine account
   - `amount`: `1000`
   - `msg`: `<victim_evm_address_hex>`
4. The NEP-141 contract credits Aurora with **900** tokens (fee deducted) and calls `ft_on_transfer` on Aurora with `amount = "1000"`.
5. Aurora executes `receive_erc20_tokens` → `let amount = args.amount.as_u128()` → `1000` → mints **1000** ERC-20 tokens to the victim address.
6. Aurora's actual NEP-141 balance is **900**, but **1000** ERC-20 tokens are outstanding.
7. Repeat step 3–5 many times. The deficit compounds.
8. When any user calls the exit precompile to burn ERC-20 and reclaim NEP-141, the final users whose cumulative claims exceed Aurora's NEP-141 balance receive nothing — their funds are permanently frozen. [5](#0-4) [6](#0-5)

### Citations

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

**File:** engine/src/engine.rs (L1305-1314)
```rust
#[must_use]
pub fn setup_receive_erc20_tokens_input(recipient: &Address, amount: u128) -> Vec<u8> {
    let selector = ERC20_MINT_SELECTOR;
    let tail = ethabi::encode(&[
        ethabi::Token::Address(recipient.raw().0.into()),
        ethabi::Token::Uint(amount.into()),
    ]);

    [selector, tail.as_slice()].concat()
}
```
