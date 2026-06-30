### Title
Fee-on-Transfer NEP-141 Token Over-Minting in Bridge Deposit — (`engine/src/engine.rs`)

---

### Summary

Aurora Engine's `ft_on_transfer` bridge entry point unconditionally trusts the `args.amount` field supplied by the calling NEP-141 contract to determine how many ERC-20 tokens to mint on the EVM side. It performs no before/after balance check to confirm the actual amount received. A fee-on-transfer NEP-141 token will cause Aurora to mint more ERC-20 tokens than the NEP-141 tokens it actually holds, making the bridge insolvent and permanently freezing funds for honest users.

---

### Finding Description

When a NEP-141 token is bridged into Aurora, the NEAR runtime calls `ft_on_transfer` on the Aurora contract. The handler in `engine/src/contract_methods/connector.rs` reads the JSON arguments and dispatches to `Engine::receive_erc20_tokens`:

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

Inside `receive_erc20_tokens`, the engine takes `args.amount` at face value and mints exactly that many ERC-20 tokens:

```rust
// engine/src/engine.rs:803, 831
let amount = args.amount.as_u128();
// ...
setup_receive_erc20_tokens_input(&recipient, amount),
```

`args.amount` is the value the NEP-141 contract *claims* it transferred. For a fee-on-transfer NEP-141 token, the actual balance credited to Aurora's account is `args.amount − fee`. No balance snapshot is taken before or after the transfer to verify the real delta. The same pattern applies to `receive_base_tokens` (line 778), which credits ETH balance directly from `args.amount`.

---

### Impact Explanation

**Critical — Protocol insolvency and permanent fund freeze.**

After a fee-on-transfer deposit:

- Aurora holds `X − fee` NEP-141 tokens but has minted `X` ERC-20 tokens.
- The ERC-20 total supply exceeds the NEP-141 backing by `fee` per deposit.
- When any user calls `exit_to_near` (the `ExitToNear` precompile in `engine-precompiles/src/native.rs`), Aurora issues an `ft_transfer` or `ft_transfer_call` promise for the full ERC-20 amount. Once the cumulative shortfall exceeds Aurora's NEP-141 balance, those promises fail.
- Honest users who deposited standard tokens cannot redeem their ERC-20 tokens because the pool is undercollateralised — their funds are permanently frozen.
- An attacker who deposited the fee-on-transfer token can exit first, draining NEP-141 tokens that belong to other depositors.

---

### Likelihood Explanation

**Medium.** Any NEAR account can call `deploy_erc20_token` to register an arbitrary NEP-141 as an ERC-20 mirror, and any token holder can then call `ft_transfer_call` on that NEP-141 to trigger the deposit path. No privileged role is required. The only prerequisite is a NEP-141 token that implements a fee-on-transfer mechanism, which is a realistic token design (analogous to STA or fee-mode USDT on Ethereum). The attacker controls the NEP-141 contract and can set the fee to any value.

---

### Recommendation

1. **Before/after balance check**: Record Aurora's NEP-141 balance before the `ft_transfer_call` completes and compare it to the balance after. Use the actual delta — not `args.amount` — as the mint amount. Because `ft_on_transfer` is a callback that fires *after* the transfer, a cross-contract call to `ft_balance_of` can be issued as a prerequisite promise, and the result passed into the minting logic.

2. **Alternatively**, return `args.amount` (reject the full transfer) for any NEP-141 whose `ft_on_transfer`-reported amount does not match a verified balance change, effectively disallowing fee-on-transfer tokens.

3. **Document and enforce** an allowlist of supported NEP-141 tokens if a balance-check approach is not feasible, preventing arbitrary fee-on-transfer tokens from being registered.

---

### Proof of Concept

1. Attacker deploys a NEP-141 token `fee_token.near` that deducts 10% from the receiver on every transfer.
2. Attacker calls `deploy_erc20_token` on Aurora to register `fee_token.near` → ERC-20 mirror deployed at address `0xABC`.
3. Attacker calls `ft_transfer_call` on `fee_token.near` with `amount = 1000`, `receiver_id = aurora`, `msg = <attacker_evm_address>`.
4. `fee_token.near` transfers 900 tokens to Aurora (keeps 100 as fee), then calls `aurora.ft_on_transfer(sender=attacker, amount=1000, msg=<attacker_evm_address>)`.
5. Aurora executes `receive_erc20_tokens`:
   - `amount = args.amount.as_u128()` → **1000** (line 803 of `engine/src/engine.rs`)
   - Mints **1000** ERC-20 tokens to attacker's EVM address.
6. Aurora's actual NEP-141 balance: **900**. ERC-20 supply: **1000**. Shortfall: **100**.
7. Attacker calls `withdrawToNear` (exit precompile) for 900 tokens → succeeds, draining Aurora's entire NEP-141 balance.
8. Any other user who had legitimately deposited `fee_token.near` and holds the remaining 100 ERC-20 tokens cannot exit — `ft_transfer` will fail with insufficient balance. Funds are permanently frozen. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** engine/src/engine.rs (L773-789)
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
```

**File:** engine/src/engine.rs (L796-837)
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

**File:** engine-precompiles/src/native.rs (L558-656)
```rust
fn exit_erc20_token_to_near<I: IO>(
    context: &Context,
    exit_params: &Erc20TokenParams,
    io: &I,
) -> Result<
    (
        AccountId,
        String,
        events::ExitToNear,
        String,
        Option<TransferNearArgs>,
    ),
    ExitError,
> {
    // In case of withdrawing ERC-20 tokens, the `apparent_value` should be zero. In opposite way
    // the funds will be locked in the address of the precompile without any possibility
    // to withdraw them in the future. So, in case if the `apparent_value` is not zero, the error
    // will be returned to prevent that.
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
    }

    let erc20_address = context.caller; // because ERC-20 contract calls the precompile.
    let nep141_account_id = get_nep141_from_erc20(erc20_address.as_bytes(), io)?;

    let (nep141_account_id, args, method, transfer_near_args, event) = match exit_params.message {
        // wNEAR address should be set via the `factory_set_wnear_address` transaction first.
        Some(Message::UnwrapWnear) if erc20_address == get_wnear_address(io).raw() =>
        // The flow is following here:
        // 1. We call `near_withdraw` on wNEAR account id on `aurora` behalf.
        // In such way we unwrap wNEAR to NEAR.
        // 2. After that, we call callback `exit_to_near_precompile_callback` on the `aurora`
        // in which make transfer of unwrapped NEAR to the `target_account_id`.
        {
            (
                nep141_account_id,
                format!(r#"{{"amount":"{}"}}"#, exit_params.amount.as_u128()),
                "near_withdraw",
                Some(TransferNearArgs {
                    target_account_id: exit_params.receiver_account_id.clone(),
                    amount: exit_params.amount.as_u128(),
                }),
                events::ExitToNear::Legacy(ExitToNearLegacy {
                    sender: Address::new(erc20_address),
                    erc20_address: Address::new(erc20_address),
                    dest: exit_params.receiver_account_id.to_string(),
                    amount: exit_params.amount,
                }),
            )
        }
        // In this flow, we're just forwarding the `msg` to the `ft_transfer_call` transaction.
        Some(Message::Omni(msg)) => (
            nep141_account_id,
            ft_transfer_call_args(&exit_params.receiver_account_id, exit_params.amount, msg)?,
            "ft_transfer_call",
            None,
            events::ExitToNear::Omni(ExitToNearOmni {
                sender: Address::new(erc20_address),
                erc20_address: Address::new(erc20_address),
                dest: exit_params.receiver_account_id.to_string(),
                amount: exit_params.amount,
                msg: msg.to_string(),
            }),
        ),
        // The legacy flow. Just withdraw the tokens to the NEAR account id.
        // P.S. We use underscore here instead of `None` to handle the case when a user
        // could add the `unwrap` suffix for non wNEAR ERC-20 token by mistake.
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
    };

    Ok((
        nep141_account_id,
        args,
        event,
        method.to_string(),
        transfer_near_args,
    ))
}
```
