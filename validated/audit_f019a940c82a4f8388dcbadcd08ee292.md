### Title
Over-Minting ERC-20 Tokens Due to Fee-on-Transfer NEP-141 Accounting — (`engine/src/engine.rs`)

---

### Summary

Aurora Engine's NEP-141 → ERC-20 bridge mints ERC-20 tokens (and credits base ETH balances) using the `amount` field supplied in the `ft_on_transfer` callback, without verifying the actual balance change in Aurora's NEP-141 account. For fee-on-transfer NEP-141 tokens, the amount Aurora actually receives is `amount - fee`, but the engine mints the full `amount`. This creates a permanent insolvency: more ERC-20 tokens are minted than NEP-141 tokens held in reserve, so the last holders cannot exit.

---

### Finding Description

The bridge deposit flow is:

1. A user calls `ft_transfer_call(receiver_id=aurora, amount, msg)` on a NEP-141 token.
2. The NEP-141 contract deducts `amount` from the sender, credits Aurora with `amount - fee` (for a fee-on-transfer token), and then calls `ft_on_transfer` on Aurora with `args.amount = amount` (the gross amount, not the net received).
3. Aurora's `ft_on_transfer` entry point dispatches to either `receive_base_tokens` or `receive_erc20_tokens`.

In `receive_base_tokens`:

```rust
// engine/src/engine.rs:778
let amount = Wei::new_u128(args.amount.as_u128());
// ...
set_balance(&mut self.io, &receipient, &new_balance);
```

In `receive_erc20_tokens`:

```rust
// engine/src/engine.rs:803
let amount = args.amount.as_u128();
// ...
setup_receive_erc20_tokens_input(&recipient, amount),  // mints `amount` ERC-20 tokens
```

Both functions unconditionally trust `args.amount` from the callback argument. Neither checks Aurora's actual NEP-141 balance before and after the transfer to determine the true net received amount.

The `ft_on_transfer` dispatcher in `engine/src/contract_methods/connector.rs` also uses `args.amount` verbatim for the refund path on error, but the core accounting bug is in the two `receive_*` functions above.

---

### Impact Explanation

**Critical — Insolvency / Permanent Freezing of Funds.**

For every `ft_transfer_call` of a fee-on-transfer NEP-141 token:
- Aurora mints `amount` ERC-20 tokens (or credits `amount` base ETH).
- Aurora's actual NEP-141 reserve only increases by `amount - fee`.

The deficit accumulates with each deposit. When users later call the `ExitToNear` precompile to burn ERC-20 tokens and reclaim NEP-141, the last `Σfee` worth of ERC-20 tokens cannot be redeemed because Aurora does not hold enough NEP-141. Those ERC-20 holders suffer a permanent loss of funds — their tokens are backed by nothing.

---

### Likelihood Explanation

Any NEP-141 token that implements a transfer fee (a common pattern for deflationary or tax tokens) triggers this automatically when bridged to Aurora. No special privilege is required — any token holder can call `ft_transfer_call` on such a token with `receiver_id = aurora`. The NEAR ecosystem has multiple such tokens. The vulnerability is triggered by normal, intended bridge usage.

---

### Recommendation

In both `receive_base_tokens` and `receive_erc20_tokens`, replace the use of `args.amount` with the actual balance delta:

1. Read Aurora's NEP-141 balance for the token **before** the transfer is applied (this is available via a storage read at the time `ft_on_transfer` is called, since the transfer has already settled).
2. Compute `actual_received = balance_after - balance_before`.
3. Mint/credit only `actual_received` to the recipient.

Alternatively, document that fee-on-transfer NEP-141 tokens are explicitly unsupported and add a registry check or a blocklist to reject `ft_on_transfer` calls from such tokens.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Deploy or use an existing fee-on-transfer NEP-141 token (e.g., 1% fee on every transfer).
2. Call `ft_transfer_call` on that token with `receiver_id = aurora`, `amount = 1000`, `msg = <evm_recipient_address>`.
3. The NEP-141 contract transfers 990 tokens to Aurora (deducting 10 as fee) and calls `ft_on_transfer` on Aurora with `args.amount = 1000`.
4. Aurora's `ft_on_transfer` → `receive_erc20_tokens` mints **1000** ERC-20 tokens to the EVM recipient.
5. Aurora's actual NEP-141 balance increased by only **990**.
6. Repeat N times. After N deposits, Aurora has minted `N × 1000` ERC-20 tokens but holds only `N × 990` NEP-141 tokens.
7. The last `N × 10` ERC-20 tokens cannot be redeemed via `ExitToNear` — those funds are permanently frozen.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

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
