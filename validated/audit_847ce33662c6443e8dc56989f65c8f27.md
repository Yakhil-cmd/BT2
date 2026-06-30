### Title
`receive_erc20_tokens` Trusts `ft_on_transfer` Amount Without Verifying Actual Balance Change, Enabling Over-Minting for Rebasing NEP-141 Tokens - (`engine/src/engine.rs`)

---

### Summary

`Engine::receive_erc20_tokens` and `Engine::receive_base_tokens` both consume the `amount` field from the `FtOnTransferArgs` callback directly to mint ERC-20 tokens or credit base-token balances, without ever checking Aurora's actual NEP-141 balance before and after the transfer. For any rebasing or share-based NEP-141 token (the NEAR analog of stETH), the token contract may call `ft_on_transfer` with the *requested* amount while only crediting Aurora's account with `amount - N` tokens due to internal share rounding. Aurora then over-mints ERC-20 tokens relative to the NEP-141 it actually holds, creating a permanent insolvency for that token pair.

---

### Finding Description

When a NEAR account calls `ft_transfer_call` on a NEP-141 token contract targeting Aurora, the NEP-141 contract transfers tokens to Aurora and then invokes Aurora's `ft_on_transfer` callback. Aurora's handler in `connector.rs` routes to either `receive_base_tokens` or `receive_erc20_tokens` in `engine.rs`.

**`receive_base_tokens`** (lines 773–790):

```rust
pub fn receive_base_tokens(
    &mut self,
    args: &FtOnTransferArgs,
) -> Result<Option<SubmitResult>, ContractError> {
    let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
    let amount = Wei::new_u128(args.amount.as_u128());   // ← taken verbatim from callback
    let receipient = message_data.recipient;
    let balance = get_balance(&self.io, &receipient);
    let new_balance = balance
        .checked_add(amount)
        .ok_or(errors::ERR_BALANCE_OVERFLOW)?;
    set_balance(&mut self.io, &receipient, &new_balance); // ← mints args.amount, not actual received
    ...
}
```

**`receive_erc20_tokens`** (lines 796–844):

```rust
pub fn receive_erc20_tokens<P: PromiseHandler>(
    &mut self,
    token: &AccountId,
    args: &FtOnTransferArgs,
    ...
) -> Result<Option<SubmitResult>, ContractError> {
    let amount = args.amount.as_u128();   // ← taken verbatim from callback
    ...
    let result = self
        .call(
            &erc20_admin_address,
            &erc20_token,
            Wei::zero(),
            setup_receive_erc20_tokens_input(&recipient, amount),  // ← mints args.amount ERC-20 tokens
            ...
        )
        ...
}
```

`setup_receive_erc20_tokens_input` encodes an `ERC20_MINT_SELECTOR` call with `amount` as the mint quantity. There is no balance-before / balance-after check anywhere in this path.

The NEP-141 standard does not prohibit rebasing or share-based token implementations. A token that tracks balances in shares (like stETH on Ethereum) will call `ft_on_transfer` with the *nominal* amount while Aurora's actual NEP-141 balance increases by only `amount - 1` or `amount - 2` due to integer rounding in share conversion. Aurora mints the full nominal amount of ERC-20 tokens, creating a surplus of ERC-20 supply relative to the NEP-141 collateral it holds.

The entry point is `ft_on_transfer` in `connector.rs` (lines 62–109), which is a public NEAR contract method callable by any NEP-141 token contract that has been registered via `deploy_erc20_token`.

---

### Impact Explanation

Each deposit of a rebasing NEP-141 token accumulates a 1–2 wei discrepancy between ERC-20 supply and actual NEP-141 collateral held by Aurora. Over many deposits the gap grows. When users attempt to exit (burn ERC-20 tokens via `ExitToNear` precompile → `ft_transfer` on the NEP-141 contract), the last user(s) to exit will find Aurora's NEP-141 balance insufficient to cover their ERC-20 holdings. Their exit transaction will fail and their ERC-20 tokens become permanently unwithdrawable — a **permanent freezing of funds** and **insolvency** of the ERC-20/NEP-141 bridge for that token.

**Impact: Critical — Permanent freezing of funds / Insolvency.**

---

### Likelihood Explanation

Any NEP-141 token that uses share-based accounting (a common pattern for yield-bearing or rebasing tokens on NEAR) triggers this bug when bridged to Aurora. The `deploy_erc20_token` entrypoint is permissionless for the owner, and once a token is registered, any user can call `ft_transfer_call` on it. The discrepancy is deterministic and reproducible on every deposit. No special privileges are required; an ordinary token holder is sufficient.

**Likelihood: High** — the pattern is well-known (Lido's stETH issue is documented), rebasing tokens exist on NEAR, and the code path is reachable by any unprivileged user.

---

### Recommendation

Replace the direct use of `args.amount` with a balance-before / balance-after check:

```rust
// Before calling the ERC-20 mint, read Aurora's actual NEP-141 balance
let balance_before = query_nep141_balance_of_aurora(token);
// ... (the transfer has already occurred before ft_on_transfer is called)
let balance_after  = query_nep141_balance_of_aurora(token);
let actual_received = balance_after - balance_before;
// Use actual_received instead of args.amount for minting
```

Alternatively, document that only non-rebasing NEP-141 tokens may be registered via `deploy_erc20_token`, and enforce this with an on-chain check or allowlist.

---

### Proof of Concept

1. Deploy a rebasing NEP-141 token `rebase.near` whose `ft_transfer_call` internally converts to shares, resulting in Aurora receiving `amount - 1` tokens while calling `ft_on_transfer` with `amount`.
2. Call `deploy_erc20_token` on Aurora to register `rebase.near` → ERC-20 address `0xABCD`.
3. Call `rebase.near::ft_transfer_call(receiver_id="aurora", amount="1000000", msg="<evm_address>")`.
4. Aurora's `ft_on_transfer` fires with `args.amount = 1000000`. `receive_erc20_tokens` mints `1000000` of `0xABCD` to `<evm_address>`. Aurora's actual `rebase.near` balance is `999999`.
5. Repeat step 3 many times. Each iteration widens the gap.
6. All holders attempt to exit via `ExitToNear`. The last holder's `ft_transfer` on `rebase.near` fails because Aurora's balance is insufficient. Their ERC-20 tokens are permanently frozen.

**Vulnerable code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

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
