## Title
Nonce Account Full-Withdraw DoS via Griefing the Strict `lamports == balance` Equality Check - (File: `programs/system/src/system_instruction.rs`)

### Summary
`withdraw_nonce_account` in the System Program uses a strict equality check (`lamports == from.get_lamports()`) to decide whether a withdrawal is a "close" (bypassing the rent-exempt-reserve requirement) or a "partial withdraw" (which must preserve the rent-exempt reserve). Because any unprivileged account can send lamports to an arbitrary nonce account via a normal `system_instruction::transfer`, an attacker can grief a victim's in-flight "withdraw all" transaction by bumping the nonce account's balance by as little as 1 lamport before it lands. This breaks the equality, forces execution into the partial-withdraw branch, and causes the transaction to fail with `InstructionError::InsufficientFunds` — an exact structural analog of the reported GMX `createDeposit` execution-fee DoS, where a strict equality on an externally-influenced balance is used as a control-flow discriminator.

### Finding Description
`withdraw_nonce_account` branches on whether the requested withdrawal amount exactly equals the current account balance: [1](#0-0) 

```rust
State::Initialized(data) => {
    if lamports == from.get_lamports() {
        // "close" path: no rent-exempt reserve required, account becomes Uninitialized
        ...
    } else {
        // "partial withdraw" path: must retain rent.minimum_balance(...)
        let min_balance = rent.minimum_balance(from.get_data().len());
        let amount = checked_add(lamports, min_balance)?;
        if amount > from.get_lamports() {
            return Err(InstructionError::InsufficientFunds);
        }
        ...
    }
}
```

The `lamports` argument comes from the client-signed instruction data and is fixed at transaction-build time (e.g. computed from a `getBalance` RPC call when building a `WithdrawNonceAccount` instruction with `SpendAmount::All`/`Available`, as seen in the CLI's `process_withdraw_from_nonce_account` and `resolve_spend_tx_and_check_account_balance` flow): [2](#0-1) 

`from.get_lamports()` is read live at execution time. Because the "from" nonce account is owned by the system program and lamports can be added to *any* account key by anyone via an ordinary `SystemInstruction::Transfer` (transfers only require the sender to sign/own funds — the recipient's owner/state is irrelevant to a lamport credit), an attacker can send even 1 lamport to the victim's nonce account between the moment the victim signs a "close/withdraw all" transaction and the moment it lands on-chain.

Once the balance no longer exactly matches the hardcoded `lamports` value, the strict equality fails and the check falls into the partial-withdraw branch, which additionally requires the account to retain `rent.minimum_balance(...)` (governed by `Rent` sysvar; see `min_balance` calculation) on top of the withdrawal amount. Since the victim's transaction only supplied enough `lamports` to drain the account fully (assuming the "close" path), the new required total (`lamports + min_balance`) now exceeds the account's balance, and the instruction deterministically reverts with `InstructionError::InsufficientFunds`. Existing test coverage in this file demonstrates that "withdraw == balance" and "withdraw != balance" take fundamentally different code paths with different fund requirements: [3](#0-2) 

### Impact Explanation
This is a low-severity, transaction-triggered griefing/DoS vector reachable by any unprivileged sender: it does not move or mint unsigned funds, escalate CPI privileges, or corrupt consensus/stake accounting. Its effect is that a legitimate nonce-account "close and withdraw all" transaction can be made to deterministically fail (revert) whenever an attacker races a tiny lamport transfer into the target nonce account first. Repeated griefing can indefinitely block users (e.g. CLI operators, dApps using nonce accounts) from fully closing/withdrawing durable-nonce accounts, forcing them to compute a new withdrawal amount and resubmit, or to submit multiple/adjusted transactions. No funds are stolen; the impact is availability/UX degradation for the specific fund-recovery operation, analogous to the acknowledged GMX report where the impact was also "denial of service, not fund loss."

### Likelihood Explanation
The attack requires only: (1) knowledge of the target nonce-account pubkey (public), and (2) the ability to submit an ordinary system transfer of a tiny amount of lamports to that pubkey before the victim's withdrawal transaction is committed. Both are trivially available to any network participant with no special privilege, matching the "malicious address griefs another user's fixed-amount check" pattern from the referenced report. The likelihood of successful griefing depends on timing/front-running feasibility, but no signature, precompile, or special account state is required.

### Recommendation
Replace the strict equality discriminator with an explicit intent flag or a `>=`/threshold-based comparison that is robust to small balance increases, e.g.:
- Require callers to explicitly request "close account" semantics (rather than inferring it from `lamports == balance`), or
- Treat any withdrawal that would leave the account below `rent.minimum_balance` for the *full* balance (not just the requested `lamports`) as an implicit full-close, so that incidental extra lamports don't change withdrawal semantics, or
- Allow the withdrawal amount to be computed as `min(lamports, from.get_lamports())` when the account would otherwise be left non-rent-exempt, closing it fully instead of failing.

### Proof of Concept
1. Victim creates and initializes a durable nonce account with balance `X` (rent-exempt minimum).
2. Victim signs and broadcasts `SystemInstruction::WithdrawNonceAccount { lamports: X }` intending to fully close the account (this hits the `lamports == from.get_lamports()` branch, requiring no rent-exempt reserve, per `programs/system/src/system_instruction.rs:126-137`).
3. Before the victim's transaction lands, an attacker submits `SystemInstruction::Transfer` sending `1` lamport to the victim's nonce account pubkey, landing first. New balance becomes `X + 1`.
4. Victim's transaction now executes with `lamports = X`, `from.get_lamports() = X + 1` → equality check fails → falls into the `else` branch at `programs/system/src/system_instruction.rs:138-150`.
5. `amount = X + min_balance` is compared against `from.get_lamports() = X + 1`. Since `min_balance` (rent-exempt reserve for `nonce::state::State::size()`) is far greater than `1`, `amount > from.get_lamports()`, and the instruction returns `InstructionError::InsufficientFunds`, causing the victim's withdrawal transaction to fail.

### Citations

**File:** programs/system/src/system_instruction.rs (L125-152)
```rust
        State::Initialized(data) => {
            if lamports == from.get_lamports() {
                let durable_nonce =
                    DurableNonce::from_blockhash(&invoke_context.environment_config.blockhash);
                if data.durable_nonce == durable_nonce {
                    ic_msg!(
                        invoke_context,
                        "Withdraw nonce account: nonce can only advance once per slot"
                    );
                    return Err(SystemError::NonceBlockhashNotExpired.into());
                }
                check_signer(&data.authority)?;
                from.set_state(&Versions::new(State::Uninitialized))?;
            } else {
                let min_balance = rent.minimum_balance(from.get_data().len());
                let amount = checked_add(lamports, min_balance)?;
                if amount > from.get_lamports() {
                    ic_msg!(
                        invoke_context,
                        "Withdraw nonce account: insufficient lamports {}, need {}",
                        from.get_lamports(),
                        amount,
                    );
                    return Err(InstructionError::InsufficientFunds);
                }
                check_signer(&data.authority)?;
            }
        }
```

**File:** programs/system/src/system_instruction.rs (L873-903)
```rust
    #[test]
    fn withdraw_inx_initialized_acc_insuff_rent_fail() {
        prepare_mockup!(
            invoke_context,
            instruction_accounts,
            rent,
            transaction_context
        );
        push_instruction_context!(invoke_context, instruction_context, instruction_accounts);
        let mut nonce_account = instruction_context
            .try_borrow_instruction_account(NONCE_ACCOUNT_INDEX)
            .unwrap();
        set_invoke_context_blockhash!(invoke_context, 95);
        let authorized = *nonce_account.get_key();
        initialize_nonce_account(&mut nonce_account, &authorized, &rent, &invoke_context).unwrap();
        set_invoke_context_blockhash!(invoke_context, 63);
        let mut signers = HashSet::new();
        signers.insert(*nonce_account.get_key());
        let withdraw_lamports = 42 + 1;
        drop(nonce_account);
        let result = withdraw_nonce_account(
            NONCE_ACCOUNT_INDEX,
            withdraw_lamports,
            WITHDRAW_TO_ACCOUNT_INDEX,
            &rent,
            &signers,
            &invoke_context,
            &instruction_context,
        );
        assert_eq!(result, Err(InstructionError::InsufficientFunds));
    }
```

**File:** cli/src/nonce.rs (L661-706)
```rust
pub async fn process_withdraw_from_nonce_account(
    rpc_client: &RpcClient,
    config: &CliConfig<'_>,
    nonce_account: &Pubkey,
    nonce_authority: SignerIndex,
    memo: Option<&String>,
    destination_account_pubkey: &Pubkey,
    lamports: u64,
    compute_unit_price: Option<u64>,
) -> ProcessResult {
    let latest_blockhash = rpc_client.get_latest_blockhash().await?;

    let nonce_authority = config.signers[nonce_authority];
    let compute_unit_limit = ComputeUnitLimit::Simulated;
    let ixs = vec![withdraw_nonce_account(
        nonce_account,
        &nonce_authority.pubkey(),
        destination_account_pubkey,
        lamports,
    )]
    .with_memo(memo)
    .with_compute_unit_config(&ComputeUnitConfig {
        compute_unit_price,
        compute_unit_limit,
    });
    let mut message = Message::new(&ixs, Some(&config.signers[0].pubkey()));
    simulate_and_update_compute_unit_limit(&compute_unit_limit, rpc_client, &mut message).await?;
    let mut tx = Transaction::new_unsigned(message);
    tx.try_sign(&config.signers, latest_blockhash)?;
    check_account_for_fee_with_commitment(
        rpc_client,
        &config.signers[0].pubkey(),
        &tx.message,
        config.commitment,
    )
    .await?;
    let result = rpc_client
        .send_and_confirm_transaction_with_spinner_and_config(
            &tx,
            config.commitment,
            config.send_transaction_config,
        )
        .await;

    log_instruction_custom_error::<SystemError>(result, config)
}
```
