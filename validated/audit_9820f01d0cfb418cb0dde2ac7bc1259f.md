### Title
Swap and Liquidity Events Are Emitted Before Invariant Checks and Token Transfers Can Revert - ([File: programs/cp-swap/src/instructions/swap_base_input.rs], [File: programs/cp-swap/src/instructions/swap_base_output.rs], [File: programs/cp-swap/src/instructions/deposit.rs], [File: programs/cp-swap/src/instructions/withdraw.rs])

### Summary
In `swap_base_input`, `swap_base_output`, `deposit`, and `withdraw`, the Anchor `emit!(SwapEvent {...})` / `emit!(LpChangeEvent {...})` calls occur *before* the constant-product invariant check and/or the actual token CPI transfers, any of which can still cause the instruction to fail and the whole transaction to revert.

### Finding Description
In `swap_base_input`, the sequence is: compute swap result → `emit!(SwapEvent {...})` at [1](#0-0)  → then `require_gte!(constant_after, constant_before)` at [2](#0-1)  → then the `transfer_from_user_to_pool_vault` and `transfer_from_pool_vault_to_user` CPIs at [3](#0-2) .

The exact same pattern exists in `swap_base_output`: `emit!(SwapEvent {...})` at [4](#0-3) , followed by the invariant check and transfers at [5](#0-4) .

`deposit` and `withdraw` follow the same order: `emit!(LpChangeEvent {...})` at [6](#0-5)  occurs before the `token_mint_to`/transfer CPIs that follow it, and in `withdraw` the emit at [7](#0-6)  occurs before the slippage check, `token_burn`, and `transfer_from_pool_vault_to_user` calls at [8](#0-7) .

On Solana, `emit!` compiles to a log-emission syscall (`sol_log_data`), and log lines written by a program before it errors out are still retained in the finalized transaction's `logMessages`/log stream (with `meta.err` set to indicate failure), even though all account/state changes from the instruction are rolled back atomically. Any off-chain consumer, bot, or indexer that subscribes to program logs / `emit!`-decoded events without also checking the transaction's success status (`meta.err == null`) will observe a `SwapEvent` or `LpChangeEvent` for a swap/deposit/withdraw that never actually executed and had no effect on pool state or user balances.

### Impact Explanation
This is reachable by any unprivileged swapper or LP: they simply submit a swap/deposit/withdraw whose invariant check (`require_gte!(constant_after, constant_before)`) or downstream token transfer CPI fails (e.g., due to rounding at fee-rate boundaries, a frozen or insufficiently-funded token account, or Token-2022 transfer-fee/extension edge cases) after the event has already been logged. Bots, price oracles, or accounting systems relying on these emitted events without cross-checking transaction success can be fed fabricated trade/liquidity data, leading to incorrect price feeds, false volume/liquidity metrics, or downstream automated decisions (e.g., arbitrage, risk models) based on trades/deposits/withdrawals that never happened. This matches the Medium severity classification of the original report.

### Likelihood Explanation
Likelihood is moderate: the invariant check `require_gte!(constant_after, constant_before)` and the SPL/Token-2022 transfer CPIs are exactly the parts of the instruction most likely to fail under adversarial or edge-case fee configurations (e.g., Token-2022 mints with transfer fees/interest-bearing extensions), and they execute strictly after the event emission in all four affected instructions. No privileged signer or special build is required — this is triggerable by any normal user transaction.

### Recommendation
Move all `emit!(...)` calls in `swap_base_input`, `swap_base_output`, `deposit`, and `withdraw` to occur only after all fallible operations — invariant checks (`require_gte!(constant_after, constant_before)`) and token transfer/mint/burn CPIs — have succeeded, so that an event is only ever emitted once the instruction is guaranteed to complete successfully.

### Proof of Concept
1. A user calls `swap_base_input` (or `swap_base_output`) with `amount_in`/`minimum_amount_out` values that pass the slippage checks at [9](#0-8)  but, due to rounding in the fee split (e.g., a mint with Token-2022 transfer fees), produce `constant_after < constant_before`.
2. Execution reaches `emit!(SwapEvent {...})` at [1](#0-0) , which is logged via the `sol_log_data` syscall.
3. Execution then hits `require_gte!(constant_after, constant_before)` at [2](#0-1) , which fails and aborts the instruction; the whole transaction is rolled back and marked failed.
4. The transaction is still included on-chain with `meta.err` set, but its `logMessages` still contain the `Program data:` line encoding the `SwapEvent` that was emitted in step 2.
5. Any listener parsing program logs for `SwapEvent`/`LpChangeEvent` without checking `meta.err` records a swap/deposit/withdraw that never affected any account balance.

### Citations

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L149-155)
```rust
        require_gt!(amount_received, 0);
        require_gte!(
            amount_received,
            minimum_amount_out,
            ErrorCode::ExceededSlippage
        );
        (amount_out, transfer_fee)
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L165-179)
```rust
    emit!(SwapEvent {
        pool_id,
        input_vault_before: total_input_token_amount,
        output_vault_before: total_output_token_amount,
        input_amount: u64::try_from(result.input_amount).unwrap(),
        output_amount: u64::try_from(result.output_amount).unwrap(),
        input_transfer_fee,
        output_transfer_fee,
        base_input: true,
        input_mint: ctx.accounts.input_token_mint.key(),
        output_mint: ctx.accounts.output_token_mint.key(),
        trade_fee: u64::try_from(result.trade_fee).unwrap(),
        creator_fee: u64::try_from(result.creator_fee).unwrap(),
        creator_fee_on_input: is_creator_fee_on_input,
    });
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L180-180)
```rust
    require_gte!(constant_after, constant_before);
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L182-201)
```rust
    transfer_from_user_to_pool_vault(
        ctx.accounts.payer.to_account_info(),
        ctx.accounts.input_token_account.to_account_info(),
        ctx.accounts.input_vault.to_account_info(),
        ctx.accounts.input_token_mint.to_account_info(),
        ctx.accounts.input_token_program.to_account_info(),
        input_transfer_amount,
        ctx.accounts.input_token_mint.decimals,
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.output_vault.to_account_info(),
        ctx.accounts.output_token_account.to_account_info(),
        ctx.accounts.output_token_mint.to_account_info(),
        ctx.accounts.output_token_program.to_account_info(),
        output_transfer_amount,
        ctx.accounts.output_token_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;
```

**File:** programs/cp-swap/src/instructions/swap_base_output.rs (L107-121)
```rust
    emit!(SwapEvent {
        pool_id,
        input_vault_before: total_input_token_amount,
        output_vault_before: total_output_token_amount,
        input_amount: u64::try_from(result.input_amount).unwrap(),
        output_amount: u64::try_from(result.output_amount).unwrap(),
        input_transfer_fee,
        output_transfer_fee,
        base_input: false,
        input_mint: ctx.accounts.input_token_mint.key(),
        output_mint: ctx.accounts.output_token_mint.key(),
        trade_fee: u64::try_from(result.trade_fee).unwrap(),
        creator_fee: u64::try_from(result.creator_fee).unwrap(),
        creator_fee_on_input: is_creator_fee_on_input,
    });
```

**File:** programs/cp-swap/src/instructions/swap_base_output.rs (L122-143)
```rust
    require_gte!(constant_after, constant_before);

    transfer_from_user_to_pool_vault(
        ctx.accounts.payer.to_account_info(),
        ctx.accounts.input_token_account.to_account_info(),
        ctx.accounts.input_vault.to_account_info(),
        ctx.accounts.input_token_mint.to_account_info(),
        ctx.accounts.input_token_program.to_account_info(),
        input_transfer_amount,
        ctx.accounts.input_token_mint.decimals,
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.output_vault.to_account_info(),
        ctx.accounts.output_token_account.to_account_info(),
        ctx.accounts.output_token_mint.to_account_info(),
        ctx.accounts.output_token_program.to_account_info(),
        output_transfer_amount,
        ctx.accounts.output_token_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;
```

**File:** programs/cp-swap/src/instructions/deposit.rs (L146-156)
```rust
    emit!(LpChangeEvent {
        pool_id,
        lp_amount_before: pool_state.lp_supply,
        token_0_vault_before: total_token_0_amount,
        token_1_vault_before: total_token_1_amount,
        token_0_amount,
        token_1_amount,
        token_0_transfer_fee: transfer_token_0_fee,
        token_1_transfer_fee: transfer_token_1_fee,
        change_type: 0
    });
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L160-170)
```rust
    emit!(LpChangeEvent {
        pool_id,
        lp_amount_before: pool_state.lp_supply,
        token_0_vault_before: total_token_0_amount,
        token_1_vault_before: total_token_1_amount,
        token_0_amount: receive_token_0_amount,
        token_1_amount: receive_token_1_amount,
        token_0_transfer_fee,
        token_1_transfer_fee,
        change_type: 1
    });
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L172-201)
```rust
    if receive_token_0_amount < minimum_token_0_amount
        || receive_token_1_amount < minimum_token_1_amount
    {
        return Err(ErrorCode::ExceededSlippage.into());
    }

    pool_state.lp_supply = pool_state.lp_supply.checked_sub(lp_token_amount).unwrap();
    token_burn(
        ctx.accounts.owner.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
        ctx.accounts.lp_mint.to_account_info(),
        ctx.accounts.owner_lp_token.to_account_info(),
        lp_token_amount,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.token_0_account.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        if ctx.accounts.vault_0_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        token_0_amount,
        ctx.accounts.vault_0_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;
```
