### Title
Unchecked division-by-zero in `PoolState::token_price_x32` causes reachable panic / DoS on `swap_base_input` and `swap_base_output` - ([File: programs/cp-swap/src/states/pool.rs])

### Summary
`PoolState::token_price_x32` performs raw integer division against vault balances without any zero-guard, and is invoked unconditionally on every swap via `get_swap_params`. If the "usable" vault amount (raw vault balance minus accrued protocol/fund/creator fees) for either side of the pool is ever `0`, the division panics and aborts the transaction, rather than returning a graceful `Result` error like the rest of the fee/vault math in this file does.

### Finding Description
`vault_amount_without_fee` subtracts accumulated `protocol_fees`, `fund_fees`, and `creator_fees` from the raw vault balance and returns the remainder, using `checked_sub` so it can legitimately return `0` (as long as fees do not exceed the raw balance) rather than erroring: [1](#0-0) 

`token_price_x32` then re-derives these same "amount without fee" values and divides by them directly, with no `checked_div` / zero check, unlike almost every other arithmetic operation in this file which uses `checked_*` helpers and returns `ErrorCode::MathOverflow`/similar: [2](#0-1) 

This function is called unconditionally from `get_swap_params`, which is the entry computation for both `swap_base_input` and `swap_base_output` — instructions reachable by any unprivileged swapper with attacker-chosen accounts and swap amounts: [3](#0-2) [4](#0-3) [5](#0-4) 

Because `vault_amount_without_fee` can return exactly `0` for a token side once accrued fees consume the entire "free" vault balance (i.e., raw vault amount == accumulated protocol_fees + fund_fees + creator_fees for that token), the subsequent division in `token_price_x32` (`... / token_0_amount` or `... / token_1_amount`) divides by zero and panics, aborting the transaction. Integer division by zero panics unconditionally in Rust regardless of build profile (unlike overflow checks, which are debug-only), so this is a deterministic, repeatable crash path, not a compute-cost or best-practice issue.

This mirrors the CVE-2021-2300 bug class: a reachable, repeatable operation (the MySQL DML-equivalent here is the swap instruction) that a normal (non-privileged) actor can trigger via ordinary usage, causing a hang/crash (here, a deterministic transaction abort) rather than any privileged-only or off-chain condition.

### Impact Explanation
Once a pool reaches a state where one side's raw vault balance equals its accrued (protocol + fund + creator) fees exactly, every subsequent `swap_base_input` / `swap_base_output` call against that pool will panic in `token_price_x32` before any fee/curve validation runs, because `get_swap_params` is called unconditionally at the top of both swap handlers. This permanently disables swapping on the affected pool (a DoS/availability impact analogous to the CVE), since the panic path cannot be bypassed by any swapper-supplied instruction data — the condition is a property of the pool's on-chain state, not something a caller can avoid. This constitutes a repeatable, unprivileged denial-of-service against a core pool function, matching the "freezing of ... pool" bar in the validation criteria as it can make the swap surface of the pool permanently unusable.

### Likelihood Explanation
Exploitability requires driving `raw_vault_balance == accrued_fees_for_that_token` for one side of the pool. Whether this is realistically reachable by an ordinary LP/swapper in a single or few transactions (as opposed to only through extreme, possibly gas/fee-accumulation-limited scenarios) could not be fully confirmed from the code inspected. I verified that `initialize` locks a minimum of 100 LP tokens and requires `liquidity > lock_lp_amount`, and that `withdraw`/`deposit` compute proportional amounts via `lp_tokens_to_trading_tokens`, but I did not trace all fee-accrual and withdrawal-timing paths that would let an attacker precisely zero out the "amount without fee" for one token while leaving `lp_supply` nonzero. This part of the reachability analysis is uncertain and would benefit from further review/testing (e.g., a Devin session running a local validator/test harness) to confirm a concrete sequence of deposit/swap/withdraw calls that reaches the zero-division state.

### Recommendation
Replace the raw division in `token_price_x32` with checked arithmetic that returns a proper `Result`/error (e.g., `checked_div` combined with `ok_or(ErrorCode::...)`), consistent with the rest of `vault_amount_without_fee` and `update_lp_supply`, so that a zero-liquidity-after-fees condition surfaces as a handled program error instead of an unrecoverable panic.

### Proof of Concept
Not independently reproduced with a test harness (no filesystem/terminal access available in this mode). Conceptually:
1. Create a pool via `initialize`.
2. Drive fee accrual (via repeated `swap_base_input`/`swap_base_output`) and/or withdraw liquidity via `withdraw` until, for one token side, `vault_balance == protocol_fees + fund_fees + creator_fees` for that token (i.e., `vault_amount_without_fee` returns `0` for that side).
3. Call `swap_base_input` or `swap_base_output` again — `get_swap_params` → `token_price_x32` divides by the zero amount and panics, aborting the transaction and blocking all further swaps on the pool. [2](#0-1)

### Citations

**File:** programs/cp-swap/src/states/pool.rs (L200-221)
```rust
    pub fn vault_amount_without_fee(&self, vault_0: u64, vault_1: u64) -> Result<(u64, u64)> {
        let fees_token_0 = self
            .protocol_fees_token_0
            .checked_add(self.fund_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?;
        let fees_token_1 = self
            .protocol_fees_token_1
            .checked_add(self.fund_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?;
        Ok((
            vault_0
                .checked_sub(fees_token_0)
                .ok_or(ErrorCode::InsufficientVault)?,
            vault_1
                .checked_sub(fees_token_1)
                .ok_or(ErrorCode::InsufficientVault)?,
        ))
    }
```

**File:** programs/cp-swap/src/states/pool.rs (L223-229)
```rust
    pub fn token_price_x32(&self, vault_0: u64, vault_1: u64) -> Result<(u128, u128)> {
        let (token_0_amount, token_1_amount) = self.vault_amount_without_fee(vault_0, vault_1)?;
        Ok((
            token_1_amount as u128 * Q32 as u128 / token_0_amount as u128,
            token_0_amount as u128 * Q32 as u128 / token_1_amount as u128,
        ))
    }
```

**File:** programs/cp-swap/src/states/pool.rs (L263-307)
```rust
    pub fn get_swap_params(
        &self,
        input_vault_key: Pubkey,
        output_vault_key: Pubkey,
        input_vault_amount: u64,
        output_vault_amount: u64,
    ) -> Result<SwapParams> {
        let (
            trade_direction,
            total_input_token_amount,
            total_output_token_amount,
            token_0_price_x64,
            token_1_price_x64,
            is_creator_fee_on_input,
        ) = if input_vault_key == self.token_0_vault && output_vault_key == self.token_1_vault {
            let (total_input_token_amount, total_output_token_amount) =
                self.vault_amount_without_fee(input_vault_amount, output_vault_amount)?;
            let (token_0_price_x64, token_1_price_x64) =
                self.token_price_x32(input_vault_amount, output_vault_amount)?;

            (
                TradeDirection::ZeroForOne,
                total_input_token_amount,
                total_output_token_amount,
                token_0_price_x64,
                token_1_price_x64,
                self.is_creator_fee_on_input(TradeDirection::ZeroForOne)?,
            )
        } else if input_vault_key == self.token_1_vault && output_vault_key == self.token_0_vault {
            let (total_output_token_amount, total_input_token_amount) =
                self.vault_amount_without_fee(output_vault_amount, input_vault_amount)?;
            let (token_0_price_x64, token_1_price_x64) =
                self.token_price_x32(output_vault_amount, input_vault_amount)?;

            (
                TradeDirection::OneForZero,
                total_input_token_amount,
                total_output_token_amount,
                token_0_price_x64,
                token_1_price_x64,
                self.is_creator_fee_on_input(TradeDirection::OneForZero)?,
            )
        } else {
            return err!(ErrorCode::InvalidVault);
        };
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L98-103)
```rust
    } = pool_state.get_swap_params(
        ctx.accounts.input_vault.key(),
        ctx.accounts.output_vault.key(),
        ctx.accounts.input_vault.amount,
        ctx.accounts.output_vault.amount,
    )?;
```

**File:** programs/cp-swap/src/instructions/swap_base_output.rs (L36-41)
```rust
    } = pool_state.get_swap_params(
        ctx.accounts.input_vault.key(),
        ctx.accounts.output_vault.key(),
        ctx.accounts.input_vault.amount,
        ctx.accounts.output_vault.amount,
    )?;
```
