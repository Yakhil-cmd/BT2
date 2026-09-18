### Title
Unchecked division in `token_price_x32` causes a divide-by-zero panic that permanently disables swaps on a pool - (File: `programs/cp-swap/src/states/pool.rs`)

### Summary
`PoolState::token_price_x32` computes on-chain "price" values using raw Rust `/` division instead of the `checked_div`/`Option` pattern used everywhere else in the fee and curve math. If either side of the pool's fee-adjusted vault balance nets to exactly zero, this function panics, aborting any swap transaction that touches the pool. This is the same bug class as ALPINE-CVE-2019-11472 (ImageMagick `ReadXWDImage` divide-by-zero DoS): an unvalidated divisor derived from program state causes a runtime panic instead of a graceful error.

### Finding Description
`token_price_x32` divides directly by `token_0_amount` and `token_1_amount` without any zero check: [1](#0-0) 

This contrasts with every other division in the program, which consistently uses `checked_div`/`Option` to fail gracefully instead of panicking, e.g. in `Fees::trading_fee`/`floor_div`/`ceil_div`: [2](#0-1) 
and in `ConstantProductCurve::swap_base_input_without_fees`/`lp_tokens_to_trading_tokens`: [3](#0-2) 

`token_price_x32` is invoked on every swap through `get_swap_params`, using the *current* vault token balances minus the accumulated protocol/fund/creator fee ledger (`vault_amount_without_fee`): [4](#0-3) [5](#0-4) 

`get_swap_params` is called unconditionally at the start of both `swap_base_input` and `swap_base_output`: [6](#0-5) [7](#0-6) 

`vault_amount_without_fee(vault_0, vault_1) = (vault_0 - fees_token_0, vault_1 - fees_token_1)`. Because `fees_token_0`/`fees_token_1` grow with every trade (protocol, fund, and creator fee accounting) while the real vault balance is drawn down by output transfers, a swap can legitimately leave `vault_x == fees_token_x` for one side, i.e. `token_0_amount` or `token_1_amount` == 0, *after* that swap commits (the swap itself only reads `token_price_x32` on the pre-swap balances, so it does not panic on the transaction that creates the zero state). Any subsequent swap transaction — submitted by any unprivileged user — will then call `token_price_x32` on the now-zero balance and panic, aborting the transaction with no graceful error path.

### Impact Explanation
Once this zero-balance condition is committed, `swap_base_input`/`swap_base_output` become permanently unusable for the affected pool: every future swap transaction panics before performing any economic effect, since the divide-by-zero occurs on the very first read of vault state. This is a permanent denial of service on the pool's swap functionality — user and LP capital is not directly stolen, but trading (and thus price discovery / exit via swap) for that pool is permanently bricked, matching the "permanent freezing" bar (LPs can still call `withdraw`, which does not go through `token_price_x32`, but ordinary swappers lose the ability to trade against the pool indefinitely).

### Likelihood Explanation
Reaching the zero condition does not require special privileges — any user who can submit a swap can, through normal fee accrual over one or more swaps, drive `vault_x - fees_token_x` to exactly zero for a low-liquidity pool (small pools/newly created pools with tiny reserves are especially exposed). Because `PoolState::initialize` and `deposit`/`withdraw` never assert that `vault_amount_without_fee` stays strictly greater than zero going forward (only `EmptySupply`/`ZeroTradingTokens` checks at those specific call sites), the invariant is not actually enforced at every state transition, making this reachable in production without any privileged action.

### Recommendation
Change `token_price_x32` to use `checked_mul`/`checked_div` and propagate an error (e.g. `ErrorCode::ZeroTradingTokens` or a new `ErrorCode::InsufficientVault`) instead of panicking when either `token_0_amount` or `token_1_amount` is zero, consistent with the rest of the curve/fee math in `programs/cp-swap/src/curve/`.

### Proof of Concept
1. Create a pool with minimal reserves via `initialize`.
2. Repeatedly call `swap_base_output` (or a single well-sized swap) choosing `amount_out_received` such that, after the swap, `total_output_vault_amount - accumulated_fees_on_that_token == 0` (achievable by draining the output side down to the exact accrued protocol/fund/creator fee amount tracked in `PoolState`). This transaction commits successfully because `token_price_x32` is evaluated on the pre-swap balances.
3. Submit any further `swap_base_input`/`swap_base_output` transaction against this pool. `get_swap_params` → `token_price_x32` divides by the now-zero `token_x_amount`, panicking and aborting the transaction — reproducibly, for every future swap attempt, without any special signer privileges.

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

**File:** programs/cp-swap/src/states/pool.rs (L263-316)
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
        Ok(SwapParams {
            trade_direction,
            total_input_token_amount,
            total_output_token_amount,
            token_0_price_x64,
            token_1_price_x64,
            is_creator_fee_on_input,
        })
    }
```

**File:** programs/cp-swap/src/curve/fees.rs (L7-26)
```rust
fn ceil_div(token_amount: u128, fee_numerator: u128, fee_denominator: u128) -> Option<u128> {
    if fee_denominator == 0 {
        return None;
    }
    token_amount
        .checked_mul(u128::from(fee_numerator))?
        .checked_add(fee_denominator)?
        .checked_sub(1)?
        .checked_div(fee_denominator)
}

/// Helper function for calculating swap fee
pub fn floor_div(token_amount: u128, fee_numerator: u128, fee_denominator: u128) -> Option<u128> {
    if fee_denominator == 0 {
        return None;
    }
    token_amount
        .checked_mul(fee_numerator)?
        .checked_div(fee_denominator)
}
```

**File:** programs/cp-swap/src/curve/constant_product.rs (L19-30)
```rust
    pub fn swap_base_input_without_fees(
        input_amount: u128,
        input_vault_amount: u128,
        output_vault_amount: u128,
    ) -> u128 {
        // (x + delta_x) * (y - delta_y) = x * y
        // delta_y = (delta_x * y) / (x + delta_x)
        let numerator = input_amount.checked_mul(output_vault_amount).unwrap();
        let denominator = input_vault_amount.checked_add(input_amount).unwrap();
        let output_amount = numerator.checked_div(denominator).unwrap();
        output_amount
    }
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

**File:** programs/cp-swap/src/instructions/swap_base_output.rs (L29-41)
```rust
    let SwapParams {
        trade_direction,
        total_input_token_amount,
        total_output_token_amount,
        token_0_price_x64,
        token_1_price_x64,
        is_creator_fee_on_input,
    } = pool_state.get_swap_params(
        ctx.accounts.input_vault.key(),
        ctx.accounts.output_vault.key(),
        ctx.accounts.input_vault.amount,
        ctx.accounts.output_vault.amount,
    )?;
```
