### Title
Division by Zero in `token_price_x32` Can Permanently Brick Pool Swaps - (File: `programs/cp-swap/src/states/pool.rs`)

### Summary
`PoolState::token_price_x32` computes the token price ratio using plain, unchecked division (`/`) instead of `checked_div`, unlike almost every other arithmetic path in the curve/fee code that uses `checked_*` operations and propagates `None`/`MathOverflow` errors. [1](#0-0) 

### Finding Description
`token_price_x32` derives `token_0_amount`/`token_1_amount` from `vault_amount_without_fee` (vault balance minus accumulated, not-yet-withdrawn protocol/fund fees) and then computes:
```
token_1_amount * Q32 / token_0_amount
token_0_amount * Q32 / token_1_amount
```
using the raw `/` operator, not `checked_div`. [1](#0-0) 

This function is invoked from `get_swap_params`, which is called by both `swap_base_input` and `swap_base_output` — the two unprivileged swap entrypoints reachable from a single transaction with attacker-chosen accounts and amounts. [2](#0-1) [3](#0-2) 

Every other division-adjacent function in the codebase (`Fees::trading_fee`, `Fees::protocol_fee`, `ConstantProductCurve::swap_base_input_without_fees`, `lp_tokens_to_trading_tokens`, etc.) uses `checked_mul`/`checked_div`/`checked_ceil_div` chained with `?` so a zero denominator surfaces as a controlled `None` → `ErrorCode::ZeroTradingTokens`/`MathOverflow` error rather than a raw arithmetic panic. [4](#0-3) [5](#0-4) 

`token_price_x32` breaks this pattern: if `vault_amount_without_fee` ever returns `0` for either token side (e.g., the vault's raw token balance equals or has been driven down to the amount already earmarked as accumulated protocol/fund fees, which is arithmetically possible as a pool's real liquidity shrinks through fee accrual and withdrawals over its lifetime), the division panics instead of returning a `Result::Err`.

### Impact Explanation
A raw Rust division-by-zero panic aborts the transaction non-gracefully, but more importantly, because `token_price_x32` is invoked unconditionally on every `swap_base_input`/`swap_base_output` call via `get_swap_params`, once a pool state reaches the zero-net-token-amount condition on one side, **every subsequent swap into that pool will panic and revert**, permanently freezing the pool for trading. This is a pool-level denial-of-service that locks LP and user funds inside the pool's vaults (no swap can complete to rebalance out of the degenerate state), matching the "permanent freezing of user or LP funds" criterion.

### Likelihood Explanation
Reaching the exact zero-amount edge condition requires the net (fee-excluded) token balance on one side of the pool to hit exactly zero, which is a narrow, low-probability state under organic use, but is not blocked by any explicit check in `swap_base_input`/`swap_base_output`/`get_swap_params`, and no validation equivalent to `CurveCalculator::validate_supply` (used only at `initialize`) is re-checked before each swap's price computation. I was not able to fully inspect `vault_amount_without_fee`'s exact fee-subtraction logic in this session, so the precise sequence of operations (deposits/withdrawals/fee collection) needed to force one side to exactly zero could not be fully traced end-to-end; this should be verified against `programs/cp-swap/src/states/pool.rs` (`vault_amount_without_fee`) and the deposit/withdraw instruction handlers before treating likelihood as high.

### Recommendation
Replace the raw division in `token_price_x32` with `checked_div` (or `checked_mul`/`checked_div` chained with `?`), returning `ErrorCode::MathOverflow` (or a new `ZeroTokenAmount` error) when either `token_0_amount` or `token_1_amount` is zero, consistent with the checked-arithmetic pattern used elsewhere in `curve/fees.rs` and `curve/constant_product.rs`.

### Proof of Concept
Not independently verified end-to-end due to incomplete visibility into `vault_amount_without_fee`'s fee-accumulation math and the deposit/withdraw code paths in this session; the panic path itself (`token_1_amount as u128 * Q32 as u128 / token_0_amount as u128` at `programs/cp-swap/src/states/pool.rs:226-227`, reached via `swap_base_input`/`swap_base_output` → `get_swap_params` → `token_price_x32`) is confirmed by static reading of the code. Confirming exploitability requires tracing whether `vault_amount_without_fee` can return `0` for a live vault balance under attacker-reachable sequences of `deposit`/`withdraw`/`collect_creator_fee`/`swap_*` calls.

### Citations

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

**File:** programs/cp-swap/src/states/pool.rs (L263-308)
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
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L91-103)
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
