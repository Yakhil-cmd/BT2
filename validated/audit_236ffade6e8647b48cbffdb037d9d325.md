### Title
Unchecked integer division by zero in `token_price_x32` causes swap-path panic/DoS - ([File: programs/cp-swap/src/states/pool.rs])

### Summary
`PoolState::token_price_x32` computes the token-0/token-1 spot price using the raw Rust division operator (`/`) on `u128` values instead of Solana's convention of `checked_div`. If either side of the post-fee vault balance is `0`, this triggers an integer division-by-zero trap, which aborts the transaction (and, more importantly, means any transaction that reaches this state cannot succeed, effectively bricking that trade direction or the whole pool). This mirrors the CVE-2025-71005 bug class (division/FPE causing a DoS), except here the vulnerable arithmetic sits directly in the on-chain constant-product swap path reachable by any unprivileged swapper.

### Finding Description
`token_price_x32` is: [1](#0-0) 

```
pub fn token_price_x32(&self, vault_0: u64, vault_1: u64) -> Result<(u128, u128)> {
    let (token_0_amount, token_1_amount) = self.vault_amount_without_fee(vault_0, vault_1)?;
    Ok((
        token_1_amount as u128 * Q32 as u128 / token_0_amount as u128,
        token_0_amount as u128 * Q32 as u128 / token_1_amount as u128,
    ))
}
```

Both divisions use the raw `/` operator rather than `checked_div`, unlike virtually every other arithmetic operation in the codebase (`curve/calculator.rs`, `curve/fees.rs`, `curve/constant_product.rs` consistently use `checked_*` combinators, e.g. `Fees::trading_fee`/`floor_div` explicitly guard against a zero denominator). `token_0_amount`/`token_1_amount` come from `vault_amount_without_fee`, which is the vault's raw SPL balance minus already-accrued (uncollected) protocol/fund/creator fees: [2](#0-1) 

`token_price_x32` is unconditionally invoked from `get_swap_params`, which every `swap_base_input` and `swap_base_output` call goes through, before any of the swap-amount checks: [3](#0-2) 

and is called from the `Swap` instruction handlers: [4](#0-3) [5](#0-4) 

If either post-fee vault balance (`token_0_amount` or `token_1_amount`) is exactly `0` at the moment `get_swap_params` runs, the raw `/` panics inside the BPF program, aborting the transaction non-recoverably (no `Result`/`Option` is returned from this computation — the panic occurs before any error handling can intervene). Note that the actual curve math in `ConstantProductCurve::swap_base_output_without_fees`/`swap_base_input_without_fees` and `Fees::*` is careful to route through `checked_div`/`checked_ceil_div` specifically to avoid this trap, but the price-oracle helper `token_price_x32` was not written with the same defensive pattern.

### Impact Explanation
A panic inside the swap instruction causes the transaction to fail, which in isolation is a griefing/DoS against that specific transaction. However, because `token_price_x32` is evaluated using the **live vault balances at call time** and is part of the mandatory `get_swap_params` step for both `swap_base_input` and `swap_base_output`, any pool state where one side's post-fee balance reaches exactly zero becomes permanently unswappable in that direction (every subsequent swap attempt against the pool will panic instead of returning a graceful `ZeroTradingTokens`/`InsufficientVault` error), which is a form of permanent freezing of pool functionality/funds for LPs and swappers relying on that pool.

### Likelihood Explanation
The constant-product swap math (`ConstantProductCurve::swap_base_output_without_fees`) mathematically prevents the *tradable* vault balance from being driven to exactly zero in a single swap (the denominator `output_vault_amount - output_amount` must stay ≥ 1, else the `checked_div` in `checked_ceil_div` already returns `None`/`ZeroTradingTokens`). Reaching the true zero-division edge case therefore requires the post-fee balance (`vault_raw - accrued_fees`) to land on exactly zero, which is a narrower, state-dependent condition (e.g., vault liquidity driven near the floor while uncollected fees exactly consume the remainder) rather than trivially triggerable in one instruction. This lowers likelihood relative to a straightforward first-swap DoS, but the unguarded `/` is a clear deviation from the codebase's otherwise consistent `checked_div` discipline and is reachable purely through unprivileged `swap_base_input`/`swap_base_output` calls with attacker-chosen amounts over a sequence of trades.

### Recommendation
Replace both raw divisions in `token_price_x32` with `checked_div` (propagating `None` to a proper `ErrorCode`, e.g. reusing `ErrorCode::ZeroTradingTokens` or a new `ErrorCode::MathOverflow`/`DivideByZero`), consistent with the rest of `curve/calculator.rs` and `curve/fees.rs`:
```rust
pub fn token_price_x32(&self, vault_0: u64, vault_1: u64) -> Result<(u128, u128)> {
    let (token_0_amount, token_1_amount) = self.vault_amount_without_fee(vault_0, vault_1)?;
    let price_1_over_0 = (token_1_amount as u128)
        .checked_mul(Q32 as u128)
        .and_then(|v| v.checked_div(token_0_amount as u128))
        .ok_or(ErrorCode::ZeroTradingTokens)?;
    let price_0_over_1 = (token_0_amount as u128)
        .checked_mul(Q32 as u128)
        .and_then(|v| v.checked_div(token_1_amount as u128))
        .ok_or(ErrorCode::ZeroTradingTokens)?;
    Ok((price_1_over_0, price_0_over_1))
}
```

### Proof of Concept
1. Engineer pool state (through a sequence of unprivileged `swap_base_output`/`swap_base_input` calls plus deliberately deferred fee collection) so that one side's `vault_amount_without_fee` result equals exactly `0` — i.e., the vault's raw SPL balance equals the sum of `protocol_fees_token_x + fund_fees_token_x + creator_fees_token_x` for that token.
2. Submit any further `swap_base_input` or `swap_base_output` transaction touching that pool.
3. `get_swap_params` → `token_price_x32` executes `token_1_amount as u128 * Q32 as u128 / token_0_amount as u128` (or the symmetric expression) with a zero denominator, causing the BPF program to panic and the transaction to fail.
4. Because the state persists, every subsequent swap against the pool in that configuration will panic identically, denying service to all swappers/LPs of the pool until intervention.

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

**File:** programs/cp-swap/src/states/pool.rs (L263-296)
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
