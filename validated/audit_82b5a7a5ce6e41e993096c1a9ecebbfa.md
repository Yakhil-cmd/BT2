### Title
Unchecked division by zero in `PoolState::token_price_x32` permanently bricks pool swaps - ([File: programs/cp-swap/src/states/pool.rs])

### Summary
`PoolState::token_price_x32` performs raw integer division (`/`) on the fee-adjusted vault reserves without any zero-check or `checked_div`, unlike every other arithmetic path in the curve/fee code which uses `checked_*` operators. If either side's fee-adjusted reserve becomes `0`, every subsequent call panics, permanently breaking `swap_base_input` and `swap_base_output` for that pool — directly analogous to the CVE-2022-49670 divide-by-zero in `rdma_dim_stats_compare()`.

### Finding Description
`token_price_x32` computes the oracle price using plain division operators: [1](#0-0) 

Unlike `Fees::floor_div`/`ceil_div` in `curve/fees.rs`, which explicitly guard `fee_denominator == 0` before dividing [2](#0-1) , and unlike `ConstantProductCurve` which uses `checked_div`/`checked_mul` [3](#0-2) , `token_price_x32` uses the raw `/` operator on `token_0_amount` and `token_1_amount`, which are the result of `vault_amount_without_fee` — the raw SPL vault balance minus the accumulated protocol/fund/creator fees owed: [4](#0-3) 

`token_price_x32` is invoked unconditionally on **every** swap via `get_swap_params`, before any funds move: [5](#0-4) 

and this call happens at the very start of `swap_base_input` (and equivalently `swap_base_output`), prior to the transfer CPIs: [6](#0-5) 

Because fees accrue in the vault but are only removed from LP-withdrawable reserves logically (via `vault_amount_without_fee`), it is possible for the true LP reserve on one side (`vault_balance - accumulated_fees_on_that_side`) to reach exactly `0` — e.g. once all liquidity providers fully withdraw their share (bounded by `vault_amount_without_fee`, which is the LP-owned reserve), while the raw vault balance still retains the uncollected protocol/fund/creator fees. At that point `token_0_amount` or `token_1_amount` equals `0`, and the next `/` in `token_price_x32` divides by zero, causing an arithmetic panic that aborts the transaction. Since this call is unconditional and unguarded, **every** future swap attempt against this pool will panic in the same way, permanently disabling swapping for the pool.

### Impact Explanation
Once triggered, the pool enters a state where `swap_base_input`/`swap_base_output` can never succeed again — every transaction reaches `get_swap_params` → `token_price_x32` and panics before any transfer occurs. This is a permanent denial-of-service on the pool's core trading function, effectively freezing the remaining pool funds (protocol/fund/creator fees still sitting in the vaults, and any residual dust) from being traded against, satisfying the "permanent freezing of user or LP funds" impact category. This matches the root cause class of CVE-2022-49670 (unchecked division causing a hard fault on a code path reachable by ordinary, unprivileged operation).

### Likelihood Explanation
Reachable purely through the documented unprivileged instruction set (`deposit`/`withdraw`/`swap_base_input`/`swap_base_output`) with attacker-chosen amounts; no privileged signer or special build flag is required. The zero-reserve state requires liquidity providers to withdraw down to the fee-adjusted floor on one side (a legitimate, permitted operation via `withdraw`), after which any subsequent swap call by any user (including the attacker) triggers the panic. This makes exploitation likely for pools with concentrated or fully-withdrawable liquidity and non-trivial accrued fees.

### Recommendation
Replace the raw `/` operators in `token_price_x32` with `checked_div` (mirroring the pattern already used in `curve/constant_product.rs` and `curve/fees.rs`), returning a proper `ErrorCode` (e.g. `ErrorCode::MathOverflow` or a new `ZeroReserve` error) instead of panicking when `token_0_amount` or `token_1_amount` is zero. Optionally also guard `vault_amount_without_fee` callers to reject swaps when either fee-adjusted reserve is zero, preventing pool from entering an unswappable state entirely.

### Proof of Concept
1. Pool P is created and liquidity is deposited via `deposit`; swaps occur so protocol/fund/creator fees accrue in the vaults (tracked in `protocol_fees_token_0/1`, `fund_fees_token_0/1`, `creator_fees_token_0/1`).
2. LPs fully withdraw via `withdraw` until the LP-owned reserve on one side (`vault_balance - accumulated_fees`) reaches exactly `0` (permitted, since `withdraw` is bounded by `vault_amount_without_fee`, not by the raw vault balance).
3. Any subsequent call to `swap_base_input` or `swap_base_output` on pool P invokes `pool_state.get_swap_params(...)` → `self.token_price_x32(vault_0, vault_1)`, computing `token_0_amount as u128 * Q32 as u128 / token_1_amount as u128` (or the symmetric case) where the divisor is `0`.
4. The Rust arithmetic panic aborts the transaction. Because this happens before any transfer logic and unconditionally on every swap call, the pool's swap functionality is permanently unusable from that point forward.

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

**File:** programs/cp-swap/src/states/pool.rs (L263-305)
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
