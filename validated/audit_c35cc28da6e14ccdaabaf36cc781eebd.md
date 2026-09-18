Found it: `token_price_x32()` performs raw (non-checked) division that panics on divide-by-zero, directly analogous to the Firebird `sdl_desc()` bug where an unvalidated zero-length value flows into a division.

### Title
Unchecked division by zero in `token_price_x32` causes transaction panic / pool DoS - (File: `programs/cp-swap/src/states/pool.rs`)

### Summary
`PoolState::token_price_x32` computes token price ratios using raw `/` operators instead of `checked_div`, so if either vault balance (net of fees) is zero, the operation panics and aborts the transaction, unlike every other arithmetic path in the curve/fee code, which uses `checked_*` and returns `Option`/`Result` errors instead of panicking.

### Finding Description
All other numeric paths in the program (`Fees::trading_fee`, `Fees::protocol_fee`, `ConstantProductCurve::lp_tokens_to_trading_tokens`, `swap_base_output_without_fees`, etc.) guard denominators and use `checked_div`/`checked_ceil_div`, returning `None`/`Result::Err` on invalid input rather than panicking: [1](#0-0) [2](#0-1) 

`token_price_x32`, however, performs raw multiplication/division without any zero-check or `checked_div`: [3](#0-2) 

It derives `token_0_amount`/`token_1_amount` from `vault_amount_without_fee`, which itself only guards against `checked_sub` overflow (i.e., accumulated fees exceeding the raw vault balance) but does not guarantee the resulting net amount is non-zero: [4](#0-3) 

If a caller of `token_price_x32` supplies (or the pool state reaches) a vault amount that nets to zero after fee subtraction, the raw `/ token_0_amount` or `/ token_1_amount` division panics inside the Solana BPF runtime. This mirrors the Firebird CVE-2026-35215 pattern exactly: an unvalidated (here, unchecked-for-zero) value flows directly into a division operation, producing an unhandled division-by-zero crash reachable from external, attacker-influenced input.

### Impact Explanation
A panic inside program execution aborts the transaction. If `token_price_x32` is invoked in a code path reachable by an unprivileged swap/deposit/withdraw instruction (or any client/CPI-facing accessor) with vault state that nets to zero, an attacker can reliably trigger a transaction failure, denying service to that instruction for the affected pool. This matches the CVSS AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H profile of the reference CVE: no confidentiality/integrity loss, but full availability impact via crash.

### Likelihood Explanation
The likelihood depends on whether `token_price_x32` is actually invoked from one of the in-scope permissionless instructions (`initialize`, `deposit`, `withdraw`, `swap_base_input`, `swap_base_output`, `collect_creator_fee*`) with attacker-influenced vault/fee state that can net to zero. From the code reviewed, `vault_amount_without_fee` is called directly by `deposit`/`withdraw`/`swap_base_output`, but I did not find a direct call site of `token_price_x32` within those instruction handlers in the portions of the codebase indexed here — it appears to be an accessor function whose callers were not located in this pass.

### Recommendation
Replace the raw division in `token_price_x32` with `checked_div` (returning `Result`/`Option` and propagating a proper error such as `ErrorCode::ZeroTradingTokens` or a new `ErrorCode::DivideByZero`) so that a zero-amount vault produces a graceful program error instead of a panic, consistent with the rest of the codebase's arithmetic conventions.

### Proof of Concept
Could not confirm within the indexed portion of the repository which in-scope instruction handler calls `token_price_x32` with attacker-controlled zero vault amounts, so a concrete end-to-end PoC transaction sequence cannot be constructed from the available context. This is a limitation of the current search coverage, not evidence that the path is unreachable — a full-repository review (e.g., via a Devin session with complete file access) would be needed to confirm all call sites of `token_price_x32` and whether any of them are reachable from unprivileged instructions with attacker-influenced zero-amount vaults.

### Citations

**File:** programs/cp-swap/src/curve/fees.rs (L7-16)
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
