### Title
`swap_base_input`/`swap_base_output` permanently revert on legitimate zero-fee configs due to a division-by-zero in `Fees::split_creator_fee` - ([File: programs/cp-swap/src/curve/fees.rs])

### Summary
When an `AmmConfig` is created with `trade_fee_rate = 0` and `creator_fee_rate = 0` (a valid, non-malicious "zero fee" configuration allowed by `create_amm_config`'s assertions), every swap on the input side where `is_creator_fee_on_input` is `true` unconditionally fails, because `Fees::split_creator_fee` divides by `trade_fee_rate + creator_fee_rate`, which is `0`. This mirrors the referenced Badger Citadel bug: a legitimate "no discount / no fee" configuration causes the core `getAmountOut`/`deposit` (here, `swap_base_input`/`swap_base_output`) computation to silently degrade into a value that makes the transaction always revert, permanently freezing that swap path for the pool.

### Finding Description
`create_amm_config` only asserts an upper bound on the fee rates, not a lower bound: [1](#0-0) 
so `trade_fee_rate = 0` together with `creator_fee_rate = 0` is a perfectly valid configuration an admin can create.

In `CurveCalculator::swap_base_input`, when `is_creator_fee_on_input` is true, the code computes: [2](#0-1) 
`Fees::trading_fee(input_amount, trade_fee_rate + creator_fee_rate)` returns `0` when the combined rate is `0`, and then `Fees::split_creator_fee(0, 0, 0)` is called, which internally calls `floor_div(total_fee, creator_fee_rate, trade_fee_rate + creator_fee_rate)`: [3](#0-2) 
`floor_div` explicitly checks for a zero denominator and returns `None` in that case: [4](#0-3) 
Since `trade_fee_rate + creator_fee_rate == 0`, the `?` operator propagates `None` out of `swap_base_input`, so the whole `CurveCalculator::swap_base_input` returns `None` regardless of any other input.

The instruction handler treats `None` as an unconditional error: [5](#0-4) 

The identical pattern exists on the `swap_base_output` path: when `is_creator_fee_on_input` is true, `calculate_pre_fee_amount(input_amount_swapped, trade_fee_rate + creator_fee_rate)` short-circuits to `Some(post_fee_amount)` when the combined rate is `0` (giving `total_fee = 0`), and the subsequent `Fees::split_creator_fee(0, 0, 0)` again divides by zero and returns `None`: [6](#0-5) [3](#0-2) 

This is structurally identical to the Badger Citadel bug: a normal, allowed configuration state (no discount / here, zero fee) causes the core pricing function to always return a value that forces the calling instruction to unconditionally revert, rather than gracefully degrading to "no fee applied."

### Impact Explanation
Any pool whose `AmmConfig` has `trade_fee_rate = 0` and `creator_fee_rate = 0` becomes permanently unable to execute swaps in the direction where `is_creator_fee_on_input` evaluates to `true` (this depends on the pool's `CreatorFeeOn` setting and the trade direction). Every unprivileged swapper submitting `swap_base_input` or `swap_base_output` on that side will have their transaction revert with `ZeroTradingTokens`, permanently freezing that trading direction and any funds a user attempts to swap through it. This is a denial-of-service on core AMM functionality for a legitimate, admin-permitted fee configuration — not a hypothetical or contrived edge case, since zero-fee promotional pools are a realistic configuration choice.

### Likelihood Explanation
Likelihood is moderate-to-high in any deployment that supports fee-less or promotional pools: the only precondition is an `AmmConfig` with `trade_fee_rate = 0` and `creator_fee_rate = 0`, which passes all of `create_amm_config`'s validation. Once such a config exists, every unprivileged user's normal swap call on the affected side deterministically fails — no attacker-controlled malicious input is even required beyond simply calling the standard swap instruction against that pool.

### Recommendation
Guard `Fees::split_creator_fee` (and any other fee-splitting helper) against a zero combined rate by short-circuiting to `Some(0)` when `trade_fee_rate + creator_fee_rate == 0`, analogous to how `Fees::calculate_pre_fee_amount` already special-cases `trade_fee_rate == 0`. Concretely, in `programs/cp-swap/src/curve/fees.rs`, `split_creator_fee` should return `Some(0)` immediately if `trade_fee_rate + creator_fee_rate == 0` instead of calling `floor_div` with a zero denominator, ensuring zero-fee configurations degrade to "no fee charged" instead of causing every swap in the affected direction to revert.

### Proof of Concept
1. Admin calls `create_amm_config` with `trade_fee_rate = 0`, `protocol_fee_rate = 0`, `fund_fee_rate = 0`, `creator_fee_rate = 0` — passes all asserts in `programs/cp-swap/src/lib.rs` lines 97–101.
2. A pool is initialized against this config (`CreatorFeeOn` set such that, for some trade direction, `is_creator_fee_on_input` is `true`).
3. Any unprivileged user calls `swap_base_input` (or `swap_base_output`) in that direction with any positive `amount_in`.
4. Inside `CurveCalculator::swap_base_input`, `Fees::trading_fee(input_amount, 0)` returns `0`, then `Fees::split_creator_fee(0, 0, 0)` calls `floor_div(0, 0, 0)`, which detects `fee_denominator == 0` and returns `None`.
5. The `?` operator propagates `None`, `CurveCalculator::swap_base_input` returns `None`, and `swap_base_input` in `programs/cp-swap/src/instructions/swap_base_input.rs` line 120 converts this to `Err(ErrorCode::ZeroTradingTokens)`, reverting the transaction — for every call, regardless of amount, permanently freezing that swap direction.

### Citations

**File:** programs/cp-swap/src/lib.rs (L97-101)
```rust
    ) -> Result<()> {
        assert!(trade_fee_rate + creator_fee_rate < FEE_RATE_DENOMINATOR_VALUE);
        assert!(protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
        assert!(fund_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
        assert!(fund_fee_rate + protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
```

**File:** programs/cp-swap/src/curve/calculator.rs (L108-112)
```rust
        let input_amount_less_fees = if is_creator_fee_on_input {
            let total_fee = Fees::trading_fee(input_amount, trade_fee_rate + creator_fee_rate)?;
            creator_fee = Fees::split_creator_fee(total_fee, trade_fee_rate, creator_fee_rate)?;
            trade_fee = total_fee - creator_fee;
            input_amount.checked_sub(total_fee)?
```

**File:** programs/cp-swap/src/curve/calculator.rs (L173-182)
```rust
        let input_amount = if is_creator_fee_on_input {
            let input_amount_with_fee = Fees::calculate_pre_fee_amount(
                input_amount_swapped,
                trade_fee_rate + creator_fee_rate,
            )
            .unwrap();
            let total_fee = input_amount_with_fee - input_amount_swapped;
            creator_fee = Fees::split_creator_fee(total_fee, trade_fee_rate, creator_fee_rate)?;
            trade_fee = total_fee - creator_fee;
            input_amount_with_fee
```

**File:** programs/cp-swap/src/curve/fees.rs (L19-26)
```rust
pub fn floor_div(token_amount: u128, fee_numerator: u128, fee_denominator: u128) -> Option<u128> {
    if fee_denominator == 0 {
        return None;
    }
    token_amount
        .checked_mul(fee_numerator)?
        .checked_div(fee_denominator)
}
```

**File:** programs/cp-swap/src/curve/fees.rs (L65-75)
```rust
    pub fn split_creator_fee(
        total_fee: u128,
        trade_fee_rate: u64,
        creator_fee_rate: u64,
    ) -> Option<u128> {
        floor_div(
            total_fee,
            u128::from(creator_fee_rate),
            u128::from(trade_fee_rate + creator_fee_rate),
        )
    }
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L110-120)
```rust
    let result = CurveCalculator::swap_base_input(
        u128::from(actual_amount_in),
        u128::from(total_input_token_amount),
        u128::from(total_output_token_amount),
        ctx.accounts.amm_config.trade_fee_rate,
        creator_fee_rate,
        ctx.accounts.amm_config.protocol_fee_rate,
        ctx.accounts.amm_config.fund_fee_rate,
        is_creator_fee_on_input,
    )
    .ok_or(ErrorCode::ZeroTradingTokens)?;
```
