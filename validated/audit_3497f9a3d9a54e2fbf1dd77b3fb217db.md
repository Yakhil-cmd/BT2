### Title
Zero-fee AmmConfig (`trade_fee_rate = 0` with creator fee disabled/zero) permanently DoSes `swap_base_input`/`swap_base_output` via unguarded division-by-zero in `Fees::split_creator_fee` - (File: `programs/cp-swap/src/curve/fees.rs`)

### Summary
`create_amm_config` explicitly permits `trade_fee_rate = 0` (the assertion only requires `trade_fee_rate + creator_fee_rate < FEE_RATE_DENOMINATOR_VALUE`, so `0 + 0 < 1_000_000` passes) [1](#0-0) . When a pool is swapped in a direction where `is_creator_fee_on_input` is `true` (the default `CreatorFeeOn::BothToken` mode returns `true` for every direction), `CurveCalculator::swap_base_input`/`swap_base_output` call `Fees::split_creator_fee(total_fee, trade_fee_rate, creator_fee_rate)`, whose denominator is `trade_fee_rate + creator_fee_rate` [2](#0-1) . If both `trade_fee_rate` and the effective `creator_fee_rate` (forced to `0` whenever `enable_creator_fee` is false via `adjust_creator_fee_rate`) are `0`, this denominator is `0`, and `floor_div` explicitly returns `None` in that case [3](#0-2) . That `None` propagates all the way up and causes `swap_base_input`/`swap_base_output` to unconditionally return `ErrorCode::ZeroTradingTokens` [4](#0-3) [5](#0-4) .

### Finding Description
The root cause is analogous to the referenced Honorarium bug: a rate of `0%` is a documented/allowed configuration value (validated only by `assert!(trade_fee_rate + creator_fee_rate < FEE_RATE_DENOMINATOR_VALUE)` [6](#0-5) ), but downstream arithmetic assumes the sum is strictly positive without gracefully handling the zero case — unlike `calculate_pre_fee_amount`, which explicitly special-cases `trade_fee_rate == 0` [7](#0-6) , `split_creator_fee` has no such guard and instead delegates to `floor_div`, which treats a zero denominator as an unconditional failure (`return None`) rather than as "no fee, don't divide" [8](#0-7) .

`split_creator_fee` is reached in both swap paths whenever `is_creator_fee_on_input` is `true`:
- `swap_base_input`: `let total_fee = Fees::trading_fee(input_amount, trade_fee_rate + creator_fee_rate)?; let creator_fee = Fees::split_creator_fee(total_fee, trade_fee_rate, creator_fee_rate)?;` [9](#0-8) 
- `swap_base_output`: same call pattern [10](#0-9) 

`is_creator_fee_on_input` returns `true` for every trade direction under the default `CreatorFeeOn::BothToken` mode [11](#0-10) , and the effective `creator_fee_rate` passed into the curve is forced to `0` whenever `enable_creator_fee` is `false`, regardless of the `AmmConfig`'s configured `creator_fee_rate`: `pub fn adjust_creator_fee_rate(&self, creator_fee_rate: u64) -> u64 { if self.enable_creator_fee { creator_fee_rate } else { 0 } }` [12](#0-11) , and this adjusted value is what's actually fed into `CurveCalculator::swap_base_input`/`swap_base_output` [13](#0-12) .

Consequently, any pool created against an `AmmConfig` with `trade_fee_rate = 0` (a legitimate, permitted admin configuration — e.g. intended as a "no-fee" pool) combined with creator fee disabled/zero will have `split_creator_fee(0, 0, 0)` return `None` on every single swap attempt in the `BothToken` mode (the default), causing `CurveCalculator::swap_base_input`/`swap_base_output` to return `None` and the instruction handler to revert with `ErrorCode::ZeroTradingTokens` unconditionally.

### Impact Explanation
This is a permanent Denial of Service on the pool's core swap functionality. Any unprivileged swapper submitting a transaction to `swap_base_input` or `swap_base_output` against such a pool will always fail — the pool becomes completely unusable for trading, permanently freezing all liquidity for swapping purposes (deposits/withdrawals may still work, but the primary AMM function is bricked). Because `trade_fee_rate = 0` is explicitly allowed by the config validation and represents a reasonable admin intent (a zero-fee pool), this is a realistic and not merely theoretical configuration, mirroring the exact class of issue validated as Medium in the referenced report (a documented/allowed 0% rate silently breaks core protocol functionality).

### Likelihood Explanation
Likelihood is moderate: it requires an admin to create an `AmmConfig` with `trade_fee_rate = 0` and either leave `creator_fee_rate = 0` or leave `enable_creator_fee = false` (which forces the effective creator fee rate to 0 regardless of config), and use the default `CreatorFeeOn::BothToken` mode. All three conditions are permitted by validation and plausible for anyone wanting to deploy a genuinely fee-free pool (e.g., for promotional or stable-pair use cases), and no privileged or malicious action beyond a routine `create_amm_config`/`initialize` call is needed. Once such a pool exists, every unprivileged swapper's `placeBid`-equivalent call (`swap_base_input`/`swap_base_output`) is deterministically DoS'd.

### Recommendation
Add an explicit zero-denominator guard in `Fees::split_creator_fee` (or in the calling code) analogous to the fix pattern already used in `calculate_pre_fee_amount`:
```rust
pub fn split_creator_fee(
    total_fee: u128,
    trade_fee_rate: u64,
    creator_fee_rate: u64,
) -> Option<u128> {
    if trade_fee_rate + creator_fee_rate == 0 {
        return Some(0);
    }
    floor_div(
        total_fee,
        u128::from(creator_fee_rate),
        u128::from(trade_fee_rate + creator_fee_rate),
    )
}
```
This makes a `0%`/`0%` fee configuration degrade gracefully (no fee is charged/split) instead of unconditionally failing every swap.

### Proof of Concept
1. Admin calls `create_amm_config` with `trade_fee_rate = 0`, `protocol_fee_rate = 0`, `fund_fee_rate = 0`, `creator_fee_rate = 0` (passes the validation `assert!(trade_fee_rate + creator_fee_rate < FEE_RATE_DENOMINATOR_VALUE)` since `0 < 1_000_000`) [14](#0-13) .
2. A pool is initialized against this config with default `creator_fee_on = CreatorFeeOn::BothToken` (`is_creator_fee_on_input` always returns `true`) [11](#0-10) .
3. Any unprivileged user calls `swap_base_input` with a valid `amount_in`. Inside `CurveCalculator::swap_base_input`, `total_fee = Fees::trading_fee(input_amount, 0) = 0`, then `Fees::split_creator_fee(0, 0, 0)` calls `floor_div(0, 0, 0)`, which hits `if fee_denominator == 0 { return None; }` and returns `None` [8](#0-7) .
4. `CurveCalculator::swap_base_input` therefore returns `None`, and `swap_base_input`'s `.ok_or(ErrorCode::ZeroTradingTokens)?` reverts the transaction [4](#0-3) .
5. Every subsequent swap attempt on this pool reverts identically — the pool's swap functionality is permanently unusable.

### Citations

**File:** programs/cp-swap/src/lib.rs (L89-111)
```rust
    pub fn create_amm_config(
        ctx: Context<CreateAmmConfig>,
        index: u16,
        trade_fee_rate: u64,
        protocol_fee_rate: u64,
        fund_fee_rate: u64,
        create_pool_fee: u64,
        creator_fee_rate: u64,
    ) -> Result<()> {
        assert!(trade_fee_rate + creator_fee_rate < FEE_RATE_DENOMINATOR_VALUE);
        assert!(protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
        assert!(fund_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
        assert!(fund_fee_rate + protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
        instructions::create_amm_config(
            ctx,
            index,
            trade_fee_rate,
            protocol_fee_rate,
            fund_fee_rate,
            create_pool_fee,
            creator_fee_rate,
        )
    }
```

**File:** programs/cp-swap/src/curve/fees.rs (L18-26)
```rust
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

**File:** programs/cp-swap/src/curve/fees.rs (L77-90)
```rust
    pub fn calculate_pre_fee_amount(post_fee_amount: u128, trade_fee_rate: u64) -> Option<u128> {
        if trade_fee_rate == 0 {
            Some(post_fee_amount)
        } else {
            let numerator = post_fee_amount.checked_mul(u128::from(FEE_RATE_DENOMINATOR_VALUE))?;
            let denominator =
                u128::from(FEE_RATE_DENOMINATOR_VALUE).checked_sub(u128::from(trade_fee_rate))?;

            numerator
                .checked_add(denominator)?
                .checked_sub(1)?
                .checked_div(denominator)
        }
    }
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L108-120)
```rust
    let creator_fee_rate =
        pool_state.adjust_creator_fee_rate(ctx.accounts.amm_config.creator_fee_rate);
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

**File:** programs/cp-swap/src/instructions/swap_base_output.rs (L48-58)
```rust
    let result = CurveCalculator::swap_base_output(
        u128::from(amount_out_with_transfer_fee),
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

**File:** programs/cp-swap/src/states/pool.rs (L253-261)
```rust
    pub fn is_creator_fee_on_input(&self, direction: TradeDirection) -> Result<bool> {
        let fee_on = CreatorFeeOn::from_u8(self.creator_fee_on)?;
        Ok(match (fee_on, direction) {
            (CreatorFeeOn::BothToken, _) => true,
            (CreatorFeeOn::OnlyToken0, TradeDirection::ZeroForOne) => true,
            (CreatorFeeOn::OnlyToken1, TradeDirection::OneForZero) => true,
            _ => false,
        })
    }
```

**File:** programs/cp-swap/src/states/pool.rs (L318-324)
```rust
    pub fn adjust_creator_fee_rate(&self, creator_fee_rate: u64) -> u64 {
        if self.enable_creator_fee {
            creator_fee_rate
        } else {
            0
        }
    }
```
