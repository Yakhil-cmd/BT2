### Title
Unvalidated `trade_fee_rate + creator_fee_rate` at config creation causes permanent panic/DoS on `swap_base_output` - (File: programs/cp-swap/src/instructions/admin/create_config.rs, programs/cp-swap/src/curve/fees.rs, programs/cp-swap/src/curve/calculator.rs)

### Summary
`create_amm_config` writes `trade_fee_rate` and `creator_fee_rate` directly into a new `AmmConfig` with no bounds validation, unlike `update_amm_config`, which enforces `trade_fee_rate + creator_fee_rate < FEE_RATE_DENOMINATOR_VALUE` on every subsequent update. [1](#0-0) [2](#0-1)  If a config is ever created with `trade_fee_rate + creator_fee_rate >= FEE_RATE_DENOMINATOR_VALUE` (1_000_000), any pool using that config becomes permanently unable to process `swap_base_output`, because `Fees::calculate_pre_fee_amount` performs an unchecked-looking subtraction whose `Option::None` result is `.unwrap()`'d directly in the calculator, causing a panic/revert on every call — mirroring the DAIInterestRateModel bug where a rate parameter outside the range the code implicitly assumes causes `checked_sub`/subtraction-derived `None` to propagate into an unconditional revert of a function that legitimate, unprivileged users must call.

### Finding Description
`Fees::calculate_pre_fee_amount` computes `denominator = FEE_RATE_DENOMINATOR_VALUE.checked_sub(trade_fee_rate)`. [3](#0-2)  This is called from `CurveCalculator::swap_base_output` with `trade_fee_rate + creator_fee_rate` (when fee is on input) or `trade_fee_rate` alone (when fee is on output), and the result is `.unwrap()`'d immediately, not propagated as an `Option`: [4](#0-3) 

The only code path that is supposed to keep `trade_fee_rate + creator_fee_rate < FEE_RATE_DENOMINATOR_VALUE` is `update_trade_fee_rate` / `update_creator_fee_rate` in the admin update path: [5](#0-4)  However, `create_amm_config`, which sets the *initial* `trade_fee_rate` and `creator_fee_rate` values for a brand-new `AmmConfig`, performs no such check at all: [1](#0-0) 

If a config is created (via a single malformed/misconfigured `create_amm_config` call) with `trade_fee_rate + creator_fee_rate >= 1_000_000`, then for any pool using that config, every unprivileged `swap_base_output` call — reachable by any swapper with attacker-chosen `max_amount_in`/`amount_out_received` — will hit `calculate_pre_fee_amount` with a denominator of `0` or an underflowed subtraction returning `None`, and the immediate `.unwrap()` inside `swap_base_output` (the calculator function, not the instruction handler) will panic and abort the transaction unconditionally. This is analogous to the reported DSR bug: a rate-like configuration value that the code implicitly assumes stays inside a bound, when that bound is violated through a code path lacking validation, causes an unconditional revert (panic) of a function ordinary users must call (`swap_base_output`), rather than a graceful, recoverable error.

Unlike the update path (which correctly guards the invariant with `assert!(... < FEE_RATE_DENOMINATOR_VALUE)`), the creation path has no equivalent guard, so the invariant that the rest of the fee-calculation code silently relies on can be violated once — and after that, it can never be un-violated for that config, permanently freezing `swap_base_output` for every pool attached to it (LP funds become inaccessible via that entry point, and if the pool has no alternative arbitrage/exit route relying on `swap_base_output`, output-denominated swaps are permanently DoS'd).

### Impact Explanation
This is a Medium-severity availability/DoS issue: it does not directly let an attacker steal funds via a single crafted transaction, since triggering the root cause requires a governance/admin action (`create_amm_config`) with an unvalidated fee-rate combination. However, once triggered, it permanently and unconditionally breaks `swap_base_output` — an unprivileged, user-reachable entry point — for every pool on the affected `AmmConfig`, which is a permanent-freezing-of-functionality issue analogous to the cited DSR bug (unexpected reverts blocking a core user-facing operation, with no way to reverse the underlying state once set).

### Likelihood Explanation
Likelihood is low-to-moderate: it requires the config-creation transaction to pass fee-rate values summing to ≥ `FEE_RATE_DENOMINATOR_VALUE`, which the protocol's own update path treats as an invariant violation elsewhere (`update_trade_fee_rate`/`update_creator_fee_rate` explicitly enforce `< FEE_RATE_DENOMINATOR_VALUE`) but `create_amm_config` does not enforce at all. This exact create/update asymmetry increases the likelihood of the invariant being violated by mistake (e.g., an admin script porting fee percentages incorrectly, or a config created before the update-side checks were added) despite there being no other privileged-attacker consideration required for the resulting revert.

### Recommendation
Add the same invariant check that `update_trade_fee_rate`/`update_creator_fee_rate` enforce (`trade_fee_rate + creator_fee_rate < FEE_RATE_DENOMINATOR_VALUE`, and similarly `protocol_fee_rate + fund_fee_rate <= FEE_RATE_DENOMINATOR_VALUE`) directly inside `create_amm_config` before writing the values, so that no `AmmConfig` can ever be created in a state that violates the invariant relied upon by `Fees::calculate_pre_fee_amount`. Additionally, replace the `.unwrap()` calls in `CurveCalculator::swap_base_output` (`programs/cp-swap/src/curve/calculator.rs` lines 174-188) with proper `?`/`ok_or(...)` propagation of `None` into a defined `ErrorCode` (e.g., `ErrorCode::MathOverflow` or a new `InvalidFeeRate`), so that even if the invariant is ever violated, the failure is a graceful, well-defined error rather than a raw panic.

### Proof of Concept
1. Admin calls `create_amm_config(index, trade_fee_rate = 900_000, protocol_fee_rate = 0, fund_fee_rate = 0, create_pool_fee = 0, creator_fee_rate = 150_000)`. No validation rejects this even though `900_000 + 150_000 = 1_050_000 > FEE_RATE_DENOMINATOR_VALUE (1_000_000)`, per [1](#0-0) .
2. A pool is initialized using this `AmmConfig` via `initialize` (or `initialize_with_permission`) — no cross-check against this invariant occurs there either.
3. Any user calls `swap_base_output` with `is_creator_fee_on_input = true`. Inside `CurveCalculator::swap_base_output`, `Fees::calculate_pre_fee_amount(input_amount_swapped, trade_fee_rate + creator_fee_rate)` is invoked with `trade_fee_rate + creator_fee_rate = 1_050_000`; the denominator `FEE_RATE_DENOMINATOR_VALUE.checked_sub(1_050_000)` underflows and returns `None`, and the subsequent `.unwrap()` panics, per [4](#0-3) .
4. Every subsequent `swap_base_output` call against this pool reverts identically and permanently — the pool's `swap_base_output` path is permanently frozen for all users.

### Citations

**File:** programs/cp-swap/src/instructions/admin/create_config.rs (L32-53)
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
    let amm_config = ctx.accounts.amm_config.deref_mut();
    amm_config.protocol_owner = crate::protocol_fee_owner::ID;
    amm_config.bump = ctx.bumps.amm_config;
    amm_config.disable_create_pool = false;
    amm_config.index = index;
    amm_config.trade_fee_rate = trade_fee_rate;
    amm_config.protocol_fee_rate = protocol_fee_rate;
    amm_config.fund_fee_rate = fund_fee_rate;
    amm_config.create_pool_fee = create_pool_fee;
    amm_config.fund_owner = crate::fund_fee_owner::ID;
    amm_config.creator_fee_rate = creator_fee_rate;
    Ok(())
}
```

**File:** programs/cp-swap/src/instructions/admin/update_config.rs (L41-61)
```rust
fn update_protocol_fee_rate(amm_config: &mut Account<AmmConfig>, protocol_fee_rate: u64) {
    assert!(protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
    assert!(protocol_fee_rate + amm_config.fund_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
    amm_config.protocol_fee_rate = protocol_fee_rate;
}

fn update_trade_fee_rate(amm_config: &mut Account<AmmConfig>, trade_fee_rate: u64) {
    assert!(trade_fee_rate + amm_config.creator_fee_rate < FEE_RATE_DENOMINATOR_VALUE);
    amm_config.trade_fee_rate = trade_fee_rate;
}

fn update_fund_fee_rate(amm_config: &mut Account<AmmConfig>, fund_fee_rate: u64) {
    assert!(fund_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
    assert!(fund_fee_rate + amm_config.protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
    amm_config.fund_fee_rate = fund_fee_rate;
}

fn update_creator_fee_rate(amm_config: &mut Account<AmmConfig>, creator_fee_rate: u64) {
    assert!(creator_fee_rate + amm_config.trade_fee_rate < FEE_RATE_DENOMINATOR_VALUE);
    amm_config.creator_fee_rate = creator_fee_rate;
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

**File:** programs/cp-swap/src/curve/calculator.rs (L173-188)
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
        } else {
            let input_amount_with_fee =
                Fees::calculate_pre_fee_amount(input_amount_swapped, trade_fee_rate).unwrap();
            trade_fee = input_amount_with_fee - input_amount_swapped;
            input_amount_with_fee
        };
```
