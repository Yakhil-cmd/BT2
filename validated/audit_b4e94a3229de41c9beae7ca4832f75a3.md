### Title
RAY value overflow during interest accrual permanently freezes a whale market - (File: common/src/rates/simulate.rs)

### Summary
A sufficiently large market can accumulate interest until the unscaled RAY value of its stored debt or supply exceeds `i128::MAX`. The accrual path unscales these balances before applying the index ceiling, so the overflow panic prevents any further market operation and permanently freezes the market absent a contract upgrade.

### Finding Description
`accrue_step` converts the market's scaled debt and supply back to original RAY-denominated values before calculating utilization and the next borrow rate. [1](#0-0) 

Those conversions call `scaled_to_original`, which performs `scaled.mul(env, index)` without saturation or an overflow-safe intermediate representation. [2](#0-1) 

The borrow index ceiling is applied only after the unsafe value multiplication, so it does not prevent the debt or supply value itself from overflowing. [3](#0-2) 

Every mutating market operation loads the market and runs `global_sync` before its repayment, withdrawal, seizure, or other accounting mutation. [4](#0-3) [5](#0-4) [6](#0-5) 

An unprivileged user can create the precondition through `controller.supply(caller, 0, spoke_id, assets)` and `controller.borrow(caller, account_id, borrows, to)`, then trigger or observe the failure through `controller.update_indexes(caller, assets)`. Once reached, `controller.repay`, `controller.withdraw`, and `controller.liquidate` for that market all execute the same accrual first and revert with `MathOverflow`.

### Impact Explanation
This permanently freezes user funds in the affected market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot reduce unsafe debt, and cleanup or recapitalization paths that require a market load cannot progress because they all hit the same accrual panic. The pool continues to hold the tokens while the controller cannot complete accounting for the market.

This is a permanent freezing of funds and a market-level protocol liveness failure, not merely a transaction CPU or memory limit.

### Likelihood Explanation
The attack requires a very large position and sustained high utilization, so it is most relevant to high-cap markets, whale suppliers, or assets with sufficient circulating liquidity. The admitted cap domain extends to approximately 170 billion whole tokens, while a smaller position can become unrepresentable after index growth. Valid market parameters are therefore sufficient; no privileged call, leaked key, oracle manipulation, or transaction-budget exhaustion is required after the market is populated.

### Recommendation
Constrain scaled supply and debt at entry so `scaled * MAX_SUPPLY_INDEX_RAY` and `scaled * MAX_BORROW_INDEX_RAY` remain representable, or perform accrual valuation with a wider intermediate integer type. The accrual path should also handle representability limits without trapping before `last_timestamp` advances, for example by applying an explicit bounded-value policy that preserves the ability to repay, withdraw, or liquidate.

### Proof of Concept
1. In a market whose configured caps admit a whale position, call `controller.supply` for the debt asset with a large `Vec<(HubAssetKey, i128)>` entry, for example a billion whole tokens of an 18-decimal asset.
2. Supply sufficient collateral in another listed market to the same account.
3. Call `controller.borrow` to bring the debt market to sustained high utilization while keeping the account solvent.
4. Leave the debt market inactive while interest accrues, or repeatedly call `controller.update_indexes(caller, vec![debt_hub_asset])`.
5. After the scaled debt times the borrow index exceeds `i128::MAX`, `accrue_step → scaled_to_original → Ray::mul` panics before `global_sync` can commit the new timestamp.
6. Any subsequent `controller.repay`, `controller.withdraw`, `controller.liquidate`, `controller.clean_bad_debt`, `controller.recapitalize`, `controller.flash_loan`, or strategy touching that market reruns the same accrual and reverts, leaving the market's funds frozen.

### Citations

**File:** common/src/rates/simulate.rs (L51-64)
```rust
pub fn accrue_step(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    supplied: Ray,
    borrow_index: Ray,
    supply_index: Ray,
    delta_ms: u64,
) -> AccrualStep {
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** contracts/pool/src/interest.rs (L20-33)
```rust
pub(crate) fn global_sync(env: &Env, cache: &mut Cache) {
    if !cache.needs_accrual() {
        return;
    }

    let mut remaining = cache.elapsed_ms();
    while let Some(nonzero) = NonZeroU64::new(remaining) {
        let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
        accrue_chunk(env, cache, chunk);
        remaining = remaining.saturating_sub(chunk);
    }

    cache.mark_accrued();
}
```

**File:** contracts/pool/src/ops/repay.rs (L40-45)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
```

**File:** contracts/pool/src/ops/withdraw.rs (L57-67)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
    // Burn first: `protocol_fee_shares` caps the fee mint at `i128::MAX - supplied`.
    let remaining = burn_position(env, &mut cache, position, burned);
```
