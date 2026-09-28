### Title
RAY-scaled market totals overflow `i128` and permanently freeze all market operations - (File: common/src/rates/scaling.rs)

### Summary
`accrue_step` converts scaled borrow and supply shares back into RAY values before applying the borrow-index ceiling. Both conversions use `scaled_to_original`, which delegates to panicking `Ray::mul` rather than a saturating operation. Once `borrowed * borrow_index` or `supplied * supply_index` exceeds `i128::MAX`, every market mutation reverts while attempting accrual, including permissionless `update_indexes`, user repayment, withdrawals, and liquidation. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
The interest accumulator first computes the market's aggregate values:

```rust
let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
let supplied_original = scaled_to_original(env, supplied, supply_index);
```

`scaled_to_original` is an exact panicking fixed-point multiplication. The subsequent `update_borrow_index` caps the index at `MAX_BORROW_INDEX_RAY`, but that cap is applied to the index alone and occurs after aggregate value multiplication has already succeeded. Thus, an index below the documented cap can still make a sufficiently large market's aggregate RAY value exceed `i128::MAX`. [1](#0-0) [4](#0-3) 

The pool applies `global_sync` as part of its normal mutation sequence, so an overflowing accrual aborts the whole entrypoint before repayment, withdrawal, liquidation, or any other recovery path can execute. An unprivileged caller can reach the same accrual directly through `controller::update_indexes(caller, vec![hub_asset])`. [3](#0-2) [5](#0-4) 

The protocol's own harness demonstrates this state at scale: with a one-billion-token 18-decimal market at 98% utilization on a steep rate curve, accrual eventually fails with `MathOverflow` before `borrow_index` reaches `MAX_BORROW_INDEX_RAY`; subsequent withdrawal and repayment attempts fail with the same error. [6](#0-5) 

### Impact Explanation
This is a permanent freezing of all funds associated with the affected market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, and maintenance calls cannot advance `last_timestamp`, because each path re-enters the same overflowing accrual before performing its operation. [7](#0-6) [8](#0-7) 

The state is not recoverable by waiting. `borrow_index` remains below its cap, so later calls calculate a nonzero interest factor and again attempt to unscale the oversized market total. No separate emergency path bypasses `global_sync` for repayment or withdrawal. [9](#0-8) 

### Likelihood Explanation
Triggering the condition requires a very large market and sustained high-utilization interest accrual. The demonstrated configuration uses one billion 18-decimal tokens and 98% utilization on the XLM stress curve. Those magnitudes are possible within the protocol's admitted cap domain, but the practical liquidity and elapsed-time requirements reduce the likelihood. The trigger itself is permissionless once the market state exists. [10](#0-9) [11](#0-10) 

### Recommendation
Make aggregate unscale operations saturation-aware or avoid materializing aggregate RAY values whose product can exceed `i128`:

- Use a saturating `scaled_to_original` variant for aggregate utilization/reward calculations.
- Prefer clamping the effective index before unscale multiplication when the result would exceed `i128::MAX`.
- Detect the aggregate-value ceiling separately from `MAX_BORROW_INDEX_RAY` and enter a defined terminal/no-accrual mode rather than reverting.
- Keep repayments, withdrawals, liquidation, and bad-debt cleanup executable when the terminal condition is reached.
- Add a regression test equivalent to `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` that proves exits remain callable after the ceiling is reached.

### Proof of Concept
The existing deterministic harness provides the proof:

```rust
// tests/test-harness/tests/controller/large_positions_and_long_horizons.rs
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.borrow_raw(ALICE, "BIG18", debt);

loop {
    t.advance_time(YEAR_SECS);
    if t.try_update_indexes_for(&["BIG18"]).is_err() {
        break;
    }
}
```

At the failing call, `update_indexes` returns `MathOverflow`, while `book.borrow_index` remains below `MAX_BORROW_INDEX_RAY`. A one-unit withdrawal by the supplier and a one-unit repayment by the borrower both return `MathOverflow`, confirming that ordinary recovery paths are blocked by the same accrual. [12](#0-11)

### Citations

**File:** common/src/rates/simulate.rs (L60-71)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);

    let new_supply_index = update_supply_index(env, supplied, supply_index, supplier_rewards);
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** contracts/pool/src/interest.rs (L20-32)
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

**File:** contracts/controller/src/markets.rs (L119-125)
```rust
pub(crate) fn update_indexes(env: &Env, caller: Address, assets: Vec<HubAssetKey>) {
    validation::require_authorized_caller(env, &caller);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    pool_update_indexes_call(env, &pool_addr, &assets);
}
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-356)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
#[test]
fn a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap() {
    let mut t = LendingTest::new()
        .with_market(big("BIG18", 18, xlm_curve()))
        .with_market(col())
        .with_max_utilization_disabled_all_markets()
        .build();
    lift_caps(&t, "BIG18", 18);
    lift_caps(&t, "COL", 7);
    let principal = BILLION * 10i128.pow(18);
    t.supply_raw(BOB, "BIG18", principal);
    let debt = principal / 100 * 98;
    t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
    t.borrow_raw(ALICE, "BIG18", debt);

    let mut years = 0u32;
    let failure = loop {
        years += 1;
        assert!(
            years <= 40,
            "no cliff within 40 years; the bound in docs/reference/formulas.md is wrong"
        );
        t.advance_time(YEAR_SECS);
        if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
            break e;
        }
    };
    let failed: Result<(), soroban_sdk::Error> = Err(failure);
    assert_contract_error(failed, errors::MATH_OVERFLOW);
    let last = book(&t, "BIG18");
    assert!(
        last.borrow_index < MAX_BORROW_INDEX_RAY,
        "the index cap did not engage before the value overflow"
    );
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

**File:** docs/reference/formulas.md (L429-437)
```markdown
| Token-to-RAY input maximum `i128::MAX / 10^(27-d)` | About 170.14 billion whole tokens, before other limits |
| Deposit conversion at the supply-index floor | About 170.14 million whole tokens before scaled-share overflow |

The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```
