### Title
RAY-denominated market value overflow permanently freezes an oversized high-utilization market - ([File: common/src/rates/index.rs](common/src/rates/index.rs))

### Summary

A market can become permanently unusable when the RAY value of its scaled debt or supply exceeds `i128::MAX`, even though both indexes remain below their configured ceilings. Every pool operation synchronizes interest before mutating state, so once this arithmetic boundary is crossed, `repay`, `withdraw`, `liquidate`, `clean_bad_debt`, `recapitalize`, and even `update_indexes` revert before any recovery logic can run. The repository contains a regression test demonstrating this cliff with a one-billion-token, 18-decimal market at 98% utilization. [1](#0-0) 

### Finding Description

The pool stores market totals as scaled RAY shares and obtains their current values by multiplying them by the relevant index. `global_sync` executes before each market leg through `ops::synced_market` or `ops::load_leg`. [2](#0-1) 

During each accrual chunk, `accrue_step` updates the borrow and supply indexes. [3](#0-2)  `calculate_supplier_rewards` separately computes `borrowed * old_borrow_index` and `borrowed * new_borrow_index`, while `update_supply_index` computes `supplied * old_index`. [4](#0-3) [5](#0-4) 

The borrow-index cap only applies after `old_index * interest_factor` has already been calculated; it does not constrain the resulting `borrowed * index` market value. [6](#0-5)  Consequently, a large enough scaled balance can overflow during value reconstruction while `borrow_index` is still below `MAX_BORROW_INDEX_RAY`.

An unprivileged whale can reach this state through ordinary controller calls:

1. Supply approximately `1_000_000_000 * 10^18` base units of an 18-decimal asset.
2. Supply sufficient collateral in another market.
3. Borrow approximately 98% of the first market’s cash.
4. Leave utilization high while interest accrues, or advance the market through repeated activity.
5. Call controller `update_indexes` for that `HubAssetKey`, or simply wait until any user attempts a market operation.

The regression test constructs exactly this shape and observes `MathOverflow` from `try_update_indexes`; it then confirms that withdrawal and repayment revert with the same error while the stored index remains below its cap. [7](#0-6) 

### Impact Explanation

This is a permanent freezing-of-funds condition for the affected market. Once the scaled-balance/index product exceeds `i128::MAX`, every path that loads the market through `synced_market` executes accrual first and panics before reaching the operation-specific logic. [2](#0-1) 

Suppliers cannot withdraw because `withdraw::accounting` begins by loading an interest-synced market leg. [8](#0-7)  Borrowers cannot repay because `repay::accounting` follows the same `load_leg` path. [9](#0-8)  Liquidation and bad-debt cleanup are likewise blocked because their pool legs require the same synchronized market state.

The result is worse than a temporary pause: the overflowing product is part of the next accrual calculation, so reducing a position cannot occur without first executing the failing accrual. The documentation acknowledges that value overflow can occur before the index ceiling and can block repayment and withdrawal. [10](#0-9) 

### Likelihood Explanation

Likelihood is limited by the capital and time required. The demonstrated scenario needs roughly one billion whole units of an 18-decimal asset, substantial collateral, and sustained approximately 98% utilization under a steep rate curve. [11](#0-10) 

Nevertheless, the required market size is below the documented asset-domain admission bound of roughly 170.14 billion whole tokens, so ordinary cap validation does not exclude it. [12](#0-11)  A single sufficiently funded attacker can create the market state without privileged access, oracle manipulation, leaked keys, or malformed parameters.

Because exploitation depends on an unusually large listed asset and prolonged high utilization rather than an immediately repeatable transaction, this is best classified as Medium severity despite the permanent-freeze impact.

### Recommendation

Do not compute accrued interest by reconstructing full RAY-denominated market values when the scaled totals can overflow. Instead:

- Bound `(scaled_total, index)` products before accrual, not only the indexes themselves.
- Derive accrued debt using widened `I256` arithmetic or a quotient/remainder formulation that does not require `borrowed * index` to fit in `i128`.
- Add a market-value ceiling or effective TVL ceiling that guarantees all total-value reconstructions remain representable.
- If a bound is intentionally imposed, fail new supply/borrow before the bound is reached and leave an emergency debt-reduction path that does not first execute the overflowing accrual calculation.
- Add assertions that `MAX_BORROW_INDEX_RAY`, `MAX_SUPPLY_INDEX_RAY`, admitted caps, and maximum decimals are jointly safe for `scaled_to_original`, `calculate_supplier_rewards`, and `update_supply_index`.

The existing test should be converted from an accepted cliff demonstration into an invariant test asserting that admitted market configurations cannot reach the overflow state.

### Proof of Concept

The repository already contains an executable proof at `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`:

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
        break;
    }
}

assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

The test asserts that `MathOverflow` is returned before `borrow_index` reaches `MAX_BORROW_INDEX_RAY`, then confirms that both withdrawal and repayment remain impossible. [13](#0-12)

### Citations

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

**File:** contracts/pool/src/ops/mod.rs (L29-46)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
}

/// Renews instance TTL, then loads and accrues the market.
pub(crate) fn renewed_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    renew_instance(env);
    synced_market(env, hub_asset)
}

/// Validates `action.amount ≥ 0`, syncs the market, and returns (cache, scaled position).
pub(crate) fn load_leg(env: &Env, action: &PoolAction) -> (Cache, Ray) {
    require_nonneg_amount(env, action.amount);
    let cache = synced_market(env, &action.hub_asset);
    (cache, Ray::from(action.position.scaled_amount))
```

**File:** contracts/pool/src/interest.rs (L20-52)
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

/// Applies one compound step of `delta_ms` to indexes and protocol revenue.
///
/// The arithmetic lives in [`accrue_step`], shared with the read-only
/// `simulate_update_indexes` so the view and the mutator cannot drift.
fn accrue_chunk(env: &Env, cache: &mut Cache, delta_ms: u64) {
    let step = accrue_step(
        env,
        cache.params(),
        cache.borrowed(),
        cache.supplied(),
        cache.borrow_index(),
        cache.supply_index(),
        delta_ms,
    );

    cache.set_borrow_index(step.borrow_index);
    cache.set_supply_index(step.supply_index);
    cache.accrue_revenue(step.revenue_shares);
```

**File:** common/src/rates/index.rs (L11-19)
```rust
/// Applies `interest_factor` to `old_index` to produce the new borrow index,
/// capped at `MAX_BORROW_INDEX_RAY`.
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
}
```

**File:** common/src/rates/index.rs (L29-44)
```rust
pub fn update_supply_index(env: &Env, supplied: Ray, old_index: Ray, rewards_increase: Ray) -> Ray {
    if supplied == Ray::ZERO || rewards_increase == Ray::ZERO {
        return old_index;
    }

    let total_supplied_value = supplied.mul(env, old_index);

    if total_supplied_value == Ray::ZERO {
        return old_index;
    }

    let new_value = total_supplied_value.checked_add(env, rewards_increase);
    let grown = fp_core::mul_div_floor_saturating(env, new_value.raw(), RAY, supplied.raw());

    let bounded_old = old_index.raw().min(MAX_SUPPLY_INDEX_RAY);
    Ray::from(grown.min(MAX_SUPPLY_INDEX_RAY).max(bounded_old))
```

**File:** common/src/rates/index.rs (L73-88)
```rust
pub fn calculate_supplier_rewards(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    new_borrow_index: Ray,
    old_borrow_index: Ray,
) -> (Ray, Ray) {
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);

    (supplier_rewards, protocol_fee)
```

**File:** contracts/pool/src/ops/withdraw.rs (L57-65)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
```

**File:** contracts/pool/src/ops/repay.rs (L36-45)
```rust
/// Accrues interest, resolves the repay amount into burned debt shares and
/// overpayment, burns the shares, and credits the net repay to cash without
/// transferring the overpayment refund. Panics if a positive net repay would
/// burn zero scaled shares.
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
```

**File:** docs/reference/formulas.md (L423-430)
```markdown
| Bound | Consequence |
|---|---|
| Asset decimals 0..=18 | Exact token-to-RAY upscaling. Below 3: collateral only, no flash loans, no liquidation fee, its account's only supply position, at least 2 whole units while in debt |
| Both indexes initially RAY; ceiling 10^36 | 10^9 times initial index; protocol constants |
| Supply-index floor 10^24 | At most 1,000 times the shares minted at index one for the same deposit |
| Borrow APR maximum 2 RAY | 200% annual rate; not a bound on balance growth alone |
| Token-to-RAY input maximum `i128::MAX / 10^(27-d)` | About 170.14 billion whole tokens, before other limits |
| Deposit conversion at the supply-index floor | About 170.14 million whole tokens before scaled-share overflow |
```

**File:** docs/reference/formulas.md (L432-437)
```markdown
The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```
