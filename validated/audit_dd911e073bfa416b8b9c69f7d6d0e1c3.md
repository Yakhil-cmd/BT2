### Title
RAY-value overflow during accrual permanently freezes a saturated market - (File: common/src/rates/simulate.rs)

### Summary
A market whose scaled borrow balance exceeds `i128::MAX` after index growth causes every state-changing pool path to revert in `accrue_step`. Because `borrowed * borrow_index` is evaluated before the borrow-index cap can clamp growth, an oversized high-utilization market can cross the representable RAY-value ceiling first. The resulting `MathOverflow` blocks index updates, withdrawals, repayments, liquidations, and any other operation that synchronizes the market.

### Finding Description
`accrue_step` derives utilization from `scaled_to_original(borrowed, borrow_index)` and `scaled_to_original(supplied, supply_index)`. [1](#0-0)  `scaled_to_original` is a checked RAY multiplication and returns `MathOverflow` when `scaled * index / RAY` does not fit `i128`. [2](#0-1) [3](#0-2) 

All market operations load a synchronized cache: `synced_market` invokes `interest::global_sync` before the requested operation. [4](#0-3)  `global_sync` repeatedly invokes `accrue_step` for elapsed time chunks and commits only after all chunks complete. [5](#0-4) [6](#0-5) 

The separate borrow-index ceiling does not prevent this failure. `update_borrow_index` clamps only after multiplying the old index by the interest factor, but `accrue_step` has already multiplied the outstanding scaled debt by the old index for utilization, and later multiplies it by the new index for rewards. [7](#0-6) [8](#0-7) 

The strongest unprivileged route is the controller’s public `update_indexes` path for the affected `HubAssetKey`. Internally, the pool accrues each requested market through `Cache::load` followed by `interest::global_sync`. [9](#0-8)  Since the overflow occurs during this synchronization phase, the caller does not need authorization, storage manipulation, oracle control, or malformed calldata.

### Impact Explanation
Once `borrowed * borrow_index / RAY` exceeds `i128::MAX`, every entrypoint that synchronizes the market reverts before performing its requested action. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, revenue cannot be claimed, recapitalization cannot repair the market, and `update_indexes` cannot advance state. The condition is persistent because the stored scaled debt and index remain unchanged and time cannot be moved backward.

This satisfies permanent freezing of user funds and can leave the market unable to operate. The production regression test demonstrates this exact cliff: after sustained high utilization, `update_indexes` returns `MATH_OVERFLOW`, and both withdrawal and repayment fail with the same error before the borrow-index cap is reached. [10](#0-9) 

### Likelihood Explanation
Likelihood is constrained by capital and market configuration rather than authorization. An attacker must create an extremely large borrow book—on the order of the protocol’s documented RAY-domain limit—and sustain high utilization until index growth makes the aggregate debt value unrepresentable. The relevant bound depends on token decimals, the configured cap, utilization, and the interest-rate curve. [11](#0-10) 

No privileged action is required after the oversized position exists. Merely waiting for sufficient accrual and calling `update_indexes` for the affected `hub_id` and `asset` triggers the overflow. Because the transaction reverts atomically before updating `last_timestamp`, repeated calls continue to fail.

### Recommendation
Do not derive utilization or accrued interest through an `i128` RAY value that can overflow before index capping. At minimum:

- bound scaled supply and debt so their worst-case indexed values remain representable;
- compute utilization through bounded ratio arithmetic rather than materializing both indexed values;
- clamp or chunk accrual before calculating `borrowed * new_borrow_index`;
- make recovery paths such as repayment, liquidation, or recapitalization capable of processing a bounded accrual step without reverting;
- enforce caps dynamically against projected index growth rather than only against admission-time token-unit domains.

### Proof of Concept
Conceptually:

1. Through the controller, supply an asset with 18 decimals and a cap admitting approximately `1_000_000_000 * 10^18` base units.
2. Supply separate collateral and borrow approximately 98% of that market, producing a very large scaled `borrowed` balance.
3. Leave the market at high utilization under a steep but valid rate curve for enough ledger time that `borrowed * borrow_index / RAY > i128::MAX`.
4. Call the controller’s public `update_indexes` with `hub_assets = [HubAssetKey { hub_id, asset }]`.
5. The call reaches pool `accrue`, then `global_sync`, then `accrue_step`, where `scaled_to_original` raises `MathOverflow`. [9](#0-8) [12](#0-11) 
6. Subsequent `withdraw`, `repay`, `liquidate`, `recapitalize`, or `claim_revenue` calls revert during the same synchronization step before any recovery logic executes.

The existing live-flow regression reproduces this sequence with a one-billion-token market at 98% utilization and shows `update_indexes`, `withdraw`, and `repay` all failing with `MATH_OVERFLOW` while `borrow_index` remains below `MAX_BORROW_INDEX_RAY`. [13](#0-12)

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

**File:** common/src/math/fp.rs (L50-52)
```rust
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** contracts/pool/src/ops/mod.rs (L29-40)
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

**File:** contracts/pool/src/interest.rs (L39-53)
```rust
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
}
```

**File:** common/src/rates/index.rs (L13-19)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
}
```

**File:** common/src/rates/index.rs (L80-86)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);
```

**File:** contracts/pool/src/ops/market.rs (L65-72)
```rust
pub(crate) fn accrue(env: &Env, hub_assets: Vec<HubAssetKey>) {
    renew_instance(env);

    for hub_asset in hub_assets.iter() {
        let mut cache = Cache::load(env, &hub_asset);
        interest::global_sync(env, &mut cache);
        events::emit_market_state(env, cache.commit());
    }
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-356)
```rust
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

**File:** docs/reference/formulas.md (L425-437)
```markdown
| Asset decimals 0..=18 | Exact token-to-RAY upscaling. Below 3: collateral only, no flash loans, no liquidation fee, its account's only supply position, at least 2 whole units while in debt |
| Both indexes initially RAY; ceiling 10^36 | 10^9 times initial index; protocol constants |
| Supply-index floor 10^24 | At most 1,000 times the shares minted at index one for the same deposit |
| Borrow APR maximum 2 RAY | 200% annual rate; not a bound on balance growth alone |
| Token-to-RAY input maximum `i128::MAX / 10^(27-d)` | About 170.14 billion whole tokens, before other limits |
| Deposit conversion at the supply-index floor | About 170.14 million whole tokens before scaled-share overflow |

The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```
