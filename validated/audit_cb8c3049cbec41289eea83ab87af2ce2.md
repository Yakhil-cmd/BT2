### Title
Accrual-time RAY-value overflow permanently freezes a large market - (File: `common/src/rates/simulate.rs`)

### Summary
A market whose scaled supply or debt value can grow past `i128::MAX` cannot accrue safely. The first `scaled_to_original` multiplication panics before the configured index ceiling can stop growth, and because every state-changing pool path accrues first, subsequent `withdraw`, `repay`, `liquidate`, `update_indexes`, `recapitalize`, and related operations revert with `MathOverflow`.

### Finding Description
`Controller::update_indexes(caller, assets)` is permissionless apart from caller authorization and forwards the supplied `HubAssetKey` list to the pool. [1](#0-0)  The controller forwards that list to `pool.update_indexes`. [2](#0-1) 

For each market, `ops::market::accrue` calls `interest::global_sync`. [3](#0-2)  The same `global_sync` runs before ordinary market mutations through `synced_market`. [4](#0-3) 

`accrue_step` converts total scaled debt and total scaled supply back to RAY values using `scaled_to_original`. [5](#0-4)  `scaled_to_original` is a direct `scaled.mul(index)` operation. [6](#0-5)  Once `scaled * index` exceeds `i128::MAX`, accrual panics before `update_borrow_index` can clamp the new index to `MAX_BORROW_INDEX_RAY`. [7](#0-6) 

The repository contains a regression test demonstrating the exact condition: a one-billion-token, 18-decimal market borrowed to 98% utilization eventually makes permissionless `update_indexes` return `MathOverflow`, after which both withdrawal and repayment also return `MathOverflow`. [8](#0-7) 

### Impact Explanation
This permanently freezes the affected `(hub_id, asset)` market. Suppliers cannot withdraw, borrowers cannot reduce or close debt, liquidators cannot service the account, and maintenance operations cannot advance the market because accrual is executed before the requested mutation. The pool can retain real token balances while all account paths that depend on the market remain unusable.

The impact is market-wide rather than limited to the attacker’s position. Any unrelated supplier’s claim on that market is inaccessible after the overflow threshold is crossed.

### Likelihood Explanation
The attack path is unprivileged but requires an exceptionally large market and sustained high utilization. An attacker or whale can supply the target asset, supply sufficient collateral elsewhere, and borrow the target asset to keep utilization high. Thereafter, any address can trigger the failing accrual through `update_indexes`; ordinary users will also trigger it automatically through repayments, withdrawals, and liquidations.

Market caps, utilization limits, available token supply, collateral requirements, and market age constrain feasibility. The demonstrated test needed caps raised and max-utilization checks disabled, so the finding is conditional on a listed market being allowed to approach the protocol’s RAY-value domain. When those limits permit the state, however, no privileged action is needed to create or trigger the freeze.

### Recommendation
Do not let accrual depend on a checked multiplication of the total scaled balance by an index that can grow independently of the `i128` value domain.

Appropriate fixes include:

- cap or saturate total scaled balances based on the maximum representable value under the current index;
- before applying index growth, bound `new_borrow_index` so `borrowed * new_borrow_index` and `supplied * new_supply_index` cannot overflow;
- evaluate accrual using widened or saturating arithmetic before converting to `Ray`;
- enforce market caps against the projected index ceiling rather than only the current index;
- add an emergency path that can reduce `borrowed`/`supplied` or socialize the market without first running ordinary accrual.

Add a regression test equivalent to `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` that verifies at least repayment and withdrawal remain executable at the numeric boundary.

### Proof of Concept
The repository test already demonstrates the sequence:

```rust
// tests/test-harness/tests/controller/large_positions_and_long_horizons.rs
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

loop {
    t.advance_time(YEAR_SECS);
    if t.try_update_indexes_for(&["BIG18"]).is_err() {
        break;
    }
}

// Both revert with MathOverflow.
t.try_withdraw_raw(BOB, "BIG18", 1);
t.try_repay(ALICE, "BIG18", 1.0);
```

The committed borrow index remains below `MAX_BORROW_INDEX_RAY`, proving that the index ceiling does not prevent the earlier total-value multiplication from overflowing. [9](#0-8)

### Citations

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }
```

**File:** contracts/controller/src/markets.rs (L118-125)
```rust
/// Accrues indexes for each hub asset. Requires caller authorization and no flash loan.
pub(crate) fn update_indexes(env: &Env, caller: Address, assets: Vec<HubAssetKey>) {
    validation::require_authorized_caller(env, &caller);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    pool_update_indexes_call(env, &pool_addr, &assets);
}
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

**File:** contracts/pool/src/ops/mod.rs (L29-34)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
}
```

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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L321-356)
```rust
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
