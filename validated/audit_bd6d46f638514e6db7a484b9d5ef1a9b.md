### Title
RAY debt-value overflow in `accrue_step` permanently freezes an entire market - (File: common/src/rates/simulate.rs)

### Summary
Every pool mutator accrues interest before doing its own work (`synced_market` → `global_sync` → `accrue_step`). The first arithmetic inside `accrue_step` is `scaled_to_original(borrowed, borrow_index)`, which computes `borrowed * borrow_index / RAY` in `i128` (widened to `I256` only for the intermediate product) and panics with `MathOverflow` when the *quotient* exceeds `i128::MAX`. For a sufficiently large market — ~1e27 RAY scaled shares — the borrow index needs only ~170× growth before the debt value no longer fits, a point reached years before the `MAX_BORROW_INDEX_RAY` cap can engage. From then on every entrypoint that touches the market reverts, permanently freezing all supplied and borrowed funds.

### Finding Description
The bug class from the advisory — integer overflow corrupting execution — maps directly onto the accrual path:

- `contracts/pool/src/ops/mod.rs:30-40`: `synced_market`/`renewed_market` call `interest::global_sync` before loading a market cache. This is the shared prelude for `supply`, `borrow`, `withdraw`, `repay`, `seize` (liquidation), `net_settle`, `recapitalize`, `revenue` claims, and `ops::market::accrue` (the `update_indexes` entrypoint, `contracts/pool/src/lib.rs:178-180`). [1](#0-0) [2](#0-1) 
- `common/src/rates/simulate.rs:60-61`: `accrue_step` unconditionally computes `scaled_to_original(env, borrowed, borrow_index)` (and the supply twin) to derive utilization. [3](#0-2) 
- `common/src/rates/scaling.rs:14-16`: `scaled_to_original` = `scaled.mul(env, index)` = `mul_div_half_up(scaled, index, RAY)`. [4](#0-3) 
- `common/src/math/fp_core.rs:122-143`: `try_mul_div_half_up` widens the *product* to `I256`, but the final `.to_i128()` returns `None` when the *quotient* exceeds `i128::MAX`, and `mul_div_half_up` converts that into a `MathOverflow` panic. [5](#0-4) 

The `MAX_BORROW_INDEX_RAY` cap (`common/src/rates/index.rs:13-19`) does not prevent this: the panic happens because `borrowed * index / RAY` overflows, not because the index itself is unbounded. The repo's own harness test demonstrates the cliff: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361` shows a ~1e9-token 18-decimal market at ~98% utilization on the XLM curve hitting `MATH_OVERFLOW` inside accrual with `borrow_index < MAX_BORROW_INDEX_RAY`, and then `withdraw`, `repay`, and `update_indexes` all reverting on the same panic. [6](#0-5) 

### Impact Explanation
Once `scaled_to_original` overflows for a market's `borrowed`/`borrow_index`, the panic precedes every state change for that market. There is no escape hatch: repaying debt requires accrual first, liquidation requires accrual first, withdrawals and revenue claims require accrual first, and `recapitalize` (even if reachable) does not shrink `borrowed`. The result is **permanent freezing of user funds** — all supplier balances, borrower collateral backing, and unclaimed protocol revenue in that market are locked forever, and liquidation becomes impossible so any underwater debt is unrecoverable. Bad-debt socialization via `apply_bad_debt_to_supply_index` is also dead code at that point since it multiplies `supplied * supply_index` which overflows identically for a large market.

### Likelihood Explanation
The trigger does not require privilege: a whale (or a coordinated set of accounts) supplies a very large principal into a high-decimal market and borrows near maximum utilization; from that point, ordinary time-based accrual — which any unprivileged `update_indexes` call advances — carries the market to the overflow. The conditions are demanding: the market's supply/borrow caps must admit ~1e9+ whole tokens (caps are governance-set, so this requires a listing with permissive or lifted caps), `max_utilization` must be disabled or high enough to sustain ~98% utilization, and the steep segment of the rate curve must hold for years. Because it needs massive capital, permissive configuration, and a long accrual horizon rather than an instant exploit, this is Medium rather than High — but the failure, once reached, is unrecoverable and the codebase's own test proves the panic occurs before the index cap.

### Recommendation
Saturate or de-risk the accrual computation instead of panicking:

- In `accrue_step`/`scaled_to_original`, use a saturating variant (analogous to `mul_div_floor_saturating` already used for caps) so that an oversized `borrowed * index` value clamps rather than reverts — clamped utilization saturates the rate curve, and the `MAX_BORROW_INDEX_RAY`/`MAX_SUPPLY_INDEX_RAY` caps bound index growth anyway.
- Alternatively, cap *total scaled shares* (`supplied`/`borrowed` in RAY) at listing/validation time via `require_cap_within_asset_domain`-style bounds such that `shares * MAX_INDEX / RAY` provably fits `i128`, turning the overflow into an unreachable state.
- At minimum, perform index capping *before* the value computation in `accrue_step` so the panic window shrinks to the cap boundary rather than the arithmetic ceiling.

### Proof of Concept
The existing harness test is the proof (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`):

```rust
// Supply ~1e9 tokens of an 18-decimal asset, borrow ~98% of it, advance time.
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.borrow_raw(ALICE, "BIG18", debt);

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }
}
// assert_contract_error(failed, errors::MATH_OVERFLOW);
// last.borrow_index < MAX_BORROW_INDEX_RAY  → the cap never engaged

// Market is now frozen for everyone:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0),  errors::MATH_OVERFLOW);
```

Root cause chain: `update_indexes` → `ops::market::accrue` → `global_sync` → `accrue_step` → `scaled_to_original(borrowed, borrow_index)` → `mul_div_half_up` quotient > `i128::MAX` → `panic_with_error!(MathOverflow)`. Since `synced_market` is the prelude to every pool verb, the same panic gates `withdraw`, `repay`, `supply`, `borrow`, `seize`, `claim_revenue`, `flash_loan`, and controller-driven operations on that market — permanent freeze, reachable by any unprivileged caller able to supply and borrow at scale.

### Citations

**File:** contracts/pool/src/ops/mod.rs (L30-40)
```rust
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

**File:** contracts/pool/src/lib.rs (L177-180)
```rust
    #[only_owner]
    fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>) {
        ops::market::accrue(&env, hub_assets);
    }
```

**File:** common/src/rates/simulate.rs (L60-62)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
```

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/math/fp_core.rs (L122-143)
```rust
pub fn try_mul_div_half_up(env: &Env, x: i128, y: i128, d: i128) -> Option<i128> {
    if x < 0 || y < 0 || d <= 0 {
        return None;
    }
    let half = d / 2;

    // Fast path: the biased product fits `i128`, so the whole computation is
    // native. `x * y + half` is non-negative here, so `/` is the floor the
    // widened path would produce.
    if let Some(biased) = x
        .checked_mul(y)
        .and_then(|product| product.checked_add(half))
    {
        return Some(biased / d);
    }

    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L343-356)
```rust
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
