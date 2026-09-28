### Title
Interest accrual overflows total debt valuation and permanently freezes a market - (File: common/src/rates/simulate.rs)

### Summary
A market with sufficiently large scaled debt can reach a borrow index at which `borrowed * borrow_index / RAY` no longer fits in `i128`. `accrue_step` evaluates that product before applying or reaching the borrow-index ceiling, so accrual panics with `MathOverflow`. Because every pool mutation synchronizes interest before acting, subsequent `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `flash_loan`, `claim_revenue`, `recapitalize`, and `update_indexes` calls touching that market fail indefinitely.

### Finding Description
`Controller::update_indexes` is callable by any address that authorizes the supplied `caller` and forwards the selected `HubAssetKey`s to the owner-gated pool accrual path. [1](#0-0)  The pool loads each market and invokes `interest::global_sync` before emitting or committing the resulting state. [2](#0-1) 

`global_sync` splits elapsed time into bounded chunks and calls `accrue_step` for each chunk. [3](#0-2)  `accrue_step` first unscales aggregate debt with `scaled_to_original(env, borrowed, borrow_index)`, which is `borrowed.mul(index)`. [4](#0-3)  `Ray::mul` uses `mul_div_half_up`, whose result must fit in `i128` and otherwise panics with `MathOverflow`. [5](#0-4) [6](#0-5) 

The borrow index is capped only after its own multiplication, at `MAX_BORROW_INDEX_RAY = 1e36`. [7](#0-6) [8](#0-7)  That index cap does not bound the separate `borrowed * borrow_index` market-value product evaluated earlier in `accrue_step`. [9](#0-8) 

The freeze is persistent because the panic happens before `cache.mark_accrued()` can advance `last_timestamp`, leaving the same unsafe interval and market state for every later call. [10](#0-9)  All normal mutation legs use `ops::load_leg`, which calls `synced_market`, and `synced_market` always runs `global_sync` before returning the cache. [11](#0-10) 

### Impact Explanation
This causes permanent freezing of all funds and debt accounting in the affected market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot process the debt, and protocol revenue or recapitalization paths that touch the market also fail. The in-repo regression test demonstrates that after the first accrual failure, both withdrawal and repayment still fail with `MathOverflow`. [12](#0-11) 

The affected funds remain in the pool, but the contract cannot reach the transfer logic: `withdraw` calls `ops::load_leg` before burning shares or transferring tokens. [13](#0-12)  Likewise, `repay` calls `ops::load_leg` before it can burn debt or credit cash. [14](#0-13) 

### Likelihood Explanation
An unprivileged attacker can create and fund an account through `supply`, create debt through `borrow`, and later trigger the failing accrual through `update_indexes`. [15](#0-14)  The attack requires a listed market whose caps and collateral permit an exceptionally large borrow at sustained high utilization; it is therefore capital-intensive and dependent on market configuration, but it does not require privileged access, oracle manipulation, malformed input, or control of another account.

The existing test constructs such a state by supplying an 18-decimal market, borrowing 98% of it, advancing accrual, and observing `MathOverflow` while the stored index remains below `MAX_BORROW_INDEX_RAY`. [16](#0-15)  Once that state exists, the attacker or any third party can submit `update_indexes(caller, vec![hub_asset])` to make the panic permanent for that market. [2](#0-1) 

### Recommendation
Make accrual arithmetic survive unrepresentable market totals instead of trapping before state can be committed. In particular:

- Perform debt and supply valuation in `I256`, or provide a saturating `scaled_to_original` variant dedicated to aggregate accrual.
- Clamp utilization and total-debt calculations to the protocol’s representable domain before calculating interest rewards.
- Ensure the borrow-index ceiling is applied even when current debt valuation saturates.
- Advance `last_timestamp` or otherwise commit a bounded post-overflow state so repayment, withdrawal, liquidation, and bad-debt cleanup remain reachable.
- Add a production regression test equivalent to `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`, asserting that accrual saturates rather than freezing the market.

### Proof of Concept
1. On a listed debt market `D` with sufficient caps and an 18-decimal asset, an attacker calls `supply(caller, 0, spoke_id, [(D, very_large_amount)])`.
2. On the same controlled account, the attacker supplies sufficient collateral in another listed asset and calls `borrow(caller, account_id, [(D, approximately_98_percent_of_supply)], None)`.
3. After enough ledger time has elapsed for `borrowed * borrow_index / RAY` to exceed `i128::MAX`, anyone calls `update_indexes(caller, [D])`.
4. `accrue_step` panics in `scaled_to_original` before `borrow_index` reaches or is clamped to `MAX_BORROW_INDEX_RAY`. [9](#0-8) 
5. Since `last_timestamp` is not marked accrued after the panic, every later operation on `D` repeats the same failing accrual. [10](#0-9) 
6. The repository’s regression test already demonstrates the terminal behavior: `try_update_indexes_for(["BIG18"])`, `try_withdraw_raw(BOB, "BIG18", 1)`, and `try_repay(ALICE, "BIG18", 1.0)` all return `MATH_OVERFLOW`, while `borrow_index < MAX_BORROW_INDEX_RAY`. [17](#0-16)

### Citations

**File:** contracts/controller/README.md (L104-107)
```markdown
| --- | --- | --- | --- |
| `update_indexes` | `fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>)` | blocked by global pause | Accrues the borrow and supply indexes for each hub asset in `assets` on the pool. |
| `claim_revenue` | `fn claim_revenue(env: Env, caller: Address, assets: Vec<HubAssetKey>) -> Vec<i128>` | blocked by global pause | Claims accrued protocol revenue for each hub asset in `assets` from the pool and forwards it to the configured accumulator, returning the amount claimed per asset. |
| `recapitalize` | `fn recapitalize(env: Env, payer: Address, hub_asset: HubAssetKey, amount: i128) -> i128` | — | Transfers `amount` of `hub_asset` from `payer` into the pool to cover a backing shortfall, applying only up to the shortfall and refunding any excess; returns the amount actually applied. |
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

**File:** common/src/rates/simulate.rs (L51-67)
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

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

```

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** common/src/math/fp_core.rs (L104-118)
```rust
/// Computes `x * y / d` rounded half up. Requires `x >= 0`, `y >= 0`, and `d > 0`; a
/// `debug_assert` checks this in debug builds. Panics with `GenericError::DivisionByZero` if
/// `d == 0`, and with `GenericError::MathOverflow` if any other precondition is violated or if
/// the result does not fit in `i128`.
pub fn mul_div_half_up(env: &Env, x: i128, y: i128, d: i128) -> i128 {
    // The zero check runs first so debug and release builds agree on a zero
    // divisor: both surface `DivisionByZero` rather than tripping the assert.
    require_nonzero_divisor(env, d);
    debug_assert!(
        x >= 0 && y >= 0 && d > 0,
        "mul_div_half_up: non-negative x, y and positive d"
    );
    try_mul_div_half_up(env, x, y, d)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
}
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

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
```

**File:** contracts/pool/src/ops/mod.rs (L29-47)
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
}
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

**File:** contracts/pool/src/ops/withdraw.rs (L57-80)
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
    let net_transfer = withhold_liquidation_fee(
        env,
        &mut cache,
        gross_amount,
        is_liquidation,
        entry.protocol_fee,
    );

    // A footprint-only close must not add a utilization gate to same-market
    // net settlement: it burns no shares and moves no cash.
    let empty_close = position.raw() == 0 && entry.action.amount == i128::MAX;
    gate_and_debit(env, &mut cache, net_transfer, is_liquidation || empty_close);

```

**File:** contracts/pool/src/ops/repay.rs (L36-57)
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
        .checked_sub(overpayment)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
    assert_with_error!(
        env,
        net_repay == 0 || burned.raw() > 0,
        GenericError::RepayRoundsToZeroShares
    );

    let position = position.checked_sub(env, burned);
    cache.burn_debt(burned);

    cache.credit_cash(net_repay);
```

**File:** contracts/controller/src/lib.rs (L90-115)
```rust
    /// Supplies `assets` as collateral and returns the account id; `account_id = 0`
    /// creates an account in `spoke_id`. Third parties may only top up existing
    /// supply positions; owners and delegates may add assets.
    #[when_not_paused]
    fn supply(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        assets: Vec<(HubAssetKey, i128)>,
    ) -> u64 {
        positions::process_supply(&env, &caller, account_id, spoke_id, &assets)
    }

    /// Borrows against `account_id`'s collateral, paying `to` or the caller.
    /// Requires owner or delegate authorization and post-borrow solvency.
    #[when_not_paused]
    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) {
        positions::process_borrow(&env, &caller, account_id, &borrows, to);
    }
```
