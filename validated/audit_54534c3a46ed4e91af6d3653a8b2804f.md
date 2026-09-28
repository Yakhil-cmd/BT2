### Title
Permissionless index-accrual overflow permanently freezes a market before the borrow-index cap engages - (File: contracts/pool/src/interest.rs)

### Summary
A single user can drive a listed high-decimal, steep-curve market to sustained high utilization, then call the permissionless `Controller::update_indexes`; `Pool::update_indexes` routes to `ops::market::accrue`, which loads a `Cache` and runs `interest::global_sync` before any later operation can proceed. [1](#0-0) [2](#0-1) [3](#0-2) 
Once `borrowed * borrow_index` exceeds the `i128` value domain inside `scaled_to_original`, accrual panics with `MathOverflow`, while the stored `borrow_index` remains below `MAX_BORROW_INDEX_RAY`, so the intended index cap never engages. [4](#0-3) 
The repository’s own regression test proves the same panic then blocks `withdraw` and `repay`, matching the bug class of a crafted/forced state transition hitting an assertion-like arithmetic failure. [5](#0-4) 

### Finding Description
`Controller::update_indexes(caller, assets)` is explicitly permissionless and only requires caller authorization, and `Controller` forwards those `HubAssetKey`s to `LiquidityPoolClient::update_indexes`. [1](#0-0) [6](#0-5) 
Pool `update_indexes` is owner-only for normal callers but the controller is the pool owner, so the public controller path reaches `ops::market::accrue`, where every listed market gets `Cache::load` followed by `interest::global_sync` and `commit`. [7](#0-6) [2](#0-1) 
`global_sync` loops over elapsed milliseconds in `MAX_COMPOUND_DELTA_MS` chunks and calls `accrue_chunk`, which calls shared `accrue_step` and then commits the new indexes and revenue shares. [8](#0-7) 
The vulnerable ordering is that value conversion happens through `scaled_to_original` in utilization/index accounting before the `MAX_BORROW_INDEX_RAY` ceiling can protect the next accrual; the harness test states the cliff is `1e36` raw ray scaled by a >170x index reaching the `i128` ceiling, while `borrow_index < MAX_BORROW_INDEX_RAY`. [9](#0-8) [4](#0-3) 
Because user-facing verbs call owner-only pool mutations that load/sync the same market cache first, the first `MathOverflow` becomes a persistent market freeze rather than a bounded rejected call. [10](#0-9) [11](#0-10) [5](#0-4) 

### Impact Explanation
The accepted impact is permanent freezing of funds for that `(hub, token)` market: suppliers cannot withdraw, borrowers cannot repay, liquidators cannot de-risk the debt leg, and `clean_bad_debt`/exit paths that touch the same market hit the same accrual panic before settlement. [12](#0-11) [13](#0-12) [5](#0-4) 
This is worse than fail-closed oracle DoS because no external feed or keeper is required and the state cannot be skipped by calling a view; the mutating pool entrypoint itself reverts in accrual before commit. [2](#0-1) [14](#0-13) 

### Likelihood Explanation
Likelihood is medium rather than high because the attacker needs an already listed market with decimals/rate curve/caps that permit very large scaled exposure, enough collateral elsewhere to keep HF valid while building ~98% utilization, and enough elapsed ledger time at sustained utilization for the index to compound past the value ceiling. [15](#0-14) [1](#0-0) [16](#0-15) 
No privileged call, leaked key, upgrade, oracle dishonesty, token semantic, or route quality is required at trigger time: the attacker’s final action is authorized `update_indexes`, and prior `supply`/`borrow` are ordinary owner actions for their own account. [15](#0-14) [1](#0-0) 

### Recommendation
Order the borrow-index cap before any `scaled * index` conversion and make `accrue_step` return a saturated step when the unscaled RAY value would exceed `i128`, rather than letting `scaled_to_original` panic inside `global_sync`. [17](#0-16) [9](#0-8) 
Add a preflight in `global_sync`/`accrue_chunk` that computes each chunk’s post-step value bound using checked math and clamps `borrow_index` to `MAX_BORROW_INDEX_RAY` before `cache.set_borrow_index`, then emits/commit the saturated state instead of reverting. [18](#0-17) [19](#0-18) 
As a defense-in-depth escape, allow minimal `repay`, `withdraw`, liquidation seize and bad-debt cleanup to settle using last committed indexes when accrual would overflow, while still forbidding new supply/borrow on the saturated market. [20](#0-19) [21](#0-20) 
Regression-test the exact cliff with public `update_indexes`, then assert `withdraw` and `repay` still succeed at the cap boundary. [22](#0-21) 

### Proof of Concept
1. Attacker opens a Normal account and supplies a very large amount of an already-listed high-decimal borrowable asset via `Controller::supply(caller, 0, spoke_id, [(debt_hub_asset, principal)])`. [23](#0-22) [24](#0-23) 
2. From the same or a second funded account, the attacker supplies collateral and calls `Controller::borrow` to take utilization near the steep segment, e.g. ~98% of `BIG18` liquidity as in the harness. [25](#0-24) [26](#0-25) 
3. The attacker maintains utilization and lets ledger time advance; each public `Controller::update_indexes(caller, [debt_hub_asset])` compounds in chunks through `Pool::update_indexes -> ops::market::accrue -> global_sync`. [1](#0-0) [7](#0-6) [14](#0-13) 
4. On the chunk where scaled debt times index exceeds the `i128` value domain, `accrue_step`/`scaled_to_original` panics with `GenericError::MathOverflow`; committed `borrow_index` is still below `MAX_BORROW_INDEX_RAY`, so later calls repeat the same panic. [27](#0-26) [28](#0-27) 
5. Confirm permanent freeze by calling `withdraw` for the supplier and `repay` for the borrower; both route to pool `withdraw`/`repay`, which accrue before mutation and revert identically, matching the harness assertion. [29](#0-28) [5](#0-4)

### Citations

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

**File:** contracts/controller/src/lib.rs (L117-165)
```rust
    /// Withdraws collateral to `to` or the caller and returns actual amounts in
    /// asset units. Zero withdraws an asset's full position. Requires owner or
    /// delegate authorization and post-withdrawal solvency.
    fn withdraw(
        env: Env,
        caller: Address,
        account_id: u64,
        withdrawals: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) -> Vec<(HubAssetKey, i128)> {
        positions::process_withdraw(&env, &caller, account_id, &withdrawals, to)
    }

    /// Repays `account_id`'s debt using measured payments from the caller.
    /// Anyone may repay; excess payments are refunded to the caller.
    fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>) {
        positions::process_repay(&env, &caller, account_id, &payments);
    }

    /// Repays debt and seizes collateral at a health-factor-based bonus.
    /// Permissionless, including self-liquidation; requires liquidator authorization.
    /// Residual bad debt is socialized only at or below the collateral dust cap.
    ///
    /// `Transfer` pays pool cash and returns `0`. `Credit(id)` moves net supply
    /// shares to a different, authorized Normal-mode account on the same spoke;
    /// `Credit(0)` creates one. Credit mode needs no free collateral liquidity
    /// and returns the receiving account id.
    fn liquidate(
        env: Env,
        liquidator: Address,
        account_id: u64,
        debt_payments: Vec<(HubAssetKey, i128)>,
        seize_mode: SeizeMode,
    ) -> u64 {
        positions::liquidation::process_liquidation(
            &env,
            &liquidator,
            account_id,
            &debt_payments,
            seize_mode,
        )
    }

    /// Socializes insolvent debt into the supply index and removes the account
    /// when remaining collateral is at or below the dust cap. Permissionless;
    /// requires caller authorization.
    fn clean_bad_debt(env: Env, caller: Address, account_id: u64) {
        positions::liquidation::process_clean_bad_debt(&env, &caller, account_id);
    }
```

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
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

**File:** contracts/pool/src/interest.rs (L20-53)
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

**File:** contracts/controller/src/external/pool.rs (L109-116)
```rust
/// Accrues and persists market indexes through the current ledger time.
pub(crate) fn pool_update_indexes_call(
    env: &Env,
    pool_addr: &Address,
    hub_assets: &Vec<HubAssetKey>,
) {
    LiquidityPoolClient::new(env, pool_addr).update_indexes(hub_assets)
}
```

**File:** contracts/pool/src/lib.rs (L128-180)
```rust
    /// Accrues, mints scaled supply shares and credits cash per entry. The
    /// controller transfers the tokens in before this call. Owner-only.
    #[only_owner]
    fn supply(env: Env, entries: Vec<PoolSupplyEntry>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, ops::supply::apply)
    }

    /// Batch-borrows assets and transfers them to `receiver`: accrues
    /// interest, mints scaled debt, debits cash, and enforces max
    /// utilization after each mint. Restricted to the owner; returns one
    /// [`PoolPositionMutation`] per entry.
    #[only_owner]
    fn borrow(
        env: Env,
        receiver: Address,
        entries: Vec<PoolBorrowEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::borrow::apply(env, &receiver, entry)
        })
    }

    /// Burns supply shares and transfers the underlying to `receiver`.
    /// `is_liquidation` skips the max-utilization check and may withhold a
    /// protocol fee. Owner-only; `actual_amount` is gross of that fee.
    #[only_owner]
    fn withdraw(
        env: Env,
        receiver: Address,
        is_liquidation: bool,
        entries: Vec<PoolWithdrawEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::withdraw::apply(env, &receiver, is_liquidation, entry)
        })
    }

    /// Burns scaled debt up to the repay amount, credits cash with the net
    /// repay and refunds overpayment to `payer`. Owner-only.
    #[only_owner]
    fn repay(env: Env, payer: Address, actions: Vec<PoolAction>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, actions, |env, action| {
            ops::repay::apply(env, &payer, action)
        })
    }

    /// Accrues interest for each market in `hub_assets` through the current
    /// ledger time. Commits state even with no elapsed time to reserve the write
    /// footprint, and emits its market state event. Restricted to the owner.
    #[only_owner]
    fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>) {
        ops::market::accrue(&env, hub_assets);
    }
```

**File:** contracts/pool/src/cache/scale.rs (L19-27)
```rust
    pub(crate) fn calculate_utilization(&self) -> Ray {
        if self.supplied == Ray::ZERO {
            return Ray::ZERO;
        }
        let total_borrowed = scaled_to_original(&self.env, self.borrowed, self.borrow_index);
        let total_supplied = scaled_to_original(&self.env, self.supplied, self.supply_index);

        utilization(&self.env, total_borrowed, total_supplied)
    }
```

**File:** contracts/pool/README.md (L159-168)
```markdown
Each mutation of an existing market runs this sequence:

```text
entrypoint (#[only_owner])
  → Cache::load             # read params + state, bump TTL
  → interest::global_sync   # accrue to now, in ≤1yr chunks
  → mutate                  # cache/shares.rs, cache/cash.rs
  → guards::*               # reserve, utilization, backing checks
  → commit → transfer_out → emit
```
```

**File:** contracts/pool/src/cache/mod.rs (L73-86)
```rust
    /// Persists the full market state and returns a snapshot for events.
    pub(crate) fn commit(&self) -> MarketStateSnapshot {
        let state = PoolStateRaw {
            supplied: self.supplied.raw(),
            borrowed: self.borrowed.raw(),
            revenue: self.revenue.raw(),
            borrow_index: self.borrow_index.raw(),
            supply_index: self.supply_index.raw(),
            last_timestamp: self.last_timestamp,
            cash: self.cash,
        };
        storage::write_state(&self.env, &self.hub_asset, &state);
        self.snapshot()
    }
```

**File:** contracts/controller/src/positions/debt.rs (L68-91)
```rust
/// Repays with the caller's measured transfers; loads and persists debt only.
pub(crate) fn process_repay(
    env: &Env,
    caller: &Address,
    account_id: u64,
    payments_in: &Vec<HubPayment>,
) {
    validation::require_authorized_caller(env, caller);

    let aggregated = payments::aggregate_positive_payments(env, payments_in);
    let mut account = storage::get_account_borrow_only(env, account_id);
    let mut cache = Context::new(env);

    settle_repay(env, &mut account, caller, &aggregated, &mut cache);

    finalize_position_flow(
        env,
        account_id,
        &account,
        &mut cache,
        PositionSides::Debt,
        false,
    );
}
```

**File:** contracts/controller/src/positions/supply.rs (L38-74)
```rust
/// Supplies collateral, creating an account when `account_id` is zero.
/// Third parties may only add to existing supply positions. Returns the account id.
pub(crate) fn process_supply(
    env: &Env,
    caller: &Address,
    account_id: u64,
    spoke_id: u32,
    assets: &Vec<HubPayment>,
) -> u64 {
    validation::require_authorized_caller(env, caller);
    let aggregated = payments::aggregate_positive_payments(env, assets);
    let mut cache = Context::new(env);

    let (acct_id, mut account) = account::load_or_create_account(
        env,
        caller,
        account_id,
        spoke_id,
        PositionMode::Normal,
        account::AccountGuard::Supply,
        &mut cache,
    );

    require_third_party_existing_supply(env, account_id, acct_id, caller, &account, &aggregated);

    process_deposit(env, caller, &mut account, &aggregated, &mut cache);

    finalize_position_flow(
        env,
        acct_id,
        &account,
        &mut cache,
        PositionSides::Supply,
        false,
    );
    acct_id
}
```

**File:** contracts/controller/src/positions/supply.rs (L140-169)
```rust
pub(crate) fn process_withdraw(
    env: &Env,
    caller: &Address,
    account_id: u64,
    withdrawals: &Vec<HubPayment>,
    to: Option<Address>,
) -> Vec<HubPayment> {
    validation::require_authorized_caller(env, caller);

    let mut account = storage::get_account(env, account_id);
    require_owner_or_delegate(env, account_id, caller, &account.owner);

    let recipient = to.unwrap_or_else(|| caller.clone());
    let mut cache = Context::new(env);
    require_external_recipient(env, &mut cache, &recipient);
    let aggregated = payments::aggregate_payments(env, withdrawals, payments::ZeroLeg::MeansAll);

    let paid = settle_withdraw(env, &mut account, &recipient, &aggregated, &mut cache);
    let _ = enforce_post_pool_solvency(env, &mut cache, &mut account);

    finalize_position_flow(
        env,
        account_id,
        &account,
        &mut cache,
        PositionSides::Supply,
        true,
    );
    paid
}
```

**File:** contracts/pool/src/time.rs (L15-20)
```rust
pub(crate) fn now_ms(env: &Env) -> u64 {
    env.ledger()
        .timestamp()
        .checked_mul(MS_PER_SECOND)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
}
```
