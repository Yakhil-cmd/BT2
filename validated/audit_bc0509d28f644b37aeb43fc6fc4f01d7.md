### Title
Interest accrual overflows before the borrow-index cap and permanently freezes a large market - (File: `common/src/rates/simulate.rs`)

### Summary
A sufficiently large borrowed share balance can make `borrowed * borrow_index` exceed the `i128` range before the borrow index reaches its configured cap. Because every market mutation accrues interest before applying the requested operation, this traps the affected market in `MathOverflow`, blocking repayment, withdrawal, liquidation, recapitalization, and revenue processing for that market.

### Finding Description
`accrue_step` first converts scaled debt back to its current RAY value through `scaled_to_original`; that multiplication is not bounded by `MAX_BORROW_INDEX_RAY` and can overflow before `update_borrow_index` is reached. [1](#0-0) [2](#0-1) 

The borrow-index cap is applied only after `old_index * interest_factor`; it does not cap or saturate the earlier debt-value multiplication. [3](#0-2) 

All pool operations load a synchronized market, which unconditionally calls `interest::global_sync` before the action-specific logic. [4](#0-3)  The permissionless controller `update_indexes` entrypoint exposes the same accrual path through `markets::update_indexes` and `ops::market::accrue`. [5](#0-4) [6](#0-5) 

The repository’s own regression test demonstrates the state transition: an 18-decimal market supplied with `BILLION * 10^18` units and borrowed at 98% utilization eventually fails in `update_indexes` with `MathOverflow`, after which both `withdraw` and `repay` fail with the same error. [7](#0-6) 

### Impact Explanation
Once the stored scaled-debt and index combination reaches the overflow boundary, every later market operation re-enters the same accrual calculation and panics before it can reduce debt, release collateral, pay suppliers, or socialize losses. [4](#0-3) [8](#0-7) 

This permanently freezes supplier withdrawals and borrower repayments and prevents risk-reducing liquidation from proceeding on the affected market, satisfying both permanent freezing of user funds and protocol insolvency risk. [9](#0-8) 

### Likelihood Explanation
An unprivileged user can reach the precondition through ordinary `controller::supply` and `controller::borrow` flows if governance-configured supply, borrow, and collateral limits permit the required whale-scale position; no privileged function or leaked key is needed to place the market in the vulnerable state. [10](#0-9) 

Time passage then moves the market toward the cliff, and anyone can invoke `controller::update_indexes(caller, assets)` with the affected `HubAssetKey` to execute the failing accrual. [5](#0-4) [11](#0-10) 

The likelihood is constrained by the extremely large required token balance, high sustained utilization, and governance caps; however, the checked-in test proves that the failure occurs before the intended borrow-index ceiling once those limits admit the position. [12](#0-11) 

### Recommendation
Make accrual overflow-safe and recoverable rather than allowing a checked multiplication to abort before the index cap:

- In `accrue_step`, use a widening or saturating conversion for `scaled_to_original` when calculating utilization.
- If the debt value exceeds the representable range, clamp the borrow index to `MAX_BORROW_INDEX_RAY` and continue accrual at the capped debt value instead of panicking.
- Ensure `calculate_supplier_rewards` and `supply_index_reward_shortfall` use the same capped/widened accounting path.
- Add a regression test proving that after the large-market boundary is crossed, `update_indexes`, `repay`, `withdraw`, and liquidation continue to execute at capped index value rather than returning `MathOverflow`.
- Separately bound configured caps so `scaled_borrowed * MAX_BORROW_INDEX_RAY` cannot exceed the RAY numeric domain for any listed decimal configuration.

### Proof of Concept
The existing test at `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321` is an executable PoC:

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);

let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
        break e;
    }
}

assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

The test records that the market fails below `MAX_BORROW_INDEX_RAY`, proving that the unchecked debt-value multiplication—not the intended index ceiling—is the root cause. [9](#0-8)

### Citations

**File:** common/src/rates/simulate.rs (L60-67)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

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

**File:** contracts/pool/src/ops/mod.rs (L29-39)
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

**File:** scripts/permissionless_entrypoints.txt (L49-74)
```text
controller::borrow | caller-auth | INV-AUTH-02, INV-RISK-01 | Any address may call, but the funds are drawn against account_id, which require_owner_or_delegate pins to its owner or an active listed delegate, and post-pool solvency is re-proven.
controller::withdraw | caller-auth | INV-AUTH-02, INV-RISK-01 | Any address may call, but require_owner_or_delegate pins account_id to its owner or an active listed delegate before any collateral leaves, and solvency is re-proven afterward.
controller::multiply | caller-auth | INV-AUTH-02, INV-STRAT-02 | Leverage entry on account_id; the Multiply account guard requires the owner or an active listed delegate and asserts the account's position mode matches.
controller::flash_position | caller-auth | INV-AUTH-02, INV-STRAT-02, INV-STRAT-04 | Callback leverage entry on account_id; the Multiply account guard requires the owner or an active listed delegate, require_wasm_receiver admits only a Wasm contract receiver, collateral is credited from measured receipts only, and FlashPositionClosed plus strategy_finalize keep the minted debt on a solvent account that still holds supply.
controller::swap_debt | caller-auth | INV-AUTH-02, INV-STRAT-02 | Moves debt on account_id from one asset to another; require_owner_or_delegate pins the account before the borrow-and-repay legs run.
controller::swap_collateral | caller-auth | INV-AUTH-02, INV-STRAT-02 | Moves collateral on account_id from one asset to another; require_owner_or_delegate pins the account before the withdraw-and-deposit legs run.
controller::repay_debt_with_collateral | caller-auth | INV-AUTH-02, INV-STRAT-02 | Nets or swaps account_id's own collateral into a repayment; require_owner_or_delegate pins the account, so a stranger cannot force-close a position.
controller::migrate_from_blend | caller-auth | INV-AUTH-02, INV-STRAT-02, INV-STRAT-03 | Sweeps the caller's Blend position into account_id from a governance-approved pool only; the Migrate account guard requires the owner or an active listed delegate.
controller::add_delegate | caller-auth | INV-AUTH-02 | Grants delegate authority on account_id; require_account_owner admits the owner alone, so a delegate cannot extend its own reach, and the delegate must be an active governance-approved position manager.
controller::remove_delegate | caller-auth | INV-AUTH-02 | Revokes delegate authority on account_id; require_account_owner admits the owner alone. Revocation only narrows authority.
controller::renew_account | caller-auth | INV-AUTH-02, INV-STOR-01 | Extends account_id's storage TTL; require_account_owner admits the owner alone. Writes no accounting state, only TTLs.
#
# ---------------------------------------------------------------------------
# controller -- permissionless (INV-AUTH-03)
#
# Third parties may pay in, liquidate, clean bad debt, take flash loans and run
# maintenance. None of these can open an asset slot in a foreign account.
# Each line states what bounds its effect on accounts the caller does not
# control.
# ---------------------------------------------------------------------------
controller::supply | caller-auth | INV-AUTH-03, INV-ACCT-03 | Anyone may top up an account they do not own, but only for hub assets it already holds a supply position in; a caller that is neither the owner nor an active delegate cannot open a new asset slot, and account_id 0 creates an account owned by the caller.
controller::repay | caller-auth | INV-AUTH-03, INV-ACCT-03 | Anyone may repay any account's debt. Funds are pulled from the caller's own balance and credited from the measured receipt; the target's liabilities can only fall.
controller::liquidate | caller-auth | INV-AUTH-03, INV-LIQ-01, INV-LIQ-02 | Anyone may liquidate an account whose health factor is below one, including the account's own owner; in Credit seize mode the receiving account must be a different account that the liquidator owns or is an active delegate of, and seizure stays coupled to the debt actually repaid.
controller::clean_bad_debt | caller-auth | INV-AUTH-03, INV-LIQ-04 | Anyone may socialize an insolvent account's residual debt, but only once its remaining collateral is at or below the dust threshold; only the owner-gated force_socialize_bad_debt omits the dust cap.
controller::recapitalize | caller-auth | INV-AUTH-03, INV-ACCT-02, INV-ACCT-03 | Anyone may donate their own funds to cover a market's backing shortfall; only the measured receipt up to the shortfall is applied and the excess is refunded to the payer.
controller::update_indexes | caller-auth | INV-AUTH-03, INV-IDX-04 | Keeper maintenance: accrues interest to the current ledger timestamp. Accrual never lowers the borrow or supply index and each chunk's rate is capped at max_borrow_rate, so the caller chooses only the accrual timing and cannot lower anyone's balance.
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
