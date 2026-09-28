### Title
Bad-debt cleanup can leave permanently unbacked supplier claims - (File: contracts/pool/src/ops/seize.rs)

### Summary

`clean_bad_debt` validates that the target account is insolvent before mutation, but neither the controller nor the pool verifies that the market is backed after the debt shares are burned and the supply index is written down. The write-down is bounded by the supply-index floor, so a sufficiently large loss can leave positive supplier claims with no corresponding debt or cash backing.

### Finding Description

The permissionless `Controller::clean_bad_debt` entrypoint calls `process_clean_bad_debt`, which authorizes the caller and delegates to `clean_bad_debt_standalone` [1](#0-0) . Before cleanup, the controller only checks that the account has debt and that `total_debt > total_collateral` subject to the dust cap [2](#0-1) .

Cleanup then submits every remaining supply position as a `Deposit` seize entry and every remaining debt position as a `Borrow` seize entry [3](#0-2) . For each borrow leg, the pool applies the bad debt to the market supply index and burns the debt shares [4](#0-3) .

The missing post-condition is a check equivalent to `backing_shortfall(&cache) == 0`. Pool backing is defined as floored supplier claims minus cash plus ceiled outstanding debt [5](#0-4) . Bad-debt cleanup explicitly applies no final full-backing assertion, and the supply-index floor can leave a residual shortfall [6](#0-5) .

### Impact Explanation

A single unprivileged caller can trigger a state transition that leaves a market permanently insolvent. Once debt shares are burned, those claims no longer count as outstanding debt, while the floored supply index can preserve supplier claims that exceed the pool’s remaining cash. `require_supply_for_debt` also cannot catch this state because remaining `supplied` shares are nonzero while `borrowed` may have become zero [7](#0-6) .

The result is theft or permanent loss of supplier funds through protocol insolvency: the accounting still reports positive supplier claims, but the market lacks the assets needed to satisfy them.

### Likelihood Explanation

The path is permissionless: any authenticated caller can invoke `clean_bad_debt` once an account is insolvent and its remaining collateral is at or below the dust threshold [8](#0-7) . A sharp collateral-price decline or accumulated debt can create the required account state without privileged action.

### Recommendation

After processing each `Borrow` seize entry in `pool_seize_positions`, evaluate `guards::backing_shortfall(&cache)` and revert if it remains positive. If the intended design permits a bounded residual claim, explicitly cap or remove the remaining supplier claims rather than preserving unbacked value through the supply-index floor. The controller should additionally verify the returned market snapshot has zero backing shortfall before deleting the account and burning its NFT.

### Proof of Concept

1. A user supplies collateral and borrows a different asset.
2. The collateral price falls until the account’s debt exceeds its collateral and remaining collateral is at most the dust threshold.
3. An unprivileged caller invokes `Controller::clean_bad_debt(caller, account_id)`.
4. The controller emits one deposit seize entry and one borrow seize entry for the account [3](#0-2) .
5. The pool writes the debt loss down through `supply_index` and burns the account’s debt shares [4](#0-3) .
6. If the write-down reaches the supply-index floor before fully absorbing the loss, supplier claims remain while the burned debt is no longer counted as backing.
7. No final `backing_shortfall == 0` assertion runs, so the insolvent market state commits and the account is deleted [6](#0-5) .

### Citations

**File:** contracts/controller/src/lib.rs (L160-165)
```rust
    /// Socializes insolvent debt into the supply index and removes the account
    /// when remaining collateral is at or below the dust cap. Permissionless;
    /// requires caller authorization.
    fn clean_bad_debt(env: Env, caller: Address, account_id: u64) {
        positions::liquidation::process_clean_bad_debt(&env, &caller, account_id);
    }
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-243)
```rust
/// Authorizes permissionless dust-gated cleanup outside flash loans.
pub(crate) fn process_clean_bad_debt(env: &Env, caller: &Address, account_id: u64) {
    caller.require_auth();
    validation::require_not_flash_loaning(env);
    clean_bad_debt_standalone(env, account_id);
}

/// Admission condition for bad-debt socialization.
#[derive(Clone, Copy, PartialEq)]
enum BadDebtGate {
    /// Permissionless: insolvent *and* collateral at or below the dust threshold.
    DustCapped,
    /// Owner-only: insolvent alone, with no cap on the collateral left behind.
    InsolventOnly,
}

/// Requires open debt and the selected insolvency gate, then cleans up the account.
fn socialize_bad_debt(env: &Env, account_id: u64, gate: BadDebtGate) {
    let mut cache = Context::new(env);
    let account = storage::get_account(env, account_id);

    assert_with_error!(
        env,
        !account.borrow_positions.is_empty(),
        CollateralError::DebtPositionNotFound
    );

    let totals = risk::calculate_account_risk_totals(
        env,
        &mut cache,
        &account.supply_positions,
        &account.borrow_positions,
    );

    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);

    bad_debt::execute_bad_debt_cleanup(env, &mut cache, account_id, &account, &totals);
}

/// Socializes insolvent debt when remaining collateral is at or below the dust cap.
pub(crate) fn clean_bad_debt_standalone(env: &Env, account_id: u64) {
    socialize_bad_debt(env, account_id, BadDebtGate::DustCapped);
}
```

**File:** contracts/controller/src/positions/liquidation/bad_debt.rs (L21-49)
```rust
    let mut entries: Vec<PoolSeizeEntry> = Vec::new(env);
    for (hub_asset, position) in iter_typed_positions(&account.supply_positions) {
        cache.apply_spoke_exit(
            account.spoke_id,
            UsageSide::Supply,
            &hub_asset,
            position.scaled_amount,
        );
        entries.push_back(PoolSeizeEntry {
            hub_asset,
            side: AccountPositionType::Deposit,
            position: (&position).into(),
        });
    }
    for (hub_asset, position) in iter_debt_positions(&account.borrow_positions) {
        cache.apply_spoke_exit(
            account.spoke_id,
            UsageSide::Borrow,
            &hub_asset,
            position.scaled_amount,
        );
        entries.push_back(PoolSeizeEntry {
            hub_asset,
            side: AccountPositionType::Borrow,
            position: (&position).into(),
        });
    }
    let pool_addr = cache.cached_pool_address();
    pool_seize_positions_call(env, &pool_addr, &entries);
```

**File:** contracts/pool/src/ops/seize.rs (L23-31)
```rust
    match entry.side {
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
        AccountPositionType::Deposit => {
            cache.absorb_supply_as_revenue(position);
        }
```

**File:** contracts/pool/src/guards.rs (L49-66)
```rust
/// Panics with `PoolInsolvent` if the market has a positive backing shortfall.
///
/// Backing = cash + ceiled debt value; claims = floored supply value.
pub(crate) fn require_backed_market(env: &Env, cache: &Cache) {
    assert_with_error!(
        env,
        backing_shortfall(cache) == 0,
        CollateralError::PoolInsolvent
    );
}

/// Asset units by which supplier claims exceed cash + debt (0 if solvent).
pub(crate) fn backing_shortfall(cache: &Cache) -> i128 {
    let supplied_claim = cache.unscale_supply_floor(cache.supplied());
    let outstanding_debt = cache.unscale_borrow_ceil(cache.borrowed());
    let backing = cache.cash().saturating_add(outstanding_debt);
    supplied_claim.saturating_sub(backing).max(0)
}
```

**File:** contracts/pool/src/guards.rs (L68-73)
```rust
/// Panics with `PoolInsolvent` if supplied is zero while borrowed debt is non-zero.
pub(crate) fn require_supply_for_debt(env: &Env, cache: &Cache) {
    if cache.supplied() == Ray::ZERO && cache.borrowed() != Ray::ZERO {
        panic_with_error!(env, CollateralError::PoolInsolvent);
    }
}
```

**File:** docs/reference/invariants.md (L471-479)
```markdown
Cleanup reclassifies all remaining collateral shares as revenue and writes off
all remaining debt against each debt's market. It releases spoke usage and
atomically removes account entries and the NFT. It does not net same-market
supply against debt. Standalone cleanup emits `CleanBadDebtEvent` with
pre-cleanup USD totals, without a controller position-update batch.

Ordinary liquidation and cleanup apply no final account-health or full-backing
assertion. The index floor can leave a shortfall. Recapitalization fills that
shortfall without restoring the lost index or deleted account.
```
