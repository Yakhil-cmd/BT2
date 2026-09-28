### Title
Bad-debt write-down clamps the supply index above zero, resurrecting wiped suppliers’ claims and draining later deposits - (File: contracts/pool/src/interest.rs)

### Summary
`apply_bad_debt_to_supply_index` reduces the supply index in proportion to socialized debt, but clamps the result to `SUPPLY_INDEX_FLOOR_RAW` instead of allowing a full write-down or removing the stranded supply shares. Because `ops::seize::apply` commits this state without a post-seize solvency or supply-claim guard, a sufficiently large bad-debt cleanup can leave existing supply shares with a nonzero residual claim despite their value having been fully written down.

### Finding Description
The pool represents supplier claims as scaled shares multiplied by `supply_index`. During `clean_bad_debt`, the controller emits a `PoolSeizeEntry` for every supply and borrow position and calls the pool’s seize batch. For a borrow position, `ops::seize::apply` calculates its full RAY debt value, writes that value down against the entire market’s supply index, and burns the borrower’s debt shares.

The root cause is in `apply_bad_debt_to_supply_index`: it caps the write-down at the current total supplied value, computes the surviving index, then applies `.max(SUPPLY_INDEX_FLOOR_RAW)`. When the computed surviving index is below `RAY / 1000`, the clamp raises it back to `0.1%` of the original index while leaving `supplied` shares unchanged. Those shares therefore retain a positive claim even though the bad debt was capped because it consumed the entire supplied value.

Unlike supply, withdraw, and other normal pool operations, the seize operation performs no `require_backed_market`, `require_supply_for_debt`, or equivalent check before `cache.commit()`. A later honest deposit can therefore enter a market that still appears backed after the burn while the stranded shares continue to hold a residual withdrawal claim. Withdrawing those shares uses `resolve_withdrawal`, burns the stranded shares, and debits real pool cash.

Relevant code:

- `clean_bad_debt` is permissionless after caller authorization: `Controller::clean_bad_debt` → `process_clean_bad_debt` [1](#0-0) 
- The permissionless gate requires open debt and socializable insolvency: [2](#0-1) 
- Cleanup serializes every supply and debt position into pool seize entries: [3](#0-2) 
- Borrow-side seizure socializes the debt and burns debt shares: [4](#0-3) 
- The loss is capped, the reduced index is calculated, and then clamped upward: [5](#0-4) 
- The floor is `RAY / 1000`: [6](#0-5) 
- Withdrawal resolves the stranded claim, requires cash, burns shares, and debits cash: [7](#0-6) 

### Impact Explanation
This is theft of user funds and protocol insolvency.

After a near-total or total write-down hits the floor, old supply shares retain a positive residual claim. Once any new cash enters the affected market, holders of those stranded shares can withdraw value that should have been eliminated by the socialized loss. The payout consumes cash backing newer suppliers, leaving their aggregate claims greater than available cash plus outstanding debt.

The vulnerability can permanently impair the market and transfer value from subsequent depositors to accounts whose positions should have been fully written down.

### Likelihood Explanation
An unprivileged caller can reach the path through `Controller::clean_bad_debt(caller, account_id)`, requiring only caller authorization and the dust-capped insolvency predicate. Alternatively, residual bad debt generated through a permissionless `liquidate` follows the same seizure and index write-down implementation.

The exploit requires a debt write-down large enough to push the computed post-loss supply index below `RAY / 1000`. That is an extreme market state, but it can arise from concentrated underwater debt or repeated write-downs because each socialization reduces supplier claims while leaving unseized debt in the book. No privileged role, leaked key, upgrade, malformed token, or oracle behavior outside the protocol’s accepted price path is required.

### Recommendation
Do not clamp a fully exhausted index while leaving supply shares outstanding.

At minimum:

1. In `apply_bad_debt_to_supply_index`, detect when `capped == total_supplied_value` or when the calculated index would be below `SUPPLY_INDEX_FLOOR_RAW`.
2. For a full wipeout, burn or otherwise invalidate all outstanding supply shares rather than raising the index to the floor.
3. If retaining the floor is required for index non-zero assumptions, atomically reduce `supplied` and `revenue` consistently so no stranded claim remains.
4. Add a post-seize accounting guard that rejects any committed state whose remaining floored supply claim cannot be backed after debt removal.
5. Add an end-to-end test where socialization reaches the floor, followed by a fresh deposit and attempted withdrawal of the stranded shares.

### Proof of Concept
1. Supplier S supplies asset `D`, creating scaled supply `S_scaled`.
2. Borrower B supplies collateral in another market and borrows nearly all available `D`.
3. B becomes insolvent; liquidation or price movement leaves residual debt whose RAY value is at least `S_scaled * supply_index / RAY`, or repeated write-downs produce the same condition.
4. An attacker calls `Controller::clean_bad_debt(attacker, B_account_id)` after authorizing the call.
5. `execute_bad_debt_cleanup` submits B’s `D` debt as a `PoolSeizeEntry` with `side = Borrow`.
6. `ops::seize::apply` calls `apply_bad_debt_to_supply_index`; the loss is capped at total supplied value, computes a surviving index below `SUPPLY_INDEX_FLOOR_RAW`, and commits `supply_index = SUPPLY_INDEX_FLOOR_RAW`.
7. `S_scaled` is not burned, so its owner retains `S_scaled * (RAY / 1000) / RAY` worth of residual claim.
8. Victim V supplies new `D`; `ops::supply::apply` mints shares and credits the new cash.
9. S calls `Controller::withdraw(owner, S_account_id, [(D_key, i128::MAX)], to)` to close the stranded position.
10. Pool withdrawal pays S from V’s newly deposited cash. V’s remaining claim is now backed by less cash than required, completing the transfer of funds to the wiped supplier.

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

**File:** contracts/controller/src/positions/liquidation/mod.rs (L212-237)
```rust
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

**File:** contracts/pool/src/ops/seize.rs (L23-34)
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
    }

    cache.commit()
```

**File:** contracts/pool/src/interest.rs (L73-89)
```rust
pub(crate) fn apply_bad_debt_to_supply_index(cache: &mut Cache, bad_debt: Ray) {
    let total_supplied_value = cache.supplied().mul(cache.env(), cache.supply_index());

    if total_supplied_value == Ray::ZERO {
        return;
    }

    let capped = bad_debt.min(total_supplied_value);
    let remaining = total_supplied_value.checked_sub(cache.env(), capped);

    let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
    let new_supply_index = cache
        .supply_index()
        .mul_floor(cache.env(), reduction_factor);

    cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
}
```

**File:** common/src/constants/pool.rs (L6-9)
```rust
/// Minimum value the supply index is clamped to when bad debt is written down against
/// suppliers, in raw ray units. Interest accrual does not apply this floor; it only guarantees
/// the index never decreases.
pub const SUPPLY_INDEX_FLOOR_RAW: i128 = RAY / 1_000;
```

**File:** contracts/pool/src/ops/withdraw.rs (L91-119)
```rust
/// Maps requested amount and position to shares burned and gross asset amount.
/// Panics if a nonzero gross amount would burn zero shares.
fn resolve_close_or_partial(cache: &Cache, amount: i128, position: Ray) -> (Ray, i128) {
    let (burned, gross_amount) = cache.resolve_withdrawal(amount, position);
    assert_with_error!(
        cache.env(),
        gross_amount == 0 || burned.raw() > 0,
        GenericError::WithdrawRoundsToZeroShares
    );
    (burned, gross_amount)
}

/// Burns `burned` from market supply and returns the user's remaining scaled position.
fn burn_position(env: &Env, cache: &mut Cache, position: Ray, burned: Ray) -> Ray {
    cache.burn_supply(burned);
    position.checked_sub(env, burned)
}

/// Enforces reserve, utilization, and solvency guards, then debits cash for
/// the net transfer. Liquidations and footprint-only closes skip utilization.
fn gate_and_debit(env: &Env, cache: &mut Cache, net_transfer: i128, skip_utilization_check: bool) {
    cache.require_reserves(net_transfer);

    if !skip_utilization_check {
        guards::require_utilization_below_max(env, cache);
    }
    guards::require_supply_for_debt(env, cache);
    cache.debit_cash(net_transfer);
}
```
