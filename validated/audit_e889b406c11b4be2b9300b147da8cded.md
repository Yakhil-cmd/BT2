### Title
Bad-debt supply-index floor preserves wiped supplier claims and drains recapitalization - (File: contracts/pool/src/interest.rs)

### Summary
When bad debt equals or exceeds the market’s total supplied value, `apply_bad_debt_to_supply_index` clamps the reduced supply index to `SUPPLY_INDEX_FLOOR_RAW` instead of allowing the calculated zero index. This preserves approximately 0.1% of every supposedly wiped supplier’s claim. The market then becomes insolvent, and permissionless recapitalization can fund those phantom claims, allowing old suppliers to withdraw tokens that should have been fully socialized away.

### Finding Description
`apply_bad_debt_to_supply_index` caps the bad debt at `total_supplied_value`, computes a zero `reduction_factor` on a full wipeout, and derives a zero `new_supply_index`. It then raises that result to `SUPPLY_INDEX_FLOOR_RAW`. [1](#0-0) 

The borrow-side pool seizure path invokes this function during bad-debt cleanup. [2](#0-1) 

The controller reaches that pool path through permissionless `clean_bad_debt`: the caller authenticates, the account must have debt, and the debt must exceed collateral while collateral is below the dust cap. [3](#0-2) 

Cleanup submits every residual supply and debt position to `pool_seize_positions_call`. [4](#0-3) 

After the wipeout, `withdraw` converts the old scaled supply position using the floored index, checks accounting cash, burns the shares, and transfers the payout. [5](#0-4) [6](#0-5) 

### Impact Explanation
A full bad-debt socialization should reduce supplier claims to zero. The floor instead leaves each scaled share worth 0.1% of its pre-wipeout value. Those claims have no backing, so the market cannot accept normal supply while the accounting shortfall exists. A permissionless `recapitalize` call credits fresh cash up to the backing shortfall, after which an old supplier can call `withdraw` and consume the recapitalization through the phantom residual claim. This causes theft or permanent loss of recapitalized funds and leaves the market unable to resume normal operation while the unbacked claims remain.

### Likelihood Explanation
The trigger is a sufficiently insolvent account whose debt in a market exceeds the market’s total supplied value, for example after prolonged interest accrual or collateral loss. Once such an account exists, any authenticated unprivileged caller can invoke `clean_bad_debt`; no privileged action or malformed internal state is required. The attacker does not need to control the recapitalizer and can simply retain an old supply position and withdraw after someone else restores accounting cash.

### Recommendation
Remove the `SUPPLY_INDEX_FLOOR_RAW` clamp from full bad-debt write-downs, or explicitly burn/normalize residual supply shares when `capped == total_supplied_value`. The post-socialization invariant should make total supplier claims zero after a full wipeout. Add an end-to-end test that performs bad-debt cleanup, verifies the stored supply index and outstanding claims are zero, and confirms a subsequent recapitalization cannot be withdrawn by pre-wipeout suppliers.

### Proof of Concept
The repository already contains a raw-cache regression demonstrating the accounting flaw. It creates `old_scaled = 1_000 * RAY` shares at `supply_index = RAY`, applies bad debt of `5_000 * RAY`, observes the index clamped to `SUPPLY_INDEX_FLOOR_RAW`, and confirms the old position retains a positive stranded claim. [7](#0-6) 

The same test credits fresh cash, resolves a full withdrawal of the old shares, verifies the withdrawal pays the entire fresh deposit, and leaves less cash than the fresh supplier’s claim. [8](#0-7) 

End-to-end sequence:

1. A market accumulates bad debt greater than or equal to total supplied value.
2. Any caller invokes controller `clean_bad_debt(caller, insolvent_account_id)`.
3. The borrow-side seizure invokes `apply_bad_debt_to_supply_index`, which clamps the index to `RAY / 1000`.
4. A third party calls `recapitalize` for that market, crediting enough cash to cover the stranded claims.
5. A pre-wipeout supplier calls `withdraw` with amount `0` to withdraw all.
6. The old supplier receives recapitalized tokens despite their claim having been fully socialized.

### Citations

**File:** contracts/pool/src/interest.rs (L73-88)
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
```

**File:** contracts/pool/src/ops/seize.rs (L23-28)
```rust
    match entry.side {
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-242)
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

**File:** contracts/pool/src/ops/withdraw.rs (L63-82)
```rust
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

    let snapshot = cache.commit();
    let mutation = cache.position_mutation(remaining, gross_amount);
```

**File:** contracts/pool/src/ops/withdraw.rs (L103-118)
```rust
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
```

**File:** contracts/pool/tests/interest.rs (L372-397)
```rust
#[test]
fn test_raw_cache_floor_clamp_strands_claim_without_supply_guard() {
    let t = TestSetup::new();
    t.as_contract(|| {
        let old_scaled_raw = 1_000 * RAY;
        let mut cache = t.fresh_cache(PoolStateRaw {
            supplied: old_scaled_raw,
            borrowed: 0,
            revenue: 0,
            borrow_index: RAY,
            supply_index: RAY,
            last_timestamp: 0,
            cash: 0,
        });
        let old_scaled = Ray::from(old_scaled_raw);

        apply_bad_debt_to_supply_index(&mut cache, Ray::from(5_000 * RAY));
        assert_eq!(
            cache.supply_index().raw(),
            SUPPLY_INDEX_FLOOR_RAW,
            "wipeout clamps supply_index UP to RAY/1000 instead of resetting shares to 0",
        );

        let stranded = cache.unscale_supply_floor(old_scaled);
        assert!(stranded > 0, "floor clamp leaves S_old a phantom claim");
        assert_eq!(
```

**File:** contracts/pool/tests/interest.rs (L403-426)
```rust
        let fresh_cash = stranded;
        let fresh_scaled = cache.calculate_scaled_supply(fresh_cash);
        cache.mint_supply(fresh_scaled);
        cache.credit_cash(fresh_cash);

        let fresh_claim = cache.unscale_supply_floor(fresh_scaled);
        assert_eq!(
            fresh_claim, fresh_cash,
            "fresh supplier's claim equals deposit"
        );

        let (burn, gross) = cache.resolve_withdrawal(i128::MAX, old_scaled);
        cache.require_reserves(gross);
        cache.burn_supply(burn);
        cache.debit_cash(gross);

        assert!(gross > 0, "stranded wiped position pays out real tokens");
        assert_eq!(gross, fresh_cash, "S_old drains exactly the fresh deposit");
        assert!(
            cache.cash() < fresh_claim,
            "pool cash ({}) can no longer cover fresh supplier claim ({}): funds lost",
            cache.cash(),
            fresh_claim,
        );
```
