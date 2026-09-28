### Title
Bad-debt supply-index floor resurrects wiped supply claims that can drain later deposits - ([File: contracts/pool/src/interest.rs](contracts/pool/src/interest.rs))

### Summary
When a permissionless `clean_bad_debt` writes off debt greater than or equal to the whole supplied value, `apply_bad_debt_to_supply_index` clamps the written-down supply index upward to `SUPPLY_INDEX_FLOOR_RAW` instead of reducing supplier claims to zero. [1](#0-0)  Surviving suppliers retain their scaled shares, so those shares regain a positive withdrawal value at the floored index and can consume later cash before honest depositors are paid. [2](#0-1) 

### Finding Description
The controller’s permissionless cleanup path only requires caller authentication, no active flash loan, open debt, and the dust-capped insolvency predicate before executing `execute_bad_debt_cleanup`. [3](#0-2)  Cleanup emits a `Borrow` `PoolSeizeEntry` for each debt position, and the pool converts the seized debt shares to RAY, writes the loss into the supply index, and burns the debt. [4](#0-3) [5](#0-4) 

The write-down caps the loss at total supplied value, computes the remaining fraction, and then applies `max(new_supply_index, SUPPLY_INDEX_FLOOR_RAW)`. [6](#0-5)  On a complete wipeout the mathematically reduced index is zero, but the clamp restores it to `RAY / 1000`; the surviving `supplied` shares are not burned or otherwise marked as economically extinguished. [7](#0-6)  A later withdrawal resolves those stale shares against the resurrected index and only checks accounting cash before debiting and transferring reserves. [8](#0-7) [9](#0-8) 

The supply guard calculates the aggregate floored claim and admits a deposit whenever existing cash plus outstanding debt covers it. [10](#0-9) [11](#0-10)  Consequently, a market with enough residual cash or debt can accept a new deposit even though wiped suppliers still hold positive-value stale shares that can withdraw ahead of the new depositor. [12](#0-11) 

### Impact Explanation
A holder of pre-cleanup supply shares can extract real cash from a market whose economic supply value was already fully written off. [13](#0-12)  The withdrawal pays the stale claimant first and leaves less cash than the new supplier’s claim, constituting theft of user funds and market insolvency for later suppliers. [14](#0-13)  The loss is bounded per wipeout by the floor-residual value of all outstanding supply shares, but every wiped holder retains an economically invalid claim proportional to their shares. [7](#0-6) 

### Likelihood Explanation
An unprivileged caller can trigger the write-down through `clean_bad_debt(caller, account_id)` once an account satisfies the existing dust-capped insolvency test; no privileged operation, leaked key, oracle manipulation, or callback is required for the vulnerable transition. [15](#0-14)  The exploit requires the exceptional condition that one cleanup’s bad debt reaches the whole market’s supplied value, which can arise after severe collateral impairment and debt accrual. [1](#0-0)  After that point, exploitation only needs an ordinary admitted supply followed by the stale holder’s ordinary withdrawal. [16](#0-15) [9](#0-8) 

### Recommendation
Represent complete bad-debt wipeouts explicitly instead of clamping the live conversion index upward. [17](#0-16)  When `remaining == 0`, either burn or tombstone all outstanding supply shares, prevent subsequent unscaling, or initialize a fresh share base for a reactivated market. [7](#0-6)  At minimum, carry a wipeout epoch or zero-claim flag in market state and make `resolve_withdrawal`, `unscale_supply_floor`, `backing_shortfall`, revenue conversion, and supply minting treat pre-wipeout shares as zero rather than relying on a nonzero index floor. [18](#0-17) [10](#0-9) 

### Proof of Concept
1. Alice supplies `S` scaled shares in the debt market, and another account accumulates debt that later becomes dust-collateralized and cleanable through permissionless `clean_bad_debt`. [15](#0-14) 
2. Cleanup submits Alice’s market debt as a borrow-side `PoolSeizeEntry`; the pool converts the debt to RAY and calls `apply_bad_debt_to_supply_index` before burning it. [19](#0-18) [20](#0-19) 
3. If the bad debt equals or exceeds `supplied * supply_index`, `remaining` is zero, but the index is set to `SUPPLY_INDEX_FLOOR_RAW`, leaving Alice’s `S` shares with a positive floored claim. [7](#0-6) 
4. Bob supplies the floored residual amount; the backing gate admits the deposit when existing backing covers the stale aggregate claim, mints Bob shares, and credits his cash. [16](#0-15) [10](#0-9) 
5. Alice calls controller `withdraw` for the stale supply position; the pool resolves all `S` shares at the floored index, checks cash, burns the shares, debits cash, and transfers Bob’s deposit to Alice. [8](#0-7) [9](#0-8) 
6. The repository’s focused cache test reproduces the same sequence: wipeout clamps the index to the floor, the old position retains a positive stranded claim, a fresh deposit arrives, and withdrawal of the stale position drains exactly that fresh deposit. [12](#0-11)

### Citations

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

**File:** contracts/pool/src/cache/scale.rs (L49-105)
```rust
    /// Unscales supply shares to asset units with half-up rounding.
    pub(crate) fn unscale_supply(&self, scaled: Ray) -> i128 {
        unscale_supply(
            &self.env,
            scaled,
            self.supply_index,
            self.params.asset_decimals,
        )
    }

    /// Unscales supply shares rounding **down** (conservative claim value).
    pub(crate) fn unscale_supply_floor(&self, scaled: Ray) -> i128 {
        unscale_supply_floor(
            &self.env,
            scaled,
            self.supply_index,
            self.params.asset_decimals,
        )
    }

    /// Unscales debt shares to asset units with half-up rounding.
    pub(crate) fn unscale_borrow(&self, scaled: Ray) -> i128 {
        unscale_borrow(
            &self.env,
            scaled,
            self.borrow_index,
            self.params.asset_decimals,
        )
    }

    /// Unscales debt shares rounding **up** (conservative liability).
    pub(crate) fn unscale_borrow_ceil(&self, scaled: Ray) -> i128 {
        unscale_borrow_ceil(
            &self.env,
            scaled,
            self.borrow_index,
            self.params.asset_decimals,
        )
    }

    /// Unscales debt shares to a RAY asset amount, rounding up.
    pub(crate) fn unscale_borrow_ceil_ray(&self, scaled: Ray) -> Ray {
        scaled.mul_ceil(&self.env, self.borrow_index)
    }

    /// Resolves a withdrawal request into (shares burned, gross asset amount).
    ///
    /// Caps against `pos_scaled` so the user cannot withdraw more than held.
    pub(crate) fn resolve_withdrawal(&self, amount: i128, pos_scaled: Ray) -> (Ray, i128) {
        resolve_withdrawal(
            &self.env,
            amount,
            pos_scaled,
            self.supply_index,
            self.params.asset_decimals,
        )
    }
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-238)
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

**File:** contracts/pool/src/ops/seize.rs (L18-34)
```rust
pub(crate) fn apply(env: &Env, entry: &PoolSeizeEntry) -> MarketStateSnapshot {
    require_nonneg_amount(env, entry.position.scaled_amount);
    let mut cache = ops::synced_market(env, &entry.hub_asset);
    let position = Ray::from(entry.position.scaled_amount);

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

**File:** contracts/pool/src/ops/withdraw.rs (L61-82)
```rust
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

    let snapshot = cache.commit();
    let mutation = cache.position_mutation(remaining, gross_amount);
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

**File:** contracts/pool/src/ops/supply.rs (L19-40)
```rust
pub(crate) fn apply(
    env: &Env,
    entry: &PoolSupplyEntry,
) -> (PoolPositionMutation, MarketStateSnapshot) {
    let (mut cache, mut position) = ops::load_leg(env, &entry.action);
    let amount = entry.action.amount;

    guards::require_backed_market(env, &cache);

    let minted = cache.calculate_scaled_supply(amount);
    assert_with_error!(
        env,
        amount == 0 || minted.raw() > 0,
        GenericError::SupplyRoundsToZeroShares
    );

    position = position.checked_add(env, minted);
    cache.mint_supply(minted);

    cache.credit_cash(amount);

    let snapshot = cache.commit();
```

**File:** contracts/pool/tests/interest.rs (L316-369)
```rust
#[test]
fn test_raw_cache_floor_residual_can_consume_fresh_cash_without_supply_guard() {
    let t = TestSetup::new();
    t.as_contract(|| {
        let scaled_a_raw = 1_000_000 * RAY;
        let mut cache = t.fresh_cache(PoolStateRaw {
            supplied: scaled_a_raw,
            borrowed: 0,
            revenue: 0,
            borrow_index: RAY,
            supply_index: RAY,
            last_timestamp: 0,
            cash: 0,
        });
        let scaled_a = Ray::from(scaled_a_raw);

        apply_bad_debt_to_supply_index(&mut cache, Ray::from(2_000_000 * RAY));
        assert_eq!(
            cache.supply_index().raw(),
            SUPPLY_INDEX_FLOOR_RAW,
            "wipeout must clamp supply index UP to the floor, not reset the base"
        );

        let stranded = cache.unscale_supply_floor(scaled_a);
        assert!(stranded > 0, "floor clamp leaves userA a phantom claim");
        assert_eq!(cache.cash(), 0, "empty market: no cash to extract yet");

        let c = stranded;
        let scaled_b = cache.calculate_scaled_supply(c);
        cache.mint_supply(scaled_b);
        cache.credit_cash(c);

        let b_claim = cache.unscale_supply_floor(scaled_b);
        assert_eq!(b_claim, c, "userB's honest claim equals their deposit");

        let (burn, gross) = cache.resolve_withdrawal(i128::MAX, scaled_a);
        cache.require_reserves(gross);
        cache.burn_supply(burn);
        cache.debit_cash(gross);

        assert!(gross > 0, "stranded position pays out non-zero");
        assert_eq!(
            gross, c,
            "userA drains exactly userB's fresh deposit out of the pool"
        );

        assert!(
            cache.cash() < b_claim,
            "pool cash ({}) can no longer cover userB's claim ({}): honest supplier lost funds",
            cache.cash(),
            b_claim
        );
        assert_eq!(cache.cash(), 0, "userA drained the pool to empty");
    });
```
