### Title
Bad-debt cleanup clamps `supply_index` instead of releasing residual supplier claims, allowing stranded shares to drain future deposits - ([File: contracts/pool/src/interest.rs](contracts/pool/src/interest.rs))

### Summary
The pool socializes bad debt by reducing `supply_index`, but clamps the index to `SUPPLY_INDEX_FLOOR_RAW` rather than allowing it to reach zero or deleting the excess claims. When written-off debt exceeds total supply value, surviving suppliers retain positive claims backed by no cash or debt. A later deposit can therefore be withdrawn by holders of these stranded claims.

### Finding Description
`clean_bad_debt(caller, account_id)` is callable by any authenticated address once an account’s debt exceeds its collateral and remaining collateral is at most the dust threshold. [1](#0-0) 

Cleanup submits all remaining deposit positions before all borrow positions. [2](#0-1)  For a borrow leg, the pool computes its ceiling-valued debt, writes that loss into `supply_index`, and burns the debt shares. [3](#0-2) 

The write-down is capped at total supplied value, but the resulting index is then raised to a nonzero floor. [4](#0-3)  Consequently, even a complete write-down leaves every surviving supply share redeemable for approximately 0.1% of its original indexed value.

Withdrawals resolve those residual shares into asset units and only require current cash reserves; they do not require total supplier claims to remain covered by cash plus outstanding debt. [5](#0-4) [6](#0-5)  The backing-shortfall helper exists, but normal withdrawal does not call `require_backed_market`. [7](#0-6) 

The repository already contains a regression-style demonstration of this shape: after floor clamping, a wiped position retains a positive stranded claim, a fresh deposit creates cash, and the stranded holder withdraws that fresh cash, leaving the new depositor under-backed. [8](#0-7) 

### Impact Explanation
An attacker can preserve a small positive claim after complete bad-debt socialization. Once another user deposits into the affected market, the attacker can call `withdraw` against the residual supply position and receive cash that economically belongs to the new depositor.

This is theft of user funds and can also leave the fresh depositor’s claim temporarily or permanently frozen until the market is recapitalized. The loss is bounded by the residual claims created by the nonzero index floor, but it scales with the pre-cleanup supply-share base and market decimals.

### Likelihood Explanation
A single unprivileged actor can reach the affected path through `clean_bad_debt` once an insolvent account satisfies the dust gate. [1](#0-0)  The trigger requires the written-off debt to be at least the market’s total supplied value so that the floor clamp becomes operative. [4](#0-3) 

That condition can arise after accrual creates debt value exceeding supplier claims, followed by a collateral-value collapse that makes the account satisfy the public cleanup gate. `update_indexes(caller, assets)` is permissionless, so the attacker can force accrual before invoking cleanup. [9](#0-8)  The final exploitation step is an ordinary owner-authorized `withdraw` by the holder of a stranded supply position.

### Recommendation
Do not leave a nonzero floor after a bad-debt write-down that exhausts supplier value. Prefer one of:

- Clamp the proportional write-down to the exact total supplier claim and then atomically delete or mark all residual supply shares non-redeemable.
- Treat a complete write-down as an explicit market-level bad-debt state that blocks withdrawals and deposits until recapitalization.
- During withdrawal, enforce the market backing check or cap payouts so residual claims cannot consume cash attributable to newer deposits.
- If a floor is retained for arithmetic reasons, separately store a redemption-disable flag or haircut ledger; do not use the floor itself as a redeemable claim.

A regression test should assert that, after bad debt consumes all supplier value, no pre-existing supply position can withdraw cash contributed by a later deposit.

### Proof of Concept
1. `Supplier` calls:
   - `supply(caller=Supplier, account_id=0, spoke_id=S, assets=[(A, amount)])`
   and obtains a normal account holding supply shares in market `A`.

2. `Borrower` creates another account, supplies collateral `C`, and calls:
   - `borrow(caller=Borrower, account_id=B, borrows=[(A, borrow_amount)], to=None)`

3. Time passes, or a permissionless keeper calls:
   - `update_indexes(caller=Attacker, assets=[A])`
   until the ceiling-valued debt in market `A` is at least the floor-valued total supplier claim in that market.

4. The collateral market `C` falls so `Borrower` has debt greater than collateral and at most the public cleanup dust threshold.

5. `Attacker` calls:
   - `clean_bad_debt(caller=Attacker, account_id=B)`

   The controller emits deposit-side seize entries and borrow-side seize entries, and the pool processes the borrow side by calling `apply_bad_debt_to_supply_index` before `burn_debt`. [2](#0-1) [3](#0-2) 

6. Because the debt write-down reaches the total supply value, `new_supply_index` is raised to `SUPPLY_INDEX_FLOOR_RAW`; `Supplier`’s account therefore still contains positive supply shares with a positive floored asset value even though market backing has been exhausted. [4](#0-3) 

7. `Victim` calls `supply` into market `A`, increasing pool cash.

8. `Supplier` calls:
   - `withdraw(caller=Supplier, account_id=S_account, withdrawals=[(A, 0)], to=None)`

   The pool resolves the floored residual claim, checks only that current cash covers the requested payout, burns the residual shares, debits cash, and transfers underlying tokens to `Supplier`. [6](#0-5)  `Victim` is left with a claim exceeding the remaining pool cash.

### Citations

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-235)
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

**File:** contracts/pool/src/cache/scale.rs (L94-105)
```rust
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

**File:** contracts/pool/tests/interest.rs (L448-492)
```rust
        let bad_debt = cache.unscale_borrow_ceil_ray(borrow_scaled);
        apply_bad_debt_to_supply_index(&mut cache, bad_debt);
        cache.burn_debt(borrow_scaled);

        assert_eq!(
            cache.supply_index().raw(),
            SUPPLY_INDEX_FLOOR_RAW,
            "seize wipeout clamps supply_index UP to RAY/1000, leaving unburned shares a residual"
        );

        let alice_stranded = cache.unscale_supply_floor(alice_scaled);
        assert!(alice_stranded > 0, "wiped survivor keeps a stranded claim");
        assert_eq!(
            cache.cash(),
            0,
            "empty market: claim masked by require_reserves"
        );

        let deposit = alice_stranded;
        let bob_scaled = cache.calculate_scaled_supply(deposit);
        cache.mint_supply(bob_scaled);
        cache.credit_cash(deposit);

        let total_owed = cache.unscale_supply_floor(cache.supplied());
        assert!(
            total_owed > cache.cash(),
            "post-deposit books insolvent: owed {} > cash {}",
            total_owed,
            cache.cash()
        );

        let (burn, gross) = cache.resolve_withdrawal(i128::MAX, alice_scaled);
        cache.require_reserves(gross);
        cache.burn_supply(burn);
        cache.debit_cash(gross);

        assert!(gross > 0, "wiped position pays out real cash");
        assert_eq!(gross, deposit, "Alice extracts exactly Bob's fresh deposit");

        let bob_claim = cache.unscale_supply_floor(bob_scaled);
        assert!(
            cache.cash() < bob_claim,
            "cash {} cannot cover Bob's honest claim {}: fresh depositor lost funds",
            cache.cash(),
            bob_claim
```

**File:** docs/reference/endpoints.md (L37-40)
```markdown
| `update_indexes(caller: Address, assets: Vec<HubAssetKey>)` | None | gated | Accrue specified markets. |
| `claim_revenue(caller: Address, assets: Vec<HubAssetKey>) -> Vec<i128>` | None | gated | Pay only configured accumulator; return controller receipts. |
| `update_account_threshold(caller: Address, has_risks: bool, account_ids: Vec<u64>)` | None | gated | Refresh LTV; optional risk refresh requires final HF >= 1.05. |
| `recapitalize(payer: Address, hub_asset: HubAssetKey, amount: i128) -> i128` | None | open | Measured backing injection; refund surplus; return amount applied. |
```
