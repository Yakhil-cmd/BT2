### Title
Bad-debt wipeout floor revives supplier claims and lets them seize recapitalization funds - (File: contracts/pool/src/interest.rs)

### Summary
When bad debt exceeds the total supplied value, `apply_bad_debt_to_supply_index` computes a zero remaining claim but clamps the supply index back up to `SUPPLY_INDEX_FLOOR_RAW`. Because all historical supply shares remain recorded, the floor recreates a residual claim for suppliers whose positions should have been fully written down. A later `recapitalize` caller funds that residual claim, after which the stale supplier can withdraw real tokens.

### Finding Description
`apply_bad_debt_to_supply_index` caps the socialized loss at `total_supplied_value`, computes `remaining = 0` on a complete wipeout, derives a zero `new_supply_index`, and then applies `.max(SUPPLY_INDEX_FLOOR_RAW)`. [1](#0-0)  The floor is `RAY / 1000`, so a complete write-down still leaves every stored supply share with approximately 0.1% of its prior claim. [2](#0-1) 

The permissionless controller path admits a debt position when it is insolvent and its remaining collateral is below the dust cap. [3](#0-2)  Cleanup converts the account's supply and debt positions into pool seize entries, calls the pool, and removes only that account. [4](#0-3)  On the borrow side, the pool converts the debt shares to a RAY liability, socializes that amount through the supply index, and burns only the bad debt. [5](#0-4) 

Other suppliers' scaled shares remain in both the pool total and their controller positions; the cleanup loop only emits positions belonging to the insolvent account. [6](#0-5)  Consequently, the floor makes `unscale_supply_floor` return a positive token amount for stale shares. [7](#0-6) 

`recapitalize` credits `min(amount, backing_shortfall)` as pool cash and refunds only the excess. [8](#0-7)  Once the phantom claim is funded, normal withdrawal resolves the stale shares, debits the credited cash, and transfers tokens to the stale supplier. [9](#0-8) [10](#0-9) 

### Impact Explanation
A user who supplies before a complete bad-debt write-down retains a withdrawable claim even though the socialization calculation determined that no supplied value remained. The attacker can keep that stale supply and collect assets injected by a later recapitalizer, permanently transferring the recapitalizer's funds to the holder of shares that should have had zero value.

The extractable amount is bounded by approximately 0.1% of the pre-write-down supplied value, but that bound scales with the wiped market and can represent substantial user or protocol recapitalization funds.

### Likelihood Explanation
The trigger path is reachable by an unprivileged caller through `clean_bad_debt(account_id)` once a position is insolvent and its collateral is at or below the dust threshold. [11](#0-10)  An attacker can prepare the beneficiary by holding supply in the debt asset before creating or waiting for a fully insolvent debt position.

The payout requires subsequent recapitalization or other cash funding sufficient to cover the residual shortfall. The affected stale supplier does not need privileged access, leaked keys, bad parameters, or control of an oracle; ordinary market accrual, price movement, and the permissionless cleanup path can establish the state.

### Recommendation
On a complete write-down, prevent the floor from resurrecting claims. When `capped == total_supplied_value`, explicitly transition the market to a wiped state in which all pre-existing supply and revenue claims are worth zero, then block withdrawals and new supply for that wiped market until a governance-defined reset or migration clears the corresponding controller positions.

If the floor is retained for arithmetic reasons, `recapitalize` must not treat floor-clamped historical shares as a legitimate `backing_shortfall`; track wiped supply separately and exclude it from both claim valuation and withdrawal eligibility. Add an end-to-end test proving that after `bad_debt >= total_supplied_value`, pre-existing suppliers cannot withdraw assets injected by `recapitalize`.

### Proof of Concept
1. Attacker account `S` supplies `100 ETH` to the ETH market, acquiring scaled supply shares.
2. Account `B` supplies dust-valued collateral and borrows nearly all ETH cash.
3. Interest accrues until `B`'s ETH debt exceeds the market's total supplied value, while its remaining collateral is below the cleanup dust threshold.
4. The attacker calls `clean_bad_debt(account_id = B)`; the borrow seize leg invokes `apply_bad_debt_to_supply_index`, the loss is capped at the full supplied value, and the computed zero index is replaced by `SUPPLY_INDEX_FLOOR_RAW`. [5](#0-4) [1](#0-0) 
5. `S` still owns its original scaled shares, now valued at roughly `0.1 ETH` rather than zero.
6. A recapitalizer calls `recapitalize(ETH, payer, amount >= 0.1 ETH)`; the pool books the shortfall amount as cash. [8](#0-7) 
7. `S` calls `withdraw(account_id = S, [(ETH, 0)], None)`; the zero amount maps to withdraw-all, the pool burns the stale shares, and transfers the residual claim to `S`. [12](#0-11) [9](#0-8)

### Citations

**File:** contracts/pool/src/interest.rs (L80-88)
```rust
    let capped = bad_debt.min(total_supplied_value);
    let remaining = total_supplied_value.checked_sub(cache.env(), capped);

    let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
    let new_supply_index = cache
        .supply_index()
        .mul_floor(cache.env(), reduction_factor);

    cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
```

**File:** docs/reference/invariants.md (L513-517)
```markdown
That conversion saturates at `i128::MAX` instead of reverting, so the scaled
cap can fail open: once saturated, the configured asset-unit limit is not
enforced. An admitted cap saturates only at an index below one RAY. At the
supply-index floor (`RAY / 1000`), a supply cap above 1/1000 of the admitted
maximum saturates. The borrow index never falls below one RAY, so an admitted
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

**File:** contracts/controller/src/positions/liquidation/bad_debt.rs (L21-60)
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

    cache.persist_spoke_usage();

    CleanBadDebtEvent {
        account_id,
        total_borrow_usd_wad: totals.total_debt.raw(),
        total_collateral_usd_wad: totals.total_collateral.raw(),
    }
    .publish(env);

    remove_account_and_burn_nft(env, account_id);
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

**File:** common/src/rates/scaling.rs (L75-81)
```rust
/// Converts a scaled supply `Ray` back to an asset-unit amount, using floor
/// rounding at `decimals` precision.
pub fn unscale_supply_floor(env: &Env, scaled: Ray, supply_index: Ray, decimals: u32) -> i128 {
    scaled
        .mul_floor(env, supply_index)
        .to_asset_floor(env, decimals)
}
```

**File:** contracts/pool/src/ops/recapitalize.rs (L52-58)
```rust
    let applied = amount.min(guards::backing_shortfall(&cache));
    let refund = amount
        .checked_sub(applied)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    cache.credit_cash(applied);
    cache.commit();
```

**File:** contracts/pool/src/ops/withdraw.rs (L38-49)
```rust
    if outcome.net_transfer == 0
        && (entry.action.position.scaled_amount > 0 || entry.action.amount == i128::MAX)
        && outcome.mutation.position.scaled_amount == 0
    {
        let _ = token::Client::new(env, &outcome.cache.params().asset_id).try_transfer(
            &env.current_contract_address(),
            receiver,
            &0,
        );
    } else {
        outcome.cache.transfer_out(receiver, outcome.net_transfer);
    }
```

**File:** contracts/pool/src/ops/withdraw.rs (L65-81)
```rust
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
```

**File:** contracts/controller/src/positions/supply.rs (L181-199)
```rust
    for (hub_asset, amount) in aggregated.iter() {
        enforce_spoke_asset_flags(
            env,
            cache,
            account.spoke_id,
            &hub_asset,
            FreezePolicy::AllowOnExit,
        );
        let position = get_supply_position_or_panic(env, account, &hub_asset);
        let requested = if amount == 0 {
            WITHDRAW_ALL_SENTINEL
        } else {
            amount
        };
        entries.push_back(PoolWithdrawEntry {
            action: make_pool_action(&position, requested, hub_asset.clone()),
            protocol_fee: 0,
        });
    }
```
