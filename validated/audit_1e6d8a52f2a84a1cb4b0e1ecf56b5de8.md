### Title
Unwritten bad debt lets suppliers withdraw at the pre-loss index and concentrate insolvency on remaining suppliers - (File: contracts/pool/src/ops/withdraw.rs)

### Summary
A supplier can withdraw at the current supply index after a borrower becomes insolvent but before `liquidate` or `clean_bad_debt` writes the loss into the debt market's supply index. [1](#0-0) [2](#0-1)  The withdrawal path values claims at the live supply index and checks liquidity, reserves, utilization, and zero-supply debt, but it does not require the market's economic backing after treating known-to-be-bad debt as uncollectible. [3](#0-2) [4](#0-3) [5](#0-4)  When cleanup later runs, the unpaid debt is burned and the loss is applied only by reducing the market's supply index, so suppliers who already exited avoid the write-down and the same loss is concentrated onto the shares that remain. [6](#0-5) [7](#0-6) 

### Finding Description
`process_withdraw` authorizes the account owner or delegate, resolves a zero amount as a full withdrawal, calls the pool, and then checks only the withdrawing account's post-withdrawal solvency. [8](#0-7)  The pool withdrawal accrues interest, converts shares through `resolve_withdrawal`, burns the shares, checks reserves and utilization, requires only that nonzero debt not remain with zero supply, debits cash, and transfers the proceeds. [9](#0-8) [4](#0-3) [10](#0-9)  The market solvency helper defines backing as cash plus the full ceiled value of outstanding debt, without a haircut for debt that is already uncollateralized but not yet written down. [5](#0-4)  Bad debt is corrected only during liquidation cleanup or standalone cleanup, which removes the account's positions, calls pool seizure, deletes the account, and burns its NFT. [2](#0-1) [11](#0-10)  The pool-side correction computes `bad_debt / total_supplied_value` and multiplies the existing supply index by the remaining fraction, meaning every not-yet-withdrawn share bears a larger percentage loss after earlier suppliers have exited. [12](#0-11) 

### Impact Explanation
The exploitable result is protocol insolvency and forced transfer of the insolvency to non-exiting suppliers, not merely the exiting supplier receiving an accrued balance. [12](#0-11)  If a large supplier exits between the public price move that makes a borrower insolvent and the liquidation or cleanup transaction, the pool pays that supplier against a supply index that has not yet absorbed the defaulted debt. [13](#0-12) [14](#0-13)  Because cleanup later divides the same bad debt over a smaller supply base, remaining suppliers can suffer disproportionate index loss and may be left with claims exceeding cash plus collectible debt. [15](#0-14) [12](#0-11) [16](#0-15) 

### Likelihood Explanation
This requires a public insolvency transition, such as a collateral price move or interest accrual, followed by a withdrawal transaction ordered before `liquidate` or `clean_bad_debt`. [17](#0-16) [18](#0-17)  The attacker only needs to own a supply position in the affected debt market and submit `withdraw(caller, account_id, [(hub_asset, 0)], to)`; zero selects a full withdrawal and no authorization from the insolvent borrower or a keeper is needed. [1](#0-0) [19](#0-18)  The exit is bounded by available cash and normal reserve/utilization checks, so it is most damaging when the market still holds enough cash to pay early exits before recognizing the bad debt. [4](#0-3) 

### Recommendation
Mark known or provably imminent bad debt before permitting ordinary withdrawals, or make withdrawal value claims at a conservative index that reflects the maximum collectible debt rather than face-value outstanding debt. [16](#0-15) [20](#0-19)  At minimum, add a withdrawal-side backed-market check that excludes debt from accounts currently eligible for liquidation or cleanup, or run the permissionless bad-debt cleanup before processing withdrawals from the affected market. [4](#0-3) [18](#0-17) 

### Proof of Concept
1. Bob and Carol supply ETH to the same hub market, while Alice supplies USDC collateral and borrows ETH in the same spoke. [21](#0-20) 
2. The USDC price falls enough that Alice's health factor is below one and part of her ETH debt is unrecoverable, but neither `liquidate` nor `clean_bad_debt` has executed. [22](#0-21) [2](#0-1) 
3. Bob calls `withdraw` with amount `0` for ETH; `ZeroLeg::MeansAll` becomes `i128::MAX`, the pool resolves and burns Bob's shares at the still-unwritten-down supply index, debits cash, and transfers ETH to Bob. [23](#0-22) [9](#0-8) [10](#0-9) 
4. A liquidator then calls `liquidate`, or any caller calls `clean_bad_debt` once Alice's remaining collateral is at or below the dust gate; the pool removes Alice's debt position and applies the unpaid amount by lowering the ETH supply index. [24](#0-23) [25](#0-24) [26](#0-25) [12](#0-11) 
5. Bob's withdrawn shares are no longer in `supplied`, so Carol's remaining shares absorb the percentage reduction that would otherwise have been split across both suppliers; if enough suppliers exit, the post-cleanup index floor or cash shortfall leaves the remaining claims underbacked. [12](#0-11) [5](#0-4)

### Citations

**File:** contracts/controller/src/positions/supply.rs (L140-214)
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

/// Enforces exit flags and withdraws the batch, treating zero as withdraw-all.
/// Returns each asset's actual pool payout.
fn settle_withdraw(
    env: &Env,
    account: &mut Account,
    recipient: &Address,
    aggregated: &AggregatedPayments,
    cache: &mut Context,
) -> Vec<HubPayment> {
    let mut entries: Vec<PoolWithdrawEntry> = Vec::new(env);
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

    let results = apply_withdraw_batch(
        env,
        account,
        recipient,
        WithdrawKind::Normal,
        events::PositionAction::Withdraw,
        &entries,
        cache,
    );
    let mut paid: Vec<HubPayment> = Vec::new(env);
    for_each_leg(env, &entries, &results, |entry, result| {
        paid.push_back((entry.action.hub_asset, result.actual_amount));
    });
    paid
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L36-79)
```rust
pub(crate) fn process_liquidation(
    env: &Env,
    liquidator: &Address,
    account_id: u64,
    debt_payments: &Vec<HubPayment>,
    seize_mode: SeizeMode,
) -> u64 {
    liquidator.require_auth();
    validation::require_not_flash_loaning(env);

    let mut account = storage::get_account(env, account_id);

    let mut cache = Context::new(env);

    require_non_empty_payments(env, debt_payments);

    // Reject an unusable receiver before moving tokens.
    let mut receiver = resolve_seize_receiver(
        env, liquidator, account_id, &account, seize_mode, &mut cache,
    );

    // Share payment normalization and positivity checks with the estimate view.
    let liquidation_plan = plan::build_liquidation_plan(env, &account, debt_payments, &mut cache);
    let offered = liquidation_plan
        .repayment
        .full_close
        .then(|| payments::aggregate_positive_payments(env, debt_payments));

    let result = liquidation_plan.into_result();

    require_non_empty_payments(env, &result.repaid);

    let received_usd = apply::apply_liquidation_repayments(
        env,
        liquidator,
        &mut account,
        &result.repaid,
        offered.as_ref(),
        &mut cache,
    );

    // Under-delivering debt tokens must reduce the collateral awarded.
    let repay_usd = math::sum_repaid_usd(env, &result.repaid);
    let seized = math::scale_seizures_to_received(env, &result.seized, received_usd, repay_usd);
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

**File:** contracts/pool/src/ops/withdraw.rs (L30-50)
```rust
pub(crate) fn apply(
    env: &Env,
    receiver: &Address,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> (PoolPositionMutation, MarketStateSnapshot) {
    let outcome = accounting(env, is_liquidation, entry);

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
    (outcome.mutation, outcome.snapshot)
```

**File:** contracts/pool/src/ops/withdraw.rs (L57-89)
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

    let snapshot = cache.commit();
    let mutation = cache.position_mutation(remaining, gross_amount);
    WithdrawOutcome {
        cache,
        mutation,
        snapshot,
        net_transfer,
    }
}
```

**File:** contracts/pool/src/ops/withdraw.rs (L111-118)
```rust
fn gate_and_debit(env: &Env, cache: &mut Cache, net_transfer: i128, skip_utilization_check: bool) {
    cache.require_reserves(net_transfer);

    if !skip_utilization_check {
        guards::require_utilization_below_max(env, cache);
    }
    guards::require_supply_for_debt(env, cache);
    cache.debit_cash(net_transfer);
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

**File:** contracts/controller/src/positions/liquidation/bad_debt.rs (L14-60)
```rust
pub(crate) fn execute_bad_debt_cleanup(
    env: &Env,
    cache: &mut Context,
    account_id: u64,
    account: &Account,
    totals: &AccountRiskTotals,
) {
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

**File:** contracts/pool/src/interest.rs (L68-89)
```rust
/// Socializes `bad_debt` by reducing the supply index (capped at total supply value).
///
/// Used when seizing unpaid debt: remaining supplier claims shrink pro-rata.
/// No-op when total supplied value is zero. Floors the resulting index at
/// [`SUPPLY_INDEX_FLOOR_RAW`] to avoid a zero index.
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

**File:** contracts/pool/src/cache/scale.rs (L49-67)
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

**File:** contracts/controller/src/positions/liquidation/plan.rs (L14-44)
```rust
pub(crate) fn build_liquidation_plan(
    env: &Env,
    account: &Account,
    raw_payments: &Vec<HubPayment>,
    cache: &mut Context,
) -> LiquidationPlan {
    if account.borrow_positions.is_empty() {
        panic_with_error!(env, CollateralError::HealthFactorTooHigh);
    }

    for (hub_asset, _) in raw_payments.iter() {
        enforce_spoke_asset_flags(
            env,
            cache,
            account.spoke_id,
            &hub_asset,
            FreezePolicy::AllowOnExit,
        );
    }

    let totals = risk::calculate_account_risk_totals(
        env,
        cache,
        &account.supply_positions,
        &account.borrow_positions,
    );
    assert_with_error!(
        env,
        totals.health_factor < Wad::ONE,
        CollateralError::HealthFactorTooHigh
    );
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
