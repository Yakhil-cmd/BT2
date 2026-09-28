### Title
Unprivileged deposits can indefinitely DoS scheduled spoke-asset removal - ([File: contracts/controller/src/config/asset.rs](contracts/controller/src/config/asset.rs))

### Summary

A scheduled `RemoveAssetFromSpoke` governance operation executes `Controller::remove_asset_from_spoke`, which reverts whenever the target market has nonzero supplied or borrowed scaled usage. [1](#0-0)  An unprivileged user can therefore frontrun execution with `Controller::supply(caller, 0, spoke_id, vec![(hub_asset, 1)])`, create a new account, and make `supplied_scaled_ray` nonzero. [2](#0-1)  If the target call reverts, `finish_execute` is never reached, so the ready operation remains scheduled and the same one-unit deposit can be withdrawn and reused to block later execution attempts. [3](#0-2) 

### Finding Description

`Governance::execute` prepares a ready timelock operation and invokes the target contract before clearing its scheduled state. [4](#0-3)  A `RemoveAssetFromSpoke` proposal resolves to the controller `remove_asset_from_spoke` function without checking market usage at proposal time. [5](#0-4)  At execution, `remove_asset_from_spoke` requires both `usage.supplied_scaled_ray == 0` and `usage.borrowed_scaled_ray == 0`, reverting with `SpokeAssetInUse` otherwise. [1](#0-0) 

A normal supply call from a new `account_id = 0` is permissionless and creates an attacker-owned account. [6](#0-5)  The deposit path adds the measured token transfer to the account’s supply position, and `merge_supply_leg` records the resulting scaled amount as spoke supply usage. [7](#0-6) [8](#0-7)  Thus a single positive base unit is sufficient to change the removal precondition from true to false.

The attacker does not need to keep funds locked between failed executions: `Controller::withdraw(caller, account_id, vec![(hub_asset, 0)], None)` uses zero as withdraw-all and returns the supplied amount. [9](#0-8) [10](#0-9) 

### Impact Explanation

This allows an unprivileged address to repeatedly prevent a queued market-removal operation from completing for as long as the market remains open to entry. The failed execution does not consume the operation because the controller call reverts before `finish_execute` clears it. [11](#0-10) 

The issue is analogous to the reported LP-cap DoS: ordinary, economically reversible user liquidity changes a governance operation’s execution-time precondition and makes the operation revert. Unlike the cap updates, XOXNO cap reductions themselves do not compare the proposed cap with existing usage, so `edit_asset_in_spoke` is not vulnerable to the same condition. [12](#0-11) [13](#0-12) 

### Likelihood Explanation

Likelihood is moderate where a listed market has positive supply-cap headroom and no blocking flags. The attacker only needs one token base unit, an ordinary `supply` call, and monitoring of ready governance operations; `execute` can even be driven with `executor=None` by any address once ready. [14](#0-13) 

The attack is bounded by existing entry controls: it cannot add supply when global pause, market `paused`/`frozen`, a zero or exhausted supply cap, or position/account gates reject the deposit. [15](#0-14)  Governance or the guardian can consequently work around it by first tightening the market’s flags, but a standalone scheduled removal remains frontrunnable.

### Recommendation

Do not make asset removal depend on instantaneous zero usage, or atomically prevent new usage before evaluating removal. Suitable options include:

- Have `remove_asset_from_spoke` first persist `paused=true` and `frozen=true`, advance the flags epoch, and then either remove the listing or mark it `removal_pending`.
- Alternatively split removal into `disable_asset_entries` and `finalize_asset_removal`, where finalization still fails while usage remains but users cannot repeatedly reopen usage.
- If atomic removal must remain, schedule an operation that tightens all entry flags in the same controller call before checking `SpokeUsageRaw`.

### Proof of Concept

Conceptual call sequence against deployed contracts:

```text
// Governance has already scheduled:
// AdminOperation::RemoveAssetFromSpoke {
//     hub_asset: HUB_ASSET,
//     spoke_id: SPOKE_ID,
// }

// 1. Wait until the operation becomes Ready.
governance.get_operation_state(operation_id) == Ready;

// 2. Frontrun execution with a one-base-unit deposit.
// `account_id = 0` creates a new attacker-owned account.
attacker_account = controller.supply(
    caller = attacker,
    account_id = 0,
    spoke_id = SPOKE_ID,
    assets = [(HUB_ASSET, 1)],
);

// 3. Anyone may attempt to execute the ready operation.
// The controller reaches the usage check:
// usage.supplied_scaled_ray > 0 => SpokeAssetInUse.
governance.execute(
    executor = None,
    target = controller,
    function = "remove_asset_from_spoke",
    args = [HUB_ASSET, SPOKE_ID],
    predecessor = ZERO_BYTES32,
    salt = proposal_salt,
);
// => reverts; operation remains scheduled.

// 4. Recover the deposit, leaving no required attacker exposure.
controller.withdraw(
    caller = attacker,
    account_id = attacker_account,
    withdrawals = [(HUB_ASSET, 0)], // zero means withdraw-all
    to = None,
);

// 5. Repeat steps 2–4 before each subsequent execution attempt.
```

The critical precondition is created by `merge_supply_leg`, which applies the supply-side scaled usage delta after the pool credits the deposit. [16](#0-15)  The reverting governance target is the zero-usage assertion in `remove_asset_from_spoke`. [17](#0-16)

### Citations

**File:** contracts/controller/src/config/asset.rs (L36-43)
```rust
fn upsert_spoke_asset(env: &Env, args: &SpokeAssetArgs, mutation: SpokeAssetMutation) {
    common_validate_risk_bounds(env, args.ltv, args.threshold, args.bonus);
    common_validate_liquidation_fees(env, args.liquidation_fees);
    assert_with_error!(
        env,
        args.supply_cap >= 0 && args.borrow_cap >= 0,
        CollateralError::InvalidBorrowParams
    );
```

**File:** contracts/controller/src/config/asset.rs (L79-93)
```rust
    let config = SpokeAssetConfig {
        is_collateralizable: args.can_collateral,
        is_borrowable: args.can_borrow,
        paused: args.paused,
        frozen: args.frozen,
        no_seize: args.no_seize,
        loan_to_value: args.ltv,
        liquidation_threshold: args.threshold,
        liquidation_bonus: args.bonus,
        liquidation_fees: args.liquidation_fees,
        supply_cap: args.supply_cap,
        borrow_cap: args.borrow_cap,
    };
    storage::set_spoke_asset(env, args.spoke_id, &hub_asset, &config);
    if stored.is_none_or(|stored| flags(&stored) != flags(&config)) {
```

**File:** contracts/controller/src/config/asset.rs (L189-201)
```rust
/// Removes and emits a listed asset only when both scaled usage amounts are zero.
pub(crate) fn remove_asset_from_spoke(env: &Env, hub_asset: HubAssetKey, spoke_id: u32) {
    assert_with_error!(
        env,
        storage::get_spoke_asset(env, spoke_id, &hub_asset).is_some(),
        SpokeError::AssetNotInSpoke
    );
    let usage = storage::get_spoke_usage(env, spoke_id, &hub_asset).unwrap_or_default();
    assert_with_error!(
        env,
        usage.supplied_scaled_ray == 0 && usage.borrowed_scaled_ray == 0,
        SpokeError::SpokeAssetInUse
    );
```

**File:** contracts/controller/src/positions/supply.rs (L38-64)
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

```

**File:** contracts/controller/src/positions/supply.rs (L99-135)
```rust
/// Checks supply entry gates and credits measured pool receipts.
pub(crate) fn process_deposit(
    env: &Env,
    caller: &Address,
    account: &mut Account,
    aggregated: &AggregatedPayments,
    cache: &mut Context,
) {
    validate_position_entry_gates(
        env,
        account,
        aggregated,
        cache,
        AccountPositionType::Deposit,
    );
    let pool_addr = cache.cached_pool_address();
    let mut entries: Vec<PoolSupplyEntry> = Vec::new(env);
    for (hub_asset, amount_in) in aggregated.iter() {
        let asset_config: AssetConfig = cache.require_spoke_asset(account.spoke_id, &hub_asset);
        let received = payments::transfer_amount_measured(
            env,
            &hub_asset.asset,
            caller,
            &pool_addr,
            amount_in,
            GenericError::AmountMustBePositive,
        );
        let position = account.get_or_create_supply_position(&hub_asset, &asset_config);
        entries.push_back(PoolSupplyEntry {
            action: make_pool_action(&position, received, hub_asset.clone()),
        });
    }

    let results = pool_supply_call(env, &pool_addr, &entries);
    for_each_leg(env, &entries, &results, |entry, result| {
        merge_supply_leg(env, account, &entry.action, &result, cache);
    });
```

**File:** contracts/controller/src/positions/supply.rs (L138-157)
```rust
/// Withdraws for an authorized owner/delegate and checks post-pool solvency.
/// Zero requests withdraw all; returns the pool's actual payouts per asset.
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
```

**File:** contracts/controller/src/positions/supply.rs (L273-323)
```rust
/// Merges a supply result, refreshing risk parameters and updating usage,
/// market index, and event state.
pub(crate) fn merge_supply_leg(
    env: &Env,
    account: &mut Account,
    action: &PoolAction,
    result: &PoolPositionMutation,
    cache: &mut Context,
) {
    let hub_asset = &action.hub_asset;
    let asset_config: AssetConfig = cache.require_spoke_asset(account.spoke_id, hub_asset);

    let mut position = account.get_or_create_supply_position(hub_asset, &asset_config);
    let old_scaled = position.scaled_amount;

    refresh_supply_risk_params(
        env,
        cache,
        account,
        hub_asset,
        &mut position,
        &asset_config,
        RiskRefreshScope::FullTuple,
    );

    let outcome = LegOutcome::from(result);
    position.scaled_amount = outcome.new_scaled;

    apply_leg_usage(
        env,
        cache,
        account.spoke_id,
        UsageSide::Supply,
        hub_asset,
        LegDirection::Entry {
            asset_decimals: result.asset_decimals,
        },
        old_scaled,
        &outcome,
    );

    cache.put_market_index(hub_asset, &outcome.market_index);
    cache.record_supply_position_update(
        events::PositionAction::Supply,
        hub_asset,
        outcome.market_index.supply_index,
        action.amount,
        &position,
    );

    update_or_remove_supply_position(account, hub_asset, &position);
```

**File:** contracts/governance/src/timelock/lifecycle.rs (L81-109)
```rust
/// Executes a scheduled operation against `target` once its delay has elapsed and
/// it has not expired, and returns the invocation's result. Rejects operations
/// that target this contract itself (use `execute_self` for those). Clears the
/// operation's scheduled state on completion.
pub(crate) fn execute(
    env: &Env,
    executor: Option<Address>,
    target: Address,
    function: Symbol,
    args: Vec<Val>,
    predecessor: BytesN<32>,
    salt: BytesN<32>,
) -> Val {
    assert_with_error!(
        env,
        target != env.current_contract_address(),
        GenericError::InternalError
    );
    let operation = Operation {
        target,
        function,
        args,
        predecessor,
        salt,
    };
    let operation_id = prepare_execute(env, executor.as_ref(), &operation);
    let result = execute_operation(env, &operation);
    finish_execute(env, &operation_id);
    result
```

**File:** contracts/governance/src/op.rs (L240-248)
```rust
        AdminOperation::RemoveAssetFromSpoke(args) => controller_operation(
            env,
            "remove_asset_from_spoke",
            vec![
                env,
                args.hub_asset.clone().into_val(env),
                args.spoke_id.into_val(env),
            ],
        ),
```

**File:** contracts/controller/src/lib.rs (L90-102)
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
```

**File:** contracts/controller/src/lib.rs (L117-128)
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
```

**File:** contracts/governance/src/api.rs (L53-67)
```rust
    /// Executes a ready, non-expired scheduled op against `target` (not this
    /// contract). If `executor` is `Some`, requires that address to auth and
    /// hold `EXECUTOR_ROLE`; if `None`, no executor role check (anyone may
    /// drive execution of a ready op). Clears scheduled state on success.
    fn execute(
        env: Env,
        executor: Option<Address>,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        predecessor: BytesN<32>,
        salt: BytesN<32>,
    ) -> Val {
        lifecycle::execute(&env, executor, target, function, args, predecessor, salt)
    }
```
