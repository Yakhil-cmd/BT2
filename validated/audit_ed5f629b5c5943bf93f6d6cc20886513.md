### Title

Supplier withdraws at pre-loss supply index before permissionless bad-debt socialization - (File: contracts/pool/src/ops/withdraw.rs)

### Summary

A supplier can observe a publicly liquidatable or cleanable account, withdraw its market supply at the current `supply_index`, and thereby avoid the later bad-debt write-down. `contracts/pool/src/ops/withdraw.rs` checks cash, utilization, and nonzero supply, but does not account for imminent losses that have not yet been socialized. [1](#0-0) 

### Finding Description

`Controller.withdraw` lets an account owner or delegate request a full withdrawal by passing amount `0`, which is converted to the withdraw-all sentinel and sent to the pool. [2](#0-1) 

The pool resolves that request against the current `supply_index`, burns the shares, verifies only reserves, utilization, and the zero-supply-with-debt invariant, then debits cash and transfers tokens. [3](#0-2) [1](#0-0) 

There is no `require_backed_market` check on exit, and `backing_shortfall` values all outstanding debt at face value until a liquidation or cleanup actually socializes it. [4](#0-3) 

When `clean_bad_debt` or a liquidation later invokes `seize_positions`, the borrow-side entry writes the unpaid debt down by reducing the affected market's `supply_index`. [5](#0-4) [6](#0-5) 

Consequently, the first supplier to exit receives the pre-write-down value, while the same loss is concentrated on suppliers remaining in the market. [7](#0-6) 

### Impact Explanation

This is a redistribution of realized bad debt from the exiting supplier to remaining suppliers. The attacker can recover the full current claim while remaining suppliers absorb an amplified index loss; the repository's regression test demonstrates a supplier exiting whole and increasing another supplier's loss by more than three times. [8](#0-7) 

For remaining suppliers, this produces loss of funds that would otherwise have been shared pro rata across the larger supplier base. [9](#0-8) 

### Likelihood Explanation

No privileged role is required: a supplier calls `withdraw`, while any authenticated caller can invoke `clean_bad_debt` for an eligible insolvent account or `liquidate` for an unhealthy account. [10](#0-9) [11](#0-10) [12](#0-11) 

The trigger is public market and oracle state: once an account is visibly insolvent but before cleanup commits, the supplier can submit withdrawal first. [13](#0-12) 

The amount extractable is bounded by cash and the post-withdrawal utilization cap, so the attack is strongest in low-utilization markets or markets configured with `max_utilization >= RAY`. [14](#0-13) [15](#0-14) 

### Recommendation

Introduce a loss-aware exit mechanism so suppliers cannot redeem at an index that excludes already-identifiable bad debt. Concretely, add a withdrawal delay/claim queue or a market-level pending-loss state: once an account is marked insolvent or socialization is initiated, withdrawals from the affected debt market must value shares at the post-write-down index rather than paying at the stale index. [16](#0-15) [6](#0-5) 

At minimum, require exits to preserve market backing under a conservative estimate of pending unrecoverable debt, rather than checking only `cash >= withdrawal` and utilization. [1](#0-0) [17](#0-16) 

### Proof of Concept

1. Alice supplies collateral and borrows `ETH`; Bob supplies most of the `ETH` liquidity and Carol supplies the remainder. [18](#0-17) 

2. The collateral price crashes, making Alice publicly liquidatable, but no borrow-side `seize_positions` call has yet reduced the `ETH` `supply_index`. [13](#0-12) 

3. Bob calls `withdraw(caller = Bob, account_id = bob_account, withdrawals = [(eth_hub_asset, 0)], to = Some(Bob))`; amount `0` selects withdraw-all. [19](#0-18) [2](#0-1) 

4. The pool converts Bob's shares using the still-high `supply_index`, checks only reserves/utilization/nonzero supply, debits cash, and pays Bob. [3](#0-2) [1](#0-0) 

5. Any caller then liquidates Alice or calls `clean_bad_debt(caller, alice_account)`; the borrow-side seizure calls `apply_bad_debt_to_supply_index`, lowering `ETH` suppliers' claims. [20](#0-19) [5](#0-4) 

6. Because Bob's shares were already burned, Carol's remaining shares absorb a larger fraction of the write-down; the existing test verifies Bob exits whole and Carol's loss increases more than threefold. [21](#0-20)

### Citations

**File:** contracts/pool/src/ops/withdraw.rs (L63-79)
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
```

**File:** contracts/pool/src/ops/withdraw.rs (L93-105)
```rust
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

**File:** contracts/controller/src/positions/supply.rs (L140-158)
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
```

**File:** contracts/controller/src/positions/supply.rs (L189-198)
```rust
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
```

**File:** contracts/pool/src/guards.rs (L19-33)
```rust
pub(crate) fn require_utilization_below_max(env: &Env, cache: &Cache) {
    if cache.supplied() == Ray::ZERO || cache.params().max_utilization >= Ray::ONE {
        return;
    }

    let borrowed = cache.borrowed().mul_ceil(env, cache.borrow_index());
    if borrowed == Ray::ZERO {
        return;
    }
    let supplied = cache.supplied().mul_floor(env, cache.supply_index());
    assert_with_error!(
        env,
        supplied > Ray::ZERO && borrowed.div_ceil(env, supplied) <= cache.params().max_utilization,
        CollateralError::UtilizationAboveMax
    );
```

**File:** contracts/pool/src/guards.rs (L49-65)
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

**File:** tests/test-harness/tests/controller/bad_debt_index.rs (L396-400)
```rust
/// Bad debt is written down only when a liquidation or cleanup call runs, and
/// `backing_shortfall` counts the unrecoverable debt at face value until then.
/// A supplier can exit at the pre-write-down index and leave the loss on the
/// suppliers who stay. Runs the same crash with Bob passive and with Bob
/// exiting first, and compares Carol's loss.
```

**File:** tests/test-harness/tests/controller/bad_debt_index.rs (L403-408)
```rust
    // Scenario A: nobody dodges. Bob 75%, Carol 25% of the ETH supply.
    let mut a = setup();
    a.supply(BOB, "ETH", 75.0);
    a.supply(CAROL, "ETH", 25.0);
    a.supply(ALICE, "USDC", 10.0);
    a.borrow(ALICE, "ETH", 0.003);
```

**File:** tests/test-harness/tests/controller/bad_debt_index.rs (L426-461)
```rust
    // The crash is public state. Alice is insolvent from here on, but no
    // write-down has been applied yet.
    b.set_price("USDC", usd_cents(10));
    b.assert_liquidatable(ALICE);

    // Bob exits at the un-written-down index. No gate stops him: the
    // liquidation buffer only guards borrow draws, and `backing_shortfall`
    // still values Alice's uncollateralised debt at face.
    b.withdraw_all(BOB, "ETH");
    let bob_recovered = b.token_balance(BOB, "ETH") - bob_wallet_before;

    b.liquidate(LIQUIDATOR, ALICE, "ETH", 0.001);
    let carol_loss_b = carol_before_b - b.supply_balance(CAROL, "ETH");

    assert!(
        bob_recovered >= bob_before_b,
        "Bob exits whole: supplied={:.9} recovered={:.9}",
        bob_before_b,
        bob_recovered
    );
    assert!(
        carol_loss_b > carol_loss_a,
        "dodging must push loss onto Carol: A={:.9} B={:.9}",
        carol_loss_a,
        carol_loss_b
    );

    // Carol holds 25% of supply, so passing the whole loss to her is ~4x.
    let amplification = carol_loss_b / carol_loss_a;
    assert!(
        amplification > 3.0,
        "expected ~4x concentration onto the remaining supplier, got {:.3}x \
         (A={:.9} B={:.9})",
        amplification,
        carol_loss_a,
        carol_loss_b
```

**File:** docs/explanation/decisions.md (L107-112)
```markdown
### ADR-0012: Supplier-index loss allocation

Eligible bad debt is removed by reducing the affected market's supply index,
subject to a nonzero floor. Supplier claims in that market bear the write-down.
The floor protects share conversions but can leave unpaid backing; a displayed
claim does not guarantee that the supplier can withdraw that amount.
```

**File:** contracts/controller/src/lib.rs (L160-164)
```rust
    /// Socializes insolvent debt into the supply index and removes the account
    /// when remaining collateral is at or below the dust cap. Permissionless;
    /// requires caller authorization.
    fn clean_bad_debt(env: Env, caller: Address, account_id: u64) {
        positions::liquidation::process_clean_bad_debt(&env, &caller, account_id);
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L36-44)
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
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-199)
```rust
/// Authorizes permissionless dust-gated cleanup outside flash loans.
pub(crate) fn process_clean_bad_debt(env: &Env, caller: &Address, account_id: u64) {
    caller.require_auth();
    validation::require_not_flash_loaning(env);
    clean_bad_debt_standalone(env, account_id);
```

**File:** tests/test-harness/tests/composition/supplier_exit_before_socialization_is_bounded_by_utilization.rs (L1-4)
```rust
//! GH-15. A supplier can leave, trigger the permissionless clean-up, and come
//! back in one invocation, dodging its share of the write-down. The exit
//! size is bounded by `max_utilization`: past it the whole script reverts.

```

**File:** contracts/controller/src/positions/liquidation/bad_debt.rs (L35-49)
```rust
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
