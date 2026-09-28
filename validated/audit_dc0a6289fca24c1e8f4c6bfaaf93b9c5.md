### Title
Supply-index floor leaves phantom claims after a complete bad-debt write-down, freezing market entry - (File: contracts/pool/src/interest.rs)

### Summary
A permissionless bad-debt cleanup can reduce a market’s calculated supply index to zero, but `apply_bad_debt_to_supply_index` clamps it back to `SUPPLY_INDEX_FLOOR_RAW` while leaving all scaled supply shares outstanding. This creates a residual supplier claim backed by no debt and potentially no cash, making `backing_shortfall` permanently nonzero until an unrelated party recapitalizes the market. This is a Medium-severity temporary freeze of funds and market availability.

### Finding Description
`Controller::clean_bad_debt(caller, account_id)` is permissionless apart from `caller.require_auth()` and the flash-loan guard. [1](#0-0)  It admits an insolvent account whose remaining collateral is at or below the dust threshold, then submits every remaining supply and debt position to `Pool::seize_positions`. [2](#0-1) [3](#0-2) 

For a borrow-side entry, the pool computes the full debt value, writes it down against the supply index, and burns the debt shares. [4](#0-3)  When bad debt is at least the total supplied value, `remaining` is zero and `reduction_factor` is zero, but the result is raised to `RAY / 1_000`. [5](#0-4) [6](#0-5) 

The corresponding `supplied` shares are not removed or reset. Consequently, every outstanding share retains a floored claim equal to approximately 0.1% of its pre-wipeout value. `backing_shortfall` compares floored supply claims against `cash + ceiled debt`; after the debt burn this residual claim can exceed all remaining backing. [7](#0-6) 

### Impact Explanation
Once the floored residual claim exceeds cash, `require_backed_market` returns a positive shortfall and every subsequent supply leg reverts with `PoolInsolvent`. [8](#0-7) [9](#0-8)  Withdrawals of the stranded claims also fail whenever their gross value exceeds the remaining cash because `require_reserves` runs before cash is debited. [10](#0-9) 

The affected market remains unusable until someone voluntarily calls `Controller::recapitalize(payer, hub_asset, amount)` and funds claims that should have been fully written down. [11](#0-10)  This is temporary freezing of funds and protocol-level insolvency: normal suppliers cannot enter, residual claims cannot reliably exit, and recapitalization is spent satisfying an artifact of the floor rather than recovering genuine bad debt.

### Likelihood Explanation
The triggering entrypoint requires no privileged role and can target any account satisfying the dust-capped insolvency gate. [1](#0-0) [12](#0-11) 

The complete write-down condition requires bad debt at least equal to total supplied value and remaining cash below the floored residual claim. This is less likely than a partial bad-debt event, but it is reachable through ordinary borrowing, supplier withdrawals, interest-index divergence, and collateral deterioration without oracle manipulation or privileged actions.

### Recommendation
Do not use a nonzero supply-index floor to represent a complete write-down while retaining the same scaled supply shares. Use an explicit market reset/share epoch so old positions have zero claims while new deposits mint under a fresh index, or otherwise atomically retire all outstanding supply claims when `remaining == 0`. Add an end-to-end invariant that after `bad_debt >= total_supplied_value`, `backing_shortfall == 0` relative to surviving claims.

### Proof of Concept
Let a debt market have scaled supply `S`, supply index `I`, scaled debt `D`, borrow index `B`, and cash `C`, with:

```text
ceil(D * B) >= S * I
C < floor(S * (RAY / 1000))
```

1. Create or identify an account whose collateral is at or below the socialization dust threshold and whose debt includes `D`.
2. As an unprivileged caller, invoke `Controller::clean_bad_debt(attacker, victim_account_id)`. The authorization and dust gates permit the call. [1](#0-0) [12](#0-11) 
3. The pool’s borrow-side seize computes `bad_debt = ceil(D * B)`, calls `apply_bad_debt_to_supply_index`, and burns `D`. [4](#0-3) 
4. Because `bad_debt >= S * I`, `remaining` and `reduction_factor` are zero; the implementation then sets the index to `RAY / 1000` instead of leaving surviving claims at zero. [5](#0-4) 
5. The market still has `S` scaled supply shares, so `backing_shortfall` returns `floor(S * floor_index) - C > 0`. [7](#0-6) 
6. Any subsequent `supply` reverts with `PoolInsolvent`, and a withdrawal larger than `C` reverts under `require_reserves`, leaving the market frozen until an external recapitalization pays the artificial residual. [9](#0-8) [10](#0-9)

### Citations

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-199)
```rust
/// Authorizes permissionless dust-gated cleanup outside flash loans.
pub(crate) fn process_clean_bad_debt(env: &Env, caller: &Address, account_id: u64) {
    caller.require_auth();
    validation::require_not_flash_loaning(env);
    clean_bad_debt_standalone(env, account_id);
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L229-237)
```rust
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

**File:** contracts/pool/src/ops/seize.rs (L23-28)
```rust
    match entry.side {
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
```

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

**File:** common/src/constants/pool.rs (L6-9)
```rust
/// Minimum value the supply index is clamped to when bad debt is written down against
/// suppliers, in raw ray units. Interest accrual does not apply this floor; it only guarantees
/// the index never decreases.
pub const SUPPLY_INDEX_FLOOR_RAW: i128 = RAY / 1_000;
```

**File:** contracts/pool/src/guards.rs (L49-57)
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
```

**File:** contracts/pool/src/guards.rs (L60-65)
```rust
/// Asset units by which supplier claims exceed cash + debt (0 if solvent).
pub(crate) fn backing_shortfall(cache: &Cache) -> i128 {
    let supplied_claim = cache.unscale_supply_floor(cache.supplied());
    let outstanding_debt = cache.unscale_borrow_ceil(cache.borrowed());
    let backing = cache.cash().saturating_add(outstanding_debt);
    supplied_claim.saturating_sub(backing).max(0)
```

**File:** contracts/pool/src/ops/supply.rs (L23-27)
```rust
    let (mut cache, mut position) = ops::load_leg(env, &entry.action);
    let amount = entry.action.amount;

    guards::require_backed_market(env, &cache);

```

**File:** contracts/pool/src/ops/withdraw.rs (L109-118)
```rust
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

**File:** contracts/controller/src/markets.rs (L142-163)
```rust
pub(crate) fn recapitalize(
    env: &Env,
    payer: Address,
    hub_asset: HubAssetKey,
    amount: i128,
) -> i128 {
    validation::require_authorized_caller(env, &payer);
    require_positive_amount(env, amount);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    // Prefund the pool and credit only its measured receipt.
    let received = payments::transfer_amount_measured(
        env,
        &hub_asset.asset,
        &payer,
        &pool_addr,
        amount,
        GenericError::AmountMustBePositive,
    );

    pool_recapitalize_call(env, &pool_addr, &hub_asset, &payer, received).actual_amount
```
