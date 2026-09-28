### Title
Dust collateral top-up permanently griefs permissionless `clean_bad_debt` — (File: contracts/controller/src/positions/liquidation/mod.rs)

### Summary
`clean_bad_debt` is permissionless but gated by `is_socializable_bad_debt`: collateral must be at or below the fixed $5 dust threshold. `supply` is also permissionless for third parties as long as the target account already holds a supply position in that hub asset. A griefer can frontrun — or keep perpetually rearming — a dust top-up of the victim account's existing collateral, pushing `total_collateral` above `BAD_DEBT_USD_THRESHOLD` so every `clean_bad_debt` call reverts with `CannotCleanBadDebt`. This mirrors the report's class: a small token amount executed by an attacker makes a balance-based admission check fail for everyone else.

### Finding Description
- `process_clean_bad_debt` only requires `caller.require_auth()` plus no active flash loan, then runs `socialize_bad_debt` with `BadDebtGate::DustCapped`, which demands `is_socializable_bad_debt(total_debt, total_collateral)` — i.e., `D > C` and `C <= 5 WAD`. [1](#0-0) 
- The threshold is fixed at compile time: `BAD_DEBT_USD_THRESHOLD = DEFAULT_MIN_BORROW_COLLATERAL_USD_WAD` ($5). [2](#0-1) 
- Third-party `supply` is deliberately allowed against any existing account for assets it already supplies: `require_third_party_existing_supply` only checks `account.supply_positions.contains_key(hub_asset)`, and `process_deposit` then credits the measured receipt to the victim's position. [3](#0-2) [4](#0-3) 
- Nothing restricts the size or timing of a top-up; `supply` has no minimum, no solvency check (supply skips risk checks), and no consent from the account owner. There is no per-asset "donation" exception — the attacker's shares merge into the victim's collateral and are counted by `calculate_account_risk_totals` in `total_collateral`.

Attack loop: account sits at `C = $4.9x`, `D > C` → cleanup eligible. Griefer calls `supply(griefer, account_id, spoke_id, [(existing_collateral_asset, δ)])` where `δ` prices above `5.00 − C`. Every subsequent `clean_bad_debt` reverts at the `assert_with_error!(env, admits, CannotCleanBadDebt)` gate. If a liquidation later drives collateral back under $5, the griefer re-tops-up; the cost per rearm is at most ~$5 of collateral, which is destroyed anyway (seized by liquidators or reclassified as revenue on an eventual forced cleanup), so the griefer's spend is bounded while the delay is not.

### Impact Explanation
Bad debt that is eligible for socialization can be kept stranded: while `clean_bad_debt` is griefed, the insolvent account's debt keeps accruing interest at the borrow index, enlarging the eventual `supply_index` write-down borne by suppliers in the debt markets (`apply_bad_debt_to_supply_index`). The only fallback is the owner-only, timelocked `force_socialize_bad_debt`, which requires a governance Sensitive-tier proposal — so the grief converts a permissionless, atomic cleanup into an unbounded delay during which protocol insolvency grows. This is "temporary freezing of funds / delayed loss allocation" with real cost: supplier claims are written down by a larger amount the longer the account sits, and a full liquidation path may also be unavailable for legs flagged `no_seize` or markets paused for repayment, where cleanup is the only exit. [5](#0-4) 

### Likelihood Explanation
Medium. Preconditions: an insolvent account whose collateral is at or drifts below $5, and at least one existing supply position (always true — the gate requires collateral to exist). The attacker needs only a wallet and a dust amount of an asset the account already supplies; no delegate status, no oracle manipulation, no privileged action. The per-round cost is bounded by the $5 threshold and is partially recovered only through liquidation seizure, which the attacker does not control. The attack is front-runnable on every `clean_bad_debt` submission since both entrypoints are permissionless and the check reads fresh account state.

### Recommendation
- Exclude third-party top-up shares from the cleanup gate, or measure the dust gate on the collateral that existed before the most recent block/ledger of top-ups.
- Simpler: make `clean_bad_debt` seize-and-socialize atomically — since cleanup converts all remaining supply to revenue anyway, the dust cap could be evaluated on collateral *net of* shares minted within a recent ledger window, or the gate could accept "collateral attributable to positions older than N ledgers ≤ $5".
- Alternatively, allow `clean_bad_debt` callers to opt into burning un-backed dust: treat top-ups received in the same ledger as the cleanup as already-revenue so the gate cannot be moved by same-transaction dust.
- Any fix must preserve INV-AUTH-03 (third parties can still top up) while ensuring a single unprivileged top-up cannot flip the socialization predicate.

### Proof of Concept
1. Alice supplies 100,000 USDC, borrows 6 ETH ($12,000). USDC price crashes so collateral = $4.90, debt > collateral. `can_be_liquidated` is true and `is_socializable_bad_debt` holds (`$4.90 ≤ $5`).
2. Keeper submits `clean_bad_debt(caller, alice_id)`.
3. Griefer observes it and submits `supply(griefer, alice_id, alice_spoke, [(hub_asset(USDC), 200_000)])` (≈$0.20 top-up). `require_third_party_existing_supply` passes because Alice already holds a USDC supply position; the measured receipt is credited to her account.
4. `clean_bad_debt` executes: `total_collateral ≈ $5.10 > 5 WAD` → `assert_with_error!` reverts with `CannotCleanBadDebt`.
5. Any liquidator reducing collateral back under $5 re-enables the gate, but the griefer frontruns the next cleanup again with a fresh top-up. Repeatable indefinitely at ≤ ~$5 per round, while the ETH debt accrues and the eventual `supply_index` write-down on ETH suppliers grows. Only a timelocked `force_socialize_bad_debt` governance action terminates the loop.

Code path: `Controller::supply` → `positions::process_supply` → `require_third_party_existing_supply` (passes) → `process_deposit` credits shares; `Controller::clean_bad_debt` → `process_clean_bad_debt` → `socialize_bad_debt(DustCapped)` → gate fails. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/controller/src/positions/liquidation/mod.rs (L196-238)
```rust
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

**File:** contracts/controller/src/constants.rs (L3-3)
```rust
pub const BAD_DEBT_USD_THRESHOLD: i128 = DEFAULT_MIN_BORROW_COLLATERAL_USD_WAD;
```

**File:** contracts/controller/src/positions/supply.rs (L40-63)
```rust
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

**File:** contracts/controller/src/positions/supply.rs (L78-97)
```rust
fn require_third_party_existing_supply(
    env: &Env,
    account_id: u64,
    resolved_account_id: u64,
    caller: &Address,
    account: &Account,
    aggregated: &AggregatedPayments,
) {
    if account_id != 0
        && !account::is_owner_or_delegate(env, resolved_account_id, caller, &account.owner)
    {
        for (hub_asset, _) in aggregated.iter() {
            assert_with_error!(
                env,
                account.supply_positions.contains_key(hub_asset.clone()),
                GenericError::NotAuthorized
            );
        }
    }
}
```

**File:** contracts/controller/src/positions/supply.rs (L116-135)
```rust
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

**File:** docs/reference/runbooks/force-socialize-bad-debt.md (L17-40)
```markdown
## Before scheduling

1. Confirm the network, target controller, governance contract, account id,
   NFT owner, positions and spoke. `force_socialize_bad_debt` is owner-only.
   Governance, the controller owner, schedules `ForceSocializeBadDebt` on the
   Sensitive delay tier; follow the
   [governance interface](../endpoints.md#governance) for proposal and execution.
2. Confirm insolvency with the same risk totals the entrypoint uses: ceil-valued
   debt (`AccountRiskTotals.total_debt`) strictly greater than half-up unweighted
   collateral (`AccountRiskTotals.total_collateral`). `get_total_collateral_usd`
   (`make <network> getCollateralUsd <account-id>`) returns that collateral
   total. Do **not** use `get_total_borrow_usd` for the debt side: it returns
   half-up display debt, which can disagree with ceil risk debt near the boundary
   ([INV-RISK-02](../invariants.md#inv-risk-02)). To check `D > C` exactly,
   simulate `force_socialize_bad_debt`. If collateral is at or below $5 and
   `D > C` holds, use permissionless `clean_bad_debt` instead; it needs no
   governance.
3. Check every position's price status. Missing or invalid required prices
   prevent cleanup; listing flags and global pause do not waive pricing.
4. Snapshot debt shares, supply shares, revenue, cash, indexes and spoke usage
   for all affected markets. Preserve the ledger/time and price snapshot.
5. Simulate the intended invocation and prepare any required archived-entry
   restoration. Ownership lookup and NFT burn both require readable NFT state.

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
