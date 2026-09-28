### Title
Unprivileged third-party `supply` top-up permanently blocks permissionless `clean_bad_debt` on insolvent accounts - (contracts/controller/src/positions/supply.rs)

### Summary
`clean_bad_debt` is the permissionless path that socializes an insolvent account's residual debt and deletes the account, but it only admits accounts whose unweighted collateral is at or below the fixed `BAD_DEBT_USD_THRESHOLD` ($5). `supply` lets any authenticated third party top up an existing supply leg of any account, and ordinary supply is explicitly exempt from post-action risk gates. An unprivileged attacker can therefore keep any bad-debt account's collateral marginally above $5 forever, so every `clean_bad_debt` call reverts with `CannotCleanBadDebt`, leaving toxic debt on the books until the timelocked owner-gated `force_socialize_bad_debt` intervenes.

### Finding Description
`process_clean_bad_debt` is callable by anyone: it only does `caller.require_auth()` plus the flash guard, then runs `socialize_bad_debt` with the `BadDebtGate::DustCapped` admission check [1](#0-0) . `DustCapped` evaluates `is_socializable_bad_debt(total_debt, total_collateral)`, which requires `debt > collateral` and `collateral <= BAD_DEBT_USD_THRESHOLD` ($5 WAD USD); anything above the cap reverts with `CannotCleanBadDebt` [2](#0-1) .

On the other side, `require_third_party_existing_supply` explicitly permits a caller who is neither the NFT owner nor a delegate to add to any hub asset the target account already supplies [3](#0-2) . `process_deposit` then credits measured receipts and `finalize_position_flow` is invoked for `PositionSides::Supply`; per the endpoint spec, ordinary `supply` skips the post-action solvency/health checks, so topping up a deeply insolvent account does not revert [4](#0-3) [5](#0-4) . The harness confirms the reachability: `regression_third_party_cannot_open_new_supply_slots` shows a third-party top-up of an existing leg succeeds and leaves ownership untouched [6](#0-5) .

An insolvent account approaching the dust gate necessarily retains residual supply positions — those positions are exactly what cleanup sweeps into revenue — so an attacker always has an existing leg to top up. Each time liquidation or price drift brings `total_collateral` back under $5, the attacker supplies a few dollars more of the same asset and the gate closes again. There is no rate limit, no per-account cooldown, and no minimum meaningful amount relative to the debt: the attacker only needs to keep the half-up unweighted collateral above $5.

### Impact Explanation
Temporary freezing of protocol recovery: `clean_bad_debt` is the only permissionless way to finalize a bad-debt account — it writes off the residual debt into the supply index, releases spoke usage, deletes the account entries and burns the NFT [7](#0-6) . While it is griefed, the insolvent account's gross debt stays on the market books instead of being socialized, so the supply index keeps accruing against debt that will never be repaid, spoke usage stays locked, and the account and its NFT cannot be removed. The only fallback is `force_socialize_bad_debt`, which is owner-only and therefore sits behind the governance sensitive timelock — i.e., recovery requires privileged action the threat model treats as slow, and the attacker can re-close the gate again afterward for a few dollars. This maps the CVE's availability-impact class (DoS of a permissionless recovery path) onto the codebase's real shape.

### Likelihood Explanation
Fully unprivileged and cheap: the attacker needs only an authenticated `supply` call with roughly `$5 + ε` of a token the account already supplies, repeated only when the collateral drifts back under the gate. No privileged state, oracle manipulation, or timing window is required; `supply` is not flash-guard-sensitive for this purpose and is not blocked by `frozen` on other assets. The attacker's donated collateral is exposed to being seized by liquidators, so the grief has an ongoing cost proportional to how long the freeze is maintained — but the dollar amount per round is trivial relative to any meaningful bad-debt position, and a motivated griefer (e.g., an account owner delaying their own bad-debt write-off, or someone attacking index accounting before a withdrawal) can sustain it.

### Recommendation
Make the `DustCapped` gate robust against inflation: either (a) snapshot the collateral test on liquidation-reduced collateral only, or more practically (b) restrict third-party `supply` to solvent accounts, or skip the third-party top-up path once an account is insolvent (`total_debt > total_collateral`) since no legitimate third party needs to collateralize someone else's bad debt. Alternatively, cap the grief by excluding third-party-credited supply legs younger than N ledgers from the dust-threshold sum, or give `clean_bad_debt` a `BadDebtGate` that ignores collateral credited by non-owners within the same ledger window. At minimum, document the dependency and add a keep-alive test asserting a topped-up account above $5 can still be resolved without waiting for governance.

### Proof of Concept
1. Alice supplies 100,000 USDC and borrows 6 ETH (as in `deep_underwater_account_still_liquidates_to_the_dust_gate` [8](#0-7) ). USDC crashes 10×; after repeated liquidations the account is reduced to e.g. $4.00 of residual USDC collateral against ~$100 of ETH debt — `is_socializable_bad_debt` admits it and any `clean_bad_debt(caller, account_id)` call succeeds.
2. Attacker Eve calls `supply(caller= Eve, account_id= alice_id, spoke_id= alice_spoke, assets= [(hub_key(usdc), 2000000)])` — a $2.00 top-up of the existing USDC supply leg. `require_third_party_existing_supply` passes because the leg exists; no health check runs. Account collateral is now ~$6 > `BAD_DEBT_USD_THRESHOLD`.
3. Every subsequent `clean_bad_debt` reverts `CannotCleanBadDebt` (#114). The debt is never written off, spoke usage stays locked, the NFT cannot burn.
4. Whenever a liquidator seizes Eve's top-up and collateral falls back under $5, Eve repeats step 2. The account can only be finalized via the timelocked owner-only `force_socialize_bad_debt` (`BadDebtGate::InsolventOnly`), which carries no dust cap [9](#0-8) .

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

**File:** certora/controller/spec/boundary_rules.rs (L10-25)
```rust
fn bad_debt_socialization_threshold_boundary(e: Env, debt_wad: i128, collateral_wad: i128) {
    let _ = e;
    cvlr_assume!(debt_wad > 0 && debt_wad <= 1_000_000 * WAD);
    cvlr_assume!(collateral_wad >= 0 && collateral_wad <= 1_000_000 * WAD);

    let socializable = is_socializable_bad_debt(Wad::from(debt_wad), Wad::from(collateral_wad));

    if collateral_wad > BAD_DEBT_USD_THRESHOLD {
        cvlr_assert!(!socializable);
    }
    if debt_wad <= collateral_wad {
        cvlr_assert!(!socializable);
    }
    if debt_wad > collateral_wad && collateral_wad <= BAD_DEBT_USD_THRESHOLD {
        cvlr_assert!(socializable);
    }
```

**File:** contracts/controller/src/positions/supply.rs (L51-74)
```rust
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

    finalize_position_flow(
        env,
        acct_id,
        &account,
        &mut cache,
        PositionSides::Supply,
        false,
    );
    acct_id
}
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

**File:** docs/reference/endpoints.md (L53-55)
```markdown
### Risk checks and pause flags

After pool accounting, `borrow`, `withdraw` and the six account strategies require LTV-weighted collateral to cover debt and health factor (HF) to be at least 1. If debt remains, LTV-weighted collateral must also meet the minimum-borrow floor. Ordinary `supply` and `repay` skip these checks; repayment loads debt positions only. Liquidation uses separate admission and sizing rules. See [formulas](formulas.md) for the calculations.
```

**File:** tests/test-harness/tests/controller/supply.rs (L346-367)
```rust
#[test]
fn regression_non_owner_cannot_open_new_supply_slot_on_victim() {
    let mut t = LendingTest::new().standard_two_asset().build();

    t.supply(ALICE, "USDC", 1_000.0);
    let alice_id = t.resolve_account_id(ALICE);
    let alice = t.get_or_create_user(ALICE);

    let new_slot = t.try_supply_to_account(BOB, ALICE, "ETH", 0.5);
    assert_contract_error(new_slot, errors::NOT_AUTHORIZED);

    let top_up = t.try_supply_to_account(BOB, ALICE, "USDC", 1.0);
    assert!(
        top_up.is_ok(),
        "same-asset third-party top-up must work: {top_up:?}"
    );
    assert_eq!(
        t.get_account_owner(alice_id),
        alice,
        "owner is unchanged after third-party top-up"
    );
}
```

**File:** docs/reference/invariants.md (L463-479)
```markdown
### INV-LIQ-04 — Bad-debt socialization is explicit and total

Permissionless cleanup requires ceil risk debt greater than half-up unweighted
collateral and collateral at or below the fixed $5 dust threshold. Owner-only
forced cleanup omits the dust cap. Both require debt, readable account and NFT
state, valid required prices and no active flash guard. Listing flags and
global pause do not block standalone cleanup.

Cleanup reclassifies all remaining collateral shares as revenue and writes off
all remaining debt against each debt's market. It releases spoke usage and
atomically removes account entries and the NFT. It does not net same-market
supply against debt. Standalone cleanup emits `CleanBadDebtEvent` with
pre-cleanup USD totals, without a controller position-update batch.

Ordinary liquidation and cleanup apply no final account-health or full-backing
assertion. The index floor can leave a shortfall. Recapitalization fills that
shortfall without restoring the lost index or deleted account.
```

**File:** tests/test-harness/tests/controller/bad_debt_netting_and_exit_timing.rs (L196-218)
```rust
    // Alice: $100k USDC collateral, 6 ETH = $12,000 debt.
    t.supply(ALICE, "USDC", 100_000.0);
    t.borrow(ALICE, "ETH", 6.0);
    let alice_id = t.resolve_account_id(ALICE);
    t.get_or_create_user(LIQUIDATOR);

    // Crash USDC 10x -> collateral $10,000 against $12,000 of debt.
    t.set_price("USDC", usd_cents(10));

    std::println!(
        "V3 A4-01b start: collateral_usd={:.2} debt_usd={:.2} hf={:.4} liquidatable={}",
        t.total_collateral(ALICE),
        t.total_debt(ALICE),
        t.health_factor(ALICE),
        t.can_be_liquidated(ALICE)
    );

    // The permissionless dust gate refuses an account of this size.
    assert_contract_error(
        t.try_clean_bad_debt_by_id(alice_id),
        errors::CANNOT_CLEAN_BAD_DEBT,
    );
    std::println!("V3 A4-01b clean_bad_debt at $10k collateral: REVERT (CannotCleanBadDebt)");
```
