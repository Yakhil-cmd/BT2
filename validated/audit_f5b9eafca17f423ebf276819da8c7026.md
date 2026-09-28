### Title
Malicious third party can permanently block bad-debt socialization by dust top-ups that keep an insolvent account's collateral above the $5 `clean_bad_debt` gate - (File: contracts/controller/src/positions/supply.rs)

### Summary
XOXNO Lending's permissionless `clean_bad_debt` path is gated by `is_socializable_bad_debt`, which requires `total_collateral <= BAD_DEBT_USD_THRESHOLD` ($5 WAD) in addition to `total_debt > total_collateral`. At the same time, `Controller::supply` deliberately allows any unprivileged caller to top up an existing supply leg of an account they do not own. A single unprivileged attacker can therefore repeatedly donate dust collateral to an insolvent account so that its remaining collateral is always above $5 whenever a liquidation would otherwise cross the dust gate, permanently preventing the permissionless socialization of the bad debt. This is the direct analog of the reported `modifyTimestamp`-reset griefing: a dust-sized, permissionless write resets the eligibility condition of a protective "force close" path.

### Finding Description
Two documented behaviors compose into the vulnerability:

1. `clean_bad_debt` (and the in-call bad-debt promotion after `liquidate`) only fires when `is_socializable_bad_debt(totals.total_debt, totals.total_collateral)` returns true — i.e. `D > C` and `C <= 5 WAD`. Otherwise the call reverts `CannotCleanBadDebt` (or is skipped inside `liquidate`). [1](#0-0) 
2. `process_supply` → `require_third_party_existing_supply` permits any authenticated caller that is neither owner nor delegate to add to `hub_asset` legs that already exist in `account.supply_positions`. [2](#0-1) 

The attacker watches the insolvent account and front-runs (or simply precedes) the liquidation step that would bring collateral to ≤ $5, topping up the victim's existing collateral leg by a few dollars so `C` stays strictly above `BAD_DEBT_USD_THRESHOLD`. Because liquidation is pro-rata, subsequent liquidations only shrink collateral proportionally, so the attacker just needs to restore it above $5 each time. The dust gate is the only thing standing between a deeply insolvent account and cleanup; the alternative `force_socialize_bad_debt` is owner-gated, not permissionless.

### Impact Explanation
- Bad debt is never written down against the supply index, so the market retains a permanently unbacked borrow book instead of finalizing the loss. Suppliers' claims over that market remain inflated-but-unpayable (the index floor / shortfall machinery is never invoked), and `require_backed_market` (`PoolInsolvent`) can block new supply on the affected market indefinitely — a persistent, low-cost disruption of a protective accounting path plus delayed loss recognition. [3](#0-2) 
- Liquidators do still profit from seizing the attacker's donated collateral, so the attack costs the attacker roughly the donation each cycle, but it can be repeated forever since each top-up need only push `C` from just below to just above $5.
- Severity: Medium (temporary/permanent freezing of the socialization path rather than direct theft; bounded by the governance `force_socialize_bad_debt` escape hatch, which requires a timelocked Sensitive-tier operation).

### Likelihood Explanation
- Reachable by a single unprivileged address with only `caller.require_auth()` — no owner, delegate, or governance rights needed. The only constraint is that the topped-up leg must already exist in the account, which is trivially true for any insolvent account that still holds collateral.
- The economic cost per maintenance cycle is small (on the order of the dust threshold), and the check is a pure function of `total_collateral`, so timing is the only challenge — analogous to the original report's "partially close dust to reset `modifyTimestamp`".
- The attack can also be initiated *before* an account becomes insolvent by keeping its smallest collateral leg above $5, which is the normal state anyway.

### Recommendation
Break the coupling between permissionless top-ups and the cleanup gate. Options:
- Exclude recently received third-party top-ups from the `total_collateral` figure used by `is_socializable_bad_debt` (e.g., track a per-account "foreign donation" counter that is ignored by the gate), or
- Gate third-party top-ups on accounts that are insolvent/liquidatable — e.g., in `require_third_party_existing_supply`, revert when `account` has debt and `calculate_account_risk_totals` shows `total_debt > total_collateral`, so dust cannot be injected specifically to defeat the gate, or
- Replace the absolute $5 collateral cap with a relative measure (collateral ≤ small fraction of debt) so a multi-dollar donation cannot rescue an account carrying far larger bad debt.

### Proof of Concept
1. ALICE supplies 100 USDC and borrows 12 ETH; USDC price crashes so `D ≈ $12,000`, `C ≈ $10,000` — insolvent but above the dust cap (`CannotCleanBadDebt`, as in `deep_underwater_account_still_liquidates_to_the_dust_gate`). [4](#0-3) 
2. Liquidators run partial liquidations. Suppose one would leave `C = $4.90`, triggering in-call bad-debt promotion and account removal.
3. Before that liquidation lands, attacker BOB calls `supply(BOB, alice_id, spoke_id, [(USDC, 0.2 USDC)])`. This succeeds because the USDC leg already exists (`require_third_party_existing_supply` passes for BOB as a non-owner). [5](#0-4) 
4. `total_collateral` is now $5.10; `is_socializable_bad_debt` returns false. The liquidation executes, collateral drops proportionally (say to $4.90 again) but the in-call gate check still reads `C > 5 WAD` relative to the pre-check, and any standalone `clean_bad_debt` reverts `CannotCleanBadDebt`. [6](#0-5) 
5. Repeat step 3 whenever collateral approaches $5. The permissionless cleanup path is permanently denied; only the governance `force_socialize_bad_debt` runbook can remove the account.

### Citations

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

**File:** tests/test-harness/tests/controller/bad_debt_netting_and_exit_timing.rs (L213-218)
```rust
    // The permissionless dust gate refuses an account of this size.
    assert_contract_error(
        t.try_clean_bad_debt_by_id(alice_id),
        errors::CANNOT_CLEAN_BAD_DEBT,
    );
    std::println!("V3 A4-01b clean_bad_debt at $10k collateral: REVERT (CannotCleanBadDebt)");
```
