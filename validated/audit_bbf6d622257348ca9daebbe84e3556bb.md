### Title
Attacker keeps an insolvent account above the $5 dust cap with third-party supply top-ups, permanently gating permissionless `clean_bad_debt` - (File: contracts/controller/src/positions/liquidation/mod.rs)

### Summary

The PowerDNS bug class is: unauthenticated/spoofed data causes the recursor to cache a "non-EDNS-capable" mark on an authoritative server, which later makes DNSSEC validation fail for that server. The XOXNO analog is a capability mark set by an unprivileged caller: permissionless `clean_bad_debt` admits an account only when `total_collateral <= BAD_DEBT_USD_THRESHOLD` ($5 WAD) — the protocol's "dust-capable" check. A third-party `supply` may freely top up any collateral leg an account already holds (`require_third_party_existing_supply` only requires the leg to exist, not ownership). An attacker can therefore donate a tiny amount of the victim's existing collateral asset, pushing `total_collateral` just over $5, and repeat the top-up whenever accrual, price moves, or liquidation brings it back under. Each time, `socialize_bad_debt` fails its `DustCapped` admission check with `CannotCleanBadDebt` — the spoofed "not-dust" mark re-fails validation exactly like the cached non-EDNS mark re-fails DNSSEC validation.

### Finding Description

- `process_clean_bad_debt` is permissionless (`caller.require_auth()` only) and routes to `socialize_bad_debt` with `BadDebtGate::DustCapped` [1](#0-0) 
- The gate requires `is_socializable_bad_debt(total_debt, total_collateral)`: debt > collateral AND collateral <= $5 [2](#0-1) 
- `require_third_party_existing_supply` lets any caller add funds to a supply leg the account already holds, with no minimum amount and no consent [3](#0-2) 
- Collateral valuation is share/index-based, so even a 1-base-unit top-up into a volatile-priced leg raises `total_collateral`; the gate reads the aggregate USD total, not per-leg dust [4](#0-3) 
- The attacker can front-run every `clean_bad_debt` transaction (or simply top-up whenever the account re-approaches the line) so the admission check always observes collateral above $5. There is no other permissionless cleanup path; `force_socialize_bad_debt` is owner-only and timelocked [5](#0-4) 

### Impact Explanation

Bad debt socialization is the mechanism that reconciles the supply index after an insolvency — it burns the debt and writes down the market's supply index, restoring honest accounting [6](#0-5) . While the dust gate is held closed, the insolvent account persists, its debt keeps accruing interest (per-millisecond accrual), the market's borrowed/supplied bookkeeping stays inflated, and the real loss compounds instead of being finalized. The attacker pays only the marginal gap above $5 per top-up (donated collateral that is itself later captured as protocol revenue on eventual cleanup), i.e., near-zero cost to indefinitely delay settlement of toxic debt. The only recourse is the timelocked owner path — matching the "temporary freezing / delayed insolvency resolution" impact class.

### Likelihood Explanation

Any unprivileged address can execute this: `supply(caller, account_id, spoke_id, [HubPayment{hub_asset, amount}])` where `hub_asset` is any collateral leg the victim already holds and `amount` is a few base units. It requires no privileged role, no oracle manipulation, and no flash loan. The precondition — an insolvent account with collateral near the dust cap — is exactly the population the permissionless path exists to serve, and opportunistic griefing of cleanup bots is cheap and repeatable.

### Recommendation

Enforce the dust gate per uncorrupted metric rather than per aggregate collateral — e.g., require `total_collateral <= $5` measured only on legs the account owner controls, or track "externally donated" collateral separately. Simpler options: (a) make `clean_bad_debt` admission test collateral minus recent non-owner top-ups; (b) restrict third-party top-ups on accounts where `total_debt > total_collateral` (an insolvent account gains no benefit from strangers' collateral); or (c) raise the gate to "collateral <= $5 OR every supply leg was last touched by a non-owner" — i.e., treat recent third-party supply on an insolvent account as attacker-controlled and ignore it for the dust test.

### Proof of Concept

1. ALICE supplies $8 USDC, borrows ETH; USDC price crashes so `total_debt > total_collateral` and `total_collateral = $4.99` (below `BAD_DEBT_USD_THRESHOLD`).
2. Keeper calls `clean_bad_debt(account_id)` → attacker front-runs with `supply(attacker, alice_id, alice_spoke, [HubPayment{usdc_key, 2 base units}])`. `require_third_party_existing_supply` passes because ALICE already holds a USDC supply leg (`supply_positions.contains_key` is true).
3. `total_collateral` is now ~$5.0001; `is_socializable_bad_debt` returns false; `socialize_bad_debt` reverts with `CollateralError::CannotCleanBadDebt` [7](#0-6) .
4. Each time accrual or liquidation erodes collateral back under $5, the attacker repeats step 2 for the cost of fractions of a cent. The account is never socialized permissionlessly; only a timelocked `ForceSocializeBadDebt` governance operation can remove it, leaving the debt to accrue in the interim.

Mirrors the existing harness pattern in `test_keeper_clean_bad_debt_decreases_supply_index` (`tests/test-harness/tests/controller/bad_debt_index.rs:196`), which confirms the same fixture (collateral near the dust line) is cleanup-eligible absent the top-up.

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

**File:** docs/reference/formulas.md (L378-382)
```markdown
Bad-debt cleanup has separate eligibility: ceil risk debt must exceed half-up
unweighted collateral, and permissionless cleanup requires collateral at or
below $5. Forced owner cleanup omits the collateral cap. See
[cleanup invariants](invariants.md#inv-liq-04) for authorization and account
deletion.
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

**File:** docs/reference/runbooks/force-socialize-bad-debt.md (L20-33)
```markdown
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
