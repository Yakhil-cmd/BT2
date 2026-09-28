### Title
Collateral straddle via permissionless third-party `supply` blocks `clean_bad_debt` on insolvent accounts - (File: contracts/controller/src/positions/liquidation/curve.rs)

### Summary
The `http-proxy-agent` advisory is a resource-consumption / denial-of-service class: unsanitized input lets an attacker push a system into a state where legitimate work is refused. The on-chain analog in XOXNO Lending is the dust-gated socialization gate: any unprivileged address can permanently push a victim insolvent account out of the permissionless `clean_bad_debt` path by topping up its existing supply leg with just over $5 of collateral, forcing all cleanup through the timelocked owner-only `force_socialize_bad_debt` path while the bad debt keeps accruing.

### Finding Description
Permissionless bad-debt cleanup is admitted only by `is_socializable_bad_debt`, which requires `total_debt > total_collateral && total_collateral <= Wad::from(BAD_DEBT_USD_THRESHOLD)` where `BAD_DEBT_USD_THRESHOLD = 5 WAD` ($5) [1](#0-0) [2](#0-1) . The same gate runs in standalone `clean_bad_debt` (`BadDebtGate::DustCapped`) [3](#0-2)  and in the automatic post-liquidation cleanup `check_bad_debt_after_liquidation` [4](#0-3) .

Meanwhile `supply` is permissionless for existing legs: `process_supply` calls `require_third_party_existing_supply`, which only requires that a non-owner caller top up a hub asset the account already supplies [5](#0-4) [6](#0-5) . The gate is value-based, not count-based, so a single top-up worth more than $5 — of a token the account already holds — raises `total_collateral` above the cap while the account stays insolvent (`debt > collateral`) [7](#0-6) .

Attack path for one unprivileged address:
1. Wait for (or find) an account with `collateral <= $5 < debt`, eligible for `clean_bad_debt`.
2. Call `supply(attacker, victim_id, victim_spoke, [(existing_collateral_key, amount_worth_just_over_$5)])`.
3. Every subsequent `clean_bad_debt` call reverts `CannotCleanBadDebt` (#114), and every post-liquidation `check_bad_debt_after_liquidation` skips cleanup, because collateral now straddles the cap [8](#0-7) .

Because the top-up raises collateral but not weighted collateral enough to restore solvency, the account remains liquidatable, yet the terminal step that would burn the account and write down debt is denied to unprivileged callers. The only remaining cleanup is `force_socialize_bad_debt`, which is owner-only behind the governance Sensitive-delay timelock [9](#0-8) .

### Impact Explanation
Temporary freezing of protocol function and delayed insolvency resolution. The bad debt keeps accruing borrow interest against supply shares while permissionless socialization is blocked, and the debt write-down (which lowers supply indexes) cannot occur until a timelocked governance operation executes. The attacker can repeat this on every dust-insolvent account for ~$5 each, and can keep the straddle alive indefinitely by topping up whenever liquidation or price moves drag collateral back under $5. The attacker loses the donated funds (they are credited to the victim's account), making this a cheap sustained griefing/DoS of the cleanup mechanism rather than a theft. Severity: Medium — impact is delayed socialization and continued accrual on bad debt, mitigated by the existence of the owner-gated fallback path and by ordinary liquidation remaining open.

### Likelihood Explanation
Reachable by any authenticated address with ~$5 of a token the victim already supplies; `supply` is not pause-gated for the victim and requires no owner/delegate role for existing legs [10](#0-9) . The precondition — an insolvent account near the dust boundary — arises naturally after deep price crashes (the codebase's own tests exercise exactly this state) [11](#0-10) . The Certora boundary rules explicitly witness the straddle region as reachable predicate space [12](#0-11) . Likelihood is moderate: the attack costs real funds and only delays rather than prevents resolution, but it can be repeated at trivial cost and the straddled state persists as long as the attacker maintains it.

### Recommendation
Make the dust gate robust to collateral top-ups; for example:
- Compare `total_collateral` against the threshold net of recent third-party contributions, or
- Reject (or restrict to owner/delegate) `supply` top-ups onto accounts that are currently insolvent (`total_debt > total_collateral`) — such deposits only ever serve to game the cleanup gate, or
- Bound the block by also admitting cleanup when `collateral <= threshold + top_up_since_insolvency`, tracking a per-account "collateral at first insolvency" snapshot.

### Proof of Concept
```rust
// victim: insolvent dust account, e.g. collateral $4, debt $10 (clean_bad_debt admissible)
assert!(t.total_collateral_raw(victim_id) <= 5 * WAD);
assert!(t.total_debt_raw(victim_id) > t.total_collateral_raw(victim_id));

// attacker: any address, tops up the victim's EXISTING supply leg (allowed by
// require_third_party_existing_supply) so collateral exceeds $5 while debt > collateral
t.try_supply_to_account(ATTACKER, victim_owner, "USDC", 2.0) // $4 -> ~$6
    .expect("third-party top-up of existing leg");

// permissionless cleanup now permanently reverts
assert_contract_error(
    t.try_clean_bad_debt_by_id(victim_id),
    errors::CANNOT_CLEAN_BAD_DEBT, // #114
);
// post-liquidation socialization is silently skipped too (is_socializable_bad_debt false)
// only owner-gated force_socialize_bad_debt (timelocked) can still remove the account
```

### Citations

**File:** contracts/controller/src/positions/liquidation/curve.rs (L25-27)
```rust
pub(crate) fn is_socializable_bad_debt(total_debt: Wad, total_collateral: Wad) -> bool {
    total_debt > total_collateral && total_collateral <= Wad::from(BAD_DEBT_USD_THRESHOLD)
}
```

**File:** contracts/controller/src/constants.rs (L3-3)
```rust
pub const BAD_DEBT_USD_THRESHOLD: i128 = DEFAULT_MIN_BORROW_COLLATERAL_USD_WAD;
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L216-235)
```rust
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

**File:** contracts/controller/src/positions/liquidation/apply.rs (L308-315)
```rust
    if account.borrow_positions.is_empty() {
        account::cleanup_account_if_empty(env, account, account_id);
        return;
    }

    if is_socializable_bad_debt(totals.total_debt, totals.total_collateral) {
        bad_debt::execute_bad_debt_cleanup(env, cache, account_id, account, totals);
    }
```

**File:** contracts/controller/src/positions/supply.rs (L61-63)
```rust
    require_third_party_existing_supply(env, account_id, acct_id, caller, &account, &aggregated);

    process_deposit(env, caller, &mut account, &aggregated, &mut cache);
```

**File:** contracts/controller/README.md (L37-39)
```markdown
  remaining collateral is at or below the dust threshold. A third-party
  `supply` may only top up hub assets the account already holds a supply
  position in; an `account_id` of 0 creates a new account owned by the caller.
```

**File:** certora/controller/spec/boundary_rules.rs (L44-54)
```rust
/// Straddle, first half. An attacker who raises `total_collateral` strictly above
/// `BAD_DEBT_USD_THRESHOLD` (`BAD_DEBT_USD_THRESHOLD + 1` is the cheapest such state) blocks
/// the permissionless dust-gated socialization path while staying insolvent. The gate is
/// value-based, not count-based, so one unit of a second collateral cannot block it: the
/// attacker must post value above the threshold and keep it there.
#[rule]
fn bad_debt_straddle_blocks_dust_gate(e: Env, debt_wad: i128, collateral_wad: i128) {
    let _ = e;
    cvlr_assume!(collateral_wad >= BAD_DEBT_USD_THRESHOLD + 1);
    cvlr_assume!(collateral_wad <= 1_000_000 * WAD);
    cvlr_assume!(debt_wad > collateral_wad && debt_wad <= 2_000_000 * WAD);
```

**File:** certora/controller/spec/boundary_rules.rs (L106-120)
```rust
/// Reachability witness for the straddle at exactly
/// `collateral == BAD_DEBT_USD_THRESHOLD + 1 && debt == collateral + 1`: the two gates really do
/// split there, so neither straddle rule is vacuous.
#[rule]
fn bad_debt_straddle_gate_split_sanity(e: Env, debt_wad: i128, collateral_wad: i128) {
    let _ = e;
    cvlr_assume!(collateral_wad == BAD_DEBT_USD_THRESHOLD + 1);
    cvlr_assume!(debt_wad == collateral_wad + 1);

    let debt = Wad::from(debt_wad);
    let collateral = Wad::from(collateral_wad);

    cvlr_satisfy!(
        !is_socializable_bad_debt(debt, collateral) && insolvent_gate_admits(debt, collateral)
    );
```

**File:** docs/reference/runbooks/force-socialize-bad-debt.md (L19-23)
```markdown
1. Confirm the network, target controller, governance contract, account id,
   NFT owner, positions and spoke. `force_socialize_bad_debt` is owner-only.
   Governance, the controller owner, schedules `ForceSocializeBadDebt` on the
   Sensitive delay tier; follow the
   [governance interface](../endpoints.md#governance) for proposal and execution.
```

**File:** scripts/permissionless_entrypoints.txt (L69-72)
```text
controller::supply | caller-auth | INV-AUTH-03, INV-ACCT-03 | Anyone may top up an account they do not own, but only for hub assets it already holds a supply position in; a caller that is neither the owner nor an active delegate cannot open a new asset slot, and account_id 0 creates an account owned by the caller.
controller::repay | caller-auth | INV-AUTH-03, INV-ACCT-03 | Anyone may repay any account's debt. Funds are pulled from the caller's own balance and credited from the measured receipt; the target's liabilities can only fall.
controller::liquidate | caller-auth | INV-AUTH-03, INV-LIQ-01, INV-LIQ-02 | Anyone may liquidate an account whose health factor is below one, including the account's own owner; in Credit seize mode the receiving account must be a different account that the liquidator owns or is an active delegate of, and seizure stays coupled to the debt actually repaid.
controller::clean_bad_debt | caller-auth | INV-AUTH-03, INV-LIQ-04 | Anyone may socialize an insolvent account's residual debt, but only once its remaining collateral is at or below the dust threshold; only the owner-gated force_socialize_bad_debt omits the dust cap.
```

**File:** tests/test-harness/tests/controller/liquidation_extreme.rs (L267-282)
```rust
fn test_deep_crash_socializes_bad_debt() {
    let mut t = LendingTest::new()
        .with_market(asset("VOL", 7, usd(100), 7000, 8000, 500, 1_000_000.0))
        .with_market(stable("USD"))
        .build();

    t.supply(ALICE, "VOL", 100.0);
    t.borrow(ALICE, "USD", 7_000.0);
    t.set_price("VOL", usd_cents(3));
    t.advance_and_sync(100);
    t.assert_liquidatable(ALICE);

    let id = t.resolve_account_id(ALICE);
    t.clean_bad_debt_by_id(id);
    assert!(t.find_account_id(ALICE).is_none(), "account cleaned away");
}
```
