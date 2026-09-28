### Title
Permissionless `execute` applies stale `EditAssetInSpoke` risk params over an intervening tightening - ([File: contracts/controller/src/config/asset.rs])

### Summary
CVE-2017-7572 is a time-of-check/time-of-use authorization race: polkit checks the requester's privilege at check-time, but the privileged process is replaced before the operation is used. The analog in XOXNO Lending is the governance timelock: an `EditAssetInSpoke` operation's full `SpokeAssetArgs` (LTV, liquidation threshold, bonus, fees, caps, flags) is validated and hashed at proposal time, then executed verbatim against whatever listing exists at execution time, by anyone, via `Governance::execute(executor=None)`. Only the halt flags are guarded at use-time (`require_flag_ratchet`); the risk parameters and caps are not. An unprivileged address controls execution timing and ordering among ready operations, so it can land a stale, looser configuration on top of a newer, tighter one — a TOCTOU between proposal-time validation and execution-time application.

### Finding Description
`upsert_spoke_asset` in `contracts/controller/src/config/asset.rs:36-104` rewrites the entire `SpokeAssetConfig` from the operation's `args`. Its only use-time guard is `require_flag_ratchet` (`asset.rs:175-186`), which restricts `paused`/`frozen`/`no_seize` to keep-or-tighten. Nothing constrains `ltv`, `liquidation_threshold`, `liquidation_bonus`, `liquidation_fees`, `supply_cap`, or `borrow_cap` relative to the live listing at execution time — they are overwritten blindly [1](#0-0) .

On the governance side, `Governance::execute` permits `executor = None` with no auth or role check at all [2](#0-1)  and `lifecycle::execute` only verifies the op is Ready and not expired before invoking the target [3](#0-2) . This is confirmed reachable with no signature in `tests/test-harness/tests/governance/permissionless_execution.rs:59-71` and for a stale `edit_asset_in_spoke` specifically in `stale_edit_and_sensitive_floor.rs:149-160`.

The protocol already acknowledges this TOCTOU shape for the flags: `RelaxSpokeAssetFlags` is bound to a flags epoch that any flag write advances, precisely so a stale relaxation cannot undo a guardian freeze (`SpokeFlagsEpochMismatch`, ADR-0007). The same protection was not extended to the numeric risk fields of `EditAssetInSpoke`.

Concrete sequence:

1. Listing USDC has `ltv=8000`, `threshold=8500`, `supply_cap=C0`.
2. Governance proposes **Edit A** (early, routine): `supply_cap = C0 - 1`, carrying the *current* looser risk params — the exact pattern exercised in `stale_edit_and_sensitive_floor.rs:100-123`.
3. Market deteriorates; governance proposes and executes **Edit B**: `ltv=5000`, `threshold=5300` (the liqvid runbook shows this is a real operational tightening, `docs/reference/runbooks/liqvid-listing-params.md`).
4. Edit A is still Ready (grace window is 120,960 ledgers per `permissionless_execution.rs:16`). Any unprivileged address calls `governance.execute(None, controller, "edit_asset_in_spoke", [argsA], ...)`.
5. `upsert_spoke_asset` runs its proposal-time-baked args: `require_flag_ratchet` passes (flags unchanged), and the full old config — `ltv=8000`, `threshold=8500` — is written back over Edit B.

The attacker does not propose anything; it only chooses *when* a legitimately scheduled op lands, analogous to the PID-reuse window in the CVE: the authorization object (the scheduled args) is checked once at schedule time but used later against changed state.

### Impact Explanation
**Protocol insolvency / theft of user funds.** Execution of the stale edit restores the higher LTV and liquidation threshold. Because `calculate_account_risk_totals` and the borrow gate restamp each listed supply leg's stored LTV to the *live* `SpokeAssetConfig.loan_to_value` on every borrow (`skills/xoxno-lending/math.md:264` and INV-RISK-01), the moment the stale listing lands, existing and new borrowers can draw debt against collateral at the stale 8000 LTV instead of the intended 5000. The attacker supplies the listed collateral, borrows to the restored limit, and lets the position go bad; liquidation cannot recover full value when the collateral's price moves against the pool, leaving bad debt socialized onto suppliers via the supply-index write-down. A stale edit can similarly restore a higher `borrow_cap` or `supply_cap` that governance had since reduced, or a lower `liquidation_fees`/higher `liquidation_bonus` tuple that governance had since corrected.

### Likelihood Explanation
The trigger requires only that a Ready `EditAssetInSpoke` exists whose frozen args are looser than the live listing — a normal consequence of any sequential parameter tightening (the runbook workflow itself schedules successive `editAssetInSpoke` ops). The executor needs no role, no signature, and no capital beyond transaction fees; execution is permissionless by design (`authorize_executor` no-ops on `None`). The window is the full Ready period (delay + 120,960-ledger grace). Rating: Medium — it requires a pending stale edit and depends on governance scheduling patterns, but when it fires the primitive silently reverses a risk tightening.

### Recommendation
Bind `EditAssetInSpoke` to the listing's mutation epoch the same way `RelaxSpokeAssetFlags` is bound to the flags epoch. Options:

- Extend the flags-epoch mechanism into a general listing-revision counter incremented by every `edit_asset_in_spoke`/`set_spoke_asset_flags`/`relax_spoke_asset_flags` write, and require `SpokeAssetArgs` (or a wrapped op arg) to carry `expected_revision`; revert with a `SpokeListingRevisionMismatch` when it differs. This kills the check/use gap for the whole config, not just flags.
- Alternatively, at execution time ratchet risk fields the way flags are ratcheted: reject an `EditAssetInSpoke` that raises `ltv`, `threshold`, `supply_cap`, or `borrow_cap` above the live values, and route loosening through a separate epoch-bound op. This is coarser (some legitimate loosenings would need the new path) but minimally invasive.

### Proof of Concept
Conceptual script against the harness (mirroring `stale_edit_and_sensitive_floor.rs`):

```rust
// USDC live: ltv=8000, threshold=8500. Propose stale edit A (only cap -1).
let cfg = t.ctrl_client().get_spoke_asset(&HARNESS_SPOKE, &key);
let stale_args = SpokeAssetArgs { ltv: cfg.loan_to_value, threshold: cfg.liquidation_threshold,
    supply_cap: cfg.supply_cap - 1, ..copy_of(cfg) };
let id_a = gov.propose(&admin, &AdminOperation::EditAssetInSpoke(stale_args.clone()), &salt(1));

// Governance tightens: execute edit B -> ltv=5000, threshold=5300.
let tight = SpokeAssetArgs { ltv: 5000, threshold: 5300, ..stale_args.clone() };
let id_b = gov.propose(&admin, &AdminOperation::EditAssetInSpoke(tight.clone()), &salt(2));
advance_ledgers(delay);
gov.execute(&None, &controller, &sym("edit_asset_in_spoke"), &args(tight), &zero, &salt(2));
assert_eq!(get_spoke_asset().loan_to_value, 5000);

// Attacker (no auth) executes the stale ready op A.
env.set_auths(&[]);
gov.execute(&None, &controller, &sym("edit_asset_in_spoke"), &args(stale_args), &zero, &salt(1));

// TOCTOU: stale params overwrite the tightening.
assert_eq!(get_spoke_asset().loan_to_value, 8000);          // tightened 5000 lost
assert_eq!(get_spoke_asset().liquidation_threshold, 8500);  // tightened 5300 lost

// Attacker now borrows to the stale LTV; the borrow gate restamps stored
// LTV from the live config, so 8000 applies immediately.
t.supply(ALICE, "USDC", 10_000);
t.borrow(ALICE, "ETH", max_by_ltv_8000); // exceeds intended 5000 cap
```

Root cause: `upsert_spoke_asset` applies proposal-time args wholesale with no execution-time freshness check on non-flag fields (`contracts/controller/src/config/asset.rs:60-95`), while `Governance::execute` lets any address choose the landing ledger of a ready op (`contracts/governance/src/timelock/lifecycle.rs:85-110`, `timelock/mod.rs:75-82`).

### Citations

**File:** contracts/controller/src/config/asset.rs (L79-95)
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
        storage::bump_spoke_flags_epoch(env, args.spoke_id, &hub_asset);
    }
```

**File:** contracts/governance/src/timelock/mod.rs (L75-82)
```rust
/// When `Some(exec)`, requires `exec` auth + `EXECUTOR_ROLE`. When `None`,
/// performs no auth or role check (anyone may drive execution of a ready op).
pub(crate) fn authorize_executor(env: &Env, executor: Option<&Address>) {
    if let Some(exec) = executor {
        exec.require_auth();
        access_control::ensure_role(env, &Symbol::new(env, EXECUTOR_ROLE), exec);
    }
}
```

**File:** contracts/governance/src/timelock/lifecycle.rs (L94-109)
```rust
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
