### Title
`update_account_threshold` lets anyone cherry-pick the new LTV while keeping a stale, more favorable liquidation tuple - (File: contracts/controller/src/risk/params.rs)

### Summary
The controller's permissionless `update_account_threshold(caller, has_risks, account_ids)` accepts arbitrary `account_ids` and a caller-chosen `has_risks` scope. With `has_risks = false` (`LtvOnly`), the position's `loan_to_value` is restamped to the current listing config while the liquidation tuple (`liquidation_threshold`, `liquidation_bonus`, `liquidation_fees`) is left at its stale snapshot. A borrower can therefore adopt whichever half of a governance risk update favors them — grabbing a newly raised LTV while keeping a higher old liquidation threshold — and borrow against a collateral/health-factor combination no configured parameter set ever authorized.

### Finding Description
Every supply position caches `loan_to_value`, `liquidation_threshold`, `liquidation_bonus`, and `liquidation_fees` from the `SpokeAssetConfig` at the time it was last stamped. These snapshots only change through `refresh_supply_risk_params`, which is invoked from `update_account_threshold` — callable by any authenticated caller for any `account_id` (the function never checks ownership; `sync_account_thresholds` only fails closed when the NFT owner cannot be resolved). [1](#0-0) 

The scope is selected entirely by the caller:

- `LtvOnly` unconditionally writes `position.loan_to_value = effective_config.loan_to_value` and skips `apply_gated_liquidation_params`.
- `FullTuple` also refreshes the liquidation tuple, but only when it does not favor the liquidator, or when the resulting hypothetical HF is ≥ 1.05 (`THRESHOLD_UPDATE_MIN_HF_RAW`). [2](#0-1) [3](#0-2) 

There is no invariant that LTV and the liquidation tuple are ever restamped together. The `favors_liquidator` gate protects accounts from updates that would hurt *them*, but nothing protects the protocol from an account selectively consuming a borrower-favorable LTV increase while refusing a borrower-unfavorable liquidation-threshold decrease. Borrowing power and the health factor are computed in `calculate_account_risk_totals` from these per-position snapshots and the Context-cached strict prices/indexes, so a mismatched tuple directly inflates what the account may borrow relative to the config governance actually set.

### Impact Explanation
After a governance listing edit that raises `loan_to_value` and lowers `liquidation_threshold` (a common rebalance), an attacker calls `update_account_threshold(attacker, false, [own_account_id])`. The account's LTV jumps to the new higher value, while its HF denominator keeps the old, higher liquidation threshold — a combination where `clears_min_hf` is never consulted because `LtvOnly` skips the tuple entirely. The attacker then calls `borrow` and reaches an LTV utilization that the new config's HF curve (with the intended lower threshold) would have rejected, i.e., debt backed by less liquidation-weighted collateral than any listed parameterization permits. If prices move against the position before anyone restamps `FullTuple` (which the HF ≥ 1.05 gate may itself block on an account hovering near the threshold), the account sits in the undercollateralized band between the new threshold and the stale one — liquidation proceeds as normal but debt exceeds what risk parameters allowed, producing realized bad debt socialized onto suppliers via `apply_bad_debt_to_supply_index`. Impact class: protocol insolvency / theft of user funds through a parameter set governance never configured.

### Likelihood Explanation
- Reachable by any unprivileged authenticated caller: `update_account_threshold` has no ownership check, no spoke-role check, and is only blocked by a global pause. The attacker operates on their own account, so no victim cooperation is needed.
- Requires a listing edit where the direction of change is mixed (LTV up, threshold down, or vice versa) — or simply any config where the account's stale snapshot is more permissive than the live `AssetConfig`. Stale snapshots are the normal state between edits and restamps by design.
- The cheap variant — keeping a stale higher LTV after governance lowers it — requires no action at all until the account is restamped, since `restamp_listed_supply_ltv` is only invoked through this same permissionless, opt-in path; existing borrow capacity is measured against the stale snapshot for any borrow/withdraw that reads `position.loan_to_value`.
- Medium likelihood: it depends on a governance parameter change creating an exploitable stale/live gap, but once such a change lands, exploitation is a single permissionless call plus a borrow.

### Recommendation
- Make the refresh atomic: always restamp LTV and the liquidation tuple together, keeping `favors_liquidator` + the HF ≥ 1.05 gate as the sole mechanism for deferring liquidator-favoring changes.
- Alternatively, when `LtvOnly` restamps `loan_to_value`, also clamp the stored `liquidation_threshold` to `min(stored, effective.liquidation_threshold)` so a borrower can never run a tuple no config authorized (higher LTV paired with a higher stale threshold).
- Consider restricting `update_account_threshold` to the account owner or delegate for scope selection, or restamping all accounts' LTV eagerly inside `edit_asset_in_spoke`/`relax_spoke_asset_flags` so the stale window never depends on an opt-in call.

### Proof of Concept
1. Governance lists asset X in the spoke with `loan_to_value = 8_000`, `liquidation_threshold = 8_500`. Alice supplies 100 X (worth $100) into account `A`; the position snapshot stores LTV 80% / LT 85%.
2. Governance executes `edit_asset_in_spoke` setting `loan_to_value = 9_000`, `liquidation_threshold = 8_000` (higher borrow power, tighter liquidation margin). Alice's stored position still reads 8_000 / 8_500 — snapshots are only refreshed via `update_account_threshold`.
3. Alice calls `update_account_threshold(alice, false, [A])`. In `refresh_supply_risk_params` the `LtvOnly` scope writes `position.loan_to_value = 9_000` and skips `apply_gated_liquidation_params` entirely, so `position.liquidation_threshold` stays `8_500` — a 90% LTV / 85% LT combination present in no config.
4. Alice calls `borrow` for ~$85 of debt asset. The LTV ceiling check passes (LTV-weighted collateral $90 ≥ debt) and the health factor is computed against the stale 85% threshold (HF ≈ 1.0), where the intended config (LT 80%) would have failed the HF gate well below $80 of debt.
5. If X's price dips before a `FullTuple` restamp succeeds — and `clears_min_hf` can block restamping a borderline account at all (`params.rs:78-88`) — the position carries debt sized for a collateralization regime governance never set; on liquidation the shortfall beyond recovered collateral becomes bad debt written down against all suppliers in `apply_bad_debt_to_supply_index` (`contracts/pool/src/interest.rs:73-89`).

### Citations

**File:** contracts/controller/src/risk/params.rs (L34-40)
```rust
    let before = *position;
    position.loan_to_value = effective_config.loan_to_value;
    if scope == RiskRefreshScope::FullTuple {
        apply_gated_liquidation_params(env, cache, account, hub_asset, position, effective_config);
    }
    *position != before
}
```

**File:** contracts/controller/src/risk/params.rs (L76-93)
```rust
    if favors_liquidator(position, effective_config)
        && !account.debt_free()
        && !clears_min_hf(
            env,
            cache,
            account,
            hub_asset,
            position,
            effective_config.liquidation_threshold,
        )
    {
        return;
    }

    position.liquidation_threshold = effective_config.liquidation_threshold;
    position.liquidation_bonus = effective_config.liquidation_bonus;
    position.liquidation_fees = effective_config.liquidation_fees;
}
```

**File:** contracts/controller/src/risk/params.rs (L124-144)
```rust
pub(crate) fn update_account_threshold(
    env: &Env,
    caller: Address,
    has_risks: bool,
    account_ids: Vec<u64>,
) {
    validation::require_authorized_caller(env, &caller);

    let scope = if has_risks {
        RiskRefreshScope::FullTuple
    } else {
        RiskRefreshScope::LtvOnly
    };

    let mut cache = Context::new(env);

    for account_id in account_ids {
        cache.reset_spoke_context();
        sync_account_thresholds(env, account_id, scope, &mut cache);
    }
}
```
