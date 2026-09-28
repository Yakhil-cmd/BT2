### Title
The liquidation bonus curve is read from the live spoke config instead of being stamped on the position, so retroactive curve changes apply to all existing accounts - (contracts/controller/src/positions/liquidation/plan.rs)

### Summary
XOXNO Lending deliberately stamps per-position liquidation parameters (LTV, LT, base bonus, `liquidation_fees`) so that risk-parameter changes cannot retroactively worsen existing accounts without passing the `HF >= 1.05` gate in `apply_gated_liquidation_params`. However, the three spoke-level curve parameters — `liquidation_target_hf_wad`, `hf_for_max_bonus_wad`, and `liquidation_bonus_factor_bps` — are **not** stamped. Every liquidation rebuilds `LiquidationCurve::from_config(&cache.spoke_config(account.spoke_id))` from the current `SpokeConfig`, so a `set_spoke_liquidation_curve` update rewrites the effective bonus and close factor for every open position in the spoke, bypassing the gate that protects the stamped parameters. This is the same bug class as the YOLO report: a mutable global parameter applied retroactively to obligations created under older terms.

### Finding Description
When a supply position is created, the controller copies `ltv`, `liquidation_threshold`, `liquidation_bonus`, and `liquidation_fees` onto the position (`get_or_create_supply_position`), and the seized-fee rate is carried into the plan via `SeizeEntry.liquidation_fees` (`math.rs:498`). [1](#0-0) 

But in `build_liquidation_plan`, the curve is loaded fresh at liquidation time:

```rust
let curve = LiquidationCurve::from_config(&cache.spoke_config(account.spoke_id));
``` [2](#0-1) 

`LiquidationCurve::from_config` reads `liquidation_target_hf_wad`, `hf_for_max_bonus_wad`, and `liquidation_bonus_factor_bps` directly from `SpokeConfig`. [3](#0-2) 

These values drive both the bonus (`calculate_linear_bonus_with_target`, curve.rs:60-81) and the ideal close amount (`liquidation_at_target` via `curve.target_hf`, curve.rs:130). Meanwhile `set_spoke_liquidation_curve` overwrites them on the shared spoke config with no per-position stamping and no health-factor gate. [4](#0-3) 

The protocol's own documentation confirms the asymmetry: "The curve (`H`, `K`, `f`) is not stored. Each liquidation reads it from the spoke. `configureSpokeCurves` changes it for all accounts of the spoke at the same time" — while stamped LT/bonus/fee changes are gated by `THRESHOLD_UPDATE_MIN_HF_RAW` (1.05). [5](#0-4) 

### Impact Explanation
A borrower who opened a position under curve `(H, K, f)` can be liquidated under a strictly harsher curve. Raising `liquidation_bonus_factor_bps` multiplies the bonus increment above the stamped base bonus; lowering `hf_for_max_bonus_wad` widens the max-bonus region; raising `liquidation_target_hf_wad` increases the close factor. The borrower loses more collateral to the liquidator than the terms stamped on their position imply — theft of user funds via retroactively applied terms, exactly the class of loss the position-stamping design exists to prevent. Because the gate (`apply_gated_liquidation_params`, HF >= 1.05) only wraps the stamped fields, a deeply unhealthy account (HF < 1.05) that is *protected* from harsher stamped parameters is still fully exposed to a harsher curve.

### Likelihood Explanation
Triggering requires a `set_spoke_liquidation_curve` call, which goes through the governance/owner path — reachable in-scope via "governance execute of a ready operation". This mirrors the original finding, which likewise required an admin `updateProtocolFeeDiscountBp`. No unprivileged user can force the change, but every liquidation afterward is executed permissionlessly against the retroactively worsened terms. Medium severity, consistent with the source finding: funds are lost only if the parameter changes while underwater positions exist, and the magnitude is bounded by the curve validation (`validate_liquidation_curve`).

### Recommendation
Stamp the curve (or at least the fields that affect borrowers) the same way other risk parameters are stamped:

- Add `liquidation_target_hf_wad`, `hf_for_max_bonus_wad`, `liquidation_bonus_factor_bps` to the supply position (or the account) at creation in `get_or_create_supply_position`.
- Refresh them only through the same gated paths used for LT/bonus/fee (`refresh_supply_risk_params` / `merge_withdraw_leg` / `sync_account_thresholds` via `apply_gated_liquidation_params`).
- In `build_liquidation_plan` (plan.rs:62), build `LiquidationCurve` from the position-stamped values rather than `cache.spoke_config(...)`.

### Proof of Concept
1. Alice supplies collateral in spoke S and borrows to near the LTV limit. Her position stamps `liquidation_bonus = 900`, `liquidation_threshold = 7800`; the spoke curve is `(H=1.1, K=0.8, f=10_000)`.
2. Price drops; Alice's HF falls to 0.95 (below the 1.05 gate, so a direct LT/bonus/fee worsening could not be applied to her).
3. Governance executes `set_spoke_liquidation_curve(S, 1.1e18, 0.8e18, 20_000)` — doubling `liquidation_bonus_factor_bps`. No per-position gate applies.
4. A liquidator calls `liquidate`. `build_liquidation_plan` reads the live config and `calculate_linear_bonus_with_target` doubles Alice's bonus increment above base (per the test at `liquidation_curve.rs:90-115`, `inc_scaled = inc_default * 2`), so she loses roughly twice the bonus collateral the stamped terms implied.
5. The excess collateral is seized and transferred to the liquidator; Alice cannot recover it, and `update_account_threshold` cannot restore the old curve because the curve is never stored on her position.

### Citations

**File:** contracts/controller/src/positions/liquidation/math.rs (L492-501)
```rust
        seized.push_back(SeizeEntry {
            hub_asset,
            amount: capped_amount,
            protocol_fee,
            scaled_amount: seized_scaled.raw(),
            bonus_scaled: bonus_scaled.raw(),
            liquidation_fees: position.liquidation_fees.raw() as u32,
            feed: (&feed).into(),
            market_index: (&market_index).into(),
        });
```

**File:** contracts/controller/src/positions/liquidation/plan.rs (L62-62)
```rust
    let curve = LiquidationCurve::from_config(&cache.spoke_config(account.spoke_id));
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L36-42)
```rust
    pub(crate) fn from_config(cfg: &SpokeConfig) -> Self {
        Self {
            target_hf: Wad::from(cfg.liquidation_target_hf_wad),
            hf_for_max_bonus: Wad::from(cfg.hf_for_max_bonus_wad),
            bonus_factor: Bps::from(i128::from(cfg.liquidation_bonus_factor_bps)),
        }
    }
```

**File:** contracts/controller/src/config/spoke.rs (L52-76)
```rust
pub(crate) fn set_spoke_liquidation_curve(
    env: &Env,
    id: u32,
    target_hf_wad: i128,
    hf_for_max_bonus_wad: i128,
    liquidation_bonus_factor_bps: u32,
) {
    validate_liquidation_curve(
        env,
        target_hf_wad,
        hf_for_max_bonus_wad,
        liquidation_bonus_factor_bps,
    );

    let mut spoke = storage::get_spoke(env, id);
    spoke.liquidation_target_hf_wad = target_hf_wad;
    spoke.hf_for_max_bonus_wad = hf_for_max_bonus_wad;
    spoke.liquidation_bonus_factor_bps = liquidation_bonus_factor_bps;
    storage::set_spoke(env, id, &spoke);

    UpdateSpokeEvent {
        spoke: EventSpoke::new(id, &spoke),
    }
    .publish(env);
}
```

**File:** docs/reference/runbooks/liqvid-listing-params.md (L372-395)
```markdown
- The curve (`H`, `K`, `f`) is not stored. Each liquidation reads it from the
  spoke. `configureSpokeCurves` changes it for all accounts of the spoke at
  the same time.

Thus an `editAssetInSpoke` that lowers LT changes only the positions created
after it and the positions that the controller refreshes. Every borrow and
every withdrawal refreshes the stored LTV of each listed supply position
without a condition. The stored LT, bonus and fee refresh together, and only
in these paths:

| Path | Code |
|---|---|
| A supply of the asset into the account | `merge_supply_leg` calls `refresh_supply_risk_params` |
| A withdrawal of the asset that is not a liquidation and leaves a balance | `merge_withdraw_leg` |
| `update_account_threshold(caller, has_risks = true, account_ids)` | `sync_account_thresholds` |

A liquidation never refreshes them. `update_account_threshold` with
`has_risks = false` refreshes the LTV only.

All three paths use the same gate (`apply_gated_liquidation_params`). A
change favours the liquidator when it lowers LT, raises the bonus or lowers
the fee. For an account with debt, such a change applies only when the
account HF, calculated with the new LT, is at least 1.05
(`THRESHOLD_UPDATE_MIN_HF_RAW`). If the HF is lower, the position keeps its
```
