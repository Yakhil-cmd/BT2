### Title
Unprivileged dust `supply` force-restamps a foreign account's risk parameters without the owner's consent - (File: contracts/controller/src/positions/supply.rs)

### Summary
The external report describes a caller stamping state (`userLastDepositTime`) on a user who never consented, imposing a lock/DoS. XOXNO Lending has the same shape: any unprivileged address can call `supply` with an existing `account_id` of a victim and a dust amount of an asset the victim already holds. The merge path unconditionally restamps the position's `loan_to_value` and applies the gated refresh of `liquidation_threshold`, `liquidation_bonus`, and `liquidation_fees` from the current spoke listing — altering the victim's stored risk terms without any authorization from the account owner.

### Finding Description
`INV-AUTH-03` permits authenticated third parties to top up supply assets already held by a foreign account; there is no minimum-amount check (tests confirm a 1-stroop deposit is accepted and `supply_to(..., 0.0000001)` succeeds). On the merge path, `merge_supply_leg` / `merge_withdraw_leg` call `refresh_supply_risk_params` with `RiskRefreshScope::FullTuple`. [1](#0-0) 

Inside `refresh_supply_risk_params`, `position.loan_to_value` is overwritten unconditionally, and `apply_gated_liquidation_params` overwrites `liquidation_threshold`, `liquidation_bonus`, and `liquidation_fees` whenever the change does not push the (debt-bearing) account below hypothetical HF 1.05 — or unconditionally when the account is debt-free. [2](#0-1) [3](#0-2) 

Positions keep "vintage" stamped terms by design: HF, borrow limits, bonus base, and fees all read the stored per-position values, which normally refresh only on the owner's own actions or via `update_account_threshold`. [4](#0-3) 

The harness tests confirm the behavior end-to-end: a stranger's dust top-up immediately applies a tightened threshold when the account clears the 1.05 floor, and force-restamps LTV even when the HF gate holds the tuple. [5](#0-4) [6](#0-5) 

### Impact Explanation
- **Forced adverse restamp**: after governance tightens a listing (lower LTV/LT, higher bonus/fees), an attacker can immediately impose the new terms on any victim account whose hypothetical HF ≥ 1.05 — including raising `liquidation_bonus`, which directly increases the collateral seized from the victim in a subsequent liquidation (theft of user funds via worsened terms).
- **Unconditional LTV cut**: even when the gate holds the tuple, `loan_to_value` is always overwritten, destroying the victim's borrowing headroom before the victim's own next action — a restriction imposed without consent, mirroring the report's imposed-lock DoS.
- **Debt-free accounts get no gate at all**: `apply_gated_liquidation_params` skips the HF check when `account.debt_free()`, so a stranger can stamp a fully tightened tuple onto an account that has not yet borrowed.
- Cost to the attacker is a dust deposit of an asset the victim already holds.

### Likelihood Explanation
Requires a governance listing edit that tightens parameters (or a debt-free target), and a victim account holding that asset. Both are common conditions; the attack needs only a token transfer of dust. The design partially mitigates the worst case: accounts whose post-change HF would fall below 1.05 keep their stamped tuple, and the victim's own next borrow/withdraw would restamp LTV anyway. Medium likelihood, bounded impact — consistent with the "Acknowledged/Medium" class of the source report.

### Recommendation
- Gate third-party top-ups: either require the caller to be the account owner/delegate for risk restamping, or run `refresh_supply_risk_params` only when the caller is authorized for the account (skip the FullTuple refresh for foreign `account_id` supplies; the top-up can still credit shares).
- Alternatively, impose a minimum supply amount to make griefing expensive, and consider applying the HF gate to debt-free accounts as well.

### Proof of Concept
```rust
// tests/test-harness/tests/controller/third_party_supply_and_risk_restamp.rs
let mut t = LendingTest::new().standard_two_asset().build();
t.supply(BOB, "ETH", 100.0);
t.supply(ALICE, "USDC", 10_000.0);
t.borrow(ALICE, "ETH", 1.0);                       // victim, healthy HF
let account = t.account_id(ALICE);
assert_eq!(stamped_threshold(&t, account), 8_000); // victim's vintage LT

// Governance tightens the listing.
t.edit_asset_in_spoke("USDC", HARNESS_SPOKE, true, true, 6_500, 7_000, 500);

// CAROL — a stranger — forces the tightened terms onto ALICE with dust.
t.supply_to(CAROL, account, "USDC", 0.0000001);
assert_eq!(stamped_threshold(&t, account), 7_000); // imposed without consent
```
And the unconditional LTV restamp even when the tuple gate holds (`security_audit.rs::poc_lt_cut_stays_sticky_when_hf_below_min`): BOB's 1-unit top-up of ALICE's account rewrites `loan_to_value` from 7_500 to 5_000 while the LT stays pinned. [7](#0-6)

### Citations

**File:** contracts/controller/src/positions/supply.rs (L356-367)
```rust
    if may_restamp && position.scaled_amount != Ray::ZERO {
        let config: AssetConfig = cache.require_spoke_asset(account.spoke_id, hub_asset);
        refresh_supply_risk_params(
            env,
            cache,
            account,
            hub_asset,
            &mut position,
            &config,
            RiskRefreshScope::FullTuple,
        );
    }
```

**File:** contracts/controller/src/risk/params.rs (L34-39)
```rust
    let before = *position;
    position.loan_to_value = effective_config.loan_to_value;
    if scope == RiskRefreshScope::FullTuple {
        apply_gated_liquidation_params(env, cache, account, hub_asset, position, effective_config);
    }
    *position != before
```

**File:** contracts/controller/src/risk/params.rs (L76-92)
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
```

**File:** docs/reference/runbooks/liqvid-listing-params.md (L360-389)
```markdown
## 10. Existing positions keep their stamped terms

Each supply position stores its own LTV, LT, base bonus and liquidation fee.
It copies them from the spoke listing when it is created
(`get_or_create_supply_position`). After that, the controller uses the
stored values, not the live listing:

- HF uses the stored LT (`calculate_account_risk_totals`).
- The borrow limit uses the lower of the stored LTV and the stored LT.
- The base bonus `b0` is the USD-weighted stored bonus. The maximum bonus `M`
  comes from the stored LT. The fee is the stored fee
  (`get_account_bonus_params`).
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
```

**File:** tests/test-harness/tests/controller/third_party_supply_and_risk_restamp.rs (L50-64)
```rust
#[test]
fn a_stranger_can_tighten_when_the_account_clears_the_update_floor() {
    let mut t = LendingTest::new().standard_two_asset().build();
    t.supply(BOB, "ETH", 100.0);
    t.supply(ALICE, "USDC", 10_000.0);
    t.borrow(ALICE, "ETH", 1.0);
    let account = t.account_id(ALICE);
    t.edit_asset_in_spoke("USDC", HARNESS_SPOKE, true, true, 6_500, 7_000, 500);
    t.supply_to(CAROL, account, "USDC", 0.0000001);
    assert_eq!(
        stamped_threshold(&t, account),
        7_000,
        "HF stays far above 1.05, so the stamp moves"
    );
}
```

**File:** tests/test-harness/tests/controller/security_audit.rs (L489-499)
```rust
    t.try_supply_to_account(BOB, ALICE, "USDC", 1.0)
        .expect("top-up must remain allowed");
    let (ltv_after, lt_after) = supply_ltv_and_lt(&t, id, "USDC");
    assert_eq!(
        ltv_after, 5_000,
        "H-RISK-03/04: LTV always restamps on supply refresh"
    );
    assert_eq!(
        lt_after, 8_000,
        "H-RISK-04: LT stamp must stay sticky when post-cut HF < 1.05"
    );
```
