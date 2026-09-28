### Title
Third-party dust `supply()` forces adverse liquidation-parameter restamp on a foreign account - (File: contracts/controller/src/positions/supply.rs)

### Summary
`controller::supply` is permissionless for topping up *existing* supply legs of any account (`require_third_party_existing_supply`, contracts/controller/src/positions/supply.rs:78-97). As part of the deposit flow, the account's cached per-position risk parameters are restamped from the current spoke `AssetConfig` via `refresh_supply_risk_params` / `apply_gated_liquidation_params` (contracts/controller/src/risk/params.rs:25-93). Liquidator-favoring changes (lower `liquidation_threshold`, higher `liquidation_bonus`, lower `liquidation_fees`) are only gated by a health-factor check — they are skipped only when the account has debt AND its hypothetical HF falls below `THRESHOLD_UPDATE_MIN_HF_RAW` (1.05). For every other account the adverse restamp applies unconditionally. This mirrors the Yieldy bug: an unprivileged address can force an unwanted, economically harmful state transition on a victim's position with a dust-sized deposit.

### Finding Description
In Yieldy, a 1-wei `stake()` to `_recipient` reset `warmUpInfo[_recipient].expiry`, griefing the victim's claim. Here, a dust `supply(caller, victim_account_id, spoke_id, [(victim's_existing_asset, 1)])` triggers the supply entry gates, which restamp the victim's stored `loan_to_value`, `liquidation_threshold`, `liquidation_bonus`, and `liquidation_fees` to the *current* config values:

- `position.loan_to_value = effective_config.loan_to_value` is unconditional (params.rs:35).
- The liquidation tuple update is skipped only if `favors_liquidator(...) && !account.debt_free() && !clears_min_hf(...)` (params.rs:76-88). So it applies whenever:
  - the account is debt-free (griefing pays off later, when the victim borrows against already-degraded terms), or
  - the account has debt and HF ≥ 1.05 — precisely the window where a *lowered* `liquidation_threshold` is most damaging, since it immediately reduces the liquidation-weighted collateral value used for `health_factor`, and a *raised* `liquidation_bonus` increases the penalty paid on every subsequent liquidation leg.

The regression test `regression_supply_propagates_bonus_raise_to_healthy_account` (tests/test-harness/tests/controller/security_audit.rs:636-661) confirms this behavior end-to-end: a third-party top-up of `1.0` USDC propagates a `+500 bps` liquidation bonus to Alice's healthy account.

### Impact Explanation
A griefer can, at near-zero cost, permanently stamp a victim's supply position with worse liquidation terms than the ones under which the victim deposited:
- For a debt-free victim: the raised `liquidation_bonus` / lowered `liquidation_threshold` applies unconditionally and persists; any future borrow is evaluated and liquidated against the worse tuple.
- For a healthy leveraged victim (HF ≥ 1.05): the griefer can push through a lowered `liquidation_threshold`, immediately lowering the victim's health factor toward the liquidation boundary, and a higher `liquidation_bonus`, increasing the collateral loss on each seized leg.
This is a forced degradation of a foreign account's liquidation terms — theft-adjacent (enlarged seizure bonus) and a form of position griefing the victim cannot prevent, since `supply` is deliberately open to third parties and only blocks *new* asset slots (INV-AUTH-03).

### Likelihood Explanation
The attack requires only: (a) a governance-approved adverse parameter change on a listed asset (routine risk management — LTV/threshold/bonus retunes are normal operations), and (b) any existing supply position on the victim's account. Cost is a single token unit of an asset the victim already supplies plus gas. No timing race is needed; the restamp sticks until a later benign change restamps again (which the attacker can re-apply). The only safe window is accounts with debt and HF < 1.05.

### Recommendation
Restrict the restamp triggered by third-party supply so a non-owner/non-delegate top-up cannot apply liquidator-favoring parameter changes to the target account. Concretely: in the supply entry-gate path, treat any `favors_liquidator` tuple change like the gated case (skip it) when `caller` is not owner-or-delegate — or skip `FullTuple` restamping entirely for third-party top-ups and restamp only `LtvOnly`, or not at all, leaving adverse restamps to owner actions and `update_account_threshold` (which at least enforces the post-update HF floor across *all* positions).

### Proof of Concept
1. Alice supplies USDC and borrows ETH; her HF is 1.20, above the 1.05 gate.
2. Governance lowers `USDC.liquidation_threshold` from 8000 to 7000 bps and/or raises `liquidation_bonus`.
3. Bob calls `controller.supply(bob, alice_account_id, alice_spoke, [(USDC, 1)])`. `require_third_party_existing_supply` passes because Alice already holds a USDC supply position (supply.rs:86-95).
4. During deposit, `apply_gated_liquidation_params` sees `favors_liquidator == true`, Alice has debt, but `clears_min_hf` returns true (HF 1.20 → still ≥ 1.05 even at the new threshold), so the worse tuple is written (params.rs:76-93).
5. Alice's `liquidation_threshold` is now 7000 and `liquidation_bonus` is raised — her HF drops and her liquidation penalty increases, caused entirely by an unprivileged third party paying 1 unit of USDC. The debt-free variant is strictly worse: step 4's HF check is skipped entirely (`!account.debt_free()` is false), so the adverse restamp lands with no gate at all.

Caveat: I verified the permissionless top-up path and the gating logic in `params.rs`/`supply.rs`, plus the existing regression test proving bonus propagation on healthy accounts; I did not fully trace `validate_position_entry_gates` (positions/mod.rs) to confirm the exact scope (`LtvOnly` vs `FullTuple`) used inside the supply flow, though the test at security_audit.rs:636-661 demonstrates the liquidation tuple is restamped during supply.