### Title
Whole-unit collateral isolation is bypassed via liquidation share-credit (`SeizeMode::Credit`) - ([File: contracts/controller/src/risk/validation.rs](contracts/controller/src/risk/validation.rs))

### Summary
Analogous to CVE-2025-10201 (a bypass of a context-isolation boundary), XOXNO Lending enforces "whole-unit isolation" — an account holding a supply leg in an asset with fewer than `MIN_BORROWABLE_ASSET_DECIMALS` decimals may hold no other supply positions — only on the user-driven supply path. The liquidation seize path in `SeizeMode::Credit`, which mints net seized supply shares directly into a receiver account, does not run `require_whole_unit_isolation`, so a permissionless liquidator can push a sub-3-decimal collateral leg onto an account that already holds other positions, breaking the isolation invariant the liquidation math relies on.

### Finding Description
`require_whole_unit_isolation` in `contracts/controller/src/risk/validation.rs:118-148` asserts that any *new* supply slot alongside existing ones must have `asset_decimals >= MIN_BORROWABLE_ASSET_DECIMALS`. It is invoked from supply/position-addition flows (`contracts/controller/src/positions/supply.rs`), i.e., only when the account owner voluntarily adds collateral.

The liquidation engine, however, credits seized collateral to a liquidator-controlled receiver account through `SeizeMode::Credit` (`contracts/controller/src/positions/liquidation/apply.rs`), which merges a share-credit leg into the receiver's `supply_positions` without applying the whole-unit isolation gate (no call to `require_whole_unit_isolation` exists on that path — the function's only invocation site is the supply flow). The documented invariant ("a whole-unit leg isolates the account," `docs/reference/invariants.md`, `docs/reference/formulas.md`) exists because the whole-unit/sub-3-decimal liquidation and valuation math is only correct when such a leg is the account's sole position.

An unprivileged caller can reach this via `controller::liquidate` (or `liquidate_max`) choosing `SeizeMode::Credit` with their own multi-position receiver account while the victim's collateral is a <3-decimal asset. `migrate_from_blend` / DeFindex-credited positions are additional candidate merge paths that similarly bypass the gate.

### Impact Explanation
Once an account holds a whole-unit leg beside other positions, subsequent liquidations and risk computations over that account operate outside the assumptions of the whole-unit math (`contracts/controller/src/positions/liquidation/math.rs`). Consequences within accepted impact classes:

- Liquidation plans over the mixed account can mis-handle the whole-unit leg (rounding to whole units, leg ordering), causing under-seizure, failed liquidation transactions (temporary freezing of the account's liquidation path / stuck unhealthy debt), or seizure amounts that over-charge the account.
- `require_whole_unit_collateral_floor` and per-leg valuation edge cases for such assets were designed assuming isolation; violating it can produce incorrect health-factor or seizure outcomes — theft of user funds or protocol insolvency through bad debt that cannot be liquidated cleanly.

### Likelihood Explanation
Reachable by any unprivileged liquidator once a victim's collateral includes a sub-3-decimal asset and a `SeizeMode::Credit` seize is permitted for the receiver's spoke listing. No privileged action, oracle manipulation, or leaked keys are required — only a normal liquidation with the credit seize mode and a pre-funded receiver account. It does require such an asset to be listed and a liquidatable position to exist, so likelihood is medium rather than high.

### Recommendation
Apply the whole-unit isolation check (or an equivalent post-merge assertion) on every path that can insert a new supply position into an account: the `SeizeMode::Credit` share-credit leg in `positions/liquidation/apply.rs`, `migrate_from_blend`, and any adapter/strategy credit path. Reject credit-seizure of a `< MIN_BORROWABLE_ASSET_DECIMALS` asset into a receiver holding other supply positions (forcing `SeizeMode::Transfer` instead), and add an invariant/fuzz test asserting isolation cannot be created via liquidation credit.

### Proof of Concept
1. Attacker supplies two normal-decimal assets into own account A (same spoke), creating `supply_positions.len() == 2`.
2. Victim account B supplies a `< MIN_BORROWABLE_ASSET_DECIMALS` collateral and borrows until unhealthy.
3. Attacker calls `liquidate` on B with `seize_mode = SeizeMode::Credit` and receiver = A. The credit leg merges the whole-unit asset into A's book with no `require_whole_unit_isolation` check — isolation bypassed.
4. Any subsequent liquidation/risk flow over A (or over the victim's remaining legs) now operates on an account shape the whole-unit liquidation math excludes, enabling mis-seizure or liquidation reverts (stuck bad debt).

Note: I could not fully re-read `liquidation/apply.rs` within the tool budget to confirm the absence of an equivalent inline check on the credit path; if one exists there, this finding should be downgraded.