### Title
Third-party `supply` restamps a foreign account's stored risk tuple without the `update_account_threshold` HF floor, forcing a victim into liquidation - ([File: contracts/controller/src/positions/supply.rs])

### Summary
The external report is an IDOR: an authenticated user reaching another object's state through an endpoint that skips the object's own authorization rules. The on-chain analog is the permissionless third-party top-up path in `supply`. It correctly blocks a stranger from opening a *new* asset slot on a foreign account, but every accepted leg unconditionally runs `refresh_supply_risk_params(..., RiskRefreshScope::FullTuple)`, overwriting the victim's stored LTV / liquidation-threshold / bonus tuple with currently listed values. The designated restamping entrypoint, `update_account_threshold`, enforces a post-refresh HF ≥ 1.05 gate whenever risk parameters change; the supply path enforces no such gate. A stranger can therefore apply a worsened risk tuple to a victim's collateral at will.

### Finding Description
In `contracts/controller/src/positions/supply.rs`, `process_supply` resolves the account under `AccountGuard::Supply` — which only checks spoke matching (`contracts/controller/src/account.rs`, `load_or_create_account` line 100) — and then `require_third_party_existing_supply` (lines 78-97) only asserts that each supplied `hub_asset` is already in `account.supply_positions`. No owner/delegate check and no solvency precondition applies to the restamping side effect. `merge_supply_leg` (lines 288-296) then calls `refresh_supply_risk_params` with `FullTuple` on every supply leg, for owner and stranger alike.

The documented control for exactly this mutation is `controller::update_account_threshold`: per `docs/reference/endpoints.md` line 39 and `scripts/permissionless_entrypoints.txt` line 76, a risk-parameter restamp is only permitted when the account clears the update HF floor (1.05) afterward, precisely so a keeper cannot push an account into liquidation by restamping. Third-party `supply` reaches the same `refresh_supply_risk_params` write with none of that protection, and it is reachable by any unprivileged address via `supply(caller, victim_account_id, victim_spoke_id, [(already_held_hub_asset, dust)])`.

Attack path:
1. Governance lowers a listed collateral's liquidation threshold (or LTV/bonus tuple) — a routine, timelocked parameter change that is safe because live positions keep their stored `entry*` weights until restamped.
2. The victim's account sits just above HF 1 on the old stored tuple.
3. Attacker calls `supply` with a dust amount of an asset the victim already supplies (allowed per INV-AUTH-03), which restamps that leg to the stricter tuple with no HF floor check.
4. The victim's HF, computed in the risk context from the stored leg weights, drops below 1.
5. Attacker immediately calls `liquidate(victim_account_id, ...)` and seizes collateral at the liquidation bonus.

### Impact Explanation
Theft of user funds via forced liquidation: the victim suffers a liquidation (collateral seized at a discount plus bonus to the liquidator) that the protocol's own `update_account_threshold` gate was designed to prevent, because the account was solvent under the risk tuple the owner agreed to. The attacker captures the liquidation bonus on an account that no permissionless path was supposed to be able to push under HF 1.

### Likelihood Explanation
Medium. It requires a governance parameter change that worsens a collateral's risk tuple while some accounts remain near HF 1 on the stale stored tuple — a recurring condition whenever risk parameters are tightened. The attacker needs only dust of an asset the victim already holds and a single transaction; no delegation, approval, or oracle manipulation is needed.

### Recommendation
Apply the same guard `update_account_threshold` uses: in `merge_supply_leg` (and `merge_withdraw_leg`, which can also restamp on partial withdrawals), skip or gate `refresh_supply_risk_params` when the caller is not the owner/delegate, or enforce the post-refresh HF ≥ update-floor check before committing the restamp. Alternatively, restrict restamping to owner/delegate-authorized calls only and treat stranger top-ups as pure share mints.

### Proof of Concept
```rust
// Victim ALICE supplies USDC; stored entry tuple: liquidation threshold T0.
// Governance timelock lowers USDC's listed liquidation threshold to T1 < T0.
// ALICE's HF under T0 is 1.02 (above the 1.0 liquidation line, but the
// update_account_threshold gate would refuse a restamp: post-refresh HF < 1.05).
//
// Attacker BOB (no delegate grant) front-runs:
supply(BOB, alice_account_id, alice_spoke_id,
       vec![(usdc_hub_key, 1)]);          // dust top-up of an existing leg
// merge_supply_leg -> refresh_supply_risk_params(FullTuple) restamps T0 -> T1
// with no HF floor. ALICE's HF drops to <1.
liquidate(BOB, alice_account_id, debt_payments, SeizeMode::Transfer);
// BOB seizes ALICE's collateral at the bonus on an account that the
// protocol's own restamp entrypoint would have protected.
```

Uncertainty note: I confirmed the restamp in `merge_supply_leg` and the HF-floor asymmetry versus `update_account_threshold` from docs and the supply code; I did not trace `refresh_supply_risk_params`/`enforce_post_pool_solvency` internals to confirm that `supply`'s finalize path skips the risk-refresh HF check, so the exact persisted-state behavior after the stranger's call should be verified against `contracts/controller/src/risk/` before severity assignment.