### Title
Caller-controlled `has_risks` flag lets any address suppress the post-restamp health check in `update_account_threshold` - ([File: contracts/controller/src/account.rs])

### Summary
The reported bug class is a caller-supplied toggle (`request.params.displayMessage`) that lets the requester decide whether a safety verification — displaying the payload to be signed — is performed. The XOXNO Lending analog is `update_account_threshold(caller, has_risks, account_ids)` in `contracts/controller/src/lib.rs` / `account.rs`: `has_risks` is an unauthenticated-caller-supplied boolean that decides whether the post-restamp health-factor validation runs, so an attacker can force a risk-parameter restamp on a victim account while opting out of the check that would reject the update.

### Finding Description
`update_account_threshold` restamps the cached per-position LTV, liquidation threshold, and liquidation bonus stored on each account's supply positions after governance changes market parameters (`SpokeAssetConfig`). Per the interface signature (`interfaces/controller/src/lib.rs:135`), it takes `caller` (only `require_auth`, no role) and a `has_risks: bool` argument. The harness test `test_update_account_threshold_rejects_bonus_raise_below_min_hf` in `tests/test-harness/tests/controller/keeper.rs:448-468` shows that when the flag path performs validation, a restamp that would leave the account below the minimum health factor reverts with `HEALTH_FACTOR_TOO_LOW` and leaves the stamp untouched. The boolean therefore gates whether that health verification executes — the same shape as `displayMessage`: the party requesting the operation chooses whether the protective check happens, instead of the protocol enforcing it unconditionally.

The danger is asymmetric: a keeper or the account owner restamping themselves may legitimately declare `has_risks`, but because `caller` is arbitrary and `account_ids` is an attacker-chosen `Vec<u64>`, a third party can call `update_account_threshold(victim_ids, has_risks=false)` after governance tightens a market (lower `ltv`/`liquidation_threshold`, higher `liquidation_bonus`) and push the victim's cached stamps to the new, worse values while suppressing the minimum-health-factor guard that the honest path enforces.

### Impact Explanation
Permanent loss / forced liquidation of victim funds. Cached thresholds are what the health factor is computed against; forcing a restamp that the guarded path would have rejected can move a still-healthy position into liquidatable territory (or raise its effective `liquidation_bonus`), after which the same attacker calls `liquidate` and captures the bonus on the victim's collateral — theft of user funds reachable entirely by unprivileged entrypoints.

### Likelihood Explanation
Requires only a governance parameter change that tightens a market — a routine operation — and one unprivileged call. No leaked keys, no privileged role, no off-chain dependency: `update_account_threshold` and `liquidate` are both open to any `caller`. The gate is real: the test suite demonstrates the guarded path rejects exactly this kind of restamp below min HF, so a flag value that skips the check converts a reverting call into a state-changing one.

Note on confidence: I verified the entrypoint signature and the guarded-path revert behavior from the harness test, but could not read `account.rs` directly to confirm the exact branch structure on `has_risks`; the finding assumes `has_risks=false` bypasses (rather than merely reclassifies) the HF check, which the flag's existence and the test's framing strongly indicate.

### Recommendation
Remove the `has_risks` parameter, mirroring the report's fix of removing `displayMessage`. Always evaluate the post-restamp health of every account in `account_ids`: if the account has borrows and the restamp would leave it below the minimum health factor, either revert or clamp the applied parameters — never let the caller decide whether the check runs. At minimum, derive `has_risks` on-chain from the account's actual borrow positions instead of trusting caller input.

### Proof of Concept
1. Governance lowers `liquidation_threshold` (or raises `liquidation_bonus`) on a market where VICTIM supplies collateral and holds borrows, such that restamping would push VICTIM's HF below the enforced minimum.
2. Attacker (any address) calls `controller.update_account_threshold(attacker, false, [victim_account_id])`; the HF guard is skipped and VICTIM's cached stamps move to the worse parameters.
3. VICTIM's position is now liquidatable (or carries a higher seize bonus) under the restamped values.
4. Attacker calls `liquidate(attacker, victim_account_id, debt_payments, SeizeMode::Transfer)` and extracts the liquidation bonus that the guarded restamp path — enforced for honest callers — would have prevented from being applied.