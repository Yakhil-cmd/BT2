Audit Report

## Title
Cycles Permanently Burned Before Canister-Status Check in `ValidSetRuleImpl::enqueue` — (`rs/messaging/src/scheduling/valid_set_rule.rs`)

## Summary
`ValidSetRuleImpl::enqueue` calls `charge_ingress_induction_cost` at lines 305–315 before checking canister status at lines 318–331. When the canister is in `Stopping` state, the function returns `IngressInductionError::CanisterStopping` with no cycle refund, permanently destroying cycles without inducting the message. Any unprivileged principal can exploit this to drain a canister's cycle balance during its `Stopping` window.

## Finding Description
In `enqueue` (`rs/messaging/src/scheduling/valid_set_rule.rs`, lines 293–335), the `IngressInductionCost::Fee` branch unconditionally calls `charge_ingress_induction_cost` (lines 305–315) before the canister-status guard (lines 318–331). For a canister without a paused execution, `charge_ingress_induction_cost` (`rs/cycles_account_manager/src/cycles_account_manager.rs`, lines 335–356) takes the `else` branch and calls `consume_with_threshold`, which immediately debits `system_state.cycles_balance` with no deferred or reversible accounting. Only after this irreversible deduction does the code check `canister.status()`. If the status is `Stopping`, the function returns `Err(IngressInductionError::CanisterStopping(...))` — there is no compensating credit, no rollback, and no refund anywhere on this error path. The same applies to `Stopped`. The existing guard for `IngressHistoryFull` and the `CanisterNotFound` check both occur before the charge, but the status check does not.

## Impact Explanation
An attacker with no special privileges can send repeated valid signed ingress messages to any canister in `Stopping` state. Each message burns the full ingress induction cost (base fee + per-byte fee) from the canister's cycle balance without inducting the message. Because the `Stopping` window persists until all outstanding inter-canister calls complete — which can be arbitrarily long — the attacker can drain the canister's entire cycle balance. A canister that runs out of cycles is eventually deleted by the protocol, destroying all its state and any ICP or tokens it controls. This constitutes permanent, targeted financial loss to canister owners, matching the High impact category: unauthorized draining of canister-controlled funds with no per-target privilege requirement.

## Likelihood Explanation
The `Stopping` state is reachable by any canister whose controller calls `stop_canister` and is observable on-chain via `canister_status`. The attack requires only a valid signed ingress message — no key material, no consensus manipulation, no privileged access. The attacker pays only the ingress submission cost. The attack is fully repeatable for the duration of the stopping window and is deterministically reproducible in a local state-machine test.

## Recommendation
Move the canister-status check to before `charge_ingress_induction_cost` in the `IngressInductionCost::Fee` branch of `enqueue`. The corrected order:
1. Resolve payer canister (already done at line 295).
2. Check `canister.status()` — return `CanisterStopping`/`CanisterStopped` immediately if not `Running` (and the message is not addressed to a subnet).
3. Only then call `charge_ingress_induction_cost`.
4. Call `state.push_ingress(ingress)`.

This eliminates the window where cycles are burned before the status rejection.

## Proof of Concept
Adapt the existing test harness from `canister_on_application_subnet_charges_for_ingress` (`rs/messaging/src/scheduling/valid_set_rule/test.rs`, lines 462–518):

```rust
// 1. Create canister with threshold + induction_cost cycles.
// 2. Call stop_canister; do NOT complete outstanding calls (canister stays Stopping).
// 3. Record balance_before = canister.system_state.balance().
// 4. Submit a valid signed ingress via valid_set_rule.induct_messages().
// 5. Assert returned IngressStatus is Failed(CanisterStopping).
// 6. Record balance_after = canister.system_state.balance().
// 7. Assert balance_before == balance_after  // currently FAILS — cycles are deducted.
```

This test is deterministic, requires no mainnet access, and directly reproduces the invariant violation.